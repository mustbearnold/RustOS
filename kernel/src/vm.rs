use core::ptr::{read_volatile, write_volatile};

use bootloader_api::info::MemoryRegion;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator as PagingFrameAllocator, Mapper, OffsetPageTable, Page, PageTable,
    PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::{self, PAGE_SIZE};

/// Virtual range reserved for kernel-owned mappings that are not part of the initial heap.
///
/// It is outside the bootloader's configured physical-memory window and the heap range, leaving
/// the range available for page-backed kernel services and future address-space machinery.
pub const KERNEL_VM_START: u64 = 0x5555_0000_0000;
pub const KERNEL_VM_END: u64 = 0x5555_1000_0000;

const SELF_TEST_PATTERN: u64 = 0x5255_5354_4f53_564d;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    OutOfFrames,
    VirtualAddressExhausted,
    AddressAlreadyMapped { page: u64 },
    MappingFailed { page: u64 },
    UnmappingFailed { page: u64 },
    TranslationMissing { page: u64 },
    TranslationMismatch { expected: u64, actual: u64 },
    ReadWriteMismatch { expected: u64, actual: u64 },
    StillMapped { page: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub page: Page<Size4KiB>,
    pub frame: PhysFrame<Size4KiB>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmStats {
    pub virtual_address: u64,
    pub physical_address: u64,
    pub read_back: u64,
    pub next_frame_address: Option<u64>,
}

/// A mapper for the active kernel address space with a monotonic virtual-page allocator.
///
/// This is deliberately a kernel-space manager: it owns page-backed mappings in the active page
/// table, while creation and switching of isolated user roots remains a later process milestone.
pub struct VirtualMemoryManager<'a> {
    mapper: OffsetPageTable<'static>,
    frames: VmFrameAllocator<'a>,
    next_virtual_address: u64,
}

impl<'a> VirtualMemoryManager<'a> {
    /// Creates a manager over the bootloader-installed active page table.
    ///
    /// # Safety
    ///
    /// The bootloader must have mapped all physical memory at `physical_memory_offset`, and the
    /// caller must ensure that no other page-table writer runs concurrently during setup.
    pub unsafe fn from_active(
        physical_memory_offset: u64,
        regions: &'a [MemoryRegion],
        next_frame_address: Option<u64>,
    ) -> Self {
        let physical_memory_offset = VirtAddr::new(physical_memory_offset);
        let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
        // SAFETY: the caller guarantees the physical-memory mapping and active root-table
        // lifetime described above.
        let mapper = unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) };
        Self {
            mapper,
            frames: VmFrameAllocator {
                frames: memory::FrameAllocator::starting_at(
                    regions,
                    next_frame_address.unwrap_or(0),
                ),
            },
            next_virtual_address: KERNEL_VM_START,
        }
    }

    pub fn allocate_page(&mut self, flags: PageTableFlags) -> Result<Mapping, VmError> {
        let virtual_address = self.next_virtual_address;
        let next_virtual_address = virtual_address
            .checked_add(PAGE_SIZE)
            .ok_or(VmError::VirtualAddressExhausted)?;
        if next_virtual_address > KERNEL_VM_END {
            return Err(VmError::VirtualAddressExhausted);
        }

        let page = Page::containing_address(VirtAddr::new(virtual_address));
        if self.mapper.translate_page(page).is_ok() {
            return Err(VmError::AddressAlreadyMapped {
                page: page.start_address().as_u64(),
            });
        }

        let frame = self.frames.allocate_frame().ok_or(VmError::OutOfFrames)?;
        // SAFETY: the virtual page was just checked as unmapped, the frame is uniquely owned by
        // this monotonic allocator, and the mapping is confined to the reserved kernel range.
        let flush = unsafe {
            self.mapper
                .map_to(page, frame, flags, &mut self.frames)
                .map_err(|_| VmError::MappingFailed {
                    page: page.start_address().as_u64(),
                })?
        };
        flush.flush();
        self.next_virtual_address = next_virtual_address;
        Ok(Mapping { page, frame })
    }

    pub fn translate_page(&self, page: Page<Size4KiB>) -> Option<PhysFrame<Size4KiB>> {
        self.mapper.translate_page(page).ok()
    }

    pub fn unmap_page(&mut self, page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, VmError> {
        // SAFETY: callers must stop using the virtual page before removing its mapping; this
        // manager only exposes mappings allocated through its own monotonic range.
        let (frame, flush) = self
            .mapper
            .unmap(page)
            .map_err(|_| VmError::UnmappingFailed {
                page: page.start_address().as_u64(),
            })?;
        flush.flush();
        Ok(frame)
    }

    pub fn next_frame_address(&self) -> Option<u64> {
        self.frames.frames.next_available_address()
    }
}

/// Exercise the complete page lifecycle before other CPUs or page-table writers start.
pub fn init(
    physical_memory_offset: u64,
    regions: &[MemoryRegion],
    next_frame_address: Option<u64>,
) -> Result<VmStats, VmError> {
    let mut manager = unsafe {
        VirtualMemoryManager::from_active(physical_memory_offset, regions, next_frame_address)
    };
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    let mapping = manager.allocate_page(flags)?;
    let page_address = mapping.page.start_address().as_u64();
    let frame_address = mapping.frame.start_address().as_u64();

    let translated = manager
        .translate_page(mapping.page)
        .ok_or(VmError::TranslationMissing { page: page_address })?;
    if translated != mapping.frame {
        return Err(VmError::TranslationMismatch {
            expected: frame_address,
            actual: translated.start_address().as_u64(),
        });
    }

    // SAFETY: the mapping is PRESENT | WRITABLE, points at a unique fresh frame, and is not
    // aliased elsewhere by the self-test.
    let read_back = unsafe {
        let pointer = mapping.page.start_address().as_mut_ptr::<u64>();
        write_volatile(pointer, SELF_TEST_PATTERN);
        read_volatile(pointer)
    };
    if read_back != SELF_TEST_PATTERN {
        return Err(VmError::ReadWriteMismatch {
            expected: SELF_TEST_PATTERN,
            actual: read_back,
        });
    }

    let unmapped_frame = manager.unmap_page(mapping.page)?;
    if unmapped_frame != mapping.frame {
        return Err(VmError::TranslationMismatch {
            expected: frame_address,
            actual: unmapped_frame.start_address().as_u64(),
        });
    }
    if manager.translate_page(mapping.page).is_some() {
        return Err(VmError::StillMapped { page: page_address });
    }

    Ok(VmStats {
        virtual_address: page_address,
        physical_address: frame_address,
        read_back,
        next_frame_address: manager.next_frame_address(),
    })
}

unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    let (level_4_frame, _) = Cr3::read();
    let table_address = physical_memory_offset + level_4_frame.start_address().as_u64();
    // SAFETY: the bootloader's physical-memory mapping makes this frame accessible, and the
    // caller owns page-table mutation during early single-threaded initialization.
    unsafe { &mut *table_address.as_mut_ptr() }
}

struct VmFrameAllocator<'a> {
    frames: memory::FrameAllocator<'a>,
}

// SAFETY: the wrapped allocator advances monotonically through usable firmware regions and never
// returns the same physical frame twice.
unsafe impl PagingFrameAllocator<Size4KiB> for VmFrameAllocator<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.frames
            .next()
            .map(|frame| PhysFrame::containing_address(PhysAddr::new(frame.start_address())))
    }
}
