use bootloader_api::info::MemoryRegion;
use linked_list_allocator::LockedHeap;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator as PagingFrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PhysFrame,
    Size4KiB, page_table::PageTableFlags,
};
use x86_64::{PhysAddr, VirtAddr};

pub const HEAP_START: u64 = 0x4444_4444_0000;
pub const HEAP_SIZE: u64 = 2 * 1024 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    OutOfFrames,
    MappingFailed { page: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeapStats {
    pub start: u64,
    pub size: u64,
    pub pages: usize,
    pub next_frame_address: Option<u64>,
}

pub fn init(physical_memory_offset: u64, regions: &[MemoryRegion]) -> Result<HeapStats, HeapError> {
    let physical_memory_offset = VirtAddr::new(physical_memory_offset);
    let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
    // SAFETY: the bootloader maps every physical frame at `physical_memory_offset`, including
    // the active level-4 table and any page tables allocated below.
    let mut mapper = unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) };
    let mut frame_allocator = BootInfoFrameAllocator::new(regions);

    let heap_start = VirtAddr::new(HEAP_START);
    let heap_end = heap_start + HEAP_SIZE - 1;
    let page_range = Page::range_inclusive(
        Page::containing_address(heap_start),
        Page::containing_address(heap_end),
    );
    let mut pages = 0;

    for page in page_range {
        let Some(frame) = frame_allocator.allocate_frame() else {
            return Err(HeapError::OutOfFrames);
        };
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        // SAFETY: the heap range is reserved by the boot configuration, each page is mapped once,
        // and every frame comes from a unique usable firmware region.
        let flush =
            unsafe { mapper.map_to(page, frame, flags, &mut frame_allocator) }.map_err(|_| {
                HeapError::MappingFailed {
                    page: page.start_address().as_u64(),
                }
            })?;
        flush.flush();
        pages += 1;
    }

    // SAFETY: all pages in this range were freshly mapped above and remain valid for the kernel's
    // lifetime. The allocator is initialized exactly once during single-threaded boot.
    unsafe {
        ALLOCATOR
            .lock()
            .init(HEAP_START as *mut u8, HEAP_SIZE as usize)
    };

    Ok(HeapStats {
        start: HEAP_START,
        size: HEAP_SIZE,
        pages,
        next_frame_address: frame_allocator.frames.next_available_address(),
    })
}

unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    let (level_4_frame, _) = Cr3::read();
    let table_address = physical_memory_offset + level_4_frame.start_address().as_u64();
    // SAFETY: the bootloader's physical-memory mapping makes this frame address accessible, and
    // the caller exclusively owns the page-table mutation during kernel initialization.
    unsafe { &mut *table_address.as_mut_ptr() }
}

struct BootInfoFrameAllocator<'a> {
    frames: crate::memory::FrameAllocator<'a>,
}

impl<'a> BootInfoFrameAllocator<'a> {
    fn new(regions: &'a [MemoryRegion]) -> Self {
        Self {
            frames: crate::memory::FrameAllocator::new(regions),
        }
    }
}

// SAFETY: `crate::memory::FrameAllocator` advances monotonically through each usable region and
// never returns a frame twice.
unsafe impl PagingFrameAllocator<Size4KiB> for BootInfoFrameAllocator<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.frames
            .next()
            .map(|frame| PhysFrame::containing_address(PhysAddr::new(frame.start_address())))
    }
}
