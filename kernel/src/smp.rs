use alloc::boxed::Box;
use core::arch::global_asm;
use core::ptr::{addr_of, copy_nonoverlapping, write_bytes, write_unaligned};
use core::sync::atomic::{AtomicBool, Ordering};

use bootloader_api::info::MemoryRegion;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator as PagingFrameAllocator, Mapper, OffsetPageTable, Page, PageTable,
    PageTableFlags, PhysFrame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::acpi::{AcpiInfo, MAX_PROCESSORS, PhysicalMemory};
use crate::memory::{self, PAGE_SIZE};

const TRAMPOLINE_PAGE_SIZE: usize = PAGE_SIZE as usize;
const TRAMPOLINE_MIN_ADDRESS: u64 = 0x90000;
const TRAMPOLINE_MAX_ADDRESS: u64 = 0xa0000;
const AP_STACK_SIZE: usize = 16 * 1024;
const AP_STARTUP_SPINS: usize = 5_000_000;

global_asm!(
    r#"
    .section .text.ap_trampoline,"ax"
    .global rustos_ap_trampoline_start
    .global rustos_ap_trampoline_end
    .global rustos_ap_trampoline_cr3
    .global rustos_ap_trampoline_stack
    .global rustos_ap_trampoline_entry
    .global rustos_ap_trampoline_protected_jump
    .global rustos_ap_trampoline_protected
    .global rustos_ap_trampoline_gdt
    .global rustos_ap_trampoline_gdt_descriptor

    .code16
rustos_ap_trampoline_start:
    cli
    cld
    mov ax, cs
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x0ff0

rustos_ap_trampoline_gdt_load:
    .byte 0xbb
    .word rustos_ap_trampoline_gdt_descriptor - rustos_ap_trampoline_start
    lgdt [bx]

    mov eax, cr0
    or eax, 0x1
    mov cr0, eax
rustos_ap_trampoline_protected_jump:
    .byte 0x66, 0xea
    .long 0
    .word 0x18

    .code32
rustos_ap_trampoline_protected:
rustos_ap_trampoline_base_instruction:
    .byte 0xbb
    .long 0
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    mov eax, cr4
    or eax, 0x20
    mov cr4, eax

    .set AP_CR3_OFFSET, rustos_ap_trampoline_cr3 - rustos_ap_trampoline_start
    .set AP_STACK_OFFSET, rustos_ap_trampoline_stack - rustos_ap_trampoline_start
    .set AP_ENTRY_OFFSET, rustos_ap_trampoline_entry - rustos_ap_trampoline_start
    mov eax, dword ptr [ebx + AP_CR3_OFFSET]
    mov cr3, eax
    mov esi, dword ptr [ebx + AP_STACK_OFFSET]
    mov edi, dword ptr [ebx + AP_STACK_OFFSET + 4]
    mov ebp, dword ptr [ebx + AP_ENTRY_OFFSET]
    mov ebx, dword ptr [ebx + AP_ENTRY_OFFSET + 4]

    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x900
    wrmsr

    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax
rustos_ap_trampoline_long_jump:
    .byte 0xea
    .long rustos_ap_trampoline_long
    .word 0x08

    .code64
rustos_ap_trampoline_long:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, esi
    mov edx, edi
    shl rdx, 32
    or rax, rdx
    mov rsp, rax
    mov eax, ebp
    mov edx, ebx
    shl rdx, 32
    or rax, rdx
    jmp rax

    .align 8
rustos_ap_trampoline_cr3:
    .quad 0
rustos_ap_trampoline_stack:
    .quad 0
rustos_ap_trampoline_entry:
    .quad 0

rustos_ap_trampoline_gdt:
    .quad 0x0000000000000000
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00cf9a000000ffff
rustos_ap_trampoline_gdt_end:

rustos_ap_trampoline_gdt_descriptor:
    .word rustos_ap_trampoline_gdt_end - rustos_ap_trampoline_gdt - 1
    .long 0
    .word 0

rustos_ap_trampoline_end:
    "#
);

unsafe extern "C" {
    static rustos_ap_trampoline_start: u8;
    static rustos_ap_trampoline_end: u8;
    static rustos_ap_trampoline_cr3: u8;
    static rustos_ap_trampoline_stack: u8;
    static rustos_ap_trampoline_entry: u8;
    static rustos_ap_trampoline_protected_jump: u8;
    static rustos_ap_trampoline_protected: u8;
    static rustos_ap_trampoline_base_instruction: u8;
    static rustos_ap_trampoline_gdt: u8;
    static rustos_ap_trampoline_gdt_descriptor: u8;
}

const MAX_LOCAL_APIC_IDS: usize = 256;
static AP_ONLINE: [AtomicBool; MAX_LOCAL_APIC_IDS] =
    [const { AtomicBool::new(false) }; MAX_LOCAL_APIC_IDS];
static AP_RELEASE: [AtomicBool; MAX_LOCAL_APIC_IDS] =
    [const { AtomicBool::new(false) }; MAX_LOCAL_APIC_IDS];
static BSP_APIC_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpError {
    MissingBsp,
    NoLowMemoryPage,
    TrampolineTooLarge,
    PageTableAbove4GiB,
    InvalidAddress,
    MappingConflict,
    MappingFailed,
    ResumeTrampolineFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmpStats {
    pub discovered: u32,
    pub enabled: u32,
    pub online: u32,
    pub failed: u32,
    pub bsp_apic_id: u32,
    pub trampoline_address: u64,
    pub resume_trampoline_address: u64,
    pub next_frame_address: Option<u64>,
}

pub fn init(
    physical_memory: PhysicalMemory,
    regions: &[MemoryRegion],
    next_frame_address: Option<u64>,
    info: &AcpiInfo,
) -> Result<SmpStats, SmpError> {
    let bsp_apic_id = crate::apic::local_apic_id_u32().ok_or(SmpError::MissingBsp)?;
    BSP_APIC_ID.store(bsp_apic_id, Ordering::Release);
    let processor_count = usize::try_from(info.processor_count).unwrap_or(0);
    let processors = info
        .processors
        .get(..processor_count.min(MAX_PROCESSORS))
        .ok_or(SmpError::MissingBsp)?;
    let bsp_index = processors
        .iter()
        .position(|processor| processor.apic_id == bsp_apic_id)
        .ok_or(SmpError::MissingBsp)?;

    let bsp_online = AP_ONLINE
        .get(bsp_apic_id as usize)
        .ok_or(SmpError::MissingBsp)?;
    bsp_online.store(true, Ordering::Release);
    let enabled = processors
        .iter()
        .filter(|processor| processor.enabled)
        .count() as u32;
    let mut stats = SmpStats {
        discovered: processors.len() as u32,
        enabled,
        online: 1,
        failed: 0,
        bsp_apic_id,
        trampoline_address: 0,
        resume_trampoline_address: 0,
        next_frame_address,
    };

    let trampoline = memory::first_usable_frame_in_range(
        regions,
        TRAMPOLINE_MIN_ADDRESS,
        TRAMPOLINE_MAX_ADDRESS,
    )
    .ok_or(SmpError::NoLowMemoryPage)?;
    let trampoline_address = trampoline.start_address();
    let trampoline_vector =
        u8::try_from(trampoline_address / PAGE_SIZE).map_err(|_| SmpError::InvalidAddress)?;
    stats.trampoline_address = trampoline_address;
    stats.resume_trampoline_address = trampoline_address;

    let (page_table, _) = Cr3::read();
    let page_table_address = page_table.start_address().as_u64();
    if page_table_address > u64::from(u32::MAX) {
        return Err(SmpError::PageTableAbove4GiB);
    }

    stats.next_frame_address = map_identity_page(
        physical_memory,
        regions,
        next_frame_address,
        trampoline_address,
    )?;

    for (index, processor) in processors.iter().enumerate() {
        if enabled <= 1 {
            break;
        }
        if index == bsp_index || !processor.enabled {
            continue;
        }
        if processor.x2apic || processor.apic_id > u32::from(u8::MAX) {
            stats.failed += 1;
            continue;
        }

        let stack = Box::leak(Box::new([0u8; AP_STACK_SIZE]));
        let stack_top = (stack.as_ptr() as u64 + AP_STACK_SIZE as u64) & !0xf;
        prepare_trampoline(
            physical_memory,
            trampoline_address,
            page_table_address,
            stack_top,
            ap_entry as *const () as usize as u64,
        )?;

        if crate::apic::start_application_processor(processor.apic_id, trampoline_vector).is_err() {
            stats.failed += 1;
            continue;
        }
        if wait_for_ap(processor.apic_id) {
            stats.online += 1;
        } else {
            stats.failed += 1;
        }
    }

    if !crate::power::prepare_resume_trampoline(physical_memory, trampoline_address) {
        return Err(SmpError::ResumeTrampolineFailed);
    }

    Ok(stats)
}

/// Release application processors after the BSP has initialized its timer and entered the
/// scheduler. APs complete hardware startup first, then wait here so they cannot race the BSP's
/// first scheduler handoff.
pub fn release_application_processors() -> u32 {
    let bsp_apic_id = BSP_APIC_ID.load(Ordering::Acquire);
    let mut released = 0;
    for (apic_id, release) in AP_RELEASE.iter().enumerate() {
        if apic_id as u32 == bsp_apic_id {
            continue;
        }
        if AP_ONLINE[apic_id].load(Ordering::Acquire) && !release.swap(true, Ordering::AcqRel) {
            released += 1;
        }
    }
    released
}

fn prepare_trampoline(
    physical_memory: PhysicalMemory,
    physical_address: u64,
    page_table_address: u64,
    stack_top: u64,
    entry: u64,
) -> Result<(), SmpError> {
    let start = addr_of!(rustos_ap_trampoline_start) as usize;
    let end = addr_of!(rustos_ap_trampoline_end) as usize;
    let length = end.checked_sub(start).ok_or(SmpError::InvalidAddress)?;
    if length > TRAMPOLINE_PAGE_SIZE {
        return Err(SmpError::TrampolineTooLarge);
    }

    let destination = physical_memory
        .virtual_address(physical_address)
        .ok_or(SmpError::InvalidAddress)? as *mut u8;
    // SAFETY: the page comes from a usable low-memory region and is reserved for the AP trampoline
    // for the duration of startup. The source is the linker-owned trampoline byte range.
    unsafe {
        write_bytes(destination, 0, TRAMPOLINE_PAGE_SIZE);
        copy_nonoverlapping(start as *const u8, destination, length);
    }

    let gdt_offset = symbol_offset(start, addr_of!(rustos_ap_trampoline_gdt) as usize);
    let descriptor_offset = symbol_offset(
        start,
        addr_of!(rustos_ap_trampoline_gdt_descriptor) as usize,
    );
    let cr3_offset = symbol_offset(start, addr_of!(rustos_ap_trampoline_cr3) as usize);
    let stack_offset = symbol_offset(start, addr_of!(rustos_ap_trampoline_stack) as usize);
    let entry_offset = symbol_offset(start, addr_of!(rustos_ap_trampoline_entry) as usize);
    let protected_jump_offset = symbol_offset(
        start,
        addr_of!(rustos_ap_trampoline_protected_jump) as usize,
    );
    let base_instruction_offset = symbol_offset(
        start,
        addr_of!(rustos_ap_trampoline_base_instruction) as usize,
    );

    let gdt_address = physical_address
        .checked_add(gdt_offset as u64)
        .ok_or(SmpError::InvalidAddress)?;
    let gdt_address = u32::try_from(gdt_address).map_err(|_| SmpError::InvalidAddress)?;
    let page_table_address =
        u32::try_from(page_table_address).map_err(|_| SmpError::PageTableAbove4GiB)?;
    let protected_offset = u32::try_from(
        physical_address
            .checked_add(
                symbol_offset(start, addr_of!(rustos_ap_trampoline_protected) as usize) as u64,
            )
            .ok_or(SmpError::InvalidAddress)?,
    )
    .map_err(|_| SmpError::InvalidAddress)?;

    // SAFETY: each offset points at a writable field inside the freshly copied trampoline page.
    unsafe {
        write_unaligned(
            destination.add(descriptor_offset + 2).cast::<u32>(),
            gdt_address,
        );
        write_unaligned(
            destination.add(cr3_offset).cast::<u32>(),
            page_table_address,
        );
        write_unaligned(destination.add(stack_offset).cast::<u64>(), stack_top);
        write_unaligned(destination.add(entry_offset).cast::<u64>(), entry);
        write_unaligned(
            destination.add(protected_jump_offset + 2).cast::<u32>(),
            protected_offset,
        );
        write_unaligned(
            destination.add(base_instruction_offset + 1).cast::<u32>(),
            u32::try_from(physical_address).map_err(|_| SmpError::InvalidAddress)?,
        );
    }
    Ok(())
}

fn map_identity_page(
    physical_memory: PhysicalMemory,
    regions: &[MemoryRegion],
    next_frame_address: Option<u64>,
    physical_address: u64,
) -> Result<Option<u64>, SmpError> {
    let physical_memory_offset = physical_memory
        .virtual_address(0)
        .ok_or(SmpError::InvalidAddress)?;
    let physical_memory_offset = VirtAddr::new(physical_memory_offset);
    // SAFETY: the bootloader's physical-memory mapping makes the active level-4 table reachable;
    // this is the sole page-table mutation during single-threaded SMP setup.
    let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
    // SAFETY: the level-4 table and physical offset were validated from the bootloader contract.
    let mut mapper = unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) };
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(physical_address));
    if let Some(mapped) = mapper.translate_addr(VirtAddr::new(physical_address)) {
        if mapped.as_u64() == physical_address {
            return Ok(next_frame_address);
        }
        return Err(SmpError::MappingConflict);
    }

    let frame = PhysFrame::containing_address(PhysAddr::new(physical_address));
    let allocation_start = next_frame_address
        .unwrap_or(physical_address.saturating_add(PAGE_SIZE))
        .max(physical_address.saturating_add(PAGE_SIZE));
    let mut frame_allocator = SmpFrameAllocator {
        frames: memory::FrameAllocator::starting_at(regions, allocation_start),
    };
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    // SAFETY: the target page is firmware-reported usable memory reserved for the trampoline, and
    // the allocator only hands out later usable frames for any new page-table levels.
    let flush = unsafe {
        mapper
            .map_to(page, frame, flags, &mut frame_allocator)
            .map_err(|_| SmpError::MappingFailed)?
    };
    flush.flush();
    Ok(frame_allocator.frames.next_available_address())
}

unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    let (level_4_frame, _) = Cr3::read();
    let table_address = physical_memory_offset + level_4_frame.start_address().as_u64();
    // SAFETY: the caller owns page-table mutation during early kernel initialization, and the
    // bootloader maps the active page-table frame through the configured physical offset.
    unsafe { &mut *table_address.as_mut_ptr() }
}

struct SmpFrameAllocator<'a> {
    frames: memory::FrameAllocator<'a>,
}

// SAFETY: the underlying allocator advances monotonically through usable frames and starts after
// all frames consumed by heap setup and the trampoline page.
unsafe impl PagingFrameAllocator<Size4KiB> for SmpFrameAllocator<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.frames
            .next()
            .map(|frame| PhysFrame::containing_address(PhysAddr::new(frame.start_address())))
    }
}

fn symbol_offset(start: usize, symbol: usize) -> usize {
    symbol.saturating_sub(start)
}

fn wait_for_ap(apic_id: u32) -> bool {
    for _ in 0..AP_STARTUP_SPINS {
        if AP_ONLINE
            .get(apic_id as usize)
            .is_some_and(|online| online.load(Ordering::Acquire))
        {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

pub fn is_application_processor() -> bool {
    let bsp_apic_id = BSP_APIC_ID.load(Ordering::Acquire);
    bsp_apic_id != u32::MAX
        && crate::apic::local_apic_id_u32().is_some_and(|apic_id| apic_id != bsp_apic_id)
}

extern "C" fn ap_entry() -> ! {
    crate::interrupts::init_idt();
    crate::apic::init_application_processor();
    crate::process::init_user_mode_current_cpu();
    if let Some(apic_id) = crate::apic::local_apic_id_u32() {
        if let Some(online) = AP_ONLINE.get(apic_id as usize) {
            online.store(true, Ordering::Release);
        }
        if let Some(release) = AP_RELEASE.get(apic_id as usize) {
            while !release.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
        }
    }
    if crate::scheduler::is_initialized() {
        let _ = crate::scheduler::start_current_cpu();
    }
    crate::interrupts::enable();
    loop {
        crate::interrupts::halt();
    }
}
