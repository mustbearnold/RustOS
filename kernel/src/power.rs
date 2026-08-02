use core::arch::global_asm;
use core::ptr::{addr_of, copy_nonoverlapping, write_bytes, write_unaligned};
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use x86_64::VirtAddr;
use x86_64::instructions::{interrupts, port::Port};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{OffsetPageTable, PageTable, Translate};

use crate::acpi::{AcpiPowerInfo, PhysicalMemory};

const SLEEP_TYPE_SHIFT: u16 = 10;
const SLEEP_ENABLE: u16 = 1 << 13;
const WAKE_STATUS: u16 = 1 << 15;
const INVALID_SLEEP_TYPE: u8 = u8::MAX;
const FACS_FIRMWARE_WAKING_VECTOR_OFFSET: usize = 12;
const FACS_FLAGS_OFFSET: usize = 20;
const FACS_X_FIRMWARE_WAKING_VECTOR_OFFSET: usize = 24;
const FACS_64BIT_WAKE_SUPPORTED_FLAG: u32 = 1 << 1;
const FACS_OSPM_FLAGS_OFFSET: usize = 36;
const FACS_OSPM_64BIT_WAKE_FLAG: u32 = 1;
const FACS_MINIMUM_LENGTH: u32 = 33;
const FACS_VERSION_2: u8 = 2;
const NATIVE_RESUME_TRAMPOLINE_OFFSET: u64 = 0x200;
const CMOS_INDEX_PORT: u16 = 0x70;
const CMOS_DATA_PORT: u16 = 0x71;
const CMOS_SHUTDOWN_STATUS_INDEX: u8 = 0x0f;
const CMOS_S3_RESUME_STATUS: u8 = 0xfe;

static PM1A_EVENT_BLOCK: AtomicU32 = AtomicU32::new(0);
static PM1B_EVENT_BLOCK: AtomicU32 = AtomicU32::new(0);
static PM1_EVENT_LENGTH: AtomicU8 = AtomicU8::new(0);
static PM1A_CONTROL_BLOCK: AtomicU32 = AtomicU32::new(0);
static PM1B_CONTROL_BLOCK: AtomicU32 = AtomicU32::new(0);
static SLEEP_TYPE_A: AtomicU8 = AtomicU8::new(0);
static SLEEP_TYPE_B: AtomicU8 = AtomicU8::new(0);
static SLEEP_TYPE_S3_A: AtomicU8 = AtomicU8::new(INVALID_SLEEP_TYPE);
static SLEEP_TYPE_S3_B: AtomicU8 = AtomicU8::new(INVALID_SLEEP_TYPE);
static RESET_REGISTER: AtomicU32 = AtomicU32::new(0);
static RESET_VALUE: AtomicU8 = AtomicU8::new(0);
static FACS_PHYSICAL_ADDRESS: AtomicU64 = AtomicU64::new(0);
static FACS_VIRTUAL_ADDRESS: AtomicU64 = AtomicU64::new(0);
static FACS_LENGTH: AtomicU32 = AtomicU32::new(0);
static FACS_VERSION: AtomicU8 = AtomicU8::new(0);
static RESUME_TRAMPOLINE_PHYSICAL_ADDRESS: AtomicU64 = AtomicU64::new(0);
static RESUME_NATIVE_TRAMPOLINE_PHYSICAL_ADDRESS: AtomicU64 = AtomicU64::new(0);
static RESUME_NATIVE_SAVED_CR3_OPERAND_PHYSICAL_ADDRESS: AtomicU64 = AtomicU64::new(0);
static RESUME_WAKE_STATUS: AtomicU8 = AtomicU8::new(0);

#[unsafe(no_mangle)]
static rustos_saved_rsp: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
static rustos_saved_rip: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
static rustos_saved_cr3: AtomicU64 = AtomicU64::new(0);

global_asm!(
    r#"
    .section .text.rustos_acpi_resume32,"ax"
    .code16
    .global rustos_acpi_resume32_start
    .global rustos_acpi_resume32_end
    .global rustos_acpi_resume_trampoline
    .global rustos_resume_lgdt_operand
    .global rustos_resume_saved_cr3_operand
    .global rustos_resume_real_mode_target
    .type rustos_acpi_resume_trampoline, @function
rustos_acpi_resume32_start:
rustos_acpi_resume_trampoline:
    cli
    .byte 0x67, 0x0f, 0x01, 0x15
rustos_resume_lgdt_operand:
    .long rustos_resume_gdt_descriptor
    .byte 0x66, 0x67, 0xa1
rustos_resume_saved_cr3_operand:
    .long rustos_saved_cr3
    mov cr3, eax
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x900
    wrmsr
    mov eax, cr0
    or eax, 0x1
    mov cr0, eax
    .byte 0x66, 0xea
rustos_resume_real_mode_target:
    .long rustos_resume_protected_entry
    .word 0x08

    .code32
    .global rustos_resume_protected_entry
rustos_resume_protected_entry:
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax
    .byte 0xea
    .long rustos_resume_entry
    .word 0x10

    .align 8
    .global rustos_resume_gdt_descriptor
    .global rustos_resume_gdt_descriptor_base
    .global rustos_resume_gdt
rustos_resume_gdt_descriptor:
    .word 0x1f
rustos_resume_gdt_descriptor_base:
    .long rustos_resume_gdt
rustos_resume_gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
rustos_acpi_resume32_end:

    .section .text.rustos_acpi_resume64_native,"ax"
    .code64
    .global rustos_acpi_resume64_start
    .global rustos_acpi_resume64_end
    .global rustos_resume64_saved_cr3_operand
    .type rustos_acpi_resume64_trampoline, @function
rustos_acpi_resume64_start:
rustos_acpi_resume64_trampoline:
    cli
    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x800
    wrmsr
    mov rdx, qword ptr [rip + .Lrustos_resume_entry_address]
    .byte 0x48, 0xb8
rustos_resume64_saved_cr3_operand:
    .quad rustos_saved_cr3
    mov cr3, rax
    lgdt [rip + .Lrustos_resume64_gdt_descriptor]
    jmp rdx
.align 8
.Lrustos_resume_entry_address:
    .quad rustos_resume_entry
.align 8
.Lrustos_resume64_gdt_descriptor:
    .word 0x1f
rustos_resume64_gdt_descriptor_base:
    .quad rustos_resume_gdt
rustos_acpi_resume64_end:

    .section .text.rustos_acpi_resume64,"ax"
    .code64
    .global rustos_resume_entry
    .type rustos_resume_entry, @function
rustos_resume_entry:
    mov rsp, qword ptr [rip + rustos_saved_rsp]
    mov eax, 0x18
    mov ss, ax
    call rustos_acpi_resume_reinitialize
    jmp qword ptr [rip + rustos_saved_rip]

    .section .text.rustos_acpi_suspend,"ax"
    .code64
    .global rustos_suspend_entry
    .type rustos_suspend_entry, @function
rustos_suspend_entry:
    cli
    mov qword ptr [rip + rustos_saved_rsp], rsp
    lea rax, [rip + .Lrustos_suspend_resume]
    mov qword ptr [rip + rustos_saved_rip], rax
    mov rax, cr3
    mov qword ptr [rip + rustos_saved_cr3], rax
    call rustos_prepare_suspend
    test eax, eax
    jz .Lrustos_suspend_unavailable
.Lrustos_suspend_wait:
    hlt
    jmp .Lrustos_suspend_wait
.Lrustos_suspend_unavailable:
    xor eax, eax
    ret
.Lrustos_suspend_resume:
    mov eax, 1
    ret
    "#
);

unsafe extern "C" {
    static rustos_acpi_resume32_start: u8;
    static rustos_acpi_resume32_end: u8;
    static rustos_acpi_resume64_start: u8;
    static rustos_acpi_resume64_end: u8;
    fn rustos_suspend_entry() -> u64;
    static rustos_resume_lgdt_operand: u8;
    static rustos_resume_saved_cr3_operand: u8;
    static rustos_resume_real_mode_target: u8;
    static rustos_resume_gdt_descriptor: u8;
    static rustos_resume_gdt_descriptor_base: u8;
    static rustos_resume_gdt: u8;
    static rustos_resume_protected_entry: u8;
    static rustos_resume64_saved_cr3_operand: u8;
    static rustos_resume64_gdt_descriptor_base: u8;
}

#[unsafe(no_mangle)]
pub extern "C" fn rustos_prepare_suspend() -> u64 {
    u64::from(prepare_suspend())
}

#[unsafe(no_mangle)]
pub extern "C" fn rustos_acpi_resume_reinitialize() {
    let diagnostics = diagnostics();
    let wake_confirmed = unsafe { wake_status_is_set(&diagnostics) };
    RESUME_WAKE_STATUS.store(u8::from(wake_confirmed), Ordering::Release);
    // SAFETY: the PM1 event blocks were validated during ACPI discovery and are unchanged across
    // the firmware's S3 wake reset.
    unsafe { clear_wake_status(&diagnostics) };
    crate::process::reload_user_mode();
    crate::interrupts::reload_idt();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerDiagnostics {
    pub ready: bool,
    pub suspend_ready: bool,
    pub native_wake_ready: bool,
    pub reboot_ready: bool,
    pub pm1a_event_block: u32,
    pub pm1b_event_block: u32,
    pub pm1_event_length: u8,
    pub pm1a_control_block: u32,
    pub pm1b_control_block: u32,
    pub sleep_type_a: u8,
    pub sleep_type_b: u8,
    pub sleep_type_s3_a: Option<u8>,
    pub sleep_type_s3_b: Option<u8>,
    pub facs_address: u64,
    pub facs_length: u32,
    pub facs_version: u8,
    pub reset_register: u32,
    pub reset_value: u8,
}

pub fn init(info: Option<AcpiPowerInfo>, physical_memory_offset: u64) {
    let Some(info) = info else {
        return;
    };
    if info.pm1a_control_block > u32::from(u16::MAX)
        || (info.pm1b_control_block != 0 && info.pm1b_control_block > u32::from(u16::MAX))
        || info.pm1_control_length < 2
        || info.sleep_type_a > 7
        || info.sleep_type_b > 7
    {
        return;
    }
    let facs_virtual_address = info
        .facs_address
        .and_then(|address| physical_memory_offset.checked_add(address))
        .unwrap_or(0);
    PM1A_EVENT_BLOCK.store(info.pm1a_event_block, Ordering::Release);
    PM1B_EVENT_BLOCK.store(info.pm1b_event_block, Ordering::Release);
    PM1_EVENT_LENGTH.store(info.pm1_event_length, Ordering::Release);
    PM1A_CONTROL_BLOCK.store(info.pm1a_control_block, Ordering::Release);
    PM1B_CONTROL_BLOCK.store(info.pm1b_control_block, Ordering::Release);
    SLEEP_TYPE_A.store(info.sleep_type_a as u8, Ordering::Release);
    SLEEP_TYPE_B.store(info.sleep_type_b as u8, Ordering::Release);
    if let Some((sleep_type_a, sleep_type_b)) = info.sleep_type_s3
        && sleep_type_a <= 7
        && sleep_type_b <= 7
    {
        SLEEP_TYPE_S3_A.store(sleep_type_a as u8, Ordering::Release);
        SLEEP_TYPE_S3_B.store(sleep_type_b as u8, Ordering::Release);
    }
    if let Some(reset) = info.reset_register
        && reset.address_space == 1
        && reset.bit_width >= 8
        && reset.bit_offset == 0
        && reset.address <= u64::from(u16::MAX)
    {
        RESET_REGISTER.store(reset.address as u32, Ordering::Release);
        RESET_VALUE.store(reset.value, Ordering::Release);
    }
    FACS_PHYSICAL_ADDRESS.store(info.facs_address.unwrap_or(0), Ordering::Release);
    FACS_VIRTUAL_ADDRESS.store(facs_virtual_address, Ordering::Release);
    FACS_LENGTH.store(info.facs_length, Ordering::Release);
    FACS_VERSION.store(info.facs_version, Ordering::Release);
}

/// Copies the firmware-entry portion of the resume trampoline into the low-memory page reserved
/// by the SMP setup and patches its physical-mode addresses. The bootloader maps the linked kernel
/// image at a different physical address, so firmware cannot execute the linker-owned text
/// directly before paging has been restored.
pub fn prepare_resume_trampoline(physical_memory: PhysicalMemory, physical_address: u64) -> bool {
    if physical_address % crate::memory::PAGE_SIZE != 0 || physical_address > u64::from(u32::MAX) {
        return false;
    }

    let legacy_start = addr_of!(rustos_acpi_resume32_start) as usize;
    let legacy_end = addr_of!(rustos_acpi_resume32_end) as usize;
    let Some(legacy_length) = legacy_end.checked_sub(legacy_start) else {
        return false;
    };
    if legacy_length == 0 || legacy_length > crate::memory::PAGE_SIZE as usize {
        return false;
    }

    let native_start = addr_of!(rustos_acpi_resume64_start) as usize;
    let native_end = addr_of!(rustos_acpi_resume64_end) as usize;
    let Some(native_length) = native_end.checked_sub(native_start) else {
        return false;
    };
    let native_offset = usize::try_from(NATIVE_RESUME_TRAMPOLINE_OFFSET).unwrap_or(usize::MAX);
    if native_length == 0
        || native_offset > crate::memory::PAGE_SIZE as usize
        || native_length > crate::memory::PAGE_SIZE as usize - native_offset
    {
        return false;
    }

    let Some(native_physical_address) =
        physical_address.checked_add(NATIVE_RESUME_TRAMPOLINE_OFFSET)
    else {
        return false;
    };

    let Some(destination_address) = physical_memory.virtual_address(physical_address) else {
        return false;
    };
    let Some(native_destination_address) = physical_memory.virtual_address(native_physical_address)
    else {
        return false;
    };
    let Some(physical_memory_offset) = physical_memory.virtual_address(0) else {
        return false;
    };
    let Some(saved_cr3_physical) = virtual_to_physical(
        addr_of!(rustos_saved_cr3) as usize as u64,
        physical_memory_offset,
    ) else {
        return false;
    };

    let legacy_offset = |symbol: usize| symbol.checked_sub(legacy_start);
    let native_offset = |symbol: usize| symbol.checked_sub(native_start);
    let Some(lgdt_operand_offset) = legacy_offset(addr_of!(rustos_resume_lgdt_operand) as usize)
    else {
        return false;
    };
    let Some(saved_cr3_operand_offset) =
        legacy_offset(addr_of!(rustos_resume_saved_cr3_operand) as usize)
    else {
        return false;
    };
    let Some(real_mode_target_offset) =
        legacy_offset(addr_of!(rustos_resume_real_mode_target) as usize)
    else {
        return false;
    };
    let Some(gdt_descriptor_base_offset) =
        legacy_offset(addr_of!(rustos_resume_gdt_descriptor_base) as usize)
    else {
        return false;
    };
    let Some(gdt_descriptor_offset) =
        legacy_offset(addr_of!(rustos_resume_gdt_descriptor) as usize)
    else {
        return false;
    };
    let Some(gdt_offset) = legacy_offset(addr_of!(rustos_resume_gdt) as usize) else {
        return false;
    };
    let Some(protected_entry_offset) =
        legacy_offset(addr_of!(rustos_resume_protected_entry) as usize)
    else {
        return false;
    };
    let Some(native_saved_cr3_operand_offset) =
        native_offset(addr_of!(rustos_resume64_saved_cr3_operand) as usize)
    else {
        return false;
    };
    let Some(native_gdt_descriptor_base_offset) =
        native_offset(addr_of!(rustos_resume64_gdt_descriptor_base) as usize)
    else {
        return false;
    };
    let Some(gdt_address) = physical_address.checked_add(gdt_offset as u64) else {
        return false;
    };
    let Some(gdt_descriptor_address) = physical_address.checked_add(gdt_descriptor_offset as u64)
    else {
        return false;
    };
    let Some(protected_entry_address) = physical_address.checked_add(protected_entry_offset as u64)
    else {
        return false;
    };
    let Ok(gdt_address) = u32::try_from(gdt_address) else {
        return false;
    };
    let Ok(gdt_descriptor_address) = u32::try_from(gdt_descriptor_address) else {
        return false;
    };
    let Ok(saved_cr3_physical_legacy) = u32::try_from(saved_cr3_physical) else {
        return false;
    };
    let Ok(protected_entry_address) = u32::try_from(protected_entry_address) else {
        return false;
    };

    // SAFETY: the destination page is the low-memory page mapped and reserved by SMP setup; both
    // source ranges and every patch offset are linker-owned bytes within the copied trampolines.
    unsafe {
        write_bytes(
            destination_address as *mut u8,
            0,
            crate::memory::PAGE_SIZE as usize,
        );
        copy_nonoverlapping(
            legacy_start as *const u8,
            destination_address as *mut u8,
            legacy_length,
        );
        copy_nonoverlapping(
            native_start as *const u8,
            native_destination_address as *mut u8,
            native_length,
        );
        write_unaligned(
            (destination_address + lgdt_operand_offset as u64) as *mut u32,
            gdt_descriptor_address,
        );
        write_unaligned(
            (destination_address + saved_cr3_operand_offset as u64) as *mut u32,
            saved_cr3_physical_legacy,
        );
        write_unaligned(
            (destination_address + real_mode_target_offset as u64) as *mut u32,
            protected_entry_address,
        );
        write_unaligned(
            (destination_address + gdt_descriptor_base_offset as u64) as *mut u32,
            gdt_address,
        );
        write_unaligned(
            (native_destination_address + native_saved_cr3_operand_offset as u64) as *mut u64,
            0,
        );
        write_unaligned(
            (native_destination_address + native_gdt_descriptor_base_offset as u64) as *mut u64,
            u64::from(gdt_address),
        );
    }
    RESUME_TRAMPOLINE_PHYSICAL_ADDRESS.store(physical_address, Ordering::Release);
    RESUME_NATIVE_TRAMPOLINE_PHYSICAL_ADDRESS.store(native_physical_address, Ordering::Release);
    RESUME_NATIVE_SAVED_CR3_OPERAND_PHYSICAL_ADDRESS.store(
        native_physical_address + native_saved_cr3_operand_offset as u64,
        Ordering::Release,
    );
    true
}

fn virtual_to_physical(virtual_address: u64, physical_memory_offset: u64) -> Option<u64> {
    let physical_memory_offset = VirtAddr::new(physical_memory_offset);
    let (level_4_frame, _) = Cr3::read();
    let table_address = physical_memory_offset
        .as_u64()
        .checked_add(level_4_frame.start_address().as_u64())?;
    // SAFETY: the bootloader's physical-memory mapping exposes the active level-4 frame, and this
    // function only translates a kernel-owned address during single-threaded initialization.
    let level_4_table = unsafe { &mut *(table_address as *mut PageTable) };
    // SAFETY: the level-4 table and physical-memory offset satisfy OffsetPageTable's contract.
    let mapper = unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) };
    mapper
        .translate_addr(VirtAddr::new(virtual_address))
        .map(|address| address.as_u64())
}

pub fn diagnostics() -> PowerDiagnostics {
    let pm1a_event_block = PM1A_EVENT_BLOCK.load(Ordering::Acquire);
    let pm1b_event_block = PM1B_EVENT_BLOCK.load(Ordering::Acquire);
    let pm1_event_length = PM1_EVENT_LENGTH.load(Ordering::Acquire);
    let sleep_type_s3_a = SLEEP_TYPE_S3_A.load(Ordering::Acquire);
    let sleep_type_s3_b = SLEEP_TYPE_S3_B.load(Ordering::Acquire);
    let pm1a_control_block = PM1A_CONTROL_BLOCK.load(Ordering::Acquire);
    let reset_register = RESET_REGISTER.load(Ordering::Acquire);
    let facs_address = FACS_PHYSICAL_ADDRESS.load(Ordering::Acquire);
    let facs_length = FACS_LENGTH.load(Ordering::Acquire);
    let facs_version = FACS_VERSION.load(Ordering::Acquire);
    let native_wake_ready = facs_version == FACS_VERSION_2
        && facs_supports_native_wake()
        && facs_length >= (FACS_X_FIRMWARE_WAKING_VECTOR_OFFSET + 8) as u32
        && facs_length >= (FACS_OSPM_FLAGS_OFFSET + 4) as u32
        && RESUME_NATIVE_TRAMPOLINE_PHYSICAL_ADDRESS.load(Ordering::Acquire) != 0;
    PowerDiagnostics {
        ready: pm1a_control_block != 0,
        suspend_ready: pm1a_event_block != 0
            && pm1_event_length >= 2
            && sleep_type_s3_a != INVALID_SLEEP_TYPE
            && sleep_type_s3_b != INVALID_SLEEP_TYPE
            && facs_address != 0
            && facs_length >= FACS_MINIMUM_LENGTH
            && RESUME_TRAMPOLINE_PHYSICAL_ADDRESS.load(Ordering::Acquire) != 0,
        native_wake_ready,
        reboot_ready: reset_register != 0,
        pm1a_event_block,
        pm1b_event_block,
        pm1_event_length,
        pm1a_control_block,
        pm1b_control_block: PM1B_CONTROL_BLOCK.load(Ordering::Acquire),
        sleep_type_a: SLEEP_TYPE_A.load(Ordering::Acquire),
        sleep_type_b: SLEEP_TYPE_B.load(Ordering::Acquire),
        sleep_type_s3_a: (sleep_type_s3_a != INVALID_SLEEP_TYPE).then_some(sleep_type_s3_a),
        sleep_type_s3_b: (sleep_type_s3_b != INVALID_SLEEP_TYPE).then_some(sleep_type_s3_b),
        facs_address,
        facs_length,
        facs_version,
        reset_register,
        reset_value: RESET_VALUE.load(Ordering::Acquire),
    }
}

pub fn suspend() -> bool {
    // The ACPI firmware resume vector enters the assembly trampoline after QEMU/firmware has
    // reset the CPU. That trampoline restores the suspended syscall's stack and return address,
    // so this wrapper resumes here only after the guest has actually re-entered long mode.
    let resumed = unsafe { rustos_suspend_entry() != 0 };
    let wake_confirmed = RESUME_WAKE_STATUS.swap(0, Ordering::AcqRel) != 0;
    if resumed && wake_confirmed {
        clear_facs_waking_vector();
    }
    resumed && wake_confirmed
}

fn prepare_suspend() -> bool {
    let diagnostics = diagnostics();
    let (Some(sleep_type_a), Some(sleep_type_b)) =
        (diagnostics.sleep_type_s3_a, diagnostics.sleep_type_s3_b)
    else {
        return false;
    };
    if !diagnostics.suspend_ready {
        return false;
    }

    let legacy_trampoline = RESUME_TRAMPOLINE_PHYSICAL_ADDRESS.load(Ordering::Acquire);
    let native_trampoline = RESUME_NATIVE_TRAMPOLINE_PHYSICAL_ADDRESS.load(Ordering::Acquire);
    let native_saved_cr3_operand =
        RESUME_NATIVE_SAVED_CR3_OPERAND_PHYSICAL_ADDRESS.load(Ordering::Acquire);
    let saved_cr3 = rustos_saved_cr3.load(Ordering::Acquire);
    if legacy_trampoline == 0
        || legacy_trampoline > u64::from(u32::MAX)
        || native_trampoline == 0
        || native_saved_cr3_operand == 0
        || saved_cr3 == 0
        || !write_facs_waking_vectors(legacy_trampoline, native_trampoline)
    {
        return false;
    }

    // The native vector runs with firmware paging still active, so it cannot safely dereference
    // the RustOS-owned saved-CR3 variable. Patch the immediate operand after the suspend entry has
    // captured the live CR3 and before firmware takes the machine into S3.
    // SAFETY: SMP setup reserved and identity-mapped the low page containing this operand.
    unsafe {
        write_unaligned(native_saved_cr3_operand as *mut u64, saved_cr3);
    }

    let value_a = (u16::from(sleep_type_a) << SLEEP_TYPE_SHIFT) | SLEEP_ENABLE;
    let value_b = (u16::from(sleep_type_b) << SLEEP_TYPE_SHIFT) | SLEEP_ENABLE;

    // SAFETY: the event and control ports come from the ACPI FADT's validated system-I/O blocks.
    unsafe {
        clear_wake_status(&diagnostics);
        write_cmos_s3_resume_status();
        let mut pm1a = Port::<u16>::new(diagnostics.pm1a_control_block as u16);
        pm1a.write(value_a);
        if diagnostics.pm1b_control_block != 0 {
            let mut pm1b = Port::<u16>::new(diagnostics.pm1b_control_block as u16);
            pm1b.write(value_b);
        }
    }
    true
}

fn facs_supports_native_wake() -> bool {
    let address = FACS_VIRTUAL_ADDRESS.load(Ordering::Acquire);
    let length = FACS_LENGTH.load(Ordering::Acquire);
    if address == 0
        || length < (FACS_FLAGS_OFFSET + 4) as u32
        || FACS_VERSION.load(Ordering::Acquire) != FACS_VERSION_2
    {
        return false;
    }
    let Some(flags_address) = address.checked_add(FACS_FLAGS_OFFSET as u64) else {
        return false;
    };
    // SAFETY: ACPI discovery validated the FACS signature and bounded this field inside the
    // firmware-owned structure exposed by the bootloader's physical-memory mapping.
    unsafe {
        core::ptr::read_volatile(flags_address as *const u32) & FACS_64BIT_WAKE_SUPPORTED_FLAG != 0
    }
}

unsafe fn write_cmos_s3_resume_status() {
    let mut index = Port::<u8>::new(CMOS_INDEX_PORT);
    let mut data = Port::<u8>::new(CMOS_DATA_PORT);
    // SAFETY: these are the legacy PC CMOS index/data ports, and the caller has disabled
    // interrupts for the S3 transition.
    unsafe {
        index.write(CMOS_SHUTDOWN_STATUS_INDEX);
        data.write(CMOS_S3_RESUME_STATUS);
    }
}

fn write_facs_waking_vectors(legacy_trampoline: u64, native_trampoline: u64) -> bool {
    let address = FACS_VIRTUAL_ADDRESS.load(Ordering::Acquire);
    let length = FACS_LENGTH.load(Ordering::Acquire);
    if address == 0 || length < FACS_MINIMUM_LENGTH {
        return false;
    }
    let Some(vector_address) = address.checked_add(FACS_FIRMWARE_WAKING_VECTOR_OFFSET as u64)
    else {
        return false;
    };
    // SAFETY: ACPI discovery validated the FACS signature and bounded length; the bootloader's
    // physical-memory mapping makes this firmware-owned structure writable.
    unsafe {
        core::ptr::write_volatile(vector_address as *mut u32, legacy_trampoline as u32);
        if length >= (FACS_X_FIRMWARE_WAKING_VECTOR_OFFSET + 8) as u32 {
            let x_vector_address = address + FACS_X_FIRMWARE_WAKING_VECTOR_OFFSET as u64;
            if facs_supports_native_wake() && length >= (FACS_OSPM_FLAGS_OFFSET + 4) as u32 {
                // The extended vector is a separate long-mode entry. The legacy vector remains
                // populated for SeaBIOS and other firmware that only implements the 16-bit path.
                core::ptr::write_volatile(x_vector_address as *mut u64, native_trampoline);
                let flags_address = address + FACS_OSPM_FLAGS_OFFSET as u64;
                let flags = core::ptr::read_volatile(flags_address as *const u32);
                core::ptr::write_volatile(
                    flags_address as *mut u32,
                    flags | FACS_OSPM_64BIT_WAKE_FLAG,
                );
            } else {
                core::ptr::write_volatile(x_vector_address as *mut u64, 0);
            }
        }
    }
    true
}

fn clear_facs_waking_vector() {
    let address = FACS_VIRTUAL_ADDRESS.load(Ordering::Acquire);
    let length = FACS_LENGTH.load(Ordering::Acquire);
    if address == 0 || length < FACS_MINIMUM_LENGTH {
        return;
    }
    // SAFETY: the vector was written by `write_facs_waking_vector` and remains within the
    // validated FACS allocation.
    unsafe {
        core::ptr::write_volatile(
            (address + FACS_FIRMWARE_WAKING_VECTOR_OFFSET as u64) as *mut u32,
            0,
        );
        if length >= (FACS_X_FIRMWARE_WAKING_VECTOR_OFFSET + 8) as u32 {
            core::ptr::write_volatile(
                (address + FACS_X_FIRMWARE_WAKING_VECTOR_OFFSET as u64) as *mut u64,
                0,
            );
        }
    }
}

pub fn poweroff() -> ! {
    let diagnostics = diagnostics();
    interrupts::disable();
    let value_a = (u16::from(diagnostics.sleep_type_a) << SLEEP_TYPE_SHIFT) | SLEEP_ENABLE;
    let value_b = (u16::from(diagnostics.sleep_type_b) << SLEEP_TYPE_SHIFT) | SLEEP_ENABLE;

    // SAFETY: the ports come from the ACPI FADT's validated system-I/O PM1 control blocks.
    unsafe {
        let mut pm1a = Port::<u16>::new(diagnostics.pm1a_control_block as u16);
        pm1a.write(value_a);
        if diagnostics.pm1b_control_block != 0 {
            let mut pm1b = Port::<u16>::new(diagnostics.pm1b_control_block as u16);
            pm1b.write(value_b);
        }
    }

    loop {
        crate::interrupts::halt();
    }
}

pub fn reboot() -> ! {
    let diagnostics = diagnostics();
    interrupts::disable();

    // SAFETY: the port and value come from the ACPI FADT reset-register GAS validated at boot.
    unsafe {
        let mut reset = Port::<u8>::new(diagnostics.reset_register as u16);
        reset.write(diagnostics.reset_value);
    }

    loop {
        crate::interrupts::halt();
    }
}

unsafe fn wake_status_is_set(diagnostics: &PowerDiagnostics) -> bool {
    let mut pm1a = Port::<u16>::new(diagnostics.pm1a_event_block as u16);
    if unsafe { pm1a.read() } & WAKE_STATUS != 0 {
        return true;
    }
    if diagnostics.pm1b_event_block != 0 {
        let mut pm1b = Port::<u16>::new(diagnostics.pm1b_event_block as u16);
        return unsafe { pm1b.read() } & WAKE_STATUS != 0;
    }
    false
}

unsafe fn clear_wake_status(diagnostics: &PowerDiagnostics) {
    let mut pm1a = Port::<u16>::new(diagnostics.pm1a_event_block as u16);
    unsafe { pm1a.write(WAKE_STATUS) };
    if diagnostics.pm1b_event_block != 0 {
        let mut pm1b = Port::<u16>::new(diagnostics.pm1b_event_block as u16);
        unsafe { pm1b.write(WAKE_STATUS) };
    }
}
