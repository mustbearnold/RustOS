use core::sync::atomic::{AtomicU64, Ordering};

use crate::acpi::{AcpiInfo, PhysicalMemory};

const APIC_VERSION: u64 = 0x030;
const APIC_ID: u64 = 0x020;
const APIC_ICR_LOW: u64 = 0x300;
const APIC_ICR_HIGH: u64 = 0x310;
const APIC_EOI: u64 = 0x0b0;
const APIC_SPURIOUS_VECTOR: u64 = 0x0f0;
const APIC_LVT_TIMER: u64 = 0x320;
const APIC_TIMER_INITIAL_COUNT: u64 = 0x380;
const APIC_TIMER_DIVIDE_CONFIG: u64 = 0x3e0;
const APIC_ENABLE_BIT: u32 = 1 << 8;
const APIC_TIMER_PERIODIC: u32 = 1 << 17;
const APIC_TIMER_MASKED: u32 = 1 << 16;
const APIC_ICR_DELIVERY_STATUS: u32 = 1 << 12;
const APIC_ICR_LEVEL_ASSERT: u32 = 1 << 14;
const APIC_ICR_TRIGGER_LEVEL: u32 = 1 << 15;
const APIC_ICR_INIT: u32 = 0x500;
const APIC_ICR_STARTUP: u32 = 0x600;
const TIMER_INITIAL_COUNT: u32 = 1_000_000;
const ICR_WAIT_SPINS: usize = 1_000_000;
const INIT_TO_SIPI_SPINS: usize = 1_000_000;
const SIPI_TO_SIPI_SPINS: usize = 10_000;

static APIC_VIRTUAL_BASE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicError {
    InvalidAddress,
    UnsupportedDestination,
    IcrTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApicStats {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub version: u32,
    pub processor_count: u32,
    pub enabled_processor_count: u32,
    pub io_apic_count: u32,
    pub timer_initial_count: u32,
}

pub fn init(memory: PhysicalMemory, info: &AcpiInfo) -> Result<ApicStats, ApicError> {
    let virtual_base = memory
        .virtual_address(info.local_apic_address)
        .ok_or(ApicError::InvalidAddress)?;
    for offset in [
        APIC_VERSION,
        APIC_ICR_LOW,
        APIC_ICR_HIGH,
        APIC_EOI,
        APIC_SPURIOUS_VECTOR,
        APIC_LVT_TIMER,
        APIC_TIMER_INITIAL_COUNT,
        APIC_TIMER_DIVIDE_CONFIG,
    ] {
        virtual_base
            .checked_add(offset)
            .ok_or(ApicError::InvalidAddress)?;
    }

    let version = unsafe { read_register(virtual_base, APIC_VERSION) };
    APIC_VIRTUAL_BASE.store(virtual_base, Ordering::SeqCst);

    // SAFETY: the MADT supplied the local APIC MMIO base and the bootloader mapped all physical
    // memory at the configured offset. Interrupts are still disabled during this setup.
    unsafe {
        write_register(virtual_base, APIC_SPURIOUS_VECTOR, APIC_ENABLE_BIT | 0xff);
        write_register(virtual_base, APIC_TIMER_DIVIDE_CONFIG, 0x0b);
        write_register(
            virtual_base,
            APIC_LVT_TIMER,
            u32::from(crate::interrupts::LOCAL_APIC_TIMER_VECTOR) | APIC_TIMER_MASKED,
        );
        write_register(virtual_base, APIC_TIMER_INITIAL_COUNT, TIMER_INITIAL_COUNT);
        write_register(
            virtual_base,
            APIC_LVT_TIMER,
            u32::from(crate::interrupts::LOCAL_APIC_TIMER_VECTOR) | APIC_TIMER_PERIODIC,
        );
    }

    Ok(ApicStats {
        physical_base: info.local_apic_address,
        virtual_base,
        version,
        processor_count: info.processor_count,
        enabled_processor_count: info.enabled_processor_count,
        io_apic_count: info.io_apic_count,
        timer_initial_count: TIMER_INITIAL_COUNT,
    })
}

pub fn end_of_interrupt() {
    let virtual_base = APIC_VIRTUAL_BASE.load(Ordering::SeqCst);
    if virtual_base != 0 {
        // SAFETY: the base is written only after successful MMIO validation in `init`.
        unsafe { write_register(virtual_base, APIC_EOI, 0) };
    }
}

pub fn local_apic_id() -> Option<u8> {
    local_apic_id_u32().map(|id| id as u8)
}

pub fn local_apic_id_u32() -> Option<u32> {
    let virtual_base = APIC_VIRTUAL_BASE.load(Ordering::SeqCst);
    if virtual_base == 0 {
        return None;
    }
    Some(unsafe { read_register(virtual_base, APIC_ID) >> 24 })
}

pub fn init_application_processor() {
    let virtual_base = APIC_VIRTUAL_BASE.load(Ordering::SeqCst);
    if virtual_base == 0 {
        return;
    }

    // SAFETY: the BSP validated this MMIO mapping during APIC initialization. INIT resets the AP's
    // local APIC state, so each AP must enable its spurious vector and mask its timer independently.
    unsafe {
        write_register(virtual_base, APIC_SPURIOUS_VECTOR, APIC_ENABLE_BIT | 0xff);
        write_register(
            virtual_base,
            APIC_LVT_TIMER,
            u32::from(crate::interrupts::LOCAL_APIC_TIMER_VECTOR) | APIC_TIMER_MASKED,
        );
        write_register(virtual_base, APIC_EOI, 0);
    }
}

pub fn enable_local_timer() {
    let virtual_base = APIC_VIRTUAL_BASE.load(Ordering::SeqCst);
    if virtual_base == 0 {
        return;
    }

    // SAFETY: the BSP validated this MMIO mapping during APIC initialization. Reprogramming the
    // timer is required after INIT, which resets the AP's local-vector-table state.
    unsafe {
        write_register(virtual_base, APIC_TIMER_DIVIDE_CONFIG, 0x0b);
        write_register(virtual_base, APIC_TIMER_INITIAL_COUNT, TIMER_INITIAL_COUNT);
        write_register(
            virtual_base,
            APIC_LVT_TIMER,
            u32::from(crate::interrupts::LOCAL_APIC_TIMER_VECTOR) | APIC_TIMER_PERIODIC,
        );
    }
}

pub fn start_application_processor(destination: u32, startup_vector: u8) -> Result<(), ApicError> {
    if destination > u32::from(u8::MAX) {
        return Err(ApicError::UnsupportedDestination);
    }
    let virtual_base = APIC_VIRTUAL_BASE.load(Ordering::SeqCst);
    if virtual_base == 0 {
        return Err(ApicError::InvalidAddress);
    }

    // SAFETY: the BSP validated the local APIC MMIO mapping during initialization; interrupts are
    // disabled while the INIT/SIPI sequence is sent to the selected AP.
    unsafe {
        write_register(virtual_base, APIC_ICR_HIGH, destination << 24);
        write_register(
            virtual_base,
            APIC_ICR_LOW,
            APIC_ICR_INIT | APIC_ICR_LEVEL_ASSERT | APIC_ICR_TRIGGER_LEVEL,
        );
        wait_for_icr_idle(virtual_base)?;
        write_register(
            virtual_base,
            APIC_ICR_LOW,
            APIC_ICR_INIT | APIC_ICR_TRIGGER_LEVEL,
        );
        wait_for_icr_idle(virtual_base)?;
    }
    delay(INIT_TO_SIPI_SPINS);

    // The vector selects a 4 KiB-aligned real-mode entry point below 1 MiB. Two SIPIs are sent as
    // required by the x86 multiprocessor startup protocol; an AP that already accepted the first
    // SIPI ignores the duplicate.
    for _ in 0..2 {
        // SAFETY: the APIC mapping and destination were validated above.
        unsafe {
            write_register(
                virtual_base,
                APIC_ICR_LOW,
                APIC_ICR_STARTUP | u32::from(startup_vector),
            );
            wait_for_icr_idle(virtual_base)?;
        }
        delay(SIPI_TO_SIPI_SPINS);
    }
    Ok(())
}

unsafe fn wait_for_icr_idle(virtual_base: u64) -> Result<(), ApicError> {
    for _ in 0..ICR_WAIT_SPINS {
        // SAFETY: the caller supplies the validated local APIC mapping.
        if unsafe { read_register(virtual_base, APIC_ICR_LOW) } & APIC_ICR_DELIVERY_STATUS == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(ApicError::IcrTimeout)
}

fn delay(spins: usize) {
    for _ in 0..spins {
        core::hint::spin_loop();
    }
}

unsafe fn read_register(base: u64, offset: u64) -> u32 {
    // SAFETY: callers provide a validated local APIC MMIO address and register offset.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

unsafe fn write_register(base: u64, offset: u64, value: u32) {
    // SAFETY: callers provide a validated local APIC MMIO address and register offset.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, value) };
}
