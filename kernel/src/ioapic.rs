use crate::acpi::{AcpiInfo, PhysicalMemory};

const IOAPIC_REGSEL: u64 = 0x000;
const IOAPIC_WINDOW: u64 = 0x010;
const IOAPIC_VERSION_REGISTER: u32 = 0x01;
const IOAPIC_REDIRECTION_BASE: u32 = 0x10;
const REDIRECTION_MASKED: u32 = 1 << 16;
const REDIRECTION_ACTIVE_LOW: u32 = 1 << 13;
const REDIRECTION_LEVEL_TRIGGERED: u32 = 1 << 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoApicError {
    MissingController,
    InvalidAddress,
    GsiOutOfRange,
    InvalidVersion,
    MissingLocalApicId,
    InvalidVector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicStats {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub id: u8,
    pub version: u32,
    pub redirection_entries: u32,
    pub timer_gsi: u32,
    pub timer_vector: u8,
    pub destination_apic_id: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicRoute {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub gsi: u32,
    pub vector: u8,
    pub destination_apic_id: u8,
    version: u32,
    redirection_entries: u32,
    redirection_low_register: u32,
    low_value: u32,
}

impl IoApicRoute {
    pub fn version(self) -> u32 {
        self.version
    }

    pub fn redirection_entries(self) -> u32 {
        self.redirection_entries
    }

    pub fn unmask(self) {
        // SAFETY: this route was created from the ACPI-described IO-APIC mapping, and the low
        // register was written while masked before the route was returned.
        unsafe {
            write_register(
                self.virtual_base,
                self.redirection_low_register,
                self.low_value & !REDIRECTION_MASKED,
            );
        }
    }
}

pub fn init(memory: PhysicalMemory, info: &AcpiInfo) -> Result<IoApicStats, IoApicError> {
    let route = route_gsi(
        memory,
        info,
        info.timer_gsi,
        crate::interrupts::IO_APIC_TIMER_VECTOR,
        info.timer_flags,
    )?;
    route.unmask();

    Ok(IoApicStats {
        physical_base: route.physical_base,
        virtual_base: route.virtual_base,
        id: info.io_apic.ok_or(IoApicError::MissingController)?.id,
        version: route.version(),
        redirection_entries: route.redirection_entries(),
        timer_gsi: route.gsi,
        timer_vector: route.vector,
        destination_apic_id: route.destination_apic_id,
    })
}

pub fn mask_gsi(
    memory: PhysicalMemory,
    info: &AcpiInfo,
    gsi: u32,
    flags: u16,
) -> Result<(), IoApicError> {
    // The vector is irrelevant while the route is masked; using the first post-exception vector
    // keeps this helper independent of any device-handler allocation.
    let _ = route_gsi(memory, info, gsi, 32, flags)?;
    Ok(())
}

pub fn route_gsi(
    memory: PhysicalMemory,
    info: &AcpiInfo,
    gsi: u32,
    vector: u8,
    flags: u16,
) -> Result<IoApicRoute, IoApicError> {
    if vector < 32 {
        return Err(IoApicError::InvalidVector);
    }

    let controller = info.io_apic.ok_or(IoApicError::MissingController)?;
    let virtual_base = memory
        .virtual_address(controller.address)
        .ok_or(IoApicError::InvalidAddress)?;
    virtual_base
        .checked_add(IOAPIC_WINDOW)
        .ok_or(IoApicError::InvalidAddress)?;

    let version = unsafe { read_register(virtual_base, IOAPIC_VERSION_REGISTER) };
    let redirection_entries = ((version >> 16) & 0xff) + 1;
    if redirection_entries == 0 {
        return Err(IoApicError::InvalidVersion);
    }

    let gsi_index = gsi
        .checked_sub(controller.gsi_base)
        .ok_or(IoApicError::GsiOutOfRange)?;
    if gsi_index >= redirection_entries {
        return Err(IoApicError::GsiOutOfRange);
    }
    let destination_apic_id =
        crate::apic::local_apic_id().ok_or(IoApicError::MissingLocalApicId)?;
    let redirection_low_register = IOAPIC_REDIRECTION_BASE + gsi_index * 2;
    let redirection_high_register = redirection_low_register + 1;
    let mut low = u32::from(vector) | REDIRECTION_MASKED;
    if flags & 0b11 == 0b11 {
        low |= REDIRECTION_ACTIVE_LOW;
    }
    if flags & 0b1100 == 0b1100 {
        low |= REDIRECTION_LEVEL_TRIGGERED;
    }

    // SAFETY: the MADT supplied this MMIO range, and the redirection entry is masked while its
    // destination and trigger settings are changed.
    unsafe {
        write_register(
            virtual_base,
            redirection_high_register,
            u32::from(destination_apic_id) << 24,
        );
        write_register(virtual_base, redirection_low_register, low);
    }

    Ok(IoApicRoute {
        physical_base: controller.address,
        virtual_base,
        gsi,
        vector,
        destination_apic_id,
        version,
        redirection_entries,
        redirection_low_register,
        low_value: low,
    })
}

unsafe fn read_register(base: u64, register: u32) -> u32 {
    // SAFETY: the caller validated the MMIO base from ACPI and uses an IO-APIC register index.
    unsafe {
        core::ptr::write_volatile((base + IOAPIC_REGSEL) as *mut u32, register);
        core::ptr::read_volatile((base + IOAPIC_WINDOW) as *const u32)
    }
}

unsafe fn write_register(base: u64, register: u32, value: u32) {
    // SAFETY: the caller validated the MMIO base from ACPI and uses an IO-APIC register index.
    unsafe {
        core::ptr::write_volatile((base + IOAPIC_REGSEL) as *mut u32, register);
        core::ptr::write_volatile((base + IOAPIC_WINDOW) as *mut u32, value);
    }
}
