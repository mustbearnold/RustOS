use alloc::vec::Vec;

use x86_64::instructions::port::Port;

const CONFIG_ADDRESS_PORT: u16 = 0xcf8;
const CONFIG_DATA_PORT: u16 = 0xcfc;
const CONFIG_ENABLE: u32 = 1 << 31;
const MAX_DEVICES: usize = 4096;
const PCI_STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
const PCI_CAPABILITY_POINTER: u8 = 0x34;
const PCI_CAPABILITY_MSI: u8 = 0x05;
const PCI_CAPABILITY_VENDOR_SPECIFIC: u8 = 0x09;
const PCI_CAPABILITY_MSIX: u8 = 0x11;
const MAX_CAPABILITIES: usize = 48;
const PCI_COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;
const MSI_ENABLE: u16 = 1 << 0;
const MSI_MULTIPLE_MESSAGE_ENABLE_MASK: u16 = 0b111 << 4;
const MSI_64_BIT_CAPABLE: u16 = 1 << 7;
const MSI_PER_VECTOR_MASKING_CAPABLE: u16 = 1 << 8;
const MSIX_ENABLE: u16 = 1 << 15;
const MSIX_FUNCTION_MASK: u16 = 1 << 14;
const MSIX_TABLE_BAR_MASK: u32 = 0x07;
const MSIX_TABLE_OFFSET_MASK: u32 = !MSIX_TABLE_BAR_MASK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciError {
    TooManyDevices { limit: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciBar {
    Unassigned,
    Unused,
    Io { base: u16 },
    Memory32 { base: u32, prefetchable: bool },
    Memory64 { base: u64, prefetchable: bool },
    UpperHalf,
    Unsupported { raw: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciClass {
    Unclassified,
    MassStorage,
    Network,
    Display,
    Multimedia,
    Memory,
    Bridge,
    Communication,
    SystemPeripheral,
    Input,
    Docking,
    Processor,
    SerialBus,
    Wireless,
    IntelligentIo,
    Satellite,
    Encryption,
    SignalProcessing,
    ProcessingAccelerator,
    NonEssentialInstrumentation,
    Other(u8),
}

impl PciClass {
    fn from_code(code: u8) -> Self {
        match code {
            0x00 => Self::Unclassified,
            0x01 => Self::MassStorage,
            0x02 => Self::Network,
            0x03 => Self::Display,
            0x04 => Self::Multimedia,
            0x05 => Self::Memory,
            0x06 => Self::Bridge,
            0x07 => Self::Communication,
            0x08 => Self::SystemPeripheral,
            0x09 => Self::Input,
            0x0a => Self::Docking,
            0x0b => Self::Processor,
            0x0c => Self::SerialBus,
            0x0d => Self::Wireless,
            0x0e => Self::IntelligentIo,
            0x0f => Self::Satellite,
            0x10 => Self::Encryption,
            0x11 => Self::SignalProcessing,
            0x12 => Self::ProcessingAccelerator,
            0x13 => Self::NonEssentialInstrumentation,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverKind {
    HostBridge,
    IsaBridge,
    PciBridge,
    MassStorage,
    Network,
    Display,
    Audio,
    Usb,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciMsiCapability {
    pub offset: u8,
    pub is_64_bit: bool,
    pub multiple_message_capable: u8,
    pub per_vector_masking: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciMsixCapability {
    pub offset: u8,
    pub table_size: u16,
    pub function_masked: bool,
    pub table_bar: u8,
    pub table_offset: u32,
    pub pba_bar: u8,
    pub pba_offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciVirtioCapability {
    pub offset: u8,
    pub cfg_type: u8,
    pub bar: u8,
    pub region_offset: u32,
    pub region_length: u32,
    pub notify_off_multiplier: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciCapabilities {
    pub msi: Option<PciMsiCapability>,
    pub msix: Option<PciMsixCapability>,
    pub virtio: [Option<PciVirtioCapability>; 5],
}

impl PciCapabilities {
    const fn empty() -> Self {
        Self {
            msi: None,
            msix: None,
            virtio: [None; 5],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciInterruptMode {
    None,
    Legacy,
    Msi,
    Msix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciMsiRoute {
    pub capability_offset: u8,
    pub address: u64,
    pub data: u16,
    pub destination_apic_id: u32,
    pub vector: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciMsixRoute {
    pub capability_offset: u8,
    pub table_bar: u8,
    pub table_offset: u32,
    pub address: u64,
    pub data: u16,
    pub destination_apic_id: u32,
    pub vector: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciResourceError {
    BarIndexOutOfRange { index: usize },
    BarAlreadyClaimed { index: usize },
    NotMemoryBar { index: usize },
    NotIoBar { index: usize },
    InvalidLength,
    AddressOverflow,
    BusMasterEnableFailed,
    MsiNotSupported,
    MsixNotSupported,
    InvalidMsiVector { vector: u8 },
    MsiDestinationOutOfRange { destination: u32 },
    MsiConfigurationFailed,
    LegacyInterruptEnableFailed,
    InvalidMsixTable,
    MsixConfigurationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioError {
    UnalignedOffset { offset: u64 },
    OutOfRange { offset: u64, length: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoPortError {
    UnalignedOffset { offset: u64 },
    OutOfRange { offset: u64, length: u64 },
    PortAddressOverflow { offset: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision_id: u8,
    pub prog_if: u8,
    pub command: u16,
    pub status: u16,
    pub subclass: u8,
    pub class_code: u8,
    pub header_type: u8,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub bars: [PciBar; 6],
    pub capabilities: PciCapabilities,
}

impl PciDevice {
    pub fn class(self) -> PciClass {
        PciClass::from_code(self.class_code)
    }

    pub fn driver_kind(self) -> DriverKind {
        match (self.class_code, self.subclass) {
            (0x06, 0x00) => DriverKind::HostBridge,
            (0x06, 0x01) => DriverKind::IsaBridge,
            (0x06, 0x04 | 0x09 | 0x0a) => DriverKind::PciBridge,
            (0x01, _) => DriverKind::MassStorage,
            (0x02, _) => DriverKind::Network,
            (0x03, _) => DriverKind::Display,
            (0x04, _) => DriverKind::Audio,
            (0x0c, 0x03) => DriverKind::Usb,
            _ => DriverKind::Generic,
        }
    }

    pub fn is_multifunction(self) -> bool {
        self.header_type & 0x80 != 0
    }

    pub fn memory_space_enabled(self) -> bool {
        self.command & (1 << 1) != 0
    }

    pub fn bus_master_enabled(self) -> bool {
        self.command & (1 << 2) != 0
    }

    pub fn msi_capability(self) -> Option<PciMsiCapability> {
        self.capabilities.msi
    }

    pub fn virtio_capability(self, cfg_type: u8) -> Option<PciVirtioCapability> {
        self.capabilities
            .virtio
            .get(usize::from(cfg_type.saturating_sub(1)))
            .copied()
            .flatten()
            .filter(|capability| capability.cfg_type == cfg_type)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MmioRegion {
    physical_base: u64,
    virtual_base: u64,
    length: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct IoRegion {
    base: u16,
    length: u64,
}

impl IoRegion {
    pub fn base(self) -> u16 {
        self.base
    }

    pub fn read_u8(self, offset: u64) -> Result<u8, IoPortError> {
        let port = self.validate(offset, 1, 1)?;

        // SAFETY: the region is created only from a validated PCI I/O BAR and bounds-checks
        // every offset before exposing a volatile port read to a driver.
        Ok(unsafe { Port::<u8>::new(port).read() })
    }

    pub fn read_u16(self, offset: u64) -> Result<u16, IoPortError> {
        let port = self.validate(offset, 2, 2)?;

        // SAFETY: the region is created only from a validated PCI I/O BAR and bounds-checks
        // every offset before exposing a volatile port read to a driver.
        Ok(unsafe { Port::<u16>::new(port).read() })
    }

    pub fn write_u8(self, offset: u64, value: u8) -> Result<(), IoPortError> {
        let port = self.validate(offset, 1, 1)?;

        // SAFETY: the region is created only from a validated PCI I/O BAR and bounds-checks
        // every offset before exposing a volatile port write to a driver.
        unsafe { Port::<u8>::new(port).write(value) };
        Ok(())
    }

    pub fn write_u16(self, offset: u64, value: u16) -> Result<(), IoPortError> {
        let port = self.validate(offset, 2, 2)?;

        // SAFETY: the region is created only from a validated PCI I/O BAR and bounds-checks
        // every offset before exposing a volatile port write to a driver.
        unsafe { Port::<u16>::new(port).write(value) };
        Ok(())
    }

    pub fn write_u32(self, offset: u64, value: u32) -> Result<(), IoPortError> {
        let port = self.validate(offset, 4, 4)?;

        // SAFETY: the region is created only from a validated PCI I/O BAR and bounds-checks
        // every offset before exposing a volatile port write to a driver.
        unsafe { Port::<u32>::new(port).write(value) };
        Ok(())
    }

    fn validate(self, offset: u64, size: u64, alignment: u64) -> Result<u16, IoPortError> {
        if offset % alignment != 0 {
            return Err(IoPortError::UnalignedOffset { offset });
        }
        let end = offset.checked_add(size).ok_or(IoPortError::OutOfRange {
            offset,
            length: self.length,
        })?;
        if end > self.length {
            return Err(IoPortError::OutOfRange {
                offset,
                length: self.length,
            });
        }
        let offset =
            u16::try_from(offset).map_err(|_| IoPortError::PortAddressOverflow { offset })?;
        self.base
            .checked_add(offset)
            .ok_or(IoPortError::PortAddressOverflow {
                offset: u64::from(offset),
            })
    }
}

impl MmioRegion {
    pub fn physical_base(self) -> u64 {
        self.physical_base
    }

    pub fn length(self) -> u64 {
        self.length
    }

    pub fn read_u8(self, offset: u64) -> Result<u8, MmioError> {
        self.validate(offset, 1, 1)?;

        // SAFETY: the region is created only from a validated PCI memory BAR and bounds-checks
        // every offset before exposing a volatile register read to a driver.
        Ok(unsafe { core::ptr::read_volatile((self.virtual_base + offset) as *const u8) })
    }

    pub fn read_u16(self, offset: u64) -> Result<u16, MmioError> {
        self.validate(offset, 2, 2)?;

        // SAFETY: the region is created only from a validated PCI memory BAR and bounds-checks
        // every offset before exposing a volatile register read to a driver.
        Ok(unsafe { core::ptr::read_volatile((self.virtual_base + offset) as *const u16) })
    }

    pub fn read_u32(self, offset: u64) -> Result<u32, MmioError> {
        self.validate(offset, 4, 4)?;

        // SAFETY: the region is created only from a validated PCI memory BAR and bounds-checks
        // every offset before exposing a volatile register read to a driver.
        Ok(unsafe { core::ptr::read_volatile((self.virtual_base + offset) as *const u32) })
    }

    pub fn write_u8(self, offset: u64, value: u8) -> Result<(), MmioError> {
        self.validate(offset, 1, 1)?;

        // SAFETY: the region is created only from a validated PCI memory BAR and bounds-checks
        // every offset before exposing a volatile register write to a driver.
        unsafe { core::ptr::write_volatile((self.virtual_base + offset) as *mut u8, value) };
        Ok(())
    }

    pub fn write_u16(self, offset: u64, value: u16) -> Result<(), MmioError> {
        self.validate(offset, 2, 2)?;

        // SAFETY: the region is created only from a validated PCI memory BAR and bounds-checks
        // every offset before exposing a volatile register write to a driver.
        unsafe { core::ptr::write_volatile((self.virtual_base + offset) as *mut u16, value) };
        Ok(())
    }

    pub fn write_u32(self, offset: u64, value: u32) -> Result<(), MmioError> {
        self.validate(offset, 4, 4)?;

        // SAFETY: the region is created only from a validated PCI memory BAR and bounds-checks
        // every offset before exposing a volatile register write to a driver.
        unsafe { core::ptr::write_volatile((self.virtual_base + offset) as *mut u32, value) };
        Ok(())
    }

    fn validate(self, offset: u64, size: u64, alignment: u64) -> Result<(), MmioError> {
        if offset % alignment != 0 {
            return Err(MmioError::UnalignedOffset { offset });
        }
        let end = offset.checked_add(size).ok_or(MmioError::OutOfRange {
            offset,
            length: self.length,
        })?;
        if end > self.length {
            return Err(MmioError::OutOfRange {
                offset,
                length: self.length,
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PciDeviceResources {
    device: PciDevice,
    physical_memory_offset: u64,
    claimed_bars: u8,
}

impl PciDeviceResources {
    pub fn new(device: PciDevice, physical_memory_offset: u64) -> Self {
        Self {
            device,
            physical_memory_offset,
            claimed_bars: 0,
        }
    }

    pub fn device(&self) -> PciDevice {
        self.device
    }

    pub fn claim_mmio(
        &mut self,
        index: usize,
        length: u64,
    ) -> Result<MmioRegion, PciResourceError> {
        let bit = self.bar_bit(index)?;
        if self.claimed_bars & bit != 0 {
            return Err(PciResourceError::BarAlreadyClaimed { index });
        }
        let region = self.mmio_region(index, 0, length)?;
        self.claimed_bars |= bit;
        Ok(region)
    }

    pub fn claim_mmio_subregion(
        &mut self,
        index: usize,
        offset: u64,
        length: u64,
    ) -> Result<MmioRegion, PciResourceError> {
        let bit = self.bar_bit(index)?;
        let region = self.mmio_region(index, offset, length)?;
        // A device's MSI-X table commonly lives in the same BAR as its register block. A
        // subregion is therefore allowed to share an already-claimed BAR, but is still recorded
        // as claimed when it is the first user of that BAR.
        self.claimed_bars |= bit;
        Ok(region)
    }

    pub fn claim_io(&mut self, index: usize, length: u64) -> Result<IoRegion, PciResourceError> {
        let bit = self.bar_bit(index)?;
        if self.claimed_bars & bit != 0 {
            return Err(PciResourceError::BarAlreadyClaimed { index });
        }
        let region = self.io_region(index, 0, length)?;
        self.claimed_bars |= bit;
        Ok(region)
    }

    fn bar_bit(&self, index: usize) -> Result<u8, PciResourceError> {
        1u8.checked_shl(u32::try_from(index).unwrap_or(u32::MAX))
            .ok_or(PciResourceError::BarIndexOutOfRange { index })
    }

    fn mmio_region(
        &self,
        index: usize,
        offset: u64,
        length: u64,
    ) -> Result<MmioRegion, PciResourceError> {
        if length == 0 {
            return Err(PciResourceError::InvalidLength);
        }
        let bar = self
            .device
            .bars
            .get(index)
            .ok_or(PciResourceError::BarIndexOutOfRange { index })?;
        let bar_base = match bar {
            PciBar::Memory32 { base, .. } => u64::from(*base),
            PciBar::Memory64 { base, .. } => *base,
            _ => return Err(PciResourceError::NotMemoryBar { index }),
        };
        let physical_base = bar_base
            .checked_add(offset)
            .ok_or(PciResourceError::AddressOverflow)?;
        physical_base
            .checked_add(length)
            .ok_or(PciResourceError::AddressOverflow)?;
        let virtual_base = self
            .physical_memory_offset
            .checked_add(physical_base)
            .ok_or(PciResourceError::AddressOverflow)?;
        virtual_base
            .checked_add(length)
            .ok_or(PciResourceError::AddressOverflow)?;

        Ok(MmioRegion {
            physical_base,
            virtual_base,
            length,
        })
    }

    fn io_region(
        &self,
        index: usize,
        offset: u64,
        length: u64,
    ) -> Result<IoRegion, PciResourceError> {
        if length == 0 {
            return Err(PciResourceError::InvalidLength);
        }
        let bar = self
            .device
            .bars
            .get(index)
            .ok_or(PciResourceError::BarIndexOutOfRange { index })?;
        let base = match bar {
            PciBar::Io { base } => u64::from(*base),
            _ => return Err(PciResourceError::NotIoBar { index }),
        };
        let physical_base = base
            .checked_add(offset)
            .ok_or(PciResourceError::AddressOverflow)?;
        let end = physical_base
            .checked_add(length)
            .ok_or(PciResourceError::AddressOverflow)?;
        if end > 0x1_0000 {
            return Err(PciResourceError::AddressOverflow);
        }

        Ok(IoRegion {
            base: u16::try_from(physical_base).map_err(|_| PciResourceError::AddressOverflow)?,
            length,
        })
    }

    pub fn enable_bus_master(&mut self) -> Result<(), PciResourceError> {
        if self.device.bus_master_enabled() {
            return Ok(());
        }

        let mut config = LegacyConfigAccess::new();
        let command = config.read_u16(self.device.address, 0x04);
        let updated_command = command | (1 << 2);
        config.write_u16(self.device.address, 0x04, updated_command);
        let read_back = config.read_u16(self.device.address, 0x04);
        if read_back & (1 << 2) == 0 {
            return Err(PciResourceError::BusMasterEnableFailed);
        }
        self.device.command = read_back;
        Ok(())
    }

    pub fn enable_legacy_interrupts(&mut self) -> Result<(), PciResourceError> {
        let mut config = LegacyConfigAccess::new();
        let command = config.read_u16(self.device.address, 0x04);
        let updated_command = command & !PCI_COMMAND_INTERRUPT_DISABLE;
        config.write_u16(self.device.address, 0x04, updated_command);
        let read_back = config.read_u16(self.device.address, 0x04);
        if read_back & PCI_COMMAND_INTERRUPT_DISABLE != 0 {
            return Err(PciResourceError::LegacyInterruptEnableFailed);
        }
        self.device.command = read_back;
        Ok(())
    }

    pub fn enable_msi(
        &mut self,
        vector: u8,
        destination_apic_id: u32,
    ) -> Result<PciMsiRoute, PciResourceError> {
        let capability = self
            .device
            .msi_capability()
            .ok_or(PciResourceError::MsiNotSupported)?;
        let (message_address, message_data) = msi_message(vector, destination_apic_id)?;
        let control_offset = capability
            .offset
            .checked_add(2)
            .ok_or(PciResourceError::AddressOverflow)?;
        let address_offset = capability
            .offset
            .checked_add(4)
            .ok_or(PciResourceError::AddressOverflow)?;
        let data_offset = capability
            .offset
            .checked_add(if capability.is_64_bit { 12 } else { 8 })
            .ok_or(PciResourceError::AddressOverflow)?;

        let mut config = LegacyConfigAccess::new();
        let control = config.read_u16(self.device.address, control_offset);
        // Program a single-vector message while MSI is disabled. The device's capability bits
        // remain untouched; only the message-enable and multiple-message-enable bits are changed.
        let disabled_control = control & !(MSI_ENABLE | MSI_MULTIPLE_MESSAGE_ENABLE_MASK);
        config.write_u16(self.device.address, control_offset, disabled_control);
        config.write_u32(self.device.address, address_offset, message_address as u32);
        if capability.is_64_bit {
            let high_address_offset = address_offset
                .checked_add(4)
                .ok_or(PciResourceError::AddressOverflow)?;
            config.write_u32(
                self.device.address,
                high_address_offset,
                (message_address >> 32) as u32,
            );
        }
        config.write_u16(self.device.address, data_offset, message_data);
        if capability.per_vector_masking {
            let mask_offset = data_offset
                .checked_add(4)
                .ok_or(PciResourceError::AddressOverflow)?;
            config.write_u32(self.device.address, mask_offset, 0);
        }
        config.write_u16(
            self.device.address,
            control_offset,
            disabled_control | MSI_ENABLE,
        );
        let read_back = config.read_u16(self.device.address, control_offset);
        if read_back & MSI_ENABLE == 0 {
            return Err(PciResourceError::MsiConfigurationFailed);
        }

        Ok(PciMsiRoute {
            capability_offset: capability.offset,
            address: message_address,
            data: message_data,
            destination_apic_id,
            vector,
        })
    }

    pub fn enable_msix(
        &mut self,
        vector: u8,
        destination_apic_id: u32,
    ) -> Result<PciMsixRoute, PciResourceError> {
        let capability = self
            .device
            .capabilities
            .msix
            .ok_or(PciResourceError::MsixNotSupported)?;
        if capability.table_size == 0 || capability.table_bar >= 6 {
            return Err(PciResourceError::InvalidMsixTable);
        }
        let (message_address, message_data) = msi_message(vector, destination_apic_id)?;
        let table = self.claim_mmio_subregion(
            usize::from(capability.table_bar),
            u64::from(capability.table_offset),
            16,
        )?;
        let control_offset = capability
            .offset
            .checked_add(2)
            .ok_or(PciResourceError::AddressOverflow)?;
        let mut config = LegacyConfigAccess::new();
        let control = config.read_u16(self.device.address, control_offset);
        let masked_control = (control & !MSIX_ENABLE) | MSIX_FUNCTION_MASK;
        config.write_u16(self.device.address, control_offset, masked_control);

        table
            .write_u32(0, message_address as u32)
            .map_err(|_| PciResourceError::MsixConfigurationFailed)?;
        table
            .write_u32(4, (message_address >> 32) as u32)
            .map_err(|_| PciResourceError::MsixConfigurationFailed)?;
        table
            .write_u32(8, u32::from(message_data))
            .map_err(|_| PciResourceError::MsixConfigurationFailed)?;
        table
            .write_u32(12, 0)
            .map_err(|_| PciResourceError::MsixConfigurationFailed)?;

        let enabled_control = (masked_control & !MSIX_FUNCTION_MASK) | MSIX_ENABLE;
        config.write_u16(self.device.address, control_offset, enabled_control);
        let read_back = config.read_u16(self.device.address, control_offset);
        if read_back & MSIX_ENABLE == 0 || read_back & MSIX_FUNCTION_MASK != 0 {
            return Err(PciResourceError::MsixConfigurationFailed);
        }

        Ok(PciMsixRoute {
            capability_offset: capability.offset,
            table_bar: capability.table_bar,
            table_offset: capability.table_offset,
            address: message_address,
            data: message_data,
            destination_apic_id,
            vector,
        })
    }
}

fn msi_message(vector: u8, destination_apic_id: u32) -> Result<(u64, u16), PciResourceError> {
    if vector < 32 {
        return Err(PciResourceError::InvalidMsiVector { vector });
    }
    if destination_apic_id > u32::from(u8::MAX) {
        return Err(PciResourceError::MsiDestinationOutOfRange {
            destination: destination_apic_id,
        });
    }
    Ok((
        0xfee0_0000u64 | (u64::from(destination_apic_id) << 12),
        u16::from(vector),
    ))
}

#[derive(Debug)]
pub struct PciInventory {
    scanned_buses: u16,
    devices: Vec<PciDevice>,
}

impl PciInventory {
    pub fn enumerate() -> Result<Self, PciError> {
        let mut config = LegacyConfigAccess::new();
        let mut devices = Vec::new();

        for bus in 0u16..=u8::MAX as u16 {
            for device in 0..32u8 {
                let function_zero = PciAddress::new(bus as u8, device, 0);
                let identity = config.read_u32(function_zero, 0x00);
                if identity as u16 == u16::MAX {
                    continue;
                }

                let header_type = config.read_u8(function_zero, 0x0e);
                let function_count = if header_type & 0x80 != 0 { 8 } else { 1 };
                for function in 0..function_count {
                    let address = PciAddress::new(bus as u8, device, function);
                    if config.read_u16(address, 0x00) == u16::MAX {
                        continue;
                    }
                    if devices.len() == MAX_DEVICES {
                        return Err(PciError::TooManyDevices { limit: MAX_DEVICES });
                    }
                    devices.push(read_device(&mut config, address));
                }
            }
        }

        Ok(Self {
            scanned_buses: u8::MAX as u16 + 1,
            devices,
        })
    }

    pub fn scanned_buses(&self) -> u16 {
        self.scanned_buses
    }

    pub fn devices(&self) -> &[PciDevice] {
        &self.devices
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

struct LegacyConfigAccess {
    address: Port<u32>,
    data: Port<u32>,
}

impl LegacyConfigAccess {
    fn new() -> Self {
        Self {
            address: Port::new(CONFIG_ADDRESS_PORT),
            data: Port::new(CONFIG_DATA_PORT),
        }
    }

    fn read_u8(&mut self, address: PciAddress, offset: u8) -> u8 {
        let value = self.read_u32(address, offset & !0x03);
        let shift = u32::from(offset & 0x03) * 8;
        (value >> shift) as u8
    }

    fn read_u16(&mut self, address: PciAddress, offset: u8) -> u16 {
        let value = self.read_u32(address, offset & !0x03);
        let shift = u32::from(offset & 0x02) * 8;
        (value >> shift) as u16
    }

    fn read_u32(&mut self, address: PciAddress, offset: u8) -> u32 {
        debug_assert_eq!(offset & 0x03, 0);
        let config_address = CONFIG_ENABLE
            | (u32::from(address.bus) << 16)
            | (u32::from(address.device) << 11)
            | (u32::from(address.function) << 8)
            | u32::from(offset & 0xfc);

        // SAFETY: mechanism #1 defines these ports as the PCI configuration address/data pair;
        // every address here is assembled from bounded bus/device/function fields and an aligned
        // standard configuration-space offset.
        unsafe {
            self.address.write(config_address);
            self.data.read()
        }
    }

    fn write_u16(&mut self, address: PciAddress, offset: u8, value: u16) {
        debug_assert_eq!(offset & 0x01, 0);
        let config_address = CONFIG_ENABLE
            | (u32::from(address.bus) << 16)
            | (u32::from(address.device) << 11)
            | (u32::from(address.function) << 8)
            | u32::from(offset & 0xfc);

        // SAFETY: mechanism #1 permits a 16-bit write to the aligned configuration data port;
        // the data lane is selected from the register's low two offset bits.
        unsafe {
            self.address.write(config_address);
            let mut data_word = Port::<u16>::new(CONFIG_DATA_PORT + u16::from(offset & 0x02));
            data_word.write(value);
        }
    }

    fn write_u32(&mut self, address: PciAddress, offset: u8, value: u32) {
        debug_assert_eq!(offset & 0x03, 0);
        let config_address = CONFIG_ENABLE
            | (u32::from(address.bus) << 16)
            | (u32::from(address.device) << 11)
            | (u32::from(address.function) << 8)
            | u32::from(offset & 0xfc);

        // SAFETY: mechanism #1 permits a 32-bit write to the aligned configuration data port;
        // MSI message address and mask registers are naturally aligned DWORD fields.
        unsafe {
            self.address.write(config_address);
            self.data.write(value);
        }
    }
}

fn read_device(config: &mut LegacyConfigAccess, address: PciAddress) -> PciDevice {
    let identity = config.read_u32(address, 0x00);
    let class_register = config.read_u32(address, 0x08);
    let command_status = config.read_u32(address, 0x04);
    let class_code = (class_register >> 24) as u8;
    let subclass = (class_register >> 16) as u8;
    let prog_if = (class_register >> 8) as u8;
    let revision_id = class_register as u8;
    let header_type = config.read_u8(address, 0x0e);
    let bars = read_bars(config, address, header_type);
    let capabilities = read_capabilities(config, address, (command_status >> 16) as u16);

    PciDevice {
        address,
        vendor_id: identity as u16,
        device_id: (identity >> 16) as u16,
        revision_id,
        prog_if,
        command: command_status as u16,
        status: (command_status >> 16) as u16,
        subclass,
        class_code,
        header_type,
        interrupt_line: config.read_u8(address, 0x3c),
        interrupt_pin: config.read_u8(address, 0x3d),
        bars,
        capabilities,
    }
}

fn read_capabilities(
    config: &mut LegacyConfigAccess,
    address: PciAddress,
    status: u16,
) -> PciCapabilities {
    if status & PCI_STATUS_CAPABILITIES_LIST == 0 {
        return PciCapabilities::empty();
    }
    let first = config.read_u8(address, PCI_CAPABILITY_POINTER);
    parse_capabilities(|offset| config.read_u8(address, offset), first)
}

fn parse_capabilities<F>(mut read: F, first: u8) -> PciCapabilities
where
    F: FnMut(u8) -> u8,
{
    let mut capabilities = PciCapabilities::empty();
    let mut pointer = first & 0xfc;
    let mut visited = [0u8; MAX_CAPABILITIES];
    let mut visited_count = 0;
    while pointer != 0 && visited_count < MAX_CAPABILITIES {
        if pointer < 0x40 || visited[..visited_count].contains(&pointer) {
            break;
        }
        visited[visited_count] = pointer;
        visited_count += 1;

        let capability_id = read(pointer);
        let next = read(pointer.saturating_add(1)) & 0xfc;
        match capability_id {
            PCI_CAPABILITY_MSI => {
                let Some(control_offset) = pointer.checked_add(2) else {
                    break;
                };
                let control = read_u16(&mut read, control_offset);
                capabilities.msi = Some(PciMsiCapability {
                    offset: pointer,
                    is_64_bit: control & MSI_64_BIT_CAPABLE != 0,
                    multiple_message_capable: ((control >> 1) & 0x07) as u8,
                    per_vector_masking: control & MSI_PER_VECTOR_MASKING_CAPABLE != 0,
                });
            }
            PCI_CAPABILITY_MSIX => {
                let Some(control_offset) = pointer.checked_add(2) else {
                    break;
                };
                let Some(table_offset) = pointer.checked_add(4) else {
                    break;
                };
                let Some(pba_offset) = pointer.checked_add(8) else {
                    break;
                };
                let control = read_u16(&mut read, control_offset);
                let table = read_u32(&mut read, table_offset);
                let pba = read_u32(&mut read, pba_offset);
                capabilities.msix = Some(PciMsixCapability {
                    offset: pointer,
                    table_size: (control & 0x07ff) + 1,
                    function_masked: control & (1 << 14) != 0,
                    table_bar: (table & MSIX_TABLE_BAR_MASK) as u8,
                    table_offset: table & MSIX_TABLE_OFFSET_MASK,
                    pba_bar: (pba & MSIX_TABLE_BAR_MASK) as u8,
                    pba_offset: pba & MSIX_TABLE_OFFSET_MASK,
                });
            }
            PCI_CAPABILITY_VENDOR_SPECIFIC => {
                let Some(capability_length_offset) = pointer.checked_add(2) else {
                    break;
                };
                let Some(cfg_type_offset) = pointer.checked_add(3) else {
                    break;
                };
                let Some(bar_offset) = pointer.checked_add(4) else {
                    break;
                };
                let Some(region_offset) = pointer.checked_add(8) else {
                    break;
                };
                let Some(region_length) = pointer.checked_add(12) else {
                    break;
                };
                let capability_length = read(capability_length_offset);
                let cfg_type = read(cfg_type_offset);
                let required_length = if cfg_type == 2 { 20 } else { 16 };
                if capability_length < required_length || !(1..=5).contains(&cfg_type) {
                    pointer = next;
                    continue;
                }
                let bar = read(bar_offset);
                let region_length_value = read_u32(&mut read, region_length);
                if bar >= 6 || region_length_value == 0 {
                    pointer = next;
                    continue;
                }
                let notify_off_multiplier = if cfg_type == 2 {
                    let Some(multiplier_offset) = pointer.checked_add(16) else {
                        break;
                    };
                    read_u32(&mut read, multiplier_offset)
                } else {
                    0
                };
                capabilities.virtio[usize::from(cfg_type - 1)] = Some(PciVirtioCapability {
                    offset: pointer,
                    cfg_type,
                    bar,
                    region_offset: read_u32(&mut read, region_offset),
                    region_length: region_length_value,
                    notify_off_multiplier,
                });
            }
            _ => {}
        }
        pointer = next;
    }
    capabilities
}

fn read_u16<F>(read: &mut F, offset: u8) -> u16
where
    F: FnMut(u8) -> u8,
{
    u16::from(read(offset)) | (u16::from(read(offset.saturating_add(1))) << 8)
}

fn read_u32<F>(read: &mut F, offset: u8) -> u32
where
    F: FnMut(u8) -> u8,
{
    u32::from(read(offset))
        | (u32::from(read(offset.saturating_add(1))) << 8)
        | (u32::from(read(offset.saturating_add(2))) << 16)
        | (u32::from(read(offset.saturating_add(3))) << 24)
}

fn read_bars(config: &mut LegacyConfigAccess, address: PciAddress, header_type: u8) -> [PciBar; 6] {
    let mut bars = [PciBar::Unused; 6];
    if header_type & 0x7f != 0 {
        return bars;
    }

    let mut index = 0;
    while index < bars.len() {
        let offset = 0x10 + (index as u8 * 4);
        let raw = config.read_u32(address, offset);
        if raw == 0 {
            bars[index] = PciBar::Unassigned;
            index += 1;
            continue;
        }

        if raw & 1 != 0 {
            bars[index] = PciBar::Io {
                base: (raw & !0x03) as u16,
            };
            index += 1;
            continue;
        }

        let memory_type = (raw >> 1) & 0x03;
        let prefetchable = raw & 0x08 != 0;
        match memory_type {
            0 => {
                bars[index] = PciBar::Memory32 {
                    base: raw & !0x0f,
                    prefetchable,
                };
                index += 1;
            }
            2 if index + 1 < bars.len() => {
                let high = config.read_u32(address, offset + 4);
                bars[index] = PciBar::Memory64 {
                    base: (u64::from(high) << 32) | u64::from(raw & !0x0f),
                    prefetchable,
                };
                bars[index + 1] = PciBar::UpperHalf;
                index += 2;
            }
            _ => {
                bars[index] = PciBar::Unsupported { raw };
                index += 1;
            }
        }
    }
    bars
}

#[cfg(test)]
mod tests {
    use super::{PciCapabilities, PciResourceError, msi_message, parse_capabilities};

    #[test]
    fn parses_msi_and_msix_capabilities() {
        let mut config = [0u8; 256];
        config[0x40] = 0x05;
        config[0x41] = 0x60;
        config[0x42..0x44].copy_from_slice(&0x0186u16.to_le_bytes());
        config[0x60] = 0x11;
        config[0x61] = 0x80;
        config[0x62..0x64].copy_from_slice(&0x4003u16.to_le_bytes());
        config[0x64..0x68].copy_from_slice(&0x0000_2000u32.to_le_bytes());
        config[0x68..0x6c].copy_from_slice(&0x0000_3001u32.to_le_bytes());
        config[0x80] = 0x09;
        config[0x81] = 0;
        config[0x82] = 20;
        config[0x83] = 2;
        config[0x84] = 4;
        config[0x88..0x8c].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        config[0x8c..0x90].copy_from_slice(&0x0000_0100u32.to_le_bytes());
        config[0x90..0x94].copy_from_slice(&0x0000_0040u32.to_le_bytes());

        let capabilities = parse_capabilities(|offset| config[offset as usize], 0x40);
        assert_eq!(
            capabilities.msi,
            Some(super::PciMsiCapability {
                offset: 0x40,
                is_64_bit: true,
                multiple_message_capable: 3,
                per_vector_masking: true,
            })
        );
        assert_eq!(
            capabilities.msix,
            Some(super::PciMsixCapability {
                offset: 0x60,
                table_size: 4,
                function_masked: true,
                table_bar: 0,
                table_offset: 0x2000,
                pba_bar: 1,
                pba_offset: 0x3000,
            })
        );
        assert_eq!(
            capabilities.virtio[1],
            Some(super::PciVirtioCapability {
                offset: 0x80,
                cfg_type: 2,
                bar: 4,
                region_offset: 0x1000,
                region_length: 0x100,
                notify_off_multiplier: 0x40,
            })
        );
    }

    #[test]
    fn capability_parser_stops_on_malformed_or_cyclic_lists() {
        let mut config = [0u8; 256];
        config[0x40] = 0x05;
        config[0x41] = 0x40;
        config[0x42..0x44].copy_from_slice(&0x0000u16.to_le_bytes());

        let capabilities = parse_capabilities(|offset| config[offset as usize], 0x40);
        assert!(capabilities.msi.is_some());
        assert_eq!(capabilities.msix, None);

        let empty = parse_capabilities(|_| 0, 0x01);
        assert_eq!(empty, PciCapabilities::empty());
    }

    #[test]
    fn msi_message_targets_the_apic_and_rejects_reserved_inputs() {
        assert_eq!(msi_message(50, 3), Ok((0xfee0_3000, 50)));
        assert_eq!(
            msi_message(31, 0),
            Err(PciResourceError::InvalidMsiVector { vector: 31 })
        );
        assert_eq!(
            msi_message(50, 256),
            Err(PciResourceError::MsiDestinationOutOfRange { destination: 256 })
        );
    }
}
