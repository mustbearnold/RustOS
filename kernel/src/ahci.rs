use bootloader_api::info::MemoryRegion;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory::{FrameAllocator, PAGE_SIZE};
use crate::pci::{
    MmioError, MmioRegion, PciDevice, PciDeviceResources, PciInterruptMode, PciResourceError,
};
use crate::storage::{
    BlockDevice, BlockDeviceError, SECTOR_SIZE, parse_identify_capacity, validate_lba48,
};

const AHCI_MMIO_LENGTH: u64 = 0x1100;
const AHCI_MAX_PORTS: u8 = 32;
const AHCI_COMMAND_LIST_ENTRY_SIZE: u64 = 32;
const AHCI_COMMAND_TABLE_OFFSET: u64 = 0x80;
const AHCI_COMMAND_TABLE_ALIGNMENT: u64 = 128;
const AHCI_FIS_ALIGNMENT: u64 = 256;
const AHCI_POLL_SPINS: usize = 2_000_000;
const AHCI_INTERRUPT_WAIT_SPINS: usize = 64;

const HBA_CAP: u64 = 0x00;
const HBA_GHC: u64 = 0x04;
const HBA_IS: u64 = 0x08;
const HBA_PI: u64 = 0x0c;
const HBA_CAP_S64A: u32 = 1 << 31;
const HBA_GHC_AE: u32 = 1 << 31;
const HBA_GHC_IE: u32 = 1 << 1;

const PORT_CLB: u64 = 0x00;
const PORT_FB: u64 = 0x08;
const PORT_IS: u64 = 0x10;
const PORT_IE: u64 = 0x14;
const PORT_CMD: u64 = 0x18;
const PORT_TFD: u64 = 0x20;
const PORT_SIG: u64 = 0x24;
const PORT_SSTS: u64 = 0x28;
const PORT_SERR: u64 = 0x30;
const PORT_CI: u64 = 0x38;

const PORT_CMD_ST: u32 = 1 << 0;
const PORT_CMD_FRE: u32 = 1 << 4;
const PORT_CMD_FR: u32 = 1 << 14;
const PORT_CMD_CR: u32 = 1 << 15;
const PORT_SSTS_DET_MASK: u32 = 0x0f;
const PORT_SSTS_IPM_MASK: u32 = 0x0f00;
const PORT_SSTS_DEVICE_PRESENT: u32 = 0x03;
const PORT_SSTS_ACTIVE: u32 = 0x0100;
const PORT_IS_TFES: u32 = 1 << 30;

const SATA_SIGNATURE: u32 = 0x0000_0101;
const ATAPI_SIGNATURE: u32 = 0xeb14_0101;
const ATA_IDENTIFY: u8 = 0xec;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_CACHE_EXT: u8 = 0xea;
const FIS_TYPE_REG_H2D: u8 = 0x27;
const FIS_COMMAND: u8 = 1 << 7;
const FIS_DEVICE_LBA: u8 = 1 << 6;
const COMMAND_WRITE: u32 = 1 << 6;
const COMMAND_PRDT_LENGTH_ONE: u32 = 1 << 16;
const PRDT_INTERRUPT: u32 = 1 << 31;
const PRDT_BYTE_COUNT_MASK: u32 = 0x003f_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciError {
    Resources(PciResourceError),
    Mmio(MmioError),
    MemorySpaceDisabled,
    UnsupportedController {
        class: u8,
        subclass: u8,
        prog_if: u8,
    },
    NoPort,
    UnsupportedPort {
        port: u8,
        signature: u32,
        status: u32,
    },
    NoDmaFrame,
    DmaAddressTooLarge {
        address: u64,
    },
    DmaAddressOverflow,
    DmaUnaligned {
        address: u64,
        alignment: u64,
    },
    DmaOutOfBounds {
        offset: u64,
        size: u64,
    },
    InvalidCapacity,
    InvalidIdentify {
        word0: u16,
        word49: u16,
        word83: u16,
        lba28: u64,
        lba48: u64,
    },
    LbaOutOfRange {
        lba: u64,
        capacity: u64,
    },
    Lba48AddressOutOfRange {
        lba: u64,
    },
    InvalidBufferLength {
        expected: usize,
        actual: usize,
    },
    PortTimeout {
        register: u64,
        value: u32,
    },
    PortDeviceError {
        status: u32,
        error: u32,
    },
    InterruptRegistration(crate::interrupts::DeviceInterruptError),
}

impl From<PciResourceError> for AhciError {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

impl From<MmioError> for AhciError {
    fn from(error: MmioError) -> Self {
        Self::Mmio(error)
    }
}

impl From<crate::interrupts::DeviceInterruptError> for AhciError {
    fn from(error: crate::interrupts::DeviceInterruptError) -> Self {
        Self::InterruptRegistration(error)
    }
}

impl AhciError {
    pub fn into_block_error(self) -> BlockDeviceError {
        match self {
            Self::LbaOutOfRange { lba, capacity } => {
                BlockDeviceError::LbaOutOfRange { lba, capacity }
            }
            Self::Lba48AddressOutOfRange { lba } => {
                BlockDeviceError::Lba48AddressOutOfRange { lba }
            }
            Self::InvalidBufferLength { expected, actual } => {
                BlockDeviceError::InvalidBufferLength { expected, actual }
            }
            error => BlockDeviceError::Ahci {
                kind: error.kind_code(),
                value: error.value_code(),
            },
        }
    }

    fn kind_code(self) -> u8 {
        match self {
            Self::Resources(_) => 1,
            Self::Mmio(_) => 2,
            Self::MemorySpaceDisabled => 3,
            Self::UnsupportedController { .. } => 4,
            Self::NoPort => 5,
            Self::UnsupportedPort { .. } => 6,
            Self::NoDmaFrame => 7,
            Self::DmaAddressTooLarge { .. } => 8,
            Self::DmaAddressOverflow => 9,
            Self::DmaUnaligned { .. } => 10,
            Self::DmaOutOfBounds { .. } => 11,
            Self::InvalidCapacity => 12,
            Self::InvalidIdentify { .. } => 13,
            Self::LbaOutOfRange { .. } => 14,
            Self::Lba48AddressOutOfRange { .. } => 15,
            Self::InvalidBufferLength { .. } => 16,
            Self::PortTimeout { .. } => 17,
            Self::PortDeviceError { .. } => 18,
            Self::InterruptRegistration(_) => 19,
        }
    }

    fn value_code(self) -> u64 {
        match self {
            Self::UnsupportedPort {
                port,
                signature,
                status,
            } => (u64::from(port) << 56) | (u64::from(signature) << 24) | u64::from(status),
            Self::DmaAddressTooLarge { address }
            | Self::Lba48AddressOutOfRange { lba: address } => address,
            Self::DmaAddressOverflow => 0,
            Self::DmaUnaligned { address, alignment } => {
                (address & 0xffff_ffff) | (alignment << 32)
            }
            Self::DmaOutOfBounds { offset, size } => (offset & 0xffff_ffff) | (size << 32),
            Self::PortTimeout { register, value } => (register << 32) | u64::from(value),
            Self::PortDeviceError { status, error } => (u64::from(status) << 32) | u64::from(error),
            Self::LbaOutOfRange { lba, .. } => lba,
            Self::InvalidIdentify {
                word0,
                word49,
                word83,
                lba28,
                lba48,
            } => {
                (u64::from(word0) << 48)
                    | (u64::from(word49) << 32)
                    | (u64::from(word83) << 16)
                    | (lba28 ^ lba48)
            }
            Self::InvalidBufferLength { expected, actual } => {
                (u64::try_from(expected).unwrap_or(u64::MAX) << 32)
                    | u64::try_from(actual).unwrap_or(u64::MAX)
            }
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DmaPage {
    physical_base: u64,
    virtual_base: u64,
}

impl DmaPage {
    fn clear(self) {
        // SAFETY: the page is allocated from usable firmware memory and the bootloader's
        // physical-memory mapping makes the full page available at virtual_base.
        unsafe { core::ptr::write_bytes(self.virtual_base as *mut u8, 0, PAGE_SIZE as usize) };
    }

    fn pointer(self, offset: u64, size: u64, alignment: u64) -> Result<u64, AhciError> {
        if self.physical_base % alignment != 0 || offset % alignment != 0 {
            return Err(AhciError::DmaUnaligned {
                address: self.physical_base.saturating_add(offset),
                alignment,
            });
        }
        let end = offset
            .checked_add(size)
            .ok_or(AhciError::DmaAddressOverflow)?;
        if end > PAGE_SIZE {
            return Err(AhciError::DmaOutOfBounds { offset, size });
        }
        self.virtual_base
            .checked_add(offset)
            .ok_or(AhciError::DmaAddressOverflow)
    }

    fn write_u8(self, offset: u64, value: u8) -> Result<(), AhciError> {
        let pointer = self.pointer(offset, 1, 1)?;
        // SAFETY: pointer is bounds-checked against the allocated page.
        unsafe { core::ptr::write_volatile(pointer as *mut u8, value) };
        Ok(())
    }

    fn write_u32(self, offset: u64, value: u32) -> Result<(), AhciError> {
        let pointer = self.pointer(offset, 4, 4)?;
        // SAFETY: pointer is bounds-checked and aligned for a 32-bit volatile field.
        unsafe { core::ptr::write_volatile(pointer as *mut u32, value.to_le()) };
        Ok(())
    }

    fn write_u64(self, offset: u64, value: u64) -> Result<(), AhciError> {
        let pointer = self.pointer(offset, 8, 8)?;
        // SAFETY: pointer is bounds-checked and aligned for a 64-bit volatile field.
        unsafe { core::ptr::write_volatile(pointer as *mut u64, value.to_le()) };
        Ok(())
    }

    fn write_bytes(self, offset: u64, bytes: &[u8]) -> Result<(), AhciError> {
        for (index, byte) in bytes.iter().copied().enumerate() {
            let index = u64::try_from(index).map_err(|_| AhciError::DmaAddressOverflow)?;
            self.write_u8(
                offset
                    .checked_add(index)
                    .ok_or(AhciError::DmaAddressOverflow)?,
                byte,
            )?;
        }
        Ok(())
    }

    fn read_bytes(self, offset: u64, bytes: &mut [u8]) -> Result<(), AhciError> {
        for (index, byte) in bytes.iter_mut().enumerate() {
            let index = u64::try_from(index).map_err(|_| AhciError::DmaAddressOverflow)?;
            let pointer = self.pointer(
                offset
                    .checked_add(index)
                    .ok_or(AhciError::DmaAddressOverflow)?,
                1,
                1,
            )?;
            // SAFETY: pointer is bounds-checked against the allocated page.
            *byte = unsafe { core::ptr::read_volatile(pointer as *const u8) };
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AhciDisk {
    capacity_sectors: u64,
    port_index: u8,
    port_base: u64,
    signature: u32,
    mmio: MmioRegion,
    command_list: DmaPage,
    received_fis: DmaPage,
    command_table: DmaPage,
    data: DmaPage,
    resources: PciDeviceResources,
    next_frame_address: Option<u64>,
    supports_64bit_dma: bool,
    interrupt_vector: Option<u8>,
    interrupt_mode: PciInterruptMode,
    interrupt_driven: bool,
    interrupt_error: Option<AhciError>,
}

static AHCI_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);

fn ahci_interrupt_handler() {
    AHCI_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);
}

impl AhciDisk {
    pub fn initialize(
        device: PciDevice,
        physical_memory_offset: u64,
        regions: &[MemoryRegion],
        next_frame_address: Option<u64>,
    ) -> Result<Self, AhciError> {
        if device.class_code != 0x01 || device.subclass != 0x06 || device.prog_if != 0x01 {
            return Err(AhciError::UnsupportedController {
                class: device.class_code,
                subclass: device.subclass,
                prog_if: device.prog_if,
            });
        }
        if !device.memory_space_enabled() {
            return Err(AhciError::MemorySpaceDisabled);
        }

        let mut resources = PciDeviceResources::new(device, physical_memory_offset);
        resources.enable_bus_master()?;
        let mmio = resources.claim_mmio(5, AHCI_MMIO_LENGTH)?;
        let capabilities = mmio.read_u32(HBA_CAP)?;
        let supports_64bit_dma = capabilities & HBA_CAP_S64A != 0;
        let port_map = mmio.read_u32(HBA_PI)?;
        let max_ports = (((capabilities & 0x1f) as u8).saturating_add(1)).min(AHCI_MAX_PORTS);
        let mut selected = None;
        for port in 0..max_ports {
            if port_map & (1 << port) == 0 {
                continue;
            }
            let port_base = 0x100 + u64::from(port) * 0x80;
            let status = mmio.read_u32(port_base + PORT_SSTS)?;
            let signature = mmio.read_u32(port_base + PORT_SIG)?;
            if status & PORT_SSTS_DET_MASK == PORT_SSTS_DEVICE_PRESENT
                && status & PORT_SSTS_IPM_MASK == PORT_SSTS_ACTIVE
                && signature == SATA_SIGNATURE
            {
                selected = Some((port, port_base, signature, status));
                break;
            }
            if status & PORT_SSTS_DET_MASK == PORT_SSTS_DEVICE_PRESENT
                && signature == ATAPI_SIGNATURE
            {
                return Err(AhciError::UnsupportedPort {
                    port,
                    signature,
                    status,
                });
            }
        }
        let Some((port_index, port_base, signature, status)) = selected else {
            return Err(AhciError::NoPort);
        };

        let mut allocator = FrameAllocator::starting_at(regions, next_frame_address.unwrap_or(0));
        let command_list = allocate_page(&mut allocator, physical_memory_offset)?;
        let received_fis = allocate_page(&mut allocator, physical_memory_offset)?;
        let command_table = allocate_page(&mut allocator, physical_memory_offset)?;
        let data = allocate_page(&mut allocator, physical_memory_offset)?;
        for page in [command_list, received_fis, command_table, data] {
            if !supports_64bit_dma && page.physical_base > u64::from(u32::MAX) {
                return Err(AhciError::DmaAddressTooLarge {
                    address: page.physical_base,
                });
            }
        }

        let mut disk = Self {
            capacity_sectors: 0,
            port_index,
            port_base,
            signature,
            mmio,
            command_list,
            received_fis,
            command_table,
            data,
            resources,
            next_frame_address: allocator.next_available_address(),
            supports_64bit_dma,
            interrupt_vector: None,
            interrupt_mode: PciInterruptMode::None,
            interrupt_driven: false,
            interrupt_error: None,
        };
        disk.configure_interrupts();
        disk.prepare_port()?;
        let mut identify = [0u8; SECTOR_SIZE];
        disk.execute(ATA_IDENTIFY, 0, 1, Some(&mut identify), false)?;
        let words = bytes_to_words(&identify);
        disk.capacity_sectors = match parse_identify_capacity(&words) {
            Ok(capacity) => capacity,
            Err(_) => {
                let lba28 = u64::from(words[60]) | (u64::from(words[61]) << 16);
                let lba48 = u64::from(words[100])
                    | (u64::from(words[101]) << 16)
                    | (u64::from(words[102]) << 32)
                    | (u64::from(words[103]) << 48);
                return Err(AhciError::InvalidIdentify {
                    word0: words[0],
                    word49: words[49],
                    word83: words[83],
                    lba28,
                    lba48,
                });
            }
        };
        if disk.capacity_sectors == 0 {
            return Err(AhciError::InvalidCapacity);
        }
        // A read-back of LBA 0 exercises the DMA path before the filesystem layer claims the
        // disk. The sector is discarded because the probe performs the authoritative read.
        let mut boot_sector = [0u8; SECTOR_SIZE];
        disk.read_sector(0, &mut boot_sector)?;
        let _ = status;
        Ok(disk)
    }

    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    pub fn port_index(&self) -> u8 {
        self.port_index
    }

    pub fn signature(&self) -> u32 {
        self.signature
    }

    pub fn mmio_base(&self) -> u64 {
        self.mmio.physical_base()
    }

    pub fn supports_64bit_dma(&self) -> bool {
        self.supports_64bit_dma
    }

    pub fn next_frame_address(&self) -> Option<u64> {
        self.next_frame_address
    }

    pub fn interrupt_mode(&self) -> PciInterruptMode {
        self.interrupt_mode
    }

    pub fn interrupt_vector(&self) -> Option<u8> {
        self.interrupt_vector
    }

    pub fn interrupt_count(&self) -> u64 {
        AHCI_INTERRUPT_COUNT.load(Ordering::SeqCst)
    }

    pub fn interrupt_driven(&self) -> bool {
        self.interrupt_driven
    }

    pub fn interrupt_error(&self) -> Option<AhciError> {
        self.interrupt_error
    }

    fn configure_interrupts(&mut self) {
        let Some(destination_apic_id) = crate::apic::local_apic_id_u32() else {
            return;
        };
        let vector = match crate::interrupts::register_device_handler(ahci_interrupt_handler) {
            Ok(vector) => vector,
            Err(error) => {
                self.interrupt_error = Some(error.into());
                return;
            }
        };
        self.interrupt_vector = Some(vector);
        AHCI_INTERRUPT_COUNT.store(0, Ordering::SeqCst);

        match self.resources.enable_msix(vector, destination_apic_id) {
            Ok(_) => {
                self.interrupt_mode = PciInterruptMode::Msix;
                self.interrupt_driven = true;
                return;
            }
            Err(error) => self.interrupt_error = Some(error.into()),
        }

        match self.resources.enable_msi(vector, destination_apic_id) {
            Ok(_) => {
                self.interrupt_mode = PciInterruptMode::Msi;
                self.interrupt_driven = true;
                self.interrupt_error = None;
            }
            Err(error) => self.interrupt_error = Some(error.into()),
        }
    }

    fn prepare_port(&mut self) -> Result<(), AhciError> {
        let command = self.port_read(PORT_CMD)?;
        if command & PORT_CMD_ST != 0 {
            self.port_write(PORT_CMD, command & !PORT_CMD_ST)?;
            self.wait_port_clear(PORT_CMD, PORT_CMD_CR)?;
        }
        let command = self.port_read(PORT_CMD)?;
        if command & PORT_CMD_FRE != 0 {
            self.port_write(PORT_CMD, command & !PORT_CMD_FRE)?;
            self.wait_port_clear(PORT_CMD, PORT_CMD_FR)?;
        }

        self.command_list.clear();
        self.received_fis.clear();
        self.command_table.clear();
        self.data.clear();
        self.port_write(PORT_CLB, self.command_list.physical_base as u32)?;
        self.port_write(PORT_CLB + 4, (self.command_list.physical_base >> 32) as u32)?;
        self.port_write(PORT_FB, self.received_fis.physical_base as u32)?;
        self.port_write(PORT_FB + 4, (self.received_fis.physical_base >> 32) as u32)?;
        self.port_write(PORT_IS, u32::MAX)?;
        self.port_write(PORT_SERR, u32::MAX)?;
        self.port_write(PORT_IE, if self.interrupt_driven { u32::MAX } else { 0 })?;

        let mut hba = self.mmio.read_u32(HBA_GHC)? | HBA_GHC_AE;
        if self.interrupt_driven {
            hba |= HBA_GHC_IE;
        } else {
            hba &= !HBA_GHC_IE;
        }
        self.mmio.write_u32(HBA_GHC, hba)?;
        self.port_write(PORT_CMD, command | PORT_CMD_FRE)?;
        self.port_write(PORT_CMD, (command | PORT_CMD_FRE) | PORT_CMD_ST)?;
        Ok(())
    }

    fn execute(
        &mut self,
        command: u8,
        lba: u64,
        sectors: u16,
        buffer: Option<&mut [u8; SECTOR_SIZE]>,
        write: bool,
    ) -> Result<(), AhciError> {
        if sectors != 1 {
            return Err(AhciError::InvalidBufferLength {
                expected: SECTOR_SIZE,
                actual: usize::from(sectors) * SECTOR_SIZE,
            });
        }
        self.command_list.clear();
        self.command_table.clear();
        if let Some(buffer) = buffer.as_deref() {
            if write {
                self.data.write_bytes(0, buffer)?;
            }
        }

        let entry = 0;
        let command_offset = entry * AHCI_COMMAND_LIST_ENTRY_SIZE;
        let flags = 5
            | if write { COMMAND_WRITE } else { 0 }
            | if buffer.is_some() {
                COMMAND_PRDT_LENGTH_ONE
            } else {
                0
            };
        self.command_list.write_u32(command_offset, flags)?;
        self.command_list.write_u32(command_offset + 4, 0)?;
        self.command_list
            .write_u32(command_offset + 8, self.command_table.physical_base as u32)?;
        self.command_list.write_u32(
            command_offset + 12,
            (self.command_table.physical_base >> 32) as u32,
        )?;

        self.command_table.write_u8(0, FIS_TYPE_REG_H2D)?;
        self.command_table.write_u8(1, FIS_COMMAND)?;
        self.command_table.write_u8(2, command)?;
        self.command_table.write_u8(3, 0)?;
        let lba_bytes = lba.to_le_bytes();
        for (index, byte) in lba_bytes[..3].iter().copied().enumerate() {
            self.command_table.write_u8(4 + index as u64, byte)?;
        }
        for (index, byte) in lba_bytes[3..6].iter().copied().enumerate() {
            self.command_table.write_u8(8 + index as u64, byte)?;
        }
        self.command_table.write_u8(7, FIS_DEVICE_LBA)?;
        self.command_table.write_u8(12, sectors as u8)?;
        self.command_table.write_u8(13, (sectors >> 8) as u8)?;

        if buffer.is_some() {
            self.command_table
                .write_u64(AHCI_COMMAND_TABLE_OFFSET, self.data.physical_base)?;
            self.command_table.write_u32(
                AHCI_COMMAND_TABLE_OFFSET + 12,
                PRDT_INTERRUPT | ((SECTOR_SIZE as u32 - 1) & PRDT_BYTE_COUNT_MASK),
            )?;
        }

        self.port_write(PORT_IS, u32::MAX)?;
        self.port_write(PORT_CI, 1 << entry)?;
        let interrupt_before = AHCI_INTERRUPT_COUNT.load(Ordering::SeqCst);
        let mut last_ci = 0;
        let wait_spins = if self.interrupt_driven {
            AHCI_INTERRUPT_WAIT_SPINS
        } else {
            AHCI_POLL_SPINS
        };
        for _ in 0..wait_spins {
            let ci = self.port_read(PORT_CI)?;
            last_ci = ci;
            if ci & (1 << entry) == 0 {
                if self.interrupt_driven {
                    wait_for_interrupt_delivery(interrupt_before);
                }
                break;
            }
            wait_for_completion(self.interrupt_driven);
        }
        if last_ci & (1 << entry) != 0 {
            return Err(AhciError::PortTimeout {
                register: self.port_base + PORT_CI,
                value: last_ci,
            });
        }
        let interrupt_status = self.port_read(PORT_IS)?;
        if interrupt_status & PORT_IS_TFES != 0 {
            self.acknowledge_interrupts(interrupt_status)?;
            return Err(AhciError::PortDeviceError {
                status: interrupt_status,
                error: self.port_read(PORT_TFD)?,
            });
        }
        self.acknowledge_interrupts(interrupt_status)?;
        if let Some(buffer) = buffer {
            if !write {
                self.data.read_bytes(0, buffer)?;
            }
        }
        Ok(())
    }

    fn acknowledge_interrupts(&self, port_status: u32) -> Result<(), AhciError> {
        if port_status != 0 {
            self.port_write(PORT_IS, port_status)?;
        }
        let global_status = self.mmio.read_u32(HBA_IS)?;
        let port_mask = 1u32 << u32::from(self.port_index);
        if global_status & port_mask != 0 {
            self.mmio.write_u32(HBA_IS, port_mask)?;
        }
        Ok(())
    }

    fn wait_port_clear(&self, register: u64, mask: u32) -> Result<(), AhciError> {
        let mut last = 0;
        for _ in 0..AHCI_POLL_SPINS {
            last = self.port_read(register)?;
            if last & mask == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(AhciError::PortTimeout {
            register: self.port_base + register,
            value: last,
        })
    }

    fn port_read(&self, offset: u64) -> Result<u32, AhciError> {
        self.mmio
            .read_u32(self.port_base + offset)
            .map_err(Into::into)
    }

    fn port_write(&self, offset: u64, value: u32) -> Result<(), AhciError> {
        self.mmio
            .write_u32(self.port_base + offset, value)
            .map_err(Into::into)
    }
}

fn wait_for_interrupt_delivery(before: u64) {
    for _ in 0..AHCI_INTERRUPT_WAIT_SPINS {
        if AHCI_INTERRUPT_COUNT.load(Ordering::SeqCst) != before {
            return;
        }
        wait_for_completion(true);
    }
}

fn wait_for_completion(interrupt_driven: bool) {
    if interrupt_driven && x86_64::instructions::interrupts::are_enabled() {
        x86_64::instructions::hlt();
        return;
    }
    core::hint::spin_loop();
}

impl crate::storage::BlockDevice for AhciDisk {
    type Error = AhciError;

    fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        if buffer.len() != SECTOR_SIZE {
            return Err(AhciError::InvalidBufferLength {
                expected: SECTOR_SIZE,
                actual: buffer.len(),
            });
        }
        validate_lba48(lba, self.capacity_sectors).map_err(|error| match error {
            BlockDeviceError::LbaOutOfRange { lba, capacity } => {
                AhciError::LbaOutOfRange { lba, capacity }
            }
            BlockDeviceError::Lba48AddressOutOfRange { lba } => {
                AhciError::Lba48AddressOutOfRange { lba }
            }
            _ => AhciError::InvalidCapacity,
        })?;
        let sector: &mut [u8; SECTOR_SIZE] = buffer.try_into().expect("validated sector length");
        self.execute(ATA_READ_DMA_EXT, lba, 1, Some(sector), false)
    }

    fn write_sector(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        if buffer.len() != SECTOR_SIZE {
            return Err(AhciError::InvalidBufferLength {
                expected: SECTOR_SIZE,
                actual: buffer.len(),
            });
        }
        validate_lba48(lba, self.capacity_sectors).map_err(|error| match error {
            BlockDeviceError::LbaOutOfRange { lba, capacity } => {
                AhciError::LbaOutOfRange { lba, capacity }
            }
            BlockDeviceError::Lba48AddressOutOfRange { lba } => {
                AhciError::Lba48AddressOutOfRange { lba }
            }
            _ => AhciError::InvalidCapacity,
        })?;
        let sector: &[u8; SECTOR_SIZE] = buffer.try_into().expect("validated sector length");
        let mut sector_copy = [0u8; SECTOR_SIZE];
        sector_copy.copy_from_slice(sector);
        self.execute(ATA_WRITE_DMA_EXT, lba, 1, Some(&mut sector_copy), true)?;
        self.execute(ATA_FLUSH_CACHE_EXT, 0, 1, None, false)
    }
}

fn allocate_page(
    allocator: &mut FrameAllocator<'_>,
    physical_memory_offset: u64,
) -> Result<DmaPage, AhciError> {
    let physical_base = allocator
        .next()
        .ok_or(AhciError::NoDmaFrame)?
        .start_address();
    let virtual_base = physical_memory_offset
        .checked_add(physical_base)
        .ok_or(AhciError::DmaAddressOverflow)?;
    virtual_base
        .checked_add(PAGE_SIZE)
        .ok_or(AhciError::DmaAddressOverflow)?;
    if physical_base % AHCI_FIS_ALIGNMENT != 0 {
        return Err(AhciError::DmaUnaligned {
            address: physical_base,
            alignment: AHCI_FIS_ALIGNMENT,
        });
    }
    if physical_base % AHCI_COMMAND_TABLE_ALIGNMENT != 0 {
        return Err(AhciError::DmaUnaligned {
            address: physical_base,
            alignment: AHCI_COMMAND_TABLE_ALIGNMENT,
        });
    }
    let page = DmaPage {
        physical_base,
        virtual_base,
    };
    page.clear();
    Ok(page)
}

fn bytes_to_words(bytes: &[u8; SECTOR_SIZE]) -> [u16; 256] {
    let mut words = [0u16; 256];
    for (index, word) in words.iter_mut().enumerate() {
        let offset = index * 2;
        *word = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    }
    words
}
