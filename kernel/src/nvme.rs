#[cfg(target_os = "none")]
use core::sync::atomic::{AtomicU64, Ordering};

use bootloader_api::info::MemoryRegion;

use crate::memory::{FrameAllocator, PAGE_SIZE};
use crate::pci::{
    MmioError, MmioRegion, PciDevice, PciDeviceResources, PciInterruptMode, PciResourceError,
};
use crate::storage::{BlockDevice, BlockDeviceError, SECTOR_SIZE, validate_lba48};

#[cfg(target_os = "none")]
use crate::pci::{PciMsiRoute, PciMsixRoute};

const NVME_MMIO_LENGTH: u64 = 0x4000;
const NVME_MAX_QUEUE_ENTRIES: u16 = 16;
const NVME_ADMIN_QUEUE_ID: u16 = 0;
const NVME_IO_QUEUE_ID: u16 = 1;
const NVME_POLL_SPINS: usize = 2_000_000;
const NVME_INTERRUPT_WAIT_SPINS: usize = 64;

const REG_CAP: u64 = 0x00;
const REG_INTMC: u64 = 0x10;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1c;
const REG_AQA: u64 = 0x24;
const REG_ASQ: u64 = 0x28;
const REG_ACQ: u64 = 0x30;
const REG_DOORBELLS: u64 = 0x1000;

const CAP_MQES_MASK: u64 = 0xffff;
const CAP_CSS_SHIFT: u64 = 37;
const CAP_CSS_NVM: u64 = 1;
const CAP_DSTRD_SHIFT: u64 = 32;
const CAP_MPSMIN_SHIFT: u64 = 48;
const CAP_MPSMIN_MASK: u64 = 0x0f;

const CC_ENABLE: u32 = 1 << 0;
const CC_CSS_NVM: u32 = 0;
const CC_MPS_4K: u32 = 0 << 7;
const CC_IOSQES_64: u32 = 6 << 16;
const CC_IOCQES_16: u32 = 4 << 20;
const CSTS_READY: u32 = 1 << 0;
const CSTS_FATAL: u32 = 1 << 1;

const ADMIN_CREATE_SUBMISSION_QUEUE: u8 = 0x01;
const ADMIN_CREATE_COMPLETION_QUEUE: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const NVM_FLUSH: u8 = 0x00;
const NVM_WRITE: u8 = 0x01;
const NVM_READ: u8 = 0x02;

const IDENTIFY_CONTROLLER: u32 = 1;
const IDENTIFY_NAMESPACE: u32 = 0;
const NAMESPACE_ID: u32 = 1;
const COMMAND_QUEUE_PHYSICALLY_CONTIGUOUS: u32 = 1 << 0;
const COMMAND_QUEUE_INTERRUPT_ENABLE: u32 = 1 << 1;
const COMPLETION_STATUS_PHASE: u32 = 1;
const NAMESPACE_IDENTIFY_SIZE: usize = 4096;
const COMPLETION_STATUS_SHIFT: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeError {
    Resources(PciResourceError),
    Mmio(MmioError),
    MemorySpaceDisabled,
    UnsupportedController {
        class: u8,
        subclass: u8,
        prog_if: u8,
    },
    InvalidCapability {
        value: u64,
    },
    UnsupportedPageSize {
        minimum: u8,
    },
    UnsupportedDoorbellStride {
        shift: u8,
    },
    UnsupportedQueueSize {
        maximum: u16,
    },
    NoDmaFrame,
    DmaAddressOverflow,
    DmaOutOfBounds {
        offset: u64,
        size: u64,
    },
    DmaUnaligned {
        address: u64,
        alignment: u64,
    },
    ControllerTimeout {
        register: u64,
        value: u32,
    },
    ControllerFatal {
        status: u32,
    },
    CommandFailed {
        queue: u16,
        cid: u16,
        status: u16,
    },
    CompletionMismatch {
        queue: u16,
        expected: u16,
        actual: u16,
    },
    InvalidControllerIdentify {
        version: u32,
    },
    InvalidNamespace {
        namespace_size: u64,
        format_index: u8,
        format_count: u8,
        lbads: u8,
        metadata_size: u16,
    },
    UnsupportedLbaSize {
        bytes: u32,
    },
    InvalidCapacity,
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
    #[cfg(target_os = "none")]
    InterruptRegistration(crate::interrupts::DeviceInterruptError),
}

impl From<PciResourceError> for NvmeError {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

impl From<MmioError> for NvmeError {
    fn from(error: MmioError) -> Self {
        Self::Mmio(error)
    }
}

#[cfg(target_os = "none")]
impl From<crate::interrupts::DeviceInterruptError> for NvmeError {
    fn from(error: crate::interrupts::DeviceInterruptError) -> Self {
        Self::InterruptRegistration(error)
    }
}

impl NvmeError {
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
            error => BlockDeviceError::Nvme {
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
            Self::InvalidCapability { .. } => 5,
            Self::UnsupportedPageSize { .. } => 6,
            Self::UnsupportedDoorbellStride { .. } => 7,
            Self::UnsupportedQueueSize { .. } => 8,
            Self::NoDmaFrame => 9,
            Self::DmaAddressOverflow => 10,
            Self::DmaOutOfBounds { .. } => 11,
            Self::DmaUnaligned { .. } => 12,
            Self::ControllerTimeout { .. } => 13,
            Self::ControllerFatal { .. } => 14,
            Self::CommandFailed { .. } => 15,
            Self::CompletionMismatch { .. } => 16,
            Self::InvalidControllerIdentify { .. } => 17,
            Self::InvalidNamespace { .. } => 18,
            Self::UnsupportedLbaSize { .. } => 19,
            Self::InvalidCapacity => 20,
            Self::LbaOutOfRange { .. } => 21,
            Self::Lba48AddressOutOfRange { .. } => 22,
            Self::InvalidBufferLength { .. } => 23,
            #[cfg(target_os = "none")]
            Self::InterruptRegistration(_) => 24,
        }
    }

    fn value_code(self) -> u64 {
        match self {
            Self::InvalidCapability { value } => value,
            Self::ControllerFatal { status } => u64::from(status),
            Self::InvalidControllerIdentify { version } => u64::from(version),
            Self::UnsupportedLbaSize { bytes } => u64::from(bytes),
            Self::UnsupportedPageSize { minimum } => u64::from(minimum),
            Self::UnsupportedDoorbellStride { shift } => u64::from(shift),
            Self::UnsupportedQueueSize { maximum } => u64::from(maximum),
            Self::DmaOutOfBounds { offset, size } => (offset & 0xffff_ffff) | (size << 32),
            Self::DmaUnaligned { address, alignment } => {
                (address & 0xffff_ffff) | (alignment << 32)
            }
            Self::ControllerTimeout { register, value } => (register << 32) | u64::from(value),
            Self::CommandFailed { queue, cid, status } => {
                (u64::from(queue) << 32) | (u64::from(cid) << 16) | u64::from(status)
            }
            Self::CompletionMismatch {
                queue,
                expected,
                actual,
            } => (u64::from(queue) << 32) | (u64::from(expected) << 16) | u64::from(actual),
            Self::InvalidNamespace {
                namespace_size,
                format_index,
                format_count,
                lbads,
                metadata_size,
            } => {
                namespace_size
                    ^ (u64::from(format_index) << 48)
                    ^ (u64::from(format_count) << 40)
                    ^ (u64::from(lbads) << 32)
                    ^ u64::from(metadata_size)
            }
            Self::LbaOutOfRange { lba, .. } | Self::Lba48AddressOutOfRange { lba } => lba,
            Self::InvalidBufferLength { expected, actual } => {
                (u64::try_from(expected).unwrap_or(u64::MAX) << 32)
                    | u64::try_from(actual).unwrap_or(u64::MAX)
            }
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceIdentify {
    pub namespace_size: u64,
    pub lba_format_index: u8,
    pub lba_format_count: u8,
    pub logical_block_bytes: u32,
    pub metadata_bytes: u16,
}

pub fn parse_namespace_identify(
    identify: &[u8; NAMESPACE_IDENTIFY_SIZE],
) -> Result<NamespaceIdentify, NvmeError> {
    let namespace_size = read_le_u64(identify, 0);
    let format_count = identify[25].checked_add(1).unwrap_or(0);
    let format_index = identify[26] & 0x0f;
    if namespace_size == 0
        || format_count == 0
        || format_count > 16
        || format_index >= format_count
        || format_index >= 16
    {
        return Err(NvmeError::InvalidNamespace {
            namespace_size,
            format_index,
            format_count,
            lbads: 0,
            metadata_size: 0,
        });
    }

    let format_offset = 128 + usize::from(format_index) * 4;
    let metadata_bytes = read_le_u16(identify, format_offset);
    let lbads = identify[format_offset + 2];
    let logical_block_bytes = if lbads < 32 { 1u32 << lbads } else { 0 };
    if logical_block_bytes == 0 {
        return Err(NvmeError::InvalidNamespace {
            namespace_size,
            format_index,
            format_count,
            lbads,
            metadata_size: metadata_bytes,
        });
    }
    if metadata_bytes != 0 {
        return Err(NvmeError::InvalidNamespace {
            namespace_size,
            format_index,
            format_count,
            lbads,
            metadata_size: metadata_bytes,
        });
    }

    Ok(NamespaceIdentify {
        namespace_size,
        lba_format_index: format_index,
        lba_format_count: format_count,
        logical_block_bytes,
        metadata_bytes,
    })
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

    fn pointer(self, offset: u64, size: u64, alignment: u64) -> Result<u64, NvmeError> {
        if self.physical_base % alignment != 0 || offset % alignment != 0 {
            return Err(NvmeError::DmaUnaligned {
                address: self.physical_base.saturating_add(offset),
                alignment,
            });
        }
        let end = offset
            .checked_add(size)
            .ok_or(NvmeError::DmaAddressOverflow)?;
        if end > PAGE_SIZE {
            return Err(NvmeError::DmaOutOfBounds { offset, size });
        }
        self.virtual_base
            .checked_add(offset)
            .ok_or(NvmeError::DmaAddressOverflow)
    }

    fn write_u8(self, offset: u64, value: u8) -> Result<(), NvmeError> {
        let pointer = self.pointer(offset, 1, 1)?;
        // SAFETY: pointer is bounds-checked against the allocated page.
        unsafe { core::ptr::write_volatile(pointer as *mut u8, value) };
        Ok(())
    }

    fn write_u32(self, offset: u64, value: u32) -> Result<(), NvmeError> {
        let pointer = self.pointer(offset, 4, 4)?;
        // SAFETY: pointer is bounds-checked and aligned for a 32-bit volatile field.
        unsafe { core::ptr::write_volatile(pointer as *mut u32, value.to_le()) };
        Ok(())
    }

    fn read_u32(self, offset: u64) -> Result<u32, NvmeError> {
        let pointer = self.pointer(offset, 4, 4)?;
        // SAFETY: pointer is bounds-checked and aligned for a 32-bit volatile field.
        Ok(u32::from_le(unsafe {
            core::ptr::read_volatile(pointer as *const u32)
        }))
    }

    fn write_bytes(self, offset: u64, bytes: &[u8]) -> Result<(), NvmeError> {
        for (index, byte) in bytes.iter().copied().enumerate() {
            let index = u64::try_from(index).map_err(|_| NvmeError::DmaAddressOverflow)?;
            self.write_u8(
                offset
                    .checked_add(index)
                    .ok_or(NvmeError::DmaAddressOverflow)?,
                byte,
            )?;
        }
        Ok(())
    }

    fn read_bytes(self, offset: u64, bytes: &mut [u8]) -> Result<(), NvmeError> {
        for (index, byte) in bytes.iter_mut().enumerate() {
            let index = u64::try_from(index).map_err(|_| NvmeError::DmaAddressOverflow)?;
            let pointer = self.pointer(
                offset
                    .checked_add(index)
                    .ok_or(NvmeError::DmaAddressOverflow)?,
                1,
                1,
            )?;
            // SAFETY: pointer is bounds-checked against the allocated page.
            *byte = unsafe { core::ptr::read_volatile(pointer as *const u8) };
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Command {
    words: [u32; 16],
}

impl Command {
    fn new(opcode: u8, cid: u16) -> Self {
        let mut command = Self { words: [0; 16] };
        command.words[0] = u32::from(opcode) | (u32::from(cid) << 16);
        command
    }

    fn nsid(&mut self, nsid: u32) {
        self.words[1] = nsid;
    }

    fn prp1(&mut self, address: u64) {
        self.words[6] = address as u32;
        self.words[7] = (address >> 32) as u32;
    }

    fn cdw10(&mut self, value: u32) {
        self.words[10] = value;
    }

    fn cdw11(&mut self, value: u32) {
        self.words[11] = value;
    }

    fn cdw12(&mut self, value: u32) {
        self.words[12] = value;
    }

    fn cid(self) -> u16 {
        (self.words[0] >> 16) as u16
    }
}

#[derive(Debug)]
pub struct NvmeDisk {
    capacity_sectors: u64,
    namespace_id: u32,
    controller_version: u32,
    mmio: MmioRegion,
    doorbell_stride: u64,
    queue_entries: u16,
    admin_submission: DmaPage,
    admin_completion: DmaPage,
    io_submission: DmaPage,
    io_completion: DmaPage,
    controller_identify: DmaPage,
    namespace_identify: DmaPage,
    data: DmaPage,
    admin_tail: u16,
    admin_head: u16,
    admin_phase: bool,
    next_admin_cid: u16,
    io_tail: u16,
    io_head: u16,
    io_phase: bool,
    next_io_cid: u16,
    next_frame_address: Option<u64>,
    pub interrupt_vector: Option<u8>,
    pub interrupt_mode: PciInterruptMode,
    pub interrupt_count: u64,
    pub interrupt_driven: bool,
    pub interrupt_error: Option<NvmeError>,
    resources: PciDeviceResources,
}

#[cfg(target_os = "none")]
static NVME_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "none")]
fn nvme_interrupt_handler() {
    NVME_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);
}

impl NvmeDisk {
    pub fn initialize(
        device: PciDevice,
        physical_memory_offset: u64,
        regions: &[MemoryRegion],
        next_frame_address: Option<u64>,
    ) -> Result<Self, NvmeError> {
        if device.class_code != 0x01 || device.subclass != 0x08 || device.prog_if != 0x02 {
            return Err(NvmeError::UnsupportedController {
                class: device.class_code,
                subclass: device.subclass,
                prog_if: device.prog_if,
            });
        }
        if !device.memory_space_enabled() {
            return Err(NvmeError::MemorySpaceDisabled);
        }

        let mut resources = PciDeviceResources::new(device, physical_memory_offset);
        resources.enable_bus_master()?;
        let mmio = resources.claim_mmio(0, NVME_MMIO_LENGTH)?;
        let capabilities = read_mmio_u64(mmio, REG_CAP)?;
        let max_queue_entries = ((capabilities & CAP_MQES_MASK) as u16).saturating_add(1);
        let queue_entries = max_queue_entries.min(NVME_MAX_QUEUE_ENTRIES);
        if queue_entries < 2 {
            return Err(NvmeError::UnsupportedQueueSize {
                maximum: max_queue_entries,
            });
        }
        let minimum_page_size = ((capabilities >> CAP_MPSMIN_SHIFT) & CAP_MPSMIN_MASK) as u8;
        if minimum_page_size != 0 {
            return Err(NvmeError::UnsupportedPageSize {
                minimum: minimum_page_size,
            });
        }
        if (capabilities >> CAP_CSS_SHIFT) & CAP_CSS_NVM == 0 {
            return Err(NvmeError::InvalidCapability {
                value: capabilities,
            });
        }
        let doorbell_shift = ((capabilities >> CAP_DSTRD_SHIFT) & 0x0f) as u8;
        if doorbell_shift > 4 {
            return Err(NvmeError::UnsupportedDoorbellStride {
                shift: doorbell_shift,
            });
        }
        let doorbell_stride = 4u64
            .checked_shl(u32::from(doorbell_shift))
            .ok_or(NvmeError::DmaAddressOverflow)?;
        let last_doorbell = REG_DOORBELLS
            .checked_add(3 * doorbell_stride)
            .and_then(|offset| offset.checked_add(4))
            .ok_or(NvmeError::DmaAddressOverflow)?;
        if last_doorbell > NVME_MMIO_LENGTH {
            return Err(NvmeError::UnsupportedDoorbellStride {
                shift: doorbell_shift,
            });
        }

        let mut allocator = FrameAllocator::starting_at(regions, next_frame_address.unwrap_or(0));
        let admin_submission = allocate_page(&mut allocator, physical_memory_offset)?;
        let admin_completion = allocate_page(&mut allocator, physical_memory_offset)?;
        let io_submission = allocate_page(&mut allocator, physical_memory_offset)?;
        let io_completion = allocate_page(&mut allocator, physical_memory_offset)?;
        let controller_identify = allocate_page(&mut allocator, physical_memory_offset)?;
        let namespace_identify = allocate_page(&mut allocator, physical_memory_offset)?;
        let data = allocate_page(&mut allocator, physical_memory_offset)?;

        let mut disk = Self {
            capacity_sectors: 0,
            namespace_id: NAMESPACE_ID,
            controller_version: 0,
            mmio,
            doorbell_stride,
            queue_entries,
            admin_submission,
            admin_completion,
            io_submission,
            io_completion,
            controller_identify,
            namespace_identify,
            data,
            admin_tail: 0,
            admin_head: 0,
            admin_phase: true,
            next_admin_cid: 1,
            io_tail: 0,
            io_head: 0,
            io_phase: true,
            next_io_cid: 1,
            next_frame_address: allocator.next_available_address(),
            interrupt_vector: None,
            interrupt_mode: PciInterruptMode::None,
            interrupt_count: 0,
            interrupt_driven: false,
            interrupt_error: None,
            resources,
        };
        disk.reset_and_enable()?;
        #[cfg(target_os = "none")]
        disk.configure_interrupts();
        disk.identify_controller()?;
        disk.identify_namespace()?;
        disk.create_io_queues()?;

        // Exercise the namespace I/O queue before the filesystem layer claims the disk. The
        // authoritative filesystem probe performs its own read of LBA 0.
        let mut boot_sector = [0u8; SECTOR_SIZE];
        disk.read_sector(0, &mut boot_sector)?;
        Ok(disk)
    }

    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    pub fn namespace_id(&self) -> u32 {
        self.namespace_id
    }

    pub fn controller_version(&self) -> u32 {
        self.controller_version
    }

    pub fn mmio_base(&self) -> u64 {
        self.mmio.physical_base()
    }

    pub fn queue_entries(&self) -> u16 {
        self.queue_entries
    }

    pub fn doorbell_stride(&self) -> u64 {
        self.doorbell_stride
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
        self.interrupt_count
    }

    pub fn interrupt_driven(&self) -> bool {
        self.interrupt_driven
    }

    #[cfg(target_os = "none")]
    fn configure_interrupts(&mut self) {
        let Some(destination_apic_id) = crate::apic::local_apic_id_u32() else {
            return;
        };
        let vector = match crate::interrupts::register_device_handler(nvme_interrupt_handler) {
            Ok(vector) => vector,
            Err(error) => {
                self.interrupt_error = Some(error.into());
                return;
            }
        };
        self.interrupt_vector = Some(vector);
        NVME_INTERRUPT_COUNT.store(0, Ordering::SeqCst);

        match self.resources.enable_msix(vector, destination_apic_id) {
            Ok(route) => match self.arm_msix_interrupts(route) {
                Ok(()) => return,
                Err(_) => {}
            },
            Err(_) => {}
        }

        match self.resources.enable_msi(vector, destination_apic_id) {
            Ok(route) => match self.arm_msi_interrupts(route) {
                Ok(()) => return,
                Err(error) => self.interrupt_error = Some(error),
            },
            Err(error) => self.interrupt_error = Some(error.into()),
        }
    }

    #[cfg(target_os = "none")]
    fn arm_msix_interrupts(&mut self, _route: PciMsixRoute) -> Result<(), NvmeError> {
        self.mmio.write_u32(REG_INTMC, u32::MAX)?;
        self.interrupt_mode = PciInterruptMode::Msix;
        self.interrupt_driven = true;
        NVME_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(target_os = "none")]
    fn arm_msi_interrupts(&mut self, _route: PciMsiRoute) -> Result<(), NvmeError> {
        self.mmio.write_u32(REG_INTMC, u32::MAX)?;
        self.interrupt_mode = PciInterruptMode::Msi;
        self.interrupt_driven = true;
        NVME_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        Ok(())
    }

    fn reset_and_enable(&mut self) -> Result<(), NvmeError> {
        let current_cc = self.mmio.read_u32(REG_CC)?;
        if current_cc & CC_ENABLE != 0 {
            self.mmio.write_u32(REG_CC, current_cc & !CC_ENABLE)?;
            self.wait_ready(false)?;
        }
        self.admin_submission.clear();
        self.admin_completion.clear();
        self.io_submission.clear();
        self.io_completion.clear();

        let queue_size = u32::from(self.queue_entries - 1);
        self.mmio
            .write_u32(REG_AQA, queue_size | (queue_size << 16))?;
        write_mmio_u64(self.mmio, REG_ASQ, self.admin_submission.physical_base)?;
        write_mmio_u64(self.mmio, REG_ACQ, self.admin_completion.physical_base)?;
        self.mmio.write_u32(
            REG_CC,
            CC_ENABLE | CC_CSS_NVM | CC_MPS_4K | CC_IOSQES_64 | CC_IOCQES_16,
        )?;
        self.wait_ready(true)
    }

    fn wait_ready(&self, ready: bool) -> Result<(), NvmeError> {
        let mut last = 0;
        for _ in 0..NVME_POLL_SPINS {
            last = self.mmio.read_u32(REG_CSTS)?;
            if last & CSTS_FATAL != 0 {
                return Err(NvmeError::ControllerFatal { status: last });
            }
            if (last & CSTS_READY != 0) == ready {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(NvmeError::ControllerTimeout {
            register: REG_CSTS,
            value: last,
        })
    }

    fn identify_controller(&mut self) -> Result<(), NvmeError> {
        self.controller_identify.clear();
        let cid = self.next_admin_command_id();
        let mut command = Command::new(ADMIN_IDENTIFY, cid);
        command.prp1(self.controller_identify.physical_base);
        command.cdw10(IDENTIFY_CONTROLLER);
        self.execute_admin(command)?;
        let mut identify = [0u8; NAMESPACE_IDENTIFY_SIZE];
        self.controller_identify.read_bytes(0, &mut identify)?;
        self.controller_version = read_le_u32(&identify, 80);
        if self.controller_version == 0 {
            return Err(NvmeError::InvalidControllerIdentify {
                version: self.controller_version,
            });
        }
        Ok(())
    }

    fn identify_namespace(&mut self) -> Result<(), NvmeError> {
        self.namespace_identify.clear();
        let cid = self.next_admin_command_id();
        let mut command = Command::new(ADMIN_IDENTIFY, cid);
        command.nsid(self.namespace_id);
        command.prp1(self.namespace_identify.physical_base);
        command.cdw10(IDENTIFY_NAMESPACE);
        self.execute_admin(command)?;
        let mut identify = [0u8; NAMESPACE_IDENTIFY_SIZE];
        self.namespace_identify.read_bytes(0, &mut identify)?;
        let parsed = parse_namespace_identify(&identify)?;
        if parsed.logical_block_bytes != SECTOR_SIZE as u32 {
            return Err(NvmeError::UnsupportedLbaSize {
                bytes: parsed.logical_block_bytes,
            });
        }
        if parsed.namespace_size - 1 > crate::storage::ATA_MAX_LBA48 {
            return Err(NvmeError::Lba48AddressOutOfRange {
                lba: parsed.namespace_size - 1,
            });
        }
        self.capacity_sectors = parsed.namespace_size;
        if self.capacity_sectors == 0 {
            return Err(NvmeError::InvalidCapacity);
        }
        Ok(())
    }

    fn create_io_queues(&mut self) -> Result<(), NvmeError> {
        let queue_size = u32::from(self.queue_entries - 1);
        let cid = self.next_admin_command_id();
        let mut completion = Command::new(ADMIN_CREATE_COMPLETION_QUEUE, cid);
        completion.prp1(self.io_completion.physical_base);
        completion.cdw10(u32::from(NVME_IO_QUEUE_ID) | (queue_size << 16));
        let completion_flags = COMMAND_QUEUE_PHYSICALLY_CONTIGUOUS
            | if self.interrupt_driven {
                COMMAND_QUEUE_INTERRUPT_ENABLE
            } else {
                0
            };
        completion.cdw11(completion_flags);
        self.execute_admin(completion)?;

        let cid = self.next_admin_command_id();
        let mut submission = Command::new(ADMIN_CREATE_SUBMISSION_QUEUE, cid);
        submission.prp1(self.io_submission.physical_base);
        submission.cdw10(u32::from(NVME_IO_QUEUE_ID) | (queue_size << 16));
        submission.cdw11(COMMAND_QUEUE_PHYSICALLY_CONTIGUOUS | (u32::from(NVME_IO_QUEUE_ID) << 16));
        self.execute_admin(submission).map(|_| ())
    }

    fn next_admin_command_id(&mut self) -> u16 {
        let cid = self.next_admin_cid;
        self.next_admin_cid = self.next_admin_cid.wrapping_add(1).max(1);
        cid
    }

    fn next_io_command_id(&mut self) -> u16 {
        let cid = self.next_io_cid;
        self.next_io_cid = self.next_io_cid.wrapping_add(1).max(1);
        cid
    }

    fn execute_admin(&mut self, command: Command) -> Result<u32, NvmeError> {
        let result = execute_queue(
            self.mmio,
            self.doorbell_stride,
            NVME_ADMIN_QUEUE_ID,
            self.queue_entries,
            self.admin_submission,
            self.admin_completion,
            &mut self.admin_tail,
            &mut self.admin_head,
            &mut self.admin_phase,
            command,
            self.interrupt_driven,
        );
        self.refresh_interrupt_count();
        result
    }

    fn execute_io(&mut self, command: Command) -> Result<u32, NvmeError> {
        let result = execute_queue(
            self.mmio,
            self.doorbell_stride,
            NVME_IO_QUEUE_ID,
            self.queue_entries,
            self.io_submission,
            self.io_completion,
            &mut self.io_tail,
            &mut self.io_head,
            &mut self.io_phase,
            command,
            self.interrupt_driven,
        );
        self.refresh_interrupt_count();
        result
    }

    fn refresh_interrupt_count(&mut self) {
        #[cfg(target_os = "none")]
        {
            self.interrupt_count = NVME_INTERRUPT_COUNT.load(Ordering::Acquire);
        }
    }

    fn flush(&mut self) -> Result<(), NvmeError> {
        let cid = self.next_io_command_id();
        let mut command = Command::new(NVM_FLUSH, cid);
        command.nsid(self.namespace_id);
        self.execute_io(command).map(|_| ())
    }
}

impl BlockDevice for NvmeDisk {
    type Error = NvmeError;

    fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors()
    }

    fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        if buffer.len() != SECTOR_SIZE {
            return Err(NvmeError::InvalidBufferLength {
                expected: SECTOR_SIZE,
                actual: buffer.len(),
            });
        }
        validate_lba48(lba, self.capacity_sectors).map_err(|error| match error {
            BlockDeviceError::LbaOutOfRange { lba, capacity } => {
                NvmeError::LbaOutOfRange { lba, capacity }
            }
            BlockDeviceError::Lba48AddressOutOfRange { lba } => {
                NvmeError::Lba48AddressOutOfRange { lba }
            }
            _ => NvmeError::InvalidCapacity,
        })?;
        let cid = self.next_io_command_id();
        let mut command = Command::new(NVM_READ, cid);
        command.nsid(self.namespace_id);
        command.prp1(self.data.physical_base);
        command.cdw10(lba as u32);
        command.cdw11((lba >> 32) as u32);
        command.cdw12(0);
        self.execute_io(command)?;
        self.data.read_bytes(0, buffer)
    }

    fn write_sector(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        if buffer.len() != SECTOR_SIZE {
            return Err(NvmeError::InvalidBufferLength {
                expected: SECTOR_SIZE,
                actual: buffer.len(),
            });
        }
        validate_lba48(lba, self.capacity_sectors).map_err(|error| match error {
            BlockDeviceError::LbaOutOfRange { lba, capacity } => {
                NvmeError::LbaOutOfRange { lba, capacity }
            }
            BlockDeviceError::Lba48AddressOutOfRange { lba } => {
                NvmeError::Lba48AddressOutOfRange { lba }
            }
            _ => NvmeError::InvalidCapacity,
        })?;
        self.data.write_bytes(0, buffer)?;
        let cid = self.next_io_command_id();
        let mut command = Command::new(NVM_WRITE, cid);
        command.nsid(self.namespace_id);
        command.prp1(self.data.physical_base);
        command.cdw10(lba as u32);
        command.cdw11((lba >> 32) as u32);
        command.cdw12(0);
        self.execute_io(command)?;
        self.flush()
    }
}

fn execute_queue(
    mmio: MmioRegion,
    doorbell_stride: u64,
    queue_id: u16,
    queue_entries: u16,
    submission: DmaPage,
    completion: DmaPage,
    submission_tail: &mut u16,
    completion_head: &mut u16,
    completion_phase: &mut bool,
    command: Command,
    interrupt_driven: bool,
) -> Result<u32, NvmeError> {
    let command_offset = u64::from(*submission_tail) * 64;
    for (index, word) in command.words.iter().copied().enumerate() {
        submission.write_u32(
            u64::try_from(index).unwrap_or(u64::MAX) * 4 + command_offset,
            word,
        )?;
    }
    let tail = (*submission_tail + 1) % queue_entries;
    *submission_tail = tail;
    let submission_doorbell = REG_DOORBELLS
        .checked_add(u64::from(queue_id) * 2 * doorbell_stride)
        .ok_or(NvmeError::DmaAddressOverflow)?;
    mmio.write_u32(submission_doorbell, u32::from(tail))?;

    let expected_cid = command.cid();
    let mut last_status = 0;
    let wait_spins = if interrupt_driven {
        NVME_INTERRUPT_WAIT_SPINS
    } else {
        NVME_POLL_SPINS
    };
    for _ in 0..wait_spins {
        let completion_offset = u64::from(*completion_head) * 16;
        let status = completion.read_u32(completion_offset + 12)?;
        last_status = ((status >> 16) as u16) & !1;
        if ((status >> COMPLETION_STATUS_SHIFT) & COMPLETION_STATUS_PHASE)
            == u32::from(*completion_phase)
        {
            let actual_cid = status as u16;
            let result = completion.read_u32(completion_offset)?;
            *completion_head = (*completion_head + 1) % queue_entries;
            if *completion_head == 0 {
                *completion_phase = !*completion_phase;
            }
            let completion_doorbell = REG_DOORBELLS
                .checked_add((u64::from(queue_id) * 2 + 1) * doorbell_stride)
                .ok_or(NvmeError::DmaAddressOverflow)?;
            mmio.write_u32(completion_doorbell, u32::from(*completion_head))?;
            if actual_cid != expected_cid {
                return Err(NvmeError::CompletionMismatch {
                    queue: queue_id,
                    expected: expected_cid,
                    actual: actual_cid,
                });
            }
            if last_status != 0 {
                return Err(NvmeError::CommandFailed {
                    queue: queue_id,
                    cid: actual_cid,
                    status: last_status,
                });
            }
            return Ok(result);
        }
        wait_for_completion(interrupt_driven);
    }
    Err(NvmeError::ControllerTimeout {
        register: REG_DOORBELLS + u64::from(queue_id) * 2 * doorbell_stride,
        value: (u32::from(expected_cid) << 16) | u32::from(last_status),
    })
}

fn wait_for_completion(interrupt_driven: bool) {
    #[cfg(target_os = "none")]
    if interrupt_driven && x86_64::instructions::interrupts::are_enabled() {
        crate::interrupts::halt();
        return;
    }
    let _ = interrupt_driven;
    core::hint::spin_loop();
}

fn allocate_page(
    allocator: &mut FrameAllocator<'_>,
    physical_memory_offset: u64,
) -> Result<DmaPage, NvmeError> {
    let physical_base = allocator
        .next()
        .ok_or(NvmeError::NoDmaFrame)?
        .start_address();
    if physical_base & (PAGE_SIZE - 1) != 0 {
        return Err(NvmeError::DmaUnaligned {
            address: physical_base,
            alignment: PAGE_SIZE,
        });
    }
    let virtual_base = physical_memory_offset
        .checked_add(physical_base)
        .ok_or(NvmeError::DmaAddressOverflow)?;
    virtual_base
        .checked_add(PAGE_SIZE)
        .ok_or(NvmeError::DmaAddressOverflow)?;
    let page = DmaPage {
        physical_base,
        virtual_base,
    };
    page.clear();
    Ok(page)
}

fn read_mmio_u64(mmio: MmioRegion, offset: u64) -> Result<u64, NvmeError> {
    Ok(u64::from(mmio.read_u32(offset)?) | (u64::from(mmio.read_u32(offset + 4)?) << 32))
}

fn write_mmio_u64(mmio: MmioRegion, offset: u64, value: u64) -> Result<(), NvmeError> {
    mmio.write_u32(offset, value as u32)?;
    mmio.write_u32(offset + 4, (value >> 32) as u32)?;
    Ok(())
}

fn read_le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::{NvmeError, parse_namespace_identify};

    #[test]
    fn parses_a_512_byte_namespace() {
        let mut identify = [0u8; 4096];
        identify[0..8].copy_from_slice(&123_456u64.to_le_bytes());
        identify[25] = 0;
        identify[26] = 0;
        identify[128..132].copy_from_slice(&0x0009_0000u32.to_le_bytes());

        assert_eq!(
            parse_namespace_identify(&identify).unwrap(),
            super::NamespaceIdentify {
                namespace_size: 123_456,
                lba_format_index: 0,
                lba_format_count: 1,
                logical_block_bytes: 512,
                metadata_bytes: 0,
            }
        );
    }

    #[test]
    fn rejects_metadata_and_non_512_formats() {
        let mut identify = [0u8; 4096];
        identify[0..8].copy_from_slice(&10u64.to_le_bytes());
        identify[25] = 1;
        identify[26] = 1;
        identify[132..134].copy_from_slice(&8u16.to_le_bytes());
        identify[134] = 12;
        assert!(matches!(
            parse_namespace_identify(&identify),
            Err(NvmeError::InvalidNamespace { .. })
        ));
    }
}
