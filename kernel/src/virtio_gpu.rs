use alloc::vec::Vec;
use bootloader_api::info::{FrameBufferInfo, MemoryRegion, PixelFormat};
use core::sync::atomic::{Ordering, fence};
use spin::Mutex;

use crate::framebuffer::GraphicsInfo;
use crate::memory::{FrameAllocator, PAGE_SIZE};
use crate::pci::{
    MmioError, MmioRegion, PciAddress, PciDevice, PciDeviceResources, PciInventory,
    PciResourceError,
};

const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_GPU_DEVICE_ID: u16 = 0x1050;

const VIRTIO_PCI_CAP_COMMON_CONFIG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CONFIG: u8 = 2;
const VIRTIO_PCI_CAP_DEVICE_CONFIG: u8 = 4;

const DEVICE_FEATURE_SELECT: u64 = 0x00;
const DEVICE_FEATURE: u64 = 0x04;
const DRIVER_FEATURE_SELECT: u64 = 0x08;
const DRIVER_FEATURE: u64 = 0x0c;
const NUM_QUEUES: u64 = 0x12;
const DEVICE_STATUS: u64 = 0x14;
const QUEUE_SELECT: u64 = 0x16;
const QUEUE_SIZE: u64 = 0x18;
const QUEUE_MSIX_VECTOR: u64 = 0x1a;
const QUEUE_ENABLE: u64 = 0x1c;
const QUEUE_NOTIFY_OFFSET: u64 = 0x1e;
const QUEUE_DESC_LOW: u64 = 0x20;
const QUEUE_DRIVER_LOW: u64 = 0x28;
const QUEUE_DEVICE_LOW: u64 = 0x30;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;

const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 1 << 1;
const QUEUE_SIZE_LIMIT: u16 = 8;
const POLL_SPINS: usize = 10_000_000;
const DMA_ALLOCATION_FLOOR: u64 = 8 * 1024 * 1024;

const GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const GPU_CMD_SET_SCANOUT: u32 = 0x0103;
const GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
const GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

const GPU_RESP_OK_NODATA: u32 = 0x1100;
const GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
const GPU_RESP_ERROR_MIN: u32 = 0x1200;

const GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
const GPU_RESOURCE_ID: u32 = 1;
const GPU_SCANOUT_ID: u32 = 0;
const GPU_HEADER_LENGTH: u64 = 24;
const GPU_MAX_BACKING_ENTRIES: usize = 64;
const GPU_MAX_DIMENSION: u32 = 4096;
const GPU_MAX_BYTES: u64 = 64 * 1024 * 1024;
const GPU_RESPONSE_LENGTH: u32 = PAGE_SIZE as u32;

static GPU_RUNTIME: Mutex<Option<VirtioGpuRuntime>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuDmaError {
    NoFrame,
    AddressOverflow,
    Unaligned { offset: u64, alignment: u64 },
    OutOfBounds { offset: u64, size: u64 },
    BackingOutOfBounds { offset: usize, size: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioGpuError {
    Resources(PciResourceError),
    Mmio(MmioError),
    Dma(GpuDmaError),
    MemorySpaceDisabled,
    MissingCapability { cfg_type: u8 },
    NoFramebuffer,
    UnsupportedFramebuffer,
    DisplayUnavailable,
    FeatureNegotiationFailed,
    QueueUnavailable,
    QueueTooSmall { size: u16 },
    QueueAddressOverflow,
    QueueDescriptorInvalid { descriptor: u32 },
    CommandTooLarge,
    CommandTimeout,
    CommandFailed { response: u32 },
    BackingEntriesExceeded,
    FrameDimensionsChanged,
    FrameBufferTooShort,
}

impl From<PciResourceError> for VirtioGpuError {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

impl From<MmioError> for VirtioGpuError {
    fn from(error: MmioError) -> Self {
        Self::Mmio(error)
    }
}

impl From<GpuDmaError> for VirtioGpuError {
    fn from(error: GpuDmaError) -> Self {
        Self::Dma(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioGpuInitFailure {
    pub error: VirtioGpuError,
    pub next_frame_address: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct DmaPage {
    physical_base: u64,
    virtual_base: u64,
}

impl DmaPage {
    fn clear(self) {
        // The frame allocator only hands out physical pages covered by the bootloader's direct
        // physical mapping. The page is private to this driver and is never shared with Rust.
        unsafe { core::ptr::write_bytes(self.virtual_base as *mut u8, 0, PAGE_SIZE as usize) };
    }

    fn write_u16(self, offset: u64, value: u16) -> Result<(), GpuDmaError> {
        let pointer = self.pointer(offset, 2, 2)?;
        unsafe { core::ptr::write_volatile(pointer as *mut u16, value.to_le()) };
        Ok(())
    }

    fn write_u32(self, offset: u64, value: u32) -> Result<(), GpuDmaError> {
        let pointer = self.pointer(offset, 4, 4)?;
        unsafe { core::ptr::write_volatile(pointer as *mut u32, value.to_le()) };
        Ok(())
    }

    fn write_u64(self, offset: u64, value: u64) -> Result<(), GpuDmaError> {
        let pointer = self.pointer(offset, 8, 8)?;
        unsafe { core::ptr::write_volatile(pointer as *mut u64, value.to_le()) };
        Ok(())
    }

    fn read_u16(self, offset: u64) -> Result<u16, GpuDmaError> {
        let pointer = self.pointer(offset, 2, 2)?;
        Ok(u16::from_le(unsafe {
            core::ptr::read_volatile(pointer as *const u16)
        }))
    }

    fn read_u32(self, offset: u64) -> Result<u32, GpuDmaError> {
        let pointer = self.pointer(offset, 4, 4)?;
        Ok(u32::from_le(unsafe {
            core::ptr::read_volatile(pointer as *const u32)
        }))
    }

    fn pointer(self, offset: u64, size: u64, alignment: u64) -> Result<u64, GpuDmaError> {
        if offset % alignment != 0 {
            return Err(GpuDmaError::Unaligned { offset, alignment });
        }
        let end = offset
            .checked_add(size)
            .ok_or(GpuDmaError::AddressOverflow)?;
        if end > PAGE_SIZE {
            return Err(GpuDmaError::OutOfBounds { offset, size });
        }
        self.virtual_base
            .checked_add(offset)
            .ok_or(GpuDmaError::AddressOverflow)
    }
}

#[derive(Debug, Clone, Copy)]
struct VirtQueue {
    descriptors: DmaPage,
    available: DmaPage,
    used: DmaPage,
    size: u16,
    available_index: u16,
    last_used_index: u16,
}

impl VirtQueue {
    fn allocate(
        allocator: &mut FrameAllocator<'_>,
        physical_memory_offset: u64,
    ) -> Result<Self, VirtioGpuError> {
        Ok(Self {
            descriptors: allocate_page(allocator, physical_memory_offset)?,
            available: allocate_page(allocator, physical_memory_offset)?,
            used: allocate_page(allocator, physical_memory_offset)?,
            size: 0,
            available_index: 0,
            last_used_index: 0,
        })
    }

    fn set_descriptor(
        self,
        index: usize,
        address: u64,
        length: u32,
        flags: u16,
        next: u16,
    ) -> Result<(), VirtioGpuError> {
        let offset = u64::try_from(index)
            .map_err(|_| VirtioGpuError::QueueAddressOverflow)?
            .checked_mul(16)
            .ok_or(VirtioGpuError::QueueAddressOverflow)?;
        self.descriptors.write_u64(offset, address)?;
        self.descriptors.write_u32(offset + 8, length)?;
        self.descriptors.write_u16(offset + 12, flags)?;
        self.descriptors.write_u16(offset + 14, next)?;
        Ok(())
    }

    fn push_available(&mut self, descriptor: u16) -> Result<(), VirtioGpuError> {
        if self.size == 0 {
            return Err(VirtioGpuError::QueueUnavailable);
        }
        let ring_offset = 4u64
            .checked_add(
                u64::from(self.available_index % self.size)
                    .checked_mul(2)
                    .ok_or(VirtioGpuError::QueueAddressOverflow)?,
            )
            .ok_or(VirtioGpuError::QueueAddressOverflow)?;
        self.available.write_u16(ring_offset, descriptor)?;
        fence(Ordering::Release);
        self.available_index = self.available_index.wrapping_add(1);
        self.available.write_u16(2, self.available_index)?;
        Ok(())
    }

    fn used_index(self) -> Result<u16, VirtioGpuError> {
        fence(Ordering::Acquire);
        Ok(self.used.read_u16(2)?)
    }

    fn used_element(self, index: u16) -> Result<(u32, u32), VirtioGpuError> {
        let offset = 4u64
            .checked_add(
                u64::from(index % self.size)
                    .checked_mul(8)
                    .ok_or(VirtioGpuError::QueueAddressOverflow)?,
            )
            .ok_or(VirtioGpuError::QueueAddressOverflow)?;
        Ok((self.used.read_u32(offset)?, self.used.read_u32(offset + 4)?))
    }
}

#[derive(Debug, Clone, Copy)]
struct BackingRun {
    physical_base: u64,
    virtual_base: u64,
    length: u64,
}

#[derive(Debug, Clone, Copy)]
struct BackingMemory {
    runs: [BackingRun; GPU_MAX_BACKING_ENTRIES],
    run_count: usize,
    resource_length: u64,
}

impl BackingMemory {
    fn allocate(
        allocator: &mut FrameAllocator<'_>,
        physical_memory_offset: u64,
        resource_length: u64,
    ) -> Result<Self, VirtioGpuError> {
        let page_count = resource_length
            .checked_add(PAGE_SIZE - 1)
            .ok_or(GpuDmaError::AddressOverflow)?
            / PAGE_SIZE;
        let mut memory = Self {
            runs: [BackingRun {
                physical_base: 0,
                virtual_base: 0,
                length: 0,
            }; GPU_MAX_BACKING_ENTRIES],
            run_count: 0,
            resource_length,
        };
        for _ in 0..page_count {
            let frame = allocator.next().ok_or(GpuDmaError::NoFrame)?;
            let physical_base = frame.start_address();
            let virtual_base = physical_memory_offset
                .checked_add(physical_base)
                .ok_or(GpuDmaError::AddressOverflow)?;
            let contiguous = memory.run_count != 0
                && memory.runs[memory.run_count - 1]
                    .physical_base
                    .checked_add(memory.runs[memory.run_count - 1].length)
                    == Some(physical_base)
                && memory.runs[memory.run_count - 1]
                    .virtual_base
                    .checked_add(memory.runs[memory.run_count - 1].length)
                    == Some(virtual_base);
            if contiguous {
                memory.runs[memory.run_count - 1].length = memory.runs[memory.run_count - 1]
                    .length
                    .checked_add(PAGE_SIZE)
                    .ok_or(GpuDmaError::AddressOverflow)?;
            } else {
                if memory.run_count == GPU_MAX_BACKING_ENTRIES {
                    return Err(VirtioGpuError::BackingEntriesExceeded);
                }
                memory.runs[memory.run_count] = BackingRun {
                    physical_base,
                    virtual_base,
                    length: PAGE_SIZE,
                };
                memory.run_count += 1;
            }
        }
        Ok(memory)
    }

    fn entry_length(self, index: usize) -> u64 {
        let mut consumed = 0;
        for (run_index, run) in self.runs[..self.run_count].iter().enumerate() {
            let remaining = self.resource_length.saturating_sub(consumed);
            if run_index == index {
                return remaining.min(run.length);
            }
            consumed = consumed.saturating_add(run.length);
        }
        0
    }

    fn write_at(self, offset: usize, bytes: &[u8]) -> Result<(), VirtioGpuError> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(GpuDmaError::AddressOverflow)?;
        let resource_length =
            usize::try_from(self.resource_length).map_err(|_| GpuDmaError::AddressOverflow)?;
        if end > resource_length {
            return Err(GpuDmaError::BackingOutOfBounds {
                offset,
                size: bytes.len(),
            }
            .into());
        }

        let mut logical_start = 0usize;
        let source_end = end;
        for run in self.runs[..self.run_count].iter().copied() {
            let run_length =
                usize::try_from(run.length).map_err(|_| GpuDmaError::AddressOverflow)?;
            let logical_end = logical_start
                .checked_add(run_length)
                .ok_or(GpuDmaError::AddressOverflow)?;
            if offset < logical_end && logical_start < source_end {
                let copy_start = offset.max(logical_start);
                let run_offset = copy_start - logical_start;
                let source_start = copy_start - offset;
                let copy_length = (logical_end - copy_start).min(bytes.len() - source_start);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr().add(source_start),
                        (run.virtual_base as *mut u8).add(run_offset),
                        copy_length,
                    );
                }
            }
            logical_start = logical_end;
            if logical_start >= source_end {
                break;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct VirtioGpuRuntime {
    pub address: PciAddress,
    pub mmio_base: u64,
    pub common_config_length: u32,
    pub notify_multiplier: u32,
    pub device_config_length: u32,
    pub bus_master_enabled: bool,
    pub features: u64,
    pub queue_size: u16,
    pub num_scanouts: u32,
    pub width: u32,
    pub height: u32,
    pub resource_id: u32,
    pub transfers: u64,
    pub flushes: u64,
    pub failure: Option<VirtioGpuError>,
    next_frame_address: Option<u64>,
    common: MmioRegion,
    notify: MmioRegion,
    _device_config: MmioRegion,
    _pci_resources: PciDeviceResources,
    notify_offset: u16,
    queue: VirtQueue,
    command_page: DmaPage,
    response_page: DmaPage,
    backing: BackingMemory,
    row_buffer: Vec<u8>,
}

impl VirtioGpuRuntime {
    pub fn next_frame_address(&self) -> Option<u64> {
        self.next_frame_address
    }

    pub fn is_ready(&self) -> bool {
        self.failure.is_none() && self.resource_id == GPU_RESOURCE_ID && self.queue_size != 0
    }

    fn start(&mut self) -> Result<(), VirtioGpuError> {
        self.common.write_u8(DEVICE_STATUS, 0)?;
        self.common.write_u8(DEVICE_STATUS, STATUS_ACKNOWLEDGE)?;
        self.common
            .write_u8(DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER)?;
        self.negotiate_features()?;
        self.common.write_u8(
            DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        )?;
        if self.common.read_u8(DEVICE_STATUS)? & STATUS_FEATURES_OK == 0 {
            return Err(VirtioGpuError::FeatureNegotiationFailed);
        }
        self.setup_queue()?;
        self.common.write_u8(
            DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        )?;

        self.get_display_info()?;
        self.resource_create_2d()?;
        self.resource_attach_backing()?;
        self.set_scanout()?;
        Ok(())
    }

    fn negotiate_features(&mut self) -> Result<(), VirtioGpuError> {
        self.common.write_u32(DEVICE_FEATURE_SELECT, 0)?;
        let low = u64::from(self.common.read_u32(DEVICE_FEATURE)?);
        self.common.write_u32(DEVICE_FEATURE_SELECT, 1)?;
        let high = u64::from(self.common.read_u32(DEVICE_FEATURE)?) << 32;
        let available = low | high;
        if available & VIRTIO_F_VERSION_1 == 0 {
            return Err(VirtioGpuError::FeatureNegotiationFailed);
        }
        self.common.write_u32(DRIVER_FEATURE_SELECT, 0)?;
        self.common.write_u32(DRIVER_FEATURE, 0)?;
        self.common.write_u32(DRIVER_FEATURE_SELECT, 1)?;
        self.common
            .write_u32(DRIVER_FEATURE, (VIRTIO_F_VERSION_1 >> 32) as u32)?;
        self.features = VIRTIO_F_VERSION_1;
        Ok(())
    }

    fn setup_queue(&mut self) -> Result<(), VirtioGpuError> {
        if self.common.read_u16(NUM_QUEUES)? == 0 {
            return Err(VirtioGpuError::QueueUnavailable);
        }
        self.common.write_u16(QUEUE_SELECT, 0)?;
        let device_queue_size = self.common.read_u16(QUEUE_SIZE)?;
        let queue_size = device_queue_size.min(QUEUE_SIZE_LIMIT);
        if queue_size < 2 {
            return Err(VirtioGpuError::QueueTooSmall {
                size: device_queue_size,
            });
        }
        self.queue.size = queue_size;
        self.common.write_u16(QUEUE_SIZE, queue_size)?;
        self.common.write_u16(QUEUE_MSIX_VECTOR, u16::MAX)?;
        write_address(
            &self.common,
            QUEUE_DESC_LOW,
            self.queue.descriptors.physical_base,
        )?;
        write_address(
            &self.common,
            QUEUE_DRIVER_LOW,
            self.queue.available.physical_base,
        )?;
        write_address(
            &self.common,
            QUEUE_DEVICE_LOW,
            self.queue.used.physical_base,
        )?;
        self.common.write_u16(QUEUE_ENABLE, 1)?;
        self.notify_offset = self.common.read_u16(QUEUE_NOTIFY_OFFSET)?;
        self.queue_size = queue_size;
        Ok(())
    }

    fn get_display_info(&mut self) -> Result<(), VirtioGpuError> {
        self.command_page.clear();
        self.command_page.write_u32(0, GPU_CMD_GET_DISPLAY_INFO)?;
        let response = self.submit(GPU_HEADER_LENGTH)?;
        if response != GPU_RESP_OK_DISPLAY_INFO {
            return Err(VirtioGpuError::CommandFailed { response });
        }
        if self.num_scanouts == 0 {
            return Err(VirtioGpuError::DisplayUnavailable);
        }
        Ok(())
    }

    fn resource_create_2d(&mut self) -> Result<(), VirtioGpuError> {
        self.command_page.clear();
        self.command_page.write_u32(0, GPU_CMD_RESOURCE_CREATE_2D)?;
        self.command_page.write_u32(24, GPU_RESOURCE_ID)?;
        self.command_page.write_u32(28, GPU_FORMAT_B8G8R8A8_UNORM)?;
        self.command_page.write_u32(32, self.width)?;
        self.command_page.write_u32(36, self.height)?;
        let response = self.submit(40)?;
        self.expect_no_data(response)
    }

    fn resource_attach_backing(&mut self) -> Result<(), VirtioGpuError> {
        let entry_count = self.backing.run_count;
        let entry_bytes = u64::try_from(entry_count)
            .map_err(|_| VirtioGpuError::CommandTooLarge)?
            .checked_mul(16)
            .ok_or(VirtioGpuError::CommandTooLarge)?;
        let command_length = 32u64
            .checked_add(entry_bytes)
            .ok_or(VirtioGpuError::CommandTooLarge)?;
        if command_length > PAGE_SIZE {
            return Err(VirtioGpuError::CommandTooLarge);
        }
        self.command_page.clear();
        self.command_page
            .write_u32(0, GPU_CMD_RESOURCE_ATTACH_BACKING)?;
        self.command_page.write_u32(24, GPU_RESOURCE_ID)?;
        self.command_page.write_u32(
            28,
            u32::try_from(entry_count).map_err(|_| VirtioGpuError::CommandTooLarge)?,
        )?;
        for index in 0..entry_count {
            let offset = 32u64
                .checked_add(
                    u64::try_from(index)
                        .map_err(|_| VirtioGpuError::CommandTooLarge)?
                        .checked_mul(16)
                        .ok_or(VirtioGpuError::CommandTooLarge)?,
                )
                .ok_or(VirtioGpuError::CommandTooLarge)?;
            let run = self.backing.runs[index];
            self.command_page.write_u64(offset, run.physical_base)?;
            self.command_page
                .write_u32(offset + 8, self.backing.entry_length(index) as u32)?;
            self.command_page.write_u32(offset + 12, 0)?;
        }
        let response = self.submit(command_length)?;
        self.expect_no_data(response)
    }

    fn set_scanout(&mut self) -> Result<(), VirtioGpuError> {
        self.command_page.clear();
        self.command_page.write_u32(0, GPU_CMD_SET_SCANOUT)?;
        self.write_rect(24)?;
        self.command_page.write_u32(40, GPU_SCANOUT_ID)?;
        self.command_page.write_u32(44, GPU_RESOURCE_ID)?;
        let response = self.submit(48)?;
        self.expect_no_data(response)
    }

    fn transfer_to_host(&mut self) -> Result<(), VirtioGpuError> {
        self.command_page.clear();
        self.command_page
            .write_u32(0, GPU_CMD_TRANSFER_TO_HOST_2D)?;
        self.write_rect(24)?;
        self.command_page.write_u64(40, 0)?;
        let response = self.submit(48)?;
        self.expect_no_data(response)
    }

    fn flush(&mut self) -> Result<(), VirtioGpuError> {
        self.command_page.clear();
        self.command_page.write_u32(0, GPU_CMD_RESOURCE_FLUSH)?;
        self.write_rect(24)?;
        let response = self.submit(40)?;
        self.expect_no_data(response)
    }

    fn write_rect(&self, offset: u64) -> Result<(), VirtioGpuError> {
        self.command_page.write_u32(offset, 0)?;
        self.command_page.write_u32(offset + 4, 0)?;
        self.command_page.write_u32(offset + 8, self.width)?;
        self.command_page.write_u32(offset + 12, self.height)?;
        Ok(())
    }

    fn expect_no_data(&self, response: u32) -> Result<(), VirtioGpuError> {
        if response == GPU_RESP_OK_NODATA {
            Ok(())
        } else {
            Err(VirtioGpuError::CommandFailed { response })
        }
    }

    fn submit(&mut self, command_length: u64) -> Result<u32, VirtioGpuError> {
        if command_length > PAGE_SIZE {
            return Err(VirtioGpuError::CommandTooLarge);
        }
        let command_length =
            u32::try_from(command_length).map_err(|_| VirtioGpuError::CommandTooLarge)?;
        self.response_page.clear();
        self.queue.set_descriptor(
            0,
            self.command_page.physical_base,
            command_length,
            VIRTQ_DESC_F_NEXT,
            1,
        )?;
        self.queue.set_descriptor(
            1,
            self.response_page.physical_base,
            GPU_RESPONSE_LENGTH,
            VIRTQ_DESC_F_WRITE,
            0,
        )?;
        self.queue.push_available(0)?;
        self.notify_queue()?;
        for _ in 0..POLL_SPINS {
            let used_index = self.queue.used_index()?;
            if used_index != self.queue.last_used_index {
                let (descriptor, _) = self.queue.used_element(self.queue.last_used_index)?;
                if descriptor != 0 {
                    return Err(VirtioGpuError::QueueDescriptorInvalid { descriptor });
                }
                self.queue.last_used_index = used_index;
                let response = self.response_page.read_u32(0)?;
                if response >= GPU_RESP_ERROR_MIN {
                    return Err(VirtioGpuError::CommandFailed { response });
                }
                return Ok(response);
            }
            core::hint::spin_loop();
        }
        Err(VirtioGpuError::CommandTimeout)
    }

    fn notify_queue(&self) -> Result<(), VirtioGpuError> {
        let offset = u64::from(self.notify_offset)
            .checked_mul(u64::from(self.notify_multiplier))
            .ok_or(VirtioGpuError::QueueAddressOverflow)?;
        self.notify.write_u16(offset, 0)?;
        Ok(())
    }

    fn present(&mut self, source: &[u8], info: &FrameBufferInfo) -> Result<(), VirtioGpuError> {
        if info.width != usize::try_from(self.width).unwrap_or(usize::MAX)
            || info.height != usize::try_from(self.height).unwrap_or(usize::MAX)
        {
            return Err(VirtioGpuError::FrameDimensionsChanged);
        }
        let required_source_length = info
            .height
            .checked_mul(info.stride)
            .and_then(|pixels| pixels.checked_mul(info.bytes_per_pixel))
            .ok_or(VirtioGpuError::FrameBufferTooShort)?;
        if source.len() < required_source_length {
            return Err(VirtioGpuError::FrameBufferTooShort);
        }
        let width =
            usize::try_from(self.width).map_err(|_| VirtioGpuError::FrameDimensionsChanged)?;
        let row_length = width
            .checked_mul(4)
            .ok_or(VirtioGpuError::FrameDimensionsChanged)?;
        for y in
            0..usize::try_from(self.height).map_err(|_| VirtioGpuError::FrameDimensionsChanged)?
        {
            for x in 0..width {
                let (red, green, blue) = pixel_rgb(source, info, x, y);
                let offset = x * 4;
                self.row_buffer[offset] = blue;
                self.row_buffer[offset + 1] = green;
                self.row_buffer[offset + 2] = red;
                self.row_buffer[offset + 3] = 0xff;
            }
            let destination = y
                .checked_mul(row_length)
                .ok_or(VirtioGpuError::FrameDimensionsChanged)?;
            self.backing.write_at(destination, &self.row_buffer)?;
        }
        self.transfer_to_host()?;
        self.flush()?;
        self.transfers = self.transfers.saturating_add(1);
        self.flushes = self.flushes.saturating_add(1);
        #[cfg(target_os = "none")]
        if self.transfers == 1 {
            crate::kprintln!(
                "gpu: frame transfers={} flushes={} scanout={} status=ready",
                self.transfers,
                self.flushes,
                GPU_SCANOUT_ID
            );
        }
        Ok(())
    }
}

pub fn install(runtime: VirtioGpuRuntime) {
    *GPU_RUNTIME.lock() = Some(runtime);
}

pub fn present_frame(source: &[u8], info: &FrameBufferInfo) -> bool {
    let mut runtime = GPU_RUNTIME.lock();
    let Some(runtime) = runtime.as_mut() else {
        return true;
    };
    if !runtime.is_ready() {
        return true;
    }
    match runtime.present(source, info) {
        Ok(()) => true,
        Err(error) => {
            #[cfg(target_os = "none")]
            crate::kprintln!(
                "gpu: frame presentation failed ({:?}) status=degraded",
                error
            );
            runtime.failure = Some(error);
            false
        }
    }
}

pub fn initialize(
    inventory: &PciInventory,
    physical_memory_offset: u64,
    regions: &[MemoryRegion],
    next_frame_address: Option<u64>,
    framebuffer_info: Option<GraphicsInfo>,
) -> Result<Option<VirtioGpuRuntime>, VirtioGpuInitFailure> {
    let Some(device) = find_device(inventory) else {
        return Ok(None);
    };
    let Some(framebuffer_info) = framebuffer_info else {
        return Err(VirtioGpuInitFailure {
            error: VirtioGpuError::NoFramebuffer,
            next_frame_address,
        });
    };
    if framebuffer_info.width == 0
        || framebuffer_info.height == 0
        || framebuffer_info.width > GPU_MAX_DIMENSION
        || framebuffer_info.height > GPU_MAX_DIMENSION
        || framebuffer_info.bytes_per_pixel == 0
    {
        return Err(VirtioGpuInitFailure {
            error: VirtioGpuError::UnsupportedFramebuffer,
            next_frame_address,
        });
    }
    let resource_length = u64::from(framebuffer_info.width)
        .checked_mul(u64::from(framebuffer_info.height))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(VirtioGpuInitFailure {
            error: VirtioGpuError::UnsupportedFramebuffer,
            next_frame_address,
        })?;
    if resource_length > GPU_MAX_BYTES {
        return Err(VirtioGpuInitFailure {
            error: VirtioGpuError::UnsupportedFramebuffer,
            next_frame_address,
        });
    }
    if !device.memory_space_enabled() {
        return Err(VirtioGpuInitFailure {
            error: VirtioGpuError::MemorySpaceDisabled,
            next_frame_address,
        });
    }

    let common_cap = capability(device, VIRTIO_PCI_CAP_COMMON_CONFIG, next_frame_address)?;
    let notify_cap = capability(device, VIRTIO_PCI_CAP_NOTIFY_CONFIG, next_frame_address)?;
    let device_cap = capability(device, VIRTIO_PCI_CAP_DEVICE_CONFIG, next_frame_address)?;

    let mut resources = PciDeviceResources::new(device, physical_memory_offset);
    resources
        .enable_bus_master()
        .map_err(|error| VirtioGpuInitFailure {
            error: error.into(),
            next_frame_address,
        })?;
    let enabled_device = resources.device();
    let common = resources
        .claim_mmio_subregion(
            usize::from(common_cap.bar),
            u64::from(common_cap.region_offset),
            u64::from(common_cap.region_length),
        )
        .map_err(|error| VirtioGpuInitFailure {
            error: error.into(),
            next_frame_address,
        })?;
    let notify = resources
        .claim_mmio_subregion(
            usize::from(notify_cap.bar),
            u64::from(notify_cap.region_offset),
            u64::from(notify_cap.region_length),
        )
        .map_err(|error| VirtioGpuInitFailure {
            error: error.into(),
            next_frame_address,
        })?;
    let device_config = resources
        .claim_mmio_subregion(
            usize::from(device_cap.bar),
            u64::from(device_cap.region_offset),
            u64::from(device_cap.region_length),
        )
        .map_err(|error| VirtioGpuInitFailure {
            error: error.into(),
            next_frame_address,
        })?;

    let dma_start = next_frame_address.unwrap_or(0).max(DMA_ALLOCATION_FLOOR);
    let mut frame_allocator = FrameAllocator::starting_at(regions, dma_start);
    let queue = match VirtQueue::allocate(&mut frame_allocator, physical_memory_offset) {
        Ok(queue) => queue,
        Err(error) => {
            return Err(VirtioGpuInitFailure {
                error,
                next_frame_address: frame_allocator.next_available_address(),
            });
        }
    };
    let command_page = match allocate_page(&mut frame_allocator, physical_memory_offset) {
        Ok(page) => page,
        Err(error) => {
            return Err(VirtioGpuInitFailure {
                error,
                next_frame_address: frame_allocator.next_available_address(),
            });
        }
    };
    let response_page = match allocate_page(&mut frame_allocator, physical_memory_offset) {
        Ok(page) => page,
        Err(error) => {
            return Err(VirtioGpuInitFailure {
                error,
                next_frame_address: frame_allocator.next_available_address(),
            });
        }
    };
    let backing = match BackingMemory::allocate(
        &mut frame_allocator,
        physical_memory_offset,
        resource_length,
    ) {
        Ok(backing) => backing,
        Err(error) => {
            return Err(VirtioGpuInitFailure {
                error,
                next_frame_address: frame_allocator.next_available_address(),
            });
        }
    };
    let row_length = usize::try_from(framebuffer_info.width)
        .ok()
        .and_then(|width| width.checked_mul(4))
        .ok_or(VirtioGpuInitFailure {
            error: VirtioGpuError::UnsupportedFramebuffer,
            next_frame_address: frame_allocator.next_available_address(),
        })?;
    let mut row_buffer = Vec::new();
    row_buffer.resize(row_length, 0);
    let num_scanouts = if device_config.length() >= 12 {
        device_config
            .read_u32(8)
            .map_err(|error| VirtioGpuInitFailure {
                error: error.into(),
                next_frame_address: frame_allocator.next_available_address(),
            })?
    } else {
        0
    };

    let mut runtime = VirtioGpuRuntime {
        address: device.address,
        mmio_base: common.physical_base(),
        common_config_length: common_cap.region_length,
        notify_multiplier: notify_cap.notify_off_multiplier,
        device_config_length: device_cap.region_length,
        bus_master_enabled: enabled_device.bus_master_enabled(),
        features: 0,
        queue_size: 0,
        num_scanouts,
        width: framebuffer_info.width,
        height: framebuffer_info.height,
        resource_id: GPU_RESOURCE_ID,
        transfers: 0,
        flushes: 0,
        failure: None,
        next_frame_address: frame_allocator.next_available_address(),
        common,
        notify,
        _device_config: device_config,
        _pci_resources: resources,
        notify_offset: 0,
        queue,
        command_page,
        response_page,
        backing,
        row_buffer,
    };
    if let Err(error) = runtime.start() {
        let _ = runtime.common.write_u8(DEVICE_STATUS, STATUS_FAILED);
        runtime.failure = Some(error);
    }
    runtime.next_frame_address = frame_allocator.next_available_address();
    Ok(Some(runtime))
}

fn capability(
    device: PciDevice,
    cfg_type: u8,
    next_frame_address: Option<u64>,
) -> Result<crate::pci::PciVirtioCapability, VirtioGpuInitFailure> {
    device
        .virtio_capability(cfg_type)
        .ok_or(VirtioGpuInitFailure {
            error: VirtioGpuError::MissingCapability { cfg_type },
            next_frame_address,
        })
}

fn find_device(inventory: &PciInventory) -> Option<PciDevice> {
    inventory
        .devices()
        .iter()
        .find(|device| {
            device.vendor_id == VIRTIO_VENDOR_ID
                && device.device_id == VIRTIO_GPU_DEVICE_ID
                && device.class_code == 0x03
        })
        .copied()
}

fn allocate_page(
    allocator: &mut FrameAllocator<'_>,
    physical_memory_offset: u64,
) -> Result<DmaPage, VirtioGpuError> {
    let frame = allocator.next().ok_or(GpuDmaError::NoFrame)?;
    let physical_base = frame.start_address();
    let virtual_base = physical_memory_offset
        .checked_add(physical_base)
        .ok_or(GpuDmaError::AddressOverflow)?;
    let page = DmaPage {
        physical_base,
        virtual_base,
    };
    page.clear();
    Ok(page)
}

fn write_address(region: &MmioRegion, offset: u64, address: u64) -> Result<(), VirtioGpuError> {
    region.write_u32(offset, address as u32)?;
    region.write_u32(offset + 4, (address >> 32) as u32)?;
    Ok(())
}

fn pixel_rgb(source: &[u8], info: &FrameBufferInfo, x: usize, y: usize) -> (u8, u8, u8) {
    let Some(offset) = y
        .checked_mul(info.stride)
        .and_then(|pixels| pixels.checked_add(x))
        .and_then(|pixel| pixel.checked_mul(info.bytes_per_pixel))
    else {
        return (0, 0, 0);
    };
    let Some(end) = offset.checked_add(info.bytes_per_pixel) else {
        return (0, 0, 0);
    };
    let Some(pixel) = source.get(offset..end) else {
        return (0, 0, 0);
    };
    match info.pixel_format {
        PixelFormat::Rgb => (
            pixel.first().copied().unwrap_or(0),
            pixel.get(1).copied().unwrap_or(0),
            pixel.get(2).copied().unwrap_or(0),
        ),
        PixelFormat::Bgr => (
            pixel.get(2).copied().unwrap_or(0),
            pixel.get(1).copied().unwrap_or(0),
            pixel.first().copied().unwrap_or(0),
        ),
        PixelFormat::U8 => {
            let value = pixel.first().copied().unwrap_or(0);
            (value, value, value)
        }
        PixelFormat::Unknown {
            red_position,
            green_position,
            blue_position,
        } => {
            let mut encoded = 0u32;
            for (index, byte) in pixel.iter().copied().take(4).enumerate() {
                encoded |= u32::from(byte) << (index * 8);
            }
            (
                component(encoded, red_position),
                component(encoded, green_position),
                component(encoded, blue_position),
            )
        }
        _ => (0, 0, 0),
    }
}

fn component(encoded: u32, position: u8) -> u8 {
    if position < 32 {
        ((encoded >> position) & 0xff) as u8
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_bgr_pixels_to_gpu_order() {
        let info = FrameBufferInfo {
            byte_len: 8,
            width: 2,
            height: 1,
            pixel_format: PixelFormat::Bgr,
            bytes_per_pixel: 4,
            stride: 2,
        };
        assert_eq!(pixel_rgb(&[3, 2, 1, 0, 6, 5, 4, 0], &info, 0, 0), (1, 2, 3));
        assert_eq!(pixel_rgb(&[3, 2, 1, 0, 6, 5, 4, 0], &info, 1, 0), (4, 5, 6));
    }

    #[test]
    fn rejects_backing_writes_outside_resource() {
        let backing = BackingMemory {
            runs: [BackingRun {
                physical_base: 0,
                virtual_base: 0,
                length: 4096,
            }; GPU_MAX_BACKING_ENTRIES],
            run_count: 1,
            resource_length: 4,
        };
        assert_eq!(
            backing.write_at(3, &[1, 2]),
            Err(VirtioGpuError::Dma(GpuDmaError::BackingOutOfBounds {
                offset: 3,
                size: 2
            }))
        );
    }
}
