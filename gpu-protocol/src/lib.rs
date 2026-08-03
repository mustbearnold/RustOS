#![no_std]

extern crate alloc;

mod boot;
mod fmc;
mod fsp;

pub use boot::{
    GspBootloader, GspBootloaderError, GspFirmwareBundle, GspFirmwareBundleError, GspFmcBootParams,
    GspRmDescriptorField, GspRmUcodeDescriptor, GspWprMeta, NVIDIA_GSP_BOOTLOADER_MAX_SIZE,
    NVIDIA_GSP_FMC_BOOT_PARAMS_SIZE, NVIDIA_GSP_WPR_META_SIZE,
};
pub use fmc::{GspFmc, GspFmcError, GspFmcRequiredSection, NVIDIA_GSP_FMC_MAX_SIZE};
pub use fsp::{
    GspFspCot, GspFspCotError, GspFspResponse, GspFspResponseError, NVIDIA_GSP_FALCON_BASE,
    NVIDIA_GSP_FALCON_CPUCTL, NVIDIA_GSP_FALCON_CPUCTL_RISCV_ACTIVE_BIT, NVIDIA_GSP_FALCON_HWCFG2,
    NVIDIA_GSP_FALCON_HWCFG2_RISCV_BRANCH_PRIVILEGE_LOCKDOWN_BIT,
    NVIDIA_GSP_FALCON_HWCFG2_TARGET_MASK, NVIDIA_GSP_FALCON_HWCFG2_TARGET_MASK_LOCKED,
    NVIDIA_GSP_FALCON_MAILBOX0, NVIDIA_GSP_FALCON_MAILBOX1, NVIDIA_GSP_FALCON_QUEUE_HEAD,
    NVIDIA_GSP_FSP_BAR0_REQUIRED_LENGTH, NVIDIA_GSP_FSP_BOOT_COMPLETE_REGISTER_GB20X,
    NVIDIA_GSP_FSP_BOOT_COMPLETE_STATUS_SUCCESS, NVIDIA_GSP_FSP_COT_HASH_BYTES,
    NVIDIA_GSP_FSP_COT_PACKET_SIZE, NVIDIA_GSP_FSP_COT_PAYLOAD_SIZE,
    NVIDIA_GSP_FSP_COT_PUBLIC_KEY_BYTES, NVIDIA_GSP_FSP_COT_PUBLIC_KEY_SLOT_BYTES,
    NVIDIA_GSP_FSP_COT_SIGNATURE_BYTES, NVIDIA_GSP_FSP_COT_SIGNATURE_SLOT_BYTES,
    NVIDIA_GSP_FSP_COT_VERSION_GB20X, NVIDIA_GSP_FSP_EMEM_PIO_ADDRESS,
    NVIDIA_GSP_FSP_EMEM_PIO_DATA, NVIDIA_GSP_FSP_EMEM_PIO_MAX_BYTES,
    NVIDIA_GSP_FSP_EMEM_PIO_READ_BIT, NVIDIA_GSP_FSP_EMEM_PIO_WRITE_BIT,
    NVIDIA_GSP_FSP_FALCON_BASE, NVIDIA_GSP_FSP_FALCON_HWCFG2,
    NVIDIA_GSP_FSP_FALCON_HWCFG2_LOCKDOWN_BIT, NVIDIA_GSP_FSP_FALCON_MAILBOX0,
    NVIDIA_GSP_FSP_FALCON_MAILBOX1, NVIDIA_GSP_FSP_MSGQ_HEAD, NVIDIA_GSP_FSP_MSGQ_TAIL,
    NVIDIA_GSP_FSP_NVDM_TYPE_COT, NVIDIA_GSP_FSP_NVDM_TYPE_RESPONSE, NVIDIA_GSP_FSP_QUEUE_HEAD,
    NVIDIA_GSP_FSP_QUEUE_TAIL, NVIDIA_GSP_FSP_RESPONSE_PACKET_SIZE,
};

use alloc::vec::Vec;

pub const NVIDIA_GSP_MAX_FIRMWARE_SIZE: usize = 128 * 1024 * 1024;
pub const NVIDIA_GSP_ELF_HEADER_SIZE: usize = 64;
pub const NVIDIA_GSP_ELF_SECTION_HEADER_SIZE: usize = 64;
pub const NVIDIA_GSP_MAX_SECTIONS: usize = 128;
pub const NVIDIA_GSP_PAGE_SIZE: usize = 4096;
pub const NVIDIA_GSP_MAX_MESSAGE_PAGES: usize = 16;
pub const NVIDIA_GSP_MESSAGE_HEADER_SIZE: usize = 48;
pub const NVIDIA_GSP_RPC_HEADER_SIZE: usize = 32;
pub const NVIDIA_GSP_SHARED_QUEUE_BYTES: usize = 0x40000;
pub const NVIDIA_GSP_SHARED_QUEUE_COUNT: usize = 2;
pub const NVIDIA_GSP_QUEUE_HEADER_SIZE: usize = 32;
pub const NVIDIA_GSP_QUEUE_ENTRY_OFFSET: usize = NVIDIA_GSP_PAGE_SIZE;
pub const NVIDIA_GSP_QUEUE_ENTRY_SIZE: usize = NVIDIA_GSP_PAGE_SIZE;
pub const NVIDIA_GSP_QUEUE_ENTRY_COUNT: usize =
    (NVIDIA_GSP_SHARED_QUEUE_BYTES - NVIDIA_GSP_QUEUE_ENTRY_OFFSET) / NVIDIA_GSP_QUEUE_ENTRY_SIZE;
pub const NVIDIA_GSP_QUEUE_TX_WRITE_POINTER_OFFSET: usize = 16;
pub const NVIDIA_GSP_QUEUE_RX_READ_POINTER_OFFSET: usize = 32;
pub const NVIDIA_GSP_SHARED_PAGE_TABLE_ENTRY_SIZE: usize = core::mem::size_of::<u64>();
pub const NVIDIA_GSP_RADIX3_POINTERS_PER_PAGE: usize = NVIDIA_GSP_PAGE_SIZE / 8;
pub const NVIDIA_GSP_RADIX3_MAX_IMAGE_PAGES: usize =
    NVIDIA_GSP_RADIX3_POINTERS_PER_PAGE * NVIDIA_GSP_RADIX3_POINTERS_PER_PAGE;
pub const NVIDIA_GSP_WPR_ALIGNMENT: usize = 128 * 1024;
pub const NVIDIA_GSP_R570_BAREMETAL_OS_CARVEOUT: usize = 22 * 1024 * 1024;
pub const NVIDIA_GSP_R570_BASE_RM_HEAP: usize = 14 * 1024 * 1024;
pub const NVIDIA_GSP_R570_MIN_RM_HEAP: usize = 88 * 1024 * 1024;
pub const NVIDIA_GSP_R570_GB20X_NON_WPR_HEAP: usize = 0x220000;
pub const NVIDIA_GSP_R570_HEAP_PER_GB_FB: u64 = 96 * 1024;
pub const NVIDIA_GSP_R570_CLIENT_ALLOC_HEAP: u64 = (48 * 1024) * 2048;
pub const NVIDIA_GSP_R570_GB20X_WPR_HEAP_MIN: u64 = (88 + 12 + 70) as u64 * 1024 * 1024;
pub const NVIDIA_GSP_R570_GB20X_PMU_RESERVED_SIZE: u64 = 0x01a00000;
pub const NVIDIA_GSP_R570_FSP_CARVEOUT_ALIGNMENT: u64 = 0x00200000;
pub const NVIDIA_GSP_GB20X_FRTS_SIZE: u64 = 0x00100000;
pub const NVIDIA_GSP_GB20X_WPR_HEAP_ALIGNMENT: u64 = 0x00100000;
pub const NVIDIA_GSP_GB20X_ELF_ALIGNMENT: u64 = 0x00010000;
pub const NVIDIA_GSP_LIBOS_ARGUMENTS_SIZE: usize = NVIDIA_GSP_PAGE_SIZE;
pub const NVIDIA_GSP_RM_ARGUMENTS_SIZE: usize = NVIDIA_GSP_PAGE_SIZE;
pub const NVIDIA_GSP_LOG_BUFFER_SIZE: usize = 0x10000;
pub const NVIDIA_GSP_R570_CACHED_ARGUMENTS_SIZE: usize = 72;
pub const NVIDIA_GSP_R570_QUEUE_RX_HEADER_OFFSET: u32 = 32;
pub const NVIDIA_GSP_RPC_SIGNATURE: u32 = 0x4352_5056;
pub const NVIDIA_GSP_RPC_HEADER_VERSION: u32 = 0x0300_0000;
pub const NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO: u32 = 65;
pub const NVIDIA_GSP_FUNCTION_CONTINUATION_RECORD: u32 = 71;
pub const NVIDIA_GSP_FUNCTION_GSP_SET_SYSTEM_INFO: u32 = 72;
pub const NVIDIA_GSP_FUNCTION_SET_REGISTRY: u32 = 73;
pub const NVIDIA_GSP_EVENT_FIRST: u32 = 4096;
pub const NVIDIA_GSP_EVENT_GSP_INIT_DONE: u32 = 4097;
pub const NVIDIA_GSP_CONTINUATION_FUNCTION: u32 = NVIDIA_GSP_FUNCTION_CONTINUATION_RECORD;
pub const NVIDIA_GSP_R570_SYSTEM_INFO_SIZE: usize = 544;
pub const NVIDIA_GSP_R570_STATIC_CONFIG_INFO_SIZE: usize = 1656;
pub const NVIDIA_GSP_R570_STATIC_GPU_NAME_OFFSET: usize = 1260;
pub const NVIDIA_GSP_R570_PCI_CONFIG_MIRROR_BASE: u32 = 0x0009_2000;
pub const NVIDIA_GSP_R570_PCI_CONFIG_MIRROR_SIZE: u32 = 0x0000_1000;
pub const NVIDIA_GSP_R570_CHIPSET_GB205: u32 = 0x0000_01b5;
pub const NVIDIA_GSP_R570_MAX_USER_VA: u64 = (1u64 << 47) - 4096;
pub const NVIDIA_GSP_REGISTRY_DWORD: u8 = 1;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE: u8 = 1;
const ELF_VERSION_CURRENT: u8 = 1;
const ELF_TYPE_REL: u16 = 1;
const ELF_MACHINE_RISCV: u16 = 0x00f3;
const ELF_SECTION_PROGBITS: u32 = 1;
const ELF_SECTION_STRTAB: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspFirmwareError {
    TooLarge { size: usize, limit: usize },
    Truncated { offset: usize, size: usize },
    InvalidMagic,
    UnsupportedClass { value: u8 },
    UnsupportedEndian { value: u8 },
    UnsupportedVersion { value: u8 },
    UnsupportedType { value: u16 },
    UnsupportedMachine { value: u16 },
    ProgramHeadersPresent,
    InvalidSectionTable,
    TooManySections { count: usize },
    InvalidStringTable,
    InvalidSectionName,
    MissingFirmwareImage,
    MissingFirmwareVersion,
    InvalidFirmwareVersion,
    InvalidFirmwareImage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspBootPlanError {
    MissingGb20xSignature,
    EmptyGb20xSignature,
    ImageTooLarge { pages: usize, limit: usize },
    SizeOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspMemoryError {
    AddressUnaligned { address: u64 },
    AddressOverflow,
    BufferTooSmall { required: usize, actual: usize },
    PageCountMismatch { expected: usize, actual: usize },
    ValueTooLarge { value: usize, limit: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspSystemMemoryPlanError {
    BootLayout(GspBootPlanError),
    BaseUnaligned { address: u64 },
    AddressOverflow,
    EmptyRegion,
    SizeOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspFramebufferLayoutError {
    AddressOverflow,
    AddressUnderflow,
    InvalidBiosAddress { address: u64, framebuffer_size: u64 },
    TooSmall { required: u64, available: u64 },
    SizeOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspMaterializationError {
    BootLayout(GspBootPlanError),
    SystemPlan(GspSystemMemoryPlanError),
    Memory(GspMemoryError),
    BufferTooSmall {
        required: usize,
        actual: usize,
    },
    InvalidSectionRange {
        offset: usize,
        size: usize,
        available: usize,
    },
    SectionTooLarge {
        section: usize,
        region: usize,
    },
    LayoutMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareSection {
    pub offset: usize,
    pub size: usize,
}

impl FirmwareSection {
    pub fn bytes<'a>(self, firmware: &'a [u8]) -> &'a [u8] {
        &firmware[self.offset..self.offset + self.size]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspFirmware {
    pub image: FirmwareSection,
    pub version: FirmwareSection,
    pub gb20x_signature: Option<FirmwareSection>,
    pub section_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspSharedMemoryLayout {
    pub page_table_entry_count: usize,
    pub page_table_bytes: usize,
    pub command_queue_offset: usize,
    pub status_queue_offset: usize,
    pub total_bytes: usize,
    pub queue_entry_count: usize,
}

impl GspSharedMemoryLayout {
    pub const fn standard() -> Self {
        let queue_pages =
            (NVIDIA_GSP_SHARED_QUEUE_BYTES * NVIDIA_GSP_SHARED_QUEUE_COUNT) / NVIDIA_GSP_PAGE_SIZE;
        let page_table_entry_count = queue_pages + 1;
        let page_table_bytes = NVIDIA_GSP_PAGE_SIZE;
        let command_queue_offset = page_table_bytes;
        let status_queue_offset = command_queue_offset + NVIDIA_GSP_SHARED_QUEUE_BYTES;
        let total_bytes = status_queue_offset + NVIDIA_GSP_SHARED_QUEUE_BYTES;
        Self {
            page_table_entry_count,
            page_table_bytes,
            command_queue_offset,
            status_queue_offset,
            total_bytes,
            queue_entry_count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
        }
    }

    pub fn materialize(
        self,
        page_addresses: &[u64],
    ) -> Result<GspSharedMemoryImage, GspMemoryError> {
        if page_addresses.is_empty() {
            return Err(GspMemoryError::PageCountMismatch {
                expected: 1,
                actual: 0,
            });
        }
        if page_addresses.len() != self.page_table_entry_count {
            return Err(GspMemoryError::PageCountMismatch {
                expected: self.page_table_entry_count,
                actual: page_addresses.len(),
            });
        }
        let page_table_required = self
            .page_table_entry_count
            .checked_mul(NVIDIA_GSP_SHARED_PAGE_TABLE_ENTRY_SIZE)
            .ok_or(GspMemoryError::AddressOverflow)?;
        if page_table_required > self.page_table_bytes {
            return Err(GspMemoryError::BufferTooSmall {
                required: page_table_required,
                actual: self.page_table_bytes,
            });
        }
        for &address in page_addresses {
            validate_page_address(address)?;
        }

        let mut page_table = Vec::new();
        page_table.resize(self.page_table_bytes, 0);
        for (index, &address) in page_addresses.iter().enumerate() {
            let offset = index
                .checked_mul(NVIDIA_GSP_SHARED_PAGE_TABLE_ENTRY_SIZE)
                .ok_or(GspMemoryError::AddressOverflow)?;
            write_le_u64(&mut page_table, offset, address);
        }

        let mut command_queue = Vec::new();
        command_queue.resize(NVIDIA_GSP_SHARED_QUEUE_BYTES, 0);
        let command_header = GspQueueHeader::r570_command(self)?;
        command_queue[..NVIDIA_GSP_QUEUE_HEADER_SIZE].copy_from_slice(&command_header.encode());

        let mut status_queue = Vec::new();
        status_queue.resize(NVIDIA_GSP_SHARED_QUEUE_BYTES, 0);

        Ok(GspSharedMemoryImage {
            page_table_address: page_addresses[0],
            page_table,
            command_queue,
            status_queue,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspQueueHeader {
    pub version: u32,
    pub size: u32,
    pub message_size: u32,
    pub message_count: u32,
    pub write_pointer: u32,
    pub flags: u32,
    pub rx_header_offset: u32,
    pub entry_offset: u32,
}

impl GspQueueHeader {
    pub fn r570_command(layout: GspSharedMemoryLayout) -> Result<Self, GspMemoryError> {
        let message_count =
            u32::try_from(layout.queue_entry_count).map_err(|_| GspMemoryError::ValueTooLarge {
                value: layout.queue_entry_count,
                limit: u32::MAX as usize,
            })?;
        Ok(Self {
            version: 0,
            size: NVIDIA_GSP_SHARED_QUEUE_BYTES as u32,
            message_size: NVIDIA_GSP_QUEUE_ENTRY_SIZE as u32,
            message_count,
            write_pointer: 0,
            flags: 1,
            rx_header_offset: NVIDIA_GSP_R570_QUEUE_RX_HEADER_OFFSET,
            entry_offset: NVIDIA_GSP_QUEUE_ENTRY_OFFSET as u32,
        })
    }

    pub fn encode(self) -> [u8; NVIDIA_GSP_QUEUE_HEADER_SIZE] {
        let mut bytes = [0u8; NVIDIA_GSP_QUEUE_HEADER_SIZE];
        write_le_u32(&mut bytes, 0, self.version);
        write_le_u32(&mut bytes, 4, self.size);
        write_le_u32(&mut bytes, 8, self.message_size);
        write_le_u32(&mut bytes, 12, self.message_count);
        write_le_u32(&mut bytes, 16, self.write_pointer);
        write_le_u32(&mut bytes, 20, self.flags);
        write_le_u32(&mut bytes, 24, self.rx_header_offset);
        write_le_u32(&mut bytes, 28, self.entry_offset);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GspSharedMemoryImage {
    pub page_table_address: u64,
    pub page_table: Vec<u8>,
    pub command_queue: Vec<u8>,
    pub status_queue: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspRadix3Layout {
    pub image_pages: usize,
    pub level0_bytes: usize,
    pub level1_bytes: usize,
    pub level2_bytes: usize,
    pub level2_pages: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GspRadix3Tables {
    pub level0_address: u64,
    pub level1_address: u64,
    pub level2_addresses: Vec<u64>,
    pub level0: Vec<u8>,
    pub level1: Vec<u8>,
    pub level2: Vec<u8>,
}

impl GspRadix3Layout {
    pub fn materialize(
        self,
        level0_address: u64,
        level1_address: u64,
        level2_addresses: &[u64],
        image_page_addresses: &[u64],
    ) -> Result<GspRadix3Tables, GspMemoryError> {
        if level2_addresses.len() != self.level2_pages {
            return Err(GspMemoryError::PageCountMismatch {
                expected: self.level2_pages,
                actual: level2_addresses.len(),
            });
        }
        if image_page_addresses.len() != self.image_pages {
            return Err(GspMemoryError::PageCountMismatch {
                expected: self.image_pages,
                actual: image_page_addresses.len(),
            });
        }
        let level0_required = NVIDIA_GSP_SHARED_PAGE_TABLE_ENTRY_SIZE;
        let level1_required = self
            .level2_pages
            .checked_mul(NVIDIA_GSP_SHARED_PAGE_TABLE_ENTRY_SIZE)
            .ok_or(GspMemoryError::AddressOverflow)?;
        let level2_required = self
            .image_pages
            .checked_mul(NVIDIA_GSP_SHARED_PAGE_TABLE_ENTRY_SIZE)
            .ok_or(GspMemoryError::AddressOverflow)?;
        for (required, actual) in [
            (level0_required, self.level0_bytes),
            (level1_required, self.level1_bytes),
            (level2_required, self.level2_bytes),
        ] {
            if required > actual {
                return Err(GspMemoryError::BufferTooSmall { required, actual });
            }
        }
        validate_page_address(level0_address)?;
        validate_page_address(level1_address)?;
        for &address in level2_addresses {
            validate_page_address(address)?;
        }
        for &address in image_page_addresses {
            validate_page_address(address)?;
        }

        let mut level0 = Vec::new();
        level0.resize(self.level0_bytes, 0);
        write_le_u64(&mut level0, 0, level1_address);

        let mut level1 = Vec::new();
        level1.resize(self.level1_bytes, 0);
        for (index, &address) in level2_addresses.iter().enumerate() {
            let offset = index
                .checked_mul(NVIDIA_GSP_SHARED_PAGE_TABLE_ENTRY_SIZE)
                .ok_or(GspMemoryError::AddressOverflow)?;
            write_le_u64(&mut level1, offset, address);
        }

        let mut level2 = Vec::new();
        level2.resize(self.level2_bytes, 0);
        for (index, &address) in image_page_addresses.iter().enumerate() {
            let offset = index
                .checked_mul(NVIDIA_GSP_SHARED_PAGE_TABLE_ENTRY_SIZE)
                .ok_or(GspMemoryError::AddressOverflow)?;
            write_le_u64(&mut level2, offset, address);
        }

        Ok(GspRadix3Tables {
            level0_address,
            level1_address,
            level2_addresses: level2_addresses.to_vec(),
            level0,
            level1,
            level2,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspCachedArguments {
    pub shared_mem_phys_addr: u64,
    pub page_table_entry_count: u32,
    pub command_queue_offset: u64,
    pub status_queue_offset: u64,
    pub old_power_level: u32,
    pub power_flags: u32,
    pub in_power_transition: bool,
    pub gpu_instance: u32,
    pub dmem_stack: bool,
    pub profiler_pa: u64,
    pub profiler_size: u64,
}

impl GspCachedArguments {
    pub fn r570(
        shared_mem_phys_addr: u64,
        layout: GspSharedMemoryLayout,
    ) -> Result<Self, GspMemoryError> {
        validate_page_address(shared_mem_phys_addr)?;
        let page_table_entry_count =
            u32::try_from(layout.page_table_entry_count).map_err(|_| {
                GspMemoryError::ValueTooLarge {
                    value: layout.page_table_entry_count,
                    limit: u32::MAX as usize,
                }
            })?;
        Ok(Self {
            shared_mem_phys_addr,
            page_table_entry_count,
            command_queue_offset: layout.command_queue_offset as u64,
            status_queue_offset: layout.status_queue_offset as u64,
            old_power_level: 0,
            power_flags: 0,
            in_power_transition: false,
            gpu_instance: 0,
            dmem_stack: true,
            profiler_pa: 0,
            profiler_size: 0,
        })
    }

    pub fn encode(self) -> [u8; NVIDIA_GSP_R570_CACHED_ARGUMENTS_SIZE] {
        let mut bytes = [0u8; NVIDIA_GSP_R570_CACHED_ARGUMENTS_SIZE];
        write_le_u64(&mut bytes, 0, self.shared_mem_phys_addr);
        write_le_u32(&mut bytes, 8, self.page_table_entry_count);
        write_le_u64(&mut bytes, 16, self.command_queue_offset);
        write_le_u64(&mut bytes, 24, self.status_queue_offset);
        write_le_u32(&mut bytes, 32, self.old_power_level);
        write_le_u32(&mut bytes, 36, self.power_flags);
        bytes[40] = u8::from(self.in_power_transition);
        write_le_u32(&mut bytes, 44, self.gpu_instance);
        bytes[48] = u8::from(self.dmem_stack);
        write_le_u64(&mut bytes, 56, self.profiler_pa);
        write_le_u64(&mut bytes, 64, self.profiler_size);
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspFirmwareLayout {
    pub image: FirmwareSection,
    pub signature: FirmwareSection,
    pub signature_allocation_bytes: usize,
    pub radix3: GspRadix3Layout,
    pub shared_memory: GspSharedMemoryLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspMemoryRegion {
    pub address: u64,
    pub size: usize,
}

impl GspMemoryRegion {
    pub fn end(self) -> Option<u64> {
        self.address.checked_add(u64::try_from(self.size).ok()?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspFramebufferLayout {
    pub framebuffer_size: u64,
    pub non_wpr_heap_address: u64,
    pub non_wpr_heap_size: u64,
    pub wpr_start: u64,
    pub wpr_size: u64,
    pub wpr_heap_address: u64,
    pub wpr_heap_size: u64,
    pub gsp_image_address: u64,
    pub gsp_image_size: u64,
    pub bootloader_address: u64,
    pub bootloader_size: u64,
    pub frts_address: u64,
    pub frts_size: u64,
    pub wpr_end: u64,
    pub vga_workspace_address: u64,
    pub vga_workspace_size: u64,
    pub pmu_reserved_size: u64,
    pub fsp_carveout_size: u64,
}

impl GspFramebufferLayout {
    /// Return the FRTS offset expected by the FSP COT packet.
    ///
    /// The COT wire field is measured backwards from the end of framebuffer memory, while WPR
    /// metadata carries the absolute FRTS address.
    pub fn frts_vidmem_offset(self) -> Result<u64, GspFramebufferLayoutError> {
        self.framebuffer_size
            .checked_sub(self.frts_address)
            .ok_or(GspFramebufferLayoutError::AddressUnderflow)
    }

    pub fn r570_gb20x(
        framebuffer_size: u64,
        bios_address: u64,
        gsp_image_size: usize,
        bootloader_size: usize,
    ) -> Result<Self, GspFramebufferLayoutError> {
        if framebuffer_size == 0 || bios_address > framebuffer_size {
            return Err(GspFramebufferLayoutError::InvalidBiosAddress {
                address: bios_address,
                framebuffer_size,
            });
        }
        let gsp_image_size =
            u64::try_from(gsp_image_size).map_err(|_| GspFramebufferLayoutError::SizeOverflow)?;
        let bootloader_size =
            u64::try_from(bootloader_size).map_err(|_| GspFramebufferLayoutError::SizeOverflow)?;
        let wpr_end = align_down_u64(bios_address, NVIDIA_GSP_WPR_ALIGNMENT as u64);
        let frts_size = NVIDIA_GSP_GB20X_FRTS_SIZE;
        let frts_address = wpr_end
            .checked_sub(frts_size)
            .ok_or(GspFramebufferLayoutError::AddressUnderflow)?;
        let bootloader_address = align_down_u64(
            frts_address
                .checked_sub(bootloader_size)
                .ok_or(GspFramebufferLayoutError::AddressUnderflow)?,
            NVIDIA_GSP_PAGE_SIZE as u64,
        );
        let gsp_image_address = align_down_u64(
            bootloader_address
                .checked_sub(gsp_image_size)
                .ok_or(GspFramebufferLayoutError::AddressUnderflow)?,
            NVIDIA_GSP_GB20X_ELF_ALIGNMENT,
        );
        let framebuffer_gib = ceil_div_u64(framebuffer_size, 1 << 30)
            .ok_or(GspFramebufferLayoutError::AddressOverflow)?;
        let per_gib_heap = align_up_u64(
            NVIDIA_GSP_R570_HEAP_PER_GB_FB
                .checked_mul(framebuffer_gib)
                .ok_or(GspFramebufferLayoutError::AddressOverflow)?,
            1 << 20,
        )
        .ok_or(GspFramebufferLayoutError::AddressOverflow)?;
        let client_heap = align_up_u64(NVIDIA_GSP_R570_CLIENT_ALLOC_HEAP, 1 << 20)
            .ok_or(GspFramebufferLayoutError::AddressOverflow)?;
        let calculated_heap_size = (NVIDIA_GSP_R570_BAREMETAL_OS_CARVEOUT as u64)
            .checked_add(NVIDIA_GSP_R570_BASE_RM_HEAP as u64)
            .and_then(|size| size.checked_add(per_gib_heap))
            .and_then(|size| size.checked_add(client_heap))
            .ok_or(GspFramebufferLayoutError::AddressOverflow)?;
        let requested_heap_size = calculated_heap_size.max(NVIDIA_GSP_R570_GB20X_WPR_HEAP_MIN);
        let wpr_heap_address = align_down_u64(
            gsp_image_address
                .checked_sub(requested_heap_size)
                .ok_or(GspFramebufferLayoutError::AddressUnderflow)?,
            NVIDIA_GSP_GB20X_WPR_HEAP_ALIGNMENT,
        );
        let wpr_heap_size = gsp_image_address
            .checked_sub(wpr_heap_address)
            .map(|size| size & !(NVIDIA_GSP_GB20X_WPR_HEAP_ALIGNMENT - 1))
            .ok_or(GspFramebufferLayoutError::AddressUnderflow)?;
        let wpr_start = align_down_u64(
            wpr_heap_address
                .checked_sub(NVIDIA_GSP_WPR_META_SIZE as u64)
                .ok_or(GspFramebufferLayoutError::AddressUnderflow)?,
            NVIDIA_GSP_GB20X_WPR_HEAP_ALIGNMENT,
        );
        if wpr_start >= wpr_end {
            return Err(GspFramebufferLayoutError::TooSmall {
                required: wpr_start,
                available: wpr_end,
            });
        }
        let non_wpr_heap_size = NVIDIA_GSP_R570_GB20X_NON_WPR_HEAP as u64;
        let non_wpr_heap_address = wpr_start
            .checked_sub(non_wpr_heap_size)
            .ok_or(GspFramebufferLayoutError::AddressUnderflow)?;
        let pmu_reserved_size = NVIDIA_GSP_R570_GB20X_PMU_RESERVED_SIZE;
        let fsp_carveout_size = align_up_u64(
            non_wpr_heap_size
                .checked_add(pmu_reserved_size)
                .ok_or(GspFramebufferLayoutError::AddressOverflow)?,
            NVIDIA_GSP_R570_FSP_CARVEOUT_ALIGNMENT,
        )
        .ok_or(GspFramebufferLayoutError::AddressOverflow)?;
        let vga_workspace_size = framebuffer_size
            .checked_sub(bios_address)
            .ok_or(GspFramebufferLayoutError::AddressUnderflow)?;
        let wpr_size = wpr_end
            .checked_sub(wpr_start)
            .ok_or(GspFramebufferLayoutError::AddressUnderflow)?;
        Ok(Self {
            framebuffer_size,
            non_wpr_heap_address,
            non_wpr_heap_size,
            wpr_start,
            wpr_size,
            wpr_heap_address,
            wpr_heap_size,
            gsp_image_address,
            gsp_image_size,
            bootloader_address,
            bootloader_size,
            frts_address,
            frts_size,
            wpr_end,
            vga_workspace_address: bios_address,
            vga_workspace_size,
            pmu_reserved_size,
            fsp_carveout_size,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspBootSystemMemoryPlan {
    pub layout: GspFirmwareLayout,
    pub system_base: u64,
    pub gsp_image_bytes: usize,
    pub fmc_image_bytes: usize,
    pub bootloader_bytes: usize,
    pub bootloader_code_offset: u64,
    pub bootloader_data_offset: u64,
    pub bootloader_manifest_offset: u64,
    pub fmc_image: GspMemoryRegion,
    pub gsp_image: GspMemoryRegion,
    pub radix3_level0: GspMemoryRegion,
    pub radix3_level1: GspMemoryRegion,
    pub radix3_level2: GspMemoryRegion,
    pub signature: GspMemoryRegion,
    pub bootloader: GspMemoryRegion,
    pub wpr_meta: GspMemoryRegion,
    pub fmc_args: GspMemoryRegion,
    pub libos_args: GspMemoryRegion,
    pub loginit: GspMemoryRegion,
    pub logintr: GspMemoryRegion,
    pub logrm: GspMemoryRegion,
    pub shared_memory: GspMemoryRegion,
    pub rm_args: GspMemoryRegion,
    pub end_address: u64,
    pub total_bytes: usize,
}

impl GspBootSystemMemoryPlan {
    pub fn r570_gb20x(
        bundle: GspFirmwareBundle,
        system_base: u64,
    ) -> Result<Self, GspSystemMemoryPlanError> {
        let layout = bundle
            .gsp
            .boot_layout()
            .map_err(GspSystemMemoryPlanError::BootLayout)?;
        let mut plan = Self::r570_from_layout(
            layout,
            bundle.fmc.image.size,
            bundle.bootloader.payload.size,
            system_base,
        )?;
        plan.bootloader_code_offset = u64::from(bundle.bootloader.descriptor.monitor_code_offset);
        plan.bootloader_data_offset = u64::from(bundle.bootloader.descriptor.monitor_data_offset);
        plan.bootloader_manifest_offset = u64::from(bundle.bootloader.descriptor.manifest_offset);
        Ok(plan)
    }

    pub fn r570_from_layout(
        layout: GspFirmwareLayout,
        fmc_image_bytes: usize,
        bootloader_bytes: usize,
        system_base: u64,
    ) -> Result<Self, GspSystemMemoryPlanError> {
        if system_base & (NVIDIA_GSP_PAGE_SIZE as u64 - 1) != 0 {
            return Err(GspSystemMemoryPlanError::BaseUnaligned {
                address: system_base,
            });
        }
        if layout.image.size == 0
            || fmc_image_bytes == 0
            || bootloader_bytes == 0
            || layout.signature_allocation_bytes == 0
        {
            return Err(GspSystemMemoryPlanError::EmptyRegion);
        }
        let gsp_image_bytes = layout.image.size;
        let gsp_image_allocation =
            align_page(gsp_image_bytes).ok_or(GspSystemMemoryPlanError::SizeOverflow)?;
        let mut next = system_base;
        let fmc_image = stage_region(
            &mut next,
            align_page(fmc_image_bytes).ok_or(GspSystemMemoryPlanError::SizeOverflow)?,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let gsp_image = stage_region(&mut next, gsp_image_allocation, NVIDIA_GSP_PAGE_SIZE as u64)?;
        let radix3_level0 = stage_region(
            &mut next,
            layout.radix3.level0_bytes,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let radix3_level1 = stage_region(
            &mut next,
            layout.radix3.level1_bytes,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let radix3_level2 = stage_region(
            &mut next,
            layout.radix3.level2_bytes,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let signature = stage_region(
            &mut next,
            layout.signature_allocation_bytes,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let bootloader = stage_region(&mut next, bootloader_bytes, NVIDIA_GSP_PAGE_SIZE as u64)?;
        let wpr_meta = stage_region(
            &mut next,
            NVIDIA_GSP_WPR_META_SIZE,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let fmc_args = stage_region(
            &mut next,
            NVIDIA_GSP_FMC_BOOT_PARAMS_SIZE,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let libos_args = stage_region(
            &mut next,
            NVIDIA_GSP_LIBOS_ARGUMENTS_SIZE,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let loginit = stage_region(
            &mut next,
            NVIDIA_GSP_LOG_BUFFER_SIZE,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let logintr = stage_region(
            &mut next,
            NVIDIA_GSP_LOG_BUFFER_SIZE,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let logrm = stage_region(
            &mut next,
            NVIDIA_GSP_LOG_BUFFER_SIZE,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let shared_memory = stage_region(
            &mut next,
            layout.shared_memory.total_bytes,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let rm_args = stage_region(
            &mut next,
            NVIDIA_GSP_RM_ARGUMENTS_SIZE,
            NVIDIA_GSP_PAGE_SIZE as u64,
        )?;
        let total_bytes = usize::try_from(
            next.checked_sub(system_base)
                .ok_or(GspSystemMemoryPlanError::AddressOverflow)?,
        )
        .map_err(|_| GspSystemMemoryPlanError::SizeOverflow)?;
        Ok(Self {
            layout,
            system_base,
            gsp_image_bytes,
            fmc_image_bytes,
            bootloader_bytes,
            bootloader_code_offset: 0,
            bootloader_data_offset: 0,
            bootloader_manifest_offset: 0,
            fmc_image,
            gsp_image,
            radix3_level0,
            radix3_level1,
            radix3_level2,
            signature,
            bootloader,
            wpr_meta,
            fmc_args,
            libos_args,
            loginit,
            logintr,
            logrm,
            shared_memory,
            rm_args,
            end_address: next,
            total_bytes,
        })
    }

    pub fn radix3_tables(self) -> Result<GspRadix3Tables, GspMemoryError> {
        let level2_addresses =
            contiguous_page_addresses(self.radix3_level2, self.layout.radix3.level2_pages)?;
        let image_page_addresses =
            contiguous_page_addresses(self.gsp_image, self.layout.radix3.image_pages)?;
        self.layout.radix3.materialize(
            self.radix3_level0.address,
            self.radix3_level1.address,
            &level2_addresses,
            &image_page_addresses,
        )
    }

    pub fn shared_memory_image(self) -> Result<GspSharedMemoryImage, GspMemoryError> {
        let page_addresses = contiguous_page_addresses(
            self.shared_memory,
            self.layout.shared_memory.page_table_entry_count,
        )?;
        self.layout.shared_memory.materialize(&page_addresses)
    }

    pub fn cached_arguments(
        self,
    ) -> Result<[u8; NVIDIA_GSP_R570_CACHED_ARGUMENTS_SIZE], GspMemoryError> {
        GspCachedArguments::r570(self.shared_memory.address, self.layout.shared_memory)
            .map(GspCachedArguments::encode)
    }

    pub fn fmc_boot_params(self) -> [u8; NVIDIA_GSP_FMC_BOOT_PARAMS_SIZE] {
        GspFmcBootParams::r570(
            self.wpr_meta.address,
            NVIDIA_GSP_WPR_META_SIZE as u32,
            self.libos_args.address,
        )
        .encode()
    }

    pub fn wpr_meta(
        self,
        framebuffer: GspFramebufferLayout,
    ) -> Result<GspWprMeta, GspSystemMemoryPlanError> {
        let gsp_image_bytes = u64::try_from(self.gsp_image_bytes)
            .map_err(|_| GspSystemMemoryPlanError::SizeOverflow)?;
        let bootloader_bytes = u64::try_from(self.bootloader_bytes)
            .map_err(|_| GspSystemMemoryPlanError::SizeOverflow)?;
        let signature_bytes = u64::try_from(self.signature.size)
            .map_err(|_| GspSystemMemoryPlanError::SizeOverflow)?;
        let pmu_reserved_size = u32::try_from(framebuffer.pmu_reserved_size)
            .map_err(|_| GspSystemMemoryPlanError::SizeOverflow)?;
        Ok(GspWprMeta {
            sysmem_addr_of_radix3_elf: self.radix3_level0.address,
            size_of_radix3_elf: gsp_image_bytes,
            sysmem_addr_of_bootloader: self.bootloader.address,
            size_of_bootloader: bootloader_bytes,
            bootloader_code_offset: self.bootloader_code_offset,
            bootloader_data_offset: self.bootloader_data_offset,
            bootloader_manifest_offset: self.bootloader_manifest_offset,
            sysmem_addr_of_signature: self.signature.address,
            size_of_signature: signature_bytes,
            gsp_fw_rsvd_start: framebuffer.non_wpr_heap_address,
            non_wpr_heap_offset: framebuffer.non_wpr_heap_address,
            non_wpr_heap_size: framebuffer.non_wpr_heap_size,
            gsp_fw_wpr_start: framebuffer.wpr_start,
            gsp_fw_heap_offset: framebuffer.wpr_heap_address,
            gsp_fw_heap_size: framebuffer.wpr_heap_size,
            gsp_fw_offset: framebuffer.gsp_image_address,
            boot_bin_offset: framebuffer.bootloader_address,
            frts_offset: framebuffer.frts_address,
            frts_size: framebuffer.frts_size,
            gsp_fw_wpr_end: framebuffer.wpr_end,
            fb_size: framebuffer.framebuffer_size,
            vga_workspace_offset: framebuffer.vga_workspace_address,
            vga_workspace_size: framebuffer.vga_workspace_size,
            boot_count: 0,
            partition_rpc_addr: 0,
            partition_rpc_request_offset: 0,
            partition_rpc_reply_offset: 0,
            elf_code_offset: 0,
            elf_data_offset: 0,
            elf_code_size: 0,
            elf_data_size: 0,
            ls_ucode_version: 0,
            gsp_fw_heap_vf_partition_count: 0,
            flags: 0,
            pmu_reserved_size,
            verified: 0,
        })
    }

    pub fn materialize_bundle_into(
        self,
        bundle: GspFirmwareBundle,
        gsp_bytes: &[u8],
        fmc_bytes: &[u8],
        bootloader_bytes: &[u8],
        framebuffer: GspFramebufferLayout,
        output: &mut [u8],
    ) -> Result<(), GspMaterializationError> {
        if output.len() < self.total_bytes {
            return Err(GspMaterializationError::BufferTooSmall {
                required: self.total_bytes,
                actual: output.len(),
            });
        }
        let bundle_layout = bundle
            .gsp
            .boot_layout()
            .map_err(GspMaterializationError::BootLayout)?;
        if bundle_layout != self.layout
            || bundle.fmc.image.size != self.fmc_image_bytes
            || bundle.bootloader.payload.size != self.bootloader_bytes
        {
            return Err(GspMaterializationError::LayoutMismatch);
        }
        output[..self.total_bytes].fill(0);

        copy_section_into(
            output,
            self.system_base,
            self.fmc_image,
            bundle.fmc.image,
            fmc_bytes,
        )?;
        copy_section_into(
            output,
            self.system_base,
            self.gsp_image,
            bundle.gsp.image,
            gsp_bytes,
        )?;
        let signature = bundle
            .gsp
            .gb20x_signature
            .ok_or(GspMaterializationError::LayoutMismatch)?;
        copy_section_into(
            output,
            self.system_base,
            self.signature,
            signature,
            gsp_bytes,
        )?;
        copy_section_into(
            output,
            self.system_base,
            self.bootloader,
            bundle.bootloader.payload,
            bootloader_bytes,
        )?;

        let radix3 = self
            .radix3_tables()
            .map_err(GspMaterializationError::Memory)?;
        copy_bytes_into(output, self.system_base, self.radix3_level0, &radix3.level0)?;
        copy_bytes_into(output, self.system_base, self.radix3_level1, &radix3.level1)?;
        copy_bytes_into(output, self.system_base, self.radix3_level2, &radix3.level2)?;

        let shared = self
            .shared_memory_image()
            .map_err(GspMaterializationError::Memory)?;
        copy_bytes_into(
            output,
            self.system_base,
            self.shared_memory,
            &shared.page_table,
        )?;
        let command_queue_address = self
            .shared_memory
            .address
            .checked_add(
                u64::try_from(self.layout.shared_memory.command_queue_offset)
                    .map_err(|_| GspMaterializationError::LayoutMismatch)?,
            )
            .ok_or(GspMaterializationError::LayoutMismatch)?;
        copy_bytes_into(
            output,
            self.system_base,
            GspMemoryRegion {
                address: command_queue_address,
                size: shared.command_queue.len(),
            },
            &shared.command_queue,
        )?;
        let status_queue_address = self
            .shared_memory
            .address
            .checked_add(
                u64::try_from(self.layout.shared_memory.status_queue_offset)
                    .map_err(|_| GspMaterializationError::LayoutMismatch)?,
            )
            .ok_or(GspMaterializationError::LayoutMismatch)?;
        copy_bytes_into(
            output,
            self.system_base,
            GspMemoryRegion {
                address: status_queue_address,
                size: shared.status_queue.len(),
            },
            &shared.status_queue,
        )?;

        let cached_arguments = self
            .cached_arguments()
            .map_err(GspMaterializationError::Memory)?;
        copy_bytes_into(output, self.system_base, self.rm_args, &cached_arguments)?;
        let metadata = self
            .wpr_meta(framebuffer)
            .map_err(GspMaterializationError::SystemPlan)?
            .encode();
        copy_bytes_into(output, self.system_base, self.wpr_meta, &metadata)?;
        let fmc_args = self.fmc_boot_params();
        copy_bytes_into(output, self.system_base, self.fmc_args, &fmc_args)
    }
}

impl GspFirmware {
    pub fn parse(firmware: &[u8]) -> Result<Self, GspFirmwareError> {
        if firmware.len() > NVIDIA_GSP_MAX_FIRMWARE_SIZE {
            return Err(GspFirmwareError::TooLarge {
                size: firmware.len(),
                limit: NVIDIA_GSP_MAX_FIRMWARE_SIZE,
            });
        }
        if firmware.len() < NVIDIA_GSP_ELF_HEADER_SIZE {
            return Err(GspFirmwareError::Truncated {
                offset: 0,
                size: NVIDIA_GSP_ELF_HEADER_SIZE,
            });
        }
        if firmware[..4] != ELF_MAGIC {
            return Err(GspFirmwareError::InvalidMagic);
        }
        if firmware[4] != ELF_CLASS_64 {
            return Err(GspFirmwareError::UnsupportedClass { value: firmware[4] });
        }
        if firmware[5] != ELF_DATA_LITTLE {
            return Err(GspFirmwareError::UnsupportedEndian { value: firmware[5] });
        }
        if firmware[6] != ELF_VERSION_CURRENT {
            return Err(GspFirmwareError::UnsupportedVersion { value: firmware[6] });
        }
        let elf_type = read_u16(firmware, 16)?;
        if elf_type != ELF_TYPE_REL {
            return Err(GspFirmwareError::UnsupportedType { value: elf_type });
        }
        let machine = read_u16(firmware, 18)?;
        if machine != ELF_MACHINE_RISCV {
            return Err(GspFirmwareError::UnsupportedMachine { value: machine });
        }
        if read_u64(firmware, 32)? != 0 || read_u16(firmware, 56)? != 0 {
            return Err(GspFirmwareError::ProgramHeadersPresent);
        }
        let section_table_offset = usize_from_u64(read_u64(firmware, 40)?)?;
        let section_entry_size = usize::from(read_u16(firmware, 58)?);
        let section_count = usize::from(read_u16(firmware, 60)?);
        let string_table_index = usize::from(read_u16(firmware, 62)?);
        if section_entry_size != NVIDIA_GSP_ELF_SECTION_HEADER_SIZE
            || section_count == 0
            || section_count > NVIDIA_GSP_MAX_SECTIONS
            || string_table_index >= section_count
        {
            return Err(GspFirmwareError::InvalidSectionTable);
        }
        let section_table_size = section_count
            .checked_mul(section_entry_size)
            .ok_or(GspFirmwareError::InvalidSectionTable)?;
        checked_range(firmware, section_table_offset, section_table_size)
            .map_err(|_| GspFirmwareError::InvalidSectionTable)?;

        let string_header = section_header(firmware, section_table_offset, string_table_index)?;
        if string_header.kind != ELF_SECTION_STRTAB {
            return Err(GspFirmwareError::InvalidStringTable);
        }
        let string_table = string_header.section.bytes(firmware);
        let mut image = None;
        let mut version = None;
        let mut gb20x_signature = None;
        for index in 0..section_count {
            let header = section_header(firmware, section_table_offset, index)?;
            let name = section_name(string_table, header.name_offset)
                .ok_or(GspFirmwareError::InvalidSectionName)?;
            if header.kind == ELF_SECTION_PROGBITS && name == b".fwimage" {
                image = Some(header.section);
            } else if header.kind == ELF_SECTION_PROGBITS && name == b".fwversion" {
                version = Some(header.section);
            } else if header.kind == ELF_SECTION_PROGBITS && name == b".fwsignature_gb20x" {
                gb20x_signature = Some(header.section);
            }
        }
        let image = image.ok_or(GspFirmwareError::MissingFirmwareImage)?;
        if image.size == 0 || image.offset == 0 {
            return Err(GspFirmwareError::InvalidFirmwareImage);
        }
        let version = version.ok_or(GspFirmwareError::MissingFirmwareVersion)?;
        let version_bytes = version.bytes(firmware);
        if version_bytes.is_empty()
            || version_bytes.len() > 32
            || version_bytes[version_bytes.len() - 1] != 0
        {
            return Err(GspFirmwareError::InvalidFirmwareVersion);
        }

        Ok(Self {
            image,
            version,
            gb20x_signature,
            section_count,
        })
    }

    pub fn version_bytes<'a>(self, firmware: &'a [u8]) -> &'a [u8] {
        let bytes = self.version.bytes(firmware);
        &bytes[..bytes.len() - 1]
    }

    pub const fn supports_gb20x(self) -> bool {
        self.gb20x_signature.is_some()
    }

    pub fn boot_layout(self) -> Result<GspFirmwareLayout, GspBootPlanError> {
        let signature = self
            .gb20x_signature
            .ok_or(GspBootPlanError::MissingGb20xSignature)?;
        if signature.size == 0 {
            return Err(GspBootPlanError::EmptyGb20xSignature);
        }
        let image_pages = ceil_div(self.image.size, NVIDIA_GSP_PAGE_SIZE)
            .ok_or(GspBootPlanError::SizeOverflow)?;
        if image_pages > NVIDIA_GSP_RADIX3_MAX_IMAGE_PAGES {
            return Err(GspBootPlanError::ImageTooLarge {
                pages: image_pages,
                limit: NVIDIA_GSP_RADIX3_MAX_IMAGE_PAGES,
            });
        }
        let level2_bytes = align_page(
            image_pages
                .checked_mul(core::mem::size_of::<u64>())
                .ok_or(GspBootPlanError::SizeOverflow)?,
        )
        .ok_or(GspBootPlanError::SizeOverflow)?;
        let level2_pages = level2_bytes / NVIDIA_GSP_PAGE_SIZE;
        let signature_allocation_bytes =
            align_value(signature.size, 256).ok_or(GspBootPlanError::SizeOverflow)?;
        let radix3 = GspRadix3Layout {
            image_pages,
            level0_bytes: NVIDIA_GSP_PAGE_SIZE,
            level1_bytes: NVIDIA_GSP_PAGE_SIZE,
            level2_bytes,
            level2_pages,
            total_bytes: NVIDIA_GSP_PAGE_SIZE
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(level2_bytes))
                .ok_or(GspBootPlanError::SizeOverflow)?,
        };
        Ok(GspFirmwareLayout {
            image: self.image,
            signature,
            signature_allocation_bytes,
            radix3,
            shared_memory: GspSharedMemoryLayout::standard(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SectionHeader {
    name_offset: usize,
    kind: u32,
    section: FirmwareSection,
}

fn section_header(
    firmware: &[u8],
    table_offset: usize,
    index: usize,
) -> Result<SectionHeader, GspFirmwareError> {
    let offset = table_offset
        .checked_add(
            index
                .checked_mul(NVIDIA_GSP_ELF_SECTION_HEADER_SIZE)
                .ok_or(GspFirmwareError::InvalidSectionTable)?,
        )
        .ok_or(GspFirmwareError::InvalidSectionTable)?;
    let name_offset = usize_from_u32(read_u32(firmware, offset)?)?;
    let kind = read_u32(firmware, offset + 4)?;
    let section_offset = usize_from_u64(read_u64(firmware, offset + 24)?)?;
    let section_size = usize_from_u64(read_u64(firmware, offset + 32)?)?;
    checked_range(firmware, section_offset, section_size).map_err(|_| {
        GspFirmwareError::Truncated {
            offset: section_offset,
            size: section_size,
        }
    })?;
    Ok(SectionHeader {
        name_offset,
        kind,
        section: FirmwareSection {
            offset: section_offset,
            size: section_size,
        },
    })
}

fn section_name<'a>(table: &'a [u8], offset: usize) -> Option<&'a [u8]> {
    let bytes = table.get(offset..)?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    Some(&bytes[..end])
}

fn checked_range(bytes: &[u8], offset: usize, size: usize) -> Result<(), ()> {
    let end = offset.checked_add(size).ok_or(())?;
    if end > bytes.len() {
        return Err(());
    }
    Ok(())
}

fn usize_from_u32(value: u32) -> Result<usize, GspFirmwareError> {
    usize::try_from(value).map_err(|_| GspFirmwareError::InvalidSectionTable)
}

fn usize_from_u64(value: u64) -> Result<usize, GspFirmwareError> {
    usize::try_from(value).map_err(|_| GspFirmwareError::InvalidSectionTable)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, GspFirmwareError> {
    let end = offset
        .checked_add(2)
        .ok_or(GspFirmwareError::Truncated { offset, size: 2 })?;
    let value = bytes
        .get(offset..end)
        .ok_or(GspFirmwareError::Truncated { offset, size: 2 })?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, GspFirmwareError> {
    let end = offset
        .checked_add(4)
        .ok_or(GspFirmwareError::Truncated { offset, size: 4 })?;
    let value = bytes
        .get(offset..end)
        .ok_or(GspFirmwareError::Truncated { offset, size: 4 })?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, GspFirmwareError> {
    let end = offset
        .checked_add(8)
        .ok_or(GspFirmwareError::Truncated { offset, size: 8 })?;
    let value = bytes
        .get(offset..end)
        .ok_or(GspFirmwareError::Truncated { offset, size: 8 })?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspRpcError {
    PayloadTooLarge { size: usize, limit: usize },
    MessageTooLarge { pages: usize, limit: usize },
    InvalidHeaderVersion { actual: u32 },
    InvalidSignature { actual: u32 },
    InvalidRpcLength { length: u32 },
    InvalidElementCount { count: u32, pages: usize },
    ChecksumMismatch { expected: u32, actual: u32 },
    SizeOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspRpcMessage<'a> {
    bytes: &'a [u8],
}

impl<'a> GspRpcMessage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, GspRpcError> {
        if bytes.len() < NVIDIA_GSP_MESSAGE_HEADER_SIZE + NVIDIA_GSP_RPC_HEADER_SIZE
            || bytes.len() % NVIDIA_GSP_PAGE_SIZE != 0
        {
            return Err(GspRpcError::SizeOverflow);
        }
        let pages = bytes.len() / NVIDIA_GSP_PAGE_SIZE;
        if pages > NVIDIA_GSP_MAX_MESSAGE_PAGES {
            return Err(GspRpcError::MessageTooLarge {
                pages,
                limit: NVIDIA_GSP_MAX_MESSAGE_PAGES,
            });
        }
        let element_count = read_le_u32(bytes, 40);
        if usize::try_from(element_count).ok() != Some(pages) {
            return Err(GspRpcError::InvalidElementCount {
                count: element_count,
                pages,
            });
        }
        let rpc_offset = NVIDIA_GSP_MESSAGE_HEADER_SIZE;
        let header_version = read_le_u32(bytes, rpc_offset);
        if header_version != NVIDIA_GSP_RPC_HEADER_VERSION {
            return Err(GspRpcError::InvalidHeaderVersion {
                actual: header_version,
            });
        }
        let signature = read_le_u32(bytes, rpc_offset + 4);
        if signature != NVIDIA_GSP_RPC_SIGNATURE {
            return Err(GspRpcError::InvalidSignature { actual: signature });
        }
        let rpc_length = read_le_u32(bytes, rpc_offset + 8);
        let rpc_length_usize =
            usize::try_from(rpc_length).map_err(|_| GspRpcError::SizeOverflow)?;
        let rpc_end = rpc_offset
            .checked_add(rpc_length_usize)
            .ok_or(GspRpcError::SizeOverflow)?;
        if rpc_length_usize < NVIDIA_GSP_RPC_HEADER_SIZE || rpc_end > bytes.len() {
            return Err(GspRpcError::InvalidRpcLength { length: rpc_length });
        }
        Ok(Self { bytes })
    }

    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    pub fn sequence(self) -> u32 {
        self.transport_sequence()
    }

    pub fn transport_sequence(self) -> u32 {
        read_le_u32(self.bytes, 36)
    }

    pub fn element_count(self) -> u32 {
        read_le_u32(self.bytes, 40)
    }

    pub fn checksum(self) -> u32 {
        read_le_u32(self.bytes, 32)
    }

    pub fn rpc_length(self) -> u32 {
        read_le_u32(self.bytes, NVIDIA_GSP_MESSAGE_HEADER_SIZE + 8)
    }

    pub fn function(self) -> u32 {
        read_le_u32(self.bytes, NVIDIA_GSP_MESSAGE_HEADER_SIZE + 12)
    }

    pub fn rpc_result(self) -> u32 {
        read_le_u32(self.bytes, NVIDIA_GSP_MESSAGE_HEADER_SIZE + 16)
    }

    pub fn rpc_result_private(self) -> u32 {
        read_le_u32(self.bytes, NVIDIA_GSP_MESSAGE_HEADER_SIZE + 20)
    }

    pub fn rpc_sequence(self) -> u32 {
        read_le_u32(self.bytes, NVIDIA_GSP_MESSAGE_HEADER_SIZE + 24)
    }

    pub fn message_length(self) -> usize {
        self.bytes.len()
    }

    pub fn payload(self) -> &'a [u8] {
        let start = NVIDIA_GSP_MESSAGE_HEADER_SIZE + NVIDIA_GSP_RPC_HEADER_SIZE;
        let length = usize::try_from(self.rpc_length()).unwrap_or(0);
        let end = length
            .saturating_sub(NVIDIA_GSP_RPC_HEADER_SIZE)
            .saturating_add(start)
            .min(self.bytes.len());
        &self.bytes[start..end]
    }

    pub fn checksum_valid(self) -> bool {
        checksum_for_rpc(self.bytes, self.rpc_length()) == self.checksum()
    }
}

pub fn encode_gsp_rpc(
    function: u32,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, GspRpcError> {
    encode_gsp_rpc_with_sequences(function, sequence, 0, payload)
}

pub fn encode_gsp_rpc_with_sequences(
    function: u32,
    transport_sequence: u32,
    rpc_sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, GspRpcError> {
    let rpc_length = NVIDIA_GSP_RPC_HEADER_SIZE
        .checked_add(payload.len())
        .ok_or(GspRpcError::SizeOverflow)?;
    let maximum_rpc_length = NVIDIA_GSP_MAX_MESSAGE_PAGES
        .checked_mul(NVIDIA_GSP_PAGE_SIZE)
        .and_then(|size| size.checked_sub(NVIDIA_GSP_MESSAGE_HEADER_SIZE))
        .ok_or(GspRpcError::SizeOverflow)?;
    if rpc_length > maximum_rpc_length {
        return Err(GspRpcError::PayloadTooLarge {
            size: payload.len(),
            limit: maximum_rpc_length - NVIDIA_GSP_RPC_HEADER_SIZE,
        });
    }
    let total_length = align_page(
        NVIDIA_GSP_MESSAGE_HEADER_SIZE
            .checked_add(rpc_length)
            .ok_or(GspRpcError::SizeOverflow)?,
    )
    .ok_or(GspRpcError::SizeOverflow)?;
    let mut bytes = Vec::new();
    bytes.resize(total_length, 0);
    let element_count = u32::try_from(total_length / NVIDIA_GSP_PAGE_SIZE)
        .map_err(|_| GspRpcError::SizeOverflow)?;
    write_le_u32(&mut bytes, 36, transport_sequence);
    write_le_u32(&mut bytes, 40, element_count);
    let rpc_offset = NVIDIA_GSP_MESSAGE_HEADER_SIZE;
    write_le_u32(&mut bytes, rpc_offset, NVIDIA_GSP_RPC_HEADER_VERSION);
    write_le_u32(&mut bytes, rpc_offset + 4, NVIDIA_GSP_RPC_SIGNATURE);
    write_le_u32(
        &mut bytes,
        rpc_offset + 8,
        u32::try_from(rpc_length).map_err(|_| GspRpcError::SizeOverflow)?,
    );
    write_le_u32(&mut bytes, rpc_offset + 12, function);
    write_le_u32(&mut bytes, rpc_offset + 16, u32::MAX);
    write_le_u32(&mut bytes, rpc_offset + 20, u32::MAX);
    write_le_u32(&mut bytes, rpc_offset + 24, rpc_sequence);
    let payload_offset = rpc_offset + NVIDIA_GSP_RPC_HEADER_SIZE;
    bytes[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    let message_checksum = checksum_for_rpc(&bytes, rpc_length as u32);
    write_le_u32(&mut bytes, 32, message_checksum);
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspSystemInfoR570 {
    pub gpu_phys_addr: u64,
    pub gpu_phys_fb_addr: u64,
    pub gpu_phys_inst_addr: u64,
    pub nv_domain_bus_device_func: u16,
    pub pci_device_id: u16,
    pub pci_vendor_id: u16,
    pub pci_subdevice_id: u16,
    pub pci_subvendor_id: u16,
    pub pci_revision_id: u8,
}

impl GspSystemInfoR570 {
    pub fn r570_gb20x(
        gpu_phys_addr: u64,
        gpu_phys_fb_addr: u64,
        gpu_phys_inst_addr: u64,
        nv_domain_bus_device_func: u16,
        pci_device_id: u16,
        pci_vendor_id: u16,
        pci_subdevice_id: u16,
        pci_subvendor_id: u16,
        pci_revision_id: u8,
    ) -> Self {
        Self {
            gpu_phys_addr,
            gpu_phys_fb_addr,
            gpu_phys_inst_addr,
            nv_domain_bus_device_func,
            pci_device_id,
            pci_vendor_id,
            pci_subdevice_id,
            pci_subvendor_id,
            pci_revision_id,
        }
    }

    pub fn encode(self) -> [u8; NVIDIA_GSP_R570_SYSTEM_INFO_SIZE] {
        let mut bytes = [0u8; NVIDIA_GSP_R570_SYSTEM_INFO_SIZE];
        write_le_u64(&mut bytes, 0, self.gpu_phys_addr);
        write_le_u64(&mut bytes, 8, self.gpu_phys_fb_addr);
        write_le_u64(&mut bytes, 16, self.gpu_phys_inst_addr);
        write_le_u64(&mut bytes, 32, u64::from(self.nv_domain_bus_device_func));
        write_le_u64(&mut bytes, 72, NVIDIA_GSP_R570_MAX_USER_VA);
        write_le_u32(&mut bytes, 80, NVIDIA_GSP_R570_PCI_CONFIG_MIRROR_BASE);
        write_le_u32(&mut bytes, 84, NVIDIA_GSP_R570_PCI_CONFIG_MIRROR_SIZE);
        write_le_u32(
            &mut bytes,
            88,
            (u32::from(self.pci_device_id) << 16) | u32::from(self.pci_vendor_id),
        );
        write_le_u32(
            &mut bytes,
            92,
            (u32::from(self.pci_subdevice_id) << 16) | u32::from(self.pci_subvendor_id),
        );
        write_le_u32(&mut bytes, 96, u32::from(self.pci_revision_id));
        write_le_u32(&mut bytes, 120, NVIDIA_GSP_R570_CHIPSET_GB205);
        bytes
    }
}

pub fn encode_gsp_registry() -> Vec<u8> {
    const KEYS: [&[u8]; 3] = [
        b"RMSecBusResetEnable",
        b"RMForcePcieConfigSave",
        b"RMDevidCheckIgnore",
    ];
    const ENTRY_SIZE: usize = 16;
    let string_size = KEYS[0].len() + 1 + KEYS[1].len() + 1 + KEYS[2].len() + 1;
    let variable_size = KEYS.len() * ENTRY_SIZE + string_size;
    let mut bytes = Vec::new();
    bytes.resize(8 + variable_size, 0);
    write_le_u32(&mut bytes, 0, variable_size as u32);
    write_le_u32(&mut bytes, 4, KEYS.len() as u32);

    let string_start = 8 + KEYS.len() * ENTRY_SIZE;
    let mut string_offset = string_start;
    for (index, key) in KEYS.iter().enumerate() {
        let entry_offset = 8 + index * ENTRY_SIZE;
        write_le_u32(&mut bytes, entry_offset, string_offset as u32);
        bytes[entry_offset + 4] = NVIDIA_GSP_REGISTRY_DWORD;
        write_le_u32(&mut bytes, entry_offset + 8, 1);
        let end = string_offset + key.len();
        bytes[string_offset..end].copy_from_slice(key);
        bytes[end] = 0;
        string_offset = end + 1;
    }
    bytes
}

pub fn encode_gsp_static_info_request() -> [u8; NVIDIA_GSP_R570_STATIC_CONFIG_INFO_SIZE] {
    [0u8; NVIDIA_GSP_R570_STATIC_CONFIG_INFO_SIZE]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspStaticInfoError {
    PayloadTooSmall { required: usize, actual: usize },
    GpuNameEmpty,
    GpuNameNotTerminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspStaticInfo {
    pub gpu_name: [u8; 64],
}

pub fn parse_gsp_static_info(payload: &[u8]) -> Result<GspStaticInfo, GspStaticInfoError> {
    let name_end = NVIDIA_GSP_R570_STATIC_GPU_NAME_OFFSET + 64;
    if payload.len() < NVIDIA_GSP_R570_STATIC_CONFIG_INFO_SIZE {
        return Err(GspStaticInfoError::PayloadTooSmall {
            required: NVIDIA_GSP_R570_STATIC_CONFIG_INFO_SIZE,
            actual: payload.len(),
        });
    }
    let mut gpu_name = [0u8; 64];
    gpu_name.copy_from_slice(&payload[NVIDIA_GSP_R570_STATIC_GPU_NAME_OFFSET..name_end]);
    let Some(terminator) = gpu_name.iter().position(|byte| *byte == 0) else {
        return Err(GspStaticInfoError::GpuNameNotTerminated);
    };
    if terminator == 0 {
        return Err(GspStaticInfoError::GpuNameEmpty);
    }
    Ok(GspStaticInfo { gpu_name })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspQueueError {
    BufferTooSmall {
        required: usize,
        actual: usize,
    },
    PointerOutOfRange {
        pointer: u32,
        count: usize,
    },
    QueueFull {
        write_pointer: u32,
        read_pointer: u32,
    },
    MessageNotReady {
        required: usize,
        available: usize,
    },
    Rpc(GspRpcError),
}

impl From<GspRpcError> for GspQueueError {
    fn from(error: GspRpcError) -> Self {
        Self::Rpc(error)
    }
}

pub struct GspQueue<'a> {
    bytes: &'a mut [u8],
}

impl<'a> GspQueue<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, GspQueueError> {
        if bytes.len() < NVIDIA_GSP_SHARED_QUEUE_BYTES {
            return Err(GspQueueError::BufferTooSmall {
                required: NVIDIA_GSP_SHARED_QUEUE_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    pub fn write_pointer(&self) -> Result<u32, GspQueueError> {
        self.pointer(NVIDIA_GSP_QUEUE_TX_WRITE_POINTER_OFFSET)
    }

    pub fn read_pointer(&self) -> Result<u32, GspQueueError> {
        self.pointer(NVIDIA_GSP_QUEUE_RX_READ_POINTER_OFFSET)
    }

    pub fn available_entries(&self) -> Result<usize, GspQueueError> {
        let write = self.write_pointer()?;
        let read = self.read_pointer()?;
        let used = queue_distance(read, write)?;
        Ok(NVIDIA_GSP_QUEUE_ENTRY_COUNT - used - 1)
    }

    pub fn write_message(&mut self, message: &[u8]) -> Result<u32, GspQueueError> {
        let parsed = GspRpcMessage::parse(message)?;
        if !parsed.checksum_valid() {
            return Err(GspRpcError::ChecksumMismatch {
                expected: checksum_for_rpc(message, parsed.rpc_length()),
                actual: parsed.checksum(),
            }
            .into());
        }
        let pages = message.len() / NVIDIA_GSP_PAGE_SIZE;
        let write = self.write_pointer()?;
        let read = self.read_pointer()?;
        let available = self.available_entries()?;
        if pages > available {
            return Err(GspQueueError::QueueFull {
                write_pointer: write,
                read_pointer: read,
            });
        }
        for page in 0..pages {
            let slot = queue_advance(write, page)?;
            let offset = queue_slot_offset(slot)?;
            let slot_bytes = &mut self.bytes[offset..offset + NVIDIA_GSP_PAGE_SIZE];
            slot_bytes.fill(0);
            let source_start = page * NVIDIA_GSP_PAGE_SIZE;
            slot_bytes.copy_from_slice(&message[source_start..source_start + NVIDIA_GSP_PAGE_SIZE]);
        }
        let next = queue_advance(write, pages)?;
        write_le_u32(self.bytes, NVIDIA_GSP_QUEUE_TX_WRITE_POINTER_OFFSET, next);
        Ok(next)
    }

    pub fn try_receive_message(&mut self) -> Result<Option<Vec<u8>>, GspQueueError> {
        let write = self.write_pointer()?;
        let read = self.read_pointer()?;
        if write == read {
            return Ok(None);
        }
        let available = queue_distance(read, write)?;
        let first_offset = queue_slot_offset(read)?;
        let element_count = read_le_u32(self.bytes, first_offset + 40);
        let pages = usize::try_from(element_count).map_err(|_| GspRpcError::SizeOverflow)?;
        if pages == 0 || pages > NVIDIA_GSP_MAX_MESSAGE_PAGES {
            return Err(GspRpcError::InvalidElementCount {
                count: element_count,
                pages,
            }
            .into());
        }
        if pages > available {
            return Err(GspQueueError::MessageNotReady {
                required: pages,
                available,
            });
        }
        let message_bytes = pages
            .checked_mul(NVIDIA_GSP_PAGE_SIZE)
            .ok_or(GspRpcError::SizeOverflow)?;
        let mut message = Vec::new();
        message.resize(message_bytes, 0);
        for page in 0..pages {
            let slot = queue_advance(read, page)?;
            let offset = queue_slot_offset(slot)?;
            let destination_start = page * NVIDIA_GSP_PAGE_SIZE;
            message[destination_start..destination_start + NVIDIA_GSP_PAGE_SIZE]
                .copy_from_slice(&self.bytes[offset..offset + NVIDIA_GSP_PAGE_SIZE]);
        }
        let parsed = GspRpcMessage::parse(&message)?;
        if !parsed.checksum_valid() {
            return Err(GspRpcError::ChecksumMismatch {
                expected: checksum_for_rpc(&message, parsed.rpc_length()),
                actual: parsed.checksum(),
            }
            .into());
        }
        let next = queue_advance(read, pages)?;
        write_le_u32(self.bytes, NVIDIA_GSP_QUEUE_RX_READ_POINTER_OFFSET, next);
        Ok(Some(message))
    }

    fn pointer(&self, offset: usize) -> Result<u32, GspQueueError> {
        let pointer = read_le_u32(self.bytes, offset);
        let out_of_range = match usize::try_from(pointer) {
            Ok(value) => value >= NVIDIA_GSP_QUEUE_ENTRY_COUNT,
            Err(_) => true,
        };
        if out_of_range {
            return Err(GspQueueError::PointerOutOfRange {
                pointer,
                count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
            });
        }
        Ok(pointer)
    }
}

fn queue_distance(from: u32, to: u32) -> Result<usize, GspQueueError> {
    let from = usize::try_from(from).map_err(|_| GspQueueError::PointerOutOfRange {
        pointer: from,
        count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
    })?;
    let to = usize::try_from(to).map_err(|_| GspQueueError::PointerOutOfRange {
        pointer: to,
        count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
    })?;
    if from >= NVIDIA_GSP_QUEUE_ENTRY_COUNT {
        return Err(GspQueueError::PointerOutOfRange {
            pointer: from as u32,
            count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
        });
    }
    if to >= NVIDIA_GSP_QUEUE_ENTRY_COUNT {
        return Err(GspQueueError::PointerOutOfRange {
            pointer: to as u32,
            count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
        });
    }
    Ok(if to >= from {
        to - from
    } else {
        NVIDIA_GSP_QUEUE_ENTRY_COUNT - from + to
    })
}

fn queue_advance(pointer: u32, entries: usize) -> Result<u32, GspQueueError> {
    let pointer = usize::try_from(pointer).map_err(|_| GspQueueError::PointerOutOfRange {
        pointer,
        count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
    })?;
    if pointer >= NVIDIA_GSP_QUEUE_ENTRY_COUNT {
        return Err(GspQueueError::PointerOutOfRange {
            pointer: pointer as u32,
            count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
        });
    }
    let next = (pointer + entries) % NVIDIA_GSP_QUEUE_ENTRY_COUNT;
    u32::try_from(next).map_err(|_| GspQueueError::PointerOutOfRange {
        pointer: next as u32,
        count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
    })
}

fn queue_slot_offset(slot: u32) -> Result<usize, GspQueueError> {
    let slot = usize::try_from(slot).map_err(|_| GspQueueError::PointerOutOfRange {
        pointer: slot,
        count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
    })?;
    if slot >= NVIDIA_GSP_QUEUE_ENTRY_COUNT {
        return Err(GspQueueError::PointerOutOfRange {
            pointer: slot as u32,
            count: NVIDIA_GSP_QUEUE_ENTRY_COUNT,
        });
    }
    NVIDIA_GSP_QUEUE_ENTRY_OFFSET
        .checked_add(slot.checked_mul(NVIDIA_GSP_QUEUE_ENTRY_SIZE).ok_or(
            GspQueueError::BufferTooSmall {
                required: usize::MAX,
                actual: NVIDIA_GSP_SHARED_QUEUE_BYTES,
            },
        )?)
        .ok_or(GspQueueError::BufferTooSmall {
            required: usize::MAX,
            actual: NVIDIA_GSP_SHARED_QUEUE_BYTES,
        })
}

fn align_page(value: usize) -> Option<usize> {
    value
        .checked_add(NVIDIA_GSP_PAGE_SIZE - 1)
        .map(|value| value & !(NVIDIA_GSP_PAGE_SIZE - 1))
}

fn align_value(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

fn ceil_div(value: usize, divisor: usize) -> Option<usize> {
    value.checked_add(divisor - 1).map(|value| value / divisor)
}

fn checksum_for_rpc(bytes: &[u8], rpc_length: u32) -> u32 {
    let rpc_length = usize::try_from(rpc_length).unwrap_or(usize::MAX);
    let message_length = NVIDIA_GSP_MESSAGE_HEADER_SIZE.saturating_add(rpc_length);
    let padded_length = message_length.saturating_add(7) & !7;
    checksum_padded(bytes, padded_length)
}

fn checksum_padded(bytes: &[u8], padded_length: usize) -> u32 {
    let mut result = 0u64;
    let mut offset = 0;
    while offset < padded_length {
        let mut word = [0u8; 8];
        for (index, byte) in word.iter_mut().enumerate() {
            *byte = bytes.get(offset + index).copied().unwrap_or(0);
        }
        if offset == 32 {
            word[..4].fill(0);
        }
        result ^= u64::from_le_bytes(word);
        offset += 8;
    }
    (result as u32) ^ (result >> 32) as u32
}

fn read_le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn write_le_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_le_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn validate_page_address(address: u64) -> Result<(), GspMemoryError> {
    if address & (NVIDIA_GSP_PAGE_SIZE as u64 - 1) != 0 {
        return Err(GspMemoryError::AddressUnaligned { address });
    }
    Ok(())
}

fn stage_region(
    next: &mut u64,
    size: usize,
    alignment: u64,
) -> Result<GspMemoryRegion, GspSystemMemoryPlanError> {
    let address =
        align_up_u64(*next, alignment).ok_or(GspSystemMemoryPlanError::AddressOverflow)?;
    let end = address
        .checked_add(u64::try_from(size).map_err(|_| GspSystemMemoryPlanError::SizeOverflow)?)
        .ok_or(GspSystemMemoryPlanError::AddressOverflow)?;
    *next = end;
    Ok(GspMemoryRegion { address, size })
}

fn contiguous_page_addresses(
    region: GspMemoryRegion,
    page_count: usize,
) -> Result<Vec<u64>, GspMemoryError> {
    let required = page_count
        .checked_mul(NVIDIA_GSP_PAGE_SIZE)
        .ok_or(GspMemoryError::AddressOverflow)?;
    if required > region.size {
        return Err(GspMemoryError::BufferTooSmall {
            required,
            actual: region.size,
        });
    }
    validate_page_address(region.address)?;
    let mut addresses = Vec::new();
    addresses.reserve(page_count);
    for index in 0..page_count {
        let offset = index
            .checked_mul(NVIDIA_GSP_PAGE_SIZE)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(GspMemoryError::AddressOverflow)?;
        let address = region
            .address
            .checked_add(offset)
            .ok_or(GspMemoryError::AddressOverflow)?;
        addresses.push(address);
    }
    Ok(addresses)
}

fn copy_bytes_into(
    output: &mut [u8],
    system_base: u64,
    region: GspMemoryRegion,
    bytes: &[u8],
) -> Result<(), GspMaterializationError> {
    let offset = usize::try_from(
        region
            .address
            .checked_sub(system_base)
            .ok_or(GspMaterializationError::LayoutMismatch)?,
    )
    .map_err(|_| GspMaterializationError::LayoutMismatch)?;
    let end = offset
        .checked_add(region.size)
        .ok_or(GspMaterializationError::LayoutMismatch)?;
    let output_len = output.len();
    let target = output
        .get_mut(offset..end)
        .ok_or(GspMaterializationError::BufferTooSmall {
            required: end,
            actual: output_len,
        })?;
    if bytes.len() > target.len() {
        return Err(GspMaterializationError::SectionTooLarge {
            section: bytes.len(),
            region: target.len(),
        });
    }
    target[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

fn copy_section_into(
    output: &mut [u8],
    system_base: u64,
    region: GspMemoryRegion,
    section: FirmwareSection,
    source: &[u8],
) -> Result<(), GspMaterializationError> {
    let end = section.offset.checked_add(section.size).ok_or(
        GspMaterializationError::InvalidSectionRange {
            offset: section.offset,
            size: section.size,
            available: source.len(),
        },
    )?;
    let bytes =
        source
            .get(section.offset..end)
            .ok_or(GspMaterializationError::InvalidSectionRange {
                offset: section.offset,
                size: section.size,
                available: source.len(),
            })?;
    copy_bytes_into(output, system_base, region, bytes)
}

fn align_down_u64(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn align_up_u64(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| align_down_u64(value, alignment))
}

fn ceil_div_u64(value: u64, divisor: u64) -> Option<u64> {
    value.checked_add(divisor - 1).map(|value| value / divisor)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn synthetic_firmware() -> Vec<u8> {
        let string_table = b"\0.fwimage\0.fwversion\0.fwsignature_gb20x\0.shstrtab\0";
        let image_offset = 64usize;
        let image = b"GSP-IMAGE";
        let version_offset = image_offset + image.len();
        let version = b"610.43.03\0";
        let signature_offset = version_offset + version.len();
        let signature = [0xa5u8; 16];
        let string_offset = signature_offset + signature.len();
        let section_offset = string_offset + string_table.len();
        let total = section_offset + 5 * NVIDIA_GSP_ELF_SECTION_HEADER_SIZE;
        let mut bytes = vec![0u8; total];
        bytes[..4].copy_from_slice(&ELF_MAGIC);
        bytes[4] = ELF_CLASS_64;
        bytes[5] = ELF_DATA_LITTLE;
        bytes[6] = ELF_VERSION_CURRENT;
        write_le_u16(&mut bytes, 16, ELF_TYPE_REL);
        write_le_u16(&mut bytes, 18, ELF_MACHINE_RISCV);
        write_le_u64(&mut bytes, 40, section_offset as u64);
        write_le_u16(&mut bytes, 52, 64);
        write_le_u16(&mut bytes, 54, 0);
        write_le_u16(&mut bytes, 56, 0);
        write_le_u16(&mut bytes, 58, NVIDIA_GSP_ELF_SECTION_HEADER_SIZE as u16);
        write_le_u16(&mut bytes, 60, 5);
        write_le_u16(&mut bytes, 62, 4);
        bytes[image_offset..image_offset + image.len()].copy_from_slice(image);
        bytes[version_offset..version_offset + version.len()].copy_from_slice(version);
        bytes[signature_offset..signature_offset + signature.len()].copy_from_slice(&signature);
        bytes[string_offset..string_offset + string_table.len()].copy_from_slice(string_table);
        section(
            &mut bytes,
            section_offset,
            1,
            name_offset(string_table, b".fwimage"),
            ELF_SECTION_PROGBITS,
            image_offset,
            image.len(),
        );
        section(
            &mut bytes,
            section_offset,
            2,
            name_offset(string_table, b".fwversion"),
            ELF_SECTION_PROGBITS,
            version_offset,
            version.len(),
        );
        section(
            &mut bytes,
            section_offset,
            3,
            name_offset(string_table, b".fwsignature_gb20x"),
            ELF_SECTION_PROGBITS,
            signature_offset,
            signature.len(),
        );
        section(
            &mut bytes,
            section_offset,
            4,
            name_offset(string_table, b".shstrtab"),
            ELF_SECTION_STRTAB,
            string_offset,
            string_table.len(),
        );
        bytes
    }

    fn name_offset(table: &[u8], name: &[u8]) -> usize {
        table
            .windows(name.len())
            .position(|candidate| candidate == name)
            .expect("name")
    }

    fn section(
        bytes: &mut [u8],
        table: usize,
        index: usize,
        name: usize,
        kind: u32,
        offset: usize,
        size: usize,
    ) {
        let entry = table + index * NVIDIA_GSP_ELF_SECTION_HEADER_SIZE;
        write_le_u32(bytes, entry, name as u32);
        write_le_u32(bytes, entry + 4, kind);
        write_le_u64(bytes, entry + 24, offset as u64);
        write_le_u64(bytes, entry + 32, size as u64);
    }

    fn write_le_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_le_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parses_sectioned_riscv_gsp_firmware() {
        let bytes = synthetic_firmware();
        let firmware = GspFirmware::parse(&bytes).expect("firmware");
        assert_eq!(firmware.image.bytes(&bytes), b"GSP-IMAGE");
        assert_eq!(firmware.version_bytes(&bytes), b"610.43.03");
        assert!(firmware.supports_gb20x());
        assert_eq!(firmware.section_count, 5);
    }

    #[test]
    fn plans_gb20x_radix3_and_shared_memory_layout() {
        let bytes = synthetic_firmware();
        let firmware = GspFirmware::parse(&bytes).expect("firmware");
        let layout = firmware.boot_layout().expect("boot layout");
        assert_eq!(layout.radix3.image_pages, 1);
        assert_eq!(layout.radix3.level2_bytes, NVIDIA_GSP_PAGE_SIZE);
        assert_eq!(layout.radix3.level2_pages, 1);
        assert_eq!(layout.radix3.total_bytes, 3 * NVIDIA_GSP_PAGE_SIZE);
        assert_eq!(layout.signature_allocation_bytes, 256);
        assert_eq!(layout.shared_memory.page_table_entry_count, 129);
        assert_eq!(layout.shared_memory.page_table_bytes, NVIDIA_GSP_PAGE_SIZE);
        assert_eq!(
            layout.shared_memory.command_queue_offset,
            NVIDIA_GSP_PAGE_SIZE
        );
        assert_eq!(
            layout.shared_memory.status_queue_offset,
            NVIDIA_GSP_PAGE_SIZE + NVIDIA_GSP_SHARED_QUEUE_BYTES
        );
        assert_eq!(layout.shared_memory.total_bytes, 129 * NVIDIA_GSP_PAGE_SIZE);
        assert_eq!(layout.shared_memory.queue_entry_count, 63);
    }

    #[test]
    fn materializes_noncontiguous_radix3_pointer_tables() {
        let layout = GspRadix3Layout {
            image_pages: 2,
            level0_bytes: NVIDIA_GSP_PAGE_SIZE,
            level1_bytes: NVIDIA_GSP_PAGE_SIZE,
            level2_bytes: NVIDIA_GSP_PAGE_SIZE,
            level2_pages: 1,
            total_bytes: 3 * NVIDIA_GSP_PAGE_SIZE,
        };
        let tables = layout
            .materialize(0x1000, 0x5000, &[0x9000], &[0x11_000, 0x23_000])
            .expect("radix-3 tables");
        assert_eq!(read_test_u64(&tables.level0, 0), 0x5000);
        assert_eq!(read_test_u64(&tables.level1, 0), 0x9000);
        assert_eq!(read_test_u64(&tables.level2, 0), 0x11_000);
        assert_eq!(read_test_u64(&tables.level2, 8), 0x23_000);
        assert!(tables.level2[16..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn materializes_shared_memory_page_table_and_command_header() {
        let layout = GspSharedMemoryLayout::standard();
        let pages: Vec<u64> = (0..layout.page_table_entry_count)
            .map(|index| 0x4000_0000 + (index as u64) * NVIDIA_GSP_PAGE_SIZE as u64)
            .collect();
        let shared = layout.materialize(&pages).expect("shared memory");
        assert_eq!(shared.page_table_address, pages[0]);
        assert_eq!(shared.page_table.len(), NVIDIA_GSP_PAGE_SIZE);
        assert_eq!(shared.command_queue.len(), NVIDIA_GSP_SHARED_QUEUE_BYTES);
        assert_eq!(shared.status_queue.len(), NVIDIA_GSP_SHARED_QUEUE_BYTES);
        assert_eq!(read_test_u64(&shared.page_table, 0), pages[0]);
        assert_eq!(
            read_test_u64(&shared.page_table, 128 * core::mem::size_of::<u64>()),
            pages[128]
        );
        let header = GspQueueHeader::r570_command(layout).expect("queue header");
        assert_eq!(
            &shared.command_queue[..NVIDIA_GSP_QUEUE_HEADER_SIZE],
            &header.encode()
        );
        assert!(shared.status_queue.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn encodes_r570_cached_arguments_at_the_openrm_wire_offsets() {
        let layout = GspSharedMemoryLayout::standard();
        let arguments = GspCachedArguments::r570(0x8000, layout)
            .expect("cached arguments")
            .encode();
        assert_eq!(arguments.len(), NVIDIA_GSP_R570_CACHED_ARGUMENTS_SIZE);
        assert_eq!(read_test_u64(&arguments, 0), 0x8000);
        assert_eq!(read_test_u32(&arguments, 8), 129);
        assert_eq!(read_test_u64(&arguments, 16), 4096);
        assert_eq!(
            read_test_u64(&arguments, 24),
            4096 + NVIDIA_GSP_SHARED_QUEUE_BYTES as u64
        );
        assert_eq!(read_test_u32(&arguments, 32), 0);
        assert_eq!(arguments[40], 0);
        assert_eq!(read_test_u32(&arguments, 44), 0);
        assert_eq!(arguments[48], 1);
        assert!(arguments[49..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rejects_unaligned_or_incomplete_gsp_memory_inputs() {
        let layout = GspSharedMemoryLayout::standard();
        assert_eq!(
            layout.materialize(&[0x1001]),
            Err(GspMemoryError::PageCountMismatch {
                expected: 129,
                actual: 1
            })
        );
        assert_eq!(
            GspCachedArguments::r570(0x1001, layout),
            Err(GspMemoryError::AddressUnaligned { address: 0x1001 })
        );

        let mut small_shared_layout = layout;
        small_shared_layout.page_table_bytes = 8;
        let pages = vec![0x2000; layout.page_table_entry_count];
        assert_eq!(
            small_shared_layout.materialize(&pages),
            Err(GspMemoryError::BufferTooSmall {
                required: 129 * core::mem::size_of::<u64>(),
                actual: 8
            })
        );

        let small_radix3 = GspRadix3Layout {
            image_pages: 1,
            level0_bytes: 0,
            level1_bytes: NVIDIA_GSP_PAGE_SIZE,
            level2_bytes: NVIDIA_GSP_PAGE_SIZE,
            level2_pages: 1,
            total_bytes: 2 * NVIDIA_GSP_PAGE_SIZE,
        };
        assert_eq!(
            small_radix3.materialize(0x3000, 0x4000, &[0x5000], &[0x6000]),
            Err(GspMemoryError::BufferTooSmall {
                required: core::mem::size_of::<u64>(),
                actual: 0
            })
        );
    }

    #[test]
    fn boot_layout_requires_the_generation_signature() {
        let mut bytes = synthetic_firmware();
        let signature_name = b".fwsignature_gb20x";
        let name_offset = name_offset(
            b"\0.fwimage\0.fwversion\0.fwsignature_gb20x\0.shstrtab\0",
            signature_name,
        );
        let section_table_offset = read_u64(&bytes, 40).expect("section table") as usize;
        write_le_u32(
            &mut bytes,
            section_table_offset + 3 * NVIDIA_GSP_ELF_SECTION_HEADER_SIZE,
            name_offset as u32 + 1,
        );
        let firmware = GspFirmware::parse(&bytes).expect("firmware");
        assert_eq!(
            firmware.boot_layout(),
            Err(GspBootPlanError::MissingGb20xSignature)
        );
    }

    #[test]
    fn rejects_non_riscv_firmware() {
        let mut bytes = synthetic_firmware();
        write_le_u16(&mut bytes, 18, 0x8664);
        assert_eq!(
            GspFirmware::parse(&bytes),
            Err(GspFirmwareError::UnsupportedMachine { value: 0x8664 })
        );
    }

    #[test]
    fn encodes_exact_r570_system_info_fields() {
        let bytes = GspSystemInfoR570::r570_gb20x(
            0x1234_5678_9abc_def0,
            0x2222_0000,
            0x3333_0000,
            0x0b00,
            0x2f04,
            0x10de,
            0x1234,
            0x5678,
            0xa1,
        )
        .encode();
        assert_eq!(bytes.len(), NVIDIA_GSP_R570_SYSTEM_INFO_SIZE);
        assert_eq!(read_test_u64(&bytes, 0), 0x1234_5678_9abc_def0);
        assert_eq!(read_test_u64(&bytes, 8), 0x2222_0000);
        assert_eq!(read_test_u64(&bytes, 16), 0x3333_0000);
        assert_eq!(read_test_u64(&bytes, 32), 0x0b00);
        assert_eq!(read_test_u64(&bytes, 72), NVIDIA_GSP_R570_MAX_USER_VA);
        assert_eq!(
            read_test_u32(&bytes, 80),
            NVIDIA_GSP_R570_PCI_CONFIG_MIRROR_BASE
        );
        assert_eq!(
            read_test_u32(&bytes, 84),
            NVIDIA_GSP_R570_PCI_CONFIG_MIRROR_SIZE
        );
        assert_eq!(read_test_u32(&bytes, 88), 0x2f04_10de);
        assert_eq!(read_test_u32(&bytes, 92), 0x1234_5678);
        assert_eq!(read_test_u32(&bytes, 96), 0xa1);
        assert_eq!(read_test_u32(&bytes, 120), NVIDIA_GSP_R570_CHIPSET_GB205);
        assert!(bytes[128..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn encodes_linux_r570_registry_table_layout() {
        let bytes = encode_gsp_registry();
        assert_eq!(bytes.len(), 117);
        assert_eq!(read_test_u32(&bytes, 0), 109);
        assert_eq!(read_test_u32(&bytes, 4), 3);
        assert_eq!(read_test_u32(&bytes, 8), 56);
        assert_eq!(bytes[12], NVIDIA_GSP_REGISTRY_DWORD);
        assert_eq!(read_test_u32(&bytes, 16), 1);
        assert_eq!(read_test_u32(&bytes, 24), 76);
        assert_eq!(read_test_u32(&bytes, 40), 98);
        assert_eq!(&bytes[56..76], b"RMSecBusResetEnable\0");
        assert_eq!(&bytes[76..98], b"RMForcePcieConfigSave\0");
        assert_eq!(&bytes[98..117], b"RMDevidCheckIgnore\0");
    }

    #[test]
    fn parses_r570_static_info_gpu_name_at_wire_offset() {
        let mut payload = encode_gsp_static_info_request().to_vec();
        payload[NVIDIA_GSP_R570_STATIC_GPU_NAME_OFFSET..][..13].copy_from_slice(b"NVIDIA GB205\0");
        let info = parse_gsp_static_info(&payload).expect("static info");
        assert_eq!(&info.gpu_name[..13], b"NVIDIA GB205\0");
        assert_eq!(
            parse_gsp_static_info(&payload[..NVIDIA_GSP_R570_STATIC_CONFIG_INFO_SIZE - 1]),
            Err(GspStaticInfoError::PayloadTooSmall {
                required: NVIDIA_GSP_R570_STATIC_CONFIG_INFO_SIZE,
                actual: NVIDIA_GSP_R570_STATIC_CONFIG_INFO_SIZE - 1,
            })
        );
        payload
            [NVIDIA_GSP_R570_STATIC_GPU_NAME_OFFSET..NVIDIA_GSP_R570_STATIC_GPU_NAME_OFFSET + 64]
            .fill(0);
        assert_eq!(
            parse_gsp_static_info(&payload),
            Err(GspStaticInfoError::GpuNameEmpty)
        );
        payload
            [NVIDIA_GSP_R570_STATIC_GPU_NAME_OFFSET..NVIDIA_GSP_R570_STATIC_GPU_NAME_OFFSET + 64]
            .fill(b'X');
        assert_eq!(
            parse_gsp_static_info(&payload),
            Err(GspStaticInfoError::GpuNameNotTerminated)
        );
    }

    #[test]
    fn encodes_page_aligned_rpc_with_valid_checksum() {
        let message = encode_gsp_rpc(0x1234, 7, b"hello").expect("rpc");
        let message = GspRpcMessage::parse(&message).expect("message");
        assert_eq!(message.bytes().len(), NVIDIA_GSP_PAGE_SIZE);
        assert_eq!(message.sequence(), 7);
        assert_eq!(message.transport_sequence(), 7);
        assert_eq!(message.rpc_sequence(), 0);
        assert_eq!(message.element_count(), 1);
        assert_eq!(message.function(), 0x1234);
        assert_eq!(message.payload(), b"hello");
        assert!(message.checksum_valid());
    }

    #[test]
    fn encodes_distinct_transport_and_rpc_sequences() {
        let bytes = encode_gsp_rpc_with_sequences(65, 11, 0, b"static-info").expect("rpc");
        let message = GspRpcMessage::parse(&bytes).expect("message");
        assert_eq!(message.transport_sequence(), 11);
        assert_eq!(message.rpc_sequence(), 0);
        assert_eq!(message.function(), NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO);
    }

    #[test]
    fn enqueues_and_receives_wrapped_r570_queue_elements() {
        let mut message = encode_gsp_rpc_with_sequences(
            NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO,
            3,
            3,
            b"static-info",
        )
        .expect("rpc");
        message[NVIDIA_GSP_PAGE_SIZE - 1] = 0xa5;
        let mut command_queue = vec![0u8; NVIDIA_GSP_SHARED_QUEUE_BYTES];
        let mut command = GspQueue::new(&mut command_queue).expect("command queue");
        assert_eq!(command.available_entries().expect("capacity"), 62);
        assert_eq!(command.write_message(&message).expect("enqueue"), 1);
        assert_eq!(command.write_pointer().expect("write pointer"), 1);
        drop(command);
        let command_message_offset = queue_slot_offset(0).expect("slot");
        assert_eq!(
            GspRpcMessage::parse(
                &command_queue
                    [command_message_offset..command_message_offset + NVIDIA_GSP_PAGE_SIZE]
            )
            .expect("queued message")
            .function(),
            NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO
        );

        let mut status_queue = vec![0u8; NVIDIA_GSP_SHARED_QUEUE_BYTES];
        let wrapped_slot =
            queue_slot_offset((NVIDIA_GSP_QUEUE_ENTRY_COUNT - 1) as u32).expect("wrapped slot");
        status_queue[wrapped_slot..wrapped_slot + NVIDIA_GSP_PAGE_SIZE].copy_from_slice(&message);
        write_le_u32(
            &mut status_queue,
            NVIDIA_GSP_QUEUE_TX_WRITE_POINTER_OFFSET,
            0,
        );
        write_le_u32(
            &mut status_queue,
            NVIDIA_GSP_QUEUE_RX_READ_POINTER_OFFSET,
            62,
        );
        let mut status = GspQueue::new(&mut status_queue).expect("status queue");
        let received = status
            .try_receive_message()
            .expect("receive")
            .expect("message available");
        let received = GspRpcMessage::parse(&received).expect("received message");
        assert_eq!(received.function(), NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO);
        assert_eq!(received.transport_sequence(), 3);
        assert_eq!(status.read_pointer().expect("read pointer"), 0);
    }

    #[test]
    fn rejects_an_rpc_payload_that_exceeds_sixteen_pages() {
        let payload = vec![0u8; NVIDIA_GSP_MAX_MESSAGE_PAGES * NVIDIA_GSP_PAGE_SIZE];
        assert!(matches!(
            encode_gsp_rpc(1, 0, &payload),
            Err(GspRpcError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_a_message_that_exceeds_the_queue_element_limit() {
        let pages = NVIDIA_GSP_MAX_MESSAGE_PAGES + 1;
        let bytes = vec![0u8; pages * NVIDIA_GSP_PAGE_SIZE];
        assert!(matches!(
            GspRpcMessage::parse(&bytes),
            Err(GspRpcError::MessageTooLarge {
                pages: actual_pages,
                limit: NVIDIA_GSP_MAX_MESSAGE_PAGES
            }) if actual_pages == pages
        ));
    }

    #[test]
    fn plans_r570_system_memory_and_materializes_boot_inputs() {
        let bytes = synthetic_firmware();
        let firmware = GspFirmware::parse(&bytes).expect("firmware");
        let layout = firmware.boot_layout().expect("boot layout");
        let plan = GspBootSystemMemoryPlan::r570_from_layout(layout, 0x20_000, 0x3000, 0x1000_0000)
            .expect("system-memory plan");
        let regions = [
            plan.fmc_image,
            plan.gsp_image,
            plan.radix3_level0,
            plan.radix3_level1,
            plan.radix3_level2,
            plan.signature,
            plan.bootloader,
            plan.wpr_meta,
            plan.fmc_args,
            plan.libos_args,
            plan.loginit,
            plan.logintr,
            plan.logrm,
            plan.shared_memory,
            plan.rm_args,
        ];
        for pair in regions.windows(2) {
            assert!(pair[0].end().expect("region end") <= pair[1].address);
        }
        assert_eq!(plan.total_bytes, (plan.end_address - 0x1000_0000) as usize);

        let radix3 = plan.radix3_tables().expect("radix-3 tables");
        assert_eq!(read_test_u64(&radix3.level0, 0), plan.radix3_level1.address);
        assert_eq!(read_test_u64(&radix3.level2, 0), plan.gsp_image.address);
        let shared = plan.shared_memory_image().expect("shared memory");
        assert_eq!(shared.page_table_address, plan.shared_memory.address);
        let cached_arguments = plan.cached_arguments().expect("cached arguments");
        assert_eq!(
            read_test_u64(&cached_arguments, 0),
            plan.shared_memory.address
        );

        let framebuffer = GspFramebufferLayout::r570_gb20x(
            16 * (1u64 << 30),
            16 * (1u64 << 30) - 0x20_000,
            plan.gsp_image_bytes,
            plan.bootloader_bytes,
        )
        .expect("framebuffer layout");
        assert_eq!(
            framebuffer.non_wpr_heap_address + framebuffer.non_wpr_heap_size,
            framebuffer.wpr_start
        );
        assert_eq!(
            framebuffer.wpr_end,
            framebuffer.frts_address + framebuffer.frts_size
        );
        assert_eq!(
            framebuffer.frts_vidmem_offset().expect("FRTS COT offset"),
            framebuffer.framebuffer_size - framebuffer.frts_address
        );
        let meta = plan.wpr_meta(framebuffer).expect("WPR metadata");
        assert_eq!(
            read_test_u64(&meta.encode(), 16),
            plan.radix3_level0.address
        );
        let fmc_args = plan.fmc_boot_params();
        assert_eq!(read_test_u64(&fmc_args, 16), plan.wpr_meta.address);
        assert_eq!(read_test_u64(&fmc_args, 48), plan.libos_args.address);
    }

    #[test]
    fn materializes_r570_bundle_into_linked_system_image() {
        let gsp_bytes = synthetic_firmware();
        let gsp = GspFirmware::parse(&gsp_bytes).expect("firmware");
        let fmc_bytes = (0u8..16).collect::<Vec<_>>();
        let fmc = GspFmc {
            hash: FirmwareSection { offset: 0, size: 4 },
            signature: FirmwareSection { offset: 4, size: 4 },
            public_key: FirmwareSection { offset: 8, size: 4 },
            image: FirmwareSection {
                offset: 12,
                size: 4,
            },
            section_count: 6,
        };
        let bootloader_bytes = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let bootloader = GspBootloader {
            bin_size: bootloader_bytes.len(),
            header_offset: 0,
            data_offset: 2,
            data_size: 4,
            payload: FirmwareSection { offset: 2, size: 4 },
            descriptor: GspRmUcodeDescriptor {
                version: 5,
                bootloader_offset: 0,
                bootloader_size: 0,
                bootloader_param_offset: 0,
                bootloader_param_size: 0,
                riscv_elf_offset: 0,
                riscv_elf_size: 0,
                app_version: 0x55,
                manifest_offset: 0,
                manifest_size: 0,
                monitor_data_offset: 2,
                monitor_data_size: 1,
                monitor_code_offset: 1,
                monitor_code_size: 1,
                monitor_enabled: 0,
                swbrom_code_offset: 0,
                swbrom_code_size: 0,
                swbrom_data_offset: 0,
                swbrom_data_size: 0,
                framebuffer_reserved_size: 0,
                signed_as_code: 0,
            },
        };
        let bundle = GspFirmwareBundle {
            gsp,
            fmc,
            bootloader,
        };
        let plan =
            GspBootSystemMemoryPlan::r570_gb20x(bundle, 0x1000_0000).expect("system-memory plan");
        let framebuffer = GspFramebufferLayout::r570_gb20x(
            16 * (1u64 << 30),
            16 * (1u64 << 30) - 0x20_000,
            plan.gsp_image_bytes,
            plan.bootloader_bytes,
        )
        .expect("framebuffer layout");
        let mut output = vec![0u8; plan.total_bytes];
        plan.materialize_bundle_into(
            bundle,
            &gsp_bytes,
            &fmc_bytes,
            &bootloader_bytes,
            framebuffer,
            &mut output,
        )
        .expect("materialized system image");

        let offset = |region: GspMemoryRegion| (region.address - plan.system_base) as usize;
        let fmc_offset = offset(plan.fmc_image);
        assert_eq!(&output[fmc_offset..fmc_offset + 4], &fmc_bytes[12..16]);
        let gsp_offset = offset(plan.gsp_image);
        assert_eq!(
            &output[gsp_offset..gsp_offset + gsp.image.size],
            &gsp_bytes[gsp.image.offset..gsp.image.offset + gsp.image.size]
        );
        assert!(
            output[gsp_offset + gsp.image.size..gsp_offset + plan.gsp_image.size]
                .iter()
                .all(|byte| *byte == 0)
        );
        let signature_offset = offset(plan.signature);
        assert_eq!(
            &output[signature_offset..signature_offset + gsp.gb20x_signature.unwrap().size],
            &gsp_bytes[gsp.gb20x_signature.unwrap().offset
                ..gsp.gb20x_signature.unwrap().offset + gsp.gb20x_signature.unwrap().size]
        );
        let bootloader_offset = offset(plan.bootloader);
        assert_eq!(
            &output[bootloader_offset..bootloader_offset + 4],
            &bootloader_bytes[2..6]
        );

        let radix3_level0_offset = offset(plan.radix3_level0);
        assert_eq!(
            read_test_u64(&output[radix3_level0_offset..], 0),
            plan.radix3_level1.address
        );
        let shared_offset = offset(plan.shared_memory);
        assert_eq!(
            read_test_u64(&output[shared_offset..], 0),
            plan.shared_memory.address
        );
        let rm_args_offset = offset(plan.rm_args);
        assert_eq!(
            read_test_u64(&output[rm_args_offset..], 0),
            plan.shared_memory.address
        );
        let wpr_meta_offset = offset(plan.wpr_meta);
        assert_eq!(
            read_test_u64(&output[wpr_meta_offset..], 16),
            plan.radix3_level0.address
        );
        let fmc_args_offset = offset(plan.fmc_args);
        assert_eq!(
            read_test_u64(&output[fmc_args_offset..], 16),
            plan.wpr_meta.address
        );

        let mut small_output = vec![0u8; plan.total_bytes - 1];
        assert_eq!(
            plan.materialize_bundle_into(
                bundle,
                &gsp_bytes,
                &fmc_bytes,
                &bootloader_bytes,
                framebuffer,
                &mut small_output,
            ),
            Err(GspMaterializationError::BufferTooSmall {
                required: plan.total_bytes,
                actual: plan.total_bytes - 1,
            })
        );
    }

    #[test]
    fn rejects_unaligned_system_memory_base() {
        let bytes = synthetic_firmware();
        let layout = GspFirmware::parse(&bytes)
            .expect("firmware")
            .boot_layout()
            .expect("boot layout");
        assert_eq!(
            GspBootSystemMemoryPlan::r570_from_layout(layout, 1, 1, 0x1001),
            Err(GspSystemMemoryPlanError::BaseUnaligned { address: 0x1001 })
        );
    }

    #[test]
    fn rejects_framebuffer_that_cannot_fit_the_gb20x_wpr() {
        assert!(matches!(
            GspFramebufferLayout::r570_gb20x(
                32 * 1024 * 1024,
                31 * 1024 * 1024,
                64 * 1024 * 1024,
                64 * 1024
            ),
            Err(GspFramebufferLayoutError::AddressUnderflow)
                | Err(GspFramebufferLayoutError::TooSmall { .. })
        ));
    }

    fn read_test_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32"))
    }

    fn read_test_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64"))
    }
}
