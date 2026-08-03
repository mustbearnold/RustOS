#![no_std]

extern crate alloc;

mod boot;
mod fmc;
mod fsp;

pub use boot::{
    GspBootloader, GspBootloaderError, GspFirmwareBundle, GspFirmwareBundleError, GspFmcBootParams,
    GspRmDescriptorField, GspRmUcodeDescriptor, GspWprMeta,
};
pub use fmc::{GspFmc, GspFmcError, GspFmcRequiredSection};
pub use fsp::{
    GspFspCot, GspFspCotError, NVIDIA_GSP_FSP_BAR0_REQUIRED_LENGTH, NVIDIA_GSP_FSP_COT_HASH_BYTES,
    NVIDIA_GSP_FSP_COT_PACKET_SIZE, NVIDIA_GSP_FSP_COT_PAYLOAD_SIZE,
    NVIDIA_GSP_FSP_COT_PUBLIC_KEY_BYTES, NVIDIA_GSP_FSP_COT_PUBLIC_KEY_SLOT_BYTES,
    NVIDIA_GSP_FSP_COT_SIGNATURE_BYTES, NVIDIA_GSP_FSP_COT_SIGNATURE_SLOT_BYTES,
    NVIDIA_GSP_FSP_COT_VERSION_GB20X, NVIDIA_GSP_FSP_EMEM_PIO_ADDRESS,
    NVIDIA_GSP_FSP_EMEM_PIO_DATA, NVIDIA_GSP_FSP_FALCON_BASE, NVIDIA_GSP_FSP_FALCON_HWCFG2,
    NVIDIA_GSP_FSP_FALCON_HWCFG2_LOCKDOWN_BIT, NVIDIA_GSP_FSP_FALCON_MAILBOX0,
    NVIDIA_GSP_FSP_FALCON_MAILBOX1, NVIDIA_GSP_FSP_MSGQ_HEAD, NVIDIA_GSP_FSP_MSGQ_TAIL,
    NVIDIA_GSP_FSP_QUEUE_HEAD, NVIDIA_GSP_FSP_QUEUE_TAIL,
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
pub const NVIDIA_GSP_SHARED_PAGE_TABLE_ENTRY_SIZE: usize = core::mem::size_of::<u64>();
pub const NVIDIA_GSP_RADIX3_POINTERS_PER_PAGE: usize = NVIDIA_GSP_PAGE_SIZE / 8;
pub const NVIDIA_GSP_RADIX3_MAX_IMAGE_PAGES: usize =
    NVIDIA_GSP_RADIX3_POINTERS_PER_PAGE * NVIDIA_GSP_RADIX3_POINTERS_PER_PAGE;
pub const NVIDIA_GSP_WPR_ALIGNMENT: usize = 128 * 1024;
pub const NVIDIA_GSP_R570_BAREMETAL_OS_CARVEOUT: usize = 22 * 1024 * 1024;
pub const NVIDIA_GSP_R570_BASE_RM_HEAP: usize = 14 * 1024 * 1024;
pub const NVIDIA_GSP_R570_MIN_RM_HEAP: usize = 88 * 1024 * 1024;
pub const NVIDIA_GSP_R570_GB20X_NON_WPR_HEAP: usize = 0x220000;
pub const NVIDIA_GSP_R570_CACHED_ARGUMENTS_SIZE: usize = 72;
pub const NVIDIA_GSP_R570_QUEUE_RX_HEADER_OFFSET: u32 = 32;
pub const NVIDIA_GSP_RPC_SIGNATURE: u32 = 0x4352_5056;
pub const NVIDIA_GSP_RPC_HEADER_VERSION: u32 = 0x0300_0000;
pub const NVIDIA_GSP_CONTINUATION_FUNCTION: u32 = 0x0000_0014;

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
        Ok(Self { bytes })
    }

    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    pub fn sequence(self) -> u32 {
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
        checksum(self.bytes) == self.checksum()
    }
}

pub fn encode_gsp_rpc(
    function: u32,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, GspRpcError> {
    let rpc_length = NVIDIA_GSP_RPC_HEADER_SIZE
        .checked_add(payload.len())
        .ok_or(GspRpcError::SizeOverflow)?;
    let aligned_rpc_length = align8(rpc_length).ok_or(GspRpcError::SizeOverflow)?;
    let maximum_rpc_length = NVIDIA_GSP_MAX_MESSAGE_PAGES
        .checked_mul(NVIDIA_GSP_PAGE_SIZE)
        .and_then(|size| size.checked_sub(NVIDIA_GSP_MESSAGE_HEADER_SIZE))
        .and_then(|size| size.checked_sub(NVIDIA_GSP_RPC_HEADER_SIZE))
        .ok_or(GspRpcError::SizeOverflow)?;
    if aligned_rpc_length > maximum_rpc_length {
        return Err(GspRpcError::PayloadTooLarge {
            size: payload.len(),
            limit: maximum_rpc_length - NVIDIA_GSP_RPC_HEADER_SIZE,
        });
    }
    let total_length = align_page(
        NVIDIA_GSP_MESSAGE_HEADER_SIZE
            .checked_add(aligned_rpc_length)
            .ok_or(GspRpcError::SizeOverflow)?,
    )
    .ok_or(GspRpcError::SizeOverflow)?;
    let mut bytes = Vec::new();
    bytes.resize(total_length, 0);
    write_le_u32(&mut bytes, 36, sequence);
    write_le_u32(
        &mut bytes,
        40,
        u32::try_from(total_length / NVIDIA_GSP_PAGE_SIZE).unwrap_or(u32::MAX),
    );
    let rpc_offset = NVIDIA_GSP_MESSAGE_HEADER_SIZE;
    write_le_u32(&mut bytes, rpc_offset, NVIDIA_GSP_RPC_HEADER_VERSION);
    write_le_u32(&mut bytes, rpc_offset + 4, NVIDIA_GSP_RPC_SIGNATURE);
    write_le_u32(
        &mut bytes,
        rpc_offset + 8,
        u32::try_from(aligned_rpc_length).unwrap_or(u32::MAX),
    );
    write_le_u32(&mut bytes, rpc_offset + 12, function);
    write_le_u32(&mut bytes, rpc_offset + 16, u32::MAX);
    write_le_u32(&mut bytes, rpc_offset + 20, u32::MAX);
    write_le_u32(&mut bytes, rpc_offset + 24, sequence);
    let payload_offset = rpc_offset + NVIDIA_GSP_RPC_HEADER_SIZE;
    bytes[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    let message_checksum = checksum(&bytes);
    write_le_u32(&mut bytes, 32, message_checksum);
    Ok(bytes)
}

fn align8(value: usize) -> Option<usize> {
    value.checked_add(7).map(|value| value & !7)
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

fn checksum(bytes: &[u8]) -> u32 {
    let mut result = 0u64;
    let mut offset = 0;
    while offset < bytes.len() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[offset..offset + 8]);
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
    fn encodes_page_aligned_rpc_with_valid_checksum() {
        let message = encode_gsp_rpc(0x1234, 7, b"hello").expect("rpc");
        let message = GspRpcMessage::parse(&message).expect("message");
        assert_eq!(message.bytes().len(), NVIDIA_GSP_PAGE_SIZE);
        assert_eq!(message.sequence(), 7);
        assert_eq!(message.element_count(), 1);
        assert_eq!(message.function(), 0x1234);
        assert_eq!(&message.payload()[..5], b"hello");
        assert!(message.payload()[5..].iter().all(|byte| *byte == 0));
        assert!(message.checksum_valid());
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

    fn read_test_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32"))
    }

    fn read_test_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64"))
    }
}
