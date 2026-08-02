pub const SECTOR_SIZE: usize = 512;
pub const ATA_MAX_LBA28: u64 = (1 << 28) - 1;
pub const ATA_MAX_LBA48: u64 = (1 << 48) - 1;
pub const ATA_PRIMARY_IRQ: u8 = 14;
pub const GPT_HEADER_LBA: u64 = 1;
pub const GPT_SIGNATURE: [u8; 8] = *b"EFI PART";
pub const PERSISTENT_STATE_PATH: &[u8] = b"/RUSTOS.ST";
pub const PERSISTENT_STATE_INITIAL: [u8; 7] = *b"boot=0\n";
pub const PERSISTENT_STATE_UPDATED: [u8; 7] = *b"boot=1\n";
pub const PERSISTENT_STATE_LENGTH: usize = PERSISTENT_STATE_INITIAL.len();

#[cfg(target_os = "none")]
use spin::{Mutex, Once};

#[cfg(target_os = "none")]
static RUNTIME_FILESYSTEM: Once<Mutex<FatFileSystem<StorageDisk>>> = Once::new();

const ATA_LBA28_CAPABILITY: u16 = 1 << 9;
const ATA_LBA48_CAPABILITY: u16 = 1 << 10;
const MBR_PARTITION_TABLE_OFFSET: usize = 446;
const MBR_PARTITION_ENTRY_SIZE: usize = 16;
const MBR_SIGNATURE: u16 = 0xaa55;
const GPT_HEADER_SIZE_MIN: u32 = 92;
const GPT_PARTITION_ENTRY_SIZE_MIN: u32 = 128;
const GPT_MAX_PARTITION_ENTRIES: u32 = 1024;
const GPT_MAX_PARTITION_ARRAY_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaIdentifyError {
    Lba28Unsupported,
    ZeroCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtaIdentify {
    pub lba28_sectors: u64,
}

pub fn parse_identify(words: &[u16; 256]) -> Result<AtaIdentify, AtaIdentifyError> {
    if words[49] & ATA_LBA28_CAPABILITY == 0 {
        return Err(AtaIdentifyError::Lba28Unsupported);
    }

    let lba28_sectors = u64::from(words[60]) | (u64::from(words[61]) << 16);
    if lba28_sectors == 0 {
        return Err(AtaIdentifyError::ZeroCapacity);
    }

    Ok(AtaIdentify { lba28_sectors })
}

/// Return the largest sector address advertised by an ATA IDENTIFY response.
///
/// Modern disks normally expose the 48-bit capacity in words 100..103. Older devices can still
/// be addressed through the 28-bit words 60..61, so the parser keeps that fallback for the PIO
/// transport and for small AHCI test disks.
pub fn parse_identify_capacity(words: &[u16; 256]) -> Result<u64, AtaIdentifyError> {
    if words[83] & ATA_LBA48_CAPABILITY != 0 {
        let lba48_sectors = u64::from(words[100])
            | (u64::from(words[101]) << 16)
            | (u64::from(words[102]) << 32)
            | (u64::from(words[103]) << 48);
        if lba48_sectors != 0 {
            return Ok(lba48_sectors);
        }
    }
    parse_identify(words).map(|identify| identify.lba28_sectors)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockDeviceError {
    NoDevice,
    Timeout { status: u8 },
    DeviceFault { status: u8, error: u8 },
    Identify(AtaIdentifyError),
    InvalidBufferLength { expected: usize, actual: usize },
    LbaOutOfRange { lba: u64, capacity: u64 },
    Lba28AddressOutOfRange { lba: u64 },
    Lba48AddressOutOfRange { lba: u64 },
    Ahci { kind: u8, value: u64 },
    Nvme { kind: u8, value: u64 },
}

pub fn validate_lba28(lba: u64, capacity: u64) -> Result<(), BlockDeviceError> {
    if lba > ATA_MAX_LBA28 {
        return Err(BlockDeviceError::Lba28AddressOutOfRange { lba });
    }
    if lba >= capacity {
        return Err(BlockDeviceError::LbaOutOfRange { lba, capacity });
    }
    Ok(())
}

pub fn validate_lba48(lba: u64, capacity: u64) -> Result<(), BlockDeviceError> {
    if lba > ATA_MAX_LBA48 {
        return Err(BlockDeviceError::Lba48AddressOutOfRange { lba });
    }
    if lba >= capacity {
        return Err(BlockDeviceError::LbaOutOfRange { lba, capacity });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionExtent {
    pub first_lba: u64,
    pub sector_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionError {
    SectorTooShort {
        length: usize,
    },
    InvalidMbrSignature {
        signature: u16,
    },
    InvalidMbrEntry {
        index: usize,
    },
    InvalidGptSignature,
    InvalidGptRevision {
        revision: u32,
    },
    InvalidGptHeaderSize {
        size: u32,
    },
    InvalidGptHeaderCrc {
        expected: u32,
        actual: u32,
    },
    InvalidGptLbaRange,
    InvalidGptPartitionEntrySize {
        size: u32,
    },
    GptPartitionArrayTooLarge {
        bytes: u64,
    },
    GptPartitionArrayTooShort {
        expected: usize,
        available: usize,
    },
    InvalidGptPartitionArrayCrc {
        expected: u32,
        actual: u32,
    },
    InvalidGptPartitionEntry {
        index: u32,
    },
    InvalidPartitionRange {
        first_lba: u64,
        sector_count: u64,
    },
    PartitionOutOfRange {
        first_lba: u64,
        sector_count: u64,
        capacity: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartition {
    pub bootable: bool,
    pub partition_type: u8,
    pub start_lba: u64,
    pub sector_count: u64,
}

impl MbrPartition {
    pub fn extent(self) -> PartitionExtent {
        PartitionExtent {
            first_lba: self.start_lba,
            sector_count: self.sector_count,
        }
    }

    pub fn is_fat(self) -> bool {
        matches!(
            self.partition_type,
            0x01 | 0x04 | 0x06 | 0x0b | 0x0c | 0x0e | 0x1b | 0x1c
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartitionTable {
    pub entries: [Option<MbrPartition>; 4],
}

impl MbrPartitionTable {
    pub fn has_protective_gpt(self) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|entry| entry.partition_type == 0xee)
    }

    pub fn first_fat_partition(self) -> Option<MbrPartition> {
        self.entries
            .iter()
            .flatten()
            .copied()
            .find(|entry| entry.is_fat())
    }
}

pub fn parse_mbr(sector: &[u8]) -> Result<MbrPartitionTable, PartitionError> {
    if sector.len() < SECTOR_SIZE {
        return Err(PartitionError::SectorTooShort {
            length: sector.len(),
        });
    }
    let signature = u16::from_le_bytes([sector[510], sector[511]]);
    if signature != MBR_SIGNATURE {
        return Err(PartitionError::InvalidMbrSignature { signature });
    }

    let mut entries = [None; 4];
    for (index, entry) in entries.iter_mut().enumerate() {
        let offset = MBR_PARTITION_TABLE_OFFSET + index * MBR_PARTITION_ENTRY_SIZE;
        let boot_indicator = sector[offset];
        let partition_type = sector[offset + 4];
        let start_lba = u64::from(read_u32(sector, offset + 8));
        let sector_count = u64::from(read_u32(sector, offset + 12));
        if boot_indicator == 0 && partition_type == 0 && start_lba == 0 && sector_count == 0 {
            continue;
        }
        if !matches!(boot_indicator, 0 | 0x80)
            || partition_type == 0
            || sector_count == 0
            || start_lba.checked_add(sector_count).is_none()
        {
            return Err(PartitionError::InvalidMbrEntry { index });
        }
        *entry = Some(MbrPartition {
            bootable: boot_indicator == 0x80,
            partition_type,
            start_lba,
            sector_count,
        });
    }
    Ok(MbrPartitionTable { entries })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptHeader {
    pub revision: u32,
    pub header_size: u32,
    pub current_lba: u64,
    pub backup_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub partition_entry_count: u32,
    pub partition_entry_size: u32,
    pub partition_array_crc32: u32,
}

impl GptHeader {
    pub fn partition_array_bytes(self) -> u64 {
        u64::from(self.partition_entry_count) * u64::from(self.partition_entry_size)
    }

    pub fn partition_array_sectors(self) -> u64 {
        self.partition_array_bytes().div_ceil(SECTOR_SIZE as u64)
    }
}

pub fn parse_gpt_header(sector: &[u8]) -> Result<GptHeader, PartitionError> {
    if sector.len() < SECTOR_SIZE {
        return Err(PartitionError::SectorTooShort {
            length: sector.len(),
        });
    }
    if sector[..GPT_SIGNATURE.len()] != GPT_SIGNATURE {
        return Err(PartitionError::InvalidGptSignature);
    }

    let revision = read_u32(sector, 8);
    if revision != 0x0001_0000 {
        return Err(PartitionError::InvalidGptRevision { revision });
    }
    let header_size = read_u32(sector, 12);
    if !(GPT_HEADER_SIZE_MIN..=SECTOR_SIZE as u32).contains(&header_size) || header_size % 4 != 0 {
        return Err(PartitionError::InvalidGptHeaderSize { size: header_size });
    }

    let expected_crc = read_u32(sector, 16);
    let actual_crc = crc32_with_zeroed_range(&sector[..header_size as usize], 16..20);
    if expected_crc != actual_crc {
        return Err(PartitionError::InvalidGptHeaderCrc {
            expected: expected_crc,
            actual: actual_crc,
        });
    }

    let current_lba = read_u64(sector, 24);
    let backup_lba = read_u64(sector, 32);
    let first_usable_lba = read_u64(sector, 40);
    let last_usable_lba = read_u64(sector, 48);
    let partition_entry_lba = read_u64(sector, 72);
    let partition_entry_count = read_u32(sector, 80);
    let partition_entry_size = read_u32(sector, 84);
    let partition_array_crc32 = read_u32(sector, 88);
    if backup_lba == current_lba
        || first_usable_lba > last_usable_lba
        || partition_entry_lba == 0
        || partition_entry_count == 0
        || partition_entry_count > GPT_MAX_PARTITION_ENTRIES
    {
        return Err(PartitionError::InvalidGptLbaRange);
    }
    if partition_entry_size < GPT_PARTITION_ENTRY_SIZE_MIN || partition_entry_size % 8 != 0 {
        return Err(PartitionError::InvalidGptPartitionEntrySize {
            size: partition_entry_size,
        });
    }
    let partition_array_bytes = u64::from(partition_entry_count)
        .checked_mul(u64::from(partition_entry_size))
        .ok_or(PartitionError::GptPartitionArrayTooLarge { bytes: u64::MAX })?;
    if partition_array_bytes > GPT_MAX_PARTITION_ARRAY_BYTES {
        return Err(PartitionError::GptPartitionArrayTooLarge {
            bytes: partition_array_bytes,
        });
    }
    let partition_array_sectors = partition_array_bytes.div_ceil(SECTOR_SIZE as u64);
    if partition_entry_lba
        .checked_add(partition_array_sectors)
        .is_none()
    {
        return Err(PartitionError::InvalidGptLbaRange);
    }

    Ok(GptHeader {
        revision,
        header_size,
        current_lba,
        backup_lba,
        first_usable_lba,
        last_usable_lba,
        disk_guid: sector[56..72]
            .try_into()
            .expect("GPT disk GUID is 16 bytes"),
        partition_entry_lba,
        partition_entry_count,
        partition_entry_size,
        partition_array_crc32,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptPartition {
    pub type_guid: [u8; 16],
    pub partition_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    pub name: [u16; 36],
}

impl GptPartition {
    pub fn extent(self) -> PartitionExtent {
        PartitionExtent {
            first_lba: self.first_lba,
            sector_count: self.last_lba - self.first_lba + 1,
        }
    }
}

#[allow(dead_code)]
pub fn first_gpt_partition(
    partition_array: &[u8],
    header: &GptHeader,
) -> Result<Option<GptPartition>, PartitionError> {
    Ok(gpt_partitions(partition_array, header)?.into_iter().next())
}

/// Parse all non-empty entries from a CRC-checked GPT partition array.
pub fn gpt_partitions(
    partition_array: &[u8],
    header: &GptHeader,
) -> Result<Vec<GptPartition>, PartitionError> {
    let expected_bytes = header.partition_array_bytes() as usize;
    if partition_array.len() < expected_bytes {
        return Err(PartitionError::GptPartitionArrayTooShort {
            expected: expected_bytes,
            available: partition_array.len(),
        });
    }
    let actual_crc = crc32(&partition_array[..expected_bytes]);
    if actual_crc != header.partition_array_crc32 {
        return Err(PartitionError::InvalidGptPartitionArrayCrc {
            expected: header.partition_array_crc32,
            actual: actual_crc,
        });
    }

    let entry_size = header.partition_entry_size as usize;
    let mut partitions = Vec::new();
    for index in 0..header.partition_entry_count {
        let offset = index as usize * entry_size;
        let entry =
            parse_gpt_partition_entry(&partition_array[offset..offset + entry_size], index)?;
        if let Some(entry) = entry {
            partitions.push(entry);
        }
    }
    Ok(partitions)
}

pub fn parse_gpt_partition_entry(
    entry: &[u8],
    index: u32,
) -> Result<Option<GptPartition>, PartitionError> {
    if entry.len() < GPT_PARTITION_ENTRY_SIZE_MIN as usize {
        return Err(PartitionError::InvalidGptPartitionEntry { index });
    }
    let type_guid: [u8; 16] = entry[..16].try_into().expect("GPT type GUID is 16 bytes");
    if type_guid.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    let first_lba = read_u64(entry, 32);
    let last_lba = read_u64(entry, 40);
    if first_lba > last_lba {
        return Err(PartitionError::InvalidPartitionRange {
            first_lba,
            sector_count: last_lba,
        });
    }
    let mut name = [0u16; 36];
    for (index, word) in name.iter_mut().enumerate() {
        *word = read_u16(entry, 56 + index * 2);
    }
    Ok(Some(GptPartition {
        type_guid,
        partition_guid: entry[16..32]
            .try_into()
            .expect("GPT partition GUID is 16 bytes"),
        first_lba,
        last_lba,
        attributes: read_u64(entry, 48),
        name,
    }))
}

pub fn validate_partition_extent(
    extent: PartitionExtent,
    capacity: u64,
) -> Result<(), PartitionError> {
    if extent.sector_count == 0
        || extent.first_lba.checked_add(extent.sector_count).is_none()
        || extent.first_lba.saturating_add(extent.sector_count) > capacity
    {
        return Err(PartitionError::PartitionOutOfRange {
            first_lba: extent.first_lba,
            sector_count: extent.sector_count,
            capacity,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatBootSector {
    pub fat_type: FatType,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fat_count: u8,
    pub root_entries: u16,
    pub root_cluster: u32,
    pub total_sectors: u64,
    pub sectors_per_fat: u64,
    pub root_directory_sectors: u64,
    pub data_start_sector: u64,
    pub cluster_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatError {
    SectorTooShort { length: usize },
    InvalidSignature { signature: u16 },
    InvalidBytesPerSector { value: u16 },
    InvalidSectorsPerCluster { value: u8 },
    InvalidReservedSectorCount,
    InvalidFatCount,
    InvalidTotalSectorCount,
    InvalidSectorsPerFat,
    InvalidGeometry,
}

pub fn parse_fat_boot_sector(sector: &[u8]) -> Result<FatBootSector, FatError> {
    if sector.len() < SECTOR_SIZE {
        return Err(FatError::SectorTooShort {
            length: sector.len(),
        });
    }
    let signature = u16::from_le_bytes([sector[510], sector[511]]);
    if signature != MBR_SIGNATURE {
        return Err(FatError::InvalidSignature { signature });
    }

    let bytes_per_sector = read_u16(sector, 11);
    if bytes_per_sector != SECTOR_SIZE as u16 {
        return Err(FatError::InvalidBytesPerSector {
            value: bytes_per_sector,
        });
    }
    let sectors_per_cluster = sector[13];
    if sectors_per_cluster == 0
        || sectors_per_cluster > 128
        || sectors_per_cluster & (sectors_per_cluster - 1) != 0
    {
        return Err(FatError::InvalidSectorsPerCluster {
            value: sectors_per_cluster,
        });
    }
    let reserved_sectors = read_u16(sector, 14);
    if reserved_sectors == 0 {
        return Err(FatError::InvalidReservedSectorCount);
    }
    let fat_count = sector[16];
    if fat_count == 0 {
        return Err(FatError::InvalidFatCount);
    }
    let root_entries = read_u16(sector, 17);
    let total_sectors_16 = u64::from(read_u16(sector, 19));
    let total_sectors_32 = u64::from(read_u32(sector, 32));
    let total_sectors = if total_sectors_16 != 0 {
        total_sectors_16
    } else {
        total_sectors_32
    };
    if total_sectors == 0 {
        return Err(FatError::InvalidTotalSectorCount);
    }
    let sectors_per_fat_16 = u64::from(read_u16(sector, 22));
    let sectors_per_fat_32 = u64::from(read_u32(sector, 36));
    let sectors_per_fat = if sectors_per_fat_16 != 0 {
        sectors_per_fat_16
    } else {
        sectors_per_fat_32
    };
    if sectors_per_fat == 0 {
        return Err(FatError::InvalidSectorsPerFat);
    }

    let root_directory_sectors =
        (u64::from(root_entries) * 32).div_ceil(u64::from(bytes_per_sector));
    let fat_area_sectors = u64::from(fat_count) * sectors_per_fat;
    let data_start_sector = u64::from(reserved_sectors)
        .checked_add(fat_area_sectors)
        .and_then(|value| value.checked_add(root_directory_sectors))
        .ok_or(FatError::InvalidGeometry)?;
    if data_start_sector >= total_sectors {
        return Err(FatError::InvalidGeometry);
    }
    let cluster_count = (total_sectors - data_start_sector) / u64::from(sectors_per_cluster);
    if cluster_count == 0 {
        return Err(FatError::InvalidGeometry);
    }
    let fat_type = if cluster_count < 4085 {
        FatType::Fat12
    } else if cluster_count < 65_525 {
        FatType::Fat16
    } else {
        FatType::Fat32
    };
    let root_cluster = if fat_type == FatType::Fat32 {
        if root_entries != 0 || total_sectors_16 != 0 || sectors_per_fat_16 != 0 {
            return Err(FatError::InvalidGeometry);
        }
        let root_cluster = read_u32(sector, 44) & 0x0fff_ffff;
        if root_cluster < 2 {
            return Err(FatError::InvalidGeometry);
        }
        root_cluster
    } else {
        0
    };

    Ok(FatBootSector {
        fat_type,
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        fat_count,
        root_entries,
        root_cluster,
        total_sectors,
        sectors_per_fat,
        root_directory_sectors,
        data_start_sector,
        cluster_count,
    })
}

const FAT_DIRECTORY_ENTRY_SIZE: usize = 32;
const MAX_ROOT_FILE_ENTRIES: usize = 32;
const FAT_ATTRIBUTE_READ_ONLY: u8 = 0x01;
const FAT_ATTRIBUTE_HIDDEN: u8 = 0x02;
const FAT_ATTRIBUTE_SYSTEM: u8 = 0x04;
const FAT_ATTRIBUTE_VOLUME_LABEL: u8 = 0x08;
const FAT_ATTRIBUTE_DIRECTORY: u8 = 0x10;
const FAT_ATTRIBUTE_ARCHIVE: u8 = 0x20;
const FAT_ATTRIBUTE_LONG_NAME: u8 = FAT_ATTRIBUTE_READ_ONLY
    | FAT_ATTRIBUTE_HIDDEN
    | FAT_ATTRIBUTE_SYSTEM
    | FAT_ATTRIBUTE_VOLUME_LABEL;
const FAT_DELETED_ENTRY: u8 = 0xe5;
const FAT_DIRECTORY_CLUSTER_LIMIT: usize = 128;
const FAT_PATH_COMPONENT_LIMIT: usize = 16;
const FAT_RUNTIME_SNAPSHOT_FILE_LIMIT: usize = 128;
const FAT_RUNTIME_SNAPSHOT_PATH_LENGTH: usize = 256;
pub const MAX_MUTABLE_FILE_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatFileEntry {
    pub short_name: [u8; 11],
    pub attributes: u8,
    pub first_cluster: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatVfsNode {
    Root,
    Entry(FatFileEntry),
}

impl FatFileEntry {
    pub fn is_directory(self) -> bool {
        self.attributes & FAT_ATTRIBUTE_DIRECTORY != 0
    }

    pub fn is_regular_file(self) -> bool {
        !self.is_directory() && self.attributes & FAT_ATTRIBUTE_VOLUME_LABEL == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatDirectoryError {
    EntryTooShort { length: usize },
}

/// Parse one 32-byte FAT directory slot.
///
/// Long-name fragments, deleted slots, volume labels, and unused slots are not file entries and
/// therefore return `Ok(None)`. A caller scanning a directory can distinguish the end marker by
/// checking the slot's first byte before calling this function.
pub fn parse_fat_directory_entry(entry: &[u8]) -> Result<Option<FatFileEntry>, FatDirectoryError> {
    if entry.len() < FAT_DIRECTORY_ENTRY_SIZE {
        return Err(FatDirectoryError::EntryTooShort {
            length: entry.len(),
        });
    }
    let first_byte = entry[0];
    if first_byte == 0 || first_byte == FAT_DELETED_ENTRY {
        return Ok(None);
    }

    let attributes = entry[11];
    if attributes == FAT_ATTRIBUTE_LONG_NAME || attributes & FAT_ATTRIBUTE_VOLUME_LABEL != 0 {
        return Ok(None);
    }

    Ok(Some(FatFileEntry {
        short_name: entry[..11].try_into().expect("FAT short name is 11 bytes"),
        attributes,
        first_cluster: (u32::from(read_u16(entry, 20)) << 16) | u32::from(read_u16(entry, 26)),
        size: read_u32(entry, 28),
    }))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
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

fn crc32(bytes: &[u8]) -> u32 {
    crc32_with_zeroed_range(bytes, bytes.len()..bytes.len())
}

fn crc32_with_zeroed_range(bytes: &[u8], zeroed: core::ops::Range<usize>) -> u32 {
    let mut crc = u32::MAX;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let byte = if zeroed.contains(&index) { 0 } else { byte };
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[allow(dead_code)]
pub trait BlockDevice {
    type Error;

    fn capacity_sectors(&self) -> u64;

    fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error>;

    fn write_sector(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error>;
}

#[cfg(target_os = "none")]
pub enum StorageDisk {
    AtaPio(AtaPioDisk),
    Ahci(crate::ahci::AhciDisk),
    Nvme(crate::nvme::NvmeDisk),
}

#[cfg(target_os = "none")]
impl StorageDisk {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AtaPio(_) => "ata-pio",
            Self::Ahci(_) => "ahci",
            Self::Nvme(_) => "nvme",
        }
    }

    pub fn capacity_sectors(&self) -> u64 {
        match self {
            Self::AtaPio(disk) => disk.capacity_sectors(),
            Self::Ahci(disk) => disk.capacity_sectors(),
            Self::Nvme(disk) => disk.capacity_sectors(),
        }
    }
}

#[cfg(target_os = "none")]
impl BlockDevice for StorageDisk {
    type Error = BlockDeviceError;

    fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors()
    }

    fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        match self {
            Self::AtaPio(disk) => disk.read_sector(lba, buffer),
            Self::Ahci(disk) => disk
                .read_sector(lba, buffer)
                .map_err(|error| error.into_block_error()),
            Self::Nvme(disk) => disk
                .read_sector(lba, buffer)
                .map_err(|error| error.into_block_error()),
        }
    }

    fn write_sector(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        match self {
            Self::AtaPio(disk) => disk.write_sector(lba, buffer),
            Self::Ahci(disk) => disk
                .write_sector(lba, buffer)
                .map_err(|error| error.into_block_error()),
            Self::Nvme(disk) => disk
                .write_sector(lba, buffer)
                .map_err(|error| error.into_block_error()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FatFileSystemError<E> {
    Block(E),
    Partition(PartitionError),
    FilesystemExceedsPartition {
        filesystem_sectors: u64,
        partition_sectors: u64,
    },
    InvalidGeometry,
    InvalidName,
    DirectoryEntry(FatDirectoryError),
    VolumeSectorOutOfRange {
        relative_sector: u64,
        total_sectors: u64,
    },
    FatTableOutOfRange {
        offset: u64,
        fat_bytes: u64,
    },
    InvalidCluster {
        cluster: u32,
    },
    BadCluster {
        cluster: u32,
    },
    ReservedCluster {
        cluster: u32,
    },
    UnexpectedEndOfChain {
        cluster: u32,
    },
    ClusterChainLoop,
    DirectoryTooLarge {
        max_clusters: usize,
    },
    RootDirectoryTooLarge {
        max_entries: usize,
    },
    RuntimeSnapshotTooLarge {
        max_files: usize,
    },
    NotRegularFile,
    ReadOnlyFile,
    FileAlreadyExists,
    FileNotFound,
    DirectoryFull,
    FileTooLarge {
        size: usize,
        max_size: usize,
    },
    NoFreeClusters {
        requested: usize,
        available: usize,
    },
    FileRangeOutOfBounds {
        offset: u64,
        size: u64,
    },
    FileWriteOutOfBounds {
        offset: u64,
        length: u64,
        size: u64,
    },
}

impl<E> From<FatDirectoryError> for FatFileSystemError<E> {
    fn from(error: FatDirectoryError) -> Self {
        Self::DirectoryEntry(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FatClusterNext {
    EndOfChain,
    Next(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FatDirectoryRef {
    Root,
    Cluster(u32),
}

#[derive(Debug, Clone, Copy)]
struct FatDirectorySlot {
    relative_sector: u64,
    offset: usize,
    file: Option<FatFileEntry>,
}

#[derive(Debug, Clone, Copy)]
struct LocatedFatEntry {
    entry: FatFileEntry,
    slot: FatDirectorySlot,
}

#[derive(Clone, Copy)]
struct FatSnapshotDirectory {
    directory: FatDirectoryRef,
    path: [u8; FAT_RUNTIME_SNAPSHOT_PATH_LENGTH],
    path_length: usize,
    depth: usize,
    visited: [u32; FAT_PATH_COMPONENT_LIMIT],
    visited_length: usize,
}

pub struct FatFileSystem<D> {
    device: D,
    partition: PartitionExtent,
    boot: FatBootSector,
}

impl<D: BlockDevice> FatFileSystem<D> {
    pub fn mount(
        device: D,
        partition: PartitionExtent,
        boot: FatBootSector,
    ) -> Result<Self, FatFileSystemError<D::Error>> {
        validate_partition_extent(partition, device.capacity_sectors())
            .map_err(FatFileSystemError::Partition)?;
        if boot.total_sectors > partition.sector_count {
            return Err(FatFileSystemError::FilesystemExceedsPartition {
                filesystem_sectors: boot.total_sectors,
                partition_sectors: partition.sector_count,
            });
        }
        if boot.bytes_per_sector as usize != SECTOR_SIZE {
            return Err(FatFileSystemError::InvalidGeometry);
        }

        let fat_area_sectors = u64::from(boot.fat_count)
            .checked_mul(boot.sectors_per_fat)
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        match boot.fat_type {
            FatType::Fat12 | FatType::Fat16 => {
                let root_start_sector = u64::from(boot.reserved_sectors)
                    .checked_add(fat_area_sectors)
                    .ok_or(FatFileSystemError::InvalidGeometry)?;
                let root_end_sector = root_start_sector
                    .checked_add(boot.root_directory_sectors)
                    .ok_or(FatFileSystemError::InvalidGeometry)?;
                if root_end_sector != boot.data_start_sector
                    || root_end_sector >= boot.total_sectors
                {
                    return Err(FatFileSystemError::InvalidGeometry);
                }
            }
            FatType::Fat32 => {
                if boot.root_directory_sectors != 0
                    || boot.root_cluster < 2
                    || boot.root_cluster > boot.cluster_count as u32 + 1
                {
                    return Err(FatFileSystemError::InvalidGeometry);
                }
            }
        }
        boot.sectors_per_fat
            .checked_mul(SECTOR_SIZE as u64)
            .ok_or(FatFileSystemError::InvalidGeometry)?;

        Ok(Self {
            device,
            partition,
            boot,
        })
    }

    fn directory_sector_locations(
        &mut self,
        directory: FatDirectoryRef,
    ) -> Result<Vec<(u64, Option<u32>)>, FatFileSystemError<D::Error>> {
        let mut locations = Vec::new();
        match directory {
            FatDirectoryRef::Root => {
                if self.boot.fat_type == FatType::Fat32 {
                    let clusters = self.collect_cluster_chain(self.boot.root_cluster)?;
                    if clusters.len() > FAT_DIRECTORY_CLUSTER_LIMIT {
                        return Err(FatFileSystemError::DirectoryTooLarge {
                            max_clusters: FAT_DIRECTORY_CLUSTER_LIMIT,
                        });
                    }
                    for cluster in clusters {
                        let cluster_start = self.cluster_start_sector(cluster)?;
                        for sector_index in 0..u64::from(self.boot.sectors_per_cluster) {
                            locations.push((cluster_start + sector_index, Some(cluster)));
                        }
                    }
                } else {
                    let root_start_sector = u64::from(self.boot.reserved_sectors)
                        .checked_add(
                            u64::from(self.boot.fat_count)
                                .checked_mul(self.boot.sectors_per_fat)
                                .ok_or(FatFileSystemError::InvalidGeometry)?,
                        )
                        .ok_or(FatFileSystemError::InvalidGeometry)?;
                    for sector_index in 0..self.boot.root_directory_sectors {
                        locations.push((root_start_sector + sector_index, None));
                    }
                }
            }
            FatDirectoryRef::Cluster(first_cluster) => {
                let clusters = self.collect_cluster_chain(first_cluster)?;
                if clusters.len() > FAT_DIRECTORY_CLUSTER_LIMIT {
                    return Err(FatFileSystemError::DirectoryTooLarge {
                        max_clusters: FAT_DIRECTORY_CLUSTER_LIMIT,
                    });
                }
                for cluster in clusters {
                    let cluster_start = self.cluster_start_sector(cluster)?;
                    for sector_index in 0..u64::from(self.boot.sectors_per_cluster) {
                        locations.push((cluster_start + sector_index, Some(cluster)));
                    }
                }
            }
        }
        Ok(locations)
    }

    fn find_directory_entry_slot(
        &mut self,
        directory: FatDirectoryRef,
        short_name: &[u8; 11],
    ) -> Result<Option<FatDirectorySlot>, FatFileSystemError<D::Error>> {
        let locations = self.directory_sector_locations(directory)?;
        let mut sector = [0u8; SECTOR_SIZE];
        for (relative_sector, _) in locations {
            self.read_volume_sector(relative_sector, &mut sector)?;
            for offset in (0..SECTOR_SIZE).step_by(FAT_DIRECTORY_ENTRY_SIZE) {
                let entry = &sector[offset..offset + FAT_DIRECTORY_ENTRY_SIZE];
                if let Some(file) = parse_fat_directory_entry(entry)? {
                    if file.short_name == *short_name {
                        return Ok(Some(FatDirectorySlot {
                            relative_sector,
                            offset,
                            file: Some(file),
                        }));
                    }
                }
            }
        }
        Ok(None)
    }

    fn find_free_directory_slot(
        &mut self,
        directory: FatDirectoryRef,
    ) -> Result<FatDirectorySlot, FatFileSystemError<D::Error>> {
        let locations = self.directory_sector_locations(directory)?;
        let mut sector = [0u8; SECTOR_SIZE];
        for (relative_sector, _) in locations {
            self.read_volume_sector(relative_sector, &mut sector)?;
            for offset in (0..SECTOR_SIZE).step_by(FAT_DIRECTORY_ENTRY_SIZE) {
                if matches!(sector[offset], 0 | FAT_DELETED_ENTRY) {
                    return Ok(FatDirectorySlot {
                        relative_sector,
                        offset,
                        file: None,
                    });
                }
            }
        }

        let first_cluster = match directory {
            FatDirectoryRef::Cluster(first_cluster) => first_cluster,
            FatDirectoryRef::Root if self.boot.fat_type == FatType::Fat32 => self.boot.root_cluster,
            FatDirectoryRef::Root => return Err(FatFileSystemError::DirectoryFull),
        };
        let clusters = self.collect_cluster_chain(first_cluster)?;
        let last_cluster = clusters
            .last()
            .copied()
            .ok_or(FatFileSystemError::InvalidCluster {
                cluster: first_cluster,
            })?;
        let cluster_bytes = usize::from(self.boot.sectors_per_cluster)
            .checked_mul(SECTOR_SIZE)
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        let new_chain = self.allocate_cluster_chain(cluster_bytes)?;
        let new_cluster = new_chain
            .first()
            .copied()
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        if let Err(error) = self.set_fat_entry(last_cluster, new_cluster) {
            let _ = self.release_cluster_chain(&new_chain);
            return Err(error);
        }
        if let Err(error) = self.zero_cluster(new_cluster) {
            let _ = self.set_fat_entry(last_cluster, self.end_of_chain_value());
            let _ = self.release_cluster_chain(&new_chain);
            return Err(error);
        }
        let relative_sector = self.cluster_start_sector(new_cluster)?;
        Ok(FatDirectorySlot {
            relative_sector,
            offset: 0,
            file: None,
        })
    }

    #[cfg_attr(target_os = "none", allow(dead_code))]
    fn find_root_entry_slot(
        &mut self,
        short_name: &[u8; 11],
    ) -> Result<Option<FatDirectorySlot>, FatFileSystemError<D::Error>> {
        self.find_directory_entry_slot(FatDirectoryRef::Root, short_name)
    }

    #[cfg_attr(target_os = "none", allow(dead_code))]
    fn find_free_root_slot(&mut self) -> Result<FatDirectorySlot, FatFileSystemError<D::Error>> {
        self.find_free_directory_slot(FatDirectoryRef::Root)
    }

    #[cfg_attr(target_os = "none", allow(dead_code))]
    pub fn find_root_entry(
        &mut self,
        short_name: &[u8; 11],
    ) -> Result<Option<FatFileEntry>, FatFileSystemError<D::Error>> {
        Ok(self
            .find_root_entry_slot(short_name)?
            .and_then(|slot| slot.file))
    }

    pub fn root_files(&mut self) -> Result<Vec<FatFileEntry>, FatFileSystemError<D::Error>> {
        let mut files = Vec::new();
        let mut sector = [0u8; SECTOR_SIZE];
        for (relative_sector, _) in self.directory_sector_locations(FatDirectoryRef::Root)? {
            self.read_volume_sector(relative_sector, &mut sector)?;
            for offset in (0..SECTOR_SIZE).step_by(FAT_DIRECTORY_ENTRY_SIZE) {
                let entry = &sector[offset..offset + FAT_DIRECTORY_ENTRY_SIZE];
                if entry[0] == 0 {
                    return Ok(files);
                }
                if let Some(file) = parse_fat_directory_entry(entry)? {
                    if !file.is_regular_file() {
                        continue;
                    }
                    if files.len() == MAX_ROOT_FILE_ENTRIES {
                        return Err(FatFileSystemError::RootDirectoryTooLarge {
                            max_entries: MAX_ROOT_FILE_ENTRIES,
                        });
                    }
                    files.push(file);
                }
            }
        }
        Ok(files)
    }

    fn collect_runtime_file_snapshot(
        &mut self,
        snapshot: &mut Vec<(Vec<u8>, usize)>,
    ) -> Result<(), FatFileSystemError<D::Error>> {
        const MAX_DIRECTORIES: usize = 64;

        let mut pending = Vec::with_capacity(MAX_DIRECTORIES);
        pending.push(FatSnapshotDirectory {
            directory: FatDirectoryRef::Root,
            path: [0; FAT_RUNTIME_SNAPSHOT_PATH_LENGTH],
            path_length: 0,
            depth: 0,
            visited: [0; FAT_PATH_COMPONENT_LIMIT],
            visited_length: 0,
        });
        let mut pending_index = 0;
        while let Some(current) = pending.get(pending_index).copied() {
            pending_index += 1;
            if current.depth > FAT_PATH_COMPONENT_LIMIT {
                return Err(FatFileSystemError::DirectoryTooLarge {
                    max_clusters: FAT_PATH_COMPONENT_LIMIT,
                });
            }

            let locations = self.directory_sector_locations(current.directory)?;
            let mut sector = [0u8; SECTOR_SIZE];
            'sectors: for (relative_sector, _) in locations {
                self.read_volume_sector(relative_sector, &mut sector)?;
                for offset in (0..SECTOR_SIZE).step_by(FAT_DIRECTORY_ENTRY_SIZE) {
                    let entry = &sector[offset..offset + FAT_DIRECTORY_ENTRY_SIZE];
                    if entry[0] == 0 {
                        break 'sectors;
                    }
                    let Some(file) = parse_fat_directory_entry(entry)? else {
                        continue;
                    };
                    if is_dot_directory_entry(&file.short_name) {
                        continue;
                    }
                    let Some(short_path) = path_from_short_name(&file.short_name) else {
                        continue;
                    };
                    if file.is_regular_file() {
                        if snapshot.len() == FAT_RUNTIME_SNAPSHOT_FILE_LIMIT {
                            return Err(FatFileSystemError::RuntimeSnapshotTooLarge {
                                max_files: FAT_RUNTIME_SNAPSHOT_FILE_LIMIT,
                            });
                        }
                        let mut file_path =
                            Vec::with_capacity(current.path_length + short_path.len());
                        file_path.extend_from_slice(&current.path[..current.path_length]);
                        file_path.extend_from_slice(&short_path);
                        snapshot.push((
                            file_path,
                            usize::try_from(file.size)
                                .map_err(|_| FatFileSystemError::InvalidGeometry)?,
                        ));
                    } else if file.is_directory() {
                        if file.first_cluster == 0 {
                            return Err(FatFileSystemError::InvalidCluster { cluster: 0 });
                        }
                        if current.visited[..current.visited_length].contains(&file.first_cluster) {
                            return Err(FatFileSystemError::ClusterChainLoop);
                        }
                        if current.visited_length == current.visited.len() {
                            return Err(FatFileSystemError::DirectoryTooLarge {
                                max_clusters: FAT_PATH_COMPONENT_LIMIT,
                            });
                        }
                        let child_path_length = current
                            .path_length
                            .checked_add(short_path.len())
                            .ok_or(FatFileSystemError::InvalidName)?;
                        if child_path_length > FAT_RUNTIME_SNAPSHOT_PATH_LENGTH {
                            return Err(FatFileSystemError::InvalidName);
                        }
                        if pending.len() == MAX_DIRECTORIES {
                            return Err(FatFileSystemError::RuntimeSnapshotTooLarge {
                                max_files: MAX_DIRECTORIES,
                            });
                        }
                        let mut child = current;
                        child.directory = FatDirectoryRef::Cluster(file.first_cluster);
                        child.path[current.path_length..child_path_length]
                            .copy_from_slice(&short_path);
                        child.path_length = child_path_length;
                        child.depth += 1;
                        child.visited[child.visited_length] = file.first_cluster;
                        child.visited_length += 1;
                        pending.push(child);
                    }
                }
            }
        }
        Ok(())
    }

    fn path_components<'a>(
        &self,
        path: &'a [u8],
    ) -> Result<Vec<&'a [u8]>, FatFileSystemError<D::Error>> {
        if path.is_empty() || path[0] != b'/' {
            return Err(FatFileSystemError::InvalidName);
        }
        let mut components = Vec::new();
        for component in path[1..].split(|byte| *byte == b'/') {
            if component.is_empty() || component == b"." {
                continue;
            }
            if component == b".." || components.len() == FAT_PATH_COMPONENT_LIMIT {
                return Err(FatFileSystemError::InvalidName);
            }
            components.push(component);
        }
        Ok(components)
    }

    fn resolve_directory_components(
        &mut self,
        components: &[&[u8]],
    ) -> Result<Option<FatDirectoryRef>, FatFileSystemError<D::Error>> {
        let mut directory = FatDirectoryRef::Root;
        for component in components {
            let short_name = short_name_from_component(component)
                .map_err(|_| FatFileSystemError::InvalidName)?;
            let Some(slot) = self.find_directory_entry_slot(directory, &short_name)? else {
                return Ok(None);
            };
            let entry = slot.file.ok_or(FatFileSystemError::FileNotFound)?;
            if !entry.is_directory() {
                return Err(FatFileSystemError::NotRegularFile);
            }
            if entry.first_cluster == 0 {
                return Err(FatFileSystemError::InvalidCluster { cluster: 0 });
            }
            directory = FatDirectoryRef::Cluster(entry.first_cluster);
        }
        Ok(Some(directory))
    }

    fn locate_path_entry(
        &mut self,
        path: &[u8],
    ) -> Result<Option<LocatedFatEntry>, FatFileSystemError<D::Error>> {
        let components = self.path_components(path)?;
        if components.is_empty() {
            return Ok(None);
        }
        let mut directory = FatDirectoryRef::Root;
        for (index, component) in components.iter().enumerate() {
            let short_name = short_name_from_component(component)
                .map_err(|_| FatFileSystemError::InvalidName)?;
            let Some(slot) = self.find_directory_entry_slot(directory, &short_name)? else {
                return Ok(None);
            };
            let entry = slot.file.ok_or(FatFileSystemError::FileNotFound)?;
            if index + 1 == components.len() {
                return Ok(Some(LocatedFatEntry { entry, slot }));
            }
            if !entry.is_directory() {
                return Err(FatFileSystemError::NotRegularFile);
            }
            if entry.first_cluster == 0 {
                return Err(FatFileSystemError::InvalidCluster { cluster: 0 });
            }
            directory = FatDirectoryRef::Cluster(entry.first_cluster);
        }
        Ok(None)
    }

    fn create_file_in_directory(
        &mut self,
        directory: FatDirectoryRef,
        short_name: [u8; 11],
        contents: &[u8],
    ) -> Result<FatFileEntry, FatFileSystemError<D::Error>> {
        validate_short_name(&short_name).map_err(|_| FatFileSystemError::InvalidName)?;
        if contents.len() > MAX_MUTABLE_FILE_SIZE {
            return Err(FatFileSystemError::FileTooLarge {
                size: contents.len(),
                max_size: MAX_MUTABLE_FILE_SIZE,
            });
        }
        if self
            .find_directory_entry_slot(directory, &short_name)?
            .is_some()
        {
            return Err(FatFileSystemError::FileAlreadyExists);
        }
        let slot = self.find_free_directory_slot(directory)?;
        let new_chain = self.allocate_cluster_chain(contents.len())?;
        if let Err(error) = self.write_cluster_chain_contents(&new_chain, contents) {
            let _ = self.release_cluster_chain(&new_chain);
            return Err(error);
        }
        let file = FatFileEntry {
            short_name,
            attributes: FAT_ATTRIBUTE_ARCHIVE,
            first_cluster: new_chain.first().copied().unwrap_or(0),
            size: u32::try_from(contents.len()).map_err(|_| FatFileSystemError::InvalidGeometry)?,
        };
        if let Err(error) = self.write_directory_entry(slot, file) {
            let _ = self.release_cluster_chain(&new_chain);
            return Err(error);
        }
        Ok(file)
    }

    fn create_directory_in_directory(
        &mut self,
        parent: FatDirectoryRef,
        short_name: [u8; 11],
    ) -> Result<FatFileEntry, FatFileSystemError<D::Error>> {
        validate_short_name(&short_name).map_err(|_| FatFileSystemError::InvalidName)?;
        if self
            .find_directory_entry_slot(parent, &short_name)?
            .is_some()
        {
            return Err(FatFileSystemError::FileAlreadyExists);
        }
        let slot = self.find_free_directory_slot(parent)?;
        let cluster_bytes = usize::from(self.boot.sectors_per_cluster)
            .checked_mul(SECTOR_SIZE)
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        let new_chain = self.allocate_cluster_chain(cluster_bytes)?;
        let first_cluster = new_chain
            .first()
            .copied()
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        if let Err(error) = self.zero_cluster(first_cluster) {
            let _ = self.release_cluster_chain(&new_chain);
            return Err(error);
        }
        let directory = FatDirectoryRef::Cluster(first_cluster);
        if let Err(error) = self.initialize_directory_cluster(directory, parent) {
            let _ = self.release_cluster_chain(&new_chain);
            return Err(error);
        }
        let file = FatFileEntry {
            short_name,
            attributes: FAT_ATTRIBUTE_DIRECTORY,
            first_cluster,
            size: 0,
        };
        if let Err(error) = self.write_directory_entry(slot, file) {
            let _ = self.release_cluster_chain(&new_chain);
            return Err(error);
        }
        Ok(file)
    }

    pub fn create_file_path(
        &mut self,
        path: &[u8],
        contents: &[u8],
    ) -> Result<FatFileEntry, FatFileSystemError<D::Error>> {
        let components = self.path_components(path)?;
        let Some((name, parents)) = components.split_last() else {
            return Err(FatFileSystemError::InvalidName);
        };
        let Some(directory) = self.resolve_directory_components(parents)? else {
            return Err(FatFileSystemError::FileNotFound);
        };
        let short_name =
            short_name_from_component(name).map_err(|_| FatFileSystemError::InvalidName)?;
        self.create_file_in_directory(directory, short_name, contents)
    }

    pub fn create_directory_path(
        &mut self,
        path: &[u8],
    ) -> Result<FatFileEntry, FatFileSystemError<D::Error>> {
        let components = self.path_components(path)?;
        let Some((name, parents)) = components.split_last() else {
            return Err(FatFileSystemError::InvalidName);
        };
        let Some(parent) = self.resolve_directory_components(parents)? else {
            return Err(FatFileSystemError::FileNotFound);
        };
        let short_name =
            short_name_from_component(name).map_err(|_| FatFileSystemError::InvalidName)?;
        self.create_directory_in_directory(parent, short_name)
    }

    /// Read a bounded range from a regular FAT12/FAT16/FAT32 file.
    ///
    /// The method follows the file's cluster chain but only copies the requested range, keeping
    /// the caller's buffer as the memory bound. It is therefore suitable for loading file
    /// prefixes or streaming larger files in fixed-size chunks.
    pub fn read_file_range(
        &mut self,
        file: FatFileEntry,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, FatFileSystemError<D::Error>> {
        if !file.is_regular_file() {
            return Err(FatFileSystemError::NotRegularFile);
        }
        let file_size = u64::from(file.size);
        if offset > file_size {
            return Err(FatFileSystemError::FileRangeOutOfBounds {
                offset,
                size: file_size,
            });
        }
        let requested = core::cmp::min(buffer.len() as u64, file_size - offset) as usize;
        if requested == 0 {
            return Ok(0);
        }

        let cluster_bytes = u64::from(self.boot.sectors_per_cluster)
            .checked_mul(SECTOR_SIZE as u64)
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        let mut current_cluster = file.first_cluster;
        self.validate_data_cluster(current_cluster)?;
        let mut cluster_index = offset / cluster_bytes;
        let mut cluster_offset = offset % cluster_bytes;
        let mut traversed_clusters = 0u64;
        let mut fat_scratch = [0u8; SECTOR_SIZE];

        while cluster_index > 0 {
            current_cluster = match self.next_cluster(current_cluster, &mut fat_scratch)? {
                FatClusterNext::EndOfChain => {
                    return Err(FatFileSystemError::UnexpectedEndOfChain {
                        cluster: current_cluster,
                    });
                }
                FatClusterNext::Next(next) => next,
            };
            traversed_clusters = traversed_clusters
                .checked_add(1)
                .ok_or(FatFileSystemError::ClusterChainLoop)?;
            if traversed_clusters > self.boot.cluster_count {
                return Err(FatFileSystemError::ClusterChainLoop);
            }
            cluster_index -= 1;
        }

        let mut sector_scratch = [0u8; SECTOR_SIZE];
        let mut copied = 0usize;
        while copied < requested {
            self.validate_data_cluster(current_cluster)?;
            let cluster_start = self.cluster_start_sector(current_cluster)?;
            let mut sector_index = cluster_offset / SECTOR_SIZE as u64;
            let mut sector_offset = (cluster_offset % SECTOR_SIZE as u64) as usize;

            while sector_index < u64::from(self.boot.sectors_per_cluster) && copied < requested {
                let relative_sector = cluster_start
                    .checked_add(sector_index)
                    .ok_or(FatFileSystemError::InvalidGeometry)?;
                self.read_volume_sector(relative_sector, &mut sector_scratch)?;
                let available = SECTOR_SIZE - sector_offset;
                let count = core::cmp::min(available, requested - copied);
                buffer[copied..copied + count]
                    .copy_from_slice(&sector_scratch[sector_offset..sector_offset + count]);
                copied += count;
                sector_index += 1;
                sector_offset = 0;
            }

            if copied == requested {
                break;
            }
            current_cluster = match self.next_cluster(current_cluster, &mut fat_scratch)? {
                FatClusterNext::EndOfChain => {
                    return Err(FatFileSystemError::UnexpectedEndOfChain {
                        cluster: current_cluster,
                    });
                }
                FatClusterNext::Next(next) => next,
            };
            traversed_clusters = traversed_clusters
                .checked_add(1)
                .ok_or(FatFileSystemError::ClusterChainLoop)?;
            if traversed_clusters > self.boot.cluster_count {
                return Err(FatFileSystemError::ClusterChainLoop);
            }
            cluster_offset = 0;
        }

        Ok(copied)
    }

    /// Write a bounded range into an existing regular FAT12/FAT16/FAT32 file.
    ///
    /// This intentionally does not grow or shrink files yet. Callers must provision the file in
    /// the image first, which keeps the first writable boundary atomic at the sector level and
    /// avoids exposing partially implemented directory or free-cluster allocation semantics.
    pub fn write_file_range(
        &mut self,
        file: FatFileEntry,
        offset: u64,
        buffer: &[u8],
    ) -> Result<usize, FatFileSystemError<D::Error>> {
        if !file.is_regular_file() {
            return Err(FatFileSystemError::NotRegularFile);
        }
        if file.attributes & FAT_ATTRIBUTE_READ_ONLY != 0 {
            return Err(FatFileSystemError::ReadOnlyFile);
        }
        let file_size = u64::from(file.size);
        let length = buffer.len() as u64;
        let end = offset
            .checked_add(length)
            .ok_or(FatFileSystemError::FileWriteOutOfBounds {
                offset,
                length,
                size: file_size,
            })?;
        if offset > file_size || end > file_size {
            return Err(FatFileSystemError::FileWriteOutOfBounds {
                offset,
                length,
                size: file_size,
            });
        }
        if buffer.is_empty() {
            return Ok(0);
        }

        let cluster_bytes = u64::from(self.boot.sectors_per_cluster)
            .checked_mul(SECTOR_SIZE as u64)
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        let mut current_cluster = file.first_cluster;
        self.validate_data_cluster(current_cluster)?;
        let mut cluster_index = offset / cluster_bytes;
        let mut cluster_offset = offset % cluster_bytes;
        let mut traversed_clusters = 0u64;
        let mut fat_scratch = [0u8; SECTOR_SIZE];

        while cluster_index > 0 {
            current_cluster = match self.next_cluster(current_cluster, &mut fat_scratch)? {
                FatClusterNext::EndOfChain => {
                    return Err(FatFileSystemError::UnexpectedEndOfChain {
                        cluster: current_cluster,
                    });
                }
                FatClusterNext::Next(next) => next,
            };
            traversed_clusters = traversed_clusters
                .checked_add(1)
                .ok_or(FatFileSystemError::ClusterChainLoop)?;
            if traversed_clusters > self.boot.cluster_count {
                return Err(FatFileSystemError::ClusterChainLoop);
            }
            cluster_index -= 1;
        }

        let mut sector_scratch = [0u8; SECTOR_SIZE];
        let mut copied = 0usize;
        while copied < buffer.len() {
            self.validate_data_cluster(current_cluster)?;
            let cluster_start = self.cluster_start_sector(current_cluster)?;
            let mut sector_index = cluster_offset / SECTOR_SIZE as u64;
            let mut sector_offset = (cluster_offset % SECTOR_SIZE as u64) as usize;

            while sector_index < u64::from(self.boot.sectors_per_cluster) && copied < buffer.len() {
                let relative_sector = cluster_start
                    .checked_add(sector_index)
                    .ok_or(FatFileSystemError::InvalidGeometry)?;
                self.read_volume_sector(relative_sector, &mut sector_scratch)?;
                let available = SECTOR_SIZE - sector_offset;
                let count = core::cmp::min(available, buffer.len() - copied);
                sector_scratch[sector_offset..sector_offset + count]
                    .copy_from_slice(&buffer[copied..copied + count]);
                self.write_volume_sector(relative_sector, &sector_scratch)?;
                copied += count;
                sector_index += 1;
                sector_offset = 0;
            }

            if copied == buffer.len() {
                break;
            }
            current_cluster = match self.next_cluster(current_cluster, &mut fat_scratch)? {
                FatClusterNext::EndOfChain => {
                    return Err(FatFileSystemError::UnexpectedEndOfChain {
                        cluster: current_cluster,
                    });
                }
                FatClusterNext::Next(next) => next,
            };
            traversed_clusters = traversed_clusters
                .checked_add(1)
                .ok_or(FatFileSystemError::ClusterChainLoop)?;
            if traversed_clusters > self.boot.cluster_count {
                return Err(FatFileSystemError::ClusterChainLoop);
            }
            cluster_offset = 0;
        }

        Ok(copied)
    }

    /// Replace the contents of an existing regular root file, allocating a fresh bounded cluster
    /// chain before publishing the new directory metadata.
    #[cfg_attr(target_os = "none", allow(dead_code))]
    pub fn write_file_contents(
        &mut self,
        file: FatFileEntry,
        contents: &[u8],
    ) -> Result<usize, FatFileSystemError<D::Error>> {
        let slot = self
            .find_root_entry_slot(&file.short_name)?
            .ok_or(FatFileSystemError::FileNotFound)?;
        let actual = slot.file.ok_or(FatFileSystemError::FileNotFound)?;
        self.write_file_contents_at(slot, actual, contents)
    }

    #[cfg_attr(target_os = "none", allow(dead_code))]
    pub fn write_file_path(
        &mut self,
        path: &[u8],
        contents: &[u8],
    ) -> Result<usize, FatFileSystemError<D::Error>> {
        let located = self
            .locate_path_entry(path)?
            .ok_or(FatFileSystemError::FileNotFound)?;
        self.write_file_contents_at(located.slot, located.entry, contents)
    }

    fn write_file_contents_at(
        &mut self,
        slot: FatDirectorySlot,
        file: FatFileEntry,
        contents: &[u8],
    ) -> Result<usize, FatFileSystemError<D::Error>> {
        if !file.is_regular_file() {
            return Err(FatFileSystemError::NotRegularFile);
        }
        if file.attributes & FAT_ATTRIBUTE_READ_ONLY != 0 {
            return Err(FatFileSystemError::ReadOnlyFile);
        }
        if contents.len() > MAX_MUTABLE_FILE_SIZE {
            return Err(FatFileSystemError::FileTooLarge {
                size: contents.len(),
                max_size: MAX_MUTABLE_FILE_SIZE,
            });
        }
        let old_chain = self.collect_cluster_chain(file.first_cluster)?;
        let new_chain = self.allocate_cluster_chain(contents.len())?;

        if let Err(error) = self.write_cluster_chain_contents(&new_chain, contents) {
            let _ = self.release_cluster_chain(&new_chain);
            return Err(error);
        }
        let first_cluster = new_chain.first().copied().unwrap_or(0);
        if let Err(error) = self.update_directory_entry_metadata(
            slot,
            first_cluster,
            u32::try_from(contents.len()).map_err(|_| FatFileSystemError::InvalidGeometry)?,
        ) {
            let _ = self.release_cluster_chain(&new_chain);
            return Err(error);
        }
        self.release_cluster_chain(&old_chain)?;
        Ok(contents.len())
    }

    /// Create a regular file in the FAT root directory and provision its initial contents.
    #[cfg_attr(target_os = "none", allow(dead_code))]
    pub fn create_root_file(
        &mut self,
        short_name: [u8; 11],
        contents: &[u8],
    ) -> Result<FatFileEntry, FatFileSystemError<D::Error>> {
        self.create_file_in_directory(FatDirectoryRef::Root, short_name, contents)
    }

    fn collect_cluster_chain(
        &mut self,
        first_cluster: u32,
    ) -> Result<Vec<u32>, FatFileSystemError<D::Error>> {
        if first_cluster == 0 {
            return Ok(Vec::new());
        }
        self.validate_data_cluster(first_cluster)?;
        let mut clusters = Vec::new();
        let mut current = first_cluster;
        let mut scratch = [0u8; SECTOR_SIZE];
        loop {
            clusters.push(current);
            if clusters.len() > self.boot.cluster_count as usize {
                return Err(FatFileSystemError::ClusterChainLoop);
            }
            current = match self.next_cluster(current, &mut scratch)? {
                FatClusterNext::EndOfChain => break,
                FatClusterNext::Next(next) => next,
            };
        }
        Ok(clusters)
    }

    fn allocate_cluster_chain(
        &mut self,
        size: usize,
    ) -> Result<Vec<u32>, FatFileSystemError<D::Error>> {
        let cluster_bytes = u64::from(self.boot.sectors_per_cluster)
            .checked_mul(SECTOR_SIZE as u64)
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        let required = if size == 0 {
            0
        } else {
            size.div_ceil(
                usize::try_from(cluster_bytes).map_err(|_| FatFileSystemError::InvalidGeometry)?,
            )
        };
        if required == 0 {
            return Ok(Vec::new());
        }

        let max_cluster = self.max_data_cluster()?;
        let mut clusters = Vec::with_capacity(required);
        let mut scratch = [0u8; SECTOR_SIZE];
        for cluster in 2..=max_cluster {
            if self.fat_entry_value(cluster, &mut scratch)? == 0 {
                clusters.push(cluster);
                if clusters.len() == required {
                    break;
                }
            }
        }
        if clusters.len() != required {
            return Err(FatFileSystemError::NoFreeClusters {
                requested: required,
                available: clusters.len(),
            });
        }

        for (index, cluster) in clusters.iter().copied().enumerate() {
            let next = clusters
                .get(index + 1)
                .copied()
                .map_or_else(|| self.end_of_chain_value(), |next| next);
            if let Err(error) = self.set_fat_entry(cluster, next) {
                let _ = self.release_cluster_chain(&clusters[..=index]);
                return Err(error);
            }
        }
        Ok(clusters)
    }

    fn release_cluster_chain(
        &mut self,
        clusters: &[u32],
    ) -> Result<(), FatFileSystemError<D::Error>> {
        for cluster in clusters.iter().copied() {
            self.set_fat_entry(cluster, 0)?;
        }
        Ok(())
    }

    fn write_cluster_chain_contents(
        &mut self,
        clusters: &[u32],
        contents: &[u8],
    ) -> Result<(), FatFileSystemError<D::Error>> {
        let cluster_bytes = u64::from(self.boot.sectors_per_cluster)
            .checked_mul(SECTOR_SIZE as u64)
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        let cluster_bytes =
            usize::try_from(cluster_bytes).map_err(|_| FatFileSystemError::InvalidGeometry)?;
        for (cluster_index, cluster) in clusters.iter().copied().enumerate() {
            let cluster_start = self.cluster_start_sector(cluster)?;
            let source_start = cluster_index
                .checked_mul(cluster_bytes)
                .ok_or(FatFileSystemError::InvalidGeometry)?;
            for sector_index in 0..usize::from(self.boot.sectors_per_cluster) {
                let mut sector = [0u8; SECTOR_SIZE];
                let destination_start = source_start
                    .checked_add(sector_index * SECTOR_SIZE)
                    .ok_or(FatFileSystemError::InvalidGeometry)?;
                let count = contents
                    .len()
                    .saturating_sub(destination_start)
                    .min(SECTOR_SIZE);
                if count != 0 {
                    sector[..count]
                        .copy_from_slice(&contents[destination_start..destination_start + count]);
                }
                let relative_sector = cluster_start
                    .checked_add(sector_index as u64)
                    .ok_or(FatFileSystemError::InvalidGeometry)?;
                self.write_volume_sector(relative_sector, &sector)?;
            }
        }
        Ok(())
    }

    fn write_directory_entry(
        &mut self,
        slot: FatDirectorySlot,
        file: FatFileEntry,
    ) -> Result<(), FatFileSystemError<D::Error>> {
        if self.boot.fat_type != FatType::Fat32 && file.first_cluster > u32::from(u16::MAX) {
            return Err(FatFileSystemError::InvalidGeometry);
        }
        let mut sector = [0u8; SECTOR_SIZE];
        self.read_volume_sector(slot.relative_sector, &mut sector)?;
        sector[slot.offset..slot.offset + FAT_DIRECTORY_ENTRY_SIZE].fill(0);
        sector[slot.offset..slot.offset + 11].copy_from_slice(&file.short_name);
        sector[slot.offset + 11] = file.attributes;
        sector[slot.offset + 20..slot.offset + 22]
            .copy_from_slice(&((file.first_cluster >> 16) as u16).to_le_bytes());
        sector[slot.offset + 26..slot.offset + 28]
            .copy_from_slice(&(file.first_cluster as u16).to_le_bytes());
        sector[slot.offset + 28..slot.offset + 32].copy_from_slice(&file.size.to_le_bytes());
        self.write_volume_sector(slot.relative_sector, &sector)
    }

    fn update_directory_entry_metadata(
        &mut self,
        slot: FatDirectorySlot,
        first_cluster: u32,
        size: u32,
    ) -> Result<(), FatFileSystemError<D::Error>> {
        if self.boot.fat_type != FatType::Fat32 && first_cluster > u32::from(u16::MAX) {
            return Err(FatFileSystemError::InvalidGeometry);
        }
        let mut sector = [0u8; SECTOR_SIZE];
        self.read_volume_sector(slot.relative_sector, &mut sector)?;
        sector[slot.offset + 20..slot.offset + 22]
            .copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        sector[slot.offset + 26..slot.offset + 28]
            .copy_from_slice(&(first_cluster as u16).to_le_bytes());
        sector[slot.offset + 28..slot.offset + 32].copy_from_slice(&size.to_le_bytes());
        self.write_volume_sector(slot.relative_sector, &sector)
    }

    fn zero_cluster(&mut self, cluster: u32) -> Result<(), FatFileSystemError<D::Error>> {
        let cluster_start = self.cluster_start_sector(cluster)?;
        let zero = [0u8; SECTOR_SIZE];
        for sector_index in 0..u64::from(self.boot.sectors_per_cluster) {
            self.write_volume_sector(cluster_start + sector_index, &zero)?;
        }
        Ok(())
    }

    fn initialize_directory_cluster(
        &mut self,
        directory: FatDirectoryRef,
        parent: FatDirectoryRef,
    ) -> Result<(), FatFileSystemError<D::Error>> {
        let FatDirectoryRef::Cluster(first_cluster) = directory else {
            return Err(FatFileSystemError::InvalidGeometry);
        };
        let relative_sector = self.cluster_start_sector(first_cluster)?;
        let dot = FatFileEntry {
            short_name: [
                b'.', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ',
            ],
            attributes: FAT_ATTRIBUTE_DIRECTORY,
            first_cluster,
            size: 0,
        };
        let parent_cluster = match parent {
            FatDirectoryRef::Root if self.boot.fat_type == FatType::Fat32 => self.boot.root_cluster,
            FatDirectoryRef::Root => 0,
            FatDirectoryRef::Cluster(cluster) => cluster,
        };
        let dot_dot = FatFileEntry {
            short_name: [
                b'.', b'.', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ',
            ],
            attributes: FAT_ATTRIBUTE_DIRECTORY,
            first_cluster: parent_cluster,
            size: 0,
        };
        self.write_directory_entry(
            FatDirectorySlot {
                relative_sector,
                offset: 0,
                file: None,
            },
            dot,
        )?;
        self.write_directory_entry(
            FatDirectorySlot {
                relative_sector,
                offset: FAT_DIRECTORY_ENTRY_SIZE,
                file: None,
            },
            dot_dot,
        )
    }

    fn read_volume_sector(
        &mut self,
        relative_sector: u64,
        buffer: &mut [u8; SECTOR_SIZE],
    ) -> Result<(), FatFileSystemError<D::Error>> {
        if relative_sector >= self.boot.total_sectors
            || relative_sector >= self.partition.sector_count
        {
            return Err(FatFileSystemError::VolumeSectorOutOfRange {
                relative_sector,
                total_sectors: self.boot.total_sectors,
            });
        }
        let lba = self
            .partition
            .first_lba
            .checked_add(relative_sector)
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        self.device
            .read_sector(lba, buffer)
            .map_err(FatFileSystemError::Block)
    }

    fn write_volume_sector(
        &mut self,
        relative_sector: u64,
        buffer: &[u8; SECTOR_SIZE],
    ) -> Result<(), FatFileSystemError<D::Error>> {
        if relative_sector >= self.boot.total_sectors
            || relative_sector >= self.partition.sector_count
        {
            return Err(FatFileSystemError::VolumeSectorOutOfRange {
                relative_sector,
                total_sectors: self.boot.total_sectors,
            });
        }
        let lba = self
            .partition
            .first_lba
            .checked_add(relative_sector)
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        self.device
            .write_sector(lba, buffer)
            .map_err(FatFileSystemError::Block)
    }

    fn fat_bytes(&self) -> Result<u64, FatFileSystemError<D::Error>> {
        self.boot
            .sectors_per_fat
            .checked_mul(SECTOR_SIZE as u64)
            .ok_or(FatFileSystemError::InvalidGeometry)
    }

    fn fat_value(
        &mut self,
        offset: u64,
        scratch: &mut [u8; SECTOR_SIZE],
    ) -> Result<u32, FatFileSystemError<D::Error>> {
        let fat_bytes = self.fat_bytes()?;
        let width: usize = if self.boot.fat_type == FatType::Fat32 {
            4
        } else {
            2
        };
        if offset
            .checked_add((width - 1) as u64)
            .is_none_or(|end| end >= fat_bytes)
        {
            return Err(FatFileSystemError::FatTableOutOfRange { offset, fat_bytes });
        }
        let sector_index = offset / SECTOR_SIZE as u64;
        let byte_index = (offset % SECTOR_SIZE as u64) as usize;
        let fat_start = u64::from(self.boot.reserved_sectors);
        self.read_volume_sector(fat_start + sector_index, scratch)?;
        let mut bytes = [0u8; 4];
        let mut next_sector = [0u8; SECTOR_SIZE];
        for (index, byte) in bytes[..width].iter_mut().enumerate() {
            let absolute = byte_index + index;
            *byte = if absolute < SECTOR_SIZE {
                scratch[absolute]
            } else {
                if absolute == SECTOR_SIZE {
                    self.read_volume_sector(fat_start + sector_index + 1, &mut next_sector)?;
                }
                next_sector[absolute - SECTOR_SIZE]
            };
        }
        Ok(u32::from_le_bytes(bytes))
    }

    fn fat_entry_value(
        &mut self,
        cluster: u32,
        scratch: &mut [u8; SECTOR_SIZE],
    ) -> Result<u32, FatFileSystemError<D::Error>> {
        self.validate_data_cluster(cluster)?;
        let offset = match self.boot.fat_type {
            FatType::Fat12 => u64::from(cluster) + u64::from(cluster / 2),
            FatType::Fat16 => u64::from(cluster)
                .checked_mul(2)
                .ok_or(FatFileSystemError::InvalidGeometry)?,
            FatType::Fat32 => u64::from(cluster)
                .checked_mul(4)
                .ok_or(FatFileSystemError::InvalidGeometry)?,
        };
        let raw = self.fat_value(offset, scratch)?;
        Ok(match self.boot.fat_type {
            FatType::Fat12 if cluster & 1 == 0 => raw & 0x0fff,
            FatType::Fat12 => raw >> 4,
            FatType::Fat16 => raw,
            FatType::Fat32 => raw & 0x0fff_ffff,
        })
    }

    fn set_fat_entry(
        &mut self,
        cluster: u32,
        value: u32,
    ) -> Result<(), FatFileSystemError<D::Error>> {
        self.validate_data_cluster(cluster)?;
        let max_value = match self.boot.fat_type {
            FatType::Fat12 => 0x0fff,
            FatType::Fat16 => 0xffff,
            FatType::Fat32 => 0x0fff_ffff,
        };
        if value > max_value {
            return Err(FatFileSystemError::InvalidGeometry);
        }
        for fat_index in 0..u64::from(self.boot.fat_count) {
            let fat_start = u64::from(self.boot.reserved_sectors)
                .checked_add(
                    fat_index
                        .checked_mul(self.boot.sectors_per_fat)
                        .ok_or(FatFileSystemError::InvalidGeometry)?,
                )
                .ok_or(FatFileSystemError::InvalidGeometry)?;
            self.set_fat_entry_in_copy(fat_start, cluster, value)?;
        }
        Ok(())
    }

    fn set_fat_entry_in_copy(
        &mut self,
        fat_start: u64,
        cluster: u32,
        value: u32,
    ) -> Result<(), FatFileSystemError<D::Error>> {
        let offset = match self.boot.fat_type {
            FatType::Fat12 => u64::from(cluster) + u64::from(cluster / 2),
            FatType::Fat16 => u64::from(cluster)
                .checked_mul(2)
                .ok_or(FatFileSystemError::InvalidGeometry)?,
            FatType::Fat32 => u64::from(cluster)
                .checked_mul(4)
                .ok_or(FatFileSystemError::InvalidGeometry)?,
        };
        let fat_bytes = self.fat_bytes()?;
        let width: usize = if self.boot.fat_type == FatType::Fat32 {
            4
        } else {
            2
        };
        if offset
            .checked_add((width - 1) as u64)
            .is_none_or(|end| end >= fat_bytes)
        {
            return Err(FatFileSystemError::FatTableOutOfRange { offset, fat_bytes });
        }
        let sector_index = offset / SECTOR_SIZE as u64;
        let byte_index = (offset % SECTOR_SIZE as u64) as usize;
        let mut first = [0u8; SECTOR_SIZE];
        self.read_volume_sector(fat_start + sector_index, &mut first)?;
        match self.boot.fat_type {
            FatType::Fat16 => {
                first[byte_index..byte_index + 2].copy_from_slice(&(value as u16).to_le_bytes());
                self.write_volume_sector(fat_start + sector_index, &first)
            }
            FatType::Fat12 => {
                let crosses_sector = byte_index == SECTOR_SIZE - 1;
                let mut second = [0u8; SECTOR_SIZE];
                if crosses_sector {
                    self.read_volume_sector(fat_start + sector_index + 1, &mut second)?;
                }
                if cluster & 1 == 0 {
                    first[byte_index] = value as u8;
                    if crosses_sector {
                        second[0] = (second[0] & 0xf0) | ((value >> 8) as u8 & 0x0f);
                    } else {
                        first[byte_index + 1] =
                            (first[byte_index + 1] & 0xf0) | ((value >> 8) as u8 & 0x0f);
                    }
                } else {
                    if crosses_sector {
                        first[byte_index] = (first[byte_index] & 0x0f) | ((value as u8) << 4);
                        second[0] = (value >> 4) as u8;
                    } else {
                        first[byte_index] = (first[byte_index] & 0x0f) | ((value as u8) << 4);
                        first[byte_index + 1] = (value >> 4) as u8;
                    }
                }
                self.write_volume_sector(fat_start + sector_index, &first)?;
                if crosses_sector {
                    self.write_volume_sector(fat_start + sector_index + 1, &second)?;
                }
                Ok(())
            }
            FatType::Fat32 => {
                let existing = u32::from_le_bytes([
                    first[byte_index],
                    first[byte_index + 1],
                    first[byte_index + 2],
                    first[byte_index + 3],
                ]);
                let updated = (existing & 0xf000_0000) | (value & 0x0fff_ffff);
                first[byte_index..byte_index + 4].copy_from_slice(&updated.to_le_bytes());
                self.write_volume_sector(fat_start + sector_index, &first)
            }
        }
    }

    fn end_of_chain_value(&self) -> u32 {
        match self.boot.fat_type {
            FatType::Fat12 => 0x0fff,
            FatType::Fat16 => 0xffff,
            FatType::Fat32 => 0x0fff_ffff,
        }
    }

    fn max_data_cluster(&self) -> Result<u32, FatFileSystemError<D::Error>> {
        self.boot
            .cluster_count
            .checked_add(1)
            .and_then(|cluster| u32::try_from(cluster).ok())
            .ok_or(FatFileSystemError::InvalidGeometry)
    }

    fn validate_data_cluster(&self, cluster: u32) -> Result<(), FatFileSystemError<D::Error>> {
        if cluster < 2 || cluster > self.max_data_cluster()? {
            return Err(FatFileSystemError::InvalidCluster { cluster });
        }
        Ok(())
    }

    fn cluster_start_sector(&self, cluster: u32) -> Result<u64, FatFileSystemError<D::Error>> {
        self.validate_data_cluster(cluster)?;
        let cluster_offset = u64::from(cluster - 2)
            .checked_mul(u64::from(self.boot.sectors_per_cluster))
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        let start = self
            .boot
            .data_start_sector
            .checked_add(cluster_offset)
            .ok_or(FatFileSystemError::InvalidGeometry)?;
        if start
            .checked_add(u64::from(self.boot.sectors_per_cluster))
            .is_none_or(|end| end > self.boot.total_sectors)
        {
            return Err(FatFileSystemError::VolumeSectorOutOfRange {
                relative_sector: start,
                total_sectors: self.boot.total_sectors,
            });
        }
        Ok(start)
    }

    fn next_cluster(
        &mut self,
        cluster: u32,
        scratch: &mut [u8; SECTOR_SIZE],
    ) -> Result<FatClusterNext, FatFileSystemError<D::Error>> {
        self.validate_data_cluster(cluster)?;
        let raw = self.fat_entry_value(cluster, scratch)?;
        let (end_of_chain, bad_cluster, reserved_start, reserved_end) = match self.boot.fat_type {
            FatType::Fat12 => (0xff8, 0xff7, 0xff0, 0xff6),
            FatType::Fat16 => (0xfff8, 0xfff7, 0xfff0, 0xfff6),
            FatType::Fat32 => (0x0fff_fff8, 0x0fff_fff7, 0x0fff_fff0, 0x0fff_fff6),
        };
        if raw >= end_of_chain {
            return Ok(FatClusterNext::EndOfChain);
        }
        if raw == bad_cluster {
            return Err(FatFileSystemError::BadCluster { cluster });
        }
        if (reserved_start..=reserved_end).contains(&raw) {
            return Err(FatFileSystemError::ReservedCluster { cluster });
        }
        let next = raw;
        if next < 2 || next > self.max_data_cluster()? {
            return Err(FatFileSystemError::InvalidCluster { cluster: next });
        }
        Ok(FatClusterNext::Next(next))
    }
}

fn short_name_from_component(component: &[u8]) -> Result<[u8; 11], ()> {
    if component.is_empty() || component == b"." || component == b".." {
        return Err(());
    }
    let (base, extension) = match component.iter().position(|byte| *byte == b'.') {
        Some(dot) => {
            if component[dot + 1..].contains(&b'.') {
                return Err(());
            }
            (&component[..dot], &component[dot + 1..])
        }
        None => (component, &component[component.len()..]),
    };
    if base.is_empty() || base.len() > 8 || extension.len() > 3 {
        return Err(());
    }

    let mut short_name = [b' '; 11];
    for (index, byte) in base.iter().copied().enumerate() {
        short_name[index] = normalize_short_name_byte(byte)?;
    }
    for (index, byte) in extension.iter().copied().enumerate() {
        short_name[8 + index] = normalize_short_name_byte(byte)?;
    }
    Ok(short_name)
}

fn validate_short_name(short_name: &[u8; 11]) -> Result<(), ()> {
    if short_name[0] == 0
        || short_name[0] == FAT_DELETED_ENTRY
        || short_name[0] == b' '
        || short_name.iter().all(|byte| *byte == b' ')
    {
        return Err(());
    }
    Ok(())
}

fn is_dot_directory_entry(short_name: &[u8; 11]) -> bool {
    (short_name[0] == b'.' && short_name[1..].iter().all(|byte| *byte == b' '))
        || (short_name[0] == b'.'
            && short_name[1] == b'.'
            && short_name[2..].iter().all(|byte| *byte == b' '))
}

#[cfg_attr(target_os = "none", allow(dead_code))]
fn path_from_short_name(short_name: &[u8; 11]) -> Option<Vec<u8>> {
    let base_end = short_name[..8]
        .iter()
        .rposition(|byte| *byte != b' ')
        .map(|index| index + 1)?;
    let extension_end = short_name[8..]
        .iter()
        .rposition(|byte| *byte != b' ')
        .map(|index| index + 1)
        .unwrap_or(0);
    let mut path = Vec::with_capacity(1 + base_end + (extension_end != 0) as usize + extension_end);
    path.push(b'/');
    path.extend_from_slice(&short_name[..base_end]);
    if extension_end != 0 {
        path.push(b'.');
        path.extend_from_slice(&short_name[8..8 + extension_end]);
    }
    Some(path)
}

fn normalize_short_name_byte(byte: u8) -> Result<u8, ()> {
    if !(0x21..=0x7e).contains(&byte)
        || matches!(
            byte,
            b'"' | b'*'
                | b'+'
                | b','
                | b'/'
                | b':'
                | b';'
                | b'<'
                | b'='
                | b'>'
                | b'?'
                | b'['
                | b'\\'
                | b']'
                | b'|'
        )
    {
        return Err(());
    }
    Ok(if byte.is_ascii_lowercase() {
        byte - b'a' + b'A'
    } else {
        byte
    })
}

impl<D: BlockDevice> crate::vfs::FileSystem for FatFileSystem<D> {
    type Error = FatFileSystemError<D::Error>;
    type Node = FatVfsNode;

    fn root(&self) -> Self::Node {
        FatVfsNode::Root
    }

    fn lookup(
        &mut self,
        parent: Self::Node,
        component: &[u8],
    ) -> Result<Option<Self::Node>, Self::Error> {
        match parent {
            FatVfsNode::Root => {
                let short_name = short_name_from_component(component)
                    .map_err(|_| FatFileSystemError::InvalidName)?;
                Ok(self
                    .find_directory_entry_slot(FatDirectoryRef::Root, &short_name)?
                    .and_then(|slot| slot.file)
                    .map(FatVfsNode::Entry))
            }
            FatVfsNode::Entry(entry) if entry.is_directory() => {
                if entry.first_cluster == 0 {
                    return Err(FatFileSystemError::InvalidCluster { cluster: 0 });
                }
                let short_name = short_name_from_component(component)
                    .map_err(|_| FatFileSystemError::InvalidName)?;
                Ok(self
                    .find_directory_entry_slot(
                        FatDirectoryRef::Cluster(entry.first_cluster),
                        &short_name,
                    )?
                    .and_then(|slot| slot.file)
                    .map(FatVfsNode::Entry))
            }
            FatVfsNode::Entry(_) => Err(FatFileSystemError::NotRegularFile),
        }
    }

    fn metadata(&self, node: Self::Node) -> Result<crate::vfs::Metadata, Self::Error> {
        Ok(match node {
            FatVfsNode::Root => crate::vfs::Metadata {
                kind: crate::vfs::NodeKind::Directory,
                size: 0,
            },
            FatVfsNode::Entry(entry) => crate::vfs::Metadata {
                kind: if entry.is_directory() {
                    crate::vfs::NodeKind::Directory
                } else {
                    crate::vfs::NodeKind::RegularFile
                },
                size: u64::from(entry.size),
            },
        })
    }

    fn read(
        &mut self,
        node: Self::Node,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, Self::Error> {
        match node {
            FatVfsNode::Root => Err(FatFileSystemError::NotRegularFile),
            FatVfsNode::Entry(entry) => self.read_file_range(entry, offset, buffer),
        }
    }
}

#[cfg(target_os = "none")]
const ATA_PRIMARY_COMMAND_BASE: u16 = 0x1f0;
#[cfg(target_os = "none")]
const ATA_PRIMARY_CONTROL_PORT: u16 = 0x3f6;
#[cfg(target_os = "none")]
const ATA_STATUS_ERROR: u8 = 1 << 0;
#[cfg(target_os = "none")]
const ATA_STATUS_DEVICE_FAULT: u8 = 1 << 5;
#[cfg(target_os = "none")]
const ATA_STATUS_DATA_REQUEST: u8 = 1 << 3;
#[cfg(target_os = "none")]
const ATA_STATUS_BUSY: u8 = 1 << 7;
#[cfg(target_os = "none")]
const ATA_COMMAND_IDENTIFY: u8 = 0xec;
#[cfg(target_os = "none")]
const ATA_COMMAND_READ_SECTORS: u8 = 0x20;
#[cfg(target_os = "none")]
#[allow(dead_code)]
const ATA_COMMAND_WRITE_SECTORS: u8 = 0x30;
#[cfg(target_os = "none")]
#[allow(dead_code)]
const ATA_COMMAND_CACHE_FLUSH: u8 = 0xe7;
#[cfg(target_os = "none")]
const ATA_POLL_SPINS: usize = 1_000_000;

#[cfg(target_os = "none")]
use alloc::{vec, vec::Vec};
#[cfg(target_os = "none")]
use x86_64::instructions::port::Port;

#[cfg(target_os = "none")]
pub struct AtaPioDisk {
    capacity_sectors: u64,
}

#[cfg(target_os = "none")]
impl AtaPioDisk {
    pub fn initialize() -> Result<Self, BlockDeviceError> {
        let mut ports = AtaPorts::new();
        let identify_words = ports.identify()?;
        let identify = parse_identify(&identify_words).map_err(BlockDeviceError::Identify)?;
        Ok(Self {
            capacity_sectors: identify.lba28_sectors,
        })
    }

    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }
}

#[cfg(target_os = "none")]
impl BlockDevice for AtaPioDisk {
    type Error = BlockDeviceError;

    fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors()
    }

    fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        validate_lba28(lba, self.capacity_sectors)?;
        if buffer.len() != SECTOR_SIZE {
            return Err(BlockDeviceError::InvalidBufferLength {
                expected: SECTOR_SIZE,
                actual: buffer.len(),
            });
        }
        let mut ports = AtaPorts::new();
        ports.issue_lba28_command(lba, ATA_COMMAND_READ_SECTORS);
        ports.wait_for_data()?;
        ports.read_words(buffer);
        ports.wait_for_idle()
    }

    fn write_sector(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        validate_lba28(lba, self.capacity_sectors)?;
        if buffer.len() != SECTOR_SIZE {
            return Err(BlockDeviceError::InvalidBufferLength {
                expected: SECTOR_SIZE,
                actual: buffer.len(),
            });
        }
        let mut ports = AtaPorts::new();
        ports.issue_lba28_command(lba, ATA_COMMAND_WRITE_SECTORS);
        ports.wait_for_data()?;
        ports.write_words(buffer);
        // PIO writes complete in the device cache first; flush before reporting durable completion.
        unsafe { ports.status_command.write(ATA_COMMAND_CACHE_FLUSH) };
        ports.wait_for_idle()
    }
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionTableKind {
    Mbr,
    Gpt,
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageProbe {
    pub capacity_sectors: u64,
    pub table: PartitionTableKind,
    pub partition: PartitionExtent,
    pub fat: FatBootSector,
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageProbeError {
    Block(BlockDeviceError),
    Partition(PartitionError),
    Fat(FatError),
    NoFilesystemPartition,
    FilesystemExceedsPartition {
        filesystem_sectors: u64,
        partition_sectors: u64,
    },
}

#[cfg(target_os = "none")]
impl From<BlockDeviceError> for StorageProbeError {
    fn from(error: BlockDeviceError) -> Self {
        Self::Block(error)
    }
}

#[cfg(target_os = "none")]
impl From<PartitionError> for StorageProbeError {
    fn from(error: PartitionError) -> Self {
        Self::Partition(error)
    }
}

#[cfg(target_os = "none")]
impl From<FatError> for StorageProbeError {
    fn from(error: FatError) -> Self {
        Self::Fat(error)
    }
}

#[cfg(target_os = "none")]
pub fn probe_disk<D>(disk: &mut D) -> Result<StorageProbe, StorageProbeError>
where
    D: BlockDevice<Error = BlockDeviceError>,
{
    let mut sector = Vec::with_capacity(SECTOR_SIZE);
    sector.resize(SECTOR_SIZE, 0);
    disk.read_sector(0, &mut sector)?;
    let mbr = parse_mbr(&sector)?;

    let (table, partition, fat) = if mbr.has_protective_gpt() {
        disk.read_sector(GPT_HEADER_LBA, &mut sector)?;
        let header = parse_gpt_header(&sector)?;
        let array_sectors = header.partition_array_sectors() as usize;
        let array_len = array_sectors
            .checked_mul(SECTOR_SIZE)
            .ok_or(PartitionError::GptPartitionArrayTooLarge { bytes: u64::MAX })?;
        let mut partition_array = Vec::with_capacity(array_len);
        partition_array.resize(array_len, 0);
        for index in 0..array_sectors {
            let start = index * SECTOR_SIZE;
            let end = start + SECTOR_SIZE;
            disk.read_sector(
                header.partition_entry_lba + index as u64,
                &mut partition_array[start..end],
            )?;
        }
        let partitions = gpt_partitions(&partition_array, &header)?;
        let mut fallback = None;
        let mut selected = None;
        for candidate in partitions {
            let extent = candidate.extent();
            validate_partition_extent(extent, disk.capacity_sectors())?;
            disk.read_sector(extent.first_lba, &mut sector)?;
            let Ok(candidate_fat) = parse_fat_boot_sector(&sector) else {
                continue;
            };
            if candidate_fat.total_sectors > extent.sector_count {
                continue;
            }
            if candidate_fat.fat_type == FatType::Fat32 {
                selected = Some((extent, candidate_fat));
                break;
            }
            if fallback.is_none() {
                fallback = Some((extent, candidate_fat));
            }
        }
        let (partition, fat) = selected
            .or(fallback)
            .ok_or(StorageProbeError::NoFilesystemPartition)?;
        (PartitionTableKind::Gpt, partition, fat)
    } else {
        let partition = mbr
            .first_fat_partition()
            .ok_or(StorageProbeError::NoFilesystemPartition)?;
        validate_partition_extent(partition.extent(), disk.capacity_sectors())?;
        disk.read_sector(partition.start_lba, &mut sector)?;
        let fat = parse_fat_boot_sector(&sector)?;
        (PartitionTableKind::Mbr, partition.extent(), fat)
    };

    validate_partition_extent(partition, disk.capacity_sectors())?;
    if fat.total_sectors > partition.sector_count {
        return Err(StorageProbeError::FilesystemExceedsPartition {
            filesystem_sectors: fat.total_sectors,
            partition_sectors: partition.sector_count,
        });
    }

    Ok(StorageProbe {
        capacity_sectors: disk.capacity_sectors(),
        table,
        partition,
        fat,
    })
}

#[cfg(target_os = "none")]
#[derive(Debug)]
pub struct StorageFile {
    pub path: Vec<u8>,
    pub image: Vec<u8>,
    pub mode: u32,
    pub persistent: bool,
}

#[cfg(target_os = "none")]
#[derive(Debug)]
pub struct StorageFileProbe {
    pub metadata: crate::vfs::Metadata,
    pub bytes_read: usize,
    pub magic: [u8; 4],
    pub skipped_files: usize,
    pub initramfs_size: usize,
    pub initramfs_entries: usize,
    pub state_before: [u8; PERSISTENT_STATE_LENGTH],
    pub state_after: [u8; PERSISTENT_STATE_LENGTH],
    pub files: Vec<StorageFile>,
}

#[cfg(target_os = "none")]
#[allow(dead_code)]
#[derive(Debug)]
pub enum StorageFileProbeError {
    Filesystem(FatFileSystemError<BlockDeviceError>),
    Vfs(crate::vfs::VfsError<FatFileSystemError<BlockDeviceError>>),
    KernelFileNotFound,
    KernelFileIsDirectory,
    InvalidKernelMagic {
        bytes_read: usize,
        actual: [u8; 4],
    },
    InitramfsFileNotFound,
    InitramfsFileIsDirectory,
    InitramfsFileTooLarge {
        size: u64,
    },
    InitramfsFileShortRead {
        expected: usize,
        actual: usize,
    },
    Initramfs(crate::initramfs::Error),
    RequiredInitramfsFileMissing {
        path: &'static [u8],
    },
    PersistentStateFileNotFound,
    PersistentStateFileIsDirectory,
    PersistentStateInvalid {
        actual: [u8; PERSISTENT_STATE_LENGTH],
    },
    PersistentStateShortRead {
        expected: usize,
        actual: usize,
    },
    PersistentStateVerificationFailed {
        expected: [u8; PERSISTENT_STATE_LENGTH],
        actual: [u8; PERSISTENT_STATE_LENGTH],
    },
    RuntimeFilesystemAlreadyInstalled,
}

#[cfg(target_os = "none")]
pub fn probe_kernel_file(
    disk: StorageDisk,
    probe: StorageProbe,
) -> Result<StorageFileProbe, StorageFileProbeError> {
    use crate::vfs::{FileSystem, NodeKind};

    let mut filesystem = FatFileSystem::mount(disk, probe.partition, probe.fat)
        .map_err(StorageFileProbeError::Filesystem)?;
    let entry = filesystem
        .lookup_path(b"/KERNEL~1")
        .map_err(StorageFileProbeError::Vfs)?
        .ok_or(StorageFileProbeError::KernelFileNotFound)?;
    let metadata = filesystem
        .metadata(entry)
        .map_err(StorageFileProbeError::Filesystem)?;
    if metadata.kind != NodeKind::RegularFile {
        return Err(StorageFileProbeError::KernelFileIsDirectory);
    }

    let mut magic = [0u8; 4];
    let bytes_read = filesystem
        .read(entry, 0, &mut magic)
        .map_err(StorageFileProbeError::Filesystem)?;
    if bytes_read != magic.len() || magic != *b"\x7fELF" {
        return Err(StorageFileProbeError::InvalidKernelMagic {
            bytes_read,
            actual: magic,
        });
    }

    let root_files = filesystem
        .root_files()
        .map_err(StorageFileProbeError::Filesystem)?;
    let skipped_files = root_files
        .iter()
        .filter(|file| u64::from(file.size) > crate::initramfs::MAX_ARCHIVE_SIZE as u64)
        .count();
    let initramfs_entry = filesystem
        .lookup_path(b"/INITRD.CPI")
        .map_err(StorageFileProbeError::Vfs)?
        .ok_or(StorageFileProbeError::InitramfsFileNotFound)?;
    let initramfs_metadata = filesystem
        .metadata(initramfs_entry)
        .map_err(StorageFileProbeError::Filesystem)?;
    if initramfs_metadata.kind != NodeKind::RegularFile {
        return Err(StorageFileProbeError::InitramfsFileIsDirectory);
    }
    let initramfs_size = usize::try_from(initramfs_metadata.size).map_err(|_| {
        StorageFileProbeError::InitramfsFileTooLarge {
            size: initramfs_metadata.size,
        }
    })?;
    if initramfs_size > crate::initramfs::MAX_ARCHIVE_SIZE {
        return Err(StorageFileProbeError::InitramfsFileTooLarge {
            size: initramfs_metadata.size,
        });
    }
    let mut archive = vec![0u8; initramfs_size];
    let archive_bytes = filesystem
        .read(initramfs_entry, 0, &mut archive)
        .map_err(StorageFileProbeError::Filesystem)?;
    if archive_bytes != initramfs_size {
        return Err(StorageFileProbeError::InitramfsFileShortRead {
            expected: initramfs_size,
            actual: archive_bytes,
        });
    }

    let state_entry = filesystem
        .lookup_path(PERSISTENT_STATE_PATH)
        .map_err(StorageFileProbeError::Vfs)?
        .ok_or(StorageFileProbeError::PersistentStateFileNotFound)?;
    let state_metadata = filesystem
        .metadata(state_entry)
        .map_err(StorageFileProbeError::Filesystem)?;
    if state_metadata.kind != NodeKind::RegularFile {
        return Err(StorageFileProbeError::PersistentStateFileIsDirectory);
    }
    let FatVfsNode::Entry(state_file) = state_entry else {
        return Err(StorageFileProbeError::PersistentStateFileIsDirectory);
    };
    if state_metadata.size != PERSISTENT_STATE_LENGTH as u64 {
        return Err(StorageFileProbeError::PersistentStateShortRead {
            expected: PERSISTENT_STATE_LENGTH,
            actual: state_metadata.size as usize,
        });
    }
    let mut state_before = [0u8; PERSISTENT_STATE_LENGTH];
    let state_bytes = filesystem
        .read(state_entry, 0, &mut state_before)
        .map_err(StorageFileProbeError::Filesystem)?;
    if state_bytes != state_before.len() {
        return Err(StorageFileProbeError::PersistentStateShortRead {
            expected: state_before.len(),
            actual: state_bytes,
        });
    }
    let state_after = if state_before == PERSISTENT_STATE_INITIAL {
        PERSISTENT_STATE_UPDATED
    } else if state_before == PERSISTENT_STATE_UPDATED {
        PERSISTENT_STATE_INITIAL
    } else {
        return Err(StorageFileProbeError::PersistentStateInvalid {
            actual: state_before,
        });
    };
    filesystem
        .write_file_range(state_file, 0, &state_after)
        .map_err(StorageFileProbeError::Filesystem)?;
    let mut verified_state = [0u8; PERSISTENT_STATE_LENGTH];
    let verified_bytes = filesystem
        .read(state_entry, 0, &mut verified_state)
        .map_err(StorageFileProbeError::Filesystem)?;
    if verified_bytes != verified_state.len() || verified_state != state_after {
        return Err(StorageFileProbeError::PersistentStateVerificationFailed {
            expected: state_after,
            actual: verified_state,
        });
    }

    let mut files = Vec::new();
    let initramfs_entries = crate::initramfs::for_each_entry(&archive, |entry| {
        if entry.is_regular_file() {
            let mut path = Vec::with_capacity(entry.name.len() + 1);
            path.push(b'/');
            path.extend_from_slice(entry.name);
            files.push(StorageFile {
                path,
                image: entry.data.to_vec(),
                mode: entry.mode,
                persistent: false,
            });
        }
        Ok(())
    })
    .map_err(StorageFileProbeError::Initramfs)?;

    files.push(StorageFile {
        path: PERSISTENT_STATE_PATH.to_vec(),
        image: state_after.to_vec(),
        mode: 0o100644,
        persistent: true,
    });

    const REQUIRED_FILES: [&[u8]; 9] = [
        b"/sbin/init",
        b"/bin/sh",
        b"/bin/service",
        b"/bin/worker",
        b"/bin/replaced",
        b"/bin/restart",
        b"/bin/pkg",
        b"/etc/rustos/init.cfg",
        b"/etc/rustos/config.txt",
    ];
    for path in REQUIRED_FILES {
        if !files.iter().any(|file| file.path == path) {
            return Err(StorageFileProbeError::RequiredInitramfsFileMissing { path });
        }
    }

    let result = StorageFileProbe {
        metadata,
        bytes_read,
        magic,
        skipped_files,
        initramfs_size,
        initramfs_entries,
        state_before,
        state_after,
        files,
    };
    RUNTIME_FILESYSTEM.call_once(|| Mutex::new(filesystem));
    Ok(result)
}

#[cfg(target_os = "none")]
pub fn read_runtime_file(path: &[u8], offset: u64, buffer: &mut [u8]) -> Result<usize, ()> {
    use crate::vfs::FileSystem;

    let filesystem = RUNTIME_FILESYSTEM.get().ok_or(())?;
    let mut filesystem = filesystem.lock();
    let node = filesystem.lookup_path(path).map_err(|_| ())?.ok_or(())?;
    filesystem.read(node, offset, buffer).map_err(|_| ())
}

#[cfg(target_os = "none")]
pub fn runtime_file_size(path: &[u8]) -> Result<Option<usize>, ()> {
    let filesystem = RUNTIME_FILESYSTEM.get().ok_or(())?;
    let mut filesystem = filesystem.lock();
    let Some(located) = filesystem.locate_path_entry(path).map_err(|_| ())? else {
        return Ok(None);
    };
    if !located.entry.is_regular_file() {
        return Err(());
    }
    Ok(Some(usize::try_from(located.entry.size).map_err(|_| ())?))
}

#[cfg(target_os = "none")]
pub fn runtime_path_info(path: &[u8]) -> Result<Option<(bool, usize)>, ()> {
    use crate::vfs::FileSystem;

    let filesystem = RUNTIME_FILESYSTEM.get().ok_or(())?;
    let mut filesystem = filesystem.lock();
    let Some(node) = filesystem.lookup_path(path).map_err(|_| ())? else {
        return Ok(None);
    };
    let metadata = filesystem.metadata(node).map_err(|_| ())?;
    let is_directory = metadata.kind == crate::vfs::NodeKind::Directory;
    let size = usize::try_from(metadata.size).map_err(|_| ())?;
    Ok(Some((is_directory, size)))
}

#[cfg(target_os = "none")]
pub fn runtime_file_snapshot() -> Result<Vec<(Vec<u8>, usize)>, ()> {
    let filesystem = RUNTIME_FILESYSTEM.get().ok_or(())?;
    let mut filesystem = filesystem.lock();
    let mut snapshot = Vec::new();
    filesystem
        .collect_runtime_file_snapshot(&mut snapshot)
        .map_err(|_| ())?;
    Ok(snapshot)
}

#[cfg(target_os = "none")]
pub fn create_runtime_file(path: &[u8], contents: &[u8]) -> Result<usize, ()> {
    let filesystem = RUNTIME_FILESYSTEM.get().ok_or(())?;
    let mut filesystem = filesystem.lock();
    let file = filesystem
        .create_file_path(path, contents)
        .map_err(|_| ())?;
    Ok(usize::try_from(file.size).map_err(|_| ())?)
}

#[cfg(target_os = "none")]
pub fn create_runtime_directory(path: &[u8]) -> Result<(), ()> {
    let filesystem = RUNTIME_FILESYSTEM.get().ok_or(())?;
    let mut filesystem = filesystem.lock();
    filesystem.create_directory_path(path).map_err(|_| ())?;
    Ok(())
}

#[cfg(target_os = "none")]
pub fn write_runtime_file(path: &[u8], offset: u64, buffer: &[u8]) -> Result<(usize, usize), ()> {
    let filesystem = RUNTIME_FILESYSTEM.get().ok_or(())?;
    let mut filesystem = filesystem.lock();
    let located = match filesystem.locate_path_entry(path) {
        Ok(Some(located)) => located,
        Ok(None) => return Err(()),
        Err(error) => {
            crate::kprintln!(
                "storage: runtime write lookup failed path={:?} error={:?} status=degraded",
                path,
                error
            );
            return Err(());
        }
    };
    if !located.entry.is_regular_file() {
        return Err(());
    }
    let entry = located.entry;
    let current_size = usize::try_from(entry.size).map_err(|_| ())?;
    let offset = usize::try_from(offset).map_err(|_| ())?;
    if buffer.is_empty() {
        return Ok((0, current_size));
    }
    let end = offset.checked_add(buffer.len()).ok_or(())?;
    if end <= current_size {
        let count = match filesystem.write_file_range(entry, offset as u64, buffer) {
            Ok(count) => count,
            Err(error) => {
                crate::kprintln!(
                    "storage: runtime write range failed path={:?} offset={} bytes={} error={:?} status=degraded",
                    path,
                    offset,
                    buffer.len(),
                    error
                );
                return Err(());
            }
        };
        return Ok((count, current_size));
    }
    if end > MAX_MUTABLE_FILE_SIZE {
        return Err(());
    }

    let mut contents = vec![0u8; end.max(current_size)];
    if current_size != 0 {
        let count = match filesystem.read_file_range(entry, 0, &mut contents[..current_size]) {
            Ok(count) => count,
            Err(error) => {
                crate::kprintln!(
                    "storage: runtime write readback failed path={:?} error={:?} status=degraded",
                    path,
                    error
                );
                return Err(());
            }
        };
        if count != current_size {
            crate::kprintln!(
                "storage: runtime write readback short path={:?} expected={} actual={} status=degraded",
                path,
                current_size,
                count
            );
            return Err(());
        }
    }
    contents[offset..end].copy_from_slice(buffer);
    let count = match filesystem.write_file_contents_at(located.slot, entry, &contents) {
        Ok(count) => count,
        Err(error) => {
            crate::kprintln!(
                "storage: runtime write contents failed path={:?} offset={} bytes={} error={:?} status=degraded",
                path,
                offset,
                buffer.len(),
                error
            );
            return Err(());
        }
    };
    Ok((buffer.len(), count))
}

#[cfg(target_os = "none")]
struct AtaPorts {
    data: Port<u16>,
    error_features: Port<u8>,
    sector_count: Port<u8>,
    lba_low: Port<u8>,
    lba_mid: Port<u8>,
    lba_high: Port<u8>,
    drive_head: Port<u8>,
    status_command: Port<u8>,
    control: Port<u8>,
}

#[cfg(target_os = "none")]
impl AtaPorts {
    fn new() -> Self {
        let mut ports = Self {
            data: Port::new(ATA_PRIMARY_COMMAND_BASE),
            error_features: Port::new(ATA_PRIMARY_COMMAND_BASE + 1),
            sector_count: Port::new(ATA_PRIMARY_COMMAND_BASE + 2),
            lba_low: Port::new(ATA_PRIMARY_COMMAND_BASE + 3),
            lba_mid: Port::new(ATA_PRIMARY_COMMAND_BASE + 4),
            lba_high: Port::new(ATA_PRIMARY_COMMAND_BASE + 5),
            drive_head: Port::new(ATA_PRIMARY_COMMAND_BASE + 6),
            status_command: Port::new(ATA_PRIMARY_COMMAND_BASE + 7),
            control: Port::new(ATA_PRIMARY_CONTROL_PORT),
        };
        // Polling owns completion, so suppress legacy IRQ14 from the primary ATA channel. Leaving
        // it asserted would collide with the later interrupt-driven device setup.
        unsafe { ports.control.write(1 << 1) };
        ports
    }

    fn identify(&mut self) -> Result<[u16; 256], BlockDeviceError> {
        // Select the primary master and clear the LBA registers as required by IDENTIFY.
        unsafe {
            self.drive_head.write(0xa0);
            self.sector_count.write(0);
            self.lba_low.write(0);
            self.lba_mid.write(0);
            self.lba_high.write(0);
            self.status_command.write(ATA_COMMAND_IDENTIFY);
        }
        self.delay_400ns();
        self.wait_for_data()?;

        let mut words = [0u16; 256];
        for word in &mut words {
            // SAFETY: the device asserted DRQ after the command and exposes exactly 256 words.
            *word = unsafe { self.data.read() };
        }
        self.wait_for_idle()?;
        Ok(words)
    }

    fn issue_lba28_command(&mut self, lba: u64, command: u8) {
        unsafe {
            self.drive_head.write(0xe0 | ((lba >> 24) as u8 & 0x0f));
        }
        self.delay_400ns();
        unsafe {
            self.sector_count.write(1);
            self.lba_low.write(lba as u8);
            self.lba_mid.write((lba >> 8) as u8);
            self.lba_high.write((lba >> 16) as u8);
            self.status_command.write(command);
        }
    }

    fn read_words(&mut self, buffer: &mut [u8]) {
        for bytes in buffer.chunks_exact_mut(2) {
            // SAFETY: the device asserted DRQ and a sector contains exactly 256 ATA words.
            let word = unsafe { self.data.read() };
            bytes.copy_from_slice(&word.to_le_bytes());
        }
    }

    #[allow(dead_code)]
    fn write_words(&mut self, buffer: &[u8]) {
        for bytes in buffer.chunks_exact(2) {
            let word = u16::from_le_bytes([bytes[0], bytes[1]]);
            // SAFETY: the device asserted DRQ and accepts exactly 256 ATA words.
            unsafe { self.data.write(word) };
        }
    }

    fn wait_for_data(&mut self) -> Result<u8, BlockDeviceError> {
        let mut last_status = 0;
        for _ in 0..ATA_POLL_SPINS {
            let status = self.read_status();
            last_status = status;
            if status == 0 || status == u8::MAX {
                return Err(BlockDeviceError::NoDevice);
            }
            if status & (ATA_STATUS_ERROR | ATA_STATUS_DEVICE_FAULT) != 0 {
                return Err(self.device_fault(status));
            }
            if status & ATA_STATUS_BUSY == 0 && status & ATA_STATUS_DATA_REQUEST != 0 {
                return Ok(status);
            }
            core::hint::spin_loop();
        }
        Err(BlockDeviceError::Timeout {
            status: last_status,
        })
    }

    fn wait_for_idle(&mut self) -> Result<(), BlockDeviceError> {
        let mut last_status = 0;
        for _ in 0..ATA_POLL_SPINS {
            let status = self.read_status();
            last_status = status;
            if status == 0 || status == u8::MAX {
                return Err(BlockDeviceError::NoDevice);
            }
            if status & (ATA_STATUS_ERROR | ATA_STATUS_DEVICE_FAULT) != 0 {
                return Err(self.device_fault(status));
            }
            if status & ATA_STATUS_BUSY == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(BlockDeviceError::Timeout {
            status: last_status,
        })
    }

    fn read_status(&mut self) -> u8 {
        // SAFETY: the primary status register is a byte-wide ATA status port.
        unsafe { self.status_command.read() }
    }

    fn device_fault(&mut self, status: u8) -> BlockDeviceError {
        // SAFETY: the error/features register is valid after the status register reports ERR/DF.
        let error = unsafe { self.error_features.read() };
        BlockDeviceError::DeviceFault { status, error }
    }

    fn delay_400ns(&mut self) {
        for _ in 0..4 {
            let _ = self.read_status();
        }
        // Keep the control port live in the port set; later IRQ-mode storage can use nIEN without
        // changing the driver boundary.
        let _ = &mut self.control;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lba28_capacity_from_identify_words() {
        let mut words = [0u16; 256];
        words[49] = ATA_LBA28_CAPABILITY;
        words[60] = 0x1234;
        words[61] = 0x5678;

        assert_eq!(
            parse_identify(&words),
            Ok(AtaIdentify {
                lba28_sectors: 0x5678_1234,
            })
        );
    }

    #[test]
    fn rejects_identify_without_lba28_or_capacity() {
        let mut words = [0u16; 256];
        assert_eq!(
            parse_identify(&words),
            Err(AtaIdentifyError::Lba28Unsupported)
        );

        words[49] = ATA_LBA28_CAPABILITY;
        assert_eq!(parse_identify(&words), Err(AtaIdentifyError::ZeroCapacity));
    }

    #[test]
    fn parses_lba48_capacity_and_falls_back_to_lba28() {
        let mut words = [0u16; 256];
        words[83] = ATA_LBA48_CAPABILITY;
        words[100] = 0x1234;
        words[101] = 0x5678;
        words[102] = 0x9abc;
        words[103] = 0xdef0;
        assert_eq!(parse_identify_capacity(&words), Ok(0xdef0_9abc_5678_1234));

        words[83] = 0;
        words[49] = ATA_LBA28_CAPABILITY;
        words[60] = 0x1234;
        words[61] = 0x5678;
        assert_eq!(parse_identify_capacity(&words), Ok(0x5678_1234));
    }

    #[test]
    fn validates_lba28_capacity_and_address_limits() {
        assert_eq!(validate_lba28(0, 4), Ok(()));
        assert_eq!(
            validate_lba28(4, 4),
            Err(BlockDeviceError::LbaOutOfRange {
                lba: 4,
                capacity: 4,
            })
        );
        assert_eq!(
            validate_lba28(ATA_MAX_LBA28 + 1, u64::MAX),
            Err(BlockDeviceError::Lba28AddressOutOfRange {
                lba: ATA_MAX_LBA28 + 1,
            })
        );
    }

    #[test]
    fn validates_lba48_capacity_and_address_limits() {
        assert_eq!(validate_lba48(0, 4), Ok(()));
        assert_eq!(
            validate_lba48(4, 4),
            Err(BlockDeviceError::LbaOutOfRange {
                lba: 4,
                capacity: 4,
            })
        );
        assert_eq!(
            validate_lba48(ATA_MAX_LBA48 + 1, u64::MAX),
            Err(BlockDeviceError::Lba48AddressOutOfRange {
                lba: ATA_MAX_LBA48 + 1,
            })
        );
    }

    #[test]
    fn parses_mbr_partitions_and_selects_fat_partition() {
        let mut sector = [0u8; SECTOR_SIZE];
        sector[510..512].copy_from_slice(&MBR_SIGNATURE.to_le_bytes());

        let first = MBR_PARTITION_TABLE_OFFSET;
        sector[first] = 0x80;
        sector[first + 4] = 0x20;
        sector[first + 8..first + 12].copy_from_slice(&1u32.to_le_bytes());
        sector[first + 12..first + 16].copy_from_slice(&961u32.to_le_bytes());

        let second = first + MBR_PARTITION_ENTRY_SIZE;
        sector[second] = 0x80;
        sector[second + 4] = 0x0c;
        sector[second + 8..second + 12].copy_from_slice(&962u32.to_le_bytes());
        sector[second + 12..second + 16].copy_from_slice(&4096u32.to_le_bytes());

        let table = parse_mbr(&sector).unwrap();
        assert!(table.entries[0].unwrap().is_fat() == false);
        assert_eq!(
            table.first_fat_partition().unwrap().extent(),
            PartitionExtent {
                first_lba: 962,
                sector_count: 4096,
            }
        );
        assert_eq!(
            validate_partition_extent(table.first_fat_partition().unwrap().extent(), 5058),
            Ok(())
        );
    }

    #[test]
    fn parses_crc_checked_gpt_header_and_first_partition() {
        let mut partition_array = [0u8; 128];
        partition_array[..16].copy_from_slice(&[1u8; 16]);
        partition_array[16..32].copy_from_slice(&[2u8; 16]);
        partition_array[32..40].copy_from_slice(&34u64.to_le_bytes());
        partition_array[40..48].copy_from_slice(&4129u64.to_le_bytes());
        for (index, value) in [b'b', b'o', b'o', b't'].into_iter().enumerate() {
            partition_array[56 + index * 2..58 + index * 2]
                .copy_from_slice(&(u16::from(value)).to_le_bytes());
        }

        let mut header = [0u8; SECTOR_SIZE];
        header[..8].copy_from_slice(&GPT_SIGNATURE);
        header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        header[12..16].copy_from_slice(&92u32.to_le_bytes());
        header[24..32].copy_from_slice(&1u64.to_le_bytes());
        header[32..40].copy_from_slice(&4223u64.to_le_bytes());
        header[40..48].copy_from_slice(&34u64.to_le_bytes());
        header[48..56].copy_from_slice(&4129u64.to_le_bytes());
        header[72..80].copy_from_slice(&2u64.to_le_bytes());
        header[80..84].copy_from_slice(&1u32.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        header[88..92].copy_from_slice(&crc32(&partition_array).to_le_bytes());
        let header_crc = crc32_with_zeroed_range(&header[..92], 16..20);
        header[16..20].copy_from_slice(&header_crc.to_le_bytes());

        let parsed_header = parse_gpt_header(&header).unwrap();
        let partition = first_gpt_partition(&partition_array, &parsed_header)
            .unwrap()
            .unwrap();
        assert_eq!(parsed_header.current_lba, 1);
        assert_eq!(parsed_header.partition_array_sectors(), 1);
        assert_eq!(partition.first_lba, 34);
        assert_eq!(partition.last_lba, 4129);
        assert_eq!(
            partition.name[..4],
            [b'b' as u16, b'o' as u16, b'o' as u16, b't' as u16]
        );
    }

    #[test]
    fn parses_fat12_boot_geometry() {
        let mut sector = [0u8; SECTOR_SIZE];
        sector[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        sector[13] = 2;
        sector[14..16].copy_from_slice(&1u16.to_le_bytes());
        sector[16] = 2;
        sector[17..19].copy_from_slice(&512u16.to_le_bytes());
        sector[19..21].copy_from_slice(&4096u16.to_le_bytes());
        sector[21] = 0xf8;
        sector[22..24].copy_from_slice(&6u16.to_le_bytes());
        sector[510..512].copy_from_slice(&MBR_SIGNATURE.to_le_bytes());

        assert_eq!(
            parse_fat_boot_sector(&sector).unwrap(),
            FatBootSector {
                fat_type: FatType::Fat12,
                bytes_per_sector: 512,
                sectors_per_cluster: 2,
                reserved_sectors: 1,
                fat_count: 2,
                root_entries: 512,
                root_cluster: 0,
                total_sectors: 4096,
                sectors_per_fat: 6,
                root_directory_sectors: 32,
                data_start_sector: 45,
                cluster_count: 2025,
            }
        );
    }

    #[test]
    fn parses_fat32_boot_geometry_and_root_cluster() {
        let mut sector = [0u8; SECTOR_SIZE];
        sector[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        sector[13] = 1;
        sector[14..16].copy_from_slice(&32u16.to_le_bytes());
        sector[16] = 2;
        sector[17..19].copy_from_slice(&0u16.to_le_bytes());
        sector[19..21].copy_from_slice(&0u16.to_le_bytes());
        sector[21] = 0xf8;
        sector[22..24].copy_from_slice(&0u16.to_le_bytes());
        sector[32..36].copy_from_slice(&131_072u32.to_le_bytes());
        sector[36..40].copy_from_slice(&1_025u32.to_le_bytes());
        sector[44..48].copy_from_slice(&2u32.to_le_bytes());
        sector[510..512].copy_from_slice(&MBR_SIGNATURE.to_le_bytes());

        assert_eq!(
            parse_fat_boot_sector(&sector).unwrap(),
            FatBootSector {
                fat_type: FatType::Fat32,
                bytes_per_sector: 512,
                sectors_per_cluster: 1,
                reserved_sectors: 32,
                fat_count: 2,
                root_entries: 0,
                root_cluster: 2,
                total_sectors: 131_072,
                sectors_per_fat: 1_025,
                root_directory_sectors: 0,
                data_start_sector: 2_082,
                cluster_count: 128_990,
            }
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeBlockError {
        OutOfRange { lba: u64 },
        InvalidBufferLength { length: usize },
    }

    struct FakeDisk {
        sectors: Vec<[u8; SECTOR_SIZE]>,
    }

    impl BlockDevice for FakeDisk {
        type Error = FakeBlockError;

        fn capacity_sectors(&self) -> u64 {
            self.sectors.len() as u64
        }

        fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
            if buffer.len() != SECTOR_SIZE {
                return Err(FakeBlockError::InvalidBufferLength {
                    length: buffer.len(),
                });
            }
            let sector = self
                .sectors
                .get(lba as usize)
                .ok_or(FakeBlockError::OutOfRange { lba })?;
            buffer.copy_from_slice(sector);
            Ok(())
        }

        fn write_sector(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
            if buffer.len() != SECTOR_SIZE {
                return Err(FakeBlockError::InvalidBufferLength {
                    length: buffer.len(),
                });
            }
            let sector = self
                .sectors
                .get_mut(lba as usize)
                .ok_or(FakeBlockError::OutOfRange { lba })?;
            sector.copy_from_slice(buffer);
            Ok(())
        }
    }

    struct SparseDisk {
        capacity: u64,
        sectors: std::collections::BTreeMap<u64, [u8; SECTOR_SIZE]>,
    }

    impl BlockDevice for SparseDisk {
        type Error = FakeBlockError;

        fn capacity_sectors(&self) -> u64 {
            self.capacity
        }

        fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
            if buffer.len() != SECTOR_SIZE {
                return Err(FakeBlockError::InvalidBufferLength {
                    length: buffer.len(),
                });
            }
            if lba >= self.capacity {
                return Err(FakeBlockError::OutOfRange { lba });
            }
            if let Some(sector) = self.sectors.get(&lba) {
                buffer.copy_from_slice(sector);
            } else {
                buffer.fill(0);
            }
            Ok(())
        }

        fn write_sector(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
            if buffer.len() != SECTOR_SIZE {
                return Err(FakeBlockError::InvalidBufferLength {
                    length: buffer.len(),
                });
            }
            if lba >= self.capacity {
                return Err(FakeBlockError::OutOfRange { lba });
            }
            self.sectors.insert(lba, buffer.try_into().unwrap());
            Ok(())
        }
    }

    fn test_short_name_entry(
        sector: &mut [u8; SECTOR_SIZE],
        offset: usize,
        first_cluster: u16,
        size: u32,
    ) {
        sector[offset..offset + 11].copy_from_slice(b"HELLO   TXT");
        sector[offset + 11] = 0x20;
        sector[offset + 26..offset + 28].copy_from_slice(&first_cluster.to_le_bytes());
        sector[offset + 28..offset + 32].copy_from_slice(&size.to_le_bytes());
    }

    fn test_fat12_volume() -> (FakeDisk, PartitionExtent, FatBootSector) {
        let mut disk = FakeDisk {
            sectors: vec![[0u8; SECTOR_SIZE]; 16],
        };
        let mut boot_sector = [0u8; SECTOR_SIZE];
        boot_sector[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        boot_sector[13] = 1;
        boot_sector[14..16].copy_from_slice(&1u16.to_le_bytes());
        boot_sector[16] = 2;
        boot_sector[17..19].copy_from_slice(&16u16.to_le_bytes());
        boot_sector[19..21].copy_from_slice(&12u16.to_le_bytes());
        boot_sector[21] = 0xf8;
        boot_sector[22..24].copy_from_slice(&1u16.to_le_bytes());
        boot_sector[510..512].copy_from_slice(&MBR_SIGNATURE.to_le_bytes());
        let boot = parse_fat_boot_sector(&boot_sector).unwrap();
        disk.sectors[0] = boot_sector;

        let mut fat = [0u8; SECTOR_SIZE];
        fat[..6].copy_from_slice(&[0xf8, 0xff, 0xff, 0x03, 0xf0, 0xff]);
        disk.sectors[1] = fat;
        disk.sectors[2] = fat;
        test_short_name_entry(&mut disk.sectors[3], 0, 2, 700);
        disk.sectors[3][32] = 0;
        for (index, byte) in disk.sectors[4].iter_mut().enumerate() {
            *byte = index as u8;
        }
        for (index, byte) in disk.sectors[5].iter_mut().enumerate() {
            *byte = (index as u8) ^ 0xa5;
        }

        (
            disk,
            PartitionExtent {
                first_lba: 0,
                sector_count: boot.total_sectors,
            },
            boot,
        )
    }

    fn test_fat16_volume() -> (FakeDisk, PartitionExtent, FatBootSector) {
        let mut disk = FakeDisk {
            sectors: vec![[0u8; SECTOR_SIZE]; 5000],
        };
        let mut boot_sector = [0u8; SECTOR_SIZE];
        boot_sector[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        boot_sector[13] = 1;
        boot_sector[14..16].copy_from_slice(&1u16.to_le_bytes());
        boot_sector[16] = 2;
        boot_sector[17..19].copy_from_slice(&16u16.to_le_bytes());
        boot_sector[19..21].copy_from_slice(&5000u16.to_le_bytes());
        boot_sector[21] = 0xf8;
        boot_sector[22..24].copy_from_slice(&16u16.to_le_bytes());
        boot_sector[510..512].copy_from_slice(&MBR_SIGNATURE.to_le_bytes());
        let boot = parse_fat_boot_sector(&boot_sector).unwrap();
        assert_eq!(boot.fat_type, FatType::Fat16);
        disk.sectors[0] = boot_sector;

        let mut fat = [0u8; SECTOR_SIZE];
        fat[..8].copy_from_slice(&[0xf8, 0xff, 0xff, 0xff, 0x03, 0x00, 0xff, 0xff]);
        for sector in 0..16 {
            disk.sectors[1 + sector] = fat;
            disk.sectors[17 + sector] = fat;
        }
        test_short_name_entry(&mut disk.sectors[33], 0, 2, 8);
        disk.sectors[33][32] = 0;
        disk.sectors[34][..8].copy_from_slice(b"FAT16OK!");

        (
            disk,
            PartitionExtent {
                first_lba: 0,
                sector_count: boot.total_sectors,
            },
            boot,
        )
    }

    fn test_fat32_volume() -> (SparseDisk, PartitionExtent, FatBootSector) {
        let mut disk = SparseDisk {
            capacity: 131_072,
            sectors: std::collections::BTreeMap::new(),
        };
        let mut boot_sector = [0u8; SECTOR_SIZE];
        boot_sector[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        boot_sector[13] = 1;
        boot_sector[14..16].copy_from_slice(&32u16.to_le_bytes());
        boot_sector[16] = 2;
        boot_sector[17..19].copy_from_slice(&0u16.to_le_bytes());
        boot_sector[19..21].copy_from_slice(&0u16.to_le_bytes());
        boot_sector[21] = 0xf8;
        boot_sector[22..24].copy_from_slice(&0u16.to_le_bytes());
        boot_sector[32..36].copy_from_slice(&131_072u32.to_le_bytes());
        boot_sector[36..40].copy_from_slice(&1_025u32.to_le_bytes());
        boot_sector[44..48].copy_from_slice(&2u32.to_le_bytes());
        boot_sector[510..512].copy_from_slice(&MBR_SIGNATURE.to_le_bytes());
        let boot = parse_fat_boot_sector(&boot_sector).unwrap();
        disk.sectors.insert(0, boot_sector);

        let mut fat = [0u8; SECTOR_SIZE];
        fat[0..4].copy_from_slice(&0x0fff_fff8u32.to_le_bytes());
        fat[4..8].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
        fat[8..12].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
        fat[12..16].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
        disk.sectors.insert(32, fat);
        disk.sectors.insert(1_057, fat);

        let mut root = [0u8; SECTOR_SIZE];
        test_short_name_entry(&mut root, 0, 3, 8);
        root[32] = 0;
        disk.sectors.insert(2_082, root);
        let mut data = [0u8; SECTOR_SIZE];
        data[..8].copy_from_slice(b"FAT32OK!");
        disk.sectors.insert(2_083, data);

        (
            disk,
            PartitionExtent {
                first_lba: 0,
                sector_count: boot.total_sectors,
            },
            boot,
        )
    }

    #[test]
    fn mounts_fat12_and_reads_a_root_file_across_clusters() {
        let (disk, partition, boot) = test_fat12_volume();
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let files = filesystem.root_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].short_name, *b"HELLO   TXT");
        let entry = filesystem.find_root_entry(b"HELLO   TXT").unwrap().unwrap();
        assert!(entry.is_regular_file());
        assert_eq!(entry.first_cluster, 2);
        assert_eq!(entry.size, 700);

        let mut contents = [0u8; 300];
        assert_eq!(
            filesystem.read_file_range(entry, 500, &mut contents),
            Ok(200)
        );
        for (index, byte) in contents[..12].iter().copied().enumerate() {
            assert_eq!(byte, (500 + index) as u8);
        }
        for (index, byte) in contents[12..200].iter().copied().enumerate() {
            assert_eq!(byte, (index as u8) ^ 0xa5);
        }
        assert!(contents[200..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn converts_fat_short_names_to_catalog_paths() {
        assert_eq!(
            path_from_short_name(b"SERVICE ELF"),
            Some(b"/SERVICE.ELF".to_vec())
        );
        assert_eq!(
            path_from_short_name(b"KERNEL~1   "),
            Some(b"/KERNEL~1".to_vec())
        );
    }

    #[test]
    fn exposes_fat_root_lookup_and_reads_through_vfs() {
        use crate::vfs::{FileSystem, NodeKind};

        let (disk, partition, boot) = test_fat12_volume();
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let node = filesystem.lookup_path(b"//hello.txt/.").unwrap().unwrap();
        assert_eq!(
            filesystem.metadata(node).unwrap(),
            crate::vfs::Metadata {
                kind: NodeKind::RegularFile,
                size: 700,
            }
        );

        let mut contents = [0u8; 4];
        assert_eq!(filesystem.read(node, 508, &mut contents), Ok(4));
        assert_eq!(&contents, &[252, 253, 254, 255]);
        assert_eq!(filesystem.lookup_path(b"/missing"), Ok(None));
    }

    #[test]
    fn mounts_fat16_and_reads_a_root_file() {
        let (disk, partition, boot) = test_fat16_volume();
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let entry = filesystem.find_root_entry(b"HELLO   TXT").unwrap().unwrap();
        let mut contents = [0u8; 8];
        assert_eq!(filesystem.read_file_range(entry, 0, &mut contents), Ok(8));
        assert_eq!(&contents, b"FAT16OK!");
    }

    #[test]
    fn mounts_fat32_and_writes_a_root_file() {
        let (disk, partition, boot) = test_fat32_volume();
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let entry = filesystem.find_root_entry(b"HELLO   TXT").unwrap().unwrap();
        let mut contents = [0u8; 8];
        assert_eq!(filesystem.read_file_range(entry, 0, &mut contents), Ok(8));
        assert_eq!(&contents, b"FAT32OK!");

        let replacement = *b"RUSTOS!!";
        assert_eq!(filesystem.write_file_range(entry, 0, &replacement), Ok(8));
        let mut readback = [0u8; 8];
        assert_eq!(filesystem.read_file_range(entry, 0, &mut readback), Ok(8));
        assert_eq!(readback, replacement);

        let created = filesystem
            .create_root_file(*b"NEW     TXT", b"FAT32NEW")
            .unwrap();
        let mut created_readback = [0u8; 8];
        assert_eq!(
            filesystem.read_file_range(created, 0, &mut created_readback),
            Ok(8)
        );
        assert_eq!(&created_readback, b"FAT32NEW");
    }

    #[test]
    fn writes_a_bounded_fat12_range_across_clusters() {
        let (disk, partition, boot) = test_fat12_volume();
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let entry = filesystem.find_root_entry(b"HELLO   TXT").unwrap().unwrap();
        let replacement = *b"WRITEOK!";

        assert_eq!(
            filesystem.write_file_range(entry, 508, &replacement),
            Ok(replacement.len())
        );

        let mut contents = [0u8; 8];
        assert_eq!(filesystem.read_file_range(entry, 508, &mut contents), Ok(8));
        assert_eq!(contents, replacement);
    }

    #[test]
    fn writes_a_bounded_fat16_range() {
        let (disk, partition, boot) = test_fat16_volume();
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let entry = filesystem.find_root_entry(b"HELLO   TXT").unwrap().unwrap();
        let replacement = *b"RUSTOS!!";

        assert_eq!(
            filesystem.write_file_range(entry, 0, &replacement),
            Ok(replacement.len())
        );

        let mut contents = [0u8; 8];
        assert_eq!(filesystem.read_file_range(entry, 0, &mut contents), Ok(8));
        assert_eq!(contents, replacement);
    }

    #[test]
    fn creates_and_reads_a_grown_fat12_root_file() {
        let (disk, partition, boot) = test_fat12_volume();
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let contents = vec![0x5a; 700];

        let entry = filesystem
            .create_root_file(*b"NEW     TXT", &contents)
            .unwrap();
        assert_eq!(entry.first_cluster, 4);
        assert_eq!(entry.size, contents.len() as u32);
        assert_eq!(
            filesystem.find_root_entry(b"NEW     TXT").unwrap(),
            Some(entry)
        );
        assert_eq!(filesystem.root_files().unwrap().len(), 2);

        let mut readback = vec![0u8; contents.len()];
        assert_eq!(
            filesystem.read_file_range(entry, 0, &mut readback),
            Ok(contents.len())
        );
        assert_eq!(readback, contents);

        let replacement = vec![0xa5; 1_200];
        assert_eq!(
            filesystem.write_file_contents(entry, &replacement),
            Ok(replacement.len())
        );
        let updated = filesystem.find_root_entry(b"NEW     TXT").unwrap().unwrap();
        assert_eq!(updated.first_cluster, 6);
        assert_eq!(updated.size, replacement.len() as u32);
        let mut updated_readback = vec![0u8; replacement.len()];
        assert_eq!(
            filesystem.read_file_range(updated, 0, &mut updated_readback),
            Ok(replacement.len())
        );
        assert_eq!(updated_readback, replacement);
    }

    #[test]
    fn creates_and_grows_a_fat16_root_file() {
        let (disk, partition, boot) = test_fat16_volume();
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let contents = vec![0x11; 900];

        let entry = filesystem
            .create_root_file(*b"CACHE   BIN", &contents)
            .unwrap();
        assert_eq!(entry.first_cluster, 4);
        assert_eq!(entry.size, contents.len() as u32);
        let mut readback = vec![0u8; contents.len()];
        assert_eq!(
            filesystem.read_file_range(entry, 0, &mut readback),
            Ok(contents.len())
        );
        assert_eq!(readback, contents);

        let empty = filesystem.create_root_file(*b"EMPTY   TXT", &[]).unwrap();
        assert_eq!(empty.first_cluster, 0);
        assert_eq!(empty.size, 0);
        assert_eq!(filesystem.root_files().unwrap().len(), 3);
    }

    #[test]
    fn traverses_creates_and_grows_nested_fat_directories() {
        use crate::vfs::{FileSystem, NodeKind};

        let (disk, partition, boot) = test_fat16_volume();
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        filesystem.create_directory_path(b"/VAR").unwrap();
        filesystem.create_directory_path(b"/VAR/LIB").unwrap();
        let contents = vec![0x3c; 700];
        filesystem
            .create_file_path(b"/VAR/LIB/HELLO.TXT", &contents)
            .unwrap();

        let node = filesystem
            .lookup_path(b"//var/./lib/hello.txt")
            .unwrap()
            .unwrap();
        assert_eq!(
            filesystem.metadata(node).unwrap(),
            crate::vfs::Metadata {
                kind: NodeKind::RegularFile,
                size: contents.len() as u64,
            }
        );
        let mut readback = vec![0u8; contents.len()];
        assert_eq!(filesystem.read(node, 0, &mut readback), Ok(contents.len()));
        assert_eq!(readback, contents);

        let replacement = vec![0xa7; 1_200];
        assert_eq!(
            filesystem.write_file_path(b"/VAR/LIB/HELLO.TXT", &replacement),
            Ok(replacement.len())
        );
        let updated = filesystem
            .lookup_path(b"/VAR/LIB/HELLO.TXT")
            .unwrap()
            .unwrap();
        let mut updated_readback = vec![0u8; replacement.len()];
        assert_eq!(
            filesystem.read(updated, 0, &mut updated_readback),
            Ok(replacement.len())
        );
        assert_eq!(updated_readback, replacement);

        for index in 0..20 {
            let path = format!("/VAR/F{:02}.TXT", index);
            filesystem.create_file_path(path.as_bytes(), b"x").unwrap();
        }
        assert_eq!(
            filesystem.lookup_path(b"/VAR/F19.TXT").unwrap().is_some(),
            true
        );
    }

    #[test]
    fn rejects_writes_outside_the_provisioned_file() {
        let (disk, partition, boot) = test_fat16_volume();
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let entry = filesystem.find_root_entry(b"HELLO   TXT").unwrap().unwrap();

        assert_eq!(
            filesystem.write_file_range(entry, 4, b"too long"),
            Err(FatFileSystemError::FileWriteOutOfBounds {
                offset: 4,
                length: 8,
                size: 8,
            })
        );
    }

    #[test]
    fn rejects_short_or_looping_fat_cluster_chains() {
        let (mut disk, partition, boot) = test_fat12_volume();
        disk.sectors[1][3] = 0;
        disk.sectors[2][3] = 0;
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let entry = filesystem.find_root_entry(b"HELLO   TXT").unwrap().unwrap();
        let mut contents = [0u8; 700];
        assert_eq!(
            filesystem.read_file_range(entry, 0, &mut contents),
            Err(FatFileSystemError::InvalidCluster { cluster: 0 })
        );

        let (mut disk, partition, boot) = test_fat12_volume();
        disk.sectors[1][4] = 0x20;
        disk.sectors[1][5] = 0;
        disk.sectors[2][4] = 0x20;
        disk.sectors[2][5] = 0;
        let mut filesystem = FatFileSystem::mount(disk, partition, boot).unwrap();
        let mut entry = filesystem.find_root_entry(b"HELLO   TXT").unwrap().unwrap();
        entry.size = 5000;
        let mut contents = [0u8; 5000];
        assert_eq!(
            filesystem.read_file_range(entry, 0, &mut contents),
            Err(FatFileSystemError::ClusterChainLoop)
        );
    }
}
