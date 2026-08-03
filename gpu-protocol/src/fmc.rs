use super::FirmwareSection;

pub const NVIDIA_GSP_FMC_MAX_SIZE: usize = 4 * 1024 * 1024;
pub const NVIDIA_GSP_FMC_ELF_HEADER_SIZE: usize = 52;
pub const NVIDIA_GSP_FMC_ELF_SECTION_HEADER_SIZE: usize = 40;
pub const NVIDIA_GSP_FMC_SECTION_COUNT: usize = 6;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELF_CLASS_32: u8 = 1;
const ELF_DATA_LITTLE: u8 = 1;
const ELF_VERSION_CURRENT: u8 = 1;
const ELF_TYPE_NONE: u16 = 0;
const ELF_MACHINE_NONE: u16 = 0;
const ELF_VERSION_CURRENT_U32: u32 = 1;
const ELF_SECTION_PROGBITS: u32 = 1;
const ELF_SECTION_STRTAB: u32 = 3;
const ELF_STRING_FLAGS: u32 = 0x20;
const FMC_SECTION_FLAGS: u32 = 0xfff0_0102;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspFmcRequiredSection {
    Hash,
    Signature,
    PublicKey,
    Image,
}

impl GspFmcRequiredSection {
    pub const fn name(self) -> &'static [u8] {
        match self {
            Self::Hash => b"hash",
            Self::Signature => b"signature",
            Self::PublicKey => b"publickey",
            Self::Image => b"image",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspFmcError {
    TooLarge {
        size: usize,
        limit: usize,
    },
    Truncated {
        offset: usize,
        size: usize,
    },
    InvalidHeader,
    InvalidSectionTable,
    InvalidSection {
        index: usize,
    },
    InvalidStringTable,
    InvalidSectionName {
        index: usize,
    },
    InvalidSectionCrc {
        index: usize,
        expected: u32,
        actual: u32,
    },
    MissingSection {
        section: GspFmcRequiredSection,
    },
    DuplicateSection {
        section: GspFmcRequiredSection,
    },
    EmptySection {
        section: GspFmcRequiredSection,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspFmc {
    pub hash: FirmwareSection,
    pub signature: FirmwareSection,
    pub public_key: FirmwareSection,
    pub image: FirmwareSection,
    pub section_count: usize,
}

impl GspFmc {
    pub fn parse(bytes: &[u8]) -> Result<Self, GspFmcError> {
        if bytes.len() > NVIDIA_GSP_FMC_MAX_SIZE {
            return Err(GspFmcError::TooLarge {
                size: bytes.len(),
                limit: NVIDIA_GSP_FMC_MAX_SIZE,
            });
        }
        if bytes.len() < NVIDIA_GSP_FMC_ELF_HEADER_SIZE {
            return Err(GspFmcError::Truncated {
                offset: 0,
                size: NVIDIA_GSP_FMC_ELF_HEADER_SIZE,
            });
        }
        if bytes[..4] != ELF_MAGIC
            || bytes[4] != ELF_CLASS_32
            || bytes[5] != ELF_DATA_LITTLE
            || bytes[6] != ELF_VERSION_CURRENT
            || bytes[7] != 0
            || bytes[8..16].iter().any(|byte| *byte != 0)
            || read_u16(bytes, 16)? != ELF_TYPE_NONE
            || read_u16(bytes, 18)? != ELF_MACHINE_NONE
            || read_u32(bytes, 20)? != ELF_VERSION_CURRENT_U32
            || read_u32(bytes, 24)? != 0
            || read_u32(bytes, 28)? != 0
            || read_u32(bytes, 36)? != 0
            || read_u16(bytes, 40)? != NVIDIA_GSP_FMC_ELF_HEADER_SIZE as u16
            || read_u16(bytes, 42)? != 0
            || read_u16(bytes, 44)? != 0
            || read_u16(bytes, 46)? != NVIDIA_GSP_FMC_ELF_SECTION_HEADER_SIZE as u16
            || read_u16(bytes, 48)? != NVIDIA_GSP_FMC_SECTION_COUNT as u16
            || read_u16(bytes, 50)? != 1
        {
            return Err(GspFmcError::InvalidHeader);
        }

        let section_table_offset =
            usize::try_from(read_u32(bytes, 32)?).map_err(|_| GspFmcError::InvalidSectionTable)?;
        let section_table_size = NVIDIA_GSP_FMC_SECTION_COUNT
            .checked_mul(NVIDIA_GSP_FMC_ELF_SECTION_HEADER_SIZE)
            .ok_or(GspFmcError::InvalidSectionTable)?;
        let section_table_end = section_table_offset
            .checked_add(section_table_size)
            .ok_or(GspFmcError::InvalidSectionTable)?;
        if section_table_end > bytes.len() {
            return Err(GspFmcError::InvalidSectionTable);
        }

        let string_record = section_record(bytes, section_table_offset, 1)?;
        if string_record.kind != ELF_SECTION_STRTAB || string_record.flags != ELF_STRING_FLAGS {
            return Err(GspFmcError::InvalidStringTable);
        }
        validate_section_range(bytes, section_table_end, 1, string_record.section)?;
        let strings = string_record.section.bytes(bytes);

        let mut required = [None; 4];
        for index in 1..NVIDIA_GSP_FMC_SECTION_COUNT {
            let record = section_record(bytes, section_table_offset, index)?;
            validate_section_range(bytes, section_table_end, index, record.section)?;
            if index != 1
                && (record.kind != ELF_SECTION_PROGBITS || record.flags != FMC_SECTION_FLAGS)
            {
                return Err(GspFmcError::InvalidSection { index });
            }
            if record.info != 0 {
                let actual = crc32(record.section.bytes(bytes));
                if record.info != actual {
                    return Err(GspFmcError::InvalidSectionCrc {
                        index,
                        expected: record.info,
                        actual,
                    });
                }
            }
            let name = section_name(strings, record.name_offset)
                .ok_or(GspFmcError::InvalidSectionName { index })?;
            let Some(section) = required_section(name) else {
                continue;
            };
            let slot = section_slot(section);
            if required[slot].is_some() {
                return Err(GspFmcError::DuplicateSection { section });
            }
            required[slot] = Some(record.section);
        }

        let hash = required_section_or_error(required[0], GspFmcRequiredSection::Hash)?;
        let signature = required_section_or_error(required[1], GspFmcRequiredSection::Signature)?;
        let public_key = required_section_or_error(required[2], GspFmcRequiredSection::PublicKey)?;
        let image = required_section_or_error(required[3], GspFmcRequiredSection::Image)?;
        Ok(Self {
            hash,
            signature,
            public_key,
            image,
            section_count: NVIDIA_GSP_FMC_SECTION_COUNT,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SectionRecord {
    name_offset: usize,
    kind: u32,
    flags: u32,
    info: u32,
    section: FirmwareSection,
}

fn section_record(
    bytes: &[u8],
    table_offset: usize,
    index: usize,
) -> Result<SectionRecord, GspFmcError> {
    let offset = table_offset
        .checked_add(
            index
                .checked_mul(NVIDIA_GSP_FMC_ELF_SECTION_HEADER_SIZE)
                .ok_or(GspFmcError::InvalidSectionTable)?,
        )
        .ok_or(GspFmcError::InvalidSectionTable)?;
    let name_offset = usize::try_from(read_u32(bytes, offset)?)
        .map_err(|_| GspFmcError::InvalidSection { index })?;
    let kind = read_u32(bytes, offset + 4)?;
    let flags = read_u32(bytes, offset + 8)?;
    let section_offset = usize::try_from(read_u32(bytes, offset + 16)?)
        .map_err(|_| GspFmcError::InvalidSection { index })?;
    let section_size = usize::try_from(read_u32(bytes, offset + 20)?)
        .map_err(|_| GspFmcError::InvalidSection { index })?;
    let info = read_u32(bytes, offset + 28)?;
    Ok(SectionRecord {
        name_offset,
        kind,
        flags,
        info,
        section: FirmwareSection {
            offset: section_offset,
            size: section_size,
        },
    })
}

fn validate_section_range(
    bytes: &[u8],
    section_table_end: usize,
    index: usize,
    section: FirmwareSection,
) -> Result<(), GspFmcError> {
    if section.offset < section_table_end
        || section
            .offset
            .checked_add(section.size)
            .is_none_or(|end| end > bytes.len())
    {
        return Err(GspFmcError::InvalidSection { index });
    }
    Ok(())
}

fn section_name(strings: &[u8], offset: usize) -> Option<&[u8]> {
    let bytes = strings.get(offset..)?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    Some(&bytes[..end])
}

fn required_section(name: &[u8]) -> Option<GspFmcRequiredSection> {
    [
        GspFmcRequiredSection::Hash,
        GspFmcRequiredSection::Signature,
        GspFmcRequiredSection::PublicKey,
        GspFmcRequiredSection::Image,
    ]
    .into_iter()
    .find(|section| name == section.name())
}

const fn section_slot(section: GspFmcRequiredSection) -> usize {
    match section {
        GspFmcRequiredSection::Hash => 0,
        GspFmcRequiredSection::Signature => 1,
        GspFmcRequiredSection::PublicKey => 2,
        GspFmcRequiredSection::Image => 3,
    }
}

fn required_section_or_error(
    section: Option<FirmwareSection>,
    required: GspFmcRequiredSection,
) -> Result<FirmwareSection, GspFmcError> {
    let section = section.ok_or(GspFmcError::MissingSection { section: required })?;
    if section.size == 0 {
        return Err(GspFmcError::EmptySection { section: required });
    }
    Ok(section)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, GspFmcError> {
    let end = offset
        .checked_add(2)
        .ok_or(GspFmcError::Truncated { offset, size: 2 })?;
    let value = bytes
        .get(offset..end)
        .ok_or(GspFmcError::Truncated { offset, size: 2 })?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, GspFmcError> {
    let end = offset
        .checked_add(4)
        .ok_or(GspFmcError::Truncated { offset, size: 4 })?;
    let value = bytes
        .get(offset..end)
        .ok_or(GspFmcError::Truncated { offset, size: 4 })?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut value = !0u32;
    for &byte in bytes {
        value ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(value & 1);
            value = (value >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !value
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    const STRING_TABLE: &[u8] = b"\0.shstrtab\0hash\0signature\0publickey\0image\0";
    const SECTION_TABLE_OFFSET: usize = NVIDIA_GSP_FMC_ELF_HEADER_SIZE;
    const SECTION_DATA_OFFSET: usize = SECTION_TABLE_OFFSET
        + NVIDIA_GSP_FMC_SECTION_COUNT * NVIDIA_GSP_FMC_ELF_SECTION_HEADER_SIZE;
    const HASH: &[u8] = b"hash-bytes";
    const SIGNATURE: &[u8] = b"signature-bytes";
    const PUBLIC_KEY: &[u8] = b"public-key-bytes";
    const IMAGE: &[u8] = b"fmc-image";

    fn synthetic_fmc() -> Vec<u8> {
        let string_offset = SECTION_DATA_OFFSET;
        let hash_offset = string_offset + STRING_TABLE.len();
        let signature_offset = hash_offset + HASH.len();
        let public_key_offset = signature_offset + SIGNATURE.len();
        let image_offset = public_key_offset + PUBLIC_KEY.len();
        let mut bytes = vec![0u8; image_offset + IMAGE.len()];
        bytes[..4].copy_from_slice(&ELF_MAGIC);
        bytes[4] = ELF_CLASS_32;
        bytes[5] = ELF_DATA_LITTLE;
        bytes[6] = ELF_VERSION_CURRENT;
        write_u16(&mut bytes, 16, ELF_TYPE_NONE);
        write_u16(&mut bytes, 18, ELF_MACHINE_NONE);
        write_u32(&mut bytes, 20, ELF_VERSION_CURRENT_U32);
        write_u32(&mut bytes, 32, SECTION_TABLE_OFFSET as u32);
        write_u16(&mut bytes, 40, NVIDIA_GSP_FMC_ELF_HEADER_SIZE as u16);
        write_u16(
            &mut bytes,
            46,
            NVIDIA_GSP_FMC_ELF_SECTION_HEADER_SIZE as u16,
        );
        write_u16(&mut bytes, 48, NVIDIA_GSP_FMC_SECTION_COUNT as u16);
        write_u16(&mut bytes, 50, 1);
        bytes[string_offset..string_offset + STRING_TABLE.len()].copy_from_slice(STRING_TABLE);
        bytes[hash_offset..hash_offset + HASH.len()].copy_from_slice(HASH);
        bytes[signature_offset..signature_offset + SIGNATURE.len()].copy_from_slice(SIGNATURE);
        bytes[public_key_offset..public_key_offset + PUBLIC_KEY.len()].copy_from_slice(PUBLIC_KEY);
        bytes[image_offset..image_offset + IMAGE.len()].copy_from_slice(IMAGE);
        section(
            &mut bytes,
            1,
            1,
            ELF_SECTION_STRTAB,
            ELF_STRING_FLAGS,
            string_offset,
            STRING_TABLE.len(),
            0,
        );
        section(
            &mut bytes,
            2,
            11,
            ELF_SECTION_PROGBITS,
            FMC_SECTION_FLAGS,
            hash_offset,
            HASH.len(),
            crc32(HASH),
        );
        section(
            &mut bytes,
            3,
            16,
            ELF_SECTION_PROGBITS,
            FMC_SECTION_FLAGS,
            signature_offset,
            SIGNATURE.len(),
            crc32(SIGNATURE),
        );
        section(
            &mut bytes,
            4,
            26,
            ELF_SECTION_PROGBITS,
            FMC_SECTION_FLAGS,
            public_key_offset,
            PUBLIC_KEY.len(),
            crc32(PUBLIC_KEY),
        );
        section(
            &mut bytes,
            5,
            36,
            ELF_SECTION_PROGBITS,
            FMC_SECTION_FLAGS,
            image_offset,
            IMAGE.len(),
            crc32(IMAGE),
        );
        bytes
    }

    fn section(
        bytes: &mut [u8],
        index: usize,
        name: u32,
        kind: u32,
        flags: u32,
        offset: usize,
        size: usize,
        info: u32,
    ) {
        let base = SECTION_TABLE_OFFSET + index * NVIDIA_GSP_FMC_ELF_SECTION_HEADER_SIZE;
        write_u32(bytes, base, name);
        write_u32(bytes, base + 4, kind);
        write_u32(bytes, base + 8, flags);
        write_u32(bytes, base + 16, offset as u32);
        write_u32(bytes, base + 20, size as u32);
        write_u32(bytes, base + 28, info);
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parses_signed_gb20x_fmc_sections_and_crc32() {
        let bytes = synthetic_fmc();
        let fmc = GspFmc::parse(&bytes).expect("fmc");
        assert_eq!(fmc.section_count, NVIDIA_GSP_FMC_SECTION_COUNT);
        assert_eq!(fmc.hash.bytes(&bytes), HASH);
        assert_eq!(fmc.signature.bytes(&bytes), SIGNATURE);
        assert_eq!(fmc.public_key.bytes(&bytes), PUBLIC_KEY);
        assert_eq!(fmc.image.bytes(&bytes), IMAGE);
    }

    #[test]
    fn rejects_fmc_section_crc_tampering() {
        let mut bytes = synthetic_fmc();
        bytes[SECTION_DATA_OFFSET + STRING_TABLE.len()] ^= 1;
        assert!(matches!(
            GspFmc::parse(&bytes),
            Err(GspFmcError::InvalidSectionCrc { index: 2, .. })
        ));
    }

    #[test]
    fn rejects_an_fmc_that_is_not_the_exact_expected_elf32_shape() {
        let mut bytes = synthetic_fmc();
        write_u16(&mut bytes, 48, 5);
        assert_eq!(GspFmc::parse(&bytes), Err(GspFmcError::InvalidHeader));
    }
}
