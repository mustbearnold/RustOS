#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub const NVIDIA_GSP_MAX_FIRMWARE_SIZE: usize = 128 * 1024 * 1024;
pub const NVIDIA_GSP_ELF_HEADER_SIZE: usize = 64;
pub const NVIDIA_GSP_ELF_SECTION_HEADER_SIZE: usize = 64;
pub const NVIDIA_GSP_MAX_SECTIONS: usize = 128;
pub const NVIDIA_GSP_PAGE_SIZE: usize = 4096;
pub const NVIDIA_GSP_MAX_MESSAGE_PAGES: usize = 16;
pub const NVIDIA_GSP_MESSAGE_HEADER_SIZE: usize = 48;
pub const NVIDIA_GSP_RPC_HEADER_SIZE: usize = 32;
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
}
