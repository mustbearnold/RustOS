use core::slice;

const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
const RSDP_V1_LENGTH: usize = 20;
const RSDP_V2_LENGTH: usize = 36;
const ACPI_HEADER_LENGTH: usize = 36;
const MAX_TABLE_LENGTH: usize = 1024 * 1024;
pub const MAX_PROCESSORS: usize = 256;
pub const MAX_LEGACY_IRQS: usize = 16;
const FADT_DSDT_OFFSET: usize = 40;
const FADT_FIRMWARE_CONTROL_OFFSET: usize = 36;
const FADT_PM1A_EVENT_BLOCK_OFFSET: usize = 56;
const FADT_PM1B_EVENT_BLOCK_OFFSET: usize = 60;
const FADT_PM1A_CONTROL_BLOCK_OFFSET: usize = 64;
const FADT_PM1B_CONTROL_BLOCK_OFFSET: usize = 68;
const FADT_PM1_EVENT_LENGTH_OFFSET: usize = 88;
const FADT_PM1_CONTROL_LENGTH_OFFSET: usize = 89;
const FADT_RESET_REGISTER_OFFSET: usize = 116;
const FADT_RESET_VALUE_OFFSET: usize = 128;
const FADT_X_FIRMWARE_CONTROL_OFFSET: usize = 132;
const FADT_X_DSDT_OFFSET: usize = 140;
const FACS_LENGTH_OFFSET: usize = 4;
const FACS_VERSION_OFFSET: usize = 32;
const FACS_MINIMUM_LENGTH: usize = FACS_VERSION_OFFSET + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    MissingRsdp,
    InvalidRsdpAddress,
    InvalidRsdpSignature,
    InvalidRsdpChecksum,
    InvalidRsdpLength,
    MissingRootTable,
    InvalidRootTable,
    InvalidRootEntries,
    MissingMadt,
    InvalidMadt,
    InvalidMadtEntry,
    TooManyProcessors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcpiInfo {
    pub revision: u8,
    pub rsdp_address: u64,
    pub root_table_address: u64,
    pub madt_address: u64,
    pub fadt_address: Option<u64>,
    pub local_apic_address: u64,
    pub processor_count: u32,
    pub enabled_processor_count: u32,
    pub processors: [ProcessorInfo; MAX_PROCESSORS],
    pub io_apic_count: u32,
    pub io_apic: Option<IoApicInfo>,
    pub timer_gsi: u32,
    pub timer_flags: u16,
    pub interrupt_overrides: [Option<InterruptOverride>; MAX_LEGACY_IRQS],
    pub power: Option<AcpiPowerInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessorInfo {
    pub uid: u32,
    pub apic_id: u32,
    pub enabled: bool,
    pub x2apic: bool,
}

const EMPTY_PROCESSOR: ProcessorInfo = ProcessorInfo {
    uid: 0,
    apic_id: 0,
    enabled: false,
    x2apic: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicInfo {
    pub id: u8,
    pub address: u64,
    pub gsi_base: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptOverride {
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcpiPowerInfo {
    pub facs_address: Option<u64>,
    pub facs_length: u32,
    pub facs_version: u8,
    pub pm1a_event_block: u32,
    pub pm1b_event_block: u32,
    pub pm1_event_length: u8,
    pub pm1a_control_block: u32,
    pub pm1b_control_block: u32,
    pub pm1_control_length: u8,
    pub sleep_type_a: u16,
    pub sleep_type_b: u16,
    pub sleep_type_s3: Option<(u16, u16)>,
    pub reset_register: Option<AcpiResetRegister>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcpiResetRegister {
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
    pub value: u8,
}

impl AcpiInfo {
    pub fn legacy_irq_route(&self, irq: u8) -> Option<(u32, u16)> {
        let override_entry = self.interrupt_overrides.get(usize::from(irq))?;
        Some(
            override_entry
                .map(|entry| (entry.gsi, entry.flags))
                .unwrap_or((u32::from(irq), 0)),
        )
    }
}

#[derive(Clone, Copy)]
pub struct PhysicalMemory {
    offset: u64,
}

impl PhysicalMemory {
    pub const fn new(offset: u64) -> Self {
        Self { offset }
    }

    pub fn virtual_address(self, physical_address: u64) -> Option<u64> {
        self.offset.checked_add(physical_address)
    }

    fn read(self, physical_address: u64, length: usize) -> Option<&'static [u8]> {
        let virtual_address = self.virtual_address(physical_address)?;
        let length = u64::try_from(length).ok()?;
        virtual_address.checked_add(length)?;
        // SAFETY: the bootloader maps physical memory at `offset`; callers only request bounded
        // ACPI structures reported by firmware and the returned slice is read-only.
        Some(unsafe { slice::from_raw_parts(virtual_address as *const u8, length as usize) })
    }
}

pub fn discover(memory: PhysicalMemory, rsdp_address: Option<u64>) -> Result<AcpiInfo, AcpiError> {
    let rsdp_address = rsdp_address.ok_or(AcpiError::MissingRsdp)?;
    let rsdp_v1 = memory
        .read(rsdp_address, RSDP_V1_LENGTH)
        .ok_or(AcpiError::InvalidRsdpAddress)?;
    if rsdp_v1.get(..8) != Some(RSDP_SIGNATURE.as_slice()) {
        return Err(AcpiError::InvalidRsdpSignature);
    }
    if !checksum_is_valid(rsdp_v1) {
        return Err(AcpiError::InvalidRsdpChecksum);
    }

    let revision = *rsdp_v1.get(15).ok_or(AcpiError::InvalidRsdpLength)?;
    let (root_table_address, entry_size) = if revision >= 2 {
        let rsdp_v2 = memory
            .read(rsdp_address, RSDP_V2_LENGTH)
            .ok_or(AcpiError::InvalidRsdpAddress)?;
        let length = read_u32(rsdp_v2, 20).ok_or(AcpiError::InvalidRsdpLength)? as usize;
        if !(RSDP_V2_LENGTH..=MAX_TABLE_LENGTH).contains(&length) {
            return Err(AcpiError::InvalidRsdpLength);
        }
        let full_rsdp = memory
            .read(rsdp_address, length)
            .ok_or(AcpiError::InvalidRsdpAddress)?;
        if !checksum_is_valid(full_rsdp) {
            return Err(AcpiError::InvalidRsdpChecksum);
        }
        (
            read_u64(full_rsdp, 24).ok_or(AcpiError::InvalidRsdpLength)?,
            8,
        )
    } else {
        (
            u64::from(read_u32(rsdp_v1, 16).ok_or(AcpiError::InvalidRsdpLength)?),
            4,
        )
    };

    if root_table_address == 0 {
        return Err(AcpiError::MissingRootTable);
    }
    let root = load_table(memory, root_table_address).map_err(|_| AcpiError::InvalidRootTable)?;
    let expected_signature = if entry_size == 8 { b"XSDT" } else { b"RSDT" };
    if root.get(..4) != Some(expected_signature.as_slice()) {
        return Err(AcpiError::InvalidRootTable);
    }
    let entries = root
        .get(ACPI_HEADER_LENGTH..)
        .ok_or(AcpiError::InvalidRootEntries)?;
    if entries.len() % entry_size != 0 {
        return Err(AcpiError::InvalidRootEntries);
    }

    let mut madt_address = None;
    let mut fadt_address = None;
    for entry in entries.chunks_exact(entry_size) {
        let table_address = if entry_size == 8 {
            u64::from_le_bytes(
                entry
                    .try_into()
                    .map_err(|_| AcpiError::InvalidRootEntries)?,
            )
        } else {
            u64::from(u32::from_le_bytes(
                entry
                    .try_into()
                    .map_err(|_| AcpiError::InvalidRootEntries)?,
            ))
        };
        if table_address == 0 {
            continue;
        }
        let table = load_table(memory, table_address).map_err(|_| AcpiError::InvalidRootTable)?;
        if table.get(..4) == Some(b"APIC".as_slice()) {
            madt_address = Some(table_address);
        } else if table.get(..4) == Some(b"FACP".as_slice()) {
            fadt_address = Some(table_address);
        }
    }

    let madt_address = madt_address.ok_or(AcpiError::MissingMadt)?;
    let madt = load_table(memory, madt_address).map_err(|_| AcpiError::InvalidMadt)?;
    let madt_info = parse_madt(madt)?;
    let power = fadt_address.and_then(|address| parse_power_info(memory, address));
    Ok(AcpiInfo {
        revision,
        rsdp_address,
        root_table_address,
        madt_address,
        fadt_address,
        local_apic_address: madt_info.local_apic_address,
        processor_count: madt_info.processor_count,
        enabled_processor_count: madt_info.enabled_processor_count,
        processors: madt_info.processors,
        io_apic_count: madt_info.io_apic_count,
        io_apic: madt_info.io_apic,
        timer_gsi: madt_info.timer_gsi,
        timer_flags: madt_info.timer_flags,
        interrupt_overrides: madt_info.interrupt_overrides,
        power,
    })
}

fn parse_power_info(memory: PhysicalMemory, fadt_address: u64) -> Option<AcpiPowerInfo> {
    let fadt = load_table(memory, fadt_address).ok()?;
    let facs_address = read_u64(fadt, FADT_X_FIRMWARE_CONTROL_OFFSET)
        .filter(|address| *address != 0)
        .or_else(|| {
            read_u32(fadt, FADT_FIRMWARE_CONTROL_OFFSET)
                .filter(|address| *address != 0)
                .map(u64::from)
        });
    let (facs_address, facs_length, facs_version) = facs_address
        .and_then(|address| parse_facs(memory, address))
        .map(|(address, length, version)| (Some(address), length, version))
        .unwrap_or((None, 0, 0));
    let pm1a_event_block = read_u32(fadt, FADT_PM1A_EVENT_BLOCK_OFFSET).unwrap_or(0);
    let pm1b_event_block = read_u32(fadt, FADT_PM1B_EVENT_BLOCK_OFFSET).unwrap_or(0);
    let pm1a_control_block = read_u32(fadt, FADT_PM1A_CONTROL_BLOCK_OFFSET)?;
    let pm1b_control_block = read_u32(fadt, FADT_PM1B_CONTROL_BLOCK_OFFSET)?;
    let pm1_event_length = *fadt.get(FADT_PM1_EVENT_LENGTH_OFFSET)?;
    let pm1_control_length = *fadt.get(FADT_PM1_CONTROL_LENGTH_OFFSET)?;
    if pm1a_control_block == 0 || pm1_control_length < 2 {
        return None;
    }

    let dsdt_address = read_u64(fadt, FADT_X_DSDT_OFFSET)
        .filter(|address| *address != 0)
        .or_else(|| read_u32(fadt, FADT_DSDT_OFFSET).map(u64::from))?;
    let dsdt = load_table(memory, dsdt_address).ok()?;
    let (sleep_type_a, sleep_type_b) = parse_s5_sleep_types(dsdt)?;
    Some(AcpiPowerInfo {
        facs_address,
        facs_length,
        facs_version,
        pm1a_event_block,
        pm1b_event_block,
        pm1_event_length,
        pm1a_control_block,
        pm1b_control_block,
        pm1_control_length,
        sleep_type_a,
        sleep_type_b,
        sleep_type_s3: parse_sleep_types(dsdt, 3),
        reset_register: parse_reset_register(fadt),
    })
}

fn parse_facs(memory: PhysicalMemory, physical_address: u64) -> Option<(u64, u32, u8)> {
    let header = memory.read(physical_address, FACS_MINIMUM_LENGTH)?;
    if header.get(..4) != Some(b"FACS".as_slice()) {
        return None;
    }
    let length = read_u32(header, FACS_LENGTH_OFFSET)?;
    let length_usize = usize::try_from(length).ok()?;
    if !(FACS_MINIMUM_LENGTH..=MAX_TABLE_LENGTH).contains(&length_usize) {
        return None;
    }
    let facs = memory.read(physical_address, length_usize)?;
    Some((physical_address, length, *facs.get(FACS_VERSION_OFFSET)?))
}

fn parse_reset_register(fadt: &[u8]) -> Option<AcpiResetRegister> {
    let gas = fadt.get(FADT_RESET_REGISTER_OFFSET..FADT_RESET_VALUE_OFFSET)?;
    let register = AcpiResetRegister {
        address_space: *gas.first()?,
        bit_width: *gas.get(1)?,
        bit_offset: *gas.get(2)?,
        access_size: *gas.get(3)?,
        address: read_u64(gas, 4)?,
        value: *fadt.get(FADT_RESET_VALUE_OFFSET)?,
    };
    (register.address_space == 1
        && register.bit_width >= 8
        && register.bit_offset == 0
        && register.address != 0)
        .then_some(register)
}

fn parse_s5_sleep_types(dsdt: &[u8]) -> Option<(u16, u16)> {
    parse_sleep_types(dsdt, 5)
}

fn parse_sleep_types(dsdt: &[u8], state: u8) -> Option<(u16, u16)> {
    if state > 9 {
        return None;
    }
    let aml = dsdt.get(ACPI_HEADER_LENGTH..)?;
    let name = [0x08, b'_', b'S', b'0' + state, b'_'];
    let mut search_offset = 0;
    while search_offset + name.len() <= aml.len() {
        let relative = aml[search_offset..]
            .windows(name.len())
            .position(|window| window == name)?;
        let name_offset = search_offset + relative;
        let package_offset = name_offset.checked_add(name.len())?;
        if aml.get(package_offset) == Some(&0x12) {
            let package_bytes = aml.get(package_offset + 1..)?;
            let (package_length, package_length_bytes) = parse_aml_package_length(package_bytes)?;
            let package_end = package_offset.checked_add(1)?.checked_add(package_length)?;
            if package_end <= aml.len() {
                let elements = package_offset
                    .checked_add(1)?
                    .checked_add(package_length_bytes)?;
                let element_count = *aml.get(elements)?;
                if element_count >= 2 {
                    let first = parse_aml_integer(aml.get(elements + 1..)?)?;
                    let second = parse_aml_integer(aml.get(elements + 1 + first.1..)?)?;
                    if first.0 <= 7 && second.0 <= 7 {
                        return Some((first.0, second.0));
                    }
                }
            }
        }
        search_offset = name_offset + 1;
    }
    None
}

fn parse_aml_package_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    let follow_count = usize::from((first >> 6) & 0x03);
    let mut length = usize::from(first & 0x3f);
    for index in 0..follow_count {
        let shift = 4usize.checked_add(index.checked_mul(8)?)?;
        length |= usize::from(*bytes.get(index + 1)?) << shift;
    }
    Some((length, follow_count + 1))
}

fn parse_aml_integer(bytes: &[u8]) -> Option<(u16, usize)> {
    match *bytes.first()? {
        0x00 => Some((0, 1)),
        0x01 => Some((1, 1)),
        0x0a => Some((u16::from(*bytes.get(1)?), 2)),
        0x0b => Some((u16::from_le_bytes(bytes.get(1..3)?.try_into().ok()?), 3)),
        0x0c => {
            let value = read_u32(bytes, 1)?;
            u16::try_from(value).ok().map(|value| (value, 5))
        }
        0x0e => {
            let value = read_u64(bytes, 1)?;
            u16::try_from(value).ok().map(|value| (value, 9))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MadtInfo {
    local_apic_address: u64,
    processor_count: u32,
    enabled_processor_count: u32,
    processors: [ProcessorInfo; MAX_PROCESSORS],
    io_apic_count: u32,
    io_apic: Option<IoApicInfo>,
    timer_gsi: u32,
    timer_flags: u16,
    interrupt_overrides: [Option<InterruptOverride>; MAX_LEGACY_IRQS],
}

fn parse_madt(table: &[u8]) -> Result<MadtInfo, AcpiError> {
    if table.get(..4) != Some(b"APIC".as_slice())
        || table.len() < ACPI_HEADER_LENGTH + 8
        || !checksum_is_valid(table)
    {
        return Err(AcpiError::InvalidMadt);
    }

    let mut local_apic_address =
        u64::from(read_u32(table, ACPI_HEADER_LENGTH).ok_or(AcpiError::InvalidMadt)?);
    let mut processor_count = 0;
    let mut enabled_processor_count = 0;
    let mut processors = [EMPTY_PROCESSOR; MAX_PROCESSORS];
    let mut io_apic_count = 0;
    let mut io_apic = None;
    let mut timer_gsi = 0;
    let mut timer_flags = 0;
    let mut interrupt_overrides = [None; MAX_LEGACY_IRQS];
    let mut offset = ACPI_HEADER_LENGTH + 8;

    while offset < table.len() {
        let entry_type = *table.get(offset).ok_or(AcpiError::InvalidMadtEntry)?;
        let entry_length = usize::from(*table.get(offset + 1).ok_or(AcpiError::InvalidMadtEntry)?);
        if entry_length < 2 || offset + entry_length > table.len() {
            return Err(AcpiError::InvalidMadtEntry);
        }

        match entry_type {
            0 if entry_length >= 8 => {
                let processor_index =
                    usize::try_from(processor_count).map_err(|_| AcpiError::TooManyProcessors)?;
                if processor_index >= MAX_PROCESSORS {
                    return Err(AcpiError::TooManyProcessors);
                }
                let uid = u32::from(*table.get(offset + 2).ok_or(AcpiError::InvalidMadtEntry)?);
                let apic_id = u32::from(*table.get(offset + 3).ok_or(AcpiError::InvalidMadtEntry)?);
                let flags = read_u32(table, offset + 4).ok_or(AcpiError::InvalidMadtEntry)?;
                let enabled = flags & 1 != 0;
                processors[processor_index] = ProcessorInfo {
                    uid,
                    apic_id,
                    enabled,
                    x2apic: false,
                };
                processor_count += 1;
                if enabled {
                    enabled_processor_count += 1;
                }
            }
            1 if entry_length >= 12 => {
                io_apic_count += 1;
                if io_apic.is_none() {
                    io_apic = Some(IoApicInfo {
                        id: *table.get(offset + 2).ok_or(AcpiError::InvalidMadtEntry)?,
                        address: u64::from(
                            read_u32(table, offset + 4).ok_or(AcpiError::InvalidMadtEntry)?,
                        ),
                        gsi_base: read_u32(table, offset + 8).ok_or(AcpiError::InvalidMadtEntry)?,
                    });
                }
            }
            2 if entry_length >= 10 => {
                let bus = *table.get(offset + 2).ok_or(AcpiError::InvalidMadtEntry)?;
                let source = *table.get(offset + 3).ok_or(AcpiError::InvalidMadtEntry)?;
                if bus == 0 {
                    let gsi = read_u32(table, offset + 4).ok_or(AcpiError::InvalidMadtEntry)?;
                    let flags = u16::from_le_bytes(
                        table
                            .get(offset + 8..offset + 10)
                            .ok_or(AcpiError::InvalidMadtEntry)?
                            .try_into()
                            .map_err(|_| AcpiError::InvalidMadtEntry)?,
                    );
                    if let Some(entry) = interrupt_overrides.get_mut(usize::from(source)) {
                        *entry = Some(InterruptOverride { source, gsi, flags });
                    }
                    if source == 0 {
                        timer_gsi = gsi;
                        timer_flags = flags;
                    }
                }
            }
            5 if entry_length >= 12 => {
                local_apic_address =
                    read_u64(table, offset + 4).ok_or(AcpiError::InvalidMadtEntry)?;
            }
            9 if entry_length >= 16 => {
                let processor_index =
                    usize::try_from(processor_count).map_err(|_| AcpiError::TooManyProcessors)?;
                if processor_index >= MAX_PROCESSORS {
                    return Err(AcpiError::TooManyProcessors);
                }
                let uid = read_u32(table, offset + 4).ok_or(AcpiError::InvalidMadtEntry)?;
                let apic_id = read_u32(table, offset + 8).ok_or(AcpiError::InvalidMadtEntry)?;
                let flags = read_u32(table, offset + 12).ok_or(AcpiError::InvalidMadtEntry)?;
                let enabled = flags & 1 != 0;
                processors[processor_index] = ProcessorInfo {
                    uid,
                    apic_id,
                    enabled,
                    x2apic: true,
                };
                processor_count += 1;
                if enabled {
                    enabled_processor_count += 1;
                }
            }
            _ => {}
        }
        offset += entry_length;
    }

    if local_apic_address == 0 {
        return Err(AcpiError::InvalidMadt);
    }
    Ok(MadtInfo {
        local_apic_address,
        processor_count,
        enabled_processor_count,
        processors,
        io_apic_count,
        io_apic,
        timer_gsi,
        timer_flags,
        interrupt_overrides,
    })
}

fn load_table(memory: PhysicalMemory, physical_address: u64) -> Result<&'static [u8], AcpiError> {
    let header = memory
        .read(physical_address, ACPI_HEADER_LENGTH)
        .ok_or(AcpiError::InvalidRootTable)?;
    let length = read_u32(header, 4).ok_or(AcpiError::InvalidRootTable)? as usize;
    if !(ACPI_HEADER_LENGTH..=MAX_TABLE_LENGTH).contains(&length) {
        return Err(AcpiError::InvalidRootTable);
    }
    let table = memory
        .read(physical_address, length)
        .ok_or(AcpiError::InvalidRootTable)?;
    if !checksum_is_valid(table) {
        return Err(AcpiError::InvalidRootTable);
    }
    Ok(table)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn checksum_is_valid(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .fold(0u8, |checksum, byte| checksum.wrapping_add(*byte))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_madt_processor_and_io_apic_records() {
        let mut table = [0u8; 74];
        table[0..4].copy_from_slice(b"APIC");
        let table_length = table.len() as u32;
        table[4..8].copy_from_slice(&table_length.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[40..44].copy_from_slice(&1u32.to_le_bytes());

        table[44] = 0;
        table[45] = 8;
        table[48] = 1;

        table[52] = 1;
        table[53] = 12;
        table[54] = 1;
        table[56..60].copy_from_slice(&0xfec0_0000u32.to_le_bytes());

        table[64] = 2;
        table[65] = 10;
        table[67] = 11;
        table[68..72].copy_from_slice(&11u32.to_le_bytes());
        table[72..74].copy_from_slice(&0x000du16.to_le_bytes());

        table[9] = 0u8.wrapping_sub(
            table
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != 9)
                .fold(0u8, |sum, (_, byte)| sum.wrapping_add(*byte)),
        );
        let info = parse_madt(&table).unwrap();
        assert_eq!(info.local_apic_address, 0xfee0_0000);
        assert_eq!(info.processor_count, 1);
        assert_eq!(info.enabled_processor_count, 1);
        assert_eq!(info.io_apic_count, 1);
        assert_eq!(
            info.io_apic,
            Some(IoApicInfo {
                id: 1,
                address: 0xfec0_0000,
                gsi_base: 0,
            })
        );
        assert_eq!(info.timer_gsi, 0);
        assert_eq!(info.timer_flags, 0);
        assert_eq!(
            info.interrupt_overrides[11],
            Some(InterruptOverride {
                source: 11,
                gsi: 11,
                flags: 0x000d,
            })
        );
        assert_eq!(info.interrupt_overrides[5], None);
    }

    #[test]
    fn rejects_bad_checksums_and_malformed_entries() {
        let mut table = [0u8; 52];
        table[0..4].copy_from_slice(b"APIC");
        let table_length = table.len() as u32;
        table[4..8].copy_from_slice(&table_length.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[44] = 0;
        table[45] = 1;
        assert_eq!(parse_madt(&table), Err(AcpiError::InvalidMadt));

        table[45] = 8;
        assert_eq!(parse_madt(&table), Err(AcpiError::InvalidMadt));
    }

    #[test]
    fn parses_x2apic_processor_identity_and_flags() {
        let mut table = [0u8; 60];
        table[0..4].copy_from_slice(b"APIC");
        let table_length = table.len() as u32;
        table[4..8].copy_from_slice(&table_length.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());

        table[44] = 9;
        table[45] = 16;
        table[48..52].copy_from_slice(&7u32.to_le_bytes());
        table[52..56].copy_from_slice(&0x1234u32.to_le_bytes());
        table[56..60].copy_from_slice(&1u32.to_le_bytes());
        table[9] = 0u8.wrapping_sub(
            table
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != 9)
                .fold(0u8, |sum, (_, byte)| sum.wrapping_add(*byte)),
        );

        let info = parse_madt(&table).unwrap();
        assert_eq!(info.processor_count, 1);
        assert_eq!(info.enabled_processor_count, 1);
        assert_eq!(
            info.processors[0],
            ProcessorInfo {
                uid: 7,
                apic_id: 0x1234,
                enabled: true,
                x2apic: true,
            }
        );
    }

    #[test]
    fn resolves_legacy_irq_routes_with_overrides() {
        let mut interrupt_overrides = [None; MAX_LEGACY_IRQS];
        interrupt_overrides[11] = Some(InterruptOverride {
            source: 11,
            gsi: 19,
            flags: 0x000d,
        });
        let info = AcpiInfo {
            revision: 2,
            rsdp_address: 0,
            root_table_address: 0,
            madt_address: 0,
            fadt_address: None,
            local_apic_address: 0xfee0_0000,
            processor_count: 0,
            enabled_processor_count: 0,
            processors: [EMPTY_PROCESSOR; MAX_PROCESSORS],
            io_apic_count: 1,
            io_apic: Some(IoApicInfo {
                id: 0,
                address: 0xfec0_0000,
                gsi_base: 0,
            }),
            timer_gsi: 2,
            timer_flags: 0,
            interrupt_overrides,
            power: None,
        };

        assert_eq!(info.legacy_irq_route(11), Some((19, 0x000d)));
        assert_eq!(info.legacy_irq_route(5), Some((5, 0)));
        assert_eq!(info.legacy_irq_route(16), None);
    }

    #[test]
    fn parses_acpi_s5_sleep_package() {
        let aml = [
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x0a, 0x07, 0x0a, 0x07,
        ];
        let mut dsdt = [0u8; ACPI_HEADER_LENGTH + 12];
        let dsdt_length = dsdt.len() as u32;
        dsdt[0..4].copy_from_slice(b"DSDT");
        dsdt[4..8].copy_from_slice(&dsdt_length.to_le_bytes());
        dsdt[ACPI_HEADER_LENGTH..].copy_from_slice(&aml);
        dsdt[9] = 0u8.wrapping_sub(
            dsdt.iter()
                .enumerate()
                .filter(|(index, _)| *index != 9)
                .fold(0u8, |sum, (_, byte)| sum.wrapping_add(*byte)),
        );

        assert_eq!(parse_s5_sleep_types(&dsdt), Some((7, 7)));
    }

    #[test]
    fn parses_acpi_s3_sleep_package() {
        let aml = [
            0x08, b'_', b'S', b'3', b'_', 0x12, 0x06, 0x02, 0x0a, 0x05, 0x0a, 0x05,
        ];
        let mut dsdt = [0u8; ACPI_HEADER_LENGTH + 12];
        let dsdt_length = dsdt.len() as u32;
        dsdt[0..4].copy_from_slice(b"DSDT");
        dsdt[4..8].copy_from_slice(&dsdt_length.to_le_bytes());
        dsdt[ACPI_HEADER_LENGTH..].copy_from_slice(&aml);
        dsdt[9] = 0u8.wrapping_sub(
            dsdt.iter()
                .enumerate()
                .filter(|(index, _)| *index != 9)
                .fold(0u8, |sum, (_, byte)| sum.wrapping_add(*byte)),
        );

        assert_eq!(parse_sleep_types(&dsdt, 3), Some((5, 5)));
    }

    #[test]
    fn parses_system_io_reset_register_from_fadt() {
        let mut fadt = [0u8; FADT_RESET_VALUE_OFFSET + 1];
        fadt[FADT_RESET_REGISTER_OFFSET] = 1;
        fadt[FADT_RESET_REGISTER_OFFSET + 1] = 8;
        fadt[FADT_RESET_REGISTER_OFFSET + 3] = 1;
        fadt[FADT_RESET_REGISTER_OFFSET + 4..FADT_RESET_REGISTER_OFFSET + 12]
            .copy_from_slice(&0xcf9u64.to_le_bytes());
        fadt[FADT_RESET_VALUE_OFFSET] = 0x06;

        assert_eq!(
            parse_reset_register(&fadt),
            Some(AcpiResetRegister {
                address_space: 1,
                bit_width: 8,
                bit_offset: 0,
                access_size: 1,
                address: 0xcf9,
                value: 0x06,
            })
        );
    }

    #[test]
    fn parses_versioned_facs_with_bounded_length() {
        let mut facs = [0u8; 64];
        let facs_length = facs.len() as u32;
        facs[0..4].copy_from_slice(b"FACS");
        facs[FACS_LENGTH_OFFSET..FACS_LENGTH_OFFSET + 4]
            .copy_from_slice(&facs_length.to_le_bytes());
        facs[FACS_VERSION_OFFSET] = 2;

        let physical_memory = PhysicalMemory::new(facs.as_ptr() as u64);
        assert_eq!(parse_facs(physical_memory, 0), Some((0, facs_length, 2)));
    }

    #[test]
    fn rejects_facs_with_invalid_signature_or_length() {
        let mut facs = [0u8; FACS_MINIMUM_LENGTH];
        facs[FACS_LENGTH_OFFSET..FACS_LENGTH_OFFSET + 4]
            .copy_from_slice(&(FACS_MINIMUM_LENGTH as u32 - 1).to_le_bytes());
        let physical_memory = PhysicalMemory::new(facs.as_ptr() as u64);
        assert_eq!(parse_facs(physical_memory, 0), None);

        facs[FACS_LENGTH_OFFSET..FACS_LENGTH_OFFSET + 4]
            .copy_from_slice(&(FACS_MINIMUM_LENGTH as u32).to_le_bytes());
        facs[0..4].copy_from_slice(b"FACS");
        assert_eq!(
            parse_facs(physical_memory, 0),
            Some((0, FACS_MINIMUM_LENGTH as u32, 0))
        );

        facs[0..4].copy_from_slice(b"NOPE");
        assert_eq!(parse_facs(physical_memory, 0), None);
    }
}
