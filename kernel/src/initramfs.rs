//! Bounded parser for the POSIX `newc` initramfs format.
//!
//! The boot disk carries the archive as one FAT root file. Keeping the parser independent from
//! FAT lets the kernel expose normal nested paths to the process loader and gives later package
//! and recovery code a stable archive boundary.

pub const NEWC_HEADER_SIZE: usize = 110;
pub const MAX_ARCHIVE_SIZE: usize = 384 * 1024;
pub const MAX_ENTRIES: usize = 32;
pub const MAX_PATH_LENGTH: usize = 63;

const NEWC_MAGIC: &[u8; 6] = b"070701";
const TRAILER_NAME: &[u8] = b"TRAILER!!!";
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    ArchiveTooLarge { size: usize },
    TruncatedHeader { offset: usize },
    InvalidMagic { offset: usize },
    InvalidHexField { offset: usize },
    InvalidName,
    NameTooLong { length: usize },
    NameNotTerminated { offset: usize },
    DataOutOfBounds { offset: usize, size: usize },
    EntryLimitExceeded { max_entries: usize },
    MissingTrailer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mode: u32,
}

impl Entry<'_> {
    pub const fn is_regular_file(self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
}

/// Visit every archive record, stopping at the required `TRAILER!!!` record.
pub fn for_each_entry<F>(archive: &[u8], mut visit: F) -> Result<usize, Error>
where
    F: FnMut(Entry<'_>) -> Result<(), Error>,
{
    if archive.len() > MAX_ARCHIVE_SIZE {
        return Err(Error::ArchiveTooLarge {
            size: archive.len(),
        });
    }

    let mut offset = 0;
    let mut entries = 0;
    loop {
        if offset == archive.len() {
            return Err(Error::MissingTrailer);
        }
        let header_end = offset
            .checked_add(NEWC_HEADER_SIZE)
            .ok_or(Error::TruncatedHeader { offset })?;
        if header_end > archive.len() {
            return Err(Error::TruncatedHeader { offset });
        }
        if &archive[offset..offset + NEWC_MAGIC.len()] != NEWC_MAGIC {
            return Err(Error::InvalidMagic { offset });
        }

        let mode = read_hex(archive, offset + 14)?;
        let file_size = read_hex(archive, offset + 54)? as usize;
        let name_size = read_hex(archive, offset + 94)? as usize;
        if name_size == 0 {
            return Err(Error::InvalidName);
        }

        let name_end = header_end
            .checked_add(name_size)
            .ok_or(Error::NameTooLong { length: name_size })?;
        if name_end > archive.len() {
            return Err(Error::NameTooLong { length: name_size });
        }
        if archive[name_end - 1] != 0 {
            return Err(Error::NameNotTerminated { offset: header_end });
        }
        let name = &archive[header_end..name_end - 1];
        if name == TRAILER_NAME {
            return Ok(entries);
        }
        validate_name(name)?;

        let data_start = align4(name_end).ok_or(Error::DataOutOfBounds {
            offset: name_end,
            size: file_size,
        })?;
        let data_end = data_start
            .checked_add(file_size)
            .ok_or(Error::DataOutOfBounds {
                offset: data_start,
                size: file_size,
            })?;
        if data_end > archive.len() {
            return Err(Error::DataOutOfBounds {
                offset: data_start,
                size: file_size,
            });
        }
        if entries == MAX_ENTRIES {
            return Err(Error::EntryLimitExceeded {
                max_entries: MAX_ENTRIES,
            });
        }
        visit(Entry {
            name,
            data: &archive[data_start..data_end],
            mode,
        })?;
        entries += 1;
        offset = align4(data_end).ok_or(Error::DataOutOfBounds {
            offset: data_end,
            size: 0,
        })?;
        if offset > archive.len() {
            return Err(Error::DataOutOfBounds {
                offset: data_end,
                size: 0,
            });
        }
    }
}

fn read_hex(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset
        .checked_add(8)
        .ok_or(Error::InvalidHexField { offset })?;
    let field = bytes
        .get(offset..end)
        .ok_or(Error::InvalidHexField { offset })?;
    let mut value = 0u32;
    for byte in field.iter().copied() {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(Error::InvalidHexField { offset }),
        };
        value = value
            .checked_mul(16)
            .and_then(|value| value.checked_add(u32::from(digit)))
            .ok_or(Error::InvalidHexField { offset })?;
    }
    Ok(value)
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn validate_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty() || name.len() > MAX_PATH_LENGTH || name[0] == b'/' {
        return if name.len() > MAX_PATH_LENGTH {
            Err(Error::NameTooLong { length: name.len() })
        } else {
            Err(Error::InvalidName)
        };
    }
    let mut component_start = 0;
    for index in 0..=name.len() {
        if index != name.len() && name[index] != b'/' {
            continue;
        }
        let component = &name[component_start..index];
        if component.is_empty() || component == b"." || component == b".." {
            return Err(Error::InvalidName);
        }
        if component.iter().any(|byte| !(0x21..=0x7e).contains(byte)) {
            return Err(Error::InvalidName);
        }
        component_start = index + 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(mode: u32, size: usize, name_size: usize) -> [u8; NEWC_HEADER_SIZE] {
        let mut header = [b'0'; NEWC_HEADER_SIZE];
        header[..6].copy_from_slice(NEWC_MAGIC);
        write_hex(&mut header, 14, mode);
        write_hex(&mut header, 54, size as u32);
        write_hex(&mut header, 94, name_size as u32);
        header
    }

    fn write_hex(bytes: &mut [u8], offset: usize, value: u32) {
        for index in 0..8 {
            let shift = (7 - index) * 4;
            let digit = ((value >> shift) & 0xf) as u8;
            bytes[offset + index] = if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            };
        }
    }

    fn archive_with_file(name: &[u8], data: &[u8]) -> [u8; 256] {
        let mut archive = [0u8; 256];
        let mut offset = 0;
        let mut record = header(0o100755, data.len(), name.len() + 1);
        archive[offset..offset + NEWC_HEADER_SIZE].copy_from_slice(&record);
        offset += NEWC_HEADER_SIZE;
        archive[offset..offset + name.len()].copy_from_slice(name);
        offset += name.len();
        archive[offset] = 0;
        offset = align4(offset + 1).unwrap();
        archive[offset..offset + data.len()].copy_from_slice(data);
        offset = align4(offset + data.len()).unwrap();
        record = header(0, 0, TRAILER_NAME.len() + 1);
        archive[offset..offset + NEWC_HEADER_SIZE].copy_from_slice(&record);
        offset += NEWC_HEADER_SIZE;
        archive[offset..offset + TRAILER_NAME.len()].copy_from_slice(TRAILER_NAME);
        archive[offset + TRAILER_NAME.len()] = 0;
        archive
    }

    #[test]
    fn parses_regular_file_and_trailer() {
        let archive = archive_with_file(b"sbin/init", b"ELF");
        let count = for_each_entry(&archive, |entry| {
            assert!(entry.is_regular_file());
            assert_eq!(entry.name, b"sbin/init");
            assert_eq!(entry.data, b"ELF");
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn rejects_unsafe_nested_names() {
        let archive = archive_with_file(b"../init", b"ELF");
        assert_eq!(
            for_each_entry(&archive, |_| Ok(())),
            Err(Error::InvalidName)
        );
    }

    #[test]
    fn rejects_missing_trailer() {
        let archive = archive_with_file(b"sbin/init", b"ELF");
        assert_eq!(
            for_each_entry(&archive[..124], |_| Ok(())),
            Err(Error::MissingTrailer)
        );
    }
}
