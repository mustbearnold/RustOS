use sha2::{Digest, Sha256};

pub const MAX_ACCOUNTS: usize = 4;
pub const ACCOUNT_USERNAME_LENGTH: usize = 16;
pub const ACCOUNT_RECORD_LENGTH: usize = 128;
pub const ACCOUNT_DATABASE_LENGTH: usize = MAX_ACCOUNTS * ACCOUNT_RECORD_LENGTH;
pub const ACCOUNT_SEED_PATH: &[u8] = b"/etc/rustos/accounts\0";
pub const ACCOUNT_STORE_PATH: &[u8] = b"/VAR/RUSTOS/ACCOUNTS\0";

#[derive(Clone, Copy)]
pub struct Account {
    pub username: [u8; ACCOUNT_USERNAME_LENGTH],
    pub username_length: usize,
    pub uid: u64,
    pub gid: u64,
    pub password_digest: [u8; 32],
}

impl Account {
    const EMPTY: Self = Self {
        username: [0; ACCOUNT_USERNAME_LENGTH],
        username_length: 0,
        uid: 0,
        gid: 0,
        password_digest: [0; 32],
    };

    pub fn username(&self) -> &[u8] {
        &self.username[..self.username_length]
    }
}

#[derive(Clone, Copy)]
pub struct AccountStore {
    pub accounts: [Account; MAX_ACCOUNTS],
    pub count: usize,
}

impl AccountStore {
    pub const fn empty() -> Self {
        Self {
            accounts: [Account::EMPTY; MAX_ACCOUNTS],
            count: 0,
        }
    }

    pub fn find_username(&self, username: &[u8]) -> Option<Account> {
        self.accounts[..self.count]
            .iter()
            .copied()
            .find(|account| account.username() == username)
    }

    pub fn find_uid(&self, uid: u64, gid: u64) -> Option<Account> {
        self.accounts[..self.count]
            .iter()
            .copied()
            .find(|account| account.uid == uid && account.gid == gid)
    }
}

pub fn update_password(
    store: &mut AccountStore,
    uid: u64,
    old_digest: &[u8; 32],
    new_digest: [u8; 32],
) -> bool {
    let Some(account) = store.accounts[..store.count]
        .iter_mut()
        .find(|account| account.uid == uid && account.password_digest == *old_digest)
    else {
        return false;
    };
    account.password_digest = new_digest;
    true
}

pub fn verify_password(store: &AccountStore, uid: u64, digest: &[u8; 32]) -> bool {
    store.accounts[..store.count]
        .iter()
        .any(|account| account.uid == uid && account.password_digest == *digest)
}

pub fn add_account(
    store: &mut AccountStore,
    username: &[u8],
    uid: u64,
    gid: u64,
    password_digest: [u8; 32],
) -> bool {
    if store.count >= MAX_ACCOUNTS
        || username.is_empty()
        || username.len() > ACCOUNT_USERNAME_LENGTH
        || !valid_username(username)
        || !(1000..=u32::MAX as u64).contains(&uid)
        || !(1000..=u32::MAX as u64).contains(&gid)
        || store.accounts[..store.count].iter().any(|account| {
            account.username() == username || account.uid == uid || account.gid == gid
        })
    {
        return false;
    }
    let mut account = Account::EMPTY;
    account.username[..username.len()].copy_from_slice(username);
    account.username_length = username.len();
    account.uid = uid;
    account.gid = gid;
    account.password_digest = password_digest;
    store.accounts[store.count] = account;
    store.count += 1;
    true
}

pub fn parse(bytes: &[u8]) -> Option<AccountStore> {
    let mut store = AccountStore::empty();
    let mut cursor = 0;
    while cursor < bytes.len() {
        while cursor < bytes.len() && (bytes[cursor] == 0 || bytes[cursor] == b'\n') {
            cursor += 1;
        }
        if cursor == bytes.len() {
            break;
        }
        let end = bytes[cursor..]
            .iter()
            .position(|byte| *byte == 0 || *byte == b'\n')
            .map_or(bytes.len(), |offset| cursor + offset);
        let account = parse_record(&bytes[cursor..end])?;
        if store.count == MAX_ACCOUNTS
            || store.accounts[..store.count].iter().any(|existing| {
                existing.username() == account.username() || existing.uid == account.uid
            })
        {
            return None;
        }
        store.accounts[store.count] = account;
        store.count += 1;
        cursor = end;
    }
    (store.count != 0).then_some(store)
}

pub fn serialize(store: &AccountStore, output: &mut [u8; ACCOUNT_DATABASE_LENGTH]) -> bool {
    output.fill(0);
    if store.count == 0 || store.count > MAX_ACCOUNTS {
        return false;
    }
    for (index, account) in store.accounts[..store.count].iter().enumerate() {
        let mut record = [0u8; ACCOUNT_RECORD_LENGTH];
        let mut length = 0;
        if !append_bytes(&mut record, &mut length, account.username())
            || !append_byte(&mut record, &mut length, b'|')
            || !append_number(&mut record, &mut length, account.uid)
            || !append_byte(&mut record, &mut length, b'|')
            || !append_number(&mut record, &mut length, account.gid)
            || !append_byte(&mut record, &mut length, b'|')
        {
            return false;
        }
        for byte in account.password_digest {
            if !append_byte(&mut record, &mut length, hex_digit(byte >> 4))
                || !append_byte(&mut record, &mut length, hex_digit(byte & 0x0f))
            {
                return false;
            }
        }
        if !append_byte(&mut record, &mut length, b'\n') {
            return false;
        }
        let start = index * ACCOUNT_RECORD_LENGTH;
        output[start..start + length].copy_from_slice(&record[..length]);
    }
    true
}

pub fn password_digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

fn parse_record(record: &[u8]) -> Option<Account> {
    let first = record.iter().position(|byte| *byte == b'|')?;
    let second = record[first + 1..]
        .iter()
        .position(|byte| *byte == b'|')?
        .checked_add(first + 1)?;
    let third = record[second + 1..]
        .iter()
        .position(|byte| *byte == b'|')?
        .checked_add(second + 1)?;
    if first == 0
        || first > ACCOUNT_USERNAME_LENGTH
        || !valid_username(&record[..first])
        || third + 1 >= record.len()
        || record[third + 1..].contains(&b'|')
    {
        return None;
    }
    let uid = parse_number(&record[first + 1..second])?;
    let gid = parse_number(&record[second + 1..third])?;
    if !(1000..=u32::MAX as u64).contains(&uid) || !(1000..=u32::MAX as u64).contains(&gid) {
        return None;
    }
    let digest_bytes = &record[third + 1..];
    if digest_bytes.len() != 64 {
        return None;
    }
    let mut account = Account {
        username: [0; ACCOUNT_USERNAME_LENGTH],
        username_length: first,
        uid,
        gid,
        password_digest: [0; 32],
    };
    account.username[..first].copy_from_slice(&record[..first]);
    for (index, pair) in digest_bytes.chunks_exact(2).enumerate() {
        account.password_digest[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(account)
}

pub fn valid_username(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_uppercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'-' | b'.')
    })
}

fn parse_number(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for byte in bytes.iter().copied() {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    }
}

fn append_byte(record: &mut [u8; ACCOUNT_RECORD_LENGTH], length: &mut usize, byte: u8) -> bool {
    if *length >= record.len() {
        return false;
    }
    record[*length] = byte;
    *length += 1;
    true
}

fn append_bytes(
    record: &mut [u8; ACCOUNT_RECORD_LENGTH],
    length: &mut usize,
    bytes: &[u8],
) -> bool {
    if bytes.len() > record.len().saturating_sub(*length) {
        return false;
    }
    record[*length..*length + bytes.len()].copy_from_slice(bytes);
    *length += bytes.len();
    true
}

fn append_number(
    record: &mut [u8; ACCOUNT_RECORD_LENGTH],
    length: &mut usize,
    mut value: u64,
) -> bool {
    let mut digits = [0u8; 20];
    let mut count = 0;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for digit in digits[..count].iter().rev().copied() {
        if !append_byte(record, length, digit) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &[u8] =
        b"user|1000|1000|38007df7107968c330e766fe0710bbcece10071a9713f90dd77348d16f57baa5\n";

    #[test]
    fn parses_and_round_trips_fixed_database() {
        let store = parse(USER).unwrap();
        assert_eq!(store.count, 1);
        assert_eq!(store.accounts[0].username(), b"user");
        assert_eq!(store.accounts[0].uid, 1000);
        let mut bytes = [0u8; ACCOUNT_DATABASE_LENGTH];
        assert!(serialize(&store, &mut bytes));
        assert_eq!(
            parse(&bytes).unwrap().accounts[0].password_digest,
            store.accounts[0].password_digest
        );
    }

    #[test]
    fn accepts_multiple_distinct_accounts_and_rejects_duplicates() {
        let mut bytes = [0u8; ACCOUNT_DATABASE_LENGTH];
        let first = USER;
        let second =
            b"alice|1001|1001|38007df7107968c330e766fe0710bbcece10071a9713f90dd77348d16f57baa5\n";
        bytes[..first.len()].copy_from_slice(first);
        bytes[first.len()..first.len() + second.len()].copy_from_slice(second);
        let store = parse(&bytes).unwrap();
        assert_eq!(store.count, 2);
        assert!(store.find_username(b"alice").is_some());

        let duplicate =
            b"user|1001|1001|38007df7107968c330e766fe0710bbcece10071a9713f90dd77348d16f57baa5\n";
        assert!(parse(duplicate).is_some());
        let mut invalid = [0u8; ACCOUNT_DATABASE_LENGTH];
        invalid[..first.len()].copy_from_slice(first);
        invalid[first.len()..first.len() + duplicate.len()].copy_from_slice(duplicate);
        assert!(parse(&invalid).is_none());
    }

    #[test]
    fn hashes_passwords_with_sha256() {
        assert_eq!(
            password_digest(b"rustos"),
            [
                0x38, 0x00, 0x7d, 0xf7, 0x10, 0x79, 0x68, 0xc3, 0x30, 0xe7, 0x66, 0xfe, 0x07, 0x10,
                0xbb, 0xce, 0xce, 0x10, 0x07, 0x1a, 0x97, 0x13, 0xf9, 0x0d, 0xd7, 0x73, 0x48, 0xd1,
                0x6f, 0x57, 0xba, 0xa5,
            ]
        );
    }

    #[test]
    fn updates_only_the_account_with_the_matching_old_password() {
        let mut store = parse(USER).unwrap();
        let old = password_digest(b"rustos");
        let next = password_digest(b"daily-use");
        assert!(update_password(&mut store, 1000, &old, next));
        assert_eq!(store.accounts[0].password_digest, next);
        assert!(!update_password(
            &mut store,
            1000,
            &old,
            password_digest(b"other")
        ));
    }

    #[test]
    fn adds_and_authenticates_a_distinct_account() {
        let mut store = parse(USER).unwrap();
        let digest = password_digest(b"alice-pass");
        assert!(add_account(&mut store, b"alice", 1001, 1001, digest));
        assert_eq!(store.count, 2);
        assert!(verify_password(&store, 1001, &digest));
        assert!(!verify_password(&store, 1000, &digest));
        assert!(!add_account(
            &mut store,
            b"alice",
            1002,
            1002,
            password_digest(b"other")
        ));
        assert!(!add_account(
            &mut store,
            b"bad/name",
            1002,
            1002,
            password_digest(b"other")
        ));
    }
}
