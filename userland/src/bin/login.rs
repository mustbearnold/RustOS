#![no_std]
#![no_main]

use rustos_userland::{
    SYSCALL_ENOENT,
    accounts::{
        ACCOUNT_DATABASE_LENGTH, ACCOUNT_STORE_PATH, AccountStore, add_account, parse,
        password_digest, serialize, valid_username,
    },
    close, exit, is_syscall_error, mkdir, open, open_create_write, read, spawn_as, waitpid, write,
    write_stdout, yield_now,
};

const STDIN_FD: u64 = 0;
const ACCOUNT_BUFFER_LENGTH: usize = ACCOUNT_DATABASE_LENGTH;
const USERNAME_BUFFER_LENGTH: usize = 32;
const PASSWORD_BUFFER_LENGTH: usize = 64;
const WRITE_CHUNK_LENGTH: usize = 256;
const FIRST_ACCOUNT_UID: u64 = 1000;
const FIRST_ACCOUNT_GID: u64 = 1000;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let Some(mut accounts) = load_or_bootstrap_accounts() else {
        write_stdout(b"login: account database unavailable\n");
        exit(1);
    };

    write_stdout(b"RustOS login\n");
    let mut skip_lf = false;
    let mut session_number = 0usize;
    loop {
        write_stdout(b"login: ");
        let mut username = [0u8; USERNAME_BUFFER_LENGTH];
        let username_length = read_line(&mut username, true, &mut skip_lf);
        if username_length == 0 {
            continue;
        }

        write_stdout(b"login: username selected name=");
        write_stdout(&username[..username_length]);
        write_stdout(b" status=ready\n");

        write_stdout(b"password: ");
        let mut password = [0u8; PASSWORD_BUFFER_LENGTH];
        let password_length = read_line(&mut password, false, &mut skip_lf);
        write_stdout(b"\n");

        let authenticated =
            accounts
                .find_username(&username[..username_length])
                .filter(|account| {
                    password_digest(&password[..password_length]) == account.password_digest
                });
        if let Some(account) = authenticated {
            write_stdout(b"login: authentication ok\n");
            write_stdout(b"login: authenticated username=");
            write_stdout(account.username());
            write_stdout(b" status=ready\n");
            session_number = session_number.saturating_add(1);
            write_stdout(b"login: session authenticated number=");
            write_decimal(session_number);
            write_stdout(b" status=ready\n");
            let pid = spawn_as(b"/bin/desktop\0", account.uid, account.gid);
            if is_syscall_error(pid) {
                write_stdout(b"login: session start failed\n");
                continue;
            }
            let result = waitpid(pid);
            if result.pid == pid {
                write_stdout(b"login: session exited status=ready\n");
                write_stdout(b"login: ready for next session status=ready\n");
            } else {
                write_stdout(b"login: session wait failed\n");
            }
            if let Some(updated) = read_store() {
                accounts = updated;
            }
        } else {
            write_stdout(b"login: authentication failed\n");
        }
    }
}

fn load_or_bootstrap_accounts() -> Option<AccountStore> {
    match read_store() {
        Some(accounts) => {
            write_stdout(b"login: account store loaded status=ready\n");
            Some(accounts)
        }
        None if store_missing() => {
            write_stdout(b"login: account store setup required status=ready\n");
            let accounts = setup_first_account()?;
            if !write_store(&accounts) {
                return None;
            }
            let verified = read_store()?;
            write_stdout(b"login: account store bootstrapped status=ready\n");
            Some(verified)
        }
        None => {
            write_stdout(b"login: account store invalid\n");
            None
        }
    }
}

fn store_missing() -> bool {
    let handle = open(ACCOUNT_STORE_PATH);
    if handle == SYSCALL_ENOENT {
        return true;
    }
    if !is_syscall_error(handle) {
        let _ = close(handle);
    }
    false
}

fn read_store() -> Option<AccountStore> {
    read_account_file(ACCOUNT_STORE_PATH)
}

fn read_account_file(path: &[u8]) -> Option<AccountStore> {
    let handle = open(path);
    if is_syscall_error(handle) {
        return None;
    }
    let mut bytes = [0u8; ACCOUNT_BUFFER_LENGTH];
    let mut length = 0usize;
    let mut valid = true;
    while length < bytes.len() {
        let end = (length + WRITE_CHUNK_LENGTH).min(bytes.len());
        let count = read(handle, &mut bytes[length..end]);
        if is_syscall_error(count) {
            valid = false;
            break;
        }
        let count = count as usize;
        if count == 0 {
            break;
        }
        length = length.saturating_add(count).min(bytes.len());
    }
    let _ = close(handle);
    if !valid {
        return None;
    }
    parse(&bytes[..length])
}

fn write_store(accounts: &AccountStore) -> bool {
    let _ = mkdir(b"/VAR\0");
    let _ = mkdir(b"/VAR/RUSTOS\0");
    let mut bytes = [0u8; ACCOUNT_DATABASE_LENGTH];
    if !serialize(accounts, &mut bytes) {
        return false;
    }
    let handle = open_create_write(ACCOUNT_STORE_PATH);
    if is_syscall_error(handle) {
        return false;
    }
    let mut offset = 0;
    let mut success = true;
    while offset < bytes.len() {
        let end = (offset + WRITE_CHUNK_LENGTH).min(bytes.len());
        let count = write(handle, &bytes[offset..end]);
        if is_syscall_error(count) || count != (end - offset) as u64 {
            success = false;
            break;
        }
        offset = end;
    }
    if is_syscall_error(close(handle)) {
        success = false;
    }
    success
}

fn setup_first_account() -> Option<AccountStore> {
    let mut skip_lf = false;
    loop {
        let mut username = [0u8; USERNAME_BUFFER_LENGTH];
        write_stdout(b"login: setup username prompt=ready\n");
        write_stdout(b"login: new username: ");
        let username_length = read_line(&mut username, true, &mut skip_lf);
        if username_length == 0
            || username_length > rustos_userland::accounts::ACCOUNT_USERNAME_LENGTH
            || !valid_username(&username[..username_length])
        {
            write_stdout(b"login: username invalid\n");
            continue;
        }

        let mut password = [0u8; PASSWORD_BUFFER_LENGTH];
        write_stdout(b"login: setup password prompt=ready\n");
        write_stdout(b"login: new password: ");
        let password_length = read_line(&mut password, false, &mut skip_lf);
        write_stdout(b"\n");
        if password_length == 0 {
            write_stdout(b"login: password cannot be empty\n");
            continue;
        }

        let mut confirmation = [0u8; PASSWORD_BUFFER_LENGTH];
        write_stdout(b"login: setup confirm prompt=ready\n");
        write_stdout(b"login: retype password: ");
        let confirmation_length = read_line(&mut confirmation, false, &mut skip_lf);
        write_stdout(b"\n");
        if password_length != confirmation_length
            || password[..password_length] != confirmation[..confirmation_length]
        {
            write_stdout(b"login: passwords do not match\n");
            continue;
        }

        let mut accounts = AccountStore::empty();
        if !add_account(
            &mut accounts,
            &username[..username_length],
            FIRST_ACCOUNT_UID,
            FIRST_ACCOUNT_GID,
            password_digest(&password[..password_length]),
        ) {
            write_stdout(b"login: first account rejected\n");
            return None;
        }
        write_stdout(b"login: first account configured username=");
        write_stdout(&username[..username_length]);
        write_stdout(b" status=ready\n");
        return Some(accounts);
    }
}

fn read_line(buffer: &mut [u8], echo: bool, skip_lf: &mut bool) -> usize {
    let mut length = 0;
    loop {
        let mut byte = [0u8; 1];
        let count = read(STDIN_FD, &mut byte);
        if is_syscall_error(count) {
            exit(2);
        }
        if count == 0 {
            yield_now();
            continue;
        }
        let byte = byte[0];
        if *skip_lf && byte == b'\n' {
            *skip_lf = false;
            continue;
        }
        *skip_lf = false;
        if byte == b'\r' || byte == b'\n' {
            *skip_lf = byte == b'\r';
            if echo {
                write_stdout(b"\n");
            }
            return length;
        }
        if byte == 8 || byte == 127 {
            if length != 0 {
                length -= 1;
                if echo {
                    write_stdout(b"\x08 \x08");
                }
            }
            continue;
        }
        if !(0x20..=0x7e).contains(&byte) || length + 1 >= buffer.len() {
            continue;
        }
        buffer[length] = byte;
        length += 1;
        if echo {
            write_stdout(&[byte]);
        }
    }
}

fn write_decimal(mut value: usize) {
    let mut bytes = [0u8; 20];
    let mut length = 0;
    loop {
        bytes[length] = b'0' + (value % 10) as u8;
        length += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for byte in bytes[..length].iter().rev().copied() {
        write_stdout(&[byte]);
    }
}
