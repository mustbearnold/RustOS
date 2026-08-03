#![no_std]
#![no_main]

use rustos_userland::{
    SYSCALL_ENOENT,
    accounts::{
        ACCOUNT_DATABASE_LENGTH, ACCOUNT_STORE_PATH, ACCOUNT_USERNAME_LENGTH, AccountStore,
        add_account_with_role, parse, password_digest, serialize, valid_username,
    },
    close, exit, is_syscall_error, mkdir, open, open_create_write, read, spawn_as, waitpid, write,
    write_stdout, yield_now,
};

const STDIN_FD: u64 = 0;
const ACCOUNT_BUFFER_LENGTH: usize = ACCOUNT_DATABASE_LENGTH;
const USERNAME_BUFFER_LENGTH: usize = ACCOUNT_USERNAME_LENGTH + 1;
const PASSWORD_BUFFER_LENGTH: usize = 64;
const WRITE_CHUNK_LENGTH: usize = 256;
const FIRST_ACCOUNT_UID: u64 = 1000;
const FIRST_ACCOUNT_GID: u64 = 1000;
const SHELL_PATH: &[u8] = b"/bin/sh\0";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let Some(accounts) = load_or_bootstrap_accounts() else {
        write_stdout(b"shell-login: account database unavailable\n");
        exit(1);
    };
    let Some(account) = accounts.find_uid(FIRST_ACCOUNT_UID, FIRST_ACCOUNT_GID) else {
        write_stdout(b"shell-login: administrator account unavailable\n");
        exit(2);
    };
    write_stdout(b"shell-login: launching username=");
    write_stdout(account.username());
    write_stdout(b" status=ready\n");
    let pid = spawn_as(SHELL_PATH, account.uid, account.gid);
    if is_syscall_error(pid) {
        write_stdout(b"shell-login: shell start failed\n");
        exit(3);
    }
    let result = waitpid(pid);
    if result.pid == pid {
        exit(result.status);
    }
    exit(4);
}

fn load_or_bootstrap_accounts() -> Option<AccountStore> {
    match read_store() {
        Some(accounts) => {
            write_stdout(b"shell-login: account store loaded status=ready\n");
            Some(accounts)
        }
        None if store_missing() => {
            write_stdout(b"shell-login: account store setup required status=ready\n");
            let accounts = setup_first_account()?;
            if !write_store(&accounts) {
                return None;
            }
            let verified = read_store()?;
            write_stdout(b"shell-login: account store bootstrapped status=ready\n");
            Some(verified)
        }
        None => {
            write_stdout(b"shell-login: account store invalid\n");
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
    let handle = open(ACCOUNT_STORE_PATH);
    if is_syscall_error(handle) {
        return None;
    }
    let mut bytes = [0u8; ACCOUNT_BUFFER_LENGTH];
    let mut length = 0usize;
    while length < bytes.len() {
        let end = (length + WRITE_CHUNK_LENGTH).min(bytes.len());
        let count = read(handle, &mut bytes[length..end]);
        if is_syscall_error(count) {
            let _ = close(handle);
            return None;
        }
        let count = count as usize;
        if count == 0 {
            break;
        }
        length = length.saturating_add(count).min(bytes.len());
    }
    let _ = close(handle);
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
        write_stdout(b"shell-login: setup username prompt=ready\n");
        write_stdout(b"shell-login: new username: ");
        let username_length = read_line(&mut username, true, &mut skip_lf);
        if username_length == 0
            || username_length > ACCOUNT_USERNAME_LENGTH
            || !valid_username(&username[..username_length])
        {
            write_stdout(b"shell-login: username invalid\n");
            continue;
        }

        let mut password = [0u8; PASSWORD_BUFFER_LENGTH];
        write_stdout(b"shell-login: setup password prompt=ready\n");
        write_stdout(b"shell-login: new password: ");
        let password_length = read_line(&mut password, false, &mut skip_lf);
        write_stdout(b"\n");
        if password_length == 0 {
            write_stdout(b"shell-login: password cannot be empty\n");
            continue;
        }

        let mut confirmation = [0u8; PASSWORD_BUFFER_LENGTH];
        write_stdout(b"shell-login: setup confirm prompt=ready\n");
        write_stdout(b"shell-login: retype password: ");
        let confirmation_length = read_line(&mut confirmation, false, &mut skip_lf);
        write_stdout(b"\n");
        if password_length != confirmation_length
            || password[..password_length] != confirmation[..confirmation_length]
        {
            write_stdout(b"shell-login: passwords do not match\n");
            continue;
        }

        let mut accounts = AccountStore::empty();
        if !add_account_with_role(
            &mut accounts,
            &username[..username_length],
            FIRST_ACCOUNT_UID,
            FIRST_ACCOUNT_GID,
            password_digest(&password[..password_length]),
            true,
        ) {
            write_stdout(b"shell-login: first account rejected\n");
            return None;
        }
        write_stdout(b"shell-login: first account configured username=");
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
            exit(5);
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
