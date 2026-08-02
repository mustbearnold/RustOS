#![no_std]
#![no_main]

use rustos_userland::{
    CREDENTIALS_LENGTH, Credentials, SPAWN_INHERIT_PARENT_FD,
    accounts::{
        ACCOUNT_DATABASE_LENGTH, ACCOUNT_STORE_PATH, ACCOUNT_USERNAME_LENGTH, AccountStore,
        MAX_ACCOUNTS, add_account, parse, serialize, update_password, valid_username,
        verify_password,
    },
    close, exit, get_caller_credentials, is_syscall_error, mkdir, open, open_create_write,
    open_write, pipe, read, spawn_redirected, waitpid, write, write_stdout,
};

const STDIN_FD: u64 = 0;
const FIXED_REQUEST_LENGTH: usize = 8;
const PASSWORD_REQUEST_TAIL_LENGTH: usize = 8 + 32 + 32;
const ADD_ACCOUNT_REQUEST_TAIL_LENGTH: usize = 32 + ACCOUNT_USERNAME_LENGTH + 32;
const AUTH_REQUEST_TAIL_LENGTH: usize = 8 + 32;
const AUTH_DIGEST_LENGTH: usize = 32;
const ACCOUNT_WRITE_CHUNK_LENGTH: usize = 256;
const PACKAGE_PATH: &[u8] = b"/bin/pkg\0";
const STATE_PATH: &[u8] = b"/RUSTOS.ST\0";
const STATE_CONTENT: &[u8; 7] = b"boot=1\n";
const REQUEST_INSTALL: [u8; FIXED_REQUEST_LENGTH] = *b"INSTALL\0";
const REQUEST_UPDATE: [u8; FIXED_REQUEST_LENGTH] = *b"UPDATE\0\0";
const REQUEST_ROLLBACK: [u8; FIXED_REQUEST_LENGTH] = *b"ROLLBACK";
const REQUEST_SYNC: [u8; FIXED_REQUEST_LENGTH] = *b"SYNCNET\0";
const REQUEST_RECOVER: [u8; FIXED_REQUEST_LENGTH] = *b"RECOVER\0";
const REQUEST_STATE_SET: [u8; FIXED_REQUEST_LENGTH] = *b"STATESET";
const REQUEST_PASSWORD: [u8; FIXED_REQUEST_LENGTH] = *b"PASSWD\0\0";
const REQUEST_ADD_ACCOUNT: [u8; FIXED_REQUEST_LENGTH] = *b"ADDUSER\0";
const REQUEST_AUTHENTICATE: [u8; FIXED_REQUEST_LENGTH] = *b"AUTH\0\0\0\0";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let Some(caller) = caller_credentials() else {
        write_stdout(b"admin: caller credentials unavailable status=denied\n");
        exit(1);
    };
    let mut request = [0u8; FIXED_REQUEST_LENGTH];
    if !read_exact(STDIN_FD, &mut request) {
        write_stdout(b"admin: request invalid\n");
        exit(2);
    }

    let status = if request == REQUEST_PASSWORD {
        change_password(caller)
    } else if request == REQUEST_ADD_ACCOUNT {
        add_account_request(caller)
    } else if request == REQUEST_AUTHENTICATE {
        authenticate_request(caller)
    } else if request == REQUEST_STATE_SET {
        if authorize_admin_request(caller) {
            write_state()
        } else {
            40
        }
    } else if is_package_request(&request) {
        if authorize_admin_request(caller) {
            run_package_manager(&request)
        } else {
            41
        }
    } else {
        write_stdout(b"admin: request denied\n");
        3
    };
    exit(status);
}

fn is_package_request(request: &[u8; FIXED_REQUEST_LENGTH]) -> bool {
    *request == REQUEST_INSTALL
        || *request == REQUEST_UPDATE
        || *request == REQUEST_ROLLBACK
        || *request == REQUEST_SYNC
        || *request == REQUEST_RECOVER
}

fn run_package_manager(request: &[u8; FIXED_REQUEST_LENGTH]) -> i64 {
    let handles = pipe();
    if is_syscall_error(handles.read) || is_syscall_error(handles.write) {
        write_stdout(b"admin: package pipe failed\n");
        return 4;
    }
    let pid = spawn_redirected(PACKAGE_PATH, handles.read, SPAWN_INHERIT_PARENT_FD);
    if is_syscall_error(pid) {
        let _ = close(handles.read);
        let _ = close(handles.write);
        write_stdout(b"admin: package spawn failed\n");
        return 5;
    }
    let count = write(handles.write, request);
    let _ = close(handles.write);
    let _ = close(handles.read);
    if is_syscall_error(count) || count != FIXED_REQUEST_LENGTH as u64 {
        write_stdout(b"admin: package request failed\n");
        return 6;
    }
    let result = waitpid(pid);
    if is_syscall_error(result.pid) || result.status != 0 {
        write_stdout(b"admin: package operation failed\n");
        return 7;
    }
    write_stdout(b"admin: package operation status=ready\n");
    0
}

fn change_password(caller: Credentials) -> i64 {
    let mut tail = [0u8; PASSWORD_REQUEST_TAIL_LENGTH];
    if !read_exact(STDIN_FD, &mut tail) {
        write_stdout(b"admin: password request invalid\n");
        return 10;
    }

    let mut uid_bytes = [0u8; 8];
    uid_bytes.copy_from_slice(&tail[..8]);
    let uid = u64::from_le_bytes(uid_bytes);
    if caller.uid != 0 && caller.uid != uid {
        write_stdout(b"admin: authorization denied status=denied\n");
        return 16;
    }
    let mut old_digest = [0u8; 32];
    old_digest.copy_from_slice(&tail[8..40]);
    let mut new_digest = [0u8; 32];
    new_digest.copy_from_slice(&tail[40..72]);

    let Some(mut store) = read_store() else {
        write_stdout(b"admin: account store unavailable\n");
        return 11;
    };
    if !update_password(&mut store, uid, &old_digest, new_digest) {
        write_stdout(b"admin: old password rejected\n");
        return 12;
    }
    if !write_store(&store) {
        write_stdout(b"admin: account store write failed\n");
        return 13;
    }
    let Some(verified) = read_store() else {
        write_stdout(b"admin: account store reread failed\n");
        return 14;
    };
    if !verified.accounts[..verified.count]
        .iter()
        .any(|account| account.uid == uid && account.password_digest == new_digest)
    {
        write_stdout(b"admin: account store verification failed\n");
        return 15;
    }
    write_stdout(b"admin: password updated status=ready\n");
    0
}

fn add_account_request(caller: Credentials) -> i64 {
    let mut tail = [0u8; ADD_ACCOUNT_REQUEST_TAIL_LENGTH];
    if !read_exact(STDIN_FD, &mut tail) {
        write_stdout(b"admin: account request invalid\n");
        return 20;
    }
    let mut admin_digest = [0u8; AUTH_DIGEST_LENGTH];
    admin_digest.copy_from_slice(&tail[..AUTH_DIGEST_LENGTH]);
    if !authorize_admin(caller, &admin_digest) {
        return 28;
    }
    let username_start = AUTH_DIGEST_LENGTH;
    let username_end = username_start + ACCOUNT_USERNAME_LENGTH;
    let username_length = tail[username_start..username_end]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(ACCOUNT_USERNAME_LENGTH);
    let username = &tail[username_start..username_start + username_length];
    if username.is_empty() || !valid_username(username) || username_length > ACCOUNT_USERNAME_LENGTH
    {
        write_stdout(b"admin: account username invalid\n");
        return 21;
    }
    let mut password_digest = [0u8; 32];
    password_digest.copy_from_slice(&tail[username_end..]);
    let Some(mut store) = read_store() else {
        write_stdout(b"admin: account store unavailable\n");
        return 22;
    };
    let Some(uid) = next_uid(&store) else {
        write_stdout(b"admin: account capacity exhausted\n");
        return 23;
    };
    if !add_account(&mut store, username, uid, uid, password_digest) {
        write_stdout(b"admin: account creation rejected\n");
        return 24;
    }
    if !write_store(&store) {
        write_stdout(b"admin: account store write failed\n");
        return 25;
    }
    let Some(verified) = read_store() else {
        write_stdout(b"admin: account store reread failed\n");
        return 26;
    };
    if verified
        .find_username(username)
        .is_none_or(|account| account.uid != uid || account.password_digest != password_digest)
    {
        write_stdout(b"admin: account store verification failed\n");
        return 27;
    }
    write_stdout(b"admin: account created username=");
    write_stdout(username);
    write_stdout(b" uid=");
    write_decimal(uid);
    write_stdout(b" status=ready\n");
    0
}

fn authenticate_request(caller: Credentials) -> i64 {
    let mut tail = [0u8; AUTH_REQUEST_TAIL_LENGTH];
    if !read_exact(STDIN_FD, &mut tail) {
        write_stdout(b"admin: authentication request invalid\n");
        return 30;
    }
    let mut uid_bytes = [0u8; 8];
    uid_bytes.copy_from_slice(&tail[..8]);
    let uid = u64::from_le_bytes(uid_bytes);
    if caller.uid != 0 && caller.uid != uid {
        write_stdout(b"admin: authorization denied status=denied\n");
        return 33;
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&tail[8..]);
    let Some(store) = read_store() else {
        write_stdout(b"admin: account store unavailable\n");
        return 31;
    };
    if verify_password(&store, uid, &digest) {
        write_stdout(b"admin: authentication ok status=ready\n");
        0
    } else {
        write_stdout(b"admin: authentication failed status=denied\n");
        32
    }
}

fn next_uid(store: &AccountStore) -> Option<u64> {
    (0..MAX_ACCOUNTS)
        .map(|offset| 1000 + offset as u64)
        .find(|uid| {
            !store.accounts[..store.count]
                .iter()
                .any(|account| account.uid == *uid)
        })
}

fn read_store() -> Option<AccountStore> {
    let handle = open(ACCOUNT_STORE_PATH);
    if is_syscall_error(handle) {
        return None;
    }
    let mut bytes = [0u8; ACCOUNT_DATABASE_LENGTH];
    let mut length = 0usize;
    let mut valid = true;
    while length < bytes.len() {
        let end = (length + ACCOUNT_WRITE_CHUNK_LENGTH).min(bytes.len());
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

fn caller_credentials() -> Option<Credentials> {
    let mut credentials = Credentials::default();
    (get_caller_credentials(&mut credentials) == CREDENTIALS_LENGTH as u64).then_some(credentials)
}

fn authorize_admin_request(caller: Credentials) -> bool {
    let mut digest = [0u8; AUTH_DIGEST_LENGTH];
    if !read_exact(STDIN_FD, &mut digest) {
        write_stdout(b"admin: authorization request invalid status=denied\n");
        return false;
    }
    authorize_admin(caller, &digest)
}

fn authorize_admin(caller: Credentials, digest: &[u8; AUTH_DIGEST_LENGTH]) -> bool {
    if caller.uid == 0 {
        return true;
    }
    if caller.uid != 1000 {
        write_stdout(b"admin: authorization denied status=denied\n");
        return false;
    }
    let Some(store) = read_store() else {
        write_stdout(b"admin: account store unavailable status=denied\n");
        return false;
    };
    if verify_password(&store, 1000, digest) {
        true
    } else {
        write_stdout(b"admin: authorization failed status=denied\n");
        false
    }
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
        let end = (offset + ACCOUNT_WRITE_CHUNK_LENGTH).min(bytes.len());
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

fn read_exact(handle: u64, buffer: &mut [u8]) -> bool {
    let mut offset = 0;
    while offset < buffer.len() {
        let count = read(handle, &mut buffer[offset..]);
        if is_syscall_error(count) || count == 0 {
            return false;
        }
        offset = offset.saturating_add(count as usize);
    }
    true
}

fn write_decimal(mut value: u64) {
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

fn write_state() -> i64 {
    let handle = open_write(STATE_PATH);
    if is_syscall_error(handle) {
        write_stdout(b"admin: state open failed\n");
        return 8;
    }
    let count = write(handle, STATE_CONTENT);
    let closed = close(handle);
    if is_syscall_error(count) || count != STATE_CONTENT.len() as u64 || is_syscall_error(closed) {
        write_stdout(b"admin: state write failed\n");
        return 9;
    }
    write_stdout(b"admin: state set status=ready\n");
    0
}
