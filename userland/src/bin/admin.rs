#![no_std]
#![no_main]

use rustos_userland::{
    SPAWN_INHERIT_PARENT_FD,
    accounts::{
        ACCOUNT_DATABASE_LENGTH, ACCOUNT_STORE_PATH, AccountStore, parse, serialize,
        update_password,
    },
    close, exit, is_syscall_error, mkdir, open, open_create_write, open_write, pipe, read,
    spawn_redirected, waitpid, write, write_stdout,
};

const STDIN_FD: u64 = 0;
const FIXED_REQUEST_LENGTH: usize = 8;
const PASSWORD_REQUEST_TAIL_LENGTH: usize = 8 + 32 + 32;
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut request = [0u8; FIXED_REQUEST_LENGTH];
    if !read_exact(STDIN_FD, &mut request) {
        write_stdout(b"admin: request invalid\n");
        exit(2);
    }

    let status = if request == REQUEST_PASSWORD {
        change_password()
    } else if request == REQUEST_STATE_SET {
        write_state()
    } else if is_package_request(&request) {
        run_package_manager(&request)
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

fn change_password() -> i64 {
    let mut tail = [0u8; PASSWORD_REQUEST_TAIL_LENGTH];
    if !read_exact(STDIN_FD, &mut tail) {
        write_stdout(b"admin: password request invalid\n");
        return 10;
    }

    let mut uid_bytes = [0u8; 8];
    uid_bytes.copy_from_slice(&tail[..8]);
    let uid = u64::from_le_bytes(uid_bytes);
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
