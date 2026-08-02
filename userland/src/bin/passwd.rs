#![no_std]
#![no_main]

use rustos_userland::{
    CREDENTIALS_LENGTH, Credentials, SPAWN_INHERIT_PARENT_FD, accounts::password_digest, close,
    exit, get_credentials, is_syscall_error, pipe, read, spawn_privileged_redirected, waitpid,
    write, write_stdout,
};

const STDIN_FD: u64 = 0;
const ADMIN_PATH: &[u8] = b"/sbin/admin\0";
const REQUEST_HEADER_LENGTH: usize = 8;
const REQUEST_LENGTH: usize = REQUEST_HEADER_LENGTH + 8 + 32 + 32;
const PASSWORD_BUFFER_LENGTH: usize = 64;
const REQUEST_PASSWORD: [u8; REQUEST_HEADER_LENGTH] = *b"PASSWD\0\0";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut credentials = Credentials::default();
    if get_credentials(&mut credentials) != CREDENTIALS_LENGTH as u64 {
        write_stdout(b"passwd: credentials unavailable\n");
        exit(1);
    }

    let mut skip_lf = false;
    let mut current = [0u8; PASSWORD_BUFFER_LENGTH];
    let current_length = read_password(b"passwd: current password: ", &mut current, &mut skip_lf);
    let mut next = [0u8; PASSWORD_BUFFER_LENGTH];
    let next_length = read_password(b"passwd: new password: ", &mut next, &mut skip_lf);
    let mut confirmation = [0u8; PASSWORD_BUFFER_LENGTH];
    let confirmation_length = read_password(
        b"passwd: retype new password: ",
        &mut confirmation,
        &mut skip_lf,
    );

    if next_length == 0 {
        write_stdout(b"passwd: new password is empty\n");
        exit(2);
    }
    if next[..next_length] != confirmation[..confirmation_length]
        || next_length != confirmation_length
    {
        write_stdout(b"passwd: passwords do not match\n");
        exit(3);
    }

    let old_digest = password_digest(&current[..current_length]);
    let new_digest = password_digest(&next[..next_length]);
    let mut request = [0u8; REQUEST_LENGTH];
    request[..REQUEST_HEADER_LENGTH].copy_from_slice(&REQUEST_PASSWORD);
    request[REQUEST_HEADER_LENGTH..REQUEST_HEADER_LENGTH + 8]
        .copy_from_slice(&credentials.uid.to_le_bytes());
    request[REQUEST_HEADER_LENGTH + 8..REQUEST_HEADER_LENGTH + 8 + 32].copy_from_slice(&old_digest);
    request[REQUEST_HEADER_LENGTH + 8 + 32..].copy_from_slice(&new_digest);

    let handles = pipe();
    if is_syscall_error(handles.read) || is_syscall_error(handles.write) {
        write_stdout(b"passwd: helper pipe failed\n");
        exit(4);
    }
    let pid = spawn_privileged_redirected(ADMIN_PATH, handles.read, SPAWN_INHERIT_PARENT_FD);
    if is_syscall_error(pid) {
        let _ = close(handles.read);
        let _ = close(handles.write);
        write_stdout(b"passwd: helper unavailable\n");
        exit(5);
    }
    let count = write(handles.write, &request);
    let _ = close(handles.write);
    let _ = close(handles.read);
    if is_syscall_error(count) || count != REQUEST_LENGTH as u64 {
        write_stdout(b"passwd: request failed\n");
        exit(6);
    }
    let result = waitpid(pid);
    if is_syscall_error(result.pid) || result.status != 0 {
        write_stdout(b"passwd: change failed\n");
        exit(7);
    }
    write_stdout(b"passwd: changed status=ready\n");
    exit(0);
}

fn read_password(prompt: &[u8], buffer: &mut [u8], skip_lf: &mut bool) -> usize {
    write_stdout(prompt);
    let length = read_line(buffer, skip_lf);
    write_stdout(b"\n");
    length
}

fn read_line(buffer: &mut [u8], skip_lf: &mut bool) -> usize {
    let mut length = 0;
    loop {
        let mut byte = [0u8; 1];
        let count = read(STDIN_FD, &mut byte);
        if is_syscall_error(count) {
            exit(8);
        }
        if count == 0 {
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
            return length;
        }
        if byte == 8 || byte == 127 {
            length = length.saturating_sub(1);
            continue;
        }
        if !(0x20..=0x7e).contains(&byte) || length + 1 >= buffer.len() {
            continue;
        }
        buffer[length] = byte;
        length += 1;
    }
}
