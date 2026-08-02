#![no_std]
#![no_main]

use rustos_userland::{
    SPAWN_INHERIT_PARENT_FD,
    accounts::{ACCOUNT_USERNAME_LENGTH, password_digest, valid_username},
    close, exit, is_syscall_error, pipe, read, spawn_privileged_redirected, waitpid, write,
    write_stdout,
};

const STDIN_FD: u64 = 0;
const ADMIN_PATH: &[u8] = b"/sbin/admin\0";
const REQUEST_HEADER_LENGTH: usize = 8;
const ADMIN_PASSWORD_LENGTH: usize = 32;
const REQUEST_LENGTH: usize =
    REQUEST_HEADER_LENGTH + ADMIN_PASSWORD_LENGTH + ACCOUNT_USERNAME_LENGTH + 32;
const USERNAME_BUFFER_LENGTH: usize = ACCOUNT_USERNAME_LENGTH + 1;
const PASSWORD_BUFFER_LENGTH: usize = 64;
const REQUEST_ADD_ACCOUNT: [u8; REQUEST_HEADER_LENGTH] = *b"ADDUSER\0";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut skip_lf = false;
    let mut admin_password = [0u8; PASSWORD_BUFFER_LENGTH];
    let admin_password_length = read_line(
        b"useradd: admin password: ",
        &mut admin_password,
        false,
        &mut skip_lf,
    );
    write_stdout(b"\n");
    let mut username = [0u8; USERNAME_BUFFER_LENGTH];
    let username_length = read_line(b"useradd: username: ", &mut username, true, &mut skip_lf);
    if username_length == 0
        || username_length > ACCOUNT_USERNAME_LENGTH
        || !valid_username(&username[..username_length])
    {
        write_stdout(b"useradd: username invalid\n");
        exit(1);
    }

    let mut password = [0u8; PASSWORD_BUFFER_LENGTH];
    let password_length = read_line(b"useradd: password: ", &mut password, false, &mut skip_lf);
    write_stdout(b"\n");
    let mut confirmation = [0u8; PASSWORD_BUFFER_LENGTH];
    let confirmation_length = read_line(
        b"useradd: retype password: ",
        &mut confirmation,
        false,
        &mut skip_lf,
    );
    write_stdout(b"\n");
    if admin_password_length == 0 {
        write_stdout(b"useradd: admin password is empty\n");
        exit(2);
    }
    if password_length == 0 {
        write_stdout(b"useradd: password is empty\n");
        exit(3);
    }
    if password_length != confirmation_length
        || password[..password_length] != confirmation[..confirmation_length]
    {
        write_stdout(b"useradd: passwords do not match\n");
        exit(4);
    }

    let mut request = [0u8; REQUEST_LENGTH];
    request[..REQUEST_HEADER_LENGTH].copy_from_slice(&REQUEST_ADD_ACCOUNT);
    let admin_digest = password_digest(&admin_password[..admin_password_length]);
    request[REQUEST_HEADER_LENGTH..REQUEST_HEADER_LENGTH + ADMIN_PASSWORD_LENGTH]
        .copy_from_slice(&admin_digest);
    let username_start = REQUEST_HEADER_LENGTH + ADMIN_PASSWORD_LENGTH;
    request[username_start..username_start + username_length]
        .copy_from_slice(&username[..username_length]);
    request[username_start + ACCOUNT_USERNAME_LENGTH..]
        .copy_from_slice(&password_digest(&password[..password_length]));

    let handles = pipe();
    if is_syscall_error(handles.read) || is_syscall_error(handles.write) {
        write_stdout(b"useradd: helper pipe failed\n");
        exit(5);
    }
    let pid = spawn_privileged_redirected(ADMIN_PATH, handles.read, SPAWN_INHERIT_PARENT_FD);
    if is_syscall_error(pid) {
        let _ = close(handles.read);
        let _ = close(handles.write);
        write_stdout(b"useradd: helper unavailable\n");
        exit(6);
    }
    let count = write(handles.write, &request);
    let _ = close(handles.write);
    let _ = close(handles.read);
    if is_syscall_error(count) || count != REQUEST_LENGTH as u64 {
        write_stdout(b"useradd: request failed\n");
        exit(7);
    }
    let result = waitpid(pid);
    if is_syscall_error(result.pid) || result.status != 0 {
        write_stdout(b"useradd: account creation failed\n");
        exit(8);
    }
    write_stdout(b"useradd: account created status=ready\n");
    exit(0);
}

fn read_line(prompt: &[u8], buffer: &mut [u8], echo: bool, skip_lf: &mut bool) -> usize {
    write_stdout(prompt);
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
            if echo {
                write_stdout(b"\n");
            }
            return length;
        }
        if byte == 8 || byte == 127 {
            length = length.saturating_sub(1);
            if echo {
                write_stdout(b"\x08 \x08");
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
