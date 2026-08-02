#![no_std]
#![no_main]

use rustos_userland::{
    CREDENTIALS_LENGTH, Credentials, accounts::password_digest, close, exit, get_credentials,
    is_syscall_error, pipe, read, spawn_privileged_redirected, waitpid, write, write_stdout,
};

const STDIN_FD: u64 = 0;
const ADMIN_PATH: &[u8] = b"/sbin/admin\0";
const REQUEST_HEADER_LENGTH: usize = 8;
const REQUEST_LENGTH: usize = REQUEST_HEADER_LENGTH + 8 + 32;
const PASSWORD_BUFFER_LENGTH: usize = 64;
const RESPONSE_BUFFER_LENGTH: usize = 96;
const REQUEST_AUTHENTICATE: [u8; REQUEST_HEADER_LENGTH] = *b"AUTH\0\0\0\0";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut credentials = Credentials::default();
    if get_credentials(&mut credentials) != CREDENTIALS_LENGTH as u64 {
        write_stdout(b"lock: credentials unavailable\n");
        exit(1);
    }
    write_stdout(b"lock: session locked status=ready\n");

    let mut skip_lf = false;
    loop {
        let mut password = [0u8; PASSWORD_BUFFER_LENGTH];
        let password_length = read_line(b"lock: password: ", &mut password, &mut skip_lf);
        let digest = password_digest(&password[..password_length]);
        let mut request = [0u8; REQUEST_LENGTH];
        request[..REQUEST_HEADER_LENGTH].copy_from_slice(&REQUEST_AUTHENTICATE);
        request[REQUEST_HEADER_LENGTH..REQUEST_HEADER_LENGTH + 8]
            .copy_from_slice(&credentials.uid.to_le_bytes());
        request[REQUEST_HEADER_LENGTH + 8..].copy_from_slice(&digest);

        let request_pipe = pipe();
        let response_pipe = pipe();
        if is_syscall_error(request_pipe.read)
            || is_syscall_error(request_pipe.write)
            || is_syscall_error(response_pipe.read)
            || is_syscall_error(response_pipe.write)
        {
            write_stdout(b"lock: helper pipe failed\n");
            exit(2);
        }
        let pid = spawn_privileged_redirected(ADMIN_PATH, request_pipe.read, response_pipe.write);
        if is_syscall_error(pid) {
            close_auth_pipes(
                request_pipe.read,
                request_pipe.write,
                response_pipe.read,
                response_pipe.write,
            );
            write_stdout(b"lock: helper unavailable\n");
            exit(3);
        }
        let _ = close(request_pipe.read);
        let _ = close(response_pipe.write);
        let count = write(request_pipe.write, &request);
        let _ = close(request_pipe.write);
        if is_syscall_error(count) || count != REQUEST_LENGTH as u64 {
            let _ = close(response_pipe.read);
            let _ = waitpid(pid);
            write_stdout(b"lock: request failed\n");
            exit(4);
        }
        let result = waitpid(pid);
        let authenticated = result.status == 0 && response_contains_ok(response_pipe.read);
        let _ = close(response_pipe.read);
        if authenticated {
            write_stdout(b"lock: session unlocked status=ready\n");
            exit(0);
        }
        write_stdout(b"lock: authentication failed status=ready\n");
    }
}

fn response_contains_ok(handle: u64) -> bool {
    let mut response = [0u8; RESPONSE_BUFFER_LENGTH];
    let mut length = 0usize;
    while length < response.len() {
        let count = read(handle, &mut response[length..]);
        if is_syscall_error(count) {
            return false;
        }
        if count == 0 {
            break;
        }
        length += count as usize;
    }
    response[..length]
        .windows(b"authentication ok".len())
        .any(|window| window == b"authentication ok")
}

fn close_auth_pipes(
    request_read: u64,
    request_write: u64,
    response_read: u64,
    response_write: u64,
) {
    let _ = close(request_read);
    let _ = close(request_write);
    let _ = close(response_read);
    let _ = close(response_write);
}

fn read_line(prompt: &[u8], buffer: &mut [u8], skip_lf: &mut bool) -> usize {
    write_stdout(prompt);
    let mut length = 0;
    loop {
        let mut byte = [0u8; 1];
        let count = read(STDIN_FD, &mut byte);
        if is_syscall_error(count) {
            exit(5);
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
            write_stdout(b"\n");
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
