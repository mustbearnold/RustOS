#![no_std]
#![no_main]

use rustos_userland::{exit, is_syscall_error, read, write};

const STDIN_FD: u64 = 0;
const STDOUT_FD: u64 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut buffer = [0u8; 128];
    loop {
        let count = read(STDIN_FD, &mut buffer);
        if is_syscall_error(count) {
            exit(1);
        }
        if count == 0 {
            exit(0);
        }
        let count = count as usize;
        if is_syscall_error(write(STDOUT_FD, &buffer[..count])) {
            exit(2);
        }
    }
}
