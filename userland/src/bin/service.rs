#![no_std]
#![no_main]

use rustos_userland::{exec, exit, fork, is_syscall_error, thread_join, waitpid, write_stdout};

const REPLACED_PATH: &[u8] = b"/bin/replaced\0";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // exercise_file_and_thread is inlined here only far enough to keep the service's fork and
    // exec continuation explicit in the userland source.
    rustos_userland::yield_now();
    for _ in 0..20_000_000 {
        core::hint::spin_loop();
    }
    let _ = rustos_userland::getpid();
    let tid = rustos_userland::thread_create(helper_thread, 0);
    let handle = rustos_userland::open(b"/etc/rustos/config.txt\0");
    let mut buffer = [0u8; 4];
    if !is_syscall_error(handle) {
        let count = rustos_userland::read(handle, &mut buffer);
        let _ = rustos_userland::close(handle);
        if count == 4 {
            write_stdout(&buffer);
        }
    }
    write_stdout(b"userland: /bin/service\n");
    if !is_syscall_error(tid) {
        let _ = thread_join(tid);
    }

    let child = fork();
    if child == 0 {
        write_stdout(b"userland: FORK.CHILD\n");
        exit(17);
    }
    if !is_syscall_error(child) {
        let _ = waitpid(child);
    }
    let result = exec(REPLACED_PATH);
    if is_syscall_error(result) {
        exit(96);
    }
    exit(97)
}

extern "C" fn helper_thread(_argument: u64) -> ! {
    rustos_userland::yield_now();
    rustos_userland::thread_exit(0)
}
