#![no_std]
#![no_main]

const FIRST_RESTART_PID: u64 = 4;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    if rustos_userland::getpid() == FIRST_RESTART_PID {
        rustos_userland::write_stdout(b"userland: RESTART.FAIL\n");
        rustos_userland::exit(42);
    }
    rustos_userland::write_stdout(b"userland: RESTART.OK\n");
    rustos_userland::exit(0)
}
