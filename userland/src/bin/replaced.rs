#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    rustos_userland::write_stdout(b"userland: /bin/replaced\n");
    rustos_userland::exit(0)
}
