#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    rustos_userland::exercise_file_and_thread(
        b"userland: /bin/worker\n",
        b"/etc/rustos/config.txt\0",
    )
}
