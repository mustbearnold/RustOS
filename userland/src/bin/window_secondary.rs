#![no_std]
#![no_main]

#[path = "../window_client.rs"]
mod window_client;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    window_client::run(true)
}
