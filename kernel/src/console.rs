use core::fmt::{self, Write};

const COM1: u16 = 0x3f8;

pub fn init() {
    // 115200 baud, 8 data bits, no parity, one stop bit.
    unsafe {
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x80);
        outb(COM1, 0x01);
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03);
        outb(COM1 + 2, 0xc7);
        outb(COM1 + 4, 0x0b);
    }
}

pub fn write_fmt(arguments: fmt::Arguments<'_>) {
    let mut writer = SerialWriter;
    let _ = writer.write_fmt(arguments);
}

pub fn write_bytes(bytes: &[u8]) {
    let mut writer = SerialWriter;
    for &byte in bytes {
        writer.write_byte(byte);
    }
    crate::framebuffer::write_bytes(bytes);
}

/// Drain bytes that the firmware or QEMU has already placed in the serial receive FIFO.
///
/// This deliberately never waits for input. Userland callers can poll fd 0 and yield to the
/// scheduler between polls, which keeps the kernel syscall boundary non-blocking.
pub fn read_available(bytes: &mut [u8]) -> usize {
    let mut count = 0;
    while count < bytes.len() {
        if unsafe { inb(COM1 + 5) } & 0x01 != 0 {
            bytes[count] = unsafe { inb(COM1) };
            count += 1;
            continue;
        }
        // `input::read_keyboard_byte` selects the live USB path and falls back to PS/2, so the
        // shell and graphics event ABI consume one shared translated stream.
        if let Some(byte) = crate::input::read_keyboard_byte() {
            bytes[count] = byte;
            count += 1;
            continue;
        }
        break;
    }
    count
}

struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for byte in value.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

impl SerialWriter {
    fn write_byte(&mut self, byte: u8) {
        unsafe {
            while inb(COM1 + 5) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            outb(COM1, byte);
        }
    }
}

unsafe fn outb(port: u16, value: u8) {
    // SAFETY: COM1 is the conventional 16550-compatible debug UART port.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value) };
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: Reading the UART line-status register is safe for the configured COM1 device.
    unsafe { core::arch::asm!("in al, dx", out("al") value, in("dx") port) };
    value
}
