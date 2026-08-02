use x86_64::instructions::port::Port;

const PIT_BASE_FREQUENCY_HZ: u32 = 1_193_182;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerConfig {
    pub frequency_hz: u32,
    pub divisor: u16,
}

pub fn init(frequency_hz: u32) -> TimerConfig {
    assert!(frequency_hz > 0, "PIT frequency must be nonzero");
    let divisor = (PIT_BASE_FREQUENCY_HZ / frequency_hz).clamp(1, u32::from(u16::MAX)) as u16;

    let mut command = Port::new(0x43);
    let mut channel_zero = Port::new(0x40);
    // SAFETY: these are the standard PIT channel 0 command/data ports; interrupts remain disabled
    // until the IDT, PIC, and timer are fully configured.
    unsafe {
        command.write(0b0011_0110u8); // channel 0, access low/high, mode 3, binary
        channel_zero.write((divisor & 0xff) as u8);
        channel_zero.write((divisor >> 8) as u8);
    }

    TimerConfig {
        frequency_hz: PIT_BASE_FREQUENCY_HZ / u32::from(divisor),
        divisor,
    }
}
