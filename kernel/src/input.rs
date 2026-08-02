use spin::Mutex;

pub const INPUT_EVENT_MOUSE: u32 = 1;
pub const INPUT_EVENT_KEYBOARD: u32 = 2;
pub const INPUT_EVENT_WINDOW: u32 = 3;
pub const WINDOW_EVENT_CONFIGURE: u32 = 1;
pub const WINDOW_EVENT_CLOSE: u32 = 2;
pub const INPUT_EVENT_LENGTH: usize = 24;
const MOUSE_PACKET_LENGTH: usize = 3;
const MOUSE_QUEUE_LENGTH: usize = 8;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputEvent {
    pub kind: u32,
    pub buttons: u32,
    pub dx: i32,
    pub dy: i32,
    pub wheel: i32,
    pub code: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MousePacketParser {
    packet: [u8; MOUSE_PACKET_LENGTH],
    length: usize,
}

impl MousePacketParser {
    pub const fn new() -> Self {
        Self {
            packet: [0; MOUSE_PACKET_LENGTH],
            length: 0,
        }
    }

    pub fn push_byte(&mut self, byte: u8) -> Option<InputEvent> {
        if self.length == 0 && byte & 0x08 == 0 {
            return None;
        }
        self.packet[self.length] = byte;
        self.length += 1;
        if self.length < MOUSE_PACKET_LENGTH {
            return None;
        }
        self.length = 0;

        let flags = self.packet[0];
        if flags & 0xc0 != 0 {
            return None;
        }
        let dx = if flags & 0x10 != 0 {
            i32::from(i8::from_ne_bytes([self.packet[1]]))
        } else {
            i32::from(self.packet[1])
        };
        let dy = if flags & 0x20 != 0 {
            -i32::from(i8::from_ne_bytes([self.packet[2]]))
        } else {
            -i32::from(self.packet[2])
        };
        Some(InputEvent {
            kind: INPUT_EVENT_MOUSE,
            buttons: u32::from(flags & 0x07),
            dx,
            dy,
            wheel: 0,
            code: 0,
        })
    }
}

#[derive(Debug)]
struct MouseState {
    parser: MousePacketParser,
    queue: [Option<InputEvent>; MOUSE_QUEUE_LENGTH],
    head: usize,
    tail: usize,
    count: usize,
    enabled: bool,
}

impl MouseState {
    const fn new() -> Self {
        Self {
            parser: MousePacketParser::new(),
            queue: [None; MOUSE_QUEUE_LENGTH],
            head: 0,
            tail: 0,
            count: 0,
            enabled: false,
        }
    }

    fn push(&mut self, event: InputEvent) {
        if self.count == MOUSE_QUEUE_LENGTH {
            self.queue[self.head] = None;
            self.head = (self.head + 1) % MOUSE_QUEUE_LENGTH;
            self.count -= 1;
        }
        self.queue[self.tail] = Some(event);
        self.tail = (self.tail + 1) % MOUSE_QUEUE_LENGTH;
        self.count += 1;
    }

    fn pop(&mut self) -> Option<InputEvent> {
        let event = self.queue[self.head].take()?;
        self.head = (self.head + 1) % MOUSE_QUEUE_LENGTH;
        self.count -= 1;
        Some(event)
    }
}

static MOUSE: Mutex<MouseState> = Mutex::new(MouseState::new());

#[cfg(target_os = "none")]
const KEYBOARD_STATUS: u16 = 0x64;
#[cfg(target_os = "none")]
const KEYBOARD_DATA: u16 = 0x60;
#[cfg(target_os = "none")]
const AUXILIARY_ENABLE: u8 = 0xa8;
#[cfg(target_os = "none")]
const READ_COMMAND_BYTE: u8 = 0x20;
#[cfg(target_os = "none")]
const WRITE_COMMAND_BYTE: u8 = 0x60;
#[cfg(target_os = "none")]
const WRITE_MOUSE_DATA: u8 = 0xd4;
#[cfg(target_os = "none")]
const MOUSE_ENABLE_STREAMING: u8 = 0xf4;
#[cfg(target_os = "none")]
const MOUSE_ACK: u8 = 0xfa;
#[cfg(target_os = "none")]
const STATUS_OUTPUT_FULL: u8 = 1 << 0;
#[cfg(target_os = "none")]
const STATUS_INPUT_FULL: u8 = 1 << 1;
#[cfg(target_os = "none")]
const STATUS_AUXILIARY: u8 = 1 << 5;
#[cfg(target_os = "none")]
const PS2_POLL_SPINS: usize = 100_000;

#[cfg(target_os = "none")]
static KEYBOARD_STATE: spin::Mutex<crate::keyboard::KeyboardState> =
    spin::Mutex::new(crate::keyboard::KeyboardState::new());

#[cfg(target_os = "none")]
pub fn init_mouse() {
    let enabled = initialize_mouse();
    MOUSE.lock().enabled = enabled;
}

#[cfg(not(target_os = "none"))]
pub fn init_mouse() {}

#[cfg(target_os = "none")]
pub fn mouse_ready() -> bool {
    MOUSE.lock().enabled
}

#[cfg(not(target_os = "none"))]
pub fn mouse_ready() -> bool {
    false
}

#[cfg(target_os = "none")]
pub fn read_event() -> Option<InputEvent> {
    if let Some(event) = crate::usb::read_input_event() {
        return Some(event);
    }
    {
        let mut mouse = MOUSE.lock();
        if mouse.enabled {
            for _ in 0..MOUSE_PACKET_LENGTH * 2 {
                let status = unsafe { inb(KEYBOARD_STATUS) };
                if status & STATUS_OUTPUT_FULL == 0 || status & STATUS_AUXILIARY == 0 {
                    break;
                }
                let byte = unsafe { inb(KEYBOARD_DATA) };
                if let Some(event) = mouse.parser.push_byte(byte) {
                    mouse.push(event);
                }
            }
            if let Some(event) = mouse.pop() {
                return Some(event);
            }
        }
    }
    if crate::usb::keyboard_ready() {
        return None;
    }
    read_keyboard_byte().map(|code| InputEvent {
        kind: INPUT_EVENT_KEYBOARD,
        buttons: 0,
        dx: 0,
        dy: 0,
        wheel: 0,
        code: u32::from(code),
    })
}

#[cfg(not(target_os = "none"))]
pub fn read_event() -> Option<InputEvent> {
    None
}

#[cfg(target_os = "none")]
pub fn read_keyboard_byte() -> Option<u8> {
    if crate::usb::keyboard_ready() {
        return crate::usb::read_keyboard_byte();
    }
    let status = unsafe { inb(KEYBOARD_STATUS) };
    if status & STATUS_OUTPUT_FULL == 0 || status & STATUS_AUXILIARY != 0 {
        return None;
    }
    let scancode = unsafe { inb(KEYBOARD_DATA) };
    KEYBOARD_STATE.lock().translate(scancode)
}

#[cfg(not(target_os = "none"))]
pub fn read_keyboard_byte() -> Option<u8> {
    None
}

#[cfg(target_os = "none")]
fn initialize_mouse() -> bool {
    if !wait_input_empty() {
        return false;
    }
    unsafe { outb(KEYBOARD_STATUS, AUXILIARY_ENABLE) };

    if !wait_input_empty() {
        return false;
    }
    unsafe { outb(KEYBOARD_STATUS, READ_COMMAND_BYTE) };
    let Some(mut command_byte) = wait_controller_byte() else {
        return false;
    };
    command_byte &= !(1 << 5);
    command_byte &= !(1 << 1);

    if !wait_input_empty() {
        return false;
    }
    unsafe { outb(KEYBOARD_STATUS, WRITE_COMMAND_BYTE) };
    if !wait_input_empty() {
        return false;
    }
    unsafe { outb(KEYBOARD_DATA, command_byte) };

    send_mouse_command(MOUSE_ENABLE_STREAMING)
}

#[cfg(target_os = "none")]
fn send_mouse_command(command: u8) -> bool {
    if !wait_input_empty() {
        return false;
    }
    unsafe { outb(KEYBOARD_STATUS, WRITE_MOUSE_DATA) };
    if !wait_input_empty() {
        return false;
    }
    unsafe { outb(KEYBOARD_DATA, command) };
    for _ in 0..PS2_POLL_SPINS {
        let status = unsafe { inb(KEYBOARD_STATUS) };
        if status & STATUS_OUTPUT_FULL != 0 {
            let response = unsafe { inb(KEYBOARD_DATA) };
            return response == MOUSE_ACK;
        }
        core::hint::spin_loop();
    }
    false
}

#[cfg(target_os = "none")]
fn wait_input_empty() -> bool {
    for _ in 0..PS2_POLL_SPINS {
        if unsafe { inb(KEYBOARD_STATUS) } & STATUS_INPUT_FULL == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

#[cfg(target_os = "none")]
fn wait_controller_byte() -> Option<u8> {
    for _ in 0..PS2_POLL_SPINS {
        if unsafe { inb(KEYBOARD_STATUS) } & STATUS_OUTPUT_FULL != 0 {
            return Some(unsafe { inb(KEYBOARD_DATA) });
        }
        core::hint::spin_loop();
    }
    None
}

#[cfg(target_os = "none")]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the ports are the architecturally defined i8042 controller/data registers.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value) };
}

#[cfg(target_os = "none")]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: reading the i8042 status/data register is safe for the configured controller.
    unsafe { core::arch::asm!("in al, dx", out("al") value, in("dx") port) };
    value
}

#[cfg(test)]
mod tests {
    use super::{INPUT_EVENT_LENGTH, INPUT_EVENT_MOUSE, MousePacketParser};

    #[test]
    fn event_abi_reserves_a_code_for_keyboard_input() {
        assert_eq!(
            core::mem::size_of::<super::InputEvent>(),
            INPUT_EVENT_LENGTH
        );
        let event = super::InputEvent {
            kind: super::INPUT_EVENT_KEYBOARD,
            code: u32::from(b'k'),
            ..super::InputEvent::default()
        };
        assert_eq!(event.code, u32::from(b'k'));
    }

    #[test]
    fn parses_signed_three_byte_motion_and_buttons() {
        let mut parser = MousePacketParser::new();
        assert_eq!(parser.push_byte(0x19), None);
        assert_eq!(parser.push_byte(0xfe), None);
        assert_eq!(
            parser.push_byte(0x03),
            Some(super::InputEvent {
                kind: INPUT_EVENT_MOUSE,
                buttons: 1,
                dx: -2,
                dy: -3,
                wheel: 0,
                code: 0,
            })
        );
    }

    #[test]
    fn ignores_bytes_without_a_first_packet_bit() {
        let mut parser = MousePacketParser::new();
        assert_eq!(parser.push_byte(0x00), None);
        assert_eq!(parser.push_byte(0x08), None);
        assert_eq!(parser.push_byte(0x01), None);
        assert_eq!(parser.push_byte(0x00).unwrap().kind, INPUT_EVENT_MOUSE);
        assert_eq!(parser.push_byte(0x00), None);
    }

    #[test]
    fn drops_overflow_packets_without_leaking_motion() {
        let mut parser = MousePacketParser::new();
        assert_eq!(parser.push_byte(0x49), None);
        assert_eq!(parser.push_byte(0xff), None);
        assert_eq!(parser.push_byte(0xff), None);
    }
}
