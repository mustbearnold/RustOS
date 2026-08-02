#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardState {
    left_shift: bool,
    right_shift: bool,
    caps_lock: bool,
    extended: bool,
}

impl KeyboardState {
    pub const fn new() -> Self {
        Self {
            left_shift: false,
            right_shift: false,
            caps_lock: false,
            extended: false,
        }
    }

    pub fn translate(&mut self, scancode: u8) -> Option<u8> {
        if scancode == 0xe0 {
            self.extended = true;
            return None;
        }
        if self.extended {
            self.extended = false;
            return None;
        }

        let released = scancode & 0x80 != 0;
        let code = scancode & 0x7f;
        if released {
            match code {
                0x2a => self.left_shift = false,
                0x36 => self.right_shift = false,
                _ => {}
            }
            return None;
        }

        match code {
            0x2a => {
                self.left_shift = true;
                return None;
            }
            0x36 => {
                self.right_shift = true;
                return None;
            }
            0x3a => {
                self.caps_lock = !self.caps_lock;
                return None;
            }
            0x1c => return Some(b'\r'),
            0x0e => return Some(8),
            0x39 => return Some(b' '),
            _ => {}
        }

        let (normal, shifted) = match code {
            0x02 => (b'1', b'!'),
            0x03 => (b'2', b'@'),
            0x04 => (b'3', b'#'),
            0x05 => (b'4', b'$'),
            0x06 => (b'5', b'%'),
            0x07 => (b'6', b'^'),
            0x08 => (b'7', b'&'),
            0x09 => (b'8', b'*'),
            0x0a => (b'9', b'('),
            0x0b => (b'0', b')'),
            0x0c => (b'-', b'_'),
            0x0d => (b'=', b'+'),
            0x10 => (b'q', b'Q'),
            0x11 => (b'w', b'W'),
            0x12 => (b'e', b'E'),
            0x13 => (b'r', b'R'),
            0x14 => (b't', b'T'),
            0x15 => (b'y', b'Y'),
            0x16 => (b'u', b'U'),
            0x17 => (b'i', b'I'),
            0x18 => (b'o', b'O'),
            0x19 => (b'p', b'P'),
            0x1a => (b'[', b'{'),
            0x1b => (b']', b'}'),
            0x1e => (b'a', b'A'),
            0x1f => (b's', b'S'),
            0x20 => (b'd', b'D'),
            0x21 => (b'f', b'F'),
            0x22 => (b'g', b'G'),
            0x23 => (b'h', b'H'),
            0x24 => (b'j', b'J'),
            0x25 => (b'k', b'K'),
            0x26 => (b'l', b'L'),
            0x27 => (b';', b':'),
            0x28 => (b'\'', b'"'),
            0x29 => (b'`', b'~'),
            0x2b => (b'\\', b'|'),
            0x2c => (b'z', b'Z'),
            0x2d => (b'x', b'X'),
            0x2e => (b'c', b'C'),
            0x2f => (b'v', b'V'),
            0x30 => (b'b', b'B'),
            0x31 => (b'n', b'N'),
            0x32 => (b'm', b'M'),
            0x33 => (b',', b'<'),
            0x34 => (b'.', b'>'),
            0x35 => (b'/', b'?'),
            _ => return None,
        };

        let shift = self.left_shift || self.right_shift;
        let letter = normal.is_ascii_lowercase();
        if letter && self.caps_lock != shift {
            Some(normal - (b'a' - b'A'))
        } else if shift {
            Some(shifted)
        } else {
            Some(normal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KeyboardState;

    #[test]
    fn translates_letters_numbers_and_control_keys() {
        let mut keyboard = KeyboardState::new();
        assert_eq!(keyboard.translate(0x1e), Some(b'a'));
        assert_eq!(keyboard.translate(0x02), Some(b'1'));
        assert_eq!(keyboard.translate(0x1c), Some(b'\r'));
        assert_eq!(keyboard.translate(0x0e), Some(8));
        assert_eq!(keyboard.translate(0x39), Some(b' '));
    }

    #[test]
    fn tracks_shift_and_caps_lock_without_leaking_break_codes() {
        let mut keyboard = KeyboardState::new();
        assert_eq!(keyboard.translate(0x2a), None);
        assert_eq!(keyboard.translate(0x1e), Some(b'A'));
        assert_eq!(keyboard.translate(0xaa), None);
        assert_eq!(keyboard.translate(0x3a), None);
        assert_eq!(keyboard.translate(0x1e), Some(b'A'));
        assert_eq!(keyboard.translate(0xba), None);
    }

    #[test]
    fn ignores_extended_keys_and_preserves_the_next_normal_key() {
        let mut keyboard = KeyboardState::new();
        assert_eq!(keyboard.translate(0xe0), None);
        assert_eq!(keyboard.translate(0x4d), None);
        assert_eq!(keyboard.translate(0x30), Some(b'b'));
    }
}
