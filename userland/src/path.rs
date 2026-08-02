pub const MAX_PATH_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathBuf {
    bytes: [u8; MAX_PATH_LENGTH],
    length: usize,
}

impl PathBuf {
    pub const fn root() -> Self {
        let mut bytes = [0; MAX_PATH_LENGTH];
        bytes[0] = b'/';
        Self { bytes, length: 1 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub fn write_nul<'a>(&self, buffer: &'a mut [u8; MAX_PATH_LENGTH]) -> Option<&'a [u8]> {
        let end = self.length.checked_add(1)?;
        if end > buffer.len() {
            return None;
        }
        buffer[..self.length].copy_from_slice(self.as_bytes());
        buffer[self.length] = 0;
        Some(&buffer[..end])
    }

    fn append_component(&mut self, component: &[u8]) -> bool {
        if component.is_empty() || component == b"." {
            return true;
        }
        if component == b".." {
            if self.length > 1 {
                let mut length = self.length - 1;
                while length > 1 && self.bytes[length - 1] != b'/' {
                    length -= 1;
                }
                self.length = if length > 1 { length - 1 } else { 1 };
            }
            return true;
        }
        if component.iter().any(|byte| *byte == 0) {
            return false;
        }
        let separator = usize::from(self.length > 1);
        let Some(end) = self
            .length
            .checked_add(separator)
            .and_then(|length| length.checked_add(component.len()))
        else {
            return false;
        };
        if end >= MAX_PATH_LENGTH {
            return false;
        }
        if separator != 0 {
            self.bytes[self.length] = b'/';
            self.length += 1;
        }
        self.bytes[self.length..end].copy_from_slice(component);
        self.length = end;
        true
    }
}

pub fn resolve(cwd: &PathBuf, input: &[u8]) -> Option<PathBuf> {
    let mut path = if input.first() == Some(&b'/') {
        PathBuf::root()
    } else {
        *cwd
    };
    let mut start = 0;
    while start <= input.len() {
        let end = input[start..]
            .iter()
            .position(|byte| *byte == b'/')
            .map_or(input.len(), |offset| start + offset);
        if !path.append_component(&input[start..end]) {
            return None;
        }
        if end == input.len() {
            break;
        }
        start = end + 1;
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_absolute_and_relative_paths() {
        let cwd = resolve(&PathBuf::root(), b"/home/user").unwrap();
        assert_eq!(
            resolve(&cwd, b"notes/../draft.txt").unwrap().as_bytes(),
            b"/home/user/draft.txt"
        );
        assert_eq!(
            resolve(&cwd, b"/etc/./rustos").unwrap().as_bytes(),
            b"/etc/rustos"
        );
    }

    #[test]
    fn clamps_parent_navigation_at_root() {
        let root = PathBuf::root();
        assert_eq!(resolve(&root, b"../../tmp").unwrap().as_bytes(), b"/tmp");
    }

    #[test]
    fn rejects_paths_that_do_not_fit_the_abi_buffer() {
        let root = PathBuf::root();
        let long = [b'x'; MAX_PATH_LENGTH];
        assert!(resolve(&root, &long).is_none());
    }
}
