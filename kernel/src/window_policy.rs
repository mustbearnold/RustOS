#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowOrder<const CAPACITY: usize> {
    entries: [u8; CAPACITY],
    length: usize,
}

impl<const CAPACITY: usize> WindowOrder<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            entries: [0; CAPACITY],
            length: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn get(&self, position: usize) -> Option<usize> {
        (position < self.length).then_some(usize::from(self.entries[position]))
    }

    pub fn raise(&mut self, index: usize) {
        if index >= CAPACITY {
            return;
        }
        if let Some(position) =
            (0..self.length).find(|position| usize::from(self.entries[*position]) == index)
        {
            for offset in position..self.length.saturating_sub(1) {
                self.entries[offset] = self.entries[offset + 1];
            }
            self.entries[self.length - 1] = index as u8;
        } else if self.length < CAPACITY {
            self.entries[self.length] = index as u8;
            self.length += 1;
        }
    }

    pub fn remove(&mut self, index: usize) {
        let Some(position) =
            (0..self.length).find(|position| usize::from(self.entries[*position]) == index)
        else {
            return;
        };
        for offset in position..self.length.saturating_sub(1) {
            self.entries[offset] = self.entries[offset + 1];
        }
        self.length -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::WindowOrder;

    fn order<const CAPACITY: usize>(stack: &WindowOrder<CAPACITY>) -> [Option<usize>; CAPACITY] {
        core::array::from_fn(|position| stack.get(position))
    }

    #[test]
    fn raises_new_and_existing_windows_to_the_front() {
        let mut stack = WindowOrder::<4>::new();
        stack.raise(0);
        stack.raise(1);
        stack.raise(2);
        assert_eq!(order(&stack), [Some(0), Some(1), Some(2), None]);

        stack.raise(1);
        assert_eq!(order(&stack), [Some(0), Some(2), Some(1), None]);
    }

    #[test]
    fn removes_a_window_without_corrupting_the_remaining_stack() {
        let mut stack = WindowOrder::<4>::new();
        for index in 0..4 {
            stack.raise(index);
        }
        stack.remove(1);
        assert_eq!(order(&stack), [Some(0), Some(2), Some(3), None]);
        stack.raise(1);
        assert_eq!(order(&stack), [Some(0), Some(2), Some(3), Some(1)]);
    }
}
