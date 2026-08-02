#![no_std]
#![no_main]

use rustos_userland::{
    GRAPHICS_INFO_LENGTH, GraphicsInfo, GraphicsRect, GraphicsWindow, INPUT_EVENT_KEYBOARD,
    INPUT_EVENT_LENGTH, INPUT_EVENT_WINDOW, InputEvent, SYSCALL_EAGAIN, WINDOW_EVENT_CLOSE,
    WINDOW_EVENT_CONFIGURE, close, default_window_geometry, exit, graphics_info,
    graphics_window_clear, graphics_window_create, graphics_window_destroy,
    graphics_window_fill_rect, graphics_window_focus, graphics_window_geometry,
    graphics_window_present, graphics_window_read_event, graphics_window_text, is_syscall_error,
    read_nonblocking, spawn_redirected, waitpid_nonblocking, write, write_stdout, yield_now,
};

const SHELL_PATH: &[u8] = b"/bin/sh\0";
const OUTPUT_BUFFER_LENGTH: usize = 256;
const INPUT_BUFFER_LENGTH: usize = 80;
const TEXT_BUFFER_LENGTH: usize = 96;

const BACKGROUND: u32 = 0x101923;
const TITLE: u32 = 0x1d3046;
const PANEL: u32 = 0x17283a;
const ACCENT: u32 = 0x30d6c6;
const TEXT: u32 = 0xf1f5f9;
const MUTED: u32 = 0xa9bdd2;
const AMBER: u32 = 0xf2b84b;

struct Transcript {
    bytes: [u8; OUTPUT_BUFFER_LENGTH],
    length: usize,
}

impl Transcript {
    const fn new() -> Self {
        Self {
            bytes: [0; OUTPUT_BUFFER_LENGTH],
            length: 0,
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        if bytes.len() >= self.bytes.len() {
            let start = bytes.len() - self.bytes.len();
            self.bytes.copy_from_slice(&bytes[start..]);
            self.length = self.bytes.len();
            return;
        }
        let overflow = self
            .length
            .saturating_add(bytes.len())
            .saturating_sub(self.bytes.len());
        if overflow != 0 {
            self.bytes.copy_within(overflow..self.length, 0);
            self.length -= overflow;
        }
        self.bytes[self.length..self.length + bytes.len()].copy_from_slice(bytes);
        self.length += bytes.len();
    }

    fn visible(&self) -> &[u8] {
        let start = self.length.saturating_sub(TEXT_BUFFER_LENGTH);
        &self.bytes[start..self.length]
    }

    fn contains(&self, needle: &[u8]) -> bool {
        !needle.is_empty()
            && needle.len() <= self.length
            && self.bytes[..self.length]
                .windows(needle.len())
                .any(|window| window == needle)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut info = GraphicsInfo::default();
    if graphics_info(&mut info) != GRAPHICS_INFO_LENGTH as u64 {
        write_stdout(b"terminal: framebuffer info unavailable\n");
        exit(1);
    }

    let geometry = default_window_geometry(info, false);
    let window_id = graphics_window_create(&geometry);
    if is_syscall_error(window_id) {
        write_stdout(b"terminal: window create failed\n");
        exit(2);
    }
    if is_syscall_error(graphics_window_focus(window_id)) {
        write_stdout(b"terminal: window focus failed\n");
        exit(3);
    }

    let input = rustos_userland::pipe();
    let output = rustos_userland::pipe();
    if is_syscall_error(input.read)
        || is_syscall_error(input.write)
        || is_syscall_error(output.read)
        || is_syscall_error(output.write)
    {
        write_stdout(b"terminal: pipe setup failed\n");
        let _ = graphics_window_destroy(window_id);
        exit(4);
    }
    let shell = spawn_redirected(SHELL_PATH, input.read, output.write);
    if is_syscall_error(shell) {
        write_stdout(b"terminal: shell spawn failed\n");
        let _ = close(input.read);
        let _ = close(input.write);
        let _ = close(output.read);
        let _ = close(output.write);
        let _ = graphics_window_destroy(window_id);
        exit(5);
    }
    let _ = close(input.read);
    let _ = close(output.write);
    write_stdout(b"terminal: client surface=ready shell=spawned focus=ready status=ready\n");

    let mut width = geometry.width;
    let mut height = geometry.height;
    let mut transcript = Transcript::new();
    let mut input_line = [0u8; INPUT_BUFFER_LENGTH];
    let mut input_length = 0;
    let mut shell_finished = false;
    let mut shell_reaped = false;
    let mut keyboard_reported = false;
    let mut output_reported = false;
    let mut help_reported = false;
    let mut id_reported = false;
    let mut shell_credentials_reported = false;
    let mut exit_reported = false;
    let mut passwd_current_reported = false;
    let mut passwd_new_reported = false;
    let mut passwd_confirm_reported = false;
    let mut passwd_changed_reported = false;
    let mut admin_password_reported = false;
    let mut passwd_launch_reported = false;
    let mut passwd_output_reported = false;
    let mut useradd_username_reported = false;
    let mut useradd_password_reported = false;
    let mut useradd_confirm_reported = false;
    let mut useradd_created_reported = false;
    let mut lock_prompt_reported = false;
    let mut lock_failure_reported = false;
    let mut lock_unlocked_reported = false;
    let mut lock_command_reported = false;
    let mut password_input_masked = false;
    let mut password_mask_reported = false;
    if !draw_terminal(
        window_id,
        width,
        height,
        transcript.visible(),
        &input_line[..input_length],
        password_input_masked,
        shell_finished,
    ) {
        write_stdout(b"terminal: initial draw failed\n");
        close_terminal(window_id, input.write, output.read, shell);
    }

    loop {
        let mut redraw = false;
        let mut event = InputEvent::default();
        let event_result = graphics_window_read_event(window_id, &mut event);
        if event_result == INPUT_EVENT_LENGTH as u64 {
            if event.kind == INPUT_EVENT_WINDOW {
                if event.code == WINDOW_EVENT_CLOSE {
                    write_stdout(b"terminal: close requested status=ready\n");
                    close_terminal(window_id, input.write, output.read, shell);
                }
                if event.code == WINDOW_EVENT_CONFIGURE {
                    let mut configured = GraphicsWindow::default();
                    if graphics_window_geometry(window_id, &mut configured)
                        != rustos_userland::GRAPHICS_WINDOW_LENGTH as u64
                    {
                        write_stdout(b"terminal: geometry query failed\n");
                        exit(6);
                    }
                    width = configured.width;
                    height = configured.height;
                    redraw = true;
                }
            } else if event.kind == INPUT_EVENT_KEYBOARD {
                let enter = event.code == b'\r' as u32 || event.code == b'\n' as u32;
                let exit_input = enter && input_line[..input_length] == *b"exit";
                if handle_keyboard(event.code, &mut input_line, &mut input_length, input.write) {
                    redraw = true;
                    if enter {
                        password_input_masked = false;
                    }
                    if password_input_masked && input_length != 0 && !password_mask_reported {
                        write_stdout(b"terminal: password input masked status=ready\n");
                        password_mask_reported = true;
                    }
                    if exit_input {
                        write_stdout(b"terminal: exit input submitted status=ready\n");
                    }
                    if enter {
                        write_stdout(b"terminal: command submitted status=ready\n");
                    }
                }
                if !keyboard_reported {
                    write_stdout(b"terminal: keyboard input routed status=ready\n");
                    keyboard_reported = true;
                }
            }
        } else if is_syscall_error(event_result) {
            write_stdout(b"terminal: input read failed\n");
            close_terminal(window_id, input.write, output.read, shell);
        }

        let mut output_bytes = [0u8; TEXT_BUFFER_LENGTH];
        let output_result = read_nonblocking(output.read, &mut output_bytes);
        if output_result == 0 {
            if !shell_finished {
                shell_finished = true;
                write_stdout(b"terminal: shell exited status=ready\n");
                redraw = true;
            }
        } else if output_result == SYSCALL_EAGAIN {
            // The shell is still live and has not produced another screen update yet.
        } else if is_syscall_error(output_result) {
            write_stdout(b"terminal: shell output read failed\n");
            close_terminal(window_id, input.write, output.read, shell);
        } else {
            let output = &output_bytes[..output_result as usize];
            transcript.append(output);
            redraw = true;
            if !output_reported {
                write_stdout(b"terminal: shell output received status=ready\n");
                output_reported = true;
            }
            if !help_reported && transcript.contains(b"commands:") {
                write_stdout(b"terminal: shell command output=help status=ready\n");
                help_reported = true;
            }
            if !shell_credentials_reported
                && transcript.contains(b"shell: credentials uid=1000 gid=1000 status=ready")
            {
                write_stdout(b"terminal: shell credentials uid=1000 gid=1000 status=ready\n");
                shell_credentials_reported = true;
            }
            if !id_reported && transcript.contains(b"shell: id command status=ready") {
                write_stdout(b"terminal: shell id command output=ready\n");
                id_reported = true;
            }
            if !exit_reported && transcript.contains(b"shell: exit requested") {
                write_stdout(b"terminal: shell exit acknowledged status=ready\n");
                exit_reported = true;
            }
            if !passwd_current_reported && transcript.contains(b"passwd: current password: ") {
                write_stdout(b"terminal: passwd current prompt=ready\n");
                passwd_current_reported = true;
            }
            if !passwd_new_reported && transcript.contains(b"passwd: new password: ") {
                write_stdout(b"terminal: passwd new prompt=ready\n");
                passwd_new_reported = true;
            }
            if !passwd_confirm_reported && transcript.contains(b"passwd: retype new password: ") {
                write_stdout(b"terminal: passwd confirm prompt=ready\n");
                passwd_confirm_reported = true;
            }
            if !admin_password_reported
                && transcript.contains(b"admin: password updated status=ready")
            {
                write_stdout(b"terminal: admin password updated status=ready\n");
                admin_password_reported = true;
            }
            if !passwd_changed_reported && transcript.contains(b"passwd: changed status=ready") {
                write_stdout(b"terminal: passwd changed status=ready\n");
                passwd_changed_reported = true;
            }
            if !passwd_launch_reported && transcript.contains(b"shell: passwd launch status=ready")
            {
                write_stdout(b"terminal: passwd launch=ready\n");
                passwd_launch_reported = true;
            }
            if !passwd_output_reported
                && transcript.contains(b"passwd: ")
                && !passwd_current_reported
            {
                write_stdout(b"terminal: passwd output=ready\n");
                passwd_output_reported = true;
            }
            if bytes_contain(output, b"useradd: password: ")
                || bytes_contain(output, b"useradd: retype password: ")
                || bytes_contain(output, b"lock: password: ")
                || bytes_contain(output, b"passwd: current password: ")
                || bytes_contain(output, b"passwd: new password: ")
                || bytes_contain(output, b"passwd: retype new password: ")
            {
                password_input_masked = true;
            }
            if password_input_masked && input_length != 0 && !password_mask_reported {
                write_stdout(b"terminal: password input masked status=ready\n");
                password_mask_reported = true;
            }
            if !useradd_username_reported && transcript.contains(b"useradd: username: ") {
                write_stdout(b"terminal: useradd username prompt=ready\n");
                useradd_username_reported = true;
            }
            if !useradd_password_reported && transcript.contains(b"useradd: password: ") {
                write_stdout(b"terminal: useradd password prompt=ready\n");
                useradd_password_reported = true;
            }
            if !useradd_confirm_reported && transcript.contains(b"useradd: retype password: ") {
                write_stdout(b"terminal: useradd confirm prompt=ready\n");
                useradd_confirm_reported = true;
            }
            if !useradd_created_reported
                && (transcript.contains(b"useradd: account created status=ready")
                    || transcript.contains(b"admin: account created username="))
            {
                write_stdout(b"terminal: useradd account created status=ready\n");
                useradd_created_reported = true;
            }
            if !lock_prompt_reported && transcript.contains(b"lock: password: ") {
                write_stdout(b"terminal: lock prompt=ready\n");
                lock_prompt_reported = true;
            }
            if !lock_failure_reported
                && transcript.contains(b"lock: authentication failed status=ready")
            {
                write_stdout(b"terminal: lock authentication failed status=ready\n");
                lock_failure_reported = true;
            }
            if !lock_unlocked_reported
                && transcript.contains(b"lock: session unlocked status=ready")
            {
                write_stdout(b"terminal: lock unlocked status=ready\n");
                lock_unlocked_reported = true;
            }
            if !lock_command_reported && transcript.contains(b"shell: lock status=ready") {
                write_stdout(b"terminal: lock command status=ready\n");
                lock_command_reported = true;
            }
        }
        if !shell_reaped && (shell_finished || exit_reported) {
            let wait_result = waitpid_nonblocking(shell);
            if wait_result.pid == shell {
                shell_reaped = true;
                shell_finished = true;
                write_stdout(b"terminal: shell reaped status=ready\n");
                redraw = true;
            }
        }

        if shell_reaped {
            write_stdout(b"terminal: logout requested status=ready\n");
            let _ = close(input.write);
            let _ = close(output.read);
            let _ = graphics_window_destroy(window_id);
            exit(0);
        }

        if redraw
            && !draw_terminal(
                window_id,
                width,
                height,
                transcript.visible(),
                &input_line[..input_length],
                password_input_masked,
                shell_finished,
            )
        {
            write_stdout(b"terminal: redraw failed\n");
            close_terminal(window_id, input.write, output.read, shell);
        }
        yield_now();
    }
}

fn handle_keyboard(
    code: u32,
    line: &mut [u8; INPUT_BUFFER_LENGTH],
    length: &mut usize,
    fd: u64,
) -> bool {
    let Ok(byte) = u8::try_from(code) else {
        return false;
    };
    if byte == 8 || byte == 127 {
        if *length == 0 {
            return false;
        }
        *length -= 1;
        return true;
    }
    if byte == b'\r' || byte == b'\n' {
        let mut submitted = [0u8; INPUT_BUFFER_LENGTH];
        submitted[..*length].copy_from_slice(&line[..*length]);
        submitted[*length] = b'\n';
        let count = write(fd, &submitted[..*length + 1]);
        if is_syscall_error(count) || count != (*length + 1) as u64 {
            write_stdout(b"terminal: shell input write failed\n");
            return false;
        }
        *length = 0;
        return true;
    }
    if !(0x20..=0x7e).contains(&byte) || *length + 1 >= line.len() {
        return false;
    }
    line[*length] = byte;
    *length += 1;
    true
}

fn bytes_contain(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= bytes.len()
        && bytes.windows(needle.len()).any(|window| window == needle)
}

fn draw_terminal(
    window_id: u64,
    width: u32,
    height: u32,
    output: &[u8],
    input: &[u8],
    input_masked: bool,
    shell_finished: bool,
) -> bool {
    if is_syscall_error(graphics_window_clear(window_id)) {
        return false;
    }
    let rectangles = [
        GraphicsRect {
            x: 0,
            y: 0,
            width,
            height,
            color: BACKGROUND,
        },
        GraphicsRect {
            x: 0,
            y: 0,
            width,
            height: height.min(42),
            color: TITLE,
        },
        GraphicsRect {
            x: 0,
            y: 40,
            width,
            height: 2,
            color: ACCENT,
        },
        GraphicsRect {
            x: 14,
            y: 58,
            width: width.saturating_sub(28),
            height: height.saturating_sub(112).max(1),
            color: PANEL,
        },
        GraphicsRect {
            x: 14,
            y: height.saturating_sub(42),
            width: width.saturating_sub(28),
            height: 28,
            color: TITLE,
        },
    ];
    for rectangle in rectangles {
        if is_syscall_error(graphics_window_fill_rect(window_id, &rectangle)) {
            return false;
        }
    }

    if is_syscall_error(graphics_window_text(
        window_id,
        14,
        12,
        TEXT,
        b"RUSTOS TERMINAL",
    )) {
        return false;
    }
    if !output.is_empty() && is_syscall_error(graphics_window_text(window_id, 22, 66, TEXT, output))
    {
        return false;
    }
    let mut input_text = [0u8; TEXT_BUFFER_LENGTH];
    input_text[0] = b'>';
    input_text[1] = b' ';
    let input_length = input.len().min(TEXT_BUFFER_LENGTH - 2);
    if input_masked {
        input_text[2..2 + input_length].fill(b'*');
    } else {
        input_text[2..2 + input_length].copy_from_slice(&input[..input_length]);
    }
    if is_syscall_error(graphics_window_text(
        window_id,
        22,
        height.saturating_sub(34),
        AMBER,
        &input_text[..input_length + 2],
    )) {
        return false;
    }
    let status = if shell_finished {
        b"SHELL EXITED".as_slice()
    } else {
        b"SHELL READY".as_slice()
    };
    if is_syscall_error(graphics_window_text(
        window_id,
        width.saturating_sub(120),
        12,
        MUTED,
        status,
    )) {
        return false;
    }
    !is_syscall_error(graphics_window_present(window_id))
}

fn close_terminal(window_id: u64, input_fd: u64, output_fd: u64, shell: u64) -> ! {
    let _ = write(input_fd, b"exit\n");
    let _ = rustos_userland::waitpid(shell);
    let _ = close(input_fd);
    let _ = close(output_fd);
    let _ = graphics_window_destroy(window_id);
    exit(0);
}
