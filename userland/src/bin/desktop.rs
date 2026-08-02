#![no_std]
#![no_main]

use rustos_userland::{
    CREDENTIALS_LENGTH, Credentials, GRAPHICS_INFO_LENGTH, GraphicsInfo, GraphicsPointerEvent,
    GraphicsRect, GraphicsWindow, INPUT_EVENT_KEYBOARD, INPUT_EVENT_LENGTH, INPUT_EVENT_MOUSE,
    InputEvent, default_window_geometry, exit, get_credentials, graphics_acquire,
    graphics_compose_windows, graphics_fill_rect, graphics_info, graphics_release, graphics_text,
    graphics_window_configure, graphics_window_dispatch_keyboard, graphics_window_dispatch_pointer,
    graphics_window_request_close, input_read, is_syscall_error, spawn, waitpid,
    waitpid_nonblocking, write_stdout, yield_now,
};

const BACKGROUND: u32 = 0x0b1220;
const TOP_BAR: u32 = 0x111d31;
const SIDEBAR: u32 = 0x0f1828;
const PANEL: u32 = 0x16243b;
const PANEL_RAISED: u32 = 0x1d2d48;
const ACCENT: u32 = 0x30d6c6;
const BLUE: u32 = 0x5b8cff;
const GREEN: u32 = 0x3ddc97;
const AMBER: u32 = 0xf2b84b;
const TEXT: u32 = 0xf1f5f9;
const MUTED: u32 = 0x9fb3c8;
const TITLE_BAR_HEIGHT: u32 = 42;
const CLOSE_BUTTON_WIDTH: u32 = 34;
const RESIZE_GRAB_SIZE: u32 = 20;
const MIN_WINDOW_WIDTH: u32 = 180;
const MIN_WINDOW_HEIGHT: u32 = 180;
const LOGOUT_BUTTON_WIDTH: u32 = 132;
const LOGOUT_BUTTON_HEIGHT: u32 = 36;
const LOGOUT_BUTTON_X_MARGIN: u32 = 18;
const LOGOUT_BUTTON_Y: u32 = 18;

#[derive(Clone, Copy)]
struct ManagedWindow {
    id: u64,
    pid: u64,
    geometry: GraphicsWindow,
    live: bool,
}

impl ManagedWindow {
    const fn new(id: u64, pid: u64, geometry: GraphicsWindow) -> Self {
        Self {
            id,
            pid,
            geometry,
            live: true,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut credentials = Credentials::default();
    if get_credentials(&mut credentials) != CREDENTIALS_LENGTH as u64 {
        write_stdout(b"desktop: credentials unavailable\n");
        exit(1);
    }
    write_stdout(b"desktop: credentials uid=");
    write_decimal(credentials.uid);
    write_stdout(b" gid=");
    write_decimal(credentials.gid);
    write_stdout(b" status=ready\n");

    let mut info = GraphicsInfo::default();
    if graphics_info(&mut info) != GRAPHICS_INFO_LENGTH as u64 {
        write_stdout(b"desktop: framebuffer info unavailable\n");
        exit(2);
    }
    if is_syscall_error(graphics_acquire()) {
        write_stdout(b"desktop: framebuffer acquire failed\n");
        exit(3);
    }
    let primary_window_pid = spawn(b"/bin/terminal\0");
    if is_syscall_error(primary_window_pid) {
        write_stdout(b"desktop: terminal client spawn failed\n");
        exit(4);
    }
    let secondary_window_pid = spawn(b"/bin/window-secondary\0");
    if is_syscall_error(secondary_window_pid) {
        write_stdout(b"desktop: secondary window client spawn failed\n");
        exit(4);
    }
    let mut managed_windows = [
        ManagedWindow::new(1, primary_window_pid, default_window_geometry(info, false)),
        ManagedWindow::new(2, secondary_window_pid, default_window_geometry(info, true)),
    ];
    if !render_scene(info) || is_syscall_error(graphics_compose_windows()) {
        write_stdout(b"desktop: compositor draw failed\n");
        exit(5);
    }
    let mut cursor_x = info.width / 2;
    let mut cursor_y = info.height / 2;
    let mut buttons = 0;
    if !draw_cursor(cursor_x, cursor_y, buttons) {
        write_stdout(b"desktop: cursor draw failed\n");
        exit(6);
    }
    if is_syscall_error(graphics_compose_windows()) {
        write_stdout(b"desktop: initial GPU present failed\n");
        exit(6);
    }
    write_stdout(b"desktop: compositor framebuffer=ready scene=ready status=ready\n");

    // Keep the session alive so the framebuffer remains owned by the compositor. The cursor and
    // status indicator are intentionally redrawn through the same userland graphics ABI.
    let mut phase = false;
    let mut idle_loops = 0u32;
    let mut input_reported = false;
    let mut keyboard_reported = false;
    let mut focused_window = 0u64;
    let mut drag_window = 0u64;
    let mut resize_target = 0u64;
    let mut drag_offset_x = 0i32;
    let mut drag_offset_y = 0i32;
    let mut previous_buttons = 0u32;
    loop {
        let mut event = InputEvent::default();
        if input_read(&mut event) == INPUT_EVENT_LENGTH as u64 && event.kind == INPUT_EVENT_MOUSE {
            cursor_x = move_pointer(cursor_x, event.dx, info.width.saturating_sub(12));
            cursor_y = move_pointer(cursor_y, event.dy, info.height.saturating_sub(20));
            buttons = event.buttons;
            let left_down = event.buttons & 1 != 0 && previous_buttons & 1 == 0;
            let left_up = event.buttons & 1 == 0 && previous_buttons & 1 != 0;
            let mut gesture_active = false;
            if drag_window != 0 {
                gesture_active = true;
                if event.buttons & 1 != 0 {
                    if move_window(
                        &mut managed_windows,
                        drag_window,
                        cursor_x,
                        cursor_y,
                        drag_offset_x,
                        drag_offset_y,
                        info,
                    ) {
                        write_stdout(b"desktop: window moved status=ready\n");
                    }
                } else if left_up {
                    write_stdout(b"desktop: window drag completed status=ready\n");
                    drag_window = 0;
                }
            } else if resize_target != 0 {
                gesture_active = true;
                if event.buttons & 1 != 0 {
                    if resize_window(
                        &mut managed_windows,
                        resize_target,
                        cursor_x,
                        cursor_y,
                        info,
                    ) {
                        write_stdout(b"desktop: window resized status=ready\n");
                    }
                } else if left_up {
                    if resize_window(
                        &mut managed_windows,
                        resize_target,
                        cursor_x,
                        cursor_y,
                        info,
                    ) {
                        write_stdout(b"desktop: window resized status=ready\n");
                    }
                    write_stdout(b"desktop: window resize completed status=ready\n");
                    resize_target = 0;
                }
            }
            if !gesture_active {
                if left_down && logout_button(info, cursor_x, cursor_y) {
                    write_stdout(b"desktop: logout button pressed status=ready\n");
                    if logout_session(
                        &mut managed_windows,
                        primary_window_pid,
                        secondary_window_pid,
                    ) {
                        exit(0);
                    }
                    write_stdout(b"desktop: logout failed\n");
                    exit(12);
                }
                let pointer = GraphicsPointerEvent {
                    x: cursor_x,
                    y: cursor_y,
                    buttons: event.buttons,
                    dx: event.dx,
                    dy: event.dy,
                    wheel: event.wheel,
                };
                let hit_window = graphics_window_dispatch_pointer(&pointer);
                if is_syscall_error(hit_window) {
                    write_stdout(b"desktop: pointer dispatch failed\n");
                    exit(6);
                }
                if event.buttons != 0 && hit_window != 0 && hit_window != focused_window {
                    write_stdout(b"desktop: window focus raised status=ready\n");
                    focused_window = hit_window;
                }
                if event.buttons != 0 {
                    if hit_window == 1 {
                        write_stdout(b"desktop: pointer button hit window=1 status=ready\n");
                    } else if hit_window == 2 {
                        write_stdout(b"desktop: pointer button hit window=2 status=ready\n");
                    }
                }
                let edge_window = if left_down && hit_window == 0 {
                    resize_edge_window(&managed_windows, cursor_x, cursor_y)
                } else {
                    0
                };
                let policy_window = if hit_window != 0 {
                    hit_window
                } else {
                    edge_window
                };
                if left_down && policy_window != 0 {
                    if close_button(&managed_windows, policy_window, cursor_x, cursor_y) {
                        if is_syscall_error(graphics_window_request_close(policy_window)) {
                            write_stdout(b"desktop: window close request failed\n");
                            exit(10);
                        }
                        write_stdout(b"desktop: window close requested status=ready\n");
                        let pid = managed_windows
                            .iter()
                            .find(|window| window.id == policy_window)
                            .map_or(0, |window| window.pid);
                        if pid != 0 {
                            let result = waitpid(pid);
                            if result.pid == pid && result.status == 0 {
                                write_stdout(b"desktop: window client reaped status=ready\n");
                            } else {
                                write_stdout(b"desktop: window client reap failed\n");
                                exit(11);
                            }
                        }
                        if let Some(window) = managed_windows
                            .iter_mut()
                            .find(|window| window.id == policy_window)
                        {
                            window.live = false;
                        }
                        if focused_window == policy_window {
                            focused_window = 0;
                        }
                    } else if resize_grab(&managed_windows, policy_window, cursor_x, cursor_y)
                        || edge_window == policy_window
                    {
                        resize_target = policy_window;
                        write_stdout(b"desktop: window resize started status=ready\n");
                    } else if event.buttons & 1 != 0
                        && title_bar(&managed_windows, policy_window, cursor_x, cursor_y)
                    {
                        if let Some(window) = managed_windows
                            .iter()
                            .find(|window| window.id == policy_window)
                        {
                            drag_window = policy_window;
                            drag_offset_x = cursor_x as i32 - window.geometry.x as i32;
                            drag_offset_y = cursor_y as i32 - window.geometry.y as i32;
                            write_stdout(b"desktop: window drag started status=ready\n");
                        }
                    }
                }
            }
            previous_buttons = event.buttons;
            if !render_scene(info)
                || is_syscall_error(graphics_compose_windows())
                || !draw_cursor(cursor_x, cursor_y, buttons)
                || is_syscall_error(graphics_compose_windows())
            {
                write_stdout(b"desktop: pointer redraw failed\n");
                exit(7);
            }
            if !input_reported {
                write_stdout(b"desktop: pointer event received status=ready\n");
                input_reported = true;
            }
        } else if event.kind == INPUT_EVENT_KEYBOARD {
            if is_syscall_error(graphics_window_dispatch_keyboard(&event)) {
                write_stdout(b"desktop: keyboard dispatch failed\n");
                exit(8);
            }
            if !keyboard_reported {
                write_stdout(b"desktop: keyboard event received status=ready\n");
                keyboard_reported = true;
            }
        }
        yield_now();
        idle_loops = idle_loops.saturating_add(1);
        if idle_loops >= 2048 {
            let indicator = GraphicsRect {
                x: info.width.saturating_sub(40),
                y: 30,
                width: 12,
                height: 12,
                color: if phase { ACCENT } else { GREEN },
            };
            let _ = graphics_fill_rect(&indicator);
            let _ = graphics_compose_windows();
            if draw_cursor(cursor_x, cursor_y, buttons) {
                let _ = graphics_compose_windows();
            }
            phase = !phase;
            idle_loops = 0;
        }

        if managed_windows[0].live {
            let terminal_result = waitpid_nonblocking(primary_window_pid);
            if terminal_result.pid == primary_window_pid {
                write_stdout(b"desktop: terminal logout observed status=ready\n");
                managed_windows[0].live = false;
                if managed_windows[1].live {
                    if is_syscall_error(graphics_window_request_close(2)) {
                        write_stdout(b"desktop: secondary logout request failed\n");
                        exit(12);
                    }
                    let secondary_result = waitpid(secondary_window_pid);
                    if secondary_result.pid != secondary_window_pid
                        || is_syscall_error(secondary_result.pid)
                    {
                        write_stdout(b"desktop: secondary client reap failed\n");
                        exit(13);
                    }
                    write_stdout(b"desktop: session clients reaped status=ready\n");
                }
                if is_syscall_error(graphics_release()) {
                    write_stdout(b"desktop: framebuffer release failed\n");
                    exit(14);
                }
                exit(0);
            }
        }
    }
}

fn move_pointer(position: u32, delta: i32, limit: u32) -> u32 {
    (i64::from(position) + i64::from(delta)).clamp(0, i64::from(limit)) as u32
}

fn logout_button(info: GraphicsInfo, x: u32, y: u32) -> bool {
    let button_x = info
        .width
        .saturating_sub(LOGOUT_BUTTON_WIDTH.saturating_add(LOGOUT_BUTTON_X_MARGIN));
    x >= button_x
        && x < button_x.saturating_add(LOGOUT_BUTTON_WIDTH)
        && y >= LOGOUT_BUTTON_Y
        && y < LOGOUT_BUTTON_Y.saturating_add(LOGOUT_BUTTON_HEIGHT)
}

fn logout_session(windows: &mut [ManagedWindow; 2], primary_pid: u64, secondary_pid: u64) -> bool {
    write_stdout(b"desktop: logout requested status=ready\n");
    for window_id in [1, 2] {
        if windows
            .iter()
            .find(|window| window.id == window_id)
            .is_some_and(|window| window.live)
            && is_syscall_error(graphics_window_request_close(window_id))
        {
            write_stdout(b"desktop: logout close request failed\n");
            return false;
        }
    }

    let primary = waitpid(primary_pid);
    if primary.pid != primary_pid || is_syscall_error(primary.pid) || primary.status != 0 {
        write_stdout(b"desktop: terminal logout reap failed\n");
        return false;
    }
    let secondary = waitpid(secondary_pid);
    if secondary.pid != secondary_pid || is_syscall_error(secondary.pid) || secondary.status != 0 {
        write_stdout(b"desktop: secondary logout reap failed\n");
        return false;
    }
    for window in windows.iter_mut() {
        window.live = false;
    }
    write_stdout(b"desktop: session clients reaped status=ready\n");
    if is_syscall_error(graphics_release()) {
        write_stdout(b"desktop: framebuffer release failed\n");
        return false;
    }
    write_stdout(b"desktop: framebuffer released status=ready\n");
    true
}

fn title_bar(windows: &[ManagedWindow; 2], id: u64, x: u32, y: u32) -> bool {
    windows.iter().any(|window| {
        window.live
            && window.id == id
            && x >= window.geometry.x
            && x < window.geometry.x.saturating_add(window.geometry.width)
            && y >= window.geometry.y
            && y < window.geometry.y.saturating_add(TITLE_BAR_HEIGHT)
    })
}

fn close_button(windows: &[ManagedWindow; 2], id: u64, x: u32, y: u32) -> bool {
    windows.iter().any(|window| {
        window.live
            && window.id == id
            && x >= window
                .geometry
                .x
                .saturating_add(window.geometry.width.saturating_sub(CLOSE_BUTTON_WIDTH))
            && x < window.geometry.x.saturating_add(window.geometry.width)
            && y >= window.geometry.y
            && y < window.geometry.y.saturating_add(TITLE_BAR_HEIGHT)
    })
}

fn resize_grab(windows: &[ManagedWindow; 2], id: u64, x: u32, y: u32) -> bool {
    windows.iter().any(|window| {
        window.live
            && window.id == id
            && x >= window
                .geometry
                .x
                .saturating_add(window.geometry.width.saturating_sub(RESIZE_GRAB_SIZE))
            && y >= window
                .geometry
                .y
                .saturating_add(window.geometry.height.saturating_sub(RESIZE_GRAB_SIZE))
            && x < window.geometry.x.saturating_add(window.geometry.width)
            && y < window.geometry.y.saturating_add(window.geometry.height)
    })
}

fn resize_edge_window(windows: &[ManagedWindow; 2], x: u32, y: u32) -> u64 {
    windows
        .iter()
        .find(|window| {
            if !window.live {
                return false;
            }
            let right = window.geometry.x.saturating_add(window.geometry.width);
            let bottom = window.geometry.y.saturating_add(window.geometry.height);
            x >= right.saturating_sub(RESIZE_GRAB_SIZE)
                && x <= right.saturating_add(64)
                && y >= bottom.saturating_sub(RESIZE_GRAB_SIZE)
                && y <= bottom.saturating_add(64)
        })
        .map_or(0, |window| window.id)
}

fn move_window(
    windows: &mut [ManagedWindow; 2],
    id: u64,
    cursor_x: u32,
    cursor_y: u32,
    offset_x: i32,
    offset_y: i32,
    info: GraphicsInfo,
) -> bool {
    let Some(window) = windows
        .iter_mut()
        .find(|window| window.live && window.id == id)
    else {
        return false;
    };
    let x = (cursor_x as i32 - offset_x)
        .clamp(0, info.width.saturating_sub(window.geometry.width) as i32) as u32;
    let y = (cursor_y as i32 - offset_y)
        .clamp(0, info.height.saturating_sub(window.geometry.height) as i32) as u32;
    if x == window.geometry.x && y == window.geometry.y {
        return false;
    }
    let geometry = GraphicsWindow {
        x,
        y,
        ..window.geometry
    };
    if is_syscall_error(graphics_window_configure(window.id, &geometry)) {
        return false;
    }
    window.geometry = geometry;
    true
}

fn resize_window(
    windows: &mut [ManagedWindow; 2],
    id: u64,
    cursor_x: u32,
    cursor_y: u32,
    info: GraphicsInfo,
) -> bool {
    let Some(window) = windows
        .iter_mut()
        .find(|window| window.live && window.id == id)
    else {
        return false;
    };
    let max_width = info.width.saturating_sub(window.geometry.x);
    let max_height = info.height.saturating_sub(window.geometry.y);
    let width = cursor_x
        .saturating_sub(window.geometry.x)
        .clamp(MIN_WINDOW_WIDTH, max_width);
    let height = cursor_y
        .saturating_sub(window.geometry.y)
        .clamp(MIN_WINDOW_HEIGHT, max_height);
    if width == window.geometry.width && height == window.geometry.height {
        return false;
    }
    let geometry = GraphicsWindow {
        width,
        height,
        ..window.geometry
    };
    if is_syscall_error(graphics_window_configure(window.id, &geometry)) {
        return false;
    }
    window.geometry = geometry;
    true
}

fn draw_cursor(x: u32, y: u32, buttons: u32) -> bool {
    let color = if buttons & 1 != 0 { AMBER } else { ACCENT };
    let vertical = GraphicsRect {
        x,
        y,
        width: 3,
        height: 18,
        color,
    };
    let horizontal = GraphicsRect {
        x,
        y,
        width: 12,
        height: 3,
        color,
    };
    let tip = GraphicsRect {
        x: x.saturating_add(8),
        y: y.saturating_add(8),
        width: 4,
        height: 4,
        color: TEXT,
    };
    !is_syscall_error(graphics_fill_rect(&vertical))
        && !is_syscall_error(graphics_fill_rect(&horizontal))
        && !is_syscall_error(graphics_fill_rect(&tip))
}

fn render_scene(info: GraphicsInfo) -> bool {
    let width = info.width.max(1);
    let height = info.height.max(1);
    let sidebar_width = width.min(220);
    let content_x = sidebar_width.saturating_add(32);
    let content_width = width.saturating_sub(content_x.saturating_add(32)).max(1);
    let card_gap = 16;
    let card_width = content_width
        .saturating_sub(card_gap * 2)
        .saturating_div(3)
        .max(1);

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
            height: height.min(72),
            color: TOP_BAR,
        },
        GraphicsRect {
            x: 0,
            y: 72,
            width: sidebar_width,
            height: height.saturating_sub(72),
            color: SIDEBAR,
        },
        GraphicsRect {
            x: 0,
            y: 70,
            width,
            height: 2,
            color: ACCENT,
        },
        GraphicsRect {
            x: width.saturating_sub(LOGOUT_BUTTON_WIDTH.saturating_add(LOGOUT_BUTTON_X_MARGIN)),
            y: LOGOUT_BUTTON_Y,
            width: LOGOUT_BUTTON_WIDTH,
            height: LOGOUT_BUTTON_HEIGHT,
            color: PANEL_RAISED,
        },
        GraphicsRect {
            x: content_x,
            y: 96,
            width: content_width,
            height: 128,
            color: PANEL,
        },
        GraphicsRect {
            x: content_x,
            y: 252,
            width: card_width,
            height: 136,
            color: PANEL,
        },
        GraphicsRect {
            x: content_x.saturating_add(card_width + card_gap),
            y: 252,
            width: card_width,
            height: 136,
            color: PANEL,
        },
        GraphicsRect {
            x: content_x.saturating_add((card_width + card_gap) * 2),
            y: 252,
            width: card_width,
            height: 136,
            color: PANEL,
        },
        GraphicsRect {
            x: content_x,
            y: 416,
            width: content_width,
            height: height.saturating_sub(448).max(1),
            color: PANEL_RAISED,
        },
        GraphicsRect {
            x: 28,
            y: 120,
            width: 4,
            height: 34,
            color: ACCENT,
        },
        GraphicsRect {
            x: 28,
            y: 174,
            width: 4,
            height: 34,
            color: BLUE,
        },
        GraphicsRect {
            x: 28,
            y: 228,
            width: 4,
            height: 34,
            color: AMBER,
        },
    ];
    for rectangle in rectangles {
        if is_syscall_error(graphics_fill_rect(&rectangle)) {
            return false;
        }
    }

    let texts = [
        (24, 22, TEXT, b"RustOS Desktop".as_slice()),
        (
            content_x + 24,
            22,
            MUTED,
            b"RUST-OWNED DESKTOP SESSION".as_slice(),
        ),
        (
            width
                .saturating_sub(LOGOUT_BUTTON_WIDTH.saturating_add(LOGOUT_BUTTON_X_MARGIN))
                .saturating_add(20),
            30,
            ACCENT,
            b"LOG OUT".as_slice(),
        ),
        (32, 128, TEXT, b"Overview".as_slice()),
        (32, 182, MUTED, b"Storage".as_slice()),
        (32, 236, MUTED, b"Network".as_slice()),
        (content_x + 24, 118, TEXT, b"System overview".as_slice()),
        (
            content_x + 24,
            150,
            MUTED,
            b"A Rust kernel, Rust userland, and a native graphics boundary".as_slice(),
        ),
        (content_x + 20, 274, MUTED, b"SYSTEM".as_slice()),
        (content_x + 20, 306, GREEN, b"READY".as_slice()),
        (
            content_x + 20,
            346,
            MUTED,
            b"preemptive scheduler".as_slice(),
        ),
        (
            content_x + card_width + card_gap + 20,
            274,
            MUTED,
            b"STORAGE".as_slice(),
        ),
        (
            content_x + card_width + card_gap + 20,
            306,
            BLUE,
            b"FAT / VFS".as_slice(),
        ),
        (
            content_x + card_width + card_gap + 20,
            346,
            MUTED,
            b"ATA  AHCI  NVMe".as_slice(),
        ),
        (
            content_x + (card_width + card_gap) * 2 + 20,
            274,
            MUTED,
            b"NETWORK".as_slice(),
        ),
        (
            content_x + (card_width + card_gap) * 2 + 20,
            306,
            AMBER,
            b"DHCP / UDP".as_slice(),
        ),
        (
            content_x + (card_width + card_gap) * 2 + 20,
            346,
            MUTED,
            b"e1000 + ARP".as_slice(),
        ),
        (
            content_x + 24,
            438,
            TEXT,
            b"Native terminal and compositor".as_slice(),
        ),
        (
            content_x + 24,
            476,
            ACCENT,
            b"> graphics ABI: acquired".as_slice(),
        ),
        (
            content_x + 24,
            510,
            MUTED,
            b"> framebuffer: persistent".as_slice(),
        ),
        (
            content_x + 24,
            544,
            MUTED,
            b"> session: userland-owned".as_slice(),
        ),
        (
            24,
            height.saturating_sub(42),
            MUTED,
            b"RustOS / x86_64".as_slice(),
        ),
    ];
    for (x, y, color, text) in texts {
        if is_syscall_error(graphics_text(x, y, color, text)) {
            return false;
        }
    }
    true
}

fn write_decimal(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut length = 0;
    if value == 0 {
        write_stdout(b"0");
        return;
    }
    while value != 0 {
        digits[length] = b'0' + (value % 10) as u8;
        length += 1;
        value /= 10;
    }
    while length != 0 {
        length -= 1;
        write_stdout(&digits[length..length + 1]);
    }
}
