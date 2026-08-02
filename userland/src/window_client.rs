use rustos_userland::{
    GRAPHICS_INFO_LENGTH, GraphicsInfo, GraphicsRect, GraphicsWindow, INPUT_EVENT_KEYBOARD,
    INPUT_EVENT_LENGTH, INPUT_EVENT_MOUSE, INPUT_EVENT_WINDOW, InputEvent, WINDOW_EVENT_CLOSE,
    WINDOW_EVENT_CONFIGURE, default_window_geometry, exit, graphics_info, graphics_window_clear,
    graphics_window_create, graphics_window_destroy, graphics_window_fill_rect,
    graphics_window_geometry, graphics_window_present, graphics_window_read_event,
    graphics_window_text, is_syscall_error, list_files, write_stdout, yield_now,
};

const FILE_SNAPSHOT_LENGTH: usize = 4096;
const FILE_ROW_COUNT: usize = 3;
const FILE_ROW_LENGTH: usize = 30;

#[derive(Clone, Copy)]
struct Palette {
    background: u32,
    title: u32,
    inner: u32,
    accent: u32,
    green: u32,
    text: u32,
    muted: u32,
}

const PRIMARY: Palette = Palette {
    background: 0x1b2a42,
    title: 0x2a4164,
    inner: 0x223653,
    accent: 0x30d6c6,
    green: 0x3ddc97,
    text: 0xf1f5f9,
    muted: 0xa9bdd2,
};

const SECONDARY: Palette = Palette {
    background: 0x3a2637,
    title: 0x704064,
    inner: 0x54364f,
    accent: 0xf2b84b,
    green: 0xffd166,
    text: 0xfff7ed,
    muted: 0xe0b9c9,
};

pub fn run(secondary: bool) -> ! {
    let mut info = GraphicsInfo::default();
    if graphics_info(&mut info) != GRAPHICS_INFO_LENGTH as u64 {
        write_stdout(b"window: framebuffer info unavailable\n");
        exit(1);
    }

    let geometry = default_window_geometry(info, secondary);
    let mut width = geometry.width;
    let mut height = geometry.height;
    let mut file_snapshot = [0u8; FILE_SNAPSHOT_LENGTH];
    let mut file_snapshot_length = if secondary {
        match refresh_file_snapshot(&mut file_snapshot) {
            Some(length) => length,
            None => {
                write_stdout(b"window: secondary storage snapshot failed\n");
                exit(3);
            }
        }
    } else {
        0
    };
    let window_id = graphics_window_create(&geometry);
    if is_syscall_error(window_id) {
        write_stdout(b"window: create failed\n");
        exit(2);
    }
    let palette = if secondary { SECONDARY } else { PRIMARY };
    if !draw_surface(
        window_id,
        width,
        height,
        palette,
        0,
        0,
        secondary,
        &file_snapshot[..file_snapshot_length],
    ) {
        write_stdout(b"window: initial draw failed\n");
        exit(3);
    }
    if secondary {
        write_stdout(b"window: secondary client surface=ready presented=ready status=ready\n");
        write_stdout(b"window: secondary storage snapshot=ready status=ready\n");
    } else {
        write_stdout(b"window: primary client surface=ready presented=ready status=ready\n");
    }

    let mut input_reported = false;
    let mut keyboard_reported = false;
    let mut keyboard_routed = false;
    let mut refresh_reported = false;
    let mut refresh_ticks = 0u32;
    loop {
        let mut event = InputEvent::default();
        let result = graphics_window_read_event(window_id, &mut event);
        if result == INPUT_EVENT_LENGTH as u64 {
            if event.kind != INPUT_EVENT_MOUSE
                && event.kind != INPUT_EVENT_KEYBOARD
                && event.kind != INPUT_EVENT_WINDOW
            {
                yield_now();
                continue;
            }
            if event.kind == INPUT_EVENT_WINDOW {
                if event.code == WINDOW_EVENT_CLOSE {
                    if secondary {
                        write_stdout(b"window: secondary close requested status=ready\n");
                    } else {
                        write_stdout(b"window: primary close requested status=ready\n");
                    }
                    let _ = graphics_window_destroy(window_id);
                    exit(0);
                }
                if event.code == WINDOW_EVENT_CONFIGURE {
                    let mut configured = GraphicsWindow::default();
                    if graphics_window_geometry(window_id, &mut configured)
                        != rustos_userland::GRAPHICS_WINDOW_LENGTH as u64
                    {
                        write_stdout(b"window: geometry query failed\n");
                        exit(6);
                    }
                    width = configured.width;
                    height = configured.height;
                    if secondary {
                        write_stdout(b"window: secondary configure event received status=ready\n");
                    } else {
                        write_stdout(b"window: primary configure event received status=ready\n");
                    }
                    if !draw_surface(
                        window_id,
                        width,
                        height,
                        palette,
                        0,
                        0,
                        secondary,
                        &file_snapshot[..file_snapshot_length],
                    ) {
                        write_stdout(b"window: configure redraw failed\n");
                        exit(7);
                    }
                }
                yield_now();
                continue;
            }
            if event.kind == INPUT_EVENT_KEYBOARD {
                keyboard_routed = true;
                if secondary && (event.code == b'r' as u32 || event.code == b'R' as u32) {
                    if let Some(length) = refresh_file_snapshot(&mut file_snapshot) {
                        file_snapshot_length = length;
                        refresh_reported = true;
                        write_stdout(
                            b"window: secondary storage snapshot refreshed status=ready\n",
                        );
                    } else {
                        write_stdout(b"window: secondary storage refresh failed\n");
                    }
                }
            }
            let displayed_event_kind = if keyboard_routed {
                INPUT_EVENT_KEYBOARD
            } else {
                event.kind
            };
            if !draw_surface(
                window_id,
                width,
                height,
                palette,
                displayed_event_kind,
                event.buttons,
                secondary,
                &file_snapshot[..file_snapshot_length],
            ) {
                write_stdout(b"window: input redraw failed\n");
                exit(4);
            }
            if event.kind == INPUT_EVENT_MOUSE && !input_reported {
                if secondary {
                    write_stdout(b"window: secondary pointer focus event received status=ready\n");
                } else {
                    write_stdout(b"window: primary pointer focus event received status=ready\n");
                }
                input_reported = true;
            }
            if event.kind == INPUT_EVENT_MOUSE && event.buttons != 0 {
                if secondary {
                    write_stdout(b"window: secondary pointer raise event received status=ready\n");
                } else {
                    write_stdout(b"window: primary pointer raise event received status=ready\n");
                }
            }
            if event.kind == INPUT_EVENT_KEYBOARD && !keyboard_reported {
                if secondary {
                    write_stdout(b"window: secondary keyboard focus event received status=ready\n");
                } else {
                    write_stdout(b"window: primary keyboard focus event received status=ready\n");
                }
                keyboard_reported = true;
            }
        } else if is_syscall_error(result) {
            write_stdout(b"window: input read failed\n");
            exit(5);
        }
        if secondary && !refresh_reported {
            refresh_ticks = refresh_ticks.saturating_add(1);
            if refresh_ticks >= 256 {
                let Some(length) = refresh_file_snapshot(&mut file_snapshot) else {
                    write_stdout(b"window: secondary storage refresh failed\n");
                    exit(8);
                };
                file_snapshot_length = length;
                write_stdout(b"window: secondary storage snapshot refreshed status=ready\n");
                refresh_reported = true;
            }
        }
        yield_now();
    }
}

fn draw_surface(
    window_id: u64,
    width: u32,
    height: u32,
    palette: Palette,
    event_kind: u32,
    buttons: u32,
    secondary: bool,
    file_snapshot: &[u8],
) -> bool {
    if is_syscall_error(graphics_window_clear(window_id)) {
        return false;
    }
    let title_color = if buttons & 1 != 0 {
        palette.accent
    } else {
        palette.title
    };
    let rectangles = [
        GraphicsRect {
            x: 0,
            y: 0,
            width,
            height,
            color: palette.background,
        },
        GraphicsRect {
            x: 0,
            y: 0,
            width,
            height: height.min(42),
            color: title_color,
        },
        GraphicsRect {
            x: 0,
            y: 40,
            width,
            height: 2,
            color: palette.accent,
        },
        GraphicsRect {
            x: 20,
            y: 68,
            width: width.saturating_sub(40),
            height: height.saturating_sub(108).max(1),
            color: palette.inner,
        },
        GraphicsRect {
            x: 20,
            y: height.saturating_sub(34),
            width: 140,
            height: 22,
            color: title_color,
        },
    ];
    for rectangle in rectangles {
        if is_syscall_error(graphics_window_fill_rect(window_id, &rectangle)) {
            return false;
        }
    }

    let status = match event_kind {
        INPUT_EVENT_MOUSE => b"INPUT ROUTED".as_slice(),
        INPUT_EVENT_KEYBOARD => b"KEY ROUTED".as_slice(),
        _ => b"CLIENT READY".as_slice(),
    };
    let status_color = match event_kind {
        INPUT_EVENT_MOUSE | INPUT_EVENT_KEYBOARD => palette.accent,
        _ => palette.green,
    };
    let title = if secondary {
        b"WINDOW CLIENT B".as_slice()
    } else {
        b"WINDOW CLIENT A".as_slice()
    };
    let texts = [
        (20, 12, palette.text, title),
        (
            28,
            82,
            palette.text,
            if secondary {
                b"PERSISTENT FILES".as_slice()
            } else {
                b"first process-isolated surface".as_slice()
            },
        ),
        (
            28,
            if secondary { 104 } else { 114 },
            palette.muted,
            if secondary {
                b"catalog snapshot".as_slice()
            } else {
                b"retained draw commands".as_slice()
            },
        ),
        (
            28,
            if secondary { 182 } else { 146 },
            palette.muted,
            if secondary {
                b"press R to refresh".as_slice()
            } else {
                b"raised by pointer focus".as_slice()
            },
        ),
        (28, height.saturating_sub(30), status_color, status),
    ];
    for (x, y, color, text) in texts {
        if is_syscall_error(graphics_window_text(window_id, x, y, color, text)) {
            return false;
        }
    }
    if secondary && !draw_file_rows(window_id, file_snapshot, palette.text) {
        return false;
    }
    !is_syscall_error(graphics_window_present(window_id))
}

fn refresh_file_snapshot(buffer: &mut [u8; FILE_SNAPSHOT_LENGTH]) -> Option<usize> {
    let length = usize::try_from(list_files(buffer)).ok()?;
    (length <= buffer.len()).then_some(length)
}

fn draw_file_rows(window_id: u64, snapshot: &[u8], color: u32) -> bool {
    let mut cursor = 0;
    let mut row = 0;
    while cursor < snapshot.len() && row < FILE_ROW_COUNT {
        let line_end = snapshot[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(snapshot.len(), |offset| cursor + offset);
        if line_end > cursor {
            let end = (cursor + FILE_ROW_LENGTH).min(line_end);
            if is_syscall_error(graphics_window_text(
                window_id,
                28,
                126u32.saturating_add(row as u32 * 20),
                color,
                &snapshot[cursor..end],
            )) {
                return false;
            }
            row += 1;
        }
        cursor = if line_end < snapshot.len() {
            line_end + 1
        } else {
            line_end
        };
    }
    true
}
