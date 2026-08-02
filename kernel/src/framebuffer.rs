use bootloader_api::info::{FrameBuffer, FrameBufferInfo, PixelFormat};
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use noto_sans_mono_bitmap::{FontWeight, RasterHeight, RasterizedChar, get_raster};
use spin::Mutex;

use crate::window_policy::WindowOrder;

const LINE_SPACING: usize = 2;
const BORDER_PADDING: usize = 8;
const FONT_WEIGHT: FontWeight = FontWeight::Regular;
const FONT_HEIGHT: RasterHeight = RasterHeight::Size16;
pub const MAX_GRAPHICS_TEXT_LENGTH: usize = 256;
pub const MAX_WINDOW_TEXT_LENGTH: usize = 96;
const MAX_WINDOW_COUNT: usize = 4;
const MAX_WINDOW_RECTS: usize = 24;
const MAX_WINDOW_TEXTS: usize = 8;
const MAX_WINDOW_EVENTS: usize = 8;
const MAX_WINDOW_DIMENSION: u32 = 4096;
const MAX_WINDOW_AREA: u64 = 4 * 1024 * 1024;
const GRAPHICS_OWNER_NONE: u32 = 0;

static FRAMEBUFFER: Mutex<Option<FrameBufferWriter>> = Mutex::new(None);
static GRAPHICS_OWNER: AtomicU32 = AtomicU32::new(GRAPHICS_OWNER_NONE);
static GRAPHICS_RECT_COUNT: AtomicU64 = AtomicU64::new(0);
static GRAPHICS_TEXT_COUNT: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GraphicsInfo {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bytes_per_pixel: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GraphicsRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub color: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GraphicsWindow {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy)]
struct WindowText {
    x: u32,
    y: u32,
    color: u32,
    length: usize,
    bytes: [u8; MAX_WINDOW_TEXT_LENGTH],
}

impl WindowText {
    const fn empty() -> Self {
        Self {
            x: 0,
            y: 0,
            color: 0,
            length: 0,
            bytes: [0; MAX_WINDOW_TEXT_LENGTH],
        }
    }
}

#[derive(Clone, Copy)]
struct WindowSurface {
    owner: u32,
    geometry: GraphicsWindow,
    rects: [GraphicsRect; MAX_WINDOW_RECTS],
    rect_count: usize,
    texts: [WindowText; MAX_WINDOW_TEXTS],
    text_count: usize,
    presented: bool,
    focused: bool,
    events: [Option<crate::input::InputEvent>; MAX_WINDOW_EVENTS],
    event_head: usize,
    event_tail: usize,
    event_count: usize,
}

impl WindowSurface {
    const fn empty() -> Self {
        Self {
            owner: GRAPHICS_OWNER_NONE,
            geometry: GraphicsWindow {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            rects: [GraphicsRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
                color: 0,
            }; MAX_WINDOW_RECTS],
            rect_count: 0,
            texts: [WindowText::empty(); MAX_WINDOW_TEXTS],
            text_count: 0,
            presented: false,
            focused: false,
            events: [None; MAX_WINDOW_EVENTS],
            event_head: 0,
            event_tail: 0,
            event_count: 0,
        }
    }

    const fn active_for(self, owner: u32) -> bool {
        self.owner != GRAPHICS_OWNER_NONE && self.owner == owner
    }

    fn push_event(&mut self, event: crate::input::InputEvent) {
        if event.kind == crate::input::INPUT_EVENT_MOUSE && self.event_count != 0 {
            let previous = (self.event_tail + MAX_WINDOW_EVENTS - 1) % MAX_WINDOW_EVENTS;
            if self.events[previous]
                .is_some_and(|queued| queued.kind == crate::input::INPUT_EVENT_MOUSE)
            {
                self.events[previous] = Some(event);
                return;
            }
        }
        if event.kind == crate::input::INPUT_EVENT_WINDOW
            && event.code == crate::input::WINDOW_EVENT_CONFIGURE
            && self.event_count != 0
        {
            let previous = (self.event_tail + MAX_WINDOW_EVENTS - 1) % MAX_WINDOW_EVENTS;
            if self.events[previous].is_some_and(|queued| {
                queued.kind == crate::input::INPUT_EVENT_WINDOW
                    && queued.code == crate::input::WINDOW_EVENT_CONFIGURE
            }) {
                self.events[previous] = Some(event);
                return;
            }
        }
        if self.event_count == MAX_WINDOW_EVENTS {
            self.events[self.event_head] = None;
            self.event_head = (self.event_head + 1) % MAX_WINDOW_EVENTS;
            self.event_count -= 1;
        }
        self.events[self.event_tail] = Some(event);
        self.event_tail = (self.event_tail + 1) % MAX_WINDOW_EVENTS;
        self.event_count += 1;
    }

    fn pop_event(&mut self) -> Option<crate::input::InputEvent> {
        let event = self.events[self.event_head].take()?;
        self.event_head = (self.event_head + 1) % MAX_WINDOW_EVENTS;
        self.event_count -= 1;
        Some(event)
    }
}

struct WindowManager {
    windows: [WindowSurface; MAX_WINDOW_COUNT],
    order: WindowOrder<MAX_WINDOW_COUNT>,
}

impl WindowManager {
    const fn new() -> Self {
        Self {
            windows: [WindowSurface::empty(); MAX_WINDOW_COUNT],
            order: WindowOrder::new(),
        }
    }

    fn index(window_id: u32) -> Option<usize> {
        let index = usize::try_from(window_id.checked_sub(1)?).ok()?;
        (index < MAX_WINDOW_COUNT).then_some(index)
    }

    fn raise(&mut self, index: usize) {
        self.order.raise(index);
    }

    fn remove(&mut self, index: usize) {
        self.order.remove(index);
    }
}

static WINDOWS: Mutex<WindowManager> = Mutex::new(WindowManager::new());

pub fn init(framebuffer: FrameBuffer) {
    let info = framebuffer.info();
    let buffer = framebuffer.into_buffer();
    *FRAMEBUFFER.lock() = Some(FrameBufferWriter::new(buffer, info));
}

pub fn write_bytes(bytes: &[u8]) {
    // A userland compositor owns the visible surface for its session. Kernel diagnostics still
    // go to the serial console, but mirroring them into the desktop would destroy its scene.
    if GRAPHICS_OWNER.load(Ordering::Acquire) != GRAPHICS_OWNER_NONE {
        return;
    }
    let mut framebuffer = FRAMEBUFFER.lock();
    let Some(framebuffer) = framebuffer.as_mut() else {
        return;
    };
    for &byte in bytes {
        framebuffer.write_byte(byte);
    }
}

pub fn info() -> Option<GraphicsInfo> {
    let framebuffer = FRAMEBUFFER.lock();
    framebuffer.as_ref().map(FrameBufferWriter::info)
}

pub fn sync_gpu() -> bool {
    let framebuffer = FRAMEBUFFER.lock();
    let Some(framebuffer) = framebuffer.as_ref() else {
        return false;
    };
    crate::virtio_gpu::present_frame(framebuffer.framebuffer, &framebuffer.info)
}

pub fn acquire(owner: u32) -> bool {
    if owner == GRAPHICS_OWNER_NONE || info().is_none() {
        return false;
    }
    GRAPHICS_OWNER
        .compare_exchange(
            GRAPHICS_OWNER_NONE,
            owner,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok_and(|previous| previous == GRAPHICS_OWNER_NONE)
        || GRAPHICS_OWNER.load(Ordering::Acquire) == owner
}

pub fn release(owner: u32) {
    let _ = GRAPHICS_OWNER.compare_exchange(
        owner,
        GRAPHICS_OWNER_NONE,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

pub fn fill_rect(owner: u32, rect: GraphicsRect) -> bool {
    if GRAPHICS_OWNER.load(Ordering::Acquire) != owner {
        return false;
    }
    let mut framebuffer = FRAMEBUFFER.lock();
    let Some(framebuffer) = framebuffer.as_mut() else {
        return false;
    };
    framebuffer.fill_color_rect(rect);
    GRAPHICS_RECT_COUNT.fetch_add(1, Ordering::AcqRel);
    true
}

pub fn draw_text(owner: u32, x: u32, y: u32, color: u32, bytes: &[u8]) -> bool {
    if bytes.len() > MAX_GRAPHICS_TEXT_LENGTH || GRAPHICS_OWNER.load(Ordering::Acquire) != owner {
        return false;
    }
    let mut framebuffer = FRAMEBUFFER.lock();
    let Some(framebuffer) = framebuffer.as_mut() else {
        return false;
    };
    framebuffer.write_color_text(x as usize, y as usize, color, bytes);
    GRAPHICS_TEXT_COUNT.fetch_add(1, Ordering::AcqRel);
    true
}

pub fn create_window(owner: u32, geometry: GraphicsWindow) -> Option<u32> {
    if owner == GRAPHICS_OWNER_NONE
        || GRAPHICS_OWNER.load(Ordering::Acquire) == GRAPHICS_OWNER_NONE
        || !valid_window_geometry(geometry)
    {
        return None;
    }

    let mut windows = WINDOWS.lock();
    let index = windows
        .windows
        .iter()
        .enumerate()
        .find(|(_, window)| window.owner == GRAPHICS_OWNER_NONE)
        .map(|(index, _)| index)?;
    windows.windows[index] = WindowSurface {
        owner,
        geometry,
        ..WindowSurface::empty()
    };
    windows.raise(index);
    Some((index + 1) as u32)
}

fn valid_window_geometry(geometry: GraphicsWindow) -> bool {
    if geometry.width == 0
        || geometry.height == 0
        || geometry.width > MAX_WINDOW_DIMENSION
        || geometry.height > MAX_WINDOW_DIMENSION
        || u64::from(geometry.width) * u64::from(geometry.height) > MAX_WINDOW_AREA
    {
        return false;
    }
    let Some(info) = info() else {
        return false;
    };
    geometry.x < info.width
        && geometry.y < info.height
        && geometry.width <= info.width.saturating_sub(geometry.x)
        && geometry.height <= info.height.saturating_sub(geometry.y)
}

pub fn clear_window(owner: u32, window_id: u32) -> bool {
    let Some(index) = WindowManager::index(window_id) else {
        return false;
    };
    let mut windows = WINDOWS.lock();
    let Some(window) = windows.windows.get_mut(index) else {
        return false;
    };
    if !window.active_for(owner) {
        return false;
    }
    window.rect_count = 0;
    window.text_count = 0;
    window.presented = false;
    true
}

pub fn window_fill_rect(owner: u32, window_id: u32, rect: GraphicsRect) -> bool {
    if rect.width == 0
        || rect.height == 0
        || rect.width > MAX_WINDOW_DIMENSION
        || rect.height > MAX_WINDOW_DIMENSION
        || u64::from(rect.width) * u64::from(rect.height) > MAX_WINDOW_AREA
    {
        return false;
    }
    let Some(index) = WindowManager::index(window_id) else {
        return false;
    };
    let mut windows = WINDOWS.lock();
    let Some(window) = windows.windows.get_mut(index) else {
        return false;
    };
    if !window.active_for(owner)
        || rect.x >= window.geometry.width
        || rect.y >= window.geometry.height
        || rect.width > window.geometry.width.saturating_sub(rect.x)
        || rect.height > window.geometry.height.saturating_sub(rect.y)
        || window.rect_count >= MAX_WINDOW_RECTS
    {
        return false;
    }
    window.rects[window.rect_count] = rect;
    window.rect_count += 1;
    window.presented = false;
    true
}

pub fn window_draw_text(
    owner: u32,
    window_id: u32,
    x: u32,
    y: u32,
    color: u32,
    bytes: &[u8],
) -> bool {
    if bytes.len() > MAX_WINDOW_TEXT_LENGTH {
        return false;
    }
    let Some(index) = WindowManager::index(window_id) else {
        return false;
    };
    let mut windows = WINDOWS.lock();
    let Some(window) = windows.windows.get_mut(index) else {
        return false;
    };
    if !window.active_for(owner)
        || x >= window.geometry.width
        || y >= window.geometry.height
        || window.text_count >= MAX_WINDOW_TEXTS
    {
        return false;
    }
    let mut text = WindowText::empty();
    text.x = x;
    text.y = y;
    text.color = color;
    text.length = bytes.len();
    text.bytes[..bytes.len()].copy_from_slice(bytes);
    window.texts[window.text_count] = text;
    window.text_count += 1;
    window.presented = false;
    true
}

pub fn present_window(owner: u32, window_id: u32) -> bool {
    let Some(index) = WindowManager::index(window_id) else {
        return false;
    };
    let mut windows = WINDOWS.lock();
    let Some(window) = windows.windows.get(index) else {
        return false;
    };
    if !window.active_for(owner) {
        return false;
    }
    windows.windows[index].presented = true;
    drop(windows);
    compose_presented_windows()
}

pub fn focus_window(owner: u32, window_id: u32) -> bool {
    let Some(index) = WindowManager::index(window_id) else {
        return false;
    };
    let mut windows = WINDOWS.lock();
    let Some(window) = windows.windows.get(index) else {
        return false;
    };
    if !window.active_for(owner) {
        return false;
    }
    for window in &mut windows.windows {
        window.focused = false;
    }
    windows.raise(index);
    windows.windows[index].focused = true;
    true
}

pub fn window_geometry(owner: u32, window_id: u32) -> Option<GraphicsWindow> {
    let index = WindowManager::index(window_id)?;
    let windows = WINDOWS.lock();
    let window = windows.windows.get(index)?;
    if !window.active_for(owner) && GRAPHICS_OWNER.load(Ordering::Acquire) != owner {
        return None;
    }
    Some(window.geometry)
}

pub fn configure_window(owner: u32, window_id: u32, geometry: GraphicsWindow) -> bool {
    if GRAPHICS_OWNER.load(Ordering::Acquire) != owner || !valid_window_geometry(geometry) {
        return false;
    }
    let Some(index) = WindowManager::index(window_id) else {
        return false;
    };
    let mut windows = WINDOWS.lock();
    let Some(window) = windows.windows.get_mut(index) else {
        return false;
    };
    if window.owner == GRAPHICS_OWNER_NONE {
        return false;
    }
    window.geometry = geometry;
    window.push_event(crate::input::InputEvent {
        kind: crate::input::INPUT_EVENT_WINDOW,
        buttons: 0,
        dx: 0,
        dy: 0,
        wheel: 0,
        code: crate::input::WINDOW_EVENT_CONFIGURE,
    });
    true
}

pub fn request_window_close(owner: u32, window_id: u32) -> bool {
    if GRAPHICS_OWNER.load(Ordering::Acquire) != owner {
        return false;
    }
    let Some(index) = WindowManager::index(window_id) else {
        return false;
    };
    let mut windows = WINDOWS.lock();
    let Some(window) = windows.windows.get_mut(index) else {
        return false;
    };
    if window.owner == GRAPHICS_OWNER_NONE {
        return false;
    }
    window.focused = true;
    window.push_event(crate::input::InputEvent {
        kind: crate::input::INPUT_EVENT_WINDOW,
        buttons: 0,
        dx: 0,
        dy: 0,
        wheel: 0,
        code: crate::input::WINDOW_EVENT_CLOSE,
    });
    true
}

pub fn compose_windows(owner: u32) -> bool {
    if GRAPHICS_OWNER.load(Ordering::Acquire) != owner {
        return false;
    }
    compose_presented_windows()
}

fn compose_presented_windows() -> bool {
    let windows = WINDOWS.lock();
    let mut framebuffer_guard = FRAMEBUFFER.lock();
    let Some(framebuffer) = framebuffer_guard.as_mut() else {
        return false;
    };
    for position in 0..windows.order.len() {
        let Some(index) = windows.order.get(position) else {
            continue;
        };
        let window = windows.windows[index];
        if window.owner != GRAPHICS_OWNER_NONE && window.presented {
            draw_window(framebuffer, &window);
        }
    }
    drop(framebuffer_guard);
    drop(windows);
    sync_gpu()
}

pub fn dispatch_pointer(
    owner: u32,
    x: u32,
    y: u32,
    event: crate::input::InputEvent,
) -> Result<u32, ()> {
    if GRAPHICS_OWNER.load(Ordering::Acquire) != owner {
        return Err(());
    }
    let mut windows = WINDOWS.lock();
    let mut hit = None;
    for position in (0..windows.order.len()).rev() {
        let Some(index) = windows.order.get(position) else {
            continue;
        };
        let window = windows.windows[index];
        if window.owner != GRAPHICS_OWNER_NONE
            && window.presented
            && x >= window.geometry.x
            && y >= window.geometry.y
            && x < window.geometry.x.saturating_add(window.geometry.width)
            && y < window.geometry.y.saturating_add(window.geometry.height)
        {
            hit = Some(index);
            break;
        }
    }
    for window in &mut windows.windows {
        window.focused = false;
    }
    if let Some(index) = hit {
        if event.buttons != 0 {
            windows.raise(index);
        }
        let window = &mut windows.windows[index];
        window.focused = true;
        window.push_event(event);
    }
    #[cfg(target_os = "none")]
    if event.buttons != 0 {
        crate::kprintln!(
            "window: pointer button hit={} x={} y={} buttons={} status=ready",
            hit.map_or(0, |index| index + 1),
            x,
            y,
            event.buttons
        );
    }
    Ok(hit.map_or(0, |index| (index + 1) as u32))
}

pub fn dispatch_keyboard(owner: u32, event: crate::input::InputEvent) -> bool {
    if GRAPHICS_OWNER.load(Ordering::Acquire) != owner {
        return false;
    }
    let mut windows = WINDOWS.lock();
    for position in (0..windows.order.len()).rev() {
        let Some(index) = windows.order.get(position) else {
            continue;
        };
        let window = &mut windows.windows[index];
        if window.owner != GRAPHICS_OWNER_NONE && window.presented && window.focused {
            window.push_event(event);
            break;
        }
    }
    true
}

pub fn read_window_event(owner: u32, window_id: u32) -> Option<crate::input::InputEvent> {
    let index = WindowManager::index(window_id)?;
    let mut windows = WINDOWS.lock();
    let window = windows.windows.get_mut(index)?;
    if !window.active_for(owner) {
        return None;
    }
    window.pop_event()
}

pub fn destroy_window(owner: u32, window_id: u32) -> bool {
    let Some(index) = WindowManager::index(window_id) else {
        return false;
    };
    let mut windows = WINDOWS.lock();
    let Some(window) = windows.windows.get_mut(index) else {
        return false;
    };
    if !window.active_for(owner) {
        return false;
    }
    let was_focused = window.focused;
    *window = WindowSurface::empty();
    windows.remove(index);
    if was_focused {
        for position in (0..windows.order.len()).rev() {
            let Some(next) = windows.order.get(position) else {
                continue;
            };
            if windows.windows[next].owner == owner && windows.windows[next].presented {
                windows.windows[next].focused = true;
                break;
            }
        }
    }
    true
}

pub fn destroy_windows_for_owner(owner: u32) {
    if owner == GRAPHICS_OWNER_NONE {
        return;
    }
    // Teardown may run while a preempted graphics client owns the lock. A dead process must not
    // spin forever here; normal clients destroy their own surfaces before exit, and this cleanup
    // remains best-effort for faulted or non-window processes.
    let Some(mut windows) = WINDOWS.try_lock() else {
        return;
    };
    for window in &mut windows.windows {
        if window.owner == owner {
            *window = WindowSurface::empty();
        }
    }
    for index in (0..MAX_WINDOW_COUNT).rev() {
        if windows.windows[index].owner == GRAPHICS_OWNER_NONE {
            windows.remove(index);
        }
    }
}

fn draw_window(framebuffer: &mut FrameBufferWriter, window: &WindowSurface) {
    let right = window.geometry.x.saturating_add(window.geometry.width);
    let bottom = window.geometry.y.saturating_add(window.geometry.height);
    for rect in window.rects[..window.rect_count].iter().copied() {
        framebuffer.fill_color_rect(GraphicsRect {
            x: window.geometry.x.saturating_add(rect.x),
            y: window.geometry.y.saturating_add(rect.y),
            width: rect.width,
            height: rect.height,
            color: rect.color,
        });
    }
    for text in window.texts[..window.text_count].iter().copied() {
        framebuffer.write_color_text_clipped(
            window.geometry.x.saturating_add(text.x) as usize,
            window.geometry.y.saturating_add(text.y) as usize,
            text.color,
            &text.bytes[..text.length],
            window.geometry.x as usize,
            window.geometry.y as usize,
            right as usize,
            bottom as usize,
        );
    }
}

struct FrameBufferWriter {
    framebuffer: &'static mut [u8],
    info: FrameBufferInfo,
    x: usize,
    y: usize,
}

impl FrameBufferWriter {
    fn new(framebuffer: &'static mut [u8], info: FrameBufferInfo) -> Self {
        let mut writer = Self {
            framebuffer,
            info,
            x: BORDER_PADDING,
            y: BORDER_PADDING,
        };
        writer.clear();
        writer
    }

    fn clear(&mut self) {
        self.framebuffer.fill(0);
        self.x = BORDER_PADDING;
        self.y = BORDER_PADDING;
    }

    fn info(&self) -> GraphicsInfo {
        GraphicsInfo {
            width: self.info.width.min(u32::MAX as usize) as u32,
            height: self.info.height.min(u32::MAX as usize) as u32,
            stride: self.info.stride.min(u32::MAX as usize) as u32,
            bytes_per_pixel: self.info.bytes_per_pixel.min(u32::MAX as usize) as u32,
        }
    }

    fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.newline(),
            b'\r' => self.x = BORDER_PADDING,
            8 => self.backspace(),
            b'\t' => {
                for _ in 0..4 {
                    self.write_char(b' ');
                }
            }
            0x20..=0x7e => self.write_char(byte),
            _ => {}
        }
    }

    fn write_char(&mut self, byte: u8) {
        let character = char::from(byte);
        let raster = get_raster(character, FONT_WEIGHT, FONT_HEIGHT)
            .or_else(|| get_raster('?', FONT_WEIGHT, FONT_HEIGHT));
        let Some(raster) = raster else {
            return;
        };
        if self.x + raster.width() >= self.info.width {
            self.newline();
        }
        if self.y + raster.height() + BORDER_PADDING >= self.info.height {
            self.clear();
        }
        self.write_raster(&raster);
        self.x += raster.width();
    }

    fn fill_color_rect(&mut self, rect: GraphicsRect) {
        let right = usize::try_from(rect.x)
            .ok()
            .and_then(|x| x.checked_add(rect.width as usize))
            .unwrap_or(self.info.width)
            .min(self.info.width);
        let bottom = usize::try_from(rect.y)
            .ok()
            .and_then(|y| y.checked_add(rect.height as usize))
            .unwrap_or(self.info.height)
            .min(self.info.height);
        let left = (rect.x as usize).min(self.info.width);
        let top = (rect.y as usize).min(self.info.height);
        for y in top..bottom {
            for x in left..right {
                self.write_color_pixel(x, y, rect.color);
            }
        }
    }

    fn write_color_text(&mut self, origin_x: usize, origin_y: usize, color: u32, bytes: &[u8]) {
        let right = self.info.width;
        let bottom = self.info.height;
        self.write_color_text_clipped(origin_x, origin_y, color, bytes, 0, 0, right, bottom);
    }

    fn write_color_text_clipped(
        &mut self,
        origin_x: usize,
        origin_y: usize,
        color: u32,
        bytes: &[u8],
        clip_left: usize,
        clip_top: usize,
        clip_right: usize,
        clip_bottom: usize,
    ) {
        let mut x = origin_x;
        let mut y = origin_y;
        let width = get_raster_width();
        for &byte in bytes {
            match byte {
                b'\n' => {
                    x = origin_x;
                    y = y.saturating_add(FONT_HEIGHT.val().saturating_add(LINE_SPACING));
                }
                b'\r' => x = origin_x,
                b'\t' => x = x.saturating_add(width.saturating_mul(4)),
                0x20..=0x7e => {
                    let raster = get_raster(char::from(byte), FONT_WEIGHT, FONT_HEIGHT)
                        .or_else(|| get_raster('?', FONT_WEIGHT, FONT_HEIGHT));
                    let Some(raster) = raster else {
                        continue;
                    };
                    if x + raster.width() >= clip_right {
                        x = origin_x;
                        y = y.saturating_add(FONT_HEIGHT.val().saturating_add(LINE_SPACING));
                    }
                    if y + raster.height() >= clip_bottom {
                        break;
                    }
                    for (row, pixels) in raster.raster().iter().enumerate() {
                        for (column, intensity) in pixels.iter().copied().enumerate() {
                            if intensity != 0 {
                                let pixel_x = x + column;
                                let pixel_y = y + row;
                                if pixel_x >= clip_left
                                    && pixel_x < clip_right
                                    && pixel_y >= clip_top
                                    && pixel_y < clip_bottom
                                {
                                    self.write_color_pixel(
                                        pixel_x,
                                        pixel_y,
                                        scale_color(color, intensity),
                                    );
                                }
                            }
                        }
                    }
                    x = x.saturating_add(raster.width());
                }
                _ => {}
            }
        }
    }

    fn write_raster(&mut self, raster: &RasterizedChar) {
        for (row, pixels) in raster.raster().iter().enumerate() {
            for (column, intensity) in pixels.iter().copied().enumerate() {
                self.write_pixel(self.x + column, self.y + row, intensity);
            }
        }
    }

    fn newline(&mut self) {
        self.x = BORDER_PADDING;
        self.y = self
            .y
            .saturating_add(FONT_HEIGHT.val().saturating_add(LINE_SPACING));
        if self.y + FONT_HEIGHT.val() + BORDER_PADDING >= self.info.height {
            self.clear();
        }
    }

    fn backspace(&mut self) {
        let width = get_raster_width();
        if self.x > BORDER_PADDING + width {
            self.x -= width;
            for row in 0..FONT_HEIGHT.val() {
                for column in 0..width {
                    self.write_pixel(self.x + column, self.y + row, 0);
                }
            }
        }
    }

    fn write_pixel(&mut self, x: usize, y: usize, intensity: u8) {
        if x >= self.info.width || y >= self.info.height || self.info.bytes_per_pixel == 0 {
            return;
        }
        let Some(row_pixels) = y.checked_mul(self.info.stride) else {
            return;
        };
        let Some(row_start) = row_pixels.checked_mul(self.info.bytes_per_pixel) else {
            return;
        };
        let Some(pixel_start) = x.checked_mul(self.info.bytes_per_pixel) else {
            return;
        };
        let Some(offset) = row_start.checked_add(pixel_start) else {
            return;
        };
        let Some(end) = offset.checked_add(self.info.bytes_per_pixel) else {
            return;
        };
        if end > self.framebuffer.len() {
            return;
        }

        let pixel = &mut self.framebuffer[offset..end];
        pixel.fill(0);
        match self.info.pixel_format {
            PixelFormat::Rgb => {
                if pixel.len() >= 3 {
                    pixel[0] = intensity;
                    pixel[1] = intensity;
                    pixel[2] = intensity / 2;
                }
            }
            PixelFormat::Bgr => {
                if pixel.len() >= 3 {
                    pixel[0] = intensity / 2;
                    pixel[1] = intensity;
                    pixel[2] = intensity;
                }
            }
            PixelFormat::U8 => {
                pixel[0] = if intensity > 128 { 0xf } else { 0 };
            }
            PixelFormat::Unknown {
                red_position,
                green_position,
                blue_position,
            } => {
                let encoded = channel(intensity, red_position)
                    | channel(intensity, green_position)
                    | channel(intensity, blue_position);
                let bytes = encoded.to_le_bytes();
                for (destination, source) in pixel.iter_mut().zip(bytes) {
                    *destination = source;
                }
            }
            _ => {}
        }
    }

    fn write_color_pixel(&mut self, x: usize, y: usize, color: u32) {
        if x >= self.info.width || y >= self.info.height || self.info.bytes_per_pixel == 0 {
            return;
        }
        let Some(row_pixels) = y.checked_mul(self.info.stride) else {
            return;
        };
        let Some(row_start) = row_pixels.checked_mul(self.info.bytes_per_pixel) else {
            return;
        };
        let Some(pixel_start) = x.checked_mul(self.info.bytes_per_pixel) else {
            return;
        };
        let Some(offset) = row_start.checked_add(pixel_start) else {
            return;
        };
        let Some(end) = offset.checked_add(self.info.bytes_per_pixel) else {
            return;
        };
        if end > self.framebuffer.len() {
            return;
        }

        let red = ((color >> 16) & 0xff) as u8;
        let green = ((color >> 8) & 0xff) as u8;
        let blue = (color & 0xff) as u8;
        let pixel = &mut self.framebuffer[offset..end];
        pixel.fill(0);
        match self.info.pixel_format {
            PixelFormat::Rgb => {
                if pixel.len() >= 3 {
                    pixel[0] = red;
                    pixel[1] = green;
                    pixel[2] = blue;
                }
            }
            PixelFormat::Bgr => {
                if pixel.len() >= 3 {
                    pixel[0] = blue;
                    pixel[1] = green;
                    pixel[2] = red;
                }
            }
            PixelFormat::U8 => {
                pixel[0] = ((u16::from(red) * 77 + u16::from(green) * 150 + u16::from(blue) * 29)
                    / 256) as u8;
            }
            PixelFormat::Unknown {
                red_position,
                green_position,
                blue_position,
            } => {
                let encoded = channel(red, red_position)
                    | channel(green, green_position)
                    | channel(blue, blue_position);
                let bytes = encoded.to_le_bytes();
                for (destination, source) in pixel.iter_mut().zip(bytes) {
                    *destination = source;
                }
            }
            _ => {}
        }
    }
}

unsafe impl Send for FrameBufferWriter {}
unsafe impl Sync for FrameBufferWriter {}

impl fmt::Write for FrameBufferWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for byte in value.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

fn get_raster_width() -> usize {
    get_raster(' ', FONT_WEIGHT, FONT_HEIGHT)
        .map(|raster| raster.width())
        .unwrap_or(8)
}

fn channel(value: u8, position: u8) -> u32 {
    if position < 32 {
        u32::from(value) << position
    } else {
        0
    }
}

fn scale_color(color: u32, intensity: u8) -> u32 {
    let scale = u32::from(intensity);
    let red = ((color >> 16) & 0xff) * scale / 255;
    let green = ((color >> 8) & 0xff) * scale / 255;
    let blue = (color & 0xff) * scale / 255;
    (red << 16) | (green << 8) | blue
}

#[cfg(test)]
mod tests {
    use super::WindowSurface;
    use crate::input::{
        INPUT_EVENT_MOUSE, INPUT_EVENT_WINDOW, WINDOW_EVENT_CLOSE, WINDOW_EVENT_CONFIGURE,
    };

    #[test]
    fn coalesces_consecutive_mouse_events() {
        let mut window = WindowSurface::empty();
        window.push_event(crate::input::InputEvent {
            kind: INPUT_EVENT_MOUSE,
            dx: 1,
            ..crate::input::InputEvent::default()
        });
        window.push_event(crate::input::InputEvent {
            kind: INPUT_EVENT_MOUSE,
            dx: 2,
            ..crate::input::InputEvent::default()
        });
        assert_eq!(window.event_count, 1);
        assert_eq!(window.pop_event().map(|event| event.dx), Some(2));
    }

    #[test]
    fn coalesces_configure_events_but_preserves_close() {
        let mut window = WindowSurface::empty();
        window.push_event(crate::input::InputEvent {
            kind: INPUT_EVENT_WINDOW,
            code: WINDOW_EVENT_CONFIGURE,
            dx: 320,
            ..crate::input::InputEvent::default()
        });
        window.push_event(crate::input::InputEvent {
            kind: INPUT_EVENT_WINDOW,
            code: WINDOW_EVENT_CONFIGURE,
            dx: 640,
            ..crate::input::InputEvent::default()
        });
        assert_eq!(window.event_count, 1);
        assert_eq!(window.pop_event().map(|event| event.dx), Some(640));
        window.push_event(crate::input::InputEvent {
            kind: INPUT_EVENT_WINDOW,
            code: WINDOW_EVENT_CLOSE,
            ..crate::input::InputEvent::default()
        });
        assert_eq!(
            window.pop_event().map(|event| event.code),
            Some(WINDOW_EVENT_CLOSE)
        );
    }
}
