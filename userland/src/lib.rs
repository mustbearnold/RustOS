#![no_std]

use core::arch::asm;

pub mod accounts;
pub mod path;

pub const SYS_GETPID: u64 = 1;
pub const SYS_YIELD: u64 = 2;
pub const SYS_EXIT: u64 = 3;
pub const SYS_SPAWN: u64 = 4;
pub const SYS_WAITPID: u64 = 5;
pub const SYS_WAITPID_NONBLOCK: u64 = 50;
pub const SYS_WRITE: u64 = 6;
pub const SYS_OPEN: u64 = 7;
pub const SYS_READ: u64 = 8;
pub const SYS_CLOSE: u64 = 9;
pub const SYS_THREAD_CREATE: u64 = 10;
pub const SYS_THREAD_JOIN: u64 = 11;
pub const SYS_THREAD_EXIT: u64 = 12;
pub const SYS_EXEC: u64 = 13;
pub const SYS_FORK: u64 = 14;
pub const SYS_LIST_PROCESSES: u64 = 15;
pub const SYS_LIST_FILES: u64 = 16;
pub const SYS_MKDIR: u64 = 17;
pub const SYS_MMAP: u64 = 45;
pub const SYS_MUNMAP: u64 = 46;
pub const SYS_NET_SEND: u64 = 18;
pub const SYS_NET_RECEIVE: u64 = 19;
pub const SYS_NET_INFO: u64 = 20;
pub const SYS_NET_INTERFACES: u64 = 43;
pub const SYS_NET_RENEW: u64 = 44;
pub const SYS_GFX_INFO: u64 = 21;
pub const SYS_GFX_ACQUIRE: u64 = 22;
pub const SYS_GFX_FILL_RECT: u64 = 23;
pub const SYS_GFX_TEXT: u64 = 24;
pub const SYS_GFX_RELEASE: u64 = 25;
pub const SYS_INPUT_READ: u64 = 26;
pub const SYS_GFX_WINDOW_CREATE: u64 = 27;
pub const SYS_GFX_WINDOW_CLEAR: u64 = 28;
pub const SYS_GFX_WINDOW_FILL_RECT: u64 = 29;
pub const SYS_GFX_WINDOW_TEXT: u64 = 30;
pub const SYS_GFX_WINDOW_PRESENT: u64 = 31;
pub const SYS_GFX_WINDOW_DESTROY: u64 = 32;
pub const SYS_GFX_COMPOSE_WINDOWS: u64 = 33;
pub const SYS_GFX_WINDOW_DISPATCH_POINTER: u64 = 34;
pub const SYS_GFX_WINDOW_READ_EVENT: u64 = 35;
pub const SYS_GFX_WINDOW_DISPATCH_KEYBOARD: u64 = 36;
pub const SYS_GFX_WINDOW_GET_GEOMETRY: u64 = 37;
pub const SYS_GFX_WINDOW_CONFIGURE: u64 = 38;
pub const SYS_GFX_WINDOW_REQUEST_CLOSE: u64 = 39;
pub const SYS_POWEROFF: u64 = 40;
pub const SYS_REBOOT: u64 = 41;
pub const SYS_SUSPEND: u64 = 42;
pub const SYS_PIPE: u64 = 47;
pub const SYS_READ_NONBLOCK: u64 = 48;
pub const SYS_GFX_WINDOW_FOCUS: u64 = 49;
pub const SYS_PATH_INFO: u64 = 51;
pub const SYS_GETCREDENTIALS: u64 = 52;
pub const SYS_SPAWN_AS: u64 = 53;
pub const SYS_SPAWN_PRIVILEGED: u64 = 54;
pub const SYS_GET_CALLER_CREDENTIALS: u64 = 55;
pub const SYS_SEEK: u64 = 56;
pub const SYS_TRUNCATE: u64 = 57;
pub const SYS_UNLINK: u64 = 58;
pub const SYS_RENAME: u64 = 59;
pub const OPEN_WRITE: u64 = 1;
pub const OPEN_CREATE: u64 = 2;
pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;
pub const SPAWN_INHERIT_FD: u64 = u64::MAX;
pub const SPAWN_INHERIT_PARENT_FD: u64 = u64::MAX - 8;
pub const NET_RECEIVE_HEADER_LENGTH: usize = 6;
pub const NET_MAX_PAYLOAD_LENGTH: usize = 1024;
pub const NET_MAX_BUFFER_LENGTH: usize = NET_RECEIVE_HEADER_LENGTH + NET_MAX_PAYLOAD_LENGTH;
pub const NET_INFO_MAX_LENGTH: usize = 320;
pub const NET_INTERFACES_MAX_LENGTH: usize = 1024;
pub const NET_RENEW_MAX_LENGTH: usize = 1024;
pub const GRAPHICS_INFO_LENGTH: usize = 16;
pub const GRAPHICS_RECT_LENGTH: usize = 20;
pub const GRAPHICS_TEXT_REQUEST_LENGTH: usize = 32;
pub const INPUT_EVENT_MOUSE: u32 = 1;
pub const INPUT_EVENT_KEYBOARD: u32 = 2;
pub const INPUT_EVENT_WINDOW: u32 = 3;
pub const WINDOW_EVENT_CONFIGURE: u32 = 1;
pub const WINDOW_EVENT_CLOSE: u32 = 2;
pub const INPUT_EVENT_LENGTH: usize = 24;
pub const GRAPHICS_WINDOW_LENGTH: usize = 16;
pub const MAX_WINDOW_TEXT_LENGTH: usize = 96;
pub const GRAPHICS_POINTER_EVENT_LENGTH: usize = 24;
pub const PAGE_SIZE: usize = 4096;
pub const PATH_INFO_LENGTH: usize = 16;
pub const CREDENTIALS_LENGTH: usize = 16;
pub const PATH_KIND_FILE: u64 = 1;
pub const PATH_KIND_DIRECTORY: u64 = 2;

pub const ROOT_UID: u64 = 0;
pub const ROOT_GID: u64 = 0;
pub const USER_UID: u64 = 1000;
pub const USER_GID: u64 = 1000;

pub const SYSCALL_EPERM: u64 = u64::MAX - 8;
pub const SYSCALL_EINVAL: u64 = u64::MAX - 6;
pub const SYSCALL_ENOENT: u64 = u64::MAX - 4;
pub const SYSCALL_EAGAIN: u64 = u64::MAX - 1;
pub const SYSCALL_EROFS: u64 = u64::MAX - 7;
pub const SYSCALL_ERROR_MIN: u64 = SYSCALL_EPERM;

#[derive(Clone, Copy)]
struct RawResult {
    rax: u64,
    rdx: u64,
}

#[derive(Clone, Copy)]
pub struct WaitResult {
    pub pid: u64,
    pub status: i64,
}

#[derive(Clone, Copy)]
pub struct PipeResult {
    pub read: u64,
    pub write: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Credentials {
    pub uid: u64,
    pub gid: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GraphicsInfo {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bytes_per_pixel: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GraphicsRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub color: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GraphicsWindow {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[repr(C)]
pub struct GraphicsTextRequest {
    pub x: u32,
    pub y: u32,
    pub color: u32,
    pub reserved: u32,
    pub bytes: *const u8,
    pub length: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InputEvent {
    pub kind: u32,
    pub buttons: u32,
    pub dx: i32,
    pub dy: i32,
    pub wheel: i32,
    pub code: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GraphicsPointerEvent {
    pub x: u32,
    pub y: u32,
    pub buttons: u32,
    pub dx: i32,
    pub dy: i32,
    pub wheel: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PathInfo {
    pub kind: u64,
    pub size: u64,
}

#[inline]
pub fn default_window_geometry(info: GraphicsInfo, secondary: bool) -> GraphicsWindow {
    let (width, height) = if secondary {
        (info.width.min(280), info.height.min(232))
    } else {
        (info.width.min(500), info.height.min(232))
    };
    // Keep the title bar near the initial compositor cursor on both the 720p BIOS and 800p UEFI
    // guests, while retaining a stable lower-screen desktop layout.
    let y = info.height.saturating_div(2).saturating_sub(22);
    let x = if secondary {
        info.width.saturating_sub(width.saturating_add(40))
    } else {
        info.width.saturating_sub(width.saturating_add(240))
    };
    GraphicsWindow {
        x,
        y,
        width,
        height,
    }
}

#[inline(always)]
fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> RawResult {
    let mut rax = number;
    let mut rdx = arg2;
    // The kernel preserves all general-purpose registers across the DPL3 interrupt except for
    // the return registers. RCX and R11 are nevertheless declared clobbered because `int` uses
    // them for the hardware return frame.
    unsafe {
        asm!(
            "int 0x80",
            inout("rax") rax,
            in("rdi") arg0,
            in("rsi") arg1,
            inlateout("rdx") rdx,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    RawResult { rax, rdx }
}

#[inline]
pub fn is_syscall_error(value: u64) -> bool {
    value >= SYSCALL_ERROR_MIN
}

#[inline]
pub fn is_permission_error(value: u64) -> bool {
    value == SYSCALL_EPERM
}

#[inline]
pub fn getpid() -> u64 {
    syscall(SYS_GETPID, 0, 0, 0).rax
}

#[inline]
pub fn yield_now() {
    let _ = syscall(SYS_YIELD, 0, 0, 0);
}

#[inline]
pub fn spawn(path: &[u8]) -> u64 {
    spawn_redirected(path, SPAWN_INHERIT_PARENT_FD, SPAWN_INHERIT_PARENT_FD)
}

#[inline]
pub fn spawn_redirected(path: &[u8], stdin_fd: u64, stdout_fd: u64) -> u64 {
    syscall(SYS_SPAWN, path.as_ptr() as u64, stdin_fd, stdout_fd).rax
}

#[inline]
pub fn spawn_as(path: &[u8], uid: u64, gid: u64) -> u64 {
    syscall(SYS_SPAWN_AS, path.as_ptr() as u64, uid, gid).rax
}

#[inline]
pub fn spawn_privileged_redirected(path: &[u8], stdin_fd: u64, stdout_fd: u64) -> u64 {
    syscall(
        SYS_SPAWN_PRIVILEGED,
        path.as_ptr() as u64,
        stdin_fd,
        stdout_fd,
    )
    .rax
}

#[inline]
pub fn get_credentials(credentials: &mut Credentials) -> u64 {
    syscall(
        SYS_GETCREDENTIALS,
        credentials as *mut Credentials as u64,
        CREDENTIALS_LENGTH as u64,
        0,
    )
    .rax
}

#[inline]
pub fn get_caller_credentials(credentials: &mut Credentials) -> u64 {
    syscall(
        SYS_GET_CALLER_CREDENTIALS,
        credentials as *mut Credentials as u64,
        CREDENTIALS_LENGTH as u64,
        0,
    )
    .rax
}

#[inline]
pub fn pipe() -> PipeResult {
    let result = syscall(SYS_PIPE, 0, 0, 0);
    PipeResult {
        read: result.rax,
        write: result.rdx,
    }
}

#[inline]
pub fn read_nonblocking(handle: u64, buffer: &mut [u8]) -> u64 {
    syscall(
        SYS_READ_NONBLOCK,
        handle,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    )
    .rax
}

#[inline]
pub fn waitpid(pid: u64) -> WaitResult {
    let result = syscall(SYS_WAITPID, pid, 0, 0);
    WaitResult {
        pid: result.rax,
        status: result.rdx as i64,
    }
}

#[inline]
pub fn waitpid_nonblocking(pid: u64) -> WaitResult {
    let result = syscall(SYS_WAITPID_NONBLOCK, pid, 0, 0);
    WaitResult {
        pid: result.rax,
        status: result.rdx as i64,
    }
}

#[inline]
pub fn open(path: &[u8]) -> u64 {
    open_with_flags(path, 0)
}

#[inline]
pub fn open_with_flags(path: &[u8], flags: u64) -> u64 {
    syscall(SYS_OPEN, path.as_ptr() as u64, flags, 0).rax
}

#[inline]
pub fn open_write(path: &[u8]) -> u64 {
    open_with_flags(path, OPEN_WRITE)
}

#[inline]
pub fn open_create(path: &[u8]) -> u64 {
    open_with_flags(path, OPEN_CREATE)
}

#[inline]
pub fn open_create_write(path: &[u8]) -> u64 {
    open_with_flags(path, OPEN_CREATE | OPEN_WRITE)
}

#[inline]
pub fn mkdir(path: &[u8]) -> u64 {
    syscall(SYS_MKDIR, path.as_ptr() as u64, 0, 0).rax
}

#[inline]
pub fn path_info(path: &[u8], info: &mut PathInfo) -> u64 {
    syscall(
        SYS_PATH_INFO,
        path.as_ptr() as u64,
        info as *mut PathInfo as u64,
        PATH_INFO_LENGTH as u64,
    )
    .rax
}

#[inline]
pub fn mmap(length: usize, writable: bool) -> u64 {
    syscall(SYS_MMAP, length as u64, writable as u64, 0).rax
}

#[inline]
pub fn munmap(address: u64, length: usize) -> u64 {
    syscall(SYS_MUNMAP, address, length as u64, 0).rax
}

#[inline]
pub fn net_send(destination: [u8; 4], destination_port: u16, payload: &[u8]) -> u64 {
    let mut endpoint = [0u8; 6];
    endpoint[..4].copy_from_slice(&destination);
    endpoint[4..].copy_from_slice(&destination_port.to_be_bytes());
    syscall(
        SYS_NET_SEND,
        endpoint.as_ptr() as u64,
        payload.as_ptr() as u64,
        payload.len() as u64,
    )
    .rax
}

#[inline]
pub fn net_receive(buffer: &mut [u8]) -> u64 {
    syscall(
        SYS_NET_RECEIVE,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
        0,
    )
    .rax
}

#[inline]
pub fn net_info(buffer: &mut [u8]) -> u64 {
    syscall(
        SYS_NET_INFO,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
        0,
    )
    .rax
}

#[inline]
pub fn net_interfaces(buffer: &mut [u8]) -> u64 {
    syscall(
        SYS_NET_INTERFACES,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
        0,
    )
    .rax
}

#[inline]
pub fn net_renew(buffer: &mut [u8]) -> u64 {
    syscall(
        SYS_NET_RENEW,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
        0,
    )
    .rax
}

#[inline]
pub fn poweroff() -> u64 {
    syscall(SYS_POWEROFF, 0, 0, 0).rax
}

#[inline]
pub fn reboot() -> u64 {
    syscall(SYS_REBOOT, 0, 0, 0).rax
}

#[inline]
pub fn suspend() -> u64 {
    syscall(SYS_SUSPEND, 0, 0, 0).rax
}

#[inline]
pub fn graphics_info(info: &mut GraphicsInfo) -> u64 {
    syscall(
        SYS_GFX_INFO,
        info as *mut GraphicsInfo as u64,
        GRAPHICS_INFO_LENGTH as u64,
        0,
    )
    .rax
}

#[inline]
pub fn graphics_acquire() -> u64 {
    syscall(SYS_GFX_ACQUIRE, 0, 0, 0).rax
}

#[inline]
pub fn graphics_fill_rect(rect: &GraphicsRect) -> u64 {
    syscall(
        SYS_GFX_FILL_RECT,
        rect as *const GraphicsRect as u64,
        GRAPHICS_RECT_LENGTH as u64,
        0,
    )
    .rax
}

#[inline]
pub fn graphics_text(x: u32, y: u32, color: u32, bytes: &[u8]) -> u64 {
    let request = GraphicsTextRequest {
        x,
        y,
        color,
        reserved: 0,
        bytes: bytes.as_ptr(),
        length: bytes.len() as u64,
    };
    syscall(
        SYS_GFX_TEXT,
        &request as *const GraphicsTextRequest as u64,
        GRAPHICS_TEXT_REQUEST_LENGTH as u64,
        0,
    )
    .rax
}

#[inline]
pub fn graphics_release() -> u64 {
    syscall(SYS_GFX_RELEASE, 0, 0, 0).rax
}

#[inline]
pub fn input_read(event: &mut InputEvent) -> u64 {
    syscall(
        SYS_INPUT_READ,
        event as *mut InputEvent as u64,
        INPUT_EVENT_LENGTH as u64,
        0,
    )
    .rax
}

#[inline]
pub fn graphics_window_create(window: &GraphicsWindow) -> u64 {
    syscall(
        SYS_GFX_WINDOW_CREATE,
        window as *const GraphicsWindow as u64,
        GRAPHICS_WINDOW_LENGTH as u64,
        0,
    )
    .rax
}

#[inline]
pub fn graphics_window_clear(window_id: u64) -> u64 {
    syscall(SYS_GFX_WINDOW_CLEAR, window_id, 0, 0).rax
}

#[inline]
pub fn graphics_window_fill_rect(window_id: u64, rect: &GraphicsRect) -> u64 {
    syscall(
        SYS_GFX_WINDOW_FILL_RECT,
        window_id,
        rect as *const GraphicsRect as u64,
        GRAPHICS_RECT_LENGTH as u64,
    )
    .rax
}

#[inline]
pub fn graphics_window_text(window_id: u64, x: u32, y: u32, color: u32, bytes: &[u8]) -> u64 {
    let request = GraphicsTextRequest {
        x,
        y,
        color,
        reserved: 0,
        bytes: bytes.as_ptr(),
        length: bytes.len() as u64,
    };
    syscall(
        SYS_GFX_WINDOW_TEXT,
        window_id,
        &request as *const GraphicsTextRequest as u64,
        GRAPHICS_TEXT_REQUEST_LENGTH as u64,
    )
    .rax
}

#[inline]
pub fn graphics_window_present(window_id: u64) -> u64 {
    syscall(SYS_GFX_WINDOW_PRESENT, window_id, 0, 0).rax
}

#[inline]
pub fn graphics_window_focus(window_id: u64) -> u64 {
    syscall(SYS_GFX_WINDOW_FOCUS, window_id, 0, 0).rax
}

#[inline]
pub fn graphics_window_destroy(window_id: u64) -> u64 {
    syscall(SYS_GFX_WINDOW_DESTROY, window_id, 0, 0).rax
}

#[inline]
pub fn graphics_window_geometry(window_id: u64, geometry: &mut GraphicsWindow) -> u64 {
    syscall(
        SYS_GFX_WINDOW_GET_GEOMETRY,
        window_id,
        geometry as *mut GraphicsWindow as u64,
        GRAPHICS_WINDOW_LENGTH as u64,
    )
    .rax
}

#[inline]
pub fn graphics_window_configure(window_id: u64, geometry: &GraphicsWindow) -> u64 {
    syscall(
        SYS_GFX_WINDOW_CONFIGURE,
        window_id,
        geometry as *const GraphicsWindow as u64,
        GRAPHICS_WINDOW_LENGTH as u64,
    )
    .rax
}

#[inline]
pub fn graphics_window_request_close(window_id: u64) -> u64 {
    syscall(SYS_GFX_WINDOW_REQUEST_CLOSE, window_id, 0, 0).rax
}

#[inline]
pub fn graphics_compose_windows() -> u64 {
    syscall(SYS_GFX_COMPOSE_WINDOWS, 0, 0, 0).rax
}

#[inline]
pub fn graphics_window_dispatch_pointer(event: &GraphicsPointerEvent) -> u64 {
    syscall(
        SYS_GFX_WINDOW_DISPATCH_POINTER,
        event as *const GraphicsPointerEvent as u64,
        GRAPHICS_POINTER_EVENT_LENGTH as u64,
        0,
    )
    .rax
}

#[inline]
pub fn graphics_window_read_event(window_id: u64, event: &mut InputEvent) -> u64 {
    syscall(
        SYS_GFX_WINDOW_READ_EVENT,
        window_id,
        event as *mut InputEvent as u64,
        INPUT_EVENT_LENGTH as u64,
    )
    .rax
}

#[inline]
pub fn graphics_window_dispatch_keyboard(event: &InputEvent) -> u64 {
    syscall(
        SYS_GFX_WINDOW_DISPATCH_KEYBOARD,
        event as *const InputEvent as u64,
        INPUT_EVENT_LENGTH as u64,
        0,
    )
    .rax
}

#[inline]
pub fn read(handle: u64, buffer: &mut [u8]) -> u64 {
    syscall(
        SYS_READ,
        handle,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    )
    .rax
}

#[inline]
pub fn close(handle: u64) -> u64 {
    syscall(SYS_CLOSE, handle, 0, 0).rax
}

#[inline]
pub fn seek(handle: u64, offset: i64, whence: u64) -> u64 {
    syscall(SYS_SEEK, handle, offset as u64, whence).rax
}

#[inline]
pub fn truncate(handle: u64, size: u64) -> u64 {
    syscall(SYS_TRUNCATE, handle, size, 0).rax
}

#[inline]
pub fn unlink(path: &[u8]) -> u64 {
    syscall(SYS_UNLINK, path.as_ptr() as u64, 0, 0).rax
}

#[inline]
pub fn rename(source: &[u8], destination: &[u8]) -> u64 {
    syscall(
        SYS_RENAME,
        source.as_ptr() as u64,
        destination.as_ptr() as u64,
        0,
    )
    .rax
}

#[inline]
pub fn write(handle: u64, bytes: &[u8]) -> u64 {
    syscall(SYS_WRITE, handle, bytes.as_ptr() as u64, bytes.len() as u64).rax
}

#[inline]
pub fn write_stdout(bytes: &[u8]) {
    let mut offset = 0;
    while offset < bytes.len() {
        let length = core::cmp::min(256, bytes.len() - offset);
        let _ = write(1, &bytes[offset..offset + length]);
        offset += length;
    }
}

#[inline]
pub fn thread_create(entry: extern "C" fn(u64) -> !, argument: u64) -> u64 {
    syscall(SYS_THREAD_CREATE, entry as usize as u64, argument, 0).rax
}

#[inline]
pub fn thread_join(tid: u64) -> u64 {
    syscall(SYS_THREAD_JOIN, tid, 0, 0).rax
}

#[inline]
pub fn fork() -> u64 {
    syscall(SYS_FORK, 0, 0, 0).rax
}

#[inline]
pub fn exec(path: &[u8]) -> u64 {
    syscall(SYS_EXEC, path.as_ptr() as u64, 0, 0).rax
}

#[inline]
pub fn list_processes(buffer: &mut [u8]) -> u64 {
    syscall(
        SYS_LIST_PROCESSES,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
        0,
    )
    .rax
}

#[inline]
pub fn list_files(buffer: &mut [u8]) -> u64 {
    syscall(
        SYS_LIST_FILES,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
        0,
    )
    .rax
}

pub fn exercise_file_and_thread(message: &[u8], data_path: &[u8]) -> ! {
    yield_now();
    for _ in 0..20_000_000 {
        core::hint::spin_loop();
    }
    let _ = getpid();

    let tid = thread_create(helper_thread, 0);
    let handle = open(data_path);
    let mut buffer = [0u8; 4];
    if !is_syscall_error(handle) {
        let count = read(handle, &mut buffer);
        let _ = close(handle);
        if count == 4 {
            write_stdout(&buffer);
        }
    }
    write_stdout(message);
    if !is_syscall_error(tid) {
        let _ = thread_join(tid);
    }
    exit(0)
}

extern "C" fn helper_thread(_argument: u64) -> ! {
    yield_now();
    thread_exit(0)
}

#[inline(never)]
pub fn exit(code: i64) -> ! {
    let _ = syscall(SYS_EXIT, code as u64, 0, 0);
    halt_forever()
}

#[inline(never)]
pub fn thread_exit(code: i64) -> ! {
    let _ = syscall(SYS_THREAD_EXIT, code as u64, 0, 0);
    halt_forever()
}

#[inline(never)]
pub fn halt_forever() -> ! {
    loop {
        unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    halt_forever()
}
