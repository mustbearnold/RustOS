#[cfg(target_os = "none")]
use core::{cmp::min, fmt, fmt::Write};

pub const USER_IMAGE_BASE: u64 = 0x0000_0080_0000_0000;
pub const USER_SPACE_END: u64 = 0x0000_0080_4000_0000;
pub const USER_STACK_TOP: u64 = USER_SPACE_END;
// Package signature verification uses a deeper pure-Rust call graph than the original shell
// programs, so keep a bounded 64 KiB user stack for normal user processes.
pub const USER_STACK_PAGE_COUNT: u64 = 16;
const MAX_USER_THREADS_PER_PROCESS: usize = 4;
const USER_THREAD_STACK_PAGE_COUNT: u64 = 4;
const USER_MMAP_START: u64 = USER_IMAGE_BASE + 0x0100_0000;
const USER_MMAP_END: u64 = USER_STACK_TOP
    - (USER_STACK_PAGE_COUNT
        + (MAX_USER_THREADS_PER_PROCESS as u64 * USER_THREAD_STACK_PAGE_COUNT)
        + 1)
        * PAGE_SIZE;
const MAX_ANONYMOUS_MMAP_PAGES: u64 = 256;
const MAX_USER_MAPPINGS: usize = 16 * 1024;

pub type ProcessId = u32;
pub type ThreadId = u32;
pub type UserId = u32;
pub type GroupId = u32;
pub const INIT_PROCESS_ID: ProcessId = 1;
pub const MAIN_THREAD_ID: ThreadId = 0;
pub const ROOT_UID: UserId = 0;
pub const ROOT_GID: GroupId = 0;
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
const PATH_INFO_LENGTH: usize = 16;
const CREDENTIALS_LENGTH: usize = 16;
const PATH_KIND_FILE: u64 = 1;
const PATH_KIND_DIRECTORY: u64 = 2;
pub const OPEN_WRITE: u64 = 1;
pub const OPEN_CREATE: u64 = 2;
pub const SPAWN_INHERIT_FD: u64 = u64::MAX;
pub const SPAWN_INHERIT_PARENT_FD: u64 = u64::MAX - 8;
const PRIVILEGED_ADMIN_PATH: &[u8] = b"/sbin/admin";
pub const SYSCALL_ENOSYS: u64 = u64::MAX;
pub const SYSCALL_EAGAIN: u64 = u64::MAX - 1;
pub const SYSCALL_ECHILD: u64 = u64::MAX - 2;
pub const SYSCALL_EFAULT: u64 = u64::MAX - 3;
pub const SYSCALL_ENOENT: u64 = u64::MAX - 4;
pub const SYSCALL_EBADF: u64 = u64::MAX - 5;
pub const SYSCALL_EINVAL: u64 = u64::MAX - 6;
pub const SYSCALL_EROFS: u64 = u64::MAX - 7;
pub const SYSCALL_EPERM: u64 = u64::MAX - 8;
pub const SYSCALL_ERROR_MIN: u64 = SYSCALL_EPERM;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcessState {
    Ready = 0,
    Running = 1,
    Exited = 2,
    Faulted = 3,
    Blocked = 4,
}

impl ProcessState {
    pub const fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::Ready,
            1 => Self::Running,
            2 => Self::Exited,
            3 => Self::Faulted,
            4 => Self::Blocked,
            _ => Self::Faulted,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyscallFrame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

#[cfg(target_os = "none")]
#[repr(C)]
#[derive(Clone, Copy)]
struct UserInterruptFrame {
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

#[cfg(target_os = "none")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ForkContext {
    registers: SyscallFrame,
    return_frame: UserInterruptFrame,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallAction {
    Return,
    Yield,
    Exit,
    Spawn,
    Wait,
    Write,
    Open,
    Read,
    Close,
    ThreadCreate,
    ThreadJoin,
    ThreadExit,
    Exec,
    Fork,
    ListProcesses,
    ListFiles,
    Mkdir,
    Mmap,
    Munmap,
    NetSend,
    NetReceive,
    NetInfo,
    NetInterfaces,
    NetRenew,
    GfxInfo,
    GfxAcquire,
    GfxFillRect,
    GfxText,
    GfxRelease,
    InputRead,
    GfxWindowCreate,
    GfxWindowClear,
    GfxWindowFillRect,
    GfxWindowText,
    GfxWindowPresent,
    GfxWindowDestroy,
    GfxComposeWindows,
    GfxWindowDispatchPointer,
    GfxWindowReadEvent,
    GfxWindowDispatchKeyboard,
    GfxWindowGetGeometry,
    GfxWindowConfigure,
    GfxWindowRequestClose,
    Poweroff,
    Reboot,
    Suspend,
    Pipe,
    ReadNonblocking,
    GfxWindowFocus,
    WaitpidNonblocking,
    PathInfo,
    GetCredentials,
    SpawnAs,
    SpawnPrivileged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessExit {
    pub code: i64,
    pub syscalls: u64,
}

/// RustOS syscall ABI: `rax` selects the operation, `rdi` carries argument 0, and `rax` carries
/// the result. `SYS_GETPID` returns the process identifier; `SYS_YIELD` returns zero after a
/// scheduler handoff; `SYS_EXIT` terminates the current process with the signed exit code in `rdi`;
/// `SYS_SPAWN` reads the NUL-terminated executable path pointed to by `rdi`, duplicates or
/// inherits the parent handles selected by `rsi` (stdin) and `rdx` (stdout), creates that user
/// program from the filesystem-backed image registry, and returns its process identifier;
/// `SPAWN_INHERIT_FD` keeps the corresponding standard stream attached to the console;
/// `SPAWN_INHERIT_PARENT_FD` inherits the caller's corresponding standard stream; `SYS_SPAWN_AS`
/// is a root-only variant that reads the path from `rdi`, uses the requested UID in
/// `rsi` and GID in `rdx`, and inherits both standard streams from the caller;
/// `SYS_SPAWN_PRIVILEGED` permits an explicit non-root caller to launch only the allowlisted
/// `/sbin/admin` helper as root, with selected redirected streams; `SYS_GETCREDENTIALS`
/// writes a bounded `{uid, gid}` record to the user buffer `(rdi, rsi)`; `SYS_PIPE` returns a
/// readable descriptor in `rax` and a writable descriptor in `rdx` for a bounded
/// anonymous pipe; and `SYS_READ_NONBLOCK` has the same ABI as `SYS_READ` but returns
/// `SYSCALL_EAGAIN` instead of yielding when a pipe has no data;
/// `SYS_WAITPID` blocks until the selected child exits, then returns that child identifier;
/// `SYS_WAITPID_NONBLOCK` returns `SYSCALL_EAGAIN` while the selected child is still running;
/// `SYS_WRITE` writes the user buffer `(rsi, rdx)` to file descriptor `rdi` and returns its length;
/// file descriptor 0 is the non-blocking serial-console input stream and descriptor 1 is the
/// serial-console output stream; `SYS_OPEN` opens a filesystem-backed regular-file path, with
/// `OPEN_WRITE` in `rsi` selecting writable mode and `OPEN_CREATE` selecting bounded root-file
/// creation when the path is absent;
/// `SYS_READ` reads from its handle into the user buffer `(rsi, rdx)`; `SYS_CLOSE` releases that
/// handle; `SYS_THREAD_CREATE` starts the
/// executable entry point in the current address space with its argument in `rsi` and returns a
/// thread identifier; `SYS_THREAD_JOIN` blocks until a same-process thread exits; and
/// `SYS_THREAD_EXIT` exits the calling thread without terminating its process; `SYS_EXEC` replaces
/// the calling process's user image from a cataloged ELF path while preserving its PID; and
/// `SYS_FORK` duplicates the calling process's user address space and main-thread continuation,
/// returning the child PID to the parent and zero to the child. `SYS_LIST_PROCESSES` and
/// `SYS_LIST_FILES` writes bounded text snapshots to the user buffer `(rdi, rsi)` and returns the
/// number of bytes written; `SYS_MKDIR` creates one bounded FAT directory at the absolute path
/// pointed to by `rdi`; `SYS_PATH_INFO` resolves the absolute path at `rdi` and writes a bounded
/// `{kind, size}` record to `(rsi, rdx)`; `SYS_NET_SEND` sends a bounded UDP payload to the six-byte endpoint
/// `(IPv4 address, big-endian port)` at `rdi`, with payload `(rsi, rdx)`; `SYS_NET_RECEIVE` writes
/// a six-byte source endpoint followed by a bounded UDP payload to `(rdi, rsi)`; and
/// `SYS_NET_INFO` writes the current default-route DHCP/static network configuration text to
/// `(rdi, rsi)`; `SYS_NET_INTERFACES` writes the bounded network-manager interface and route table
/// to `(rdi, rsi)`; and `SYS_NET_RENEW` renews every DHCP lease through the network manager and
/// writes its bounded result report to `(rdi, rsi)`.
/// `SYS_GFX_INFO` writes the current framebuffer geometry to `(rdi, rsi)`; `SYS_GFX_ACQUIRE`
/// reserves the framebuffer for the calling process; `SYS_GFX_FILL_RECT` reads one bounded
/// color rectangle from `(rdi, rsi)`; `SYS_GFX_TEXT` reads a bounded text request from `(rdi, rsi)`
/// and its UTF-8/ASCII bytes from the request; and `SYS_GFX_RELEASE` relinquishes ownership.
/// `SYS_INPUT_READ` returns a bounded binary input event into `(rdi, rsi)` and returns zero when
/// no event is pending; `SYS_GFX_WINDOW_CREATE` creates a bounded retained window from the
/// geometry at `(rdi, rsi)` and returns its identifier; `SYS_GFX_WINDOW_CLEAR` clears the current
/// process's window identified by `rdi`; `SYS_GFX_WINDOW_FILL_RECT` stores a relative rectangle
/// from `(rsi, rdx)` for that window; `SYS_GFX_WINDOW_TEXT` stores a bounded relative text request
/// from `(rsi, rdx)`; `SYS_GFX_WINDOW_PRESENT` presents the window identified by `rdi`;
/// `SYS_GFX_WINDOW_DESTROY` releases it; and `SYS_GFX_COMPOSE_WINDOWS` redraws all presented
/// client windows over the compositor-owned scene. `SYS_GFX_WINDOW_FOCUS` raises and focuses the
/// caller's window. `SYS_GFX_WINDOW_DISPATCH_POINTER` hit-tests
/// the pointer event at `(rdi, rsi)`, raises the hit client on a button press, queues the event,
/// and returns the selected window identifier (or zero when no window was hit); and
/// `SYS_GFX_WINDOW_READ_EVENT` returns the next queued event for the window identified by `rdi`
/// into `(rsi, rdx)`. `SYS_GFX_WINDOW_DISPATCH_KEYBOARD` routes the keyboard event at `(rdi, rsi)`
/// to the currently focused client window. `SYS_GFX_WINDOW_GET_GEOMETRY` returns the retained
/// geometry for the caller's window; `SYS_GFX_WINDOW_CONFIGURE` lets the compositor move or resize
/// a client window and queues a configure event; and `SYS_GFX_WINDOW_REQUEST_CLOSE` queues a close
/// event for the compositor-selected client. `SYS_POWEROFF` requests an ACPI S5 shutdown when the
/// firmware exposes a validated PM1 control block and `_S5_` sleep package; `SYS_REBOOT` requests
/// a reset through the FADT reset-register GAS; and `SYS_SUSPEND` enters ACPI S3 and returns only
/// after the PM1 wake-status bit proves that the guest resumed.
pub fn dispatch_syscall(pid: ProcessId, frame: &mut SyscallFrame) -> SyscallAction {
    match frame.rax {
        SYS_GETPID => {
            frame.rax = u64::from(pid);
            SyscallAction::Return
        }
        SYS_YIELD => {
            frame.rax = 0;
            SyscallAction::Yield
        }
        SYS_EXIT => {
            frame.rax = 0;
            SyscallAction::Exit
        }
        SYS_SPAWN => SyscallAction::Spawn,
        SYS_SPAWN_AS => SyscallAction::SpawnAs,
        SYS_SPAWN_PRIVILEGED => SyscallAction::SpawnPrivileged,
        SYS_GETCREDENTIALS => SyscallAction::GetCredentials,
        SYS_WAITPID => SyscallAction::Wait,
        SYS_WAITPID_NONBLOCK => SyscallAction::WaitpidNonblocking,
        SYS_WRITE => SyscallAction::Write,
        SYS_OPEN => SyscallAction::Open,
        SYS_READ => SyscallAction::Read,
        SYS_CLOSE => SyscallAction::Close,
        SYS_THREAD_CREATE => SyscallAction::ThreadCreate,
        SYS_THREAD_JOIN => SyscallAction::ThreadJoin,
        SYS_THREAD_EXIT => SyscallAction::ThreadExit,
        SYS_EXEC => SyscallAction::Exec,
        SYS_FORK => SyscallAction::Fork,
        SYS_LIST_PROCESSES => SyscallAction::ListProcesses,
        SYS_LIST_FILES => SyscallAction::ListFiles,
        SYS_MKDIR => SyscallAction::Mkdir,
        SYS_PATH_INFO => SyscallAction::PathInfo,
        SYS_MMAP => SyscallAction::Mmap,
        SYS_MUNMAP => SyscallAction::Munmap,
        SYS_NET_SEND => SyscallAction::NetSend,
        SYS_NET_RECEIVE => SyscallAction::NetReceive,
        SYS_NET_INFO => SyscallAction::NetInfo,
        SYS_NET_INTERFACES => SyscallAction::NetInterfaces,
        SYS_NET_RENEW => SyscallAction::NetRenew,
        SYS_GFX_INFO => SyscallAction::GfxInfo,
        SYS_GFX_ACQUIRE => SyscallAction::GfxAcquire,
        SYS_GFX_FILL_RECT => SyscallAction::GfxFillRect,
        SYS_GFX_TEXT => SyscallAction::GfxText,
        SYS_GFX_RELEASE => SyscallAction::GfxRelease,
        SYS_INPUT_READ => SyscallAction::InputRead,
        SYS_GFX_WINDOW_CREATE => SyscallAction::GfxWindowCreate,
        SYS_GFX_WINDOW_CLEAR => SyscallAction::GfxWindowClear,
        SYS_GFX_WINDOW_FILL_RECT => SyscallAction::GfxWindowFillRect,
        SYS_GFX_WINDOW_TEXT => SyscallAction::GfxWindowText,
        SYS_GFX_WINDOW_PRESENT => SyscallAction::GfxWindowPresent,
        SYS_GFX_WINDOW_DESTROY => SyscallAction::GfxWindowDestroy,
        SYS_GFX_COMPOSE_WINDOWS => SyscallAction::GfxComposeWindows,
        SYS_GFX_WINDOW_DISPATCH_POINTER => SyscallAction::GfxWindowDispatchPointer,
        SYS_GFX_WINDOW_READ_EVENT => SyscallAction::GfxWindowReadEvent,
        SYS_GFX_WINDOW_DISPATCH_KEYBOARD => SyscallAction::GfxWindowDispatchKeyboard,
        SYS_GFX_WINDOW_GET_GEOMETRY => SyscallAction::GfxWindowGetGeometry,
        SYS_GFX_WINDOW_CONFIGURE => SyscallAction::GfxWindowConfigure,
        SYS_GFX_WINDOW_REQUEST_CLOSE => SyscallAction::GfxWindowRequestClose,
        SYS_POWEROFF => SyscallAction::Poweroff,
        SYS_REBOOT => SyscallAction::Reboot,
        SYS_SUSPEND => SyscallAction::Suspend,
        SYS_PIPE => SyscallAction::Pipe,
        SYS_READ_NONBLOCK => SyscallAction::ReadNonblocking,
        SYS_GFX_WINDOW_FOCUS => SyscallAction::GfxWindowFocus,
        _ => {
            frame.rax = SYSCALL_ENOSYS;
            SyscallAction::Return
        }
    }
}

const ELF_HEADER_SIZE: usize = 64;
const ELF_PROGRAM_HEADER_SIZE: usize = 56;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF_VERSION_CURRENT: u8 = 1;
const ELF_MACHINE_X86_64: u16 = 0x3e;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_PROGRAM_TYPE_LOAD: u32 = 1;
const ELF_FLAG_EXECUTABLE: u32 = 1;
const ELF_FLAG_WRITABLE: u32 = 2;
const ELF_FLAG_READABLE: u32 = 4;
const PAGE_SIZE: u64 = 4096;
const MAX_ELF_SEGMENTS: usize = 16;
pub const MAX_EXECUTABLE_PATH_LENGTH: usize = 64;
const USER_STDIN_FD: u64 = 0;
const USER_STDOUT_FD: u64 = 1;
const MODE_USER_READ: u32 = 0o400;
const MODE_USER_WRITE: u32 = 0o200;
const MODE_USER_EXECUTE: u32 = 0o100;
const MODE_GROUP_READ: u32 = 0o040;
const MODE_GROUP_WRITE: u32 = 0o020;
const MODE_GROUP_EXECUTE: u32 = 0o010;
const MODE_OTHER_READ: u32 = 0o004;
const MODE_OTHER_WRITE: u32 = 0o002;
const MODE_OTHER_EXECUTE: u32 = 0o001;
const USER_HOME_PATH: &[u8] = b"/home/user";

#[derive(Clone, Copy)]
enum AccessKind {
    Read,
    Write,
    Execute,
}

fn mode_allows(
    mode: u32,
    owner_uid: UserId,
    owner_gid: GroupId,
    uid: UserId,
    gid: GroupId,
    access: AccessKind,
) -> bool {
    if uid == ROOT_UID {
        return !matches!(access, AccessKind::Execute)
            || mode & (MODE_USER_EXECUTE | MODE_GROUP_EXECUTE | MODE_OTHER_EXECUTE) != 0;
    }
    let (user_bit, group_bit, other_bit) = match access {
        AccessKind::Read => (MODE_USER_READ, MODE_GROUP_READ, MODE_OTHER_READ),
        AccessKind::Write => (MODE_USER_WRITE, MODE_GROUP_WRITE, MODE_OTHER_WRITE),
        AccessKind::Execute => (MODE_USER_EXECUTE, MODE_GROUP_EXECUTE, MODE_OTHER_EXECUTE),
    };
    let bit = if uid == owner_uid {
        user_bit
    } else if gid == owner_gid {
        group_bit
    } else {
        other_bit
    };
    mode & bit != 0
}

fn user_home_path(path: &[u8]) -> bool {
    path == USER_HOME_PATH
        || path
            .strip_prefix(USER_HOME_PATH)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
}

fn runtime_access_allowed(path: &[u8], uid: UserId, access: AccessKind) -> bool {
    uid == ROOT_UID || matches!(access, AccessKind::Read) || user_home_path(path)
}
const MAX_USER_WRITE_LENGTH: usize = 256;
#[cfg(target_os = "none")]
const GRAPHICS_INFO_LENGTH: usize = 16;
#[cfg(target_os = "none")]
const GRAPHICS_RECT_LENGTH: usize = 20;
#[cfg(target_os = "none")]
const GRAPHICS_TEXT_REQUEST_LENGTH: usize = 32;
#[cfg(target_os = "none")]
const MAX_GRAPHICS_TEXT_LENGTH: usize = crate::framebuffer::MAX_GRAPHICS_TEXT_LENGTH;
#[cfg(target_os = "none")]
const GRAPHICS_WINDOW_LENGTH: usize = 16;
#[cfg(target_os = "none")]
const MAX_WINDOW_TEXT_LENGTH: usize = crate::framebuffer::MAX_WINDOW_TEXT_LENGTH;
#[cfg(target_os = "none")]
const GRAPHICS_POINTER_EVENT_LENGTH: usize = 24;
#[cfg(target_os = "none")]
const MAX_GRAPHICS_RECT_DIMENSION: u32 = 4096;
#[cfg(target_os = "none")]
const MAX_GRAPHICS_RECT_AREA: u64 = 4 * 1024 * 1024;
#[cfg(target_os = "none")]
const MAX_NETWORK_PAYLOAD_LENGTH: usize = crate::network_runtime::MAX_NETWORK_PAYLOAD_LENGTH;
#[cfg(target_os = "none")]
const MAX_NETWORK_BUFFER_LENGTH: usize = crate::network_runtime::MAX_NETWORK_BUFFER_LENGTH;
#[cfg(target_os = "none")]
const MAX_NETWORK_INFO_LENGTH: usize = crate::network_runtime::NETWORK_INFO_MAX_LENGTH;
#[cfg(target_os = "none")]
const MAX_NETWORK_INTERFACES_LENGTH: usize = crate::network_runtime::NETWORK_INTERFACES_MAX_LENGTH;
#[cfg(target_os = "none")]
const MAX_NETWORK_RENEW_LENGTH: usize = crate::network_runtime::NETWORK_RENEW_MAX_LENGTH;
const MAX_PROCESS_HANDLES: usize = 8;
const OPEN_SUPPORTED_FLAGS: u64 = OPEN_WRITE | OPEN_CREATE;
const USER_L4_INDEX: usize = ((USER_IMAGE_BASE >> 39) & 0x1ff) as usize;
const USER_INIT_CODE_OFFSET: usize = 0x1000;
const USER_INIT_DATA_OFFSET: usize = 0x2000;
const USER_INIT_EXEC_PATH: &[u8] = b"/sbin/init\0";
pub const USER_INIT_CONFIG_READ_LENGTH: u8 = 44;
pub const USER_SHELL_CONFIG_READ_LENGTH: u8 = 10;
const USER_INIT_PROGRAM_DATA_LENGTH: usize = USER_INIT_EXEC_PATH.len();
const USER_INIT_EXEC_PATH_ADDRESS: u64 = USER_IMAGE_BASE + 2 * PAGE_SIZE;

const fn emit_syscall(code: &mut [u8], offset: usize, syscall: u8) -> usize {
    code[offset] = 0xb8;
    code[offset + 1] = syscall;
    code[offset + 5] = 0xcd;
    code[offset + 6] = 0x80;
    offset + 7
}

const fn emit_path_argument(code: &mut [u8], offset: usize, address: u64) -> usize {
    code[offset] = 0x48;
    code[offset + 1] = 0xbf;
    put_u64(code, offset + 2, address);
    offset + 10
}

const fn build_user_init_code() -> [u8; 32] {
    let mut code = [0u8; 32];
    let mut offset = 0;

    // The initial process is a tiny Rust-kernel-owned trampoline. It replaces itself with the
    // compiled Rust userland supervisor after the filesystem catalog has been installed.
    offset = emit_path_argument(&mut code, offset, USER_INIT_EXEC_PATH_ADDRESS);
    offset = emit_syscall(&mut code, offset, SYS_EXEC as u8);
    code[offset] = 0xbf;
    code[offset + 1] = 98;
    offset += 5;
    offset = emit_syscall(&mut code, offset, SYS_EXIT as u8);
    let _ = offset;
    code
}

const USER_INIT_CODE: [u8; 32] = build_user_init_code();
pub const USER_INIT_ELF_LENGTH: usize = USER_INIT_DATA_OFFSET + USER_INIT_PROGRAM_DATA_LENGTH;
#[cfg(not(target_os = "none"))]
const USER_WORKER_CODE: [u8; 35] = [
    0xb8, 2, 0, 0, 0, 0xcd, 0x80, // yield
    0xb9, 0x00, 0x2d, 0x31, 0x01, // mov ecx, 20,000,000
    0xff, 0xc9, // dec ecx
    0x75, 0xfc, // jnz loop
    0xb8, 1, 0, 0, 0, 0xcd, 0x80, // getpid
    0xb8, 3, 0, 0, 0, 0xbf, 0, 0, 0, 0, 0xcd, 0x80, // exit(0)
];
#[cfg(not(target_os = "none"))]
pub const USER_WORKER_ELF_LENGTH: usize = USER_INIT_CODE_OFFSET + USER_WORKER_CODE.len();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfLoadSegment {
    pub virtual_address: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: u32,
}

impl ElfLoadSegment {
    pub fn end_address(self) -> Option<u64> {
        self.virtual_address.checked_add(self.memory_size)
    }

    pub fn contains(self, address: u64) -> bool {
        self.end_address()
            .is_some_and(|end| self.virtual_address <= address && address < end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfImage {
    pub entry: u64,
    segments: [ElfLoadSegment; MAX_ELF_SEGMENTS],
    segment_count: usize,
}

impl ElfImage {
    pub fn segments(&self) -> &[ElfLoadSegment] {
        &self.segments[..self.segment_count]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    InvalidMagic,
    UnsupportedClass,
    UnsupportedEndianness,
    UnsupportedVersion,
    UnsupportedType,
    UnsupportedMachine,
    InvalidProgramHeaderSize,
    ProgramHeadersOutOfBounds,
    TooManySegments,
    InvalidSegment,
    SegmentOutOfBounds,
    SegmentAlignment,
    SegmentOverlap,
    NoLoadSegments,
    InvalidEntry,
}

pub fn parse_elf64(image: &[u8]) -> Result<ElfImage, ElfError> {
    if image.len() < ELF_HEADER_SIZE {
        return Err(ElfError::TooShort);
    }
    if image[..4] != *b"\x7fELF" {
        return Err(ElfError::InvalidMagic);
    }
    if image[4] != ELF_CLASS_64 {
        return Err(ElfError::UnsupportedClass);
    }
    if image[5] != ELF_DATA_LITTLE_ENDIAN {
        return Err(ElfError::UnsupportedEndianness);
    }
    if image[6] != ELF_VERSION_CURRENT {
        return Err(ElfError::UnsupportedVersion);
    }
    if read_u16(image, 16) != Some(ELF_TYPE_EXECUTABLE) {
        return Err(ElfError::UnsupportedType);
    }
    if read_u16(image, 18) != Some(ELF_MACHINE_X86_64) {
        return Err(ElfError::UnsupportedMachine);
    }

    let entry = read_u64(image, 24).ok_or(ElfError::TooShort)?;
    let program_header_offset = usize::try_from(read_u64(image, 32).ok_or(ElfError::TooShort)?)
        .map_err(|_| ElfError::ProgramHeadersOutOfBounds)?;
    let program_header_size = usize::from(read_u16(image, 54).ok_or(ElfError::TooShort)?);
    let program_header_count = usize::from(read_u16(image, 56).ok_or(ElfError::TooShort)?);
    if program_header_size < ELF_PROGRAM_HEADER_SIZE {
        return Err(ElfError::InvalidProgramHeaderSize);
    }
    let program_headers_bytes = program_header_size
        .checked_mul(program_header_count)
        .ok_or(ElfError::ProgramHeadersOutOfBounds)?;
    let program_headers_end = program_header_offset
        .checked_add(program_headers_bytes)
        .ok_or(ElfError::ProgramHeadersOutOfBounds)?;
    if program_headers_end > image.len() {
        return Err(ElfError::ProgramHeadersOutOfBounds);
    }

    let mut segments = [ElfLoadSegment {
        virtual_address: 0,
        file_offset: 0,
        file_size: 0,
        memory_size: 0,
        flags: 0,
    }; MAX_ELF_SEGMENTS];
    let mut segment_count = 0;
    for index in 0..program_header_count {
        let offset = program_header_offset + index * program_header_size;
        let segment_type = read_u32(image, offset).ok_or(ElfError::ProgramHeadersOutOfBounds)?;
        if segment_type != ELF_PROGRAM_TYPE_LOAD {
            continue;
        }
        if segment_count == MAX_ELF_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }

        let flags = read_u32(image, offset + 4).ok_or(ElfError::InvalidSegment)?;
        if flags & !(ELF_FLAG_EXECUTABLE | ELF_FLAG_WRITABLE | ELF_FLAG_READABLE) != 0 {
            return Err(ElfError::InvalidSegment);
        }
        let file_offset = read_u64(image, offset + 8).ok_or(ElfError::InvalidSegment)?;
        let virtual_address = read_u64(image, offset + 16).ok_or(ElfError::InvalidSegment)?;
        let file_size = read_u64(image, offset + 32).ok_or(ElfError::InvalidSegment)?;
        let memory_size = read_u64(image, offset + 40).ok_or(ElfError::InvalidSegment)?;
        let alignment = read_u64(image, offset + 48).ok_or(ElfError::InvalidSegment)?;
        if memory_size == 0 || file_size > memory_size {
            return Err(ElfError::InvalidSegment);
        }
        if file_offset
            .checked_add(file_size)
            .is_none_or(|end| end > image.len() as u64)
        {
            return Err(ElfError::SegmentOutOfBounds);
        }
        let end_address = virtual_address
            .checked_add(memory_size)
            .ok_or(ElfError::SegmentOutOfBounds)?;
        if virtual_address < USER_IMAGE_BASE || end_address > USER_SPACE_END {
            return Err(ElfError::SegmentOutOfBounds);
        }
        if virtual_address % PAGE_SIZE != file_offset % PAGE_SIZE {
            return Err(ElfError::SegmentAlignment);
        }
        if alignment > 1
            && (alignment & (alignment - 1) != 0
                || virtual_address % alignment != file_offset % alignment)
        {
            return Err(ElfError::SegmentAlignment);
        }

        let segment = ElfLoadSegment {
            virtual_address,
            file_offset,
            file_size,
            memory_size,
            flags,
        };
        if segments[..segment_count].iter().any(|previous| {
            let previous_end = previous
                .end_address()
                .expect("validated ELF segment end must not overflow");
            virtual_address < previous_end && previous.virtual_address < end_address
        }) {
            return Err(ElfError::SegmentOverlap);
        }
        segments[segment_count] = segment;
        segment_count += 1;
    }

    if segment_count == 0 {
        return Err(ElfError::NoLoadSegments);
    }
    if !segments[..segment_count]
        .iter()
        .any(|segment| segment.contains(entry))
    {
        return Err(ElfError::InvalidEntry);
    }

    Ok(ElfImage {
        entry,
        segments,
        segment_count,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset.checked_add(1)?)?,
    ]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset.checked_add(1)?)?,
        *bytes.get(offset.checked_add(2)?)?,
        *bytes.get(offset.checked_add(3)?)?,
    ]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset.checked_add(1)?)?,
        *bytes.get(offset.checked_add(2)?)?,
        *bytes.get(offset.checked_add(3)?)?,
        *bytes.get(offset.checked_add(4)?)?,
        *bytes.get(offset.checked_add(5)?)?,
        *bytes.get(offset.checked_add(6)?)?,
        *bytes.get(offset.checked_add(7)?)?,
    ]))
}

const fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    let value = value.to_le_bytes();
    bytes[offset] = value[0];
    bytes[offset + 1] = value[1];
}

const fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    let value = value.to_le_bytes();
    let mut index = 0;
    while index < value.len() {
        bytes[offset + index] = value[index];
        index += 1;
    }
}

const fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    let value = value.to_le_bytes();
    let mut index = 0;
    while index < value.len() {
        bytes[offset + index] = value[index];
        index += 1;
    }
}

const fn build_user_init_elf() -> [u8; USER_INIT_ELF_LENGTH] {
    let mut image = [0u8; USER_INIT_ELF_LENGTH];
    image[0] = 0x7f;
    image[1] = b'E';
    image[2] = b'L';
    image[3] = b'F';
    image[4] = ELF_CLASS_64;
    image[5] = ELF_DATA_LITTLE_ENDIAN;
    image[6] = ELF_VERSION_CURRENT;
    put_u16(&mut image, 16, ELF_TYPE_EXECUTABLE);
    put_u16(&mut image, 18, ELF_MACHINE_X86_64);
    put_u32(&mut image, 20, 1);
    put_u64(&mut image, 24, USER_IMAGE_BASE);
    put_u64(&mut image, 32, ELF_HEADER_SIZE as u64);
    put_u16(&mut image, 52, ELF_HEADER_SIZE as u16);
    put_u16(&mut image, 54, ELF_PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut image, 56, 2);

    let header = ELF_HEADER_SIZE;
    put_u32(&mut image, header, ELF_PROGRAM_TYPE_LOAD);
    put_u32(
        &mut image,
        header + 4,
        ELF_FLAG_EXECUTABLE | ELF_FLAG_READABLE,
    );
    put_u64(&mut image, header + 8, USER_INIT_CODE_OFFSET as u64);
    put_u64(&mut image, header + 16, USER_IMAGE_BASE);
    put_u64(&mut image, header + 24, USER_IMAGE_BASE);
    put_u64(&mut image, header + 32, USER_INIT_CODE.len() as u64);
    put_u64(&mut image, header + 40, PAGE_SIZE);
    put_u64(&mut image, header + 48, PAGE_SIZE);

    let data_header = header + ELF_PROGRAM_HEADER_SIZE;
    put_u32(&mut image, data_header, ELF_PROGRAM_TYPE_LOAD);
    put_u32(
        &mut image,
        data_header + 4,
        ELF_FLAG_WRITABLE | ELF_FLAG_READABLE,
    );
    put_u64(&mut image, data_header + 8, USER_INIT_DATA_OFFSET as u64);
    put_u64(&mut image, data_header + 16, USER_INIT_EXEC_PATH_ADDRESS);
    put_u64(&mut image, data_header + 24, USER_INIT_EXEC_PATH_ADDRESS);
    put_u64(
        &mut image,
        data_header + 32,
        USER_INIT_PROGRAM_DATA_LENGTH as u64,
    );
    put_u64(&mut image, data_header + 40, PAGE_SIZE);
    put_u64(&mut image, data_header + 48, PAGE_SIZE);

    let mut index = 0;
    while index < USER_INIT_CODE.len() {
        image[USER_INIT_CODE_OFFSET + index] = USER_INIT_CODE[index];
        index += 1;
    }
    let mut index = 0;
    while index < USER_INIT_EXEC_PATH.len() {
        image[USER_INIT_DATA_OFFSET + index] = USER_INIT_EXEC_PATH[index];
        index += 1;
    }
    image
}

pub const USER_INIT_ELF: [u8; USER_INIT_ELF_LENGTH] = build_user_init_elf();

#[cfg(not(target_os = "none"))]
const fn build_user_worker_elf() -> [u8; USER_WORKER_ELF_LENGTH] {
    let mut image = [0u8; USER_WORKER_ELF_LENGTH];
    image[0] = 0x7f;
    image[1] = b'E';
    image[2] = b'L';
    image[3] = b'F';
    image[4] = ELF_CLASS_64;
    image[5] = ELF_DATA_LITTLE_ENDIAN;
    image[6] = ELF_VERSION_CURRENT;
    put_u16(&mut image, 16, ELF_TYPE_EXECUTABLE);
    put_u16(&mut image, 18, ELF_MACHINE_X86_64);
    put_u32(&mut image, 20, 1);
    put_u64(&mut image, 24, USER_IMAGE_BASE);
    put_u64(&mut image, 32, ELF_HEADER_SIZE as u64);
    put_u16(&mut image, 52, ELF_HEADER_SIZE as u16);
    put_u16(&mut image, 54, ELF_PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut image, 56, 1);

    let header = ELF_HEADER_SIZE;
    put_u32(&mut image, header, ELF_PROGRAM_TYPE_LOAD);
    put_u32(
        &mut image,
        header + 4,
        ELF_FLAG_EXECUTABLE | ELF_FLAG_READABLE,
    );
    put_u64(&mut image, header + 8, USER_INIT_CODE_OFFSET as u64);
    put_u64(&mut image, header + 16, USER_IMAGE_BASE);
    put_u64(&mut image, header + 24, USER_IMAGE_BASE);
    put_u64(&mut image, header + 32, USER_WORKER_CODE.len() as u64);
    put_u64(&mut image, header + 40, PAGE_SIZE);
    put_u64(&mut image, header + 48, PAGE_SIZE);

    let mut index = 0;
    while index < USER_WORKER_CODE.len() {
        image[USER_INIT_CODE_OFFSET + index] = USER_WORKER_CODE[index];
        index += 1;
    }
    image
}

#[cfg(not(target_os = "none"))]
pub const USER_WORKER_ELF: [u8; USER_WORKER_ELF_LENGTH] = build_user_worker_elf();

#[cfg(target_os = "none")]
use alloc::{boxed::Box, vec, vec::Vec};
#[cfg(target_os = "none")]
use bootloader_api::info::MemoryRegion;
#[cfg(target_os = "none")]
use core::arch::global_asm;
#[cfg(target_os = "none")]
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
#[cfg(target_os = "none")]
use spin::{Mutex, Once};
#[cfg(target_os = "none")]
use x86_64::registers::control::Cr3;
#[cfg(target_os = "none")]
use x86_64::registers::control::Cr3Flags;
#[cfg(target_os = "none")]
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
use x86_64::structures::paging::mapper::CleanUp;
#[cfg(target_os = "none")]
use x86_64::structures::paging::{
    FrameAllocator as PagingFrameAllocator, FrameDeallocator, Mapper, OffsetPageTable, Page,
    PageTable, PageTableFlags, PhysFrame, Size4KiB,
};
#[cfg(target_os = "none")]
use x86_64::structures::tss::TaskStateSegment;
#[cfg(target_os = "none")]
use x86_64::{PhysAddr, VirtAddr};

#[cfg(target_os = "none")]
// Network receive parses bounded Ethernet, IPv4, and UDP values before copying the result back
// into user memory. Keep enough per-process kernel stack for that nested path and its interrupt
// frame; the original 16 KiB stack could overwrite adjacent heap metadata.
const USER_KERNEL_STACK_SIZE: usize = 64 * 1024;
#[cfg(target_os = "none")]
const MAX_LOCAL_APIC_IDS: usize = 256;

#[cfg(target_os = "none")]
struct PerCpuAtomicU64 {
    values: [AtomicU64; MAX_LOCAL_APIC_IDS],
}

#[cfg(target_os = "none")]
impl PerCpuAtomicU64 {
    const fn new() -> Self {
        Self {
            values: [const { AtomicU64::new(0) }; MAX_LOCAL_APIC_IDS],
        }
    }

    fn current() -> usize {
        crate::apic::local_apic_id_u32()
            .and_then(|apic_id| usize::try_from(apic_id).ok())
            .filter(|apic_id| *apic_id < MAX_LOCAL_APIC_IDS)
            .unwrap_or(0)
    }

    fn load(&self, ordering: Ordering) -> u64 {
        self.values[Self::current()].load(ordering)
    }

    fn store(&self, value: u64, ordering: Ordering) {
        self.values[Self::current()].store(value, ordering);
    }
}

#[cfg(target_os = "none")]
static mut BOOT_USER_KERNEL_STACK: [u8; USER_KERNEL_STACK_SIZE] = [0; USER_KERNEL_STACK_SIZE];
#[cfg(target_os = "none")]
static USER_KERNEL_STACKS: [Once<Box<[u8]>>; MAX_LOCAL_APIC_IDS] =
    [const { Once::new() }; MAX_LOCAL_APIC_IDS];
#[cfg(target_os = "none")]
static KERNEL_CR3: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "none")]
static CURRENT_PROCESS_ID: PerCpuAtomicU64 = PerCpuAtomicU64::new();
#[cfg(target_os = "none")]
static CURRENT_THREAD_ID: PerCpuAtomicU64 = PerCpuAtomicU64::new();
#[cfg(target_os = "none")]
const PROCESS_TABLE_SIZE: usize = 16;
#[cfg(target_os = "none")]
static PROCESS_POINTERS: [AtomicU64; PROCESS_TABLE_SIZE] =
    [const { AtomicU64::new(0) }; PROCESS_TABLE_SIZE];
#[cfg(target_os = "none")]
static NEXT_PROCESS_ID: AtomicU64 = AtomicU64::new(2);
#[cfg(target_os = "none")]
static NEXT_ADDRESS_SPACE_ID: AtomicU64 = AtomicU64::new(1);
#[cfg(target_os = "none")]
const THREAD_TABLE_SIZE: usize = 16;
#[cfg(target_os = "none")]
static THREAD_POINTERS: [AtomicU64; THREAD_TABLE_SIZE] =
    [const { AtomicU64::new(0) }; THREAD_TABLE_SIZE];
#[cfg(target_os = "none")]
static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);
#[cfg(target_os = "none")]
static USER_TSS: [Once<TaskStateSegment>; MAX_LOCAL_APIC_IDS] =
    [const { Once::new() }; MAX_LOCAL_APIC_IDS];
#[cfg(target_os = "none")]
static USER_GDT: [Once<UserGdt>; MAX_LOCAL_APIC_IDS] = [const { Once::new() }; MAX_LOCAL_APIC_IDS];
#[cfg(target_os = "none")]
static PROCESS_FACTORY: Once<ProcessFactory> = Once::new();
#[cfg(target_os = "none")]
const MAX_FILESYSTEM_FILES: usize = 32;
#[cfg(target_os = "none")]
static FILE_CATALOG: Once<FileCatalog> = Once::new();
#[cfg(target_os = "none")]
const MAX_SNAPSHOT_LENGTH: usize = 4096;

#[cfg(target_os = "none")]
const INIT_EXECUTABLE_NAME: &str = "<builtin-init>";
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
struct FileImage {
    path: &'static [u8],
    name: &'static str,
    image: &'static [u8],
    mode: u32,
    executable: bool,
    persistent: bool,
}

#[cfg(target_os = "none")]
struct FileCatalog {
    entries: [Option<FileImage>; MAX_FILESYSTEM_FILES],
}

#[cfg(target_os = "none")]
pub struct FilesystemFile {
    pub path: Vec<u8>,
    pub image: Vec<u8>,
    pub mode: u32,
    pub persistent: bool,
}

#[cfg(target_os = "none")]
struct PendingExec {
    address_space: UserAddressSpace,
    name: &'static str,
}

#[cfg(target_os = "none")]
const MAX_PIPES: usize = 8;
#[cfg(target_os = "none")]
const PIPE_BUFFER_LENGTH: usize = 4096;

#[cfg(target_os = "none")]
struct PipeState {
    bytes: [u8; PIPE_BUFFER_LENGTH],
    head: usize,
    tail: usize,
    length: usize,
    readers: usize,
    writers: usize,
}

#[cfg(target_os = "none")]
impl PipeState {
    const fn new() -> Self {
        Self {
            bytes: [0; PIPE_BUFFER_LENGTH],
            head: 0,
            tail: 0,
            length: 0,
            readers: 1,
            writers: 1,
        }
    }

    fn read(&mut self, output: &mut [u8]) -> PipeReadResult {
        if self.length == 0 {
            return if self.writers == 0 {
                PipeReadResult::Eof
            } else {
                PipeReadResult::Empty
            };
        }
        let count = min(output.len(), self.length);
        for byte in output.iter_mut().take(count) {
            *byte = self.bytes[self.head];
            self.head = (self.head + 1) % PIPE_BUFFER_LENGTH;
        }
        self.length -= count;
        PipeReadResult::Data(count)
    }

    fn write(&mut self, input: &[u8]) -> PipeWriteResult {
        if self.readers == 0 {
            return PipeWriteResult::Closed;
        }
        let available = PIPE_BUFFER_LENGTH - self.length;
        if available == 0 {
            return PipeWriteResult::Full;
        }
        let count = min(input.len(), available);
        for &byte in input.iter().take(count) {
            self.bytes[self.tail] = byte;
            self.tail = (self.tail + 1) % PIPE_BUFFER_LENGTH;
        }
        self.length += count;
        PipeWriteResult::Data(count)
    }
}

#[cfg(target_os = "none")]
enum PipeReadResult {
    Data(usize),
    Empty,
    Eof,
    Closed,
}

#[cfg(target_os = "none")]
enum PipeWriteResult {
    Data(usize),
    Full,
    Closed,
}

#[cfg(target_os = "none")]
static PIPE_TABLE: [Mutex<Option<PipeState>>; MAX_PIPES] = [const { Mutex::new(None) }; MAX_PIPES];

#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
enum ProcessHandle {
    Console,
    Pipe {
        id: u8,
        readable: bool,
    },
    File {
        image: &'static [u8],
        path: &'static [u8],
        offset: usize,
        executable: bool,
        persistent: bool,
        writable: bool,
    },
    Disk {
        path: &'static [u8],
        offset: usize,
        size: usize,
        writable: bool,
    },
}

#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
enum FileHandleSnapshot {
    Pipe {
        id: u8,
        readable: bool,
    },
    Catalog {
        image: &'static [u8],
        path: &'static [u8],
        offset: usize,
        executable: bool,
        persistent: bool,
        writable: bool,
    },
    Disk {
        path: &'static [u8],
        offset: usize,
        size: usize,
        writable: bool,
    },
}

#[cfg(target_os = "none")]
fn retain_process_handle(handle: ProcessHandle) -> bool {
    let ProcessHandle::Pipe { id, readable } = handle else {
        return true;
    };
    let Some(slot) = PIPE_TABLE.get(usize::from(id)) else {
        return false;
    };
    let mut pipe = slot.lock();
    let Some(pipe) = pipe.as_mut() else {
        return false;
    };
    if readable {
        pipe.readers = pipe.readers.saturating_add(1);
    } else {
        pipe.writers = pipe.writers.saturating_add(1);
    }
    true
}

#[cfg(target_os = "none")]
fn release_process_handle(handle: ProcessHandle) {
    let ProcessHandle::Pipe { id, readable } = handle else {
        return;
    };
    let Some(slot) = PIPE_TABLE.get(usize::from(id)) else {
        return;
    };
    let mut pipe = slot.lock();
    let Some(pipe_state) = pipe.as_mut() else {
        return;
    };
    if readable {
        pipe_state.readers = pipe_state.readers.saturating_sub(1);
    } else {
        pipe_state.writers = pipe_state.writers.saturating_sub(1);
    }
    if pipe_state.readers == 0 && pipe_state.writers == 0 {
        *pipe = None;
    }
}

#[cfg(target_os = "none")]
fn allocate_pipe() -> Option<u8> {
    for (index, slot) in PIPE_TABLE.iter().enumerate() {
        let mut pipe = slot.lock();
        if pipe.is_none() {
            *pipe = Some(PipeState::new());
            return u8::try_from(index).ok();
        }
    }
    None
}

#[cfg(target_os = "none")]
fn release_pipe(id: u8) {
    if let Some(slot) = PIPE_TABLE.get(usize::from(id)) {
        *slot.lock() = None;
    }
}

#[cfg(target_os = "none")]
fn pipe_read(id: u8, output: &mut [u8]) -> PipeReadResult {
    let Some(slot) = PIPE_TABLE.get(usize::from(id)) else {
        return PipeReadResult::Closed;
    };
    let mut pipe = slot.lock();
    let Some(pipe) = pipe.as_mut() else {
        return PipeReadResult::Closed;
    };
    pipe.read(output)
}

#[cfg(target_os = "none")]
fn pipe_write(id: u8, input: &[u8]) -> PipeWriteResult {
    let Some(slot) = PIPE_TABLE.get(usize::from(id)) else {
        return PipeWriteResult::Closed;
    };
    let mut pipe = slot.lock();
    let Some(pipe) = pipe.as_mut() else {
        return PipeWriteResult::Closed;
    };
    pipe.write(input)
}

#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
struct ProcessHandleTable {
    entries: [Option<ProcessHandle>; MAX_PROCESS_HANDLES],
}

#[cfg(target_os = "none")]
impl ProcessHandleTable {
    const fn new() -> Self {
        let mut entries = [None; MAX_PROCESS_HANDLES];
        entries[USER_STDIN_FD as usize] = Some(ProcessHandle::Console);
        entries[USER_STDOUT_FD as usize] = Some(ProcessHandle::Console);
        Self { entries }
    }

    fn duplicate(&self) -> Self {
        let duplicate = *self;
        for handle in duplicate.entries.iter().flatten().copied() {
            let _ = retain_process_handle(handle);
        }
        duplicate
    }

    fn redirected(&self, stdin_fd: u64, stdout_fd: u64) -> Result<Self, SpawnError> {
        let mut redirected = Self::new();
        for (target, source) in [(USER_STDIN_FD, stdin_fd), (USER_STDOUT_FD, stdout_fd)] {
            if source == SPAWN_INHERIT_FD {
                continue;
            }
            let handle = if source == SPAWN_INHERIT_PARENT_FD {
                self.entries[target as usize]
            } else {
                let Ok(index) = usize::try_from(source) else {
                    redirected.release_all();
                    return Err(SpawnError::InvalidHandle);
                };
                self.entries.get(index).and_then(|entry| *entry)
            };
            let Some(handle) = handle else {
                redirected.release_all();
                return Err(SpawnError::InvalidHandle);
            };
            if !retain_process_handle(handle) {
                redirected.release_all();
                return Err(SpawnError::InvalidHandle);
            }
            redirected.entries[target as usize] = Some(handle);
        }
        Ok(redirected)
    }

    fn release_all(&mut self) {
        for entry in &mut self.entries {
            if let Some(handle) = entry.take() {
                release_process_handle(handle);
            }
        }
    }
}

#[cfg(target_os = "none")]
struct ProcessFactory {
    physical_memory_offset: u64,
    regions: &'static [MemoryRegion],
    frame_allocator: Mutex<ProcessFrameAllocatorState>,
}

#[cfg(target_os = "none")]
struct ProcessFrameAllocatorState {
    next_frame_address: Option<u64>,
    recycled_frames: Vec<PhysFrame<Size4KiB>>,
}

#[cfg(target_os = "none")]
global_asm!(
    r#"
    .section .text.rustos_user_transition,"ax"
    .global rustos_enter_user
rustos_enter_user:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r10, [rsp + 56]
    mov [r9], rsp
    mov cr3, rdi
    mov rax, 0x202
    push rdx
    push rcx
    push rax
    push rsi
    push r8
    mov rdi, r10
    iretq

    .global rustos_leave_user
rustos_leave_user:
    mov cr3, rdi
    mov rsp, [rsi]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

    .global rustos_enter_user_context
rustos_enter_user_context:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r10, rsi
    mov [rdx], rsp
    mov cr3, rdi

    mov rax, [r10 + 0]
    mov rbx, [r10 + 8]
    mov rcx, [r10 + 16]
    mov rdx, [r10 + 24]
    mov rsi, [r10 + 32]
    mov rdi, [r10 + 40]
    mov rbp, [r10 + 48]
    mov r8, [r10 + 56]
    mov r9, [r10 + 64]
    mov r12, [r10 + 88]
    mov r13, [r10 + 96]
    mov r14, [r10 + 104]
    mov r15, [r10 + 112]
    push qword ptr [r10 + 152]
    push qword ptr [r10 + 144]
    push qword ptr [r10 + 136]
    push qword ptr [r10 + 128]
    push qword ptr [r10 + 120]
    mov r11, [r10 + 80]
    mov r10, [r10 + 72]
    iretq

    .global rustos_syscall_entry
rustos_syscall_entry:
    cld
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
    mov rdi, rsp
    call rustos_user_syscall_dispatch
    test rax, rax
    jnz rustos_syscall_exit
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    iretq

rustos_syscall_exit:
    call rustos_user_process_exit
    ud2
    "#
);

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn rustos_syscall_entry();
    fn rustos_enter_user(
        root_frame: u64,
        user_code: u64,
        user_data: u64,
        user_stack: u64,
        entry: u64,
        return_stack_slot: *const AtomicU64,
        user_argument: u64,
    );
    fn rustos_enter_user_context(
        root_frame: u64,
        context: *const ForkContext,
        return_stack_slot: *const AtomicU64,
    );
    fn rustos_leave_user(kernel_frame: u64, return_stack_slot: *const AtomicU64) -> !;
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpaceError {
    Elf(ElfError),
    OutOfFrames,
    RootSlotInUse,
    PhysicalAddressOverflow,
    MappingFailed { page: u64 },
    SegmentPageMissing { page: u64 },
    InvalidMappingLength,
    MappingRangeExhausted,
    MappingLimit,
    NotAnonymousMapping { page: u64 },
    ModeNotInitialized,
    UserDidNotExit,
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserMemoryError {
    InvalidAddress,
    Unmapped { page: u64 },
    ReadOnly { page: u64 },
    Unterminated,
}

#[cfg(target_os = "none")]
pub struct UserAddressSpace {
    mapper: OffsetPageTable<'static>,
    physical_memory_offset: u64,
    root_frame: PhysFrame<Size4KiB>,
    address_space_id: u64,
    entry: u64,
    stack_top: u64,
    next_frame_address: Option<u64>,
    next_mmap_address: u64,
    free_mmap_ranges: Vec<FreeMmapRange>,
    mappings: Vec<UserMapping>,
    reclaimed: bool,
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy)]
struct UserMapping {
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    writable: bool,
    executable: bool,
    anonymous: bool,
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy)]
struct FreeMmapRange {
    start: u64,
    length: u64,
}

#[cfg(target_os = "none")]
struct FrameReclaimer<'a> {
    recycled_frames: &'a mut Vec<PhysFrame<Size4KiB>>,
}

#[cfg(target_os = "none")]
impl FrameDeallocator<Size4KiB> for FrameReclaimer<'_> {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        self.recycled_frames.push(frame);
    }
}

#[cfg(target_os = "none")]
impl UserAddressSpace {
    fn load_elf(
        physical_memory_offset: u64,
        frame_allocator: &mut UserFrameAllocator<'_>,
        image: &[u8],
    ) -> Result<Self, AddressSpaceError> {
        let elf = parse_elf64(image).map_err(AddressSpaceError::Elf)?;
        let physical_memory_offset = VirtAddr::new(physical_memory_offset);
        let address_space_id = NEXT_ADDRESS_SPACE_ID.fetch_add(1, Ordering::AcqRel);
        let root_frame = frame_allocator
            .allocate_leaf_frame()
            .ok_or(AddressSpaceError::OutOfFrames)?;
        let root_address = physical_memory_offset
            .as_u64()
            .checked_add(root_frame.start_address().as_u64())
            .ok_or(AddressSpaceError::PhysicalAddressOverflow)?;
        let root = unsafe { &mut *(root_address as *mut PageTable) };
        {
            // User processes can be created from a syscall while another user root is active, so
            // copy the supervisor mapping template from the saved kernel root instead of CR3.
            let kernel_root = unsafe { kernel_level_4_table(physical_memory_offset) };
            if !kernel_root[USER_L4_INDEX].is_unused() {
                return Err(AddressSpaceError::RootSlotInUse);
            }
            root.zero();
            for index in 0..512 {
                if index != USER_L4_INDEX {
                    root[index] = kernel_root[index].clone();
                }
            }
        }
        let mapper = unsafe { OffsetPageTable::new(root, physical_memory_offset) };
        let mut address_space = Self {
            mapper,
            physical_memory_offset: physical_memory_offset.as_u64(),
            root_frame,
            address_space_id,
            entry: elf.entry,
            stack_top: USER_STACK_TOP,
            next_frame_address: None,
            next_mmap_address: USER_MMAP_START,
            free_mmap_ranges: Vec::new(),
            mappings: Vec::new(),
            reclaimed: false,
        };

        for segment in elf.segments() {
            address_space.map_segment(*segment, frame_allocator)?;
        }
        address_space.map_stack(frame_allocator)?;
        address_space.map_thread_stacks(frame_allocator)?;
        address_space.copy_segments(image, elf.segments(), physical_memory_offset)?;
        address_space.next_frame_address = advance_frame_address(
            address_space.next_frame_address,
            frame_allocator.next_available_address(),
        );
        Ok(address_space)
    }

    fn clone_for_fork(
        &self,
        frame_allocator: &mut UserFrameAllocator<'_>,
    ) -> Result<Self, AddressSpaceError> {
        let physical_memory_offset = VirtAddr::new(self.physical_memory_offset);
        let address_space_id = NEXT_ADDRESS_SPACE_ID.fetch_add(1, Ordering::AcqRel);
        let root_frame = frame_allocator
            .allocate_leaf_frame()
            .ok_or(AddressSpaceError::OutOfFrames)?;
        let root_address = physical_memory_offset
            .as_u64()
            .checked_add(root_frame.start_address().as_u64())
            .ok_or(AddressSpaceError::PhysicalAddressOverflow)?;
        let root = unsafe { &mut *(root_address as *mut PageTable) };
        {
            let kernel_root = unsafe { kernel_level_4_table(physical_memory_offset) };
            if !kernel_root[USER_L4_INDEX].is_unused() {
                return Err(AddressSpaceError::RootSlotInUse);
            }
            root.zero();
            for index in 0..512 {
                if index != USER_L4_INDEX {
                    root[index] = kernel_root[index].clone();
                }
            }
        }
        let mapper = unsafe { OffsetPageTable::new(root, physical_memory_offset) };
        let mut clone = Self {
            mapper,
            physical_memory_offset: physical_memory_offset.as_u64(),
            root_frame,
            address_space_id,
            entry: self.entry,
            stack_top: self.stack_top,
            next_frame_address: None,
            next_mmap_address: self.next_mmap_address,
            free_mmap_ranges: self.free_mmap_ranges.clone(),
            mappings: Vec::with_capacity(self.mappings.len()),
            reclaimed: false,
        };

        for mapping in self.mappings.iter().copied() {
            let frame = frame_allocator
                .allocate_leaf_frame()
                .ok_or(AddressSpaceError::OutOfFrames)?;
            let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
            if mapping.writable {
                flags |= PageTableFlags::WRITABLE;
            }
            if !mapping.executable {
                flags |= PageTableFlags::NO_EXECUTE;
            }
            let flush = unsafe {
                let mut page_table_allocator = frame_allocator.page_table_allocator();
                clone
                    .mapper
                    .map_to(mapping.page, frame, flags, &mut page_table_allocator)
                    .map_err(|_| AddressSpaceError::MappingFailed {
                        page: mapping.page.start_address().as_u64(),
                    })?
            };
            flush.flush();
            let source = physical_memory_offset
                .as_u64()
                .checked_add(mapping.frame.start_address().as_u64())
                .ok_or(AddressSpaceError::PhysicalAddressOverflow)?;
            let destination = physical_memory_offset
                .as_u64()
                .checked_add(frame.start_address().as_u64())
                .ok_or(AddressSpaceError::PhysicalAddressOverflow)?;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source as *const u8,
                    destination as *mut u8,
                    PAGE_SIZE as usize,
                );
            }
            clone.mappings.push(UserMapping {
                page: mapping.page,
                frame,
                writable: mapping.writable,
                executable: mapping.executable,
                anonymous: mapping.anonymous,
            });
        }
        clone.next_frame_address = advance_frame_address(
            clone.next_frame_address,
            frame_allocator.next_available_address(),
        );
        Ok(clone)
    }

    pub fn root_frame(&self) -> PhysFrame<Size4KiB> {
        self.root_frame
    }

    pub fn address_space_id(&self) -> u64 {
        self.address_space_id
    }

    pub fn entry(&self) -> u64 {
        self.entry
    }

    pub fn stack_top(&self) -> u64 {
        self.stack_top
    }

    pub fn next_frame_address(&self) -> Option<u64> {
        self.next_frame_address
    }

    fn reclaim(&mut self, recycled_frames: &mut Vec<PhysFrame<Size4KiB>>) -> usize {
        if self.reclaimed {
            return 0;
        }

        let recycled_before = recycled_frames.len();
        let mappings = core::mem::take(&mut self.mappings);
        for mapping in mappings {
            if let Ok((frame, flush)) = self.mapper.unmap(mapping.page) {
                flush.flush();
                recycled_frames.push(frame);
            }
        }
        self.free_mmap_ranges.clear();

        let start_page = Page::containing_address(VirtAddr::new(USER_IMAGE_BASE));
        let end_page = Page::containing_address(VirtAddr::new(USER_SPACE_END - PAGE_SIZE));
        let mut deallocator = FrameReclaimer { recycled_frames };
        // The user L4 entry is private to this address space. The other root entries are shared
        // supervisor mappings, so cleanup is deliberately limited to the user virtual range.
        unsafe {
            self.mapper.clean_up_addr_range(
                Page::range_inclusive(start_page, end_page),
                &mut deallocator,
            );
        }
        deallocator.recycled_frames.push(self.root_frame);
        self.reclaimed = true;
        self.next_frame_address = None;
        deallocator.recycled_frames.len() - recycled_before
    }

    pub fn executable_pages(&self) -> usize {
        self.mappings
            .iter()
            .filter(|mapping| mapping.executable)
            .count()
    }

    pub fn thread_stack_top(&self, slot: usize) -> Option<u64> {
        if slot >= MAX_USER_THREADS_PER_PROCESS {
            return None;
        }
        let stack_pages_before =
            USER_STACK_PAGE_COUNT.checked_add((slot as u64 + 1) * USER_THREAD_STACK_PAGE_COUNT)?;
        USER_STACK_TOP.checked_sub(stack_pages_before * PAGE_SIZE)
    }

    fn map_anonymous(
        &mut self,
        frame_allocator: &mut UserFrameAllocator<'_>,
        length: u64,
        writable: bool,
    ) -> Result<u64, AddressSpaceError> {
        let length = round_mapping_length(length)?;
        let page_count = length / PAGE_SIZE;
        let page_count_usize =
            usize::try_from(page_count).map_err(|_| AddressSpaceError::MappingLimit)?;
        if self.mappings.len().saturating_add(page_count_usize) > MAX_USER_MAPPINGS {
            return Err(AddressSpaceError::MappingLimit);
        }
        let start = self
            .take_mmap_range(length)
            .ok_or(AddressSpaceError::MappingRangeExhausted)?;
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE
            | if writable {
                PageTableFlags::WRITABLE
            } else {
                PageTableFlags::empty()
            };
        for index in 0..page_count {
            let page = Page::containing_address(VirtAddr::new(start + index * PAGE_SIZE));
            let frame = match frame_allocator.allocate_leaf_frame() {
                Some(frame) => frame,
                None => {
                    self.rollback_anonymous_mapping(start, index, frame_allocator);
                    self.free_mmap_ranges.push(FreeMmapRange { start, length });
                    return Err(AddressSpaceError::OutOfFrames);
                }
            };
            let flush = match unsafe {
                let mut page_table_allocator = frame_allocator.page_table_allocator();
                self.mapper
                    .map_to(page, frame, flags, &mut page_table_allocator)
            } {
                Ok(flush) => flush,
                Err(_) => {
                    frame_allocator.recycle_frame(frame);
                    self.rollback_anonymous_mapping(start, index, frame_allocator);
                    self.free_mmap_ranges.push(FreeMmapRange { start, length });
                    return Err(AddressSpaceError::MappingFailed {
                        page: page.start_address().as_u64(),
                    });
                }
            };
            flush.flush();
            unsafe { zero_frame(frame, self.mapper_offset()) };
            self.mappings.push(UserMapping {
                page,
                frame,
                writable,
                executable: false,
                anonymous: true,
            });
        }
        self.next_frame_address = advance_frame_address(
            self.next_frame_address,
            frame_allocator.next_available_address(),
        );
        Ok(start)
    }

    fn unmap_anonymous(
        &mut self,
        address: u64,
        length: u64,
    ) -> Result<Vec<PhysFrame<Size4KiB>>, AddressSpaceError> {
        if address % PAGE_SIZE != 0 {
            return Err(AddressSpaceError::InvalidMappingLength);
        }
        let length = round_mapping_length(length)?;
        let end = address
            .checked_add(length)
            .ok_or(AddressSpaceError::InvalidMappingLength)?;
        if address < USER_MMAP_START || end > USER_MMAP_END {
            return Err(AddressSpaceError::InvalidMappingLength);
        }
        let page_count =
            usize::try_from(length / PAGE_SIZE).map_err(|_| AddressSpaceError::MappingLimit)?;
        let mut released_frames = Vec::with_capacity(page_count);
        for index in 0..page_count {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                address + index as u64 * PAGE_SIZE,
            ));
            let Some(mapping) = self.mappings.iter().find(|mapping| mapping.page == page) else {
                return Err(AddressSpaceError::NotAnonymousMapping {
                    page: page.start_address().as_u64(),
                });
            };
            if !mapping.anonymous {
                return Err(AddressSpaceError::NotAnonymousMapping {
                    page: page.start_address().as_u64(),
                });
            }
            released_frames.push(mapping.frame);
        }
        for index in 0..page_count {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                address + index as u64 * PAGE_SIZE,
            ));
            let (_, flush) =
                self.mapper
                    .unmap(page)
                    .map_err(|_| AddressSpaceError::MappingFailed {
                        page: page.start_address().as_u64(),
                    })?;
            flush.flush();
        }
        self.mappings.retain(|mapping| {
            let page = mapping.page.start_address().as_u64();
            !(mapping.anonymous && address <= page && page < end)
        });
        self.free_mmap_ranges.push(FreeMmapRange {
            start: address,
            length,
        });
        Ok(released_frames)
    }

    fn take_mmap_range(&mut self, length: u64) -> Option<u64> {
        if let Some(index) = self
            .free_mmap_ranges
            .iter()
            .position(|range| range.length >= length)
        {
            let range = self.free_mmap_ranges[index];
            if range.length == length {
                self.free_mmap_ranges.swap_remove(index);
            } else {
                self.free_mmap_ranges[index].start = range.start + length;
                self.free_mmap_ranges[index].length = range.length - length;
            }
            return Some(range.start);
        }
        let end = self.next_mmap_address.checked_add(length)?;
        if end > USER_MMAP_END {
            return None;
        }
        let start = self.next_mmap_address;
        self.next_mmap_address = end;
        Some(start)
    }

    fn rollback_anonymous_mapping(
        &mut self,
        start: u64,
        page_count: u64,
        frame_allocator: &mut UserFrameAllocator<'_>,
    ) {
        for index in 0..page_count {
            let page =
                Page::<Size4KiB>::containing_address(VirtAddr::new(start + index * PAGE_SIZE));
            if let Ok((_, flush)) = self.mapper.unmap(page) {
                flush.flush();
            }
        }
        let end = start + page_count * PAGE_SIZE;
        self.mappings.retain(|mapping| {
            let page = mapping.page.start_address().as_u64();
            if mapping.anonymous && start <= page && page < end {
                frame_allocator.recycle_frame(mapping.frame);
                false
            } else {
                true
            }
        });
    }

    fn is_executable_address(&self, address: u64) -> bool {
        if !(USER_IMAGE_BASE..USER_SPACE_END).contains(&address) {
            return false;
        }
        let page = Page::containing_address(VirtAddr::new(address));
        self.mappings
            .iter()
            .any(|mapping| mapping.page == page && mapping.executable)
    }

    fn read_user_byte(&self, address: u64) -> Result<u8, UserMemoryError> {
        if !(USER_IMAGE_BASE..USER_SPACE_END).contains(&address) {
            return Err(UserMemoryError::InvalidAddress);
        }
        let page = Page::containing_address(VirtAddr::new(address));
        if !self.mappings.iter().any(|mapping| mapping.page == page) {
            return Err(UserMemoryError::Unmapped {
                page: page.start_address().as_u64(),
            });
        }
        // Syscalls run with this address space's CR3 active. The range and mapping checks above
        // keep the byte read inside a user-accessible page owned by the current process.
        Ok(unsafe { core::ptr::read_volatile(address as *const u8) })
    }

    fn copy_user_bytes(&self, address: u64, buffer: &mut [u8]) -> Result<(), UserMemoryError> {
        for (index, byte) in buffer.iter_mut().enumerate() {
            let current = address
                .checked_add(index as u64)
                .ok_or(UserMemoryError::InvalidAddress)?;
            *byte = self.read_user_byte(current)?;
        }
        Ok(())
    }

    fn copy_to_user_bytes(&self, address: u64, buffer: &[u8]) -> Result<(), UserMemoryError> {
        for (index, &byte) in buffer.iter().enumerate() {
            let current = address
                .checked_add(index as u64)
                .ok_or(UserMemoryError::InvalidAddress)?;
            if !(USER_IMAGE_BASE..USER_SPACE_END).contains(&current) {
                return Err(UserMemoryError::InvalidAddress);
            }
            let page = Page::containing_address(VirtAddr::new(current));
            let mapping = self
                .mappings
                .iter()
                .find(|mapping| mapping.page == page)
                .ok_or(UserMemoryError::Unmapped {
                    page: page.start_address().as_u64(),
                })?;
            if !mapping.writable {
                return Err(UserMemoryError::ReadOnly {
                    page: page.start_address().as_u64(),
                });
            }
            // Syscalls run with this address space's CR3 active. The range, mapping, and writable
            // checks above keep the write inside a writable user page owned by this process.
            unsafe { core::ptr::write_volatile(current as *mut u8, byte) };
        }
        Ok(())
    }

    fn copy_user_string(&self, address: u64, buffer: &mut [u8]) -> Result<usize, UserMemoryError> {
        for (index, byte) in buffer.iter_mut().enumerate() {
            let current = address
                .checked_add(index as u64)
                .ok_or(UserMemoryError::InvalidAddress)?;
            *byte = self.read_user_byte(current)?;
            if *byte == 0 {
                return Ok(index);
            }
        }
        Err(UserMemoryError::Unterminated)
    }

    fn map_segment(
        &mut self,
        segment: ElfLoadSegment,
        frame_allocator: &mut UserFrameAllocator<'_>,
    ) -> Result<(), AddressSpaceError> {
        let start = segment.virtual_address & !(PAGE_SIZE - 1);
        let end = segment
            .end_address()
            .ok_or(AddressSpaceError::SegmentPageMissing { page: start })?
            - 1;
        let page_count = (end - start) / PAGE_SIZE + 1;
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if segment.flags & ELF_FLAG_WRITABLE != 0 {
            flags |= PageTableFlags::WRITABLE;
        }
        if segment.flags & ELF_FLAG_EXECUTABLE == 0 {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        for index in 0..page_count {
            let page = Page::containing_address(VirtAddr::new(start + index * PAGE_SIZE));
            let frame = frame_allocator
                .allocate_leaf_frame()
                .ok_or(AddressSpaceError::OutOfFrames)?;
            let flush = unsafe {
                let mut page_table_allocator = frame_allocator.page_table_allocator();
                self.mapper
                    .map_to(page, frame, flags, &mut page_table_allocator)
                    .map_err(|_| AddressSpaceError::MappingFailed {
                        page: page.start_address().as_u64(),
                    })?
            };
            flush.flush();
            unsafe { zero_frame(frame, self.mapper_offset()) };
            self.mappings.push(UserMapping {
                page,
                frame,
                writable: segment.flags & ELF_FLAG_WRITABLE != 0,
                executable: segment.flags & ELF_FLAG_EXECUTABLE != 0,
                anonymous: false,
            });
        }
        Ok(())
    }

    fn map_stack(
        &mut self,
        frame_allocator: &mut UserFrameAllocator<'_>,
    ) -> Result<(), AddressSpaceError> {
        let start = USER_STACK_TOP - USER_STACK_PAGE_COUNT * PAGE_SIZE;
        for index in 0..USER_STACK_PAGE_COUNT {
            let page = Page::containing_address(VirtAddr::new(start + index * PAGE_SIZE));
            let frame = frame_allocator
                .allocate_leaf_frame()
                .ok_or(AddressSpaceError::OutOfFrames)?;
            let flags = PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::NO_EXECUTE;
            let flush = unsafe {
                let mut page_table_allocator = frame_allocator.page_table_allocator();
                self.mapper
                    .map_to(page, frame, flags, &mut page_table_allocator)
                    .map_err(|_| AddressSpaceError::MappingFailed {
                        page: page.start_address().as_u64(),
                    })?
            };
            flush.flush();
            unsafe { zero_frame(frame, self.mapper_offset()) };
            self.mappings.push(UserMapping {
                page,
                frame,
                writable: true,
                executable: false,
                anonymous: false,
            });
        }
        Ok(())
    }

    fn map_thread_stacks(
        &mut self,
        frame_allocator: &mut UserFrameAllocator<'_>,
    ) -> Result<(), AddressSpaceError> {
        for slot in 0..MAX_USER_THREADS_PER_PROCESS {
            let stack_top = self
                .thread_stack_top(slot)
                .ok_or(AddressSpaceError::SegmentPageMissing { page: 0 })?;
            let start = stack_top
                .checked_sub(USER_THREAD_STACK_PAGE_COUNT * PAGE_SIZE)
                .ok_or(AddressSpaceError::SegmentPageMissing { page: stack_top })?;
            for index in 0..USER_THREAD_STACK_PAGE_COUNT {
                let page = Page::containing_address(VirtAddr::new(start + index * PAGE_SIZE));
                let frame = frame_allocator
                    .allocate_leaf_frame()
                    .ok_or(AddressSpaceError::OutOfFrames)?;
                let flags = PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::NO_EXECUTE;
                let flush = unsafe {
                    let mut page_table_allocator = frame_allocator.page_table_allocator();
                    self.mapper
                        .map_to(page, frame, flags, &mut page_table_allocator)
                        .map_err(|_| AddressSpaceError::MappingFailed {
                            page: page.start_address().as_u64(),
                        })?
                };
                flush.flush();
                unsafe { zero_frame(frame, self.mapper_offset()) };
                self.mappings.push(UserMapping {
                    page,
                    frame,
                    writable: true,
                    executable: false,
                    anonymous: false,
                });
            }
        }
        Ok(())
    }

    fn copy_segments(
        &self,
        image: &[u8],
        segments: &[ElfLoadSegment],
        physical_memory_offset: VirtAddr,
    ) -> Result<(), AddressSpaceError> {
        for segment in segments.iter().copied() {
            let mut copied = 0;
            while copied < segment.file_size {
                let virtual_address = segment.virtual_address + copied;
                let page = Page::containing_address(VirtAddr::new(virtual_address));
                let mapping = self
                    .mappings
                    .iter()
                    .find(|mapping| mapping.page == page)
                    .ok_or(AddressSpaceError::SegmentPageMissing {
                        page: page.start_address().as_u64(),
                    })?;
                let page_offset = virtual_address % PAGE_SIZE;
                let count = min(PAGE_SIZE - page_offset, segment.file_size - copied);
                let source_offset =
                    usize::try_from(segment.file_offset + copied).map_err(|_| {
                        AddressSpaceError::SegmentPageMissing {
                            page: page.start_address().as_u64(),
                        }
                    })?;
                let destination = physical_memory_offset
                    .as_u64()
                    .checked_add(mapping.frame.start_address().as_u64())
                    .and_then(|address| address.checked_add(page_offset))
                    .ok_or(AddressSpaceError::PhysicalAddressOverflow)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        image.as_ptr().add(source_offset),
                        destination as *mut u8,
                        count as usize,
                    );
                }
                copied += count;
            }
        }
        Ok(())
    }

    fn mapper_offset(&self) -> u64 {
        self.physical_memory_offset
    }
}

#[cfg(target_os = "none")]
fn round_mapping_length(length: u64) -> Result<u64, AddressSpaceError> {
    if length == 0 {
        return Err(AddressSpaceError::InvalidMappingLength);
    }
    let rounded = length
        .checked_add(PAGE_SIZE - 1)
        .ok_or(AddressSpaceError::InvalidMappingLength)?
        & !(PAGE_SIZE - 1);
    let pages = rounded / PAGE_SIZE;
    if pages == 0 || pages > MAX_ANONYMOUS_MMAP_PAGES {
        return Err(AddressSpaceError::InvalidMappingLength);
    }
    Ok(rounded)
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessRegistryError {
    InvalidProcessId,
    ProcessAlreadyRegistered,
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnImageError {
    AlreadyInstalled,
    TooManyFiles { max_files: usize },
    InvalidPath,
    DuplicatePath,
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    ImageNotInstalled,
    ExecutableNotFound,
    InvalidHandle,
    ProcessTableFull,
    AddressSpace(AddressSpaceError),
    Registry(ProcessRegistryError),
    Scheduler(crate::scheduler::SchedulerError),
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeProcessStats {
    pub pid: ProcessId,
    pub parent_pid: ProcessId,
    pub uid: UserId,
    pub gid: GroupId,
    pub origin: &'static str,
    pub executable: &'static str,
    pub state: ProcessState,
    pub root_frame: u64,
    pub address_space_id: u64,
    pub address_space_reclaimed: bool,
    pub entry: u64,
    pub exec_count: u64,
    pub fork_count: u64,
    pub syscall_count: u64,
    pub open_count: u64,
    pub read_count: u64,
    pub read_bytes: u64,
    pub data_read_count: u64,
    pub close_count: u64,
    pub file_write_count: u64,
    pub file_write_bytes: u64,
    pub file_create_count: u64,
    pub process_snapshot_count: u64,
    pub file_snapshot_count: u64,
    pub yield_count: u64,
    pub wait_count: u64,
    pub wait_status_count: u64,
    pub nonzero_wait_statuses: u64,
    pub last_wait_status: u64,
    pub wait_blocks: u64,
    pub thread_create_count: u64,
    pub thread_join_count: u64,
    pub last_return_result: u64,
    pub task_switches: u64,
    pub last_cpu_apic_id: u32,
    pub exit_code: Option<i64>,
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeThreadStats {
    pub tid: ThreadId,
    pub pid: ProcessId,
    pub state: ProcessState,
    pub entry: u64,
    pub stack_top: u64,
    pub syscall_count: u64,
    pub yield_count: u64,
    pub task_switches: u64,
    pub exit_code: Option<i64>,
}

#[cfg(target_os = "none")]
struct Thread {
    tid: ThreadId,
    pid: ProcessId,
    entry: u64,
    argument: u64,
    stack_top: u64,
    kernel_stack: Box<[u8]>,
    return_stack: AtomicU64,
    state: AtomicU8,
    syscall_count: AtomicU64,
    yield_count: AtomicU64,
    task_switches: AtomicU64,
    exit_code: AtomicU64,
    exit_requested: AtomicBool,
    last_return_result: AtomicU64,
}

#[cfg(target_os = "none")]
impl Thread {
    fn new(tid: ThreadId, pid: ProcessId, entry: u64, argument: u64, stack_top: u64) -> Self {
        Self {
            tid,
            pid,
            entry,
            argument,
            stack_top,
            kernel_stack: vec![0; USER_KERNEL_STACK_SIZE].into_boxed_slice(),
            return_stack: AtomicU64::new(0),
            state: AtomicU8::new(ProcessState::Ready as u8),
            syscall_count: AtomicU64::new(0),
            yield_count: AtomicU64::new(0),
            task_switches: AtomicU64::new(0),
            exit_code: AtomicU64::new(0),
            exit_requested: AtomicBool::new(false),
            last_return_result: AtomicU64::new(0),
        }
    }

    fn state(&self) -> ProcessState {
        ProcessState::from_raw(self.state.load(Ordering::Acquire))
    }

    fn kernel_stack_top(&self) -> u64 {
        (self.kernel_stack.as_ptr() as u64 + USER_KERNEL_STACK_SIZE as u64) & !0xf
    }

    fn exit_code(&self) -> Option<i64> {
        self.exit_requested
            .load(Ordering::Acquire)
            .then(|| self.exit_code.load(Ordering::Acquire) as i64)
    }

    fn record_syscall(&self, frame: &SyscallFrame, action: SyscallAction) {
        self.syscall_count.fetch_add(1, Ordering::AcqRel);
        match action {
            SyscallAction::Return => {
                self.last_return_result.store(frame.rax, Ordering::Release);
            }
            SyscallAction::Yield => {
                self.last_return_result.store(frame.rax, Ordering::Release);
                self.yield_count.fetch_add(1, Ordering::AcqRel);
            }
            SyscallAction::Exit | SyscallAction::ThreadExit => {
                self.exit_code.store(frame.rdi, Ordering::Release);
                self.exit_requested.store(true, Ordering::Release);
            }
            SyscallAction::Spawn
            | SyscallAction::SpawnAs
            | SyscallAction::SpawnPrivileged
            | SyscallAction::GetCredentials
            | SyscallAction::Wait
            | SyscallAction::WaitpidNonblocking
            | SyscallAction::Write
            | SyscallAction::Open
            | SyscallAction::Read
            | SyscallAction::ReadNonblocking
            | SyscallAction::Close
            | SyscallAction::ThreadCreate
            | SyscallAction::ThreadJoin
            | SyscallAction::Exec
            | SyscallAction::Fork
            | SyscallAction::ListProcesses
            | SyscallAction::ListFiles
            | SyscallAction::Mkdir
            | SyscallAction::PathInfo
            | SyscallAction::Mmap
            | SyscallAction::Munmap
            | SyscallAction::NetSend
            | SyscallAction::NetReceive
            | SyscallAction::NetInfo
            | SyscallAction::NetInterfaces
            | SyscallAction::NetRenew
            | SyscallAction::GfxInfo
            | SyscallAction::GfxAcquire
            | SyscallAction::GfxFillRect
            | SyscallAction::GfxText
            | SyscallAction::GfxRelease
            | SyscallAction::InputRead
            | SyscallAction::GfxWindowCreate
            | SyscallAction::GfxWindowClear
            | SyscallAction::GfxWindowFillRect
            | SyscallAction::GfxWindowText
            | SyscallAction::GfxWindowPresent
            | SyscallAction::GfxWindowFocus
            | SyscallAction::GfxWindowDestroy
            | SyscallAction::GfxComposeWindows
            | SyscallAction::GfxWindowDispatchPointer
            | SyscallAction::GfxWindowReadEvent
            | SyscallAction::GfxWindowDispatchKeyboard
            | SyscallAction::GfxWindowGetGeometry
            | SyscallAction::GfxWindowConfigure
            | SyscallAction::GfxWindowRequestClose
            | SyscallAction::Poweroff
            | SyscallAction::Reboot
            | SyscallAction::Suspend
            | SyscallAction::Pipe => {}
        }
    }

    fn note_task_switch(&self) {
        self.task_switches.fetch_add(1, Ordering::AcqRel);
    }

    fn run(&self, process: &Process) -> Result<ProcessExit, AddressSpaceError> {
        self.state
            .store(ProcessState::Running as u8, Ordering::Release);
        let _ = crate::scheduler::set_thread_state(self.tid, ProcessState::Running);
        CURRENT_PROCESS_ID.store(u64::from(self.pid), Ordering::Release);
        CURRENT_THREAD_ID.store(u64::from(self.tid), Ordering::Release);
        let result = run_user_context(
            &process.address_space,
            self.entry,
            self.stack_top,
            &self.return_stack,
            self.argument,
        );
        match result.and_then(|()| {
            self.exit_code()
                .map(|code| ProcessExit {
                    code,
                    syscalls: self.syscall_count.load(Ordering::Acquire),
                })
                .ok_or(AddressSpaceError::UserDidNotExit)
        }) {
            Ok(exit) => {
                self.state
                    .store(ProcessState::Exited as u8, Ordering::Release);
                wake_thread_waiter(self.pid, self.tid);
                let _ = crate::scheduler::set_thread_state(self.tid, ProcessState::Exited);
                Ok(exit)
            }
            Err(error) => {
                self.state
                    .store(ProcessState::Faulted as u8, Ordering::Release);
                wake_thread_waiter(self.pid, self.tid);
                let _ = crate::scheduler::set_thread_state(self.tid, ProcessState::Faulted);
                Err(error)
            }
        }
    }
}

#[cfg(target_os = "none")]
pub struct Process {
    pid: ProcessId,
    parent_pid: ProcessId,
    uid: UserId,
    gid: GroupId,
    origin: &'static str,
    executable: &'static str,
    address_space: UserAddressSpace,
    pending_exec: Mutex<Option<PendingExec>>,
    fork_context: Mutex<Option<ForkContext>>,
    handles: Mutex<ProcessHandleTable>,
    kernel_stack: Box<[u8]>,
    return_stack: AtomicU64,
    state: AtomicU8,
    address_space_reclaimed: AtomicBool,
    syscall_count: AtomicU64,
    open_count: AtomicU64,
    read_count: AtomicU64,
    read_bytes: AtomicU64,
    data_read_count: AtomicU64,
    close_count: AtomicU64,
    file_write_count: AtomicU64,
    file_write_bytes: AtomicU64,
    file_create_count: AtomicU64,
    process_snapshot_count: AtomicU64,
    file_snapshot_count: AtomicU64,
    exit_code: AtomicU64,
    exit_requested: AtomicBool,
    exec_count: AtomicU64,
    fork_count: AtomicU64,
    last_return_result: AtomicU64,
    task_switches: AtomicU64,
    last_cpu_apic_id: AtomicU64,
    yield_count: AtomicU64,
    wait_count: AtomicU64,
    wait_status_count: AtomicU64,
    nonzero_wait_statuses: AtomicU64,
    last_wait_status: AtomicU64,
    wait_blocks: AtomicU64,
    waiting_on: AtomicU64,
    waiting_on_thread: AtomicU64,
    next_thread_slot: AtomicU64,
    thread_create_count: AtomicU64,
    thread_join_count: AtomicU64,
}

#[cfg(target_os = "none")]
impl Process {
    pub fn new_init(address_space: UserAddressSpace) -> Self {
        Self::new(INIT_PROCESS_ID, address_space)
    }

    pub fn new(pid: ProcessId, address_space: UserAddressSpace) -> Self {
        Self::new_with_parent(
            pid,
            0,
            INIT_EXECUTABLE_NAME,
            address_space,
            ROOT_UID,
            ROOT_GID,
        )
    }

    fn new_with_parent(
        pid: ProcessId,
        parent_pid: ProcessId,
        executable: &'static str,
        address_space: UserAddressSpace,
        uid: UserId,
        gid: GroupId,
    ) -> Self {
        Self::new_with_state(
            pid,
            parent_pid,
            executable,
            executable,
            address_space,
            ProcessHandleTable::new(),
            None,
            uid,
            gid,
        )
    }

    fn new_fork_child(
        pid: ProcessId,
        parent_pid: ProcessId,
        origin: &'static str,
        executable: &'static str,
        address_space: UserAddressSpace,
        handles: ProcessHandleTable,
        fork_context: ForkContext,
        uid: UserId,
        gid: GroupId,
    ) -> Self {
        Self::new_with_state(
            pid,
            parent_pid,
            origin,
            executable,
            address_space,
            handles,
            Some(fork_context),
            uid,
            gid,
        )
    }

    fn new_with_state(
        pid: ProcessId,
        parent_pid: ProcessId,
        origin: &'static str,
        executable: &'static str,
        address_space: UserAddressSpace,
        handles: ProcessHandleTable,
        fork_context: Option<ForkContext>,
        uid: UserId,
        gid: GroupId,
    ) -> Self {
        let kernel_stack = vec![0; USER_KERNEL_STACK_SIZE].into_boxed_slice();
        let process = Self {
            pid,
            parent_pid,
            uid,
            gid,
            origin,
            executable,
            address_space,
            pending_exec: Mutex::new(None),
            fork_context: Mutex::new(fork_context),
            handles: Mutex::new(handles),
            kernel_stack,
            return_stack: AtomicU64::new(0),
            state: AtomicU8::new(ProcessState::Ready as u8),
            address_space_reclaimed: AtomicBool::new(false),
            syscall_count: AtomicU64::new(0),
            open_count: AtomicU64::new(0),
            read_count: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
            data_read_count: AtomicU64::new(0),
            close_count: AtomicU64::new(0),
            file_write_count: AtomicU64::new(0),
            file_write_bytes: AtomicU64::new(0),
            file_create_count: AtomicU64::new(0),
            process_snapshot_count: AtomicU64::new(0),
            file_snapshot_count: AtomicU64::new(0),
            exit_code: AtomicU64::new(0),
            exit_requested: AtomicBool::new(false),
            exec_count: AtomicU64::new(0),
            fork_count: AtomicU64::new(0),
            last_return_result: AtomicU64::new(0),
            task_switches: AtomicU64::new(0),
            last_cpu_apic_id: AtomicU64::new(u64::from(u32::MAX)),
            yield_count: AtomicU64::new(0),
            wait_count: AtomicU64::new(0),
            wait_status_count: AtomicU64::new(0),
            nonzero_wait_statuses: AtomicU64::new(0),
            last_wait_status: AtomicU64::new(0),
            wait_blocks: AtomicU64::new(0),
            waiting_on: AtomicU64::new(0),
            waiting_on_thread: AtomicU64::new(0),
            next_thread_slot: AtomicU64::new(0),
            thread_create_count: AtomicU64::new(0),
            thread_join_count: AtomicU64::new(0),
        };
        process
    }

    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    fn credentials(&self) -> (UserId, GroupId) {
        (self.uid, self.gid)
    }

    fn is_root(&self) -> bool {
        self.uid == ROOT_UID
    }

    pub fn address_space(&self) -> &UserAddressSpace {
        &self.address_space
    }

    fn reclaim_address_space(&mut self) -> usize {
        if self.address_space_reclaimed.load(Ordering::Acquire) {
            return 0;
        }
        let Some(reclaimed) = reclaim_user_address_space(&mut self.address_space) else {
            return 0;
        };
        self.address_space_reclaimed.store(true, Ordering::Release);
        reclaimed
    }

    pub fn state(&self) -> ProcessState {
        ProcessState::from_raw(self.state.load(Ordering::Acquire))
    }

    pub fn syscall_count(&self) -> u64 {
        self.syscall_count.load(Ordering::Acquire)
    }

    pub fn fork_count(&self) -> u64 {
        self.fork_count.load(Ordering::Acquire)
    }

    fn note_open(&self) {
        self.open_count.fetch_add(1, Ordering::AcqRel);
    }

    fn note_read(&self) {
        self.read_count.fetch_add(1, Ordering::AcqRel);
    }

    fn note_read_bytes(&self, amount: usize) {
        self.read_bytes.fetch_add(amount as u64, Ordering::AcqRel);
    }

    fn note_data_read(&self) {
        self.data_read_count.fetch_add(1, Ordering::AcqRel);
    }

    fn note_close(&self) {
        self.close_count.fetch_add(1, Ordering::AcqRel);
    }

    fn note_file_write(&self, amount: usize) {
        self.file_write_count.fetch_add(1, Ordering::AcqRel);
        self.file_write_bytes
            .fetch_add(amount as u64, Ordering::AcqRel);
    }

    fn note_file_created(&self) {
        self.file_create_count.fetch_add(1, Ordering::AcqRel);
    }

    fn note_process_snapshot(&self) {
        self.process_snapshot_count.fetch_add(1, Ordering::AcqRel);
    }

    fn note_file_snapshot(&self) {
        self.file_snapshot_count.fetch_add(1, Ordering::AcqRel);
    }

    fn install_file_handle(&self, file: &FileImage, writable: bool) -> Option<u64> {
        let mut handles = self.handles.lock();
        for index in 3..MAX_PROCESS_HANDLES {
            if handles.entries[index].is_none() {
                handles.entries[index] = Some(ProcessHandle::File {
                    image: file.image,
                    path: file.path,
                    offset: 0,
                    executable: file.executable,
                    persistent: file.persistent,
                    writable,
                });
                return Some(index as u64);
            }
        }
        None
    }

    fn install_pipe_handles(&self, id: u8) -> Option<(u64, u64)> {
        let mut handles = self.handles.lock();
        let mut free = [None; 2];
        for (index, entry) in handles.entries.iter().enumerate().skip(3) {
            if entry.is_none() {
                if free[0].is_none() {
                    free[0] = Some(index);
                } else {
                    free[1] = Some(index);
                    break;
                }
            }
        }
        let (Some(read_index), Some(write_index)) = (free[0], free[1]) else {
            return None;
        };
        handles.entries[read_index] = Some(ProcessHandle::Pipe { id, readable: true });
        handles.entries[write_index] = Some(ProcessHandle::Pipe {
            id,
            readable: false,
        });
        Some((read_index as u64, write_index as u64))
    }

    fn install_disk_handle(&self, path: &'static [u8], size: usize, writable: bool) -> Option<u64> {
        let mut handles = self.handles.lock();
        for index in 3..MAX_PROCESS_HANDLES {
            if handles.entries[index].is_none() {
                handles.entries[index] = Some(ProcessHandle::Disk {
                    path,
                    offset: 0,
                    size,
                    writable,
                });
                return Some(index as u64);
            }
        }
        None
    }

    fn file_handle_snapshot(&self, handle: u64) -> Option<FileHandleSnapshot> {
        let index = usize::try_from(handle).ok()?;
        let handles = self.handles.lock();
        match handles.entries.get(index).copied()? {
            Some(ProcessHandle::File {
                image,
                path,
                offset,
                executable,
                persistent,
                writable,
            }) => Some(FileHandleSnapshot::Catalog {
                image,
                path,
                offset,
                executable,
                persistent,
                writable,
            }),
            Some(ProcessHandle::Disk {
                path,
                offset,
                size,
                writable,
            }) => Some(FileHandleSnapshot::Disk {
                path,
                offset,
                size,
                writable,
            }),
            Some(ProcessHandle::Pipe { id, readable }) => {
                Some(FileHandleSnapshot::Pipe { id, readable })
            }
            Some(ProcessHandle::Console) | None => None,
        }
    }

    fn advance_file_handle(&self, handle: u64, amount: usize) -> bool {
        let Ok(index) = usize::try_from(handle) else {
            return false;
        };
        let mut handles = self.handles.lock();
        let Some(Some(handle)) = handles.entries.get_mut(index) else {
            return false;
        };
        let offset = match handle {
            ProcessHandle::File { offset, .. } | ProcessHandle::Disk { offset, .. } => offset,
            ProcessHandle::Console | ProcessHandle::Pipe { .. } => return false,
        };
        let Some(next) = offset.checked_add(amount) else {
            return false;
        };
        *offset = next;
        true
    }

    fn update_disk_handle_size(&self, handle: u64, size: usize) -> bool {
        let Ok(index) = usize::try_from(handle) else {
            return false;
        };
        let mut handles = self.handles.lock();
        let Some(Some(ProcessHandle::Disk { size: current, .. })) = handles.entries.get_mut(index)
        else {
            return false;
        };
        *current = size;
        true
    }

    fn close_file_handle(&self, handle: u64) -> bool {
        let Ok(index) = usize::try_from(handle) else {
            return false;
        };
        if index < 3 || index >= MAX_PROCESS_HANDLES {
            return false;
        }
        let mut handles = self.handles.lock();
        let Some(handle) = handles.entries[index].take() else {
            return false;
        };
        if matches!(
            handle,
            ProcessHandle::File { .. } | ProcessHandle::Disk { .. } | ProcessHandle::Pipe { .. }
        ) {
            release_process_handle(handle);
            true
        } else {
            false
        }
    }

    fn close_file_handles_on_exec(&self) {
        let mut handles = self.handles.lock();
        for entry in handles.entries.iter_mut().skip(3) {
            if let Some(handle) = entry.take() {
                release_process_handle(handle);
            }
        }
    }

    fn release_all_handles(&self) {
        self.handles.lock().release_all();
    }

    fn has_console_handle(&self, handle: u64) -> bool {
        let Ok(index) = usize::try_from(handle) else {
            return false;
        };
        let handles = self.handles.lock();
        matches!(
            handles.entries.get(index),
            Some(Some(ProcessHandle::Console))
        )
    }

    pub fn exit_code(&self) -> Option<i64> {
        self.exit_requested
            .load(Ordering::Acquire)
            .then(|| self.exit_code.load(Ordering::Acquire) as i64)
    }

    pub fn last_return_result(&self) -> u64 {
        self.last_return_result.load(Ordering::Acquire)
    }

    pub fn task_switches(&self) -> u64 {
        self.task_switches.load(Ordering::Acquire)
    }

    pub fn yield_count(&self) -> u64 {
        self.yield_count.load(Ordering::Acquire)
    }

    pub fn wait_count(&self) -> u64 {
        self.wait_count.load(Ordering::Acquire)
    }

    pub fn wait_status_count(&self) -> u64 {
        self.wait_status_count.load(Ordering::Acquire)
    }

    pub fn nonzero_wait_statuses(&self) -> u64 {
        self.nonzero_wait_statuses.load(Ordering::Acquire)
    }

    pub fn last_wait_status(&self) -> u64 {
        self.last_wait_status.load(Ordering::Acquire)
    }

    pub fn wait_blocks(&self) -> u64 {
        self.wait_blocks.load(Ordering::Acquire)
    }

    pub fn thread_create_count(&self) -> u64 {
        self.thread_create_count.load(Ordering::Acquire)
    }

    pub fn thread_join_count(&self) -> u64 {
        self.thread_join_count.load(Ordering::Acquire)
    }

    fn note_thread_created(&self) {
        self.thread_create_count.fetch_add(1, Ordering::AcqRel);
    }

    fn note_thread_join(&self) {
        self.thread_join_count.fetch_add(1, Ordering::AcqRel);
    }

    fn allocate_thread_slot(&self) -> Option<usize> {
        let slot = self
            .next_thread_slot
            .fetch_add(1, Ordering::AcqRel)
            .try_into()
            .ok()?;
        (slot < MAX_USER_THREADS_PER_PROCESS).then_some(slot)
    }

    fn kernel_stack_top(&self) -> u64 {
        (self.kernel_stack.as_ptr() as u64 + USER_KERNEL_STACK_SIZE as u64) & !0xf
    }

    fn record_syscall(&self, frame: &SyscallFrame, action: SyscallAction) {
        self.syscall_count.fetch_add(1, Ordering::AcqRel);
        match action {
            SyscallAction::Return => {
                self.last_return_result.store(frame.rax, Ordering::Release);
            }
            SyscallAction::Yield => {
                self.last_return_result.store(frame.rax, Ordering::Release);
                self.yield_count.fetch_add(1, Ordering::AcqRel);
            }
            SyscallAction::Exit => {
                self.exit_code.store(frame.rdi, Ordering::Release);
                self.exit_requested.store(true, Ordering::Release);
            }
            SyscallAction::Spawn => {}
            SyscallAction::SpawnAs => {}
            SyscallAction::SpawnPrivileged => {}
            SyscallAction::GetCredentials => {}
            SyscallAction::Wait => {}
            SyscallAction::WaitpidNonblocking => {}
            SyscallAction::Write => {}
            SyscallAction::Open => {}
            SyscallAction::Read => {}
            SyscallAction::ReadNonblocking => {}
            SyscallAction::Close => {}
            SyscallAction::ThreadCreate => {}
            SyscallAction::ThreadJoin => {}
            SyscallAction::ThreadExit => {}
            SyscallAction::Exec => {}
            SyscallAction::Fork => {}
            SyscallAction::ListProcesses => {}
            SyscallAction::ListFiles => {}
            SyscallAction::Mkdir => {}
            SyscallAction::PathInfo => {}
            SyscallAction::Mmap => {}
            SyscallAction::Munmap => {}
            SyscallAction::NetSend => {}
            SyscallAction::NetReceive => {}
            SyscallAction::NetInfo => {}
            SyscallAction::NetInterfaces => {}
            SyscallAction::NetRenew => {}
            SyscallAction::GfxInfo => {}
            SyscallAction::GfxAcquire => {}
            SyscallAction::GfxFillRect => {}
            SyscallAction::GfxText => {}
            SyscallAction::GfxRelease => {}
            SyscallAction::InputRead => {}
            SyscallAction::GfxWindowCreate => {}
            SyscallAction::GfxWindowClear => {}
            SyscallAction::GfxWindowFillRect => {}
            SyscallAction::GfxWindowText => {}
            SyscallAction::GfxWindowPresent => {}
            SyscallAction::GfxWindowFocus => {}
            SyscallAction::GfxWindowDestroy => {}
            SyscallAction::GfxComposeWindows => {}
            SyscallAction::GfxWindowDispatchPointer => {}
            SyscallAction::GfxWindowReadEvent => {}
            SyscallAction::GfxWindowDispatchKeyboard => {}
            SyscallAction::GfxWindowGetGeometry => {}
            SyscallAction::GfxWindowConfigure => {}
            SyscallAction::GfxWindowRequestClose => {}
            SyscallAction::Poweroff => {}
            SyscallAction::Reboot => {}
            SyscallAction::Suspend => {}
            SyscallAction::Pipe => {}
        }
    }

    fn note_task_switch(&self, apic_id: u32) {
        self.task_switches.fetch_add(1, Ordering::AcqRel);
        self.last_cpu_apic_id
            .store(u64::from(apic_id), Ordering::Release);
    }

    fn note_wait(&self) {
        self.wait_count.fetch_add(1, Ordering::AcqRel);
    }

    fn note_wait_status(&self, status: u64) {
        self.wait_status_count.fetch_add(1, Ordering::AcqRel);
        self.last_wait_status.store(status, Ordering::Release);
        if status != 0 {
            self.nonzero_wait_statuses.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn block_on(&self, child_pid: ProcessId) {
        self.wait_blocks.fetch_add(1, Ordering::AcqRel);
        self.waiting_on
            .store(u64::from(child_pid), Ordering::Release);
        self.state
            .store(ProcessState::Blocked as u8, Ordering::Release);
        let _ = crate::scheduler::set_process_state(self.pid, ProcessState::Blocked);
    }

    fn block_on_thread(&self, tid: ThreadId) {
        self.wait_blocks.fetch_add(1, Ordering::AcqRel);
        self.waiting_on_thread
            .store(u64::from(tid), Ordering::Release);
        self.state
            .store(ProcessState::Blocked as u8, Ordering::Release);
        let _ = crate::scheduler::set_process_state(self.pid, ProcessState::Blocked);
    }

    fn resume_from_wait(&self) {
        self.waiting_on.store(0, Ordering::Release);
        self.state
            .store(ProcessState::Running as u8, Ordering::Release);
        let _ = crate::scheduler::set_process_state(self.pid, ProcessState::Running);
    }

    pub fn run(&mut self) -> Result<ProcessExit, AddressSpaceError> {
        self.state
            .store(ProcessState::Running as u8, Ordering::Release);
        let _ = crate::scheduler::set_process_state(self.pid, ProcessState::Running);
        let result = loop {
            CURRENT_PROCESS_ID.store(u64::from(self.pid), Ordering::Release);
            CURRENT_THREAD_ID.store(u64::from(MAIN_THREAD_ID), Ordering::Release);
            prepare_task_switch(Some(self.pid));
            let user_result = if let Some(context) = self.fork_context.lock().take() {
                run_user_context_from_context(&self.address_space, &context, &self.return_stack)
            } else {
                run_user_context(
                    &self.address_space,
                    self.address_space.entry,
                    self.address_space.stack_top,
                    &self.return_stack,
                    0,
                )
            };
            let pending = self.pending_exec.lock().take();
            if let Some(pending) = pending {
                self.reclaim_address_space();
                self.address_space = pending.address_space;
                self.address_space_reclaimed.store(false, Ordering::Release);
                self.executable = pending.name;
                self.close_file_handles_on_exec();
                self.exec_count.fetch_add(1, Ordering::AcqRel);
                self.exit_code.store(0, Ordering::Release);
                self.exit_requested.store(false, Ordering::Release);
                continue;
            }
            break user_result.and_then(|()| {
                self.exit_code()
                    .map(|code| ProcessExit {
                        code,
                        syscalls: self.syscall_count(),
                    })
                    .ok_or(AddressSpaceError::UserDidNotExit)
            });
        };
        // Process teardown runs after returning from user mode, with interrupts enabled again.
        // Keep every lock-bearing cleanup step in one non-preemptible section; otherwise a timer
        // can switch away while this process owns a global pipe or framebuffer lock and strand all
        // other clients that need it.
        x86_64::instructions::interrupts::without_interrupts(|| {
            self.reclaim_address_space();
            self.release_all_handles();
            match result {
                Ok(exit) => {
                    crate::framebuffer::destroy_windows_for_owner(self.pid);
                    self.state
                        .store(ProcessState::Exited as u8, Ordering::Release);
                    // Wake the parent before making this task unrunnable. A timer interrupt can
                    // land between these operations; if the task were marked Exited first, the
                    // scheduler could switch away from this stack before the wake reached the
                    // blocked waiter.
                    wake_waiter(self.parent_pid, self.pid);
                    let _ = crate::scheduler::set_process_state(self.pid, ProcessState::Exited);
                    Ok(exit)
                }
                Err(error) => {
                    crate::framebuffer::destroy_windows_for_owner(self.pid);
                    self.state
                        .store(ProcessState::Faulted as u8, Ordering::Release);
                    wake_waiter(self.parent_pid, self.pid);
                    let _ = crate::scheduler::set_process_state(self.pid, ProcessState::Faulted);
                    Err(error)
                }
            }
        })
    }
}

#[cfg(target_os = "none")]
pub fn init_process_factory(
    physical_memory_offset: u64,
    regions: &'static [MemoryRegion],
    next_frame_address: Option<u64>,
) {
    PROCESS_FACTORY.call_once(|| ProcessFactory {
        physical_memory_offset,
        regions,
        frame_allocator: Mutex::new(ProcessFrameAllocatorState {
            next_frame_address,
            recycled_frames: Vec::new(),
        }),
    });
}

#[cfg(target_os = "none")]
fn advance_frame_address(current: Option<u64>, candidate: Option<u64>) -> Option<u64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.max(candidate)),
        (None, candidate) => candidate,
        (current, None) => current,
    }
}

#[cfg(target_os = "none")]
pub fn update_frame_allocator(next_frame_address: Option<u64>) {
    if let Some(factory) = PROCESS_FACTORY.get() {
        let mut frame_state = factory.frame_allocator.lock();
        frame_state.next_frame_address =
            advance_frame_address(frame_state.next_frame_address, next_frame_address);
    }
}

#[cfg(target_os = "none")]
fn reclaim_user_address_space(address_space: &mut UserAddressSpace) -> Option<usize> {
    let factory = PROCESS_FACTORY.get()?;
    let kernel_cr3 = KERNEL_CR3.load(Ordering::Acquire);
    if kernel_cr3 == 0 {
        return None;
    }
    let reclaimed = x86_64::instructions::interrupts::without_interrupts(|| {
        let kernel_frame = PhysFrame::containing_address(PhysAddr::new(kernel_cr3));
        // Address-space teardown is always performed from the supervisor root. This prevents the
        // cleanup walk from executing through a page-table tree that is about to be returned.
        unsafe {
            Cr3::write(kernel_frame, Cr3Flags::empty());
        }
        let mut frame_state = factory.frame_allocator.lock();
        address_space.reclaim(&mut frame_state.recycled_frames)
    });
    Some(reclaimed)
}

#[cfg(target_os = "none")]
pub fn load_user_image(image: &[u8]) -> Result<UserAddressSpace, AddressSpaceError> {
    let factory = PROCESS_FACTORY
        .get()
        .ok_or(AddressSpaceError::ModeNotInitialized)?;
    let mut frame_state = factory.frame_allocator.lock();
    let recycled_frames = core::mem::take(&mut frame_state.recycled_frames);
    let mut frame_allocator = UserFrameAllocator::new(
        factory.regions,
        frame_state.next_frame_address,
        recycled_frames,
    );
    let result =
        UserAddressSpace::load_elf(factory.physical_memory_offset, &mut frame_allocator, image);
    frame_state.next_frame_address = advance_frame_address(
        frame_state.next_frame_address,
        frame_allocator.next_available_address(),
    );
    frame_state.recycled_frames = frame_allocator.into_recycled_frames();
    result
}

#[cfg(target_os = "none")]
fn clone_user_address_space(
    address_space: &UserAddressSpace,
) -> Result<UserAddressSpace, AddressSpaceError> {
    let factory = PROCESS_FACTORY
        .get()
        .ok_or(AddressSpaceError::ModeNotInitialized)?;
    let mut frame_state = factory.frame_allocator.lock();
    let recycled_frames = core::mem::take(&mut frame_state.recycled_frames);
    let mut frame_allocator = UserFrameAllocator::new(
        factory.regions,
        frame_state.next_frame_address,
        recycled_frames,
    );
    let result = address_space.clone_for_fork(&mut frame_allocator);
    frame_state.next_frame_address = advance_frame_address(
        frame_state.next_frame_address,
        frame_allocator.next_available_address(),
    );
    frame_state.recycled_frames = frame_allocator.into_recycled_frames();
    result
}

#[cfg(target_os = "none")]
pub fn install_filesystem_files(files: Vec<FilesystemFile>) -> Result<(), SpawnImageError> {
    if FILE_CATALOG.get().is_some() {
        return Err(SpawnImageError::AlreadyInstalled);
    }
    if files.len() > MAX_FILESYSTEM_FILES {
        return Err(SpawnImageError::TooManyFiles {
            max_files: MAX_FILESYSTEM_FILES,
        });
    }
    let mut entries: [Option<FileImage>; MAX_FILESYSTEM_FILES] = [None; MAX_FILESYSTEM_FILES];
    for (index, file) in files.into_iter().enumerate() {
        if file.path.is_empty()
            || file.path[0] != b'/'
            || file.path.len() > MAX_EXECUTABLE_PATH_LENGTH
        {
            return Err(SpawnImageError::InvalidPath);
        }
        if entries
            .iter()
            .flatten()
            .any(|entry| entry.path == file.path.as_slice())
        {
            return Err(SpawnImageError::DuplicatePath);
        }
        let path: &'static [u8] = Box::leak(file.path.into_boxed_slice());
        let name = core::str::from_utf8(path).map_err(|_| SpawnImageError::InvalidPath)?;
        let image: &'static [u8] = Box::leak(file.image.into_boxed_slice());
        let executable = image.starts_with(b"\x7fELF") && parse_elf64(image).is_ok();
        entries[index] = Some(FileImage {
            path,
            name,
            image,
            mode: file.mode,
            executable,
            persistent: file.persistent,
        });
    }
    FILE_CATALOG.call_once(|| FileCatalog { entries });
    Ok(())
}

#[cfg(target_os = "none")]
fn process_slot(pid: ProcessId) -> Result<usize, ProcessRegistryError> {
    let slot = usize::try_from(pid).map_err(|_| ProcessRegistryError::InvalidProcessId)?;
    if pid == 0 || slot >= PROCESS_TABLE_SIZE {
        return Err(ProcessRegistryError::InvalidProcessId);
    }
    Ok(slot)
}

#[cfg(target_os = "none")]
pub fn register_runtime_process(process: &mut Process) -> Result<(), ProcessRegistryError> {
    let slot = process_slot(process.pid)?;
    let pointer = process as *mut Process as usize as u64;
    PROCESS_POINTERS[slot]
        .compare_exchange(0, pointer, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| ProcessRegistryError::ProcessAlreadyRegistered)
}

#[cfg(target_os = "none")]
fn allocate_process_id() -> Result<ProcessId, SpawnError> {
    loop {
        let next = NEXT_PROCESS_ID.load(Ordering::Acquire);
        if next >= PROCESS_TABLE_SIZE as u64 {
            return Err(SpawnError::ProcessTableFull);
        }
        let successor = next + 1;
        if NEXT_PROCESS_ID
            .compare_exchange(next, successor, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(next as ProcessId);
        }
    }
}

#[cfg(target_os = "none")]
fn find_file(path: &[u8]) -> Result<&'static FileImage, SpawnError> {
    FILE_CATALOG
        .get()
        .ok_or(SpawnError::ImageNotInstalled)?
        .entries
        .iter()
        .flatten()
        .find(|file| file.path == path)
        .ok_or(SpawnError::ExecutableNotFound)
}

#[cfg(target_os = "none")]
fn find_spawn_image(
    path: &[u8],
    uid: UserId,
    gid: GroupId,
) -> Result<&'static FileImage, SpawnError> {
    let file = find_file(path)?;
    if file.executable && mode_allows(file.mode, ROOT_UID, ROOT_GID, uid, gid, AccessKind::Execute)
    {
        Ok(file)
    } else {
        Err(SpawnError::ExecutableNotFound)
    }
}

#[cfg(target_os = "none")]
fn spawn_configured_process(
    path: &[u8],
    stdin_fd: u64,
    stdout_fd: u64,
    credential_override: Option<(UserId, GroupId)>,
) -> Result<ProcessId, SpawnError> {
    if !crate::scheduler::is_initialized() {
        return Err(SpawnError::Scheduler(
            crate::scheduler::SchedulerError::ProcessNotFound,
        ));
    }
    let parent_pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let parent_pointer = process_pointer(parent_pid);
    let inherited_credentials = parent_pointer
        .map(|pointer| {
            // SAFETY: the parent process was registered before entering user mode and remains
            // stable for the duration of process creation.
            unsafe { (&*pointer).credentials() }
        })
        .unwrap_or((ROOT_UID, ROOT_GID));
    let (uid, gid) = credential_override.unwrap_or(inherited_credentials);
    let image = find_spawn_image(path, uid, gid)?;
    let pid = allocate_process_id()?;
    let address_space = load_user_image(image.image).map_err(SpawnError::AddressSpace)?;
    let handles = if stdin_fd == SPAWN_INHERIT_FD && stdout_fd == SPAWN_INHERIT_FD {
        ProcessHandleTable::new()
    } else {
        let Some(parent_pointer) = parent_pointer else {
            return Err(SpawnError::InvalidHandle);
        };
        // SAFETY: the parent process was registered before entering user mode and remains stable.
        let parent = unsafe { &*parent_pointer };
        parent.handles.lock().redirected(stdin_fd, stdout_fd)?
    };
    let process_value = Process::new_with_state(
        pid,
        parent_pid,
        image.name,
        image.name,
        address_space,
        handles,
        None,
        uid,
        gid,
    );
    let process = Box::leak(Box::new(process_value));
    register_runtime_process(process).map_err(SpawnError::Registry)?;
    crate::scheduler::register_process(pid).map_err(SpawnError::Scheduler)?;
    Ok(pid)
}

#[cfg(target_os = "none")]
fn spawn_for_syscall(frame: &SyscallFrame) -> u64 {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        return SYSCALL_EFAULT;
    };
    let mut path = [0u8; MAX_EXECUTABLE_PATH_LENGTH];
    let path_length = {
        // SAFETY: the current process pointer was registered before entering user mode and its
        // address space remains stable for the duration of this syscall.
        let process = unsafe { &*pointer };
        match process.address_space.copy_user_string(frame.rdi, &mut path) {
            Ok(length) => length,
            Err(error) => {
                crate::kprintln!(
                    "process: spawn path copy failed ({:?}) status=degraded",
                    error
                );
                return SYSCALL_EFAULT;
            }
        }
    };

    match spawn_configured_process(&path[..path_length], frame.rsi, frame.rdx, None) {
        Ok(child_pid) => u64::from(child_pid),
        Err(SpawnError::ExecutableNotFound) => SYSCALL_ENOENT,
        Err(SpawnError::InvalidHandle) => SYSCALL_EBADF,
        Err(error) => {
            crate::kprintln!("process: spawn failed ({:?}) status=degraded", error);
            SYSCALL_EAGAIN
        }
    }
}

#[cfg(target_os = "none")]
fn spawn_as_for_syscall(frame: &SyscallFrame) -> u64 {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        return SYSCALL_EFAULT;
    };
    // SAFETY: the current process pointer was registered before entering user mode and remains
    // stable for the duration of this syscall.
    if !unsafe { (&*pointer).is_root() } {
        return SYSCALL_EPERM;
    }
    let Ok(uid) = UserId::try_from(frame.rsi) else {
        return SYSCALL_EINVAL;
    };
    let Ok(gid) = GroupId::try_from(frame.rdx) else {
        return SYSCALL_EINVAL;
    };
    let mut path = [0u8; MAX_EXECUTABLE_PATH_LENGTH];
    let path_length = {
        // SAFETY: the current process pointer was registered before entering user mode and its
        // address space remains stable for the duration of this syscall.
        let process = unsafe { &*pointer };
        match process.address_space.copy_user_string(frame.rdi, &mut path) {
            Ok(length) => length,
            Err(error) => {
                crate::kprintln!(
                    "process: spawn-as path copy failed ({:?}) status=degraded",
                    error
                );
                return SYSCALL_EFAULT;
            }
        }
    };

    match spawn_configured_process(
        &path[..path_length],
        SPAWN_INHERIT_PARENT_FD,
        SPAWN_INHERIT_PARENT_FD,
        Some((uid, gid)),
    ) {
        Ok(child_pid) => u64::from(child_pid),
        Err(SpawnError::ExecutableNotFound) => SYSCALL_ENOENT,
        Err(SpawnError::InvalidHandle) => SYSCALL_EBADF,
        Err(error) => {
            crate::kprintln!("process: spawn-as failed ({:?}) status=degraded", error);
            SYSCALL_EAGAIN
        }
    }
}

#[cfg(target_os = "none")]
fn spawn_privileged_for_syscall(frame: &SyscallFrame) -> u64 {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        return SYSCALL_EFAULT;
    };
    let mut path = [0u8; MAX_EXECUTABLE_PATH_LENGTH];
    let path_length = {
        // SAFETY: the current process pointer was registered before entering user mode and its
        // address space remains stable for the duration of this syscall.
        let process = unsafe { &*pointer };
        match process.address_space.copy_user_string(frame.rdi, &mut path) {
            Ok(length) => length,
            Err(error) => {
                crate::kprintln!(
                    "process: privileged-spawn path copy failed ({:?}) status=degraded",
                    error
                );
                return SYSCALL_EFAULT;
            }
        }
    };
    if &path[..path_length] != PRIVILEGED_ADMIN_PATH {
        return SYSCALL_EPERM;
    }

    match spawn_configured_process(
        &path[..path_length],
        frame.rsi,
        frame.rdx,
        Some((ROOT_UID, ROOT_GID)),
    ) {
        Ok(child_pid) => u64::from(child_pid),
        Err(SpawnError::ExecutableNotFound) => SYSCALL_ENOENT,
        Err(SpawnError::InvalidHandle) => SYSCALL_EBADF,
        Err(error) => {
            crate::kprintln!(
                "process: privileged-spawn failed ({:?}) status=degraded",
                error
            );
            SYSCALL_EAGAIN
        }
    }
}

#[cfg(target_os = "none")]
fn credentials_for_syscall(frame: &mut SyscallFrame) {
    if frame.rsi != CREDENTIALS_LENGTH as u64 {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    // SAFETY: the current process pointer was registered before entering user mode and remains
    // stable for the duration of this syscall.
    let process = unsafe { &*pointer };
    let (uid, gid) = process.credentials();
    let mut bytes = [0u8; CREDENTIALS_LENGTH];
    bytes[..8].copy_from_slice(&u64::from(uid).to_le_bytes());
    bytes[8..].copy_from_slice(&u64::from(gid).to_le_bytes());
    if process
        .address_space
        .copy_to_user_bytes(frame.rdi, &bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    frame.rax = CREDENTIALS_LENGTH as u64;
}

#[cfg(target_os = "none")]
fn pipe_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        frame.rdx = SYSCALL_EFAULT;
        return;
    };
    let Some(id) = allocate_pipe() else {
        frame.rax = SYSCALL_EAGAIN;
        frame.rdx = SYSCALL_EAGAIN;
        return;
    };
    // SAFETY: the current process was registered before entering user mode and remains stable.
    let process = unsafe { &*pointer };
    let Some((read_fd, write_fd)) = process.install_pipe_handles(id) else {
        release_pipe(id);
        frame.rax = SYSCALL_EAGAIN;
        frame.rdx = SYSCALL_EAGAIN;
        return;
    };
    frame.rax = read_fd;
    frame.rdx = write_fd;
}

#[cfg(target_os = "none")]
fn fork_context_from_syscall(frame: &SyscallFrame) -> ForkContext {
    let return_frame = unsafe {
        let pointer = (frame as *const SyscallFrame as *const u8)
            .add(core::mem::size_of::<SyscallFrame>())
            .cast::<UserInterruptFrame>();
        *pointer
    };
    let mut registers = *frame;
    registers.rax = 0;
    ForkContext {
        registers,
        return_frame,
    }
}

#[cfg(target_os = "none")]
fn fork_for_syscall(frame: &mut SyscallFrame) -> u64 {
    if CURRENT_THREAD_ID.load(Ordering::Acquire) != u64::from(MAIN_THREAD_ID) {
        return SYSCALL_EINVAL;
    }
    if !crate::scheduler::is_initialized() {
        return SYSCALL_EAGAIN;
    }
    let parent_pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(parent_pointer) = process_pointer(parent_pid) else {
        return SYSCALL_EFAULT;
    };
    let child_pid = match allocate_process_id() {
        Ok(pid) => pid,
        Err(_) => return SYSCALL_EAGAIN,
    };
    let (origin, executable, handles, context, address_space) = {
        // SAFETY: the current process pointer was registered before entering user mode and remains
        // stable for the lifetime of the guest.
        let parent = unsafe { &*parent_pointer };
        let context = fork_context_from_syscall(frame);
        let handles = parent.handles.lock().duplicate();
        let address_space = match clone_user_address_space(&parent.address_space) {
            Ok(address_space) => address_space,
            Err(error) => {
                crate::kprintln!(
                    "process: fork address-space clone failed ({:?}) status=degraded",
                    error
                );
                return SYSCALL_EAGAIN;
            }
        };
        (
            parent.origin,
            parent.executable,
            handles,
            context,
            address_space,
        )
    };
    let (uid, gid) = unsafe { (&*parent_pointer).credentials() };
    let child = Box::leak(Box::new(Process::new_fork_child(
        child_pid,
        parent_pid,
        origin,
        executable,
        address_space,
        handles,
        context,
        uid,
        gid,
    )));
    if register_runtime_process(child).is_err() {
        return SYSCALL_EAGAIN;
    }
    if crate::scheduler::register_process(child_pid).is_err() {
        return SYSCALL_EAGAIN;
    }
    // SAFETY: the current process pointer is a registered, stable allocation.
    unsafe { (&*parent_pointer).fork_count.fetch_add(1, Ordering::AcqRel) };
    u64::from(child_pid)
}

#[cfg(target_os = "none")]
fn exec_for_syscall(user_path: u64) -> u64 {
    if CURRENT_THREAD_ID.load(Ordering::Acquire) != u64::from(MAIN_THREAD_ID) {
        return SYSCALL_EINVAL;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        return SYSCALL_EFAULT;
    };
    let mut path = [0u8; MAX_EXECUTABLE_PATH_LENGTH];
    let path_length = {
        // SAFETY: the current process pointer was registered before entering user mode and its
        // address space remains stable for the duration of this syscall.
        let process = unsafe { &*pointer };
        match process.address_space.copy_user_string(user_path, &mut path) {
            Ok(length) => length,
            Err(error) => {
                crate::kprintln!(
                    "process: exec path copy failed ({:?}) status=degraded",
                    error
                );
                return SYSCALL_EFAULT;
            }
        }
    };
    // SAFETY: the current process pointer was registered before entering user mode and remains
    // stable for the duration of this syscall.
    let process = unsafe { &*pointer };
    let (uid, gid) = process.credentials();
    let file = match find_spawn_image(&path[..path_length], uid, gid) {
        Ok(file) => file,
        Err(SpawnError::ExecutableNotFound) => return SYSCALL_ENOENT,
        Err(_) => return SYSCALL_EAGAIN,
    };
    let address_space = match load_user_image(file.image) {
        Ok(address_space) => address_space,
        Err(error) => {
            crate::kprintln!(
                "process: exec image load failed ({:?}) status=degraded",
                error
            );
            return SYSCALL_EAGAIN;
        }
    };
    let mut pending = process.pending_exec.lock();
    if pending.is_some() {
        return SYSCALL_EAGAIN;
    }
    *pending = Some(PendingExec {
        address_space,
        name: file.name,
    });
    0
}

#[cfg(target_os = "none")]
fn write_for_syscall(frame: &mut SyscallFrame) {
    let Ok(length) = usize::try_from(frame.rdx) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if length > MAX_USER_WRITE_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let mut bytes = [0u8; MAX_USER_WRITE_LENGTH];
    // SAFETY: the current process pointer was registered before entering user mode and its address
    // space remains stable for the duration of this syscall.
    let process = unsafe { &*pointer };
    if frame.rdi == USER_STDOUT_FD && process.has_console_handle(frame.rdi) {
        if process
            .address_space
            .copy_user_bytes(frame.rsi, &mut bytes[..length])
            .is_err()
        {
            frame.rax = SYSCALL_EFAULT;
            return;
        }
        crate::console::write_bytes(&bytes[..length]);
        frame.rax = length as u64;
        return;
    }

    let Some(handle) = process.file_handle_snapshot(frame.rdi) else {
        frame.rax = SYSCALL_EBADF;
        return;
    };
    if let FileHandleSnapshot::Pipe {
        id,
        readable: false,
    } = handle
    {
        if process
            .address_space
            .copy_user_bytes(frame.rsi, &mut bytes[..length])
            .is_err()
        {
            frame.rax = SYSCALL_EFAULT;
            return;
        }
        loop {
            match pipe_write(id, &bytes[..length]) {
                PipeWriteResult::Data(count) => {
                    frame.rax = count as u64;
                    return;
                }
                PipeWriteResult::Full => crate::scheduler::yield_current(),
                PipeWriteResult::Closed => {
                    frame.rax = SYSCALL_EBADF;
                    return;
                }
            }
        }
    }
    if matches!(handle, FileHandleSnapshot::Pipe { .. }) {
        frame.rax = SYSCALL_EBADF;
        return;
    }
    let (path, offset, writable, disk_backed) = match handle {
        FileHandleSnapshot::Catalog {
            path,
            offset,
            persistent,
            writable,
            ..
        } => (path, offset, persistent && writable, false),
        FileHandleSnapshot::Disk {
            path,
            offset,
            writable,
            ..
        } => (path, offset, writable, true),
        FileHandleSnapshot::Pipe { .. } => unreachable!("pipe write handled above"),
    };
    if !writable {
        frame.rax = SYSCALL_EROFS;
        return;
    }
    if process
        .address_space
        .copy_user_bytes(frame.rsi, &mut bytes[..length])
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let Ok((count, new_size)) =
        crate::storage::write_runtime_file(path, offset as u64, &bytes[..length])
    else {
        frame.rax = SYSCALL_EAGAIN;
        return;
    };
    if disk_backed && !process.update_disk_handle_size(frame.rdi, new_size) {
        frame.rax = SYSCALL_EBADF;
        return;
    }
    if count != length || !process.advance_file_handle(frame.rdi, count) {
        frame.rax = SYSCALL_EBADF;
        return;
    }
    process.note_file_write(count);
    frame.rax = count as u64;
}

#[cfg(target_os = "none")]
fn open_for_syscall(user_path: u64, flags: u64) -> u64 {
    if flags & !OPEN_SUPPORTED_FLAGS != 0 {
        return SYSCALL_EINVAL;
    }
    let writable = flags & OPEN_WRITE != 0;
    let create_requested = flags & OPEN_CREATE != 0;
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        return SYSCALL_EFAULT;
    };
    let mut path = [0u8; MAX_EXECUTABLE_PATH_LENGTH];
    let path_length = {
        // SAFETY: the current process pointer was registered before entering user mode and its
        // address space remains stable for the duration of this syscall.
        let process = unsafe { &*pointer };
        match process.address_space.copy_user_string(user_path, &mut path) {
            Ok(length) => length,
            Err(error) => {
                crate::kprintln!(
                    "process: open path copy failed ({:?}) status=degraded",
                    error
                );
                return SYSCALL_EFAULT;
            }
        }
    };
    let process = unsafe { &*pointer };
    let (uid, gid) = process.credentials();
    let handle = match find_file(&path[..path_length]) {
        Ok(file) => {
            if !mode_allows(file.mode, ROOT_UID, ROOT_GID, uid, gid, AccessKind::Read) {
                return SYSCALL_EPERM;
            }
            if writable && !mode_allows(file.mode, ROOT_UID, ROOT_GID, uid, gid, AccessKind::Write)
            {
                return SYSCALL_EPERM;
            }
            if writable && !file.persistent {
                return SYSCALL_EROFS;
            }
            process.install_file_handle(file, writable)
        }
        Err(SpawnError::ExecutableNotFound) => {
            if (writable || create_requested)
                && !runtime_access_allowed(&path[..path_length], uid, AccessKind::Write)
            {
                return SYSCALL_EPERM;
            }
            let (size, created) = match crate::storage::runtime_file_size(&path[..path_length]) {
                Ok(Some(size)) => (size, false),
                Ok(None) if create_requested => {
                    match crate::storage::create_runtime_file(&path[..path_length], &[]) {
                        Ok(size) => (size, true),
                        Err(()) => return SYSCALL_EAGAIN,
                    }
                }
                Ok(None) => return SYSCALL_ENOENT,
                Err(()) => return SYSCALL_EAGAIN,
            };
            let path: &'static [u8] = Box::leak(path[..path_length].to_vec().into_boxed_slice());
            let handle = process.install_disk_handle(path, size, writable);
            if created {
                process.note_file_created();
            }
            handle
        }
        Err(error) => {
            crate::kprintln!("process: pid={} open lookup failed {:?}", pid, error);
            return SYSCALL_EAGAIN;
        }
    };
    let Some(handle) = handle else {
        return SYSCALL_EAGAIN;
    };
    process.note_open();
    handle
}

#[cfg(target_os = "none")]
fn mkdir_for_syscall(user_path: u64) -> u64 {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        return SYSCALL_EFAULT;
    };
    let mut path = [0u8; MAX_EXECUTABLE_PATH_LENGTH];
    let path_length = {
        // SAFETY: the current process pointer was registered before entering user mode and its
        // address space remains stable for the duration of this syscall.
        let process = unsafe { &*pointer };
        match process.address_space.copy_user_string(user_path, &mut path) {
            Ok(length) => length,
            Err(error) => {
                crate::kprintln!(
                    "process: mkdir path copy failed ({:?}) status=degraded",
                    error
                );
                return SYSCALL_EFAULT;
            }
        }
    };
    // SAFETY: the current process pointer was registered before entering user mode and remains
    // stable for the duration of this syscall.
    let process = unsafe { &*pointer };
    if !runtime_access_allowed(&path[..path_length], process.uid, AccessKind::Write) {
        return SYSCALL_EPERM;
    }
    match crate::storage::create_runtime_directory(&path[..path_length]) {
        Ok(()) => 0,
        Err(()) => SYSCALL_EAGAIN,
    }
}

#[cfg(target_os = "none")]
fn path_info_for_syscall(frame: &mut SyscallFrame) {
    if frame.rdx != PATH_INFO_LENGTH as u64 {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let mut path = [0u8; MAX_EXECUTABLE_PATH_LENGTH];
    let path_length = {
        // SAFETY: the current process pointer was registered before entering user mode and its
        // address space remains stable for the duration of this syscall.
        let process = unsafe { &*pointer };
        match process.address_space.copy_user_string(frame.rdi, &mut path) {
            Ok(length) => length,
            Err(_) => {
                frame.rax = SYSCALL_EFAULT;
                return;
            }
        }
    };

    let info = if let Ok(file) = find_file(&path[..path_length]) {
        Some((PATH_KIND_FILE, file.image.len() as u64))
    } else if let Ok(Some((is_directory, size))) =
        crate::storage::runtime_path_info(&path[..path_length])
    {
        Some((
            if is_directory {
                PATH_KIND_DIRECTORY
            } else {
                PATH_KIND_FILE
            },
            size as u64,
        ))
    } else if catalog_directory_exists(&path[..path_length]) {
        Some((PATH_KIND_DIRECTORY, 0))
    } else {
        None
    };
    let Some((kind, size)) = info else {
        frame.rax = SYSCALL_ENOENT;
        return;
    };

    let mut bytes = [0u8; PATH_INFO_LENGTH];
    bytes[..8].copy_from_slice(&kind.to_le_bytes());
    bytes[8..].copy_from_slice(&size.to_le_bytes());
    // SAFETY: the current process pointer was registered before entering user mode and its
    // address space remains stable for the duration of this syscall.
    let process = unsafe { &*pointer };
    if process
        .address_space
        .copy_to_user_bytes(frame.rsi, &bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    frame.rax = PATH_INFO_LENGTH as u64;
}

#[cfg(target_os = "none")]
fn catalog_directory_exists(path: &[u8]) -> bool {
    if path == b"/" {
        return true;
    }
    let Some(catalog) = FILE_CATALOG.get() else {
        return false;
    };
    let Some(prefix_length) = path.len().checked_add(1) else {
        return false;
    };
    if prefix_length > MAX_EXECUTABLE_PATH_LENGTH {
        return false;
    }
    let mut prefix = [0u8; MAX_EXECUTABLE_PATH_LENGTH];
    prefix[..path.len()].copy_from_slice(path);
    prefix[path.len()] = b'/';
    catalog
        .entries
        .iter()
        .flatten()
        .any(|file| file.path.starts_with(&prefix[..prefix_length]))
}

#[cfg(target_os = "none")]
fn mmap_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let Some(factory) = PROCESS_FACTORY.get() else {
        frame.rax = SYSCALL_EAGAIN;
        return;
    };
    let mut frame_state = factory.frame_allocator.lock();
    let recycled_frames = core::mem::take(&mut frame_state.recycled_frames);
    let mut frame_allocator = UserFrameAllocator::new(
        factory.regions,
        frame_state.next_frame_address,
        recycled_frames,
    );
    // The current process is the only thread executing its syscall, and the scheduler does not
    // switch address spaces until this handler returns. Mutating its mapper here is therefore
    // serialized by the syscall boundary.
    let process = unsafe { &mut *pointer };
    let result =
        process
            .address_space
            .map_anonymous(&mut frame_allocator, frame.rdi, frame.rsi & 1 != 0);
    frame_state.next_frame_address = advance_frame_address(
        frame_state.next_frame_address,
        frame_allocator.next_available_address(),
    );
    frame_state.recycled_frames = frame_allocator.into_recycled_frames();
    match result {
        Ok(address) => {
            frame.rax = address;
        }
        Err(AddressSpaceError::InvalidMappingLength) => frame.rax = SYSCALL_EINVAL,
        Err(AddressSpaceError::MappingRangeExhausted | AddressSpaceError::MappingLimit) => {
            frame.rax = SYSCALL_EAGAIN
        }
        Err(error) => {
            crate::kprintln!(
                "process: mmap pid={} length={} failed ({:?}) status=degraded",
                pid,
                frame.rdi,
                error
            );
            frame.rax = SYSCALL_EAGAIN;
        }
    }
}

#[cfg(target_os = "none")]
fn munmap_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let Some(factory) = PROCESS_FACTORY.get() else {
        frame.rax = SYSCALL_EAGAIN;
        return;
    };
    let mut frame_state = factory.frame_allocator.lock();
    let process = unsafe { &mut *pointer };
    match process.address_space.unmap_anonymous(frame.rdi, frame.rsi) {
        Ok(released_frames) => {
            frame_state.recycled_frames.extend(released_frames);
            frame.rax = 0;
        }
        Err(
            AddressSpaceError::InvalidMappingLength | AddressSpaceError::NotAnonymousMapping { .. },
        ) => frame.rax = SYSCALL_EINVAL,
        Err(error) => {
            crate::kprintln!(
                "process: munmap pid={} address=0x{:x} length={} failed ({:?}) status=degraded",
                pid,
                frame.rdi,
                frame.rsi,
                error
            );
            frame.rax = SYSCALL_EAGAIN;
        }
    }
}

#[cfg(target_os = "none")]
fn network_send_for_syscall(frame: &mut SyscallFrame) {
    let Ok(length) = usize::try_from(frame.rdx) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if length > MAX_NETWORK_PAYLOAD_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    let mut endpoint = [0u8; 6];
    if process
        .address_space
        .copy_user_bytes(frame.rdi, &mut endpoint)
        .is_err()
    {
        crate::kprintln!(
            "net: send endpoint copy fault pid={} address=0x{:x} status=degraded",
            pid,
            frame.rdi
        );
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let mut payload = [0u8; MAX_NETWORK_PAYLOAD_LENGTH];
    if process
        .address_space
        .copy_user_bytes(frame.rsi, &mut payload[..length])
        .is_err()
    {
        crate::kprintln!(
            "net: send payload copy fault pid={} address=0x{:x} length={} status=degraded",
            pid,
            frame.rsi,
            length
        );
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let destination = [endpoint[0], endpoint[1], endpoint[2], endpoint[3]];
    let destination_port = u16::from_be_bytes([endpoint[4], endpoint[5]]);
    match crate::network_runtime::network_send(destination, destination_port, &payload[..length]) {
        Ok(count) => {
            if let Some(backend) = crate::network_runtime::backend_name() {
                crate::kprintln!(
                    "net: syscall send backend={} bytes={} status=ready",
                    backend,
                    count
                );
            }
            frame.rax = count as u64;
        }
        Err(error) if error.is_no_packet() || error.is_unavailable() => {
            frame.rax = SYSCALL_EAGAIN;
        }
        Err(error) if error.is_buffer_too_small() => {
            frame.rax = SYSCALL_EINVAL;
        }
        Err(error) => {
            crate::kprintln!(
                "net: send failed pid={} error={:?} status=degraded",
                pid,
                error
            );
            frame.rax = SYSCALL_EAGAIN;
        }
    }
}

#[cfg(target_os = "none")]
fn network_receive_for_syscall(frame: &mut SyscallFrame) {
    let Ok(capacity) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if capacity < crate::network_runtime::NETWORK_RECEIVE_HEADER_LENGTH
        || capacity > MAX_NETWORK_BUFFER_LENGTH
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let mut bytes = [0u8; MAX_NETWORK_BUFFER_LENGTH];
    match crate::network_runtime::network_receive(&mut bytes[..capacity]) {
        Ok(count) => {
            let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
            let Some(pointer) = process_pointer(pid) else {
                frame.rax = SYSCALL_EFAULT;
                return;
            };
            let process = unsafe { &*pointer };
            if let Err(error) = process
                .address_space
                .copy_to_user_bytes(frame.rdi, &bytes[..count])
            {
                crate::kprintln!(
                    "net: receive buffer copy fault pid={} address=0x{:x} length={} error={:?} status=degraded",
                    pid,
                    frame.rdi,
                    count,
                    error
                );
                frame.rax = SYSCALL_EFAULT;
                return;
            }
            if let Some(backend) = crate::network_runtime::backend_name() {
                crate::kprintln!(
                    "net: syscall receive backend={} bytes={} status=ready",
                    backend,
                    count
                );
            }
            frame.rax = count as u64;
        }
        Err(error) if error.is_no_packet() || error.is_unavailable() => {
            frame.rax = SYSCALL_EAGAIN;
        }
        Err(error) if error.is_buffer_too_small() => {
            frame.rax = SYSCALL_EINVAL;
        }
        Err(error) => {
            crate::kprintln!(
                "net: receive failed pid={} error={:?} status=degraded",
                CURRENT_PROCESS_ID.load(Ordering::Acquire),
                error
            );
            frame.rax = SYSCALL_EAGAIN;
        }
    }
}

#[cfg(target_os = "none")]
fn network_info_for_syscall(frame: &mut SyscallFrame) {
    let Ok(capacity) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if capacity > MAX_NETWORK_INFO_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let mut bytes = [0u8; MAX_NETWORK_INFO_LENGTH];
    match crate::network_runtime::network_info(&mut bytes[..capacity]) {
        Ok(count) => {
            let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
            let Some(pointer) = process_pointer(pid) else {
                frame.rax = SYSCALL_EFAULT;
                return;
            };
            let process = unsafe { &*pointer };
            if process
                .address_space
                .copy_to_user_bytes(frame.rdi, &bytes[..count])
                .is_err()
            {
                frame.rax = SYSCALL_EFAULT;
                return;
            }
            if let Some(backend) = crate::network_runtime::backend_name() {
                crate::kprintln!("net: syscall info backend={} status=ready", backend);
            }
            frame.rax = count as u64;
        }
        Err(error) if error.is_unavailable() => {
            frame.rax = SYSCALL_EAGAIN;
        }
        Err(error) if error.is_buffer_too_small() => {
            frame.rax = SYSCALL_EINVAL;
        }
        Err(error) => {
            crate::kprintln!(
                "net: info failed pid={} error={:?} status=degraded",
                CURRENT_PROCESS_ID.load(Ordering::Acquire),
                error
            );
            frame.rax = SYSCALL_EAGAIN;
        }
    }
}

#[cfg(target_os = "none")]
fn network_interfaces_for_syscall(frame: &mut SyscallFrame) {
    let Ok(capacity) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if capacity > MAX_NETWORK_INTERFACES_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let mut bytes = [0u8; MAX_NETWORK_INTERFACES_LENGTH];
    match crate::network_runtime::network_interfaces(&mut bytes[..capacity]) {
        Ok(count) => {
            let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
            let Some(pointer) = process_pointer(pid) else {
                frame.rax = SYSCALL_EFAULT;
                return;
            };
            let process = unsafe { &*pointer };
            if process
                .address_space
                .copy_to_user_bytes(frame.rdi, &bytes[..count])
                .is_err()
            {
                frame.rax = SYSCALL_EFAULT;
                return;
            }
            if let (Some(default_interface), Some(backend)) = (
                crate::network_runtime::default_interface_name(),
                crate::network_runtime::backend_name(),
            ) {
                crate::kprintln!(
                    "net: syscall interfaces default={} backend={} count={} status=ready",
                    default_interface,
                    backend,
                    crate::network_runtime::interface_count()
                );
            }
            frame.rax = count as u64;
        }
        Err(error) if error.is_unavailable() => {
            frame.rax = SYSCALL_EAGAIN;
        }
        Err(error) if error.is_buffer_too_small() => {
            frame.rax = SYSCALL_EINVAL;
        }
        Err(error) => {
            crate::kprintln!(
                "net: interfaces failed pid={} error={:?} status=degraded",
                CURRENT_PROCESS_ID.load(Ordering::Acquire),
                error
            );
            frame.rax = SYSCALL_EAGAIN;
        }
    }
}

#[cfg(target_os = "none")]
fn network_renew_for_syscall(frame: &mut SyscallFrame) {
    let Ok(capacity) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if capacity > MAX_NETWORK_RENEW_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let mut bytes = [0u8; MAX_NETWORK_RENEW_LENGTH];
    match crate::network_runtime::network_renew(&mut bytes[..capacity]) {
        Ok(report) => {
            let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
            let Some(pointer) = process_pointer(pid) else {
                frame.rax = SYSCALL_EFAULT;
                return;
            };
            let process = unsafe { &*pointer };
            if process
                .address_space
                .copy_to_user_bytes(frame.rdi, &bytes[..report.length])
                .is_err()
            {
                frame.rax = SYSCALL_EFAULT;
                return;
            }
            crate::kprintln!(
                "net: syscall renew interfaces={} status={}",
                crate::network_runtime::interface_count(),
                if report.all_ready {
                    "ready"
                } else {
                    "degraded"
                }
            );
            frame.rax = report.length as u64;
        }
        Err(error) if error.is_unavailable() => {
            frame.rax = SYSCALL_EAGAIN;
        }
        Err(error) if error.is_buffer_too_small() => {
            frame.rax = SYSCALL_EINVAL;
        }
        Err(error) => {
            crate::kprintln!(
                "net: renew failed pid={} error={:?} status=degraded",
                CURRENT_PROCESS_ID.load(Ordering::Acquire),
                error
            );
            frame.rax = SYSCALL_EAGAIN;
        }
    }
}

#[cfg(target_os = "none")]
fn graphics_info_for_syscall(frame: &mut SyscallFrame) {
    let Ok(capacity) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if capacity < GRAPHICS_INFO_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let Some(info) = crate::framebuffer::info() else {
        frame.rax = SYSCALL_EAGAIN;
        return;
    };
    let mut bytes = [0u8; GRAPHICS_INFO_LENGTH];
    bytes[0..4].copy_from_slice(&info.width.to_le_bytes());
    bytes[4..8].copy_from_slice(&info.height.to_le_bytes());
    bytes[8..12].copy_from_slice(&info.stride.to_le_bytes());
    bytes[12..16].copy_from_slice(&info.bytes_per_pixel.to_le_bytes());
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    if process
        .address_space
        .copy_to_user_bytes(frame.rdi, &bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    frame.rax = GRAPHICS_INFO_LENGTH as u64;
}

#[cfg(target_os = "none")]
fn graphics_acquire_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    if crate::framebuffer::acquire(pid) {
        if let Some(info) = crate::framebuffer::info() {
            crate::kprintln!(
                "graphics: compositor pid={} framebuffer={}x{} stride={} status=ready",
                pid,
                info.width,
                info.height,
                info.stride
            );
        }
        frame.rax = 0;
    } else {
        frame.rax = SYSCALL_EAGAIN;
    }
}

#[cfg(target_os = "none")]
fn graphics_fill_rect_for_syscall(frame: &mut SyscallFrame) {
    let Ok(request_length) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if request_length != GRAPHICS_RECT_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    let mut bytes = [0u8; GRAPHICS_RECT_LENGTH];
    if process
        .address_space
        .copy_user_bytes(frame.rdi, &mut bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let rect = crate::framebuffer::GraphicsRect {
        x: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        y: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        width: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        height: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        color: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
    };
    if rect.width == 0
        || rect.height == 0
        || rect.width > MAX_GRAPHICS_RECT_DIMENSION
        || rect.height > MAX_GRAPHICS_RECT_DIMENSION
        || u64::from(rect.width) * u64::from(rect.height) > MAX_GRAPHICS_RECT_AREA
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    frame.rax = if crate::framebuffer::fill_rect(pid, rect) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_text_for_syscall(frame: &mut SyscallFrame) {
    let Ok(request_length) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if request_length != GRAPHICS_TEXT_REQUEST_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    let mut request = [0u8; GRAPHICS_TEXT_REQUEST_LENGTH];
    if process
        .address_space
        .copy_user_bytes(frame.rdi, &mut request)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let x = u32::from_le_bytes(request[0..4].try_into().unwrap());
    let y = u32::from_le_bytes(request[4..8].try_into().unwrap());
    let color = u32::from_le_bytes(request[8..12].try_into().unwrap());
    let bytes_address = u64::from_le_bytes(request[16..24].try_into().unwrap());
    let Ok(text_length) = usize::try_from(u64::from_le_bytes(request[24..32].try_into().unwrap()))
    else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if text_length > MAX_GRAPHICS_TEXT_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let mut bytes = [0u8; MAX_GRAPHICS_TEXT_LENGTH];
    if text_length != 0
        && process
            .address_space
            .copy_user_bytes(bytes_address, &mut bytes[..text_length])
            .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    frame.rax = if crate::framebuffer::draw_text(pid, x, y, color, &bytes[..text_length]) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_release_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    crate::framebuffer::release(pid);
    frame.rax = 0;
}

#[cfg(target_os = "none")]
fn input_read_for_syscall(frame: &mut SyscallFrame) {
    let Ok(capacity) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if capacity < crate::input::INPUT_EVENT_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let Some(event) = crate::input::read_event() else {
        frame.rax = 0;
        return;
    };
    let mut bytes = [0u8; crate::input::INPUT_EVENT_LENGTH];
    bytes[0..4].copy_from_slice(&event.kind.to_le_bytes());
    bytes[4..8].copy_from_slice(&event.buttons.to_le_bytes());
    bytes[8..12].copy_from_slice(&event.dx.to_le_bytes());
    bytes[12..16].copy_from_slice(&event.dy.to_le_bytes());
    bytes[16..20].copy_from_slice(&event.wheel.to_le_bytes());
    bytes[20..24].copy_from_slice(&event.code.to_le_bytes());
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    if process
        .address_space
        .copy_to_user_bytes(frame.rdi, &bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    frame.rax = crate::input::INPUT_EVENT_LENGTH as u64;
}

#[cfg(target_os = "none")]
fn graphics_window_create_for_syscall(frame: &mut SyscallFrame) {
    let Ok(length) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if length != GRAPHICS_WINDOW_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    let mut bytes = [0u8; GRAPHICS_WINDOW_LENGTH];
    if process
        .address_space
        .copy_user_bytes(frame.rdi, &mut bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let geometry = crate::framebuffer::GraphicsWindow {
        x: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        y: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        width: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        height: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
    };
    frame.rax = crate::framebuffer::create_window(pid, geometry)
        .map(u64::from)
        .unwrap_or(SYSCALL_EAGAIN);
}

#[cfg(target_os = "none")]
fn graphics_window_clear_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    frame.rax = if crate::framebuffer::clear_window(pid, frame.rdi as u32) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_window_fill_rect_for_syscall(frame: &mut SyscallFrame) {
    let Ok(length) = usize::try_from(frame.rdx) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if length != GRAPHICS_RECT_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    let mut bytes = [0u8; GRAPHICS_RECT_LENGTH];
    if process
        .address_space
        .copy_user_bytes(frame.rsi, &mut bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let rect = crate::framebuffer::GraphicsRect {
        x: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        y: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        width: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        height: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        color: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
    };
    frame.rax = if crate::framebuffer::window_fill_rect(pid, frame.rdi as u32, rect) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_window_text_for_syscall(frame: &mut SyscallFrame) {
    let Ok(length) = usize::try_from(frame.rdx) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if length != GRAPHICS_TEXT_REQUEST_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    let mut request = [0u8; GRAPHICS_TEXT_REQUEST_LENGTH];
    if process
        .address_space
        .copy_user_bytes(frame.rsi, &mut request)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let x = u32::from_le_bytes(request[0..4].try_into().unwrap());
    let y = u32::from_le_bytes(request[4..8].try_into().unwrap());
    let color = u32::from_le_bytes(request[8..12].try_into().unwrap());
    let bytes_address = u64::from_le_bytes(request[16..24].try_into().unwrap());
    let Ok(text_length) = usize::try_from(u64::from_le_bytes(request[24..32].try_into().unwrap()))
    else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if text_length > MAX_WINDOW_TEXT_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let mut bytes = [0u8; MAX_WINDOW_TEXT_LENGTH];
    if text_length != 0
        && process
            .address_space
            .copy_user_bytes(bytes_address, &mut bytes[..text_length])
            .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    frame.rax = if crate::framebuffer::window_draw_text(
        pid,
        frame.rdi as u32,
        x,
        y,
        color,
        &bytes[..text_length],
    ) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_window_present_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    frame.rax = if crate::framebuffer::present_window(pid, frame.rdi as u32) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_window_focus_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    frame.rax = if crate::framebuffer::focus_window(pid, frame.rdi as u32) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_window_destroy_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    frame.rax = if crate::framebuffer::destroy_window(pid, frame.rdi as u32) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_window_get_geometry_for_syscall(frame: &mut SyscallFrame) {
    let Ok(length) = usize::try_from(frame.rdx) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if length != GRAPHICS_WINDOW_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(geometry) = crate::framebuffer::window_geometry(pid, frame.rdi as u32) else {
        frame.rax = SYSCALL_EAGAIN;
        return;
    };
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    let mut bytes = [0u8; GRAPHICS_WINDOW_LENGTH];
    bytes[0..4].copy_from_slice(&geometry.x.to_le_bytes());
    bytes[4..8].copy_from_slice(&geometry.y.to_le_bytes());
    bytes[8..12].copy_from_slice(&geometry.width.to_le_bytes());
    bytes[12..16].copy_from_slice(&geometry.height.to_le_bytes());
    frame.rax = if process
        .address_space
        .copy_to_user_bytes(frame.rsi, &bytes)
        .is_ok()
    {
        GRAPHICS_WINDOW_LENGTH as u64
    } else {
        SYSCALL_EFAULT
    };
}

#[cfg(target_os = "none")]
fn graphics_window_configure_for_syscall(frame: &mut SyscallFrame) {
    let Ok(length) = usize::try_from(frame.rdx) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if length != GRAPHICS_WINDOW_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    let mut bytes = [0u8; GRAPHICS_WINDOW_LENGTH];
    if process
        .address_space
        .copy_user_bytes(frame.rsi, &mut bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let geometry = crate::framebuffer::GraphicsWindow {
        x: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        y: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        width: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        height: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
    };
    frame.rax = if crate::framebuffer::configure_window(pid, frame.rdi as u32, geometry) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_window_request_close_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    frame.rax = if crate::framebuffer::request_window_close(pid, frame.rdi as u32) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_compose_windows_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    frame.rax = if crate::framebuffer::compose_windows(pid) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn graphics_window_dispatch_pointer_for_syscall(frame: &mut SyscallFrame) {
    let Ok(length) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if length != GRAPHICS_POINTER_EVENT_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    let mut bytes = [0u8; GRAPHICS_POINTER_EVENT_LENGTH];
    if process
        .address_space
        .copy_user_bytes(frame.rdi, &mut bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let event = crate::input::InputEvent {
        kind: crate::input::INPUT_EVENT_MOUSE,
        buttons: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        dx: i32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        dy: i32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        wheel: i32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        code: 0,
    };
    let x = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let y = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    frame.rax = match crate::framebuffer::dispatch_pointer(pid, x, y, event) {
        Ok(window_id) => u64::from(window_id),
        Err(()) => SYSCALL_EAGAIN,
    };
}

#[cfg(target_os = "none")]
fn graphics_window_read_event_for_syscall(frame: &mut SyscallFrame) {
    let Ok(capacity) = usize::try_from(frame.rdx) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if capacity < crate::input::INPUT_EVENT_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(event) = crate::framebuffer::read_window_event(pid, frame.rdi as u32) else {
        frame.rax = 0;
        return;
    };
    let mut bytes = [0u8; crate::input::INPUT_EVENT_LENGTH];
    bytes[0..4].copy_from_slice(&event.kind.to_le_bytes());
    bytes[4..8].copy_from_slice(&event.buttons.to_le_bytes());
    bytes[8..12].copy_from_slice(&event.dx.to_le_bytes());
    bytes[12..16].copy_from_slice(&event.dy.to_le_bytes());
    bytes[16..20].copy_from_slice(&event.wheel.to_le_bytes());
    bytes[20..24].copy_from_slice(&event.code.to_le_bytes());
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    if process
        .address_space
        .copy_to_user_bytes(frame.rsi, &bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    frame.rax = crate::input::INPUT_EVENT_LENGTH as u64;
}

#[cfg(target_os = "none")]
fn graphics_window_dispatch_keyboard_for_syscall(frame: &mut SyscallFrame) {
    let Ok(length) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if length != crate::input::INPUT_EVENT_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    let mut bytes = [0u8; crate::input::INPUT_EVENT_LENGTH];
    if process
        .address_space
        .copy_user_bytes(frame.rdi, &mut bytes)
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    let event = crate::input::InputEvent {
        kind: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        buttons: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        dx: i32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        dy: i32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        wheel: i32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        code: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
    };
    if event.kind != crate::input::INPUT_EVENT_KEYBOARD {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    frame.rax = if crate::framebuffer::dispatch_keyboard(pid, event) {
        0
    } else {
        SYSCALL_EAGAIN
    };
}

#[cfg(target_os = "none")]
fn read_for_syscall(frame: &mut SyscallFrame, nonblocking: bool) {
    let Ok(length) = usize::try_from(frame.rdx) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if length > MAX_USER_WRITE_LENGTH {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    if frame.rdi == USER_STDIN_FD && process.has_console_handle(frame.rdi) {
        let mut bytes = [0u8; MAX_USER_WRITE_LENGTH];
        let count = crate::console::read_available(&mut bytes[..length]);
        if process
            .address_space
            .copy_to_user_bytes(frame.rsi, &bytes[..count])
            .is_err()
        {
            frame.rax = SYSCALL_EFAULT;
            return;
        }
        process.note_read();
        process.note_read_bytes(count);
        frame.rax = count as u64;
        return;
    }
    let Some(handle) = process.file_handle_snapshot(frame.rdi) else {
        frame.rax = SYSCALL_EBADF;
        return;
    };
    let mut bytes = [0u8; MAX_USER_WRITE_LENGTH];
    if let FileHandleSnapshot::Pipe { id, readable: true } = handle {
        loop {
            match pipe_read(id, &mut bytes[..length]) {
                PipeReadResult::Data(count) => {
                    if process
                        .address_space
                        .copy_to_user_bytes(frame.rsi, &bytes[..count])
                        .is_err()
                    {
                        frame.rax = SYSCALL_EFAULT;
                        return;
                    }
                    process.note_read();
                    process.note_read_bytes(count);
                    frame.rax = count as u64;
                    return;
                }
                PipeReadResult::Empty if nonblocking => {
                    frame.rax = SYSCALL_EAGAIN;
                    return;
                }
                PipeReadResult::Empty => crate::scheduler::yield_current(),
                PipeReadResult::Eof => {
                    frame.rax = 0;
                    return;
                }
                PipeReadResult::Closed => {
                    frame.rax = SYSCALL_EBADF;
                    return;
                }
            }
        }
    }
    if matches!(handle, FileHandleSnapshot::Pipe { .. }) {
        frame.rax = SYSCALL_EBADF;
        return;
    }
    let (count, executable) = match handle {
        FileHandleSnapshot::Catalog {
            image,
            path,
            offset,
            executable,
            persistent,
            ..
        } => {
            let count = image.len().saturating_sub(offset).min(length);
            if persistent {
                let Ok(actual) =
                    crate::storage::read_runtime_file(path, offset as u64, &mut bytes[..count])
                else {
                    frame.rax = SYSCALL_EAGAIN;
                    return;
                };
                if actual != count {
                    frame.rax = SYSCALL_EAGAIN;
                    return;
                }
            } else {
                bytes[..count].copy_from_slice(&image[offset..offset + count]);
            }
            (count, executable)
        }
        FileHandleSnapshot::Disk {
            path, offset, size, ..
        } => {
            let count = size.saturating_sub(offset).min(length);
            let Ok(actual) =
                crate::storage::read_runtime_file(path, offset as u64, &mut bytes[..count])
            else {
                frame.rax = SYSCALL_EAGAIN;
                return;
            };
            if actual != count {
                frame.rax = SYSCALL_EAGAIN;
                return;
            }
            (count, false)
        }
        FileHandleSnapshot::Pipe { .. } => unreachable!("pipe read handled above"),
    };
    if process
        .address_space
        .copy_to_user_bytes(frame.rsi, &bytes[..count])
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return;
    }
    if !process.advance_file_handle(frame.rdi, count) {
        frame.rax = SYSCALL_EBADF;
        return;
    }
    process.note_read();
    process.note_read_bytes(count);
    if !executable {
        process.note_data_read();
    }
    frame.rax = count as u64;
}

#[cfg(target_os = "none")]
struct SnapshotBuffer {
    bytes: [u8; MAX_SNAPSHOT_LENGTH],
    length: usize,
}

#[cfg(target_os = "none")]
impl SnapshotBuffer {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_SNAPSHOT_LENGTH],
            length: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[cfg(target_os = "none")]
impl fmt::Write for SnapshotBuffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.length.checked_add(value.len()).ok_or(fmt::Error)?;
        if end > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.length..end].copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}

#[cfg(target_os = "none")]
fn process_state_name(state: ProcessState) -> &'static str {
    match state {
        ProcessState::Ready => "ready",
        ProcessState::Running => "running",
        ProcessState::Exited => "exited",
        ProcessState::Faulted => "faulted",
        ProcessState::Blocked => "blocked",
    }
}

#[cfg(target_os = "none")]
fn copy_snapshot_to_user(frame: &mut SyscallFrame, snapshot: &SnapshotBuffer) -> bool {
    let Ok(capacity) = usize::try_from(frame.rsi) else {
        frame.rax = SYSCALL_EINVAL;
        return false;
    };
    if capacity > MAX_SNAPSHOT_LENGTH || snapshot.length > capacity {
        frame.rax = SYSCALL_EINVAL;
        return false;
    }
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return false;
    };
    // SAFETY: the current process pointer was registered before entering user mode and its address
    // space remains stable for the duration of this syscall.
    let process = unsafe { &*pointer };
    if process
        .address_space
        .copy_to_user_bytes(frame.rdi, snapshot.as_slice())
        .is_err()
    {
        frame.rax = SYSCALL_EFAULT;
        return false;
    }
    frame.rax = snapshot.length as u64;
    true
}

#[cfg(target_os = "none")]
fn list_processes_for_syscall(frame: &mut SyscallFrame) {
    let mut snapshot = SnapshotBuffer::new();
    if writeln!(
        &mut snapshot,
        "PID PPID UID GID STATE ORIGIN EXECUTABLE EXIT SYSCALLS READS READ_BYTES WRITES WRITE_BYTES CREATES"
    )
    .is_err()
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    for pid in runtime_process_ids().iter().flatten().copied() {
        let Some(stats) = runtime_process_stats(pid) else {
            continue;
        };
        if writeln!(
            &mut snapshot,
            "{} {} {} {} {} {} {} {:?} {} {} {} {} {} {}",
            stats.pid,
            stats.parent_pid,
            stats.uid,
            stats.gid,
            process_state_name(stats.state),
            stats.origin,
            stats.executable,
            stats.exit_code,
            stats.syscall_count,
            stats.read_count,
            stats.read_bytes,
            stats.file_write_count,
            stats.file_write_bytes,
            stats.file_create_count
        )
        .is_err()
        {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    }
    if copy_snapshot_to_user(frame, &snapshot) {
        let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
        if let Some(pointer) = process_pointer(pid) {
            // SAFETY: the current process pointer was registered before entering user mode.
            unsafe { (&*pointer).note_process_snapshot() };
        }
    }
}

#[cfg(target_os = "none")]
fn list_files_for_syscall(frame: &mut SyscallFrame) {
    let Some(catalog) = FILE_CATALOG.get() else {
        frame.rax = SYSCALL_EAGAIN;
        return;
    };
    let mut snapshot = SnapshotBuffer::new();
    if writeln!(&mut snapshot, "PATH SIZE TYPE").is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    for entry in catalog.entries.iter().flatten() {
        if writeln!(
            &mut snapshot,
            "{} {} {}",
            entry.name,
            entry.image.len(),
            if entry.executable { "elf" } else { "data" }
        )
        .is_err()
        {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    }
    if let Ok(runtime_files) = crate::storage::runtime_file_snapshot() {
        for (path, size) in runtime_files {
            if catalog
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.path == path.as_slice())
            {
                continue;
            }
            let Ok(path) = core::str::from_utf8(&path) else {
                continue;
            };
            if writeln!(&mut snapshot, "{} {} data", path, size).is_err() {
                frame.rax = SYSCALL_EINVAL;
                return;
            }
        }
    }
    if copy_snapshot_to_user(frame, &snapshot) {
        let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
        if let Some(pointer) = process_pointer(pid) {
            // SAFETY: the current process pointer was registered before entering user mode.
            unsafe { (&*pointer).note_file_snapshot() };
        }
    }
}

#[cfg(target_os = "none")]
fn close_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    let process = unsafe { &*pointer };
    if !process.close_file_handle(frame.rdi) {
        frame.rax = SYSCALL_EBADF;
        return;
    }
    process.note_close();
    frame.rax = 0;
}

#[cfg(target_os = "none")]
fn process_pointer(pid: ProcessId) -> Option<*mut Process> {
    let slot = process_slot(pid).ok()?;
    let pointer = PROCESS_POINTERS[slot].load(Ordering::Acquire);
    (pointer != 0).then_some(pointer as *mut Process)
}

#[cfg(target_os = "none")]
fn thread_slot(tid: ThreadId) -> Option<usize> {
    let slot = usize::try_from(tid).ok()?;
    (tid != MAIN_THREAD_ID && slot < THREAD_TABLE_SIZE).then_some(slot)
}

#[cfg(target_os = "none")]
fn thread_pointer(tid: ThreadId) -> Option<*mut Thread> {
    let slot = thread_slot(tid)?;
    let pointer = THREAD_POINTERS[slot].load(Ordering::Acquire);
    (pointer != 0).then_some(pointer as *mut Thread)
}

#[cfg(target_os = "none")]
fn allocate_thread_id() -> Option<ThreadId> {
    loop {
        let next = NEXT_THREAD_ID.load(Ordering::Acquire);
        if next >= THREAD_TABLE_SIZE as u64 {
            return None;
        }
        if NEXT_THREAD_ID
            .compare_exchange(next, next + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(next as ThreadId);
        }
    }
}

#[cfg(target_os = "none")]
fn create_thread_for_syscall(frame: &mut SyscallFrame) {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let Some(pointer) = process_pointer(pid) else {
        frame.rax = SYSCALL_EFAULT;
        return;
    };
    // SAFETY: the current process pointer was registered before entering user mode and remains
    // stable for the duration of this syscall.
    let process = unsafe { &*pointer };
    if !process.address_space.is_executable_address(frame.rdi) {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let Some(slot) = process.allocate_thread_slot() else {
        frame.rax = SYSCALL_EAGAIN;
        return;
    };
    let Some(stack_top) = process.address_space.thread_stack_top(slot) else {
        frame.rax = SYSCALL_EAGAIN;
        return;
    };
    let Some(tid) = allocate_thread_id() else {
        frame.rax = SYSCALL_EAGAIN;
        return;
    };
    let thread = Box::leak(Box::new(Thread::new(
        tid, pid, frame.rdi, frame.rsi, stack_top,
    )));
    let Some(table_slot) = thread_slot(tid) else {
        frame.rax = SYSCALL_EAGAIN;
        return;
    };
    let pointer_value = thread as *mut Thread as usize as u64;
    if THREAD_POINTERS[table_slot]
        .compare_exchange(0, pointer_value, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        frame.rax = SYSCALL_EAGAIN;
        return;
    }
    if let Err(error) = crate::scheduler::register_thread(pid, tid) {
        THREAD_POINTERS[table_slot].store(0, Ordering::Release);
        crate::kprintln!(
            "process: thread registration failed ({:?}) status=degraded",
            error
        );
        frame.rax = SYSCALL_EAGAIN;
        return;
    }
    process.note_thread_created();
    frame.rax = u64::from(tid);
}

#[cfg(target_os = "none")]
fn try_wait_thread(pid: ProcessId, tid: ThreadId, frame: &mut SyscallFrame) -> bool {
    let Some(pointer) = thread_pointer(tid) else {
        frame.rax = SYSCALL_ECHILD;
        return true;
    };
    // SAFETY: thread registration keeps every thread allocation stable for kernel lifetime.
    let thread = unsafe { &*pointer };
    if thread.pid != pid {
        frame.rax = SYSCALL_ECHILD;
        return true;
    }
    match thread.state() {
        ProcessState::Exited => {
            frame.rax = u64::from(tid);
            true
        }
        ProcessState::Faulted => {
            frame.rax = SYSCALL_ECHILD;
            true
        }
        ProcessState::Ready | ProcessState::Running | ProcessState::Blocked => {
            frame.rax = SYSCALL_EAGAIN;
            false
        }
    }
}

#[cfg(target_os = "none")]
fn wait_for_thread(pid: ProcessId, tid: ThreadId, frame: &mut SyscallFrame) {
    loop {
        if try_wait_thread(pid, tid, frame) {
            return;
        }
        let Some(parent_pointer) = process_pointer(pid) else {
            frame.rax = SYSCALL_ECHILD;
            return;
        };
        // SAFETY: the current process was registered before entering user mode and remains stable.
        let parent = unsafe { &*parent_pointer };
        parent
            .waiting_on_thread
            .store(u64::from(tid), Ordering::Release);
        if try_wait_thread(pid, tid, frame) {
            parent.waiting_on_thread.store(0, Ordering::Release);
            return;
        }
        parent.block_on_thread(tid);
        if thread_pointer(tid)
            .and_then(|pointer| {
                // SAFETY: the thread pointer is a registered, stable allocation.
                Some(unsafe { (&*pointer).state() })
            })
            .is_some_and(|state| matches!(state, ProcessState::Exited | ProcessState::Faulted))
        {
            wake_thread_waiter(pid, tid);
        }
        crate::scheduler::yield_current();
        parent.resume_from_wait();
    }
}

#[cfg(target_os = "none")]
fn wake_thread_waiter(pid: ProcessId, tid: ThreadId) {
    let Some(pointer) = process_pointer(pid) else {
        return;
    };
    // SAFETY: runtime registration keeps every process allocation stable for kernel lifetime.
    let parent = unsafe { &*pointer };
    if parent.waiting_on_thread.load(Ordering::Acquire) == u64::from(tid) {
        parent.waiting_on_thread.store(0, Ordering::Release);
        parent
            .state
            .store(ProcessState::Ready as u8, Ordering::Release);
        let _ = crate::scheduler::set_process_state(pid, ProcessState::Ready);
    }
}

#[cfg(target_os = "none")]
fn wake_waiter(parent_pid: ProcessId, child_pid: ProcessId) {
    if parent_pid == 0 {
        return;
    }
    let Some(pointer) = process_pointer(parent_pid) else {
        return;
    };
    // SAFETY: runtime registration keeps every process allocation stable for kernel lifetime.
    let parent = unsafe { &*pointer };
    if parent.waiting_on.load(Ordering::Acquire) == u64::from(child_pid) {
        parent.waiting_on.store(0, Ordering::Release);
        parent
            .state
            .store(ProcessState::Ready as u8, Ordering::Release);
        let _ = crate::scheduler::set_process_state(parent_pid, ProcessState::Ready);
        crate::kprintln!(
            "process: wake parent={} child={} status=ready",
            parent_pid,
            child_pid
        );
    }
}

#[cfg(target_os = "none")]
fn try_wait_child(parent_pid: ProcessId, child_pid: ProcessId, frame: &mut SyscallFrame) -> bool {
    let Some(pointer) = process_pointer(child_pid) else {
        frame.rax = SYSCALL_ECHILD;
        return true;
    };
    // SAFETY: runtime registration keeps every process allocation stable for kernel lifetime.
    let child = unsafe { &*pointer };
    if child.parent_pid != parent_pid {
        frame.rax = SYSCALL_ECHILD;
        return true;
    }
    match child.state() {
        ProcessState::Exited => {
            frame.rax = u64::from(child_pid);
            frame.rdx = child.exit_code().unwrap_or(0) as u64;
            true
        }
        ProcessState::Faulted => {
            frame.rax = SYSCALL_ECHILD;
            frame.rdx = SYSCALL_ECHILD;
            true
        }
        ProcessState::Ready | ProcessState::Running | ProcessState::Blocked => {
            frame.rax = SYSCALL_EAGAIN;
            false
        }
    }
}

#[cfg(target_os = "none")]
fn wait_for_child(parent_pid: ProcessId, child_pid: ProcessId, frame: &mut SyscallFrame) {
    loop {
        if try_wait_child(parent_pid, child_pid, frame) {
            return;
        }

        let Some(parent_pointer) = process_pointer(parent_pid) else {
            frame.rax = SYSCALL_ECHILD;
            return;
        };
        // SAFETY: the current process was registered before entering user mode and remains stable.
        let parent = unsafe { &*parent_pointer };
        parent
            .waiting_on
            .store(u64::from(child_pid), Ordering::Release);
        if try_wait_child(parent_pid, child_pid, frame) {
            parent.waiting_on.store(0, Ordering::Release);
            return;
        }

        parent.block_on(child_pid);
        // Close the check/block race: a child may have exited after the second check but before the
        // parent published Blocked to the scheduler.
        if process_pointer(child_pid)
            .and_then(|pointer| {
                // SAFETY: the child pointer is a registered, stable process allocation.
                Some(unsafe { (&*pointer).state() })
            })
            .is_some_and(|state| matches!(state, ProcessState::Exited | ProcessState::Faulted))
        {
            parent
                .waiting_on
                .store(u64::from(child_pid), Ordering::Release);
            wake_waiter(parent_pid, child_pid);
        }
        crate::scheduler::yield_current();
        parent.resume_from_wait();
    }
}

#[cfg(target_os = "none")]
pub fn runtime_process_ids() -> [Option<ProcessId>; PROCESS_TABLE_SIZE] {
    let mut ids = [None; PROCESS_TABLE_SIZE];
    for (pid, pointer) in PROCESS_POINTERS.iter().enumerate() {
        if pointer.load(Ordering::Acquire) != 0 {
            ids[pid] = Some(pid as ProcessId);
        }
    }
    ids
}

#[cfg(target_os = "none")]
pub fn runtime_thread_ids() -> [Option<ThreadId>; THREAD_TABLE_SIZE] {
    let mut ids = [None; THREAD_TABLE_SIZE];
    for (tid, pointer) in THREAD_POINTERS.iter().enumerate() {
        if pointer.load(Ordering::Acquire) != 0 {
            ids[tid] = Some(tid as ThreadId);
        }
    }
    ids
}

#[cfg(target_os = "none")]
pub fn runtime_process_stats(pid: ProcessId) -> Option<RuntimeProcessStats> {
    let pointer = process_pointer(pid)?;
    // SAFETY: runtime registration keeps every process allocation stable for kernel lifetime.
    let process = unsafe { &*pointer };
    Some(RuntimeProcessStats {
        pid: process.pid,
        parent_pid: process.parent_pid,
        uid: process.uid,
        gid: process.gid,
        origin: process.origin,
        executable: process.executable,
        state: process.state(),
        root_frame: process.address_space.root_frame.start_address().as_u64(),
        address_space_id: process.address_space.address_space_id(),
        address_space_reclaimed: process.address_space_reclaimed.load(Ordering::Acquire),
        entry: process.address_space.entry,
        exec_count: process.exec_count.load(Ordering::Acquire),
        fork_count: process.fork_count(),
        syscall_count: process.syscall_count(),
        open_count: process.open_count.load(Ordering::Acquire),
        read_count: process.read_count.load(Ordering::Acquire),
        read_bytes: process.read_bytes.load(Ordering::Acquire),
        data_read_count: process.data_read_count.load(Ordering::Acquire),
        close_count: process.close_count.load(Ordering::Acquire),
        file_write_count: process.file_write_count.load(Ordering::Acquire),
        file_write_bytes: process.file_write_bytes.load(Ordering::Acquire),
        file_create_count: process.file_create_count.load(Ordering::Acquire),
        process_snapshot_count: process.process_snapshot_count.load(Ordering::Acquire),
        file_snapshot_count: process.file_snapshot_count.load(Ordering::Acquire),
        yield_count: process.yield_count(),
        wait_count: process.wait_count(),
        wait_status_count: process.wait_status_count(),
        nonzero_wait_statuses: process.nonzero_wait_statuses(),
        last_wait_status: process.last_wait_status(),
        wait_blocks: process.wait_blocks(),
        thread_create_count: process.thread_create_count(),
        thread_join_count: process.thread_join_count(),
        last_return_result: process.last_return_result(),
        task_switches: process.task_switches(),
        last_cpu_apic_id: u32::try_from(process.last_cpu_apic_id.load(Ordering::Acquire))
            .unwrap_or(u32::MAX),
        exit_code: process.exit_code(),
    })
}

#[cfg(target_os = "none")]
pub fn runtime_thread_stats(tid: ThreadId) -> Option<RuntimeThreadStats> {
    let pointer = thread_pointer(tid)?;
    // SAFETY: runtime registration keeps every thread allocation stable for kernel lifetime.
    let thread = unsafe { &*pointer };
    Some(RuntimeThreadStats {
        tid: thread.tid,
        pid: thread.pid,
        state: thread.state(),
        entry: thread.entry,
        stack_top: thread.stack_top,
        syscall_count: thread.syscall_count.load(Ordering::Acquire),
        yield_count: thread.yield_count.load(Ordering::Acquire),
        task_switches: thread.task_switches.load(Ordering::Acquire),
        exit_code: thread.exit_code(),
    })
}

#[cfg(target_os = "none")]
pub fn note_task_switch(pid: ProcessId, apic_id: u32) {
    if let Some(pointer) = process_pointer(pid) {
        // SAFETY: the scheduler only records a counter on the registered process object.
        unsafe { (&*pointer).note_task_switch(apic_id) };
    }
}

#[cfg(target_os = "none")]
pub fn note_thread_task_switch(tid: ThreadId) {
    if let Some(pointer) = thread_pointer(tid) {
        // SAFETY: the scheduler only records a counter on the registered thread object.
        unsafe { (&*pointer).note_task_switch() };
    }
}

#[cfg(target_os = "none")]
pub fn run_registered_process(pid: ProcessId) -> ! {
    if let Some(pointer) = process_pointer(pid) {
        // SAFETY: runtime registration requires the caller to keep each process allocation stable;
        // the scheduler runs one task per registered process, so this pointer has one owner here.
        let result = unsafe { (&mut *pointer).run() };
        if let Err(error) = result {
            crate::kprintln!(
                "process: pid={} execution failed ({:?}) status=degraded",
                pid,
                error
            );
        }
    } else {
        crate::kprintln!("process: pid={} runtime registration missing", pid);
    }
    crate::interrupts::enable();
    loop {
        crate::interrupts::halt();
    }
}

#[cfg(target_os = "none")]
pub fn run_registered_thread(tid: ThreadId) -> ! {
    if let Some(thread_pointer) = thread_pointer(tid) {
        // SAFETY: runtime registration keeps each thread allocation stable; its owning process is
        // likewise a permanently registered allocation.
        let thread = unsafe { &*thread_pointer };
        if let Some(process_pointer) = process_pointer(thread.pid) {
            let process = unsafe { &*process_pointer };
            let result = thread.run(process);
            if let Err(error) = result {
                crate::kprintln!(
                    "process: tid={} execution failed ({:?}) status=degraded",
                    tid,
                    error
                );
            }
        } else {
            crate::kprintln!("process: tid={} owning process missing", tid);
        }
    } else {
        crate::kprintln!("process: tid={} runtime registration missing", tid);
    }
    crate::interrupts::enable();
    loop {
        crate::interrupts::halt();
    }
}

#[cfg(target_os = "none")]
fn set_tss_stack(stack_top: u64) {
    let cpu = PerCpuAtomicU64::current();
    let Some(tss) = USER_TSS[cpu].get() else {
        return;
    };
    let tss = tss as *const TaskStateSegment as *mut TaskStateSegment;
    // SAFETY: callers run with interrupts disabled while changing the active CPU's ring-0 stack;
    // the TSS is static and was installed before any user transition.
    unsafe {
        (*tss).privilege_stack_table[0] = VirtAddr::new(stack_top & !0xf);
    }
}

#[cfg(target_os = "none")]
pub fn prepare_task_switch(process_id: Option<ProcessId>) {
    match process_id {
        Some(pid) => {
            let Some(pointer) = process_pointer(pid) else {
                return;
            };
            // SAFETY: the process pointer was installed by register_runtime_process and remains
            // valid for the lifetime of the scheduler task.
            let process = unsafe { &*pointer };
            if process.address_space_reclaimed.load(Ordering::Acquire) {
                let kernel_frame = PhysFrame::containing_address(PhysAddr::new(
                    KERNEL_CR3.load(Ordering::Acquire),
                ));
                // A stale scheduler selection must never reactivate a reclaimed user root.
                unsafe {
                    Cr3::write(kernel_frame, Cr3Flags::empty());
                }
                return;
            }
            CURRENT_PROCESS_ID.store(u64::from(pid), Ordering::Release);
            CURRENT_THREAD_ID.store(u64::from(MAIN_THREAD_ID), Ordering::Release);
            set_tss_stack(process.kernel_stack_top());
            // SAFETY: every process root preserves the supervisor kernel mappings and is selected
            // only while the local interrupt gate has interrupts disabled.
            unsafe {
                Cr3::write(process.address_space.root_frame, Cr3Flags::empty());
            }
        }
        None => {
            CURRENT_PROCESS_ID.store(0, Ordering::Release);
            CURRENT_THREAD_ID.store(u64::from(MAIN_THREAD_ID), Ordering::Release);
            let stack_top = user_kernel_stack_top(PerCpuAtomicU64::current());
            set_tss_stack(stack_top);
            let kernel_frame =
                PhysFrame::containing_address(PhysAddr::new(KERNEL_CR3.load(Ordering::Acquire)));
            // SAFETY: KERNEL_CR3 is captured from the bootloader's active root before scheduling.
            unsafe {
                Cr3::write(kernel_frame, Cr3Flags::empty());
            }
        }
    }
}

#[cfg(target_os = "none")]
pub fn prepare_thread_task_switch(pid: ProcessId, tid: ThreadId) {
    let (Some(process_pointer), Some(thread_pointer)) = (process_pointer(pid), thread_pointer(tid))
    else {
        return;
    };
    // SAFETY: both pointers were registered before the scheduler task was created and remain
    // stable for the lifetime of the guest.
    let process = unsafe { &*process_pointer };
    let thread = unsafe { &*thread_pointer };
    if thread.pid != pid {
        return;
    }
    CURRENT_PROCESS_ID.store(u64::from(pid), Ordering::Release);
    CURRENT_THREAD_ID.store(u64::from(tid), Ordering::Release);
    set_tss_stack(thread.kernel_stack_top());
    // SAFETY: the shared process root preserves the supervisor mappings and is selected only with
    // interrupts disabled by the scheduler context-switch path.
    unsafe {
        Cr3::write(process.address_space.root_frame, Cr3Flags::empty());
    }
}

#[cfg(target_os = "none")]
fn dispatch_user_syscall(frame: &mut SyscallFrame) -> SyscallAction {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let action = match dispatch_syscall(pid, frame) {
        SyscallAction::Spawn => {
            frame.rax = spawn_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::SpawnAs => {
            frame.rax = spawn_as_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::SpawnPrivileged => {
            frame.rax = spawn_privileged_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GetCredentials => {
            credentials_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::Pipe => {
            pipe_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::Wait => {
            let child_pid = ProcessId::try_from(frame.rdi).unwrap_or(0);
            wait_for_child(pid, child_pid, frame);
            if let Some(pointer) = process_pointer(pid) {
                // SAFETY: the current process was registered before entering user mode.
                let process = unsafe { &*pointer };
                process.note_wait();
                if frame.rax < SYSCALL_ERROR_MIN {
                    process.note_wait_status(frame.rdx);
                }
            }
            SyscallAction::Return
        }
        SyscallAction::WaitpidNonblocking => {
            let child_pid = ProcessId::try_from(frame.rdi).unwrap_or(0);
            let _ = try_wait_child(pid, child_pid, frame);
            SyscallAction::Return
        }
        SyscallAction::Write => {
            write_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::Open => {
            frame.rax = open_for_syscall(frame.rdi, frame.rsi);
            SyscallAction::Return
        }
        SyscallAction::Read => {
            read_for_syscall(frame, false);
            SyscallAction::Return
        }
        SyscallAction::ReadNonblocking => {
            read_for_syscall(frame, true);
            SyscallAction::Return
        }
        SyscallAction::Close => {
            close_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::ThreadCreate => {
            create_thread_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::ThreadJoin => {
            if CURRENT_THREAD_ID.load(Ordering::Acquire) != u64::from(MAIN_THREAD_ID) {
                frame.rax = SYSCALL_EINVAL;
            } else {
                let tid = ThreadId::try_from(frame.rdi).unwrap_or(MAIN_THREAD_ID);
                wait_for_thread(pid, tid, frame);
                if let Some(pointer) = process_pointer(pid) {
                    // SAFETY: the current process was registered before entering user mode.
                    unsafe { (&*pointer).note_thread_join() };
                }
            }
            SyscallAction::Return
        }
        SyscallAction::ThreadExit => {
            if CURRENT_THREAD_ID.load(Ordering::Acquire) == u64::from(MAIN_THREAD_ID) {
                frame.rax = SYSCALL_EINVAL;
                SyscallAction::Return
            } else {
                frame.rax = 0;
                SyscallAction::ThreadExit
            }
        }
        SyscallAction::Exec => {
            let result = exec_for_syscall(frame.rdi);
            if result == 0 {
                SyscallAction::Exec
            } else {
                frame.rax = result;
                SyscallAction::Return
            }
        }
        SyscallAction::Fork => {
            frame.rax = fork_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::ListProcesses => {
            list_processes_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::ListFiles => {
            list_files_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::Mkdir => {
            frame.rax = mkdir_for_syscall(frame.rdi);
            SyscallAction::Return
        }
        SyscallAction::PathInfo => {
            path_info_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::Mmap => {
            mmap_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::Munmap => {
            munmap_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::NetSend => {
            network_send_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::NetReceive => {
            network_receive_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::NetInfo => {
            network_info_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::NetInterfaces => {
            network_interfaces_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::NetRenew => {
            network_renew_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxInfo => {
            graphics_info_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxAcquire => {
            graphics_acquire_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxFillRect => {
            graphics_fill_rect_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxText => {
            graphics_text_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxRelease => {
            graphics_release_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::InputRead => {
            input_read_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowCreate => {
            graphics_window_create_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowClear => {
            graphics_window_clear_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowFillRect => {
            graphics_window_fill_rect_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowText => {
            graphics_window_text_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowPresent => {
            graphics_window_present_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowFocus => {
            graphics_window_focus_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowDestroy => {
            graphics_window_destroy_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowGetGeometry => {
            graphics_window_get_geometry_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowConfigure => {
            graphics_window_configure_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowRequestClose => {
            graphics_window_request_close_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::Poweroff => {
            if crate::power::diagnostics().ready {
                frame.rax = 0;
                crate::kprintln!("power: ACPI S5 shutdown requested status=ready");
                SyscallAction::Poweroff
            } else {
                frame.rax = SYSCALL_ENOSYS;
                SyscallAction::Return
            }
        }
        SyscallAction::Reboot => {
            if crate::power::diagnostics().reboot_ready {
                frame.rax = 0;
                crate::kprintln!("power: ACPI reset requested status=ready");
                SyscallAction::Reboot
            } else {
                frame.rax = SYSCALL_ENOSYS;
                SyscallAction::Return
            }
        }
        SyscallAction::Suspend => {
            let diagnostics = crate::power::diagnostics();
            if diagnostics.suspend_ready {
                frame.rax = 0;
                crate::kprintln!(
                    "power: ACPI S3 suspend requested status=ready vector={}",
                    if diagnostics.native_wake_ready {
                        "native"
                    } else {
                        "legacy"
                    }
                );
                SyscallAction::Suspend
            } else {
                frame.rax = SYSCALL_ENOSYS;
                SyscallAction::Return
            }
        }
        SyscallAction::GfxComposeWindows => {
            graphics_compose_windows_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowDispatchPointer => {
            graphics_window_dispatch_pointer_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowReadEvent => {
            graphics_window_read_event_for_syscall(frame);
            SyscallAction::Return
        }
        SyscallAction::GfxWindowDispatchKeyboard => {
            graphics_window_dispatch_keyboard_for_syscall(frame);
            SyscallAction::Return
        }
        action => action,
    };
    if let Some(pointer) = process_pointer(pid) {
        // SAFETY: the current syscall was entered by the process selected in CURRENT_PROCESS_ID.
        unsafe { (&*pointer).record_syscall(frame, action) };
    }
    let tid =
        ThreadId::try_from(CURRENT_THREAD_ID.load(Ordering::Acquire)).unwrap_or(MAIN_THREAD_ID);
    if tid != MAIN_THREAD_ID {
        if let Some(pointer) = thread_pointer(tid) {
            // SAFETY: the current thread pointer was registered before entering user mode.
            unsafe { (&*pointer).record_syscall(frame, action) };
        }
    }
    action
}

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn rustos_user_syscall_dispatch(frame: *mut SyscallFrame) -> u64 {
    // SAFETY: the syscall entry stub passes a pointer to its complete, stack-resident register
    // frame and does not reclaim that frame until this function returns.
    let frame = unsafe { &mut *frame };
    match dispatch_user_syscall(frame) {
        SyscallAction::Return => 0,
        SyscallAction::Yield => {
            crate::scheduler::yield_current();
            0
        }
        SyscallAction::Exit => 1,
        SyscallAction::Spawn => unreachable!("spawn syscall must be resolved before returning"),
        SyscallAction::SpawnAs => {
            unreachable!("spawn-as syscall must be resolved before returning")
        }
        SyscallAction::SpawnPrivileged => {
            unreachable!("privileged-spawn syscall must be resolved before returning")
        }
        SyscallAction::GetCredentials => {
            unreachable!("credentials syscall must be resolved before returning")
        }
        SyscallAction::Pipe => unreachable!("pipe syscall must be resolved before returning"),
        SyscallAction::Wait => unreachable!("waitpid syscall must be resolved before returning"),
        SyscallAction::WaitpidNonblocking => {
            unreachable!("nonblocking waitpid syscall must be resolved before returning")
        }
        SyscallAction::Write => unreachable!("write syscall must be resolved before returning"),
        SyscallAction::Open => unreachable!("open syscall must be resolved before returning"),
        SyscallAction::Read => unreachable!("read syscall must be resolved before returning"),
        SyscallAction::ReadNonblocking => {
            unreachable!("nonblocking read syscall must be resolved before returning")
        }
        SyscallAction::Close => unreachable!("close syscall must be resolved before returning"),
        SyscallAction::ThreadCreate => {
            unreachable!("thread create syscall must be resolved before returning")
        }
        SyscallAction::ThreadJoin => {
            unreachable!("thread join syscall must be resolved before returning")
        }
        SyscallAction::ThreadExit => 1,
        SyscallAction::Exec => 1,
        SyscallAction::Fork => unreachable!("fork syscall must be resolved before returning"),
        SyscallAction::ListProcesses => {
            unreachable!("process-list syscall must be resolved before returning")
        }
        SyscallAction::ListFiles => {
            unreachable!("file-list syscall must be resolved before returning")
        }
        SyscallAction::Mkdir => unreachable!("mkdir syscall must be resolved before returning"),
        SyscallAction::PathInfo => {
            unreachable!("path-info syscall must be resolved before returning")
        }
        SyscallAction::Mmap => unreachable!("mmap syscall must be resolved before returning"),
        SyscallAction::Munmap => unreachable!("munmap syscall must be resolved before returning"),
        SyscallAction::NetSend => {
            unreachable!("network-send syscall must be resolved before returning")
        }
        SyscallAction::NetReceive => {
            unreachable!("network-receive syscall must be resolved before returning")
        }
        SyscallAction::NetInfo => {
            unreachable!("network-info syscall must be resolved before returning")
        }
        SyscallAction::NetInterfaces => {
            unreachable!("network-interfaces syscall must be resolved before returning")
        }
        SyscallAction::NetRenew => {
            unreachable!("network-renew syscall must be resolved before returning")
        }
        SyscallAction::GfxInfo => {
            unreachable!("graphics-info syscall must be resolved before returning")
        }
        SyscallAction::GfxAcquire => {
            unreachable!("graphics-acquire syscall must be resolved before returning")
        }
        SyscallAction::GfxFillRect => {
            unreachable!("graphics-fill-rect syscall must be resolved before returning")
        }
        SyscallAction::GfxText => {
            unreachable!("graphics-text syscall must be resolved before returning")
        }
        SyscallAction::GfxRelease => {
            unreachable!("graphics-release syscall must be resolved before returning")
        }
        SyscallAction::InputRead => {
            unreachable!("input-read syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowCreate => {
            unreachable!("graphics-window-create syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowClear => {
            unreachable!("graphics-window-clear syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowFillRect => {
            unreachable!("graphics-window-fill-rect syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowText => {
            unreachable!("graphics-window-text syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowPresent => {
            unreachable!("graphics-window-present syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowFocus => {
            unreachable!("graphics-window-focus syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowDestroy => {
            unreachable!("graphics-window-destroy syscall must be resolved before returning")
        }
        SyscallAction::GfxComposeWindows => {
            unreachable!("graphics-compose-windows syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowDispatchPointer => {
            unreachable!(
                "graphics-window-dispatch-pointer syscall must be resolved before returning"
            )
        }
        SyscallAction::GfxWindowReadEvent => {
            unreachable!("graphics-window-read-event syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowDispatchKeyboard => {
            unreachable!(
                "graphics-window-dispatch-keyboard syscall must be resolved before returning"
            )
        }
        SyscallAction::GfxWindowGetGeometry => {
            unreachable!("graphics-window-get-geometry syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowConfigure => {
            unreachable!("graphics-window-configure syscall must be resolved before returning")
        }
        SyscallAction::GfxWindowRequestClose => {
            unreachable!("graphics-window-request-close syscall must be resolved before returning")
        }
        SyscallAction::Poweroff => crate::power::poweroff(),
        SyscallAction::Reboot => crate::power::reboot(),
        SyscallAction::Suspend => {
            if crate::power::suspend() {
                frame.rax = 0;
                crate::kprintln!("power: ACPI S3 resume status=ready");
            } else {
                frame.rax = SYSCALL_ENOSYS;
            }
            0
        }
    }
}

#[cfg(target_os = "none")]
struct UserFrameAllocator<'a> {
    frames: crate::memory::FrameAllocator<'a>,
    recycled_frames: Vec<PhysFrame<Size4KiB>>,
}

#[cfg(target_os = "none")]
impl UserFrameAllocator<'_> {
    fn new(
        regions: &[MemoryRegion],
        next_frame_address: Option<u64>,
        recycled_frames: Vec<PhysFrame<Size4KiB>>,
    ) -> UserFrameAllocator<'_> {
        UserFrameAllocator {
            frames: crate::memory::FrameAllocator::starting_at(
                regions,
                next_frame_address.unwrap_or(0),
            ),
            recycled_frames,
        }
    }

    fn next_available_address(&self) -> Option<u64> {
        self.frames.next_available_address()
    }

    fn recycle_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        self.recycled_frames.push(frame);
    }

    fn into_recycled_frames(self) -> Vec<PhysFrame<Size4KiB>> {
        self.recycled_frames
    }
}

#[cfg(target_os = "none")]
impl<'a> UserFrameAllocator<'a> {
    fn allocate_leaf_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.recycled_frames.pop().or_else(|| {
            self.frames
                .next()
                .map(|frame| PhysFrame::containing_address(PhysAddr::new(frame.start_address())))
        })
    }

    fn page_table_allocator<'b>(&'b mut self) -> PageTableFrameAllocator<'b, 'a> {
        PageTableFrameAllocator {
            frames: &mut self.frames,
        }
    }
}

#[cfg(target_os = "none")]
struct PageTableFrameAllocator<'a, 'b> {
    frames: &'a mut crate::memory::FrameAllocator<'b>,
}

#[cfg(target_os = "none")]
unsafe impl PagingFrameAllocator<Size4KiB> for PageTableFrameAllocator<'_, '_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.frames
            .next()
            .map(|frame| PhysFrame::containing_address(PhysAddr::new(frame.start_address())))
    }
}

#[cfg(target_os = "none")]
unsafe fn kernel_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    let kernel_frame = if KERNEL_CR3.load(Ordering::Acquire) == 0 {
        Cr3::read().0
    } else {
        PhysFrame::containing_address(PhysAddr::new(KERNEL_CR3.load(Ordering::Acquire)))
    };
    let table_address = physical_memory_offset + kernel_frame.start_address().as_u64();
    unsafe { &mut *table_address.as_mut_ptr() }
}

#[cfg(target_os = "none")]
unsafe fn zero_frame(frame: PhysFrame<Size4KiB>, physical_memory_offset: u64) {
    let address = physical_memory_offset + frame.start_address().as_u64();
    unsafe { core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize) };
}

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserModeStats {
    pub kernel_code: u16,
    pub user_code: u16,
    pub user_data: u16,
    pub tss: u16,
}

#[cfg(target_os = "none")]
struct UserGdt {
    table: GlobalDescriptorTable,
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    user_code: SegmentSelector,
    user_data: SegmentSelector,
    tss: SegmentSelector,
}

#[cfg(target_os = "none")]
pub fn init_user_mode() -> UserModeStats {
    let (kernel_frame, _) = Cr3::read();
    KERNEL_CR3.store(kernel_frame.start_address().as_u64(), Ordering::Release);
    init_user_mode_current_cpu()
}

#[cfg(target_os = "none")]
pub fn init_user_mode_current_cpu() -> UserModeStats {
    let cpu = PerCpuAtomicU64::current();
    let tss = USER_TSS[cpu].call_once(|| {
        let mut tss = TaskStateSegment::new();
        let stack_top = user_kernel_stack_top(cpu);
        tss.privilege_stack_table[0] = VirtAddr::new(stack_top & !0xf);
        tss
    });
    let gdt = USER_GDT[cpu].call_once(|| {
        let mut table = GlobalDescriptorTable::new();
        let kernel_code = table.append(Descriptor::kernel_code_segment());
        let kernel_data = table.append(Descriptor::kernel_data_segment());
        let user_code = table.append(Descriptor::user_code_segment());
        let user_data = table.append(Descriptor::user_data_segment());
        let tss_selector = table.append(Descriptor::tss_segment(tss));
        UserGdt {
            table,
            kernel_code,
            kernel_data,
            user_code,
            user_data,
            tss: tss_selector,
        }
    });
    load_user_mode(gdt);
    UserModeStats {
        kernel_code: gdt.kernel_code.0,
        user_code: gdt.user_code.0,
        user_data: gdt.user_data.0,
        tss: gdt.tss.0,
    }
}

#[cfg(target_os = "none")]
fn user_kernel_stack_top(cpu: usize) -> u64 {
    if cpu == 0 {
        // SAFETY: CPU 0 owns this bootstrap stack for the lifetime of the kernel; its TSS is only
        // updated by CPU 0 while interrupts are disabled.
        return (unsafe {
            core::ptr::addr_of_mut!(BOOT_USER_KERNEL_STACK)
                .cast::<u8>()
                .add(USER_KERNEL_STACK_SIZE) as u64
        }) & !0xf;
    }
    let stack =
        USER_KERNEL_STACKS[cpu].call_once(|| vec![0; USER_KERNEL_STACK_SIZE].into_boxed_slice());
    (stack.as_ptr() as u64 + USER_KERNEL_STACK_SIZE as u64) & !0xf
}

#[cfg(target_os = "none")]
fn load_user_mode(gdt: &UserGdt) {
    // SAFETY: every caller obtains this GDT from a process-global `Once` slot whose storage lives
    // for the entire kernel lifetime; `GlobalDescriptorTable::load` requires that lifetime because
    // the CPU retains the descriptor-table address after this function returns.
    let gdt: &'static UserGdt = unsafe { &*(gdt as *const UserGdt) };
    gdt.table.load();
    // The TSS descriptor becomes busy after `ltr`; clear that bit before reloading the same
    // per-CPU descriptor during a repeated initialization or firmware resume.
    let tss_entry_index = usize::from(gdt.tss.0 / 8);
    if let Some(tss_entry) = gdt.table.entries().get(tss_entry_index) {
        let tss_entry_raw = tss_entry.raw();
        if tss_entry_raw & (1 << 41) != 0 {
            let tss_entry_atomic = tss_entry as *const _ as *const AtomicU64;
            // SAFETY: GDT entries are backed by AtomicU64 values in x86_64's representation, and
            // the table remains live for the duration of the restored CPU context.
            unsafe { (*tss_entry_atomic).fetch_and(!(1 << 41), Ordering::SeqCst) };
        }
    }
    unsafe {
        x86_64::instructions::tables::load_tss(gdt.tss);
        use x86_64::instructions::segmentation::{CS, DS, ES, FS, GS, SS, Segment};
        CS::set_reg(gdt.kernel_code);
        SS::set_reg(gdt.kernel_data);
        DS::set_reg(gdt.kernel_data);
        ES::set_reg(gdt.kernel_data);
        FS::set_reg(gdt.kernel_data);
        GS::set_reg(gdt.kernel_data);
    }
}

#[cfg(target_os = "none")]
pub fn reload_user_mode() {
    let cpu = PerCpuAtomicU64::current();
    let Some(gdt) = USER_GDT[cpu].get() else {
        return;
    };
    load_user_mode(gdt);
}

#[cfg(target_os = "none")]
pub fn syscall_entry_address() -> u64 {
    rustos_syscall_entry as *const () as usize as u64
}

#[cfg(target_os = "none")]
fn run_user_context(
    address_space: &UserAddressSpace,
    entry: u64,
    stack_top: u64,
    return_stack: &AtomicU64,
    user_argument: u64,
) -> Result<(), AddressSpaceError> {
    let cpu = PerCpuAtomicU64::current();
    let gdt = USER_GDT[cpu]
        .get()
        .ok_or(AddressSpaceError::ModeNotInitialized)?;
    x86_64::instructions::interrupts::disable();
    unsafe {
        rustos_enter_user(
            address_space.root_frame.start_address().as_u64(),
            u64::from(gdt.user_code.0),
            u64::from(gdt.user_data.0),
            stack_top - 16,
            entry,
            return_stack,
            user_argument,
        );
    }
    x86_64::instructions::interrupts::enable();
    Ok(())
}

#[cfg(target_os = "none")]
fn run_user_context_from_context(
    address_space: &UserAddressSpace,
    context: &ForkContext,
    return_stack: &AtomicU64,
) -> Result<(), AddressSpaceError> {
    let cpu = PerCpuAtomicU64::current();
    let _gdt = USER_GDT[cpu]
        .get()
        .ok_or(AddressSpaceError::ModeNotInitialized)?;
    x86_64::instructions::interrupts::disable();
    unsafe {
        rustos_enter_user_context(
            address_space.root_frame.start_address().as_u64(),
            context,
            return_stack,
        );
    }
    x86_64::instructions::interrupts::enable();
    Ok(())
}

#[cfg(target_os = "none")]
pub fn exit_user() -> ! {
    let pid = ProcessId::try_from(CURRENT_PROCESS_ID.load(Ordering::Acquire)).unwrap_or(0);
    let kernel_frame: PhysFrame<Size4KiB> =
        PhysFrame::containing_address(PhysAddr::new(KERNEL_CR3.load(Ordering::Acquire)));
    let tid =
        ThreadId::try_from(CURRENT_THREAD_ID.load(Ordering::Acquire)).unwrap_or(MAIN_THREAD_ID);
    if tid == MAIN_THREAD_ID {
        let pointer = process_pointer(pid).unwrap_or_else(|| {
            loop {
                crate::interrupts::halt();
            }
        });
        // SAFETY: the current process pointer and its return stack were installed before ring-3
        // entry.
        let process = unsafe { &*pointer };
        unsafe { rustos_leave_user(kernel_frame.start_address().as_u64(), &process.return_stack) }
    } else {
        let pointer = thread_pointer(tid).unwrap_or_else(|| {
            loop {
                crate::interrupts::halt();
            }
        });
        // SAFETY: the current thread pointer and its return stack were installed before ring-3
        // entry.
        let thread = unsafe { &*pointer };
        unsafe { rustos_leave_user(kernel_frame.start_address().as_u64(), &thread.return_stack) }
    }
}

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn rustos_user_process_exit() -> ! {
    exit_user()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_built_in_init_image() {
        let image = parse_elf64(&USER_INIT_ELF).unwrap();
        assert_eq!(image.entry, USER_IMAGE_BASE);
        assert_eq!(image.segments().len(), 2);
        assert_eq!(image.segments()[0].file_size, USER_INIT_CODE.len() as u64);
        assert!(image.segments()[0].flags & ELF_FLAG_EXECUTABLE != 0);
        assert_eq!(
            image.segments()[1].file_size,
            USER_INIT_PROGRAM_DATA_LENGTH as u64
        );
        assert!(image.segments()[1].flags & ELF_FLAG_WRITABLE != 0);
    }

    #[test]
    fn init_image_embeds_the_userland_init_path() {
        let config_start = USER_INIT_DATA_OFFSET;
        let config_end = config_start + USER_INIT_EXEC_PATH.len();
        assert_eq!(
            &USER_INIT_ELF[config_start..config_end],
            USER_INIT_EXEC_PATH
        );
    }

    #[test]
    fn parses_the_preemptible_worker_image() {
        let image = parse_elf64(&USER_WORKER_ELF).unwrap();
        assert_eq!(image.entry, USER_IMAGE_BASE);
        assert_eq!(image.segments().len(), 1);
        assert_eq!(image.segments()[0].file_size, USER_WORKER_CODE.len() as u64);
        assert!(image.segments()[0].flags & ELF_FLAG_EXECUTABLE != 0);
    }

    #[test]
    fn unknown_process_state_values_are_faulted() {
        assert_eq!(
            ProcessState::from_raw(ProcessState::Ready as u8),
            ProcessState::Ready
        );
        assert_eq!(
            ProcessState::from_raw(ProcessState::Blocked as u8),
            ProcessState::Blocked
        );
        assert_eq!(ProcessState::from_raw(0xff), ProcessState::Faulted);
    }

    #[test]
    fn rejects_invalid_elf_headers_and_entries() {
        let mut image = USER_INIT_ELF;
        image[0] = 0;
        assert_eq!(parse_elf64(&image), Err(ElfError::InvalidMagic));

        let mut image = USER_INIT_ELF;
        put_u64(&mut image, 24, USER_SPACE_END);
        assert_eq!(parse_elf64(&image), Err(ElfError::InvalidEntry));
    }

    #[test]
    fn rejects_segment_file_and_memory_invariants() {
        let mut image = USER_INIT_ELF;
        put_u64(&mut image, ELF_HEADER_SIZE + 32, PAGE_SIZE + 1);
        assert_eq!(parse_elf64(&image), Err(ElfError::InvalidSegment));

        let mut image = USER_INIT_ELF;
        put_u64(&mut image, ELF_HEADER_SIZE + 40, 0);
        assert_eq!(parse_elf64(&image), Err(ElfError::InvalidSegment));
    }

    #[test]
    fn syscall_abi_returns_pid_and_yield_result() {
        let mut getpid = SyscallFrame {
            rax: SYS_GETPID,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(42, &mut getpid), SyscallAction::Return);
        assert_eq!(getpid.rax, 42);

        let mut yield_call = SyscallFrame {
            rax: SYS_YIELD,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(42, &mut yield_call), SyscallAction::Yield);
        assert_eq!(yield_call.rax, 0);
    }

    #[test]
    fn syscall_abi_marks_spawn_for_kernel_resolution() {
        let mut spawn = SyscallFrame {
            rax: SYS_SPAWN,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut spawn), SyscallAction::Spawn);
        assert_eq!(spawn.rax, SYS_SPAWN);
    }

    #[test]
    fn syscall_abi_marks_credentials_operations_for_kernel_resolution() {
        let mut credentials = SyscallFrame {
            rax: SYS_GETCREDENTIALS,
            ..SyscallFrame::default()
        };
        assert_eq!(
            dispatch_syscall(1, &mut credentials),
            SyscallAction::GetCredentials
        );
        assert_eq!(credentials.rax, SYS_GETCREDENTIALS);

        let mut spawn_as = SyscallFrame {
            rax: SYS_SPAWN_AS,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut spawn_as), SyscallAction::SpawnAs);
        assert_eq!(spawn_as.rax, SYS_SPAWN_AS);

        let mut privileged_spawn = SyscallFrame {
            rax: SYS_SPAWN_PRIVILEGED,
            ..SyscallFrame::default()
        };
        assert_eq!(
            dispatch_syscall(1, &mut privileged_spawn),
            SyscallAction::SpawnPrivileged
        );
        assert_eq!(privileged_spawn.rax, SYS_SPAWN_PRIVILEGED);
    }

    #[test]
    fn permission_policy_distinguishes_system_and_user_paths() {
        assert!(mode_allows(
            0o100755,
            ROOT_UID,
            ROOT_GID,
            1000,
            1000,
            AccessKind::Execute
        ));
        assert!(mode_allows(
            0o100644,
            ROOT_UID,
            ROOT_GID,
            1000,
            1000,
            AccessKind::Read
        ));
        assert!(!mode_allows(
            0o100644,
            ROOT_UID,
            ROOT_GID,
            1000,
            1000,
            AccessKind::Write
        ));
        assert!(runtime_access_allowed(
            b"/home/user/work/note",
            1000,
            AccessKind::Write
        ));
        assert!(!runtime_access_allowed(
            b"/etc/rustos/config.txt",
            1000,
            AccessKind::Write
        ));
    }

    #[test]
    fn syscall_abi_marks_pipe_for_kernel_resolution() {
        let mut pipe = SyscallFrame {
            rax: SYS_PIPE,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut pipe), SyscallAction::Pipe);
        assert_eq!(pipe.rax, SYS_PIPE);
    }

    #[test]
    fn syscall_abi_marks_memory_mapping_operations_for_kernel_resolution() {
        let mut mmap = SyscallFrame {
            rax: SYS_MMAP,
            rdi: 3 * PAGE_SIZE,
            rsi: 1,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut mmap), SyscallAction::Mmap);
        assert_eq!(mmap.rax, SYS_MMAP);

        let mut munmap = SyscallFrame {
            rax: SYS_MUNMAP,
            rdi: USER_IMAGE_BASE + 0x0100_0000,
            rsi: 3 * PAGE_SIZE,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut munmap), SyscallAction::Munmap);
        assert_eq!(munmap.rax, SYS_MUNMAP);
    }

    #[test]
    fn syscall_abi_marks_network_operations_for_kernel_resolution() {
        for syscall in [
            SYS_NET_SEND,
            SYS_NET_RECEIVE,
            SYS_NET_INFO,
            SYS_NET_INTERFACES,
            SYS_NET_RENEW,
        ] {
            let mut frame = SyscallFrame {
                rax: syscall,
                rdi: USER_IMAGE_BASE,
                rsi: USER_IMAGE_BASE + 0x100,
                rdx: 12,
                ..SyscallFrame::default()
            };
            let action = dispatch_syscall(1, &mut frame);
            assert_eq!(
                action,
                match syscall {
                    SYS_NET_SEND => SyscallAction::NetSend,
                    SYS_NET_RECEIVE => SyscallAction::NetReceive,
                    SYS_NET_INFO => SyscallAction::NetInfo,
                    SYS_NET_INTERFACES => SyscallAction::NetInterfaces,
                    SYS_NET_RENEW => SyscallAction::NetRenew,
                    _ => unreachable!(),
                }
            );
            assert_eq!(frame.rax, syscall);
        }
    }

    #[test]
    fn syscall_abi_marks_graphics_operations_for_kernel_resolution() {
        for syscall in [
            SYS_GFX_INFO,
            SYS_GFX_ACQUIRE,
            SYS_GFX_FILL_RECT,
            SYS_GFX_TEXT,
            SYS_GFX_RELEASE,
        ] {
            let mut frame = SyscallFrame {
                rax: syscall,
                rdi: USER_IMAGE_BASE,
                rsi: 32,
                ..SyscallFrame::default()
            };
            let action = dispatch_syscall(1, &mut frame);
            assert_eq!(
                action,
                match syscall {
                    SYS_GFX_INFO => SyscallAction::GfxInfo,
                    SYS_GFX_ACQUIRE => SyscallAction::GfxAcquire,
                    SYS_GFX_FILL_RECT => SyscallAction::GfxFillRect,
                    SYS_GFX_TEXT => SyscallAction::GfxText,
                    SYS_GFX_RELEASE => SyscallAction::GfxRelease,
                    _ => unreachable!(),
                }
            );
            assert_eq!(frame.rax, syscall);
        }
    }

    #[test]
    fn syscall_abi_marks_input_reads_for_kernel_resolution() {
        let mut frame = SyscallFrame {
            rax: SYS_INPUT_READ,
            rdi: USER_IMAGE_BASE,
            rsi: 20,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut frame), SyscallAction::InputRead);
        assert_eq!(frame.rax, SYS_INPUT_READ);
    }

    #[test]
    fn syscall_abi_marks_window_operations_for_kernel_resolution() {
        for syscall in [
            SYS_GFX_WINDOW_CREATE,
            SYS_GFX_WINDOW_CLEAR,
            SYS_GFX_WINDOW_FILL_RECT,
            SYS_GFX_WINDOW_TEXT,
            SYS_GFX_WINDOW_PRESENT,
            SYS_GFX_WINDOW_DESTROY,
            SYS_GFX_COMPOSE_WINDOWS,
            SYS_GFX_WINDOW_DISPATCH_POINTER,
            SYS_GFX_WINDOW_READ_EVENT,
            SYS_GFX_WINDOW_DISPATCH_KEYBOARD,
            SYS_GFX_WINDOW_GET_GEOMETRY,
            SYS_GFX_WINDOW_CONFIGURE,
            SYS_GFX_WINDOW_REQUEST_CLOSE,
            SYS_GFX_WINDOW_FOCUS,
        ] {
            let mut frame = SyscallFrame {
                rax: syscall,
                rdi: USER_IMAGE_BASE,
                rsi: USER_IMAGE_BASE + 0x100,
                rdx: 32,
                ..SyscallFrame::default()
            };
            let action = dispatch_syscall(1, &mut frame);
            assert_eq!(
                action,
                match syscall {
                    SYS_GFX_WINDOW_CREATE => SyscallAction::GfxWindowCreate,
                    SYS_GFX_WINDOW_CLEAR => SyscallAction::GfxWindowClear,
                    SYS_GFX_WINDOW_FILL_RECT => SyscallAction::GfxWindowFillRect,
                    SYS_GFX_WINDOW_TEXT => SyscallAction::GfxWindowText,
                    SYS_GFX_WINDOW_PRESENT => SyscallAction::GfxWindowPresent,
                    SYS_GFX_WINDOW_DESTROY => SyscallAction::GfxWindowDestroy,
                    SYS_GFX_COMPOSE_WINDOWS => SyscallAction::GfxComposeWindows,
                    SYS_GFX_WINDOW_DISPATCH_POINTER => SyscallAction::GfxWindowDispatchPointer,
                    SYS_GFX_WINDOW_READ_EVENT => SyscallAction::GfxWindowReadEvent,
                    SYS_GFX_WINDOW_DISPATCH_KEYBOARD => SyscallAction::GfxWindowDispatchKeyboard,
                    SYS_GFX_WINDOW_GET_GEOMETRY => SyscallAction::GfxWindowGetGeometry,
                    SYS_GFX_WINDOW_CONFIGURE => SyscallAction::GfxWindowConfigure,
                    SYS_GFX_WINDOW_REQUEST_CLOSE => SyscallAction::GfxWindowRequestClose,
                    SYS_GFX_WINDOW_FOCUS => SyscallAction::GfxWindowFocus,
                    _ => unreachable!(),
                }
            );
            assert_eq!(frame.rax, syscall);
        }
    }

    #[test]
    fn syscall_abi_marks_waitpid_for_kernel_resolution() {
        let mut wait = SyscallFrame {
            rax: SYS_WAITPID,
            rdi: 2,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut wait), SyscallAction::Wait);
        assert_eq!(wait.rdi, 2);
    }

    #[test]
    fn syscall_abi_marks_nonblocking_io_for_kernel_resolution() {
        let mut read = SyscallFrame {
            rax: SYS_READ_NONBLOCK,
            rdi: 3,
            rsi: USER_IMAGE_BASE,
            rdx: 4,
            ..SyscallFrame::default()
        };
        assert_eq!(
            dispatch_syscall(1, &mut read),
            SyscallAction::ReadNonblocking
        );
        assert_eq!(read.rax, SYS_READ_NONBLOCK);

        let mut wait = SyscallFrame {
            rax: SYS_WAITPID_NONBLOCK,
            rdi: 2,
            ..SyscallFrame::default()
        };
        assert_eq!(
            dispatch_syscall(1, &mut wait),
            SyscallAction::WaitpidNonblocking
        );
        assert_eq!(wait.rdi, 2);
    }

    #[test]
    fn syscall_abi_marks_poweroff_for_kernel_resolution() {
        let mut poweroff = SyscallFrame {
            rax: SYS_POWEROFF,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut poweroff), SyscallAction::Poweroff);
        assert_eq!(poweroff.rax, SYS_POWEROFF);
    }

    #[test]
    fn syscall_abi_marks_reboot_for_kernel_resolution() {
        let mut reboot = SyscallFrame {
            rax: SYS_REBOOT,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut reboot), SyscallAction::Reboot);
        assert_eq!(reboot.rax, SYS_REBOOT);
    }

    #[test]
    fn syscall_abi_marks_suspend_for_kernel_resolution() {
        let mut suspend = SyscallFrame {
            rax: SYS_SUSPEND,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut suspend), SyscallAction::Suspend);
        assert_eq!(suspend.rax, SYS_SUSPEND);
    }

    #[test]
    fn syscall_abi_marks_write_for_kernel_resolution() {
        let mut write = SyscallFrame {
            rax: SYS_WRITE,
            rdi: USER_STDOUT_FD,
            rsi: USER_IMAGE_BASE,
            rdx: 4,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut write), SyscallAction::Write);
        assert_eq!(write.rax, SYS_WRITE);
    }

    #[test]
    fn syscall_abi_marks_file_handle_operations_for_kernel_resolution() {
        for syscall in [SYS_OPEN, SYS_READ, SYS_CLOSE] {
            let mut frame = SyscallFrame {
                rax: syscall,
                ..SyscallFrame::default()
            };
            let action = dispatch_syscall(1, &mut frame);
            assert_eq!(
                action,
                match syscall {
                    SYS_OPEN => SyscallAction::Open,
                    SYS_READ => SyscallAction::Read,
                    SYS_CLOSE => SyscallAction::Close,
                    _ => unreachable!(),
                }
            );
            assert_eq!(frame.rax, syscall);
        }
    }

    #[test]
    fn syscall_abi_marks_diagnostic_snapshots_for_kernel_resolution() {
        for syscall in [SYS_LIST_PROCESSES, SYS_LIST_FILES] {
            let mut frame = SyscallFrame {
                rax: syscall,
                rdi: USER_IMAGE_BASE,
                rsi: 4096,
                ..SyscallFrame::default()
            };
            let action = dispatch_syscall(1, &mut frame);
            assert_eq!(
                action,
                match syscall {
                    SYS_LIST_PROCESSES => SyscallAction::ListProcesses,
                    SYS_LIST_FILES => SyscallAction::ListFiles,
                    _ => unreachable!(),
                }
            );
            assert_eq!(frame.rax, syscall);
        }
    }

    #[test]
    fn syscall_abi_marks_mkdir_for_kernel_resolution() {
        let mut frame = SyscallFrame {
            rax: SYS_MKDIR,
            rdi: USER_IMAGE_BASE,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut frame), SyscallAction::Mkdir);
        assert_eq!(frame.rax, SYS_MKDIR);
    }

    #[test]
    fn syscall_abi_marks_path_info_for_kernel_resolution() {
        let mut frame = SyscallFrame {
            rax: SYS_PATH_INFO,
            rdi: USER_IMAGE_BASE,
            rsi: USER_IMAGE_BASE,
            rdx: PATH_INFO_LENGTH as u64,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut frame), SyscallAction::PathInfo);
        assert_eq!(frame.rax, SYS_PATH_INFO);
    }

    #[test]
    fn syscall_abi_marks_thread_operations_for_kernel_resolution() {
        for syscall in [SYS_THREAD_CREATE, SYS_THREAD_JOIN, SYS_THREAD_EXIT] {
            let mut frame = SyscallFrame {
                rax: syscall,
                rdi: USER_IMAGE_BASE,
                rsi: 0x1234,
                ..SyscallFrame::default()
            };
            let action = dispatch_syscall(1, &mut frame);
            assert_eq!(
                action,
                match syscall {
                    SYS_THREAD_CREATE => SyscallAction::ThreadCreate,
                    SYS_THREAD_JOIN => SyscallAction::ThreadJoin,
                    SYS_THREAD_EXIT => SyscallAction::ThreadExit,
                    _ => unreachable!(),
                }
            );
            assert_eq!(frame.rax, syscall);
        }
    }

    #[test]
    fn syscall_abi_marks_exec_for_kernel_resolution() {
        let mut frame = SyscallFrame {
            rax: SYS_EXEC,
            rdi: USER_IMAGE_BASE,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(2, &mut frame), SyscallAction::Exec);
        assert_eq!(frame.rax, SYS_EXEC);
    }

    #[test]
    fn syscall_abi_marks_fork_for_kernel_resolution() {
        let mut frame = SyscallFrame {
            rax: SYS_FORK,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(2, &mut frame), SyscallAction::Fork);
        assert_eq!(frame.rax, SYS_FORK);
    }

    #[test]
    fn syscall_abi_rejects_unknown_calls_and_exits_with_argument() {
        let mut unknown = SyscallFrame {
            rax: 0xfeed,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut unknown), SyscallAction::Return);
        assert_eq!(unknown.rax, SYSCALL_ENOSYS);

        let mut exit = SyscallFrame {
            rax: SYS_EXIT,
            rdi: (-7i64) as u64,
            ..SyscallFrame::default()
        };
        assert_eq!(dispatch_syscall(1, &mut exit), SyscallAction::Exit);
        assert_eq!(exit.rax, 0);
        assert_eq!(exit.rdi as i64, -7);
    }
}
