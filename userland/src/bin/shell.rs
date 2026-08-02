#![no_std]
#![no_main]

use rustos_userland::{
    CREDENTIALS_LENGTH, Credentials, NET_MAX_BUFFER_LENGTH, NET_RECEIVE_HEADER_LENGTH, OPEN_CREATE,
    OPEN_WRITE, PATH_INFO_LENGTH, PATH_KIND_DIRECTORY, PathInfo, SPAWN_INHERIT_FD,
    accounts::{ACCOUNT_DATABASE_LENGTH, ACCOUNT_STORE_PATH, AccountStore, parse},
    close, exit, get_credentials, is_permission_error, is_syscall_error, list_files,
    list_processes, mkdir, net_info, net_interfaces, net_receive, net_renew, net_send, open,
    open_with_flags, open_write,
    path::{MAX_PATH_LENGTH, PathBuf, resolve},
    path_info, pipe, poweroff, read, reboot, spawn, spawn_privileged_redirected, spawn_redirected,
    suspend, waitpid, write, write_stdout, yield_now,
};

const STDIN_FD: u64 = 0;
const INPUT_BUFFER_LENGTH: usize = 64;
const LINE_BUFFER_LENGTH: usize = 96;
const SNAPSHOT_BUFFER_LENGTH: usize = 4096;
const STATE_PATH: &[u8] = b"/RUSTOS.ST\0";
const STATE_LENGTH: usize = 7;
const ADMIN_PATH: &[u8] = b"/sbin/admin\0";
const ADMIN_STATE_SET: [u8; PACKAGE_REQUEST_LENGTH] = *b"STATESET";
const PACKAGE_REQUEST_PATH: &[u8] = b"/VAR/PKG/REQUEST\0";
const PACKAGE_REQUEST_LENGTH: usize = 8;
const PACKAGE_REQUEST_INSTALL: [u8; PACKAGE_REQUEST_LENGTH] = *b"INSTALL\0";
const PACKAGE_REQUEST_UPDATE: [u8; PACKAGE_REQUEST_LENGTH] = *b"UPDATE\0\0";
const PACKAGE_REQUEST_ROLLBACK: [u8; PACKAGE_REQUEST_LENGTH] = *b"ROLLBACK";
const PACKAGE_REQUEST_SYNC: [u8; PACKAGE_REQUEST_LENGTH] = *b"SYNCNET\0";
const PACKAGE_REQUEST_RECOVER: [u8; PACKAGE_REQUEST_LENGTH] = *b"RECOVER\0";
const RECOVERY_MARKER_PATH: &[u8] = b"/etc/rustos/recovery.cfg\0";
const RECOVERY_ACTIVE_PATH: &[u8] = b"/VAR/PKG/ACTIVE\0";
const RECOVERY_HISTORY_PATH: &[u8] = b"/VAR/PKG/HISTORY\0";
const NETWORK_PROBE_IP: [u8; 4] = [10, 0, 2, 2];
const NETWORK_PROBE_PORT: u16 = 19_000;
const NETWORK_PROBE_REQUEST: &[u8] = b"RUSTOS.REP2\0";
const WORKER_PATH: &[u8] = b"/bin/worker\0";
const CAT_PATH: &[u8] = b"/bin/cat\0";
const PASSWD_PATH: &[u8] = b"/bin/passwd\0";
const USERADD_PATH: &[u8] = b"/bin/useradd\0";
const LOCK_PATH: &[u8] = b"/bin/lock\0";
const ACCOUNT_READ_CHUNK_LENGTH: usize = 256;

struct ShellState {
    cwd: PathBuf,
}

impl ShellState {
    fn new() -> Self {
        Self {
            cwd: PathBuf::root(),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut state = ShellState::new();
    initialize_home(&mut state);
    let recovery_mode = recovery_marker_present();
    if recovery_mode {
        write_stdout(b"RustOS recovery environment\n");
        if recovery_state_present() {
            write_stdout(b"recovery: attempting verified package recovery\n");
            run_package_manager(Some(&PACKAGE_REQUEST_RECOVER));
        } else {
            write_stdout(b"recovery: no installed package generation\n");
        }
    } else {
        write_stdout(b"RustOS shell\n");
    }
    show_identity();
    write_prompt(recovery_mode, &state);

    let mut input = [0u8; INPUT_BUFFER_LENGTH];
    let mut line = [0u8; LINE_BUFFER_LENGTH];
    let mut line_length = 0;
    let mut swallow_lf = false;

    loop {
        let count = read(STDIN_FD, &mut input);
        if is_syscall_error(count) {
            write_stdout(b"sh: stdin unavailable\n");
            exit(1);
        }
        if count == 0 {
            yield_now();
            continue;
        }

        for &byte in &input[..count as usize] {
            if byte == b'\r' {
                write_stdout(b"\n");
                execute_line(&line[..line_length], recovery_mode, &mut state);
                line_length = 0;
                swallow_lf = true;
            } else if byte == b'\n' {
                if swallow_lf {
                    swallow_lf = false;
                    continue;
                }
                write_stdout(b"\n");
                execute_line(&line[..line_length], recovery_mode, &mut state);
                line_length = 0;
            } else {
                swallow_lf = false;
                handle_editable_byte(byte, &mut line, &mut line_length);
            }
        }
    }
}

fn handle_editable_byte(byte: u8, line: &mut [u8; LINE_BUFFER_LENGTH], length: &mut usize) {
    if byte == 8 || byte == 127 {
        if *length != 0 {
            *length -= 1;
            write_stdout(b"\x08 \x08");
        }
        return;
    }
    if !(0x20..=0x7e).contains(&byte) {
        return;
    }
    if *length + 1 >= line.len() {
        return;
    }
    line[*length] = byte;
    *length += 1;
    let echo = [byte];
    write_stdout(&echo);
}

fn execute_line(line: &[u8], recovery_mode: bool, state: &mut ShellState) {
    if line.is_empty() {
        write_prompt(recovery_mode, state);
    } else if let Some((left, right)) = pipeline_parts(line) {
        run_pipeline(left, right);
        write_prompt(recovery_mode, state);
    } else if line == b"help" {
        write_stdout(
            b"commands: help id whoami pwd cd [path] ls [path] ps run <path> vm passwd useradd sudo useradd lock pipe net [interfaces|renew|probe] mkdir pkg [install|update|rollback|sync|recover] sudo pkg [install|update|rollback|sync|recover] state [set] sudo state set uname echo cat touch write poweroff reboot suspend exit\n",
        );
        write_prompt(recovery_mode, state);
    } else if line == b"ls" {
        list_catalog(state, None);
        write_prompt(recovery_mode, state);
    } else if let Some(path) = argument_after(line, b"ls ") {
        list_catalog(state, Some(path));
        write_prompt(recovery_mode, state);
    } else if line == b"ps" {
        if list_process_table() {
            write_stdout(b"shell: ps status=ready\n");
        }
        write_prompt(recovery_mode, state);
    } else if line == b"id" {
        show_identity();
        write_stdout(b"shell: id command status=ready\n");
        write_prompt(recovery_mode, state);
    } else if line == b"whoami" {
        show_user_name();
        write_prompt(recovery_mode, state);
    } else if line == b"vm" {
        run_vm_workload();
        write_prompt(recovery_mode, state);
    } else if line == b"passwd" {
        run_password_change();
        write_prompt(recovery_mode, state);
    } else if line == b"useradd" || line == b"sudo useradd" {
        run_user_add();
        write_prompt(recovery_mode, state);
    } else if line == b"lock" {
        run_lock();
        write_prompt(recovery_mode, state);
    } else if let Some(path) = argument_after(line, b"run ") {
        run_external(state, path);
        write_prompt(recovery_mode, state);
    } else if line == b"pipe" {
        run_pipeline(b"worker", b"cat");
        write_prompt(recovery_mode, state);
    } else if line == b"net interfaces" {
        show_network_interfaces();
        write_prompt(recovery_mode, state);
    } else if line == b"net renew" {
        renew_network();
        write_prompt(recovery_mode, state);
    } else if line == b"net probe" {
        probe_network();
        write_prompt(recovery_mode, state);
    } else if line == b"net" {
        show_network();
        write_prompt(recovery_mode, state);
    } else if line == b"pwd" {
        print_working_directory(state);
        write_prompt(recovery_mode, state);
    } else if line == b"cd" {
        change_directory(state, b"/");
        write_prompt(recovery_mode, state);
    } else if let Some(path) = argument_after(line, b"cd ") {
        change_directory(state, path);
        write_prompt(recovery_mode, state);
    } else if let Some(path) = argument_after(line, b"mkdir ") {
        make_directory(state, path);
        write_prompt(recovery_mode, state);
    } else if line == b"pkg" {
        run_package_manager(None);
        write_prompt(recovery_mode, state);
    } else if line == b"pkg install" {
        run_package_manager(Some(&PACKAGE_REQUEST_INSTALL));
        write_prompt(recovery_mode, state);
    } else if line == b"pkg update" {
        run_package_manager(Some(&PACKAGE_REQUEST_UPDATE));
        write_prompt(recovery_mode, state);
    } else if line == b"pkg rollback" {
        run_package_manager(Some(&PACKAGE_REQUEST_ROLLBACK));
        write_prompt(recovery_mode, state);
    } else if line == b"pkg sync" {
        run_package_manager(Some(&PACKAGE_REQUEST_SYNC));
        write_prompt(recovery_mode, state);
    } else if line == b"pkg recover" {
        run_package_manager(Some(&PACKAGE_REQUEST_RECOVER));
        write_prompt(recovery_mode, state);
    } else if line == b"sudo pkg" || line == b"sudo pkg install" {
        run_privileged(&PACKAGE_REQUEST_INSTALL, b"pkg install");
        write_prompt(recovery_mode, state);
    } else if line == b"sudo pkg update" {
        run_privileged(&PACKAGE_REQUEST_UPDATE, b"pkg update");
        write_prompt(recovery_mode, state);
    } else if line == b"sudo pkg rollback" {
        run_privileged(&PACKAGE_REQUEST_ROLLBACK, b"pkg rollback");
        write_prompt(recovery_mode, state);
    } else if line == b"sudo pkg sync" {
        run_privileged(&PACKAGE_REQUEST_SYNC, b"pkg sync");
        write_prompt(recovery_mode, state);
    } else if line == b"sudo pkg recover" {
        run_privileged(&PACKAGE_REQUEST_RECOVER, b"pkg recover");
        write_prompt(recovery_mode, state);
    } else if line == b"state" {
        read_state();
        write_prompt(recovery_mode, state);
    } else if line == b"state set" {
        write_state();
        write_prompt(recovery_mode, state);
    } else if line == b"sudo state set" {
        run_privileged(&ADMIN_STATE_SET, b"state set");
        write_prompt(recovery_mode, state);
    } else if line == b"uname" {
        write_stdout(b"RustOS x86_64\n");
        write_prompt(recovery_mode, state);
    } else if line == b"exit" {
        write_stdout(b"shell: exit requested status=ready\n");
        exit(0);
    } else if line == b"poweroff" {
        let result = poweroff();
        if is_syscall_error(result) {
            write_stdout(b"poweroff: ACPI shutdown unavailable\n");
            write_prompt(recovery_mode, state);
        }
    } else if line == b"reboot" {
        let result = reboot();
        if is_syscall_error(result) {
            write_stdout(b"reboot: ACPI reset unavailable\n");
            write_prompt(recovery_mode, state);
        }
    } else if line == b"suspend" {
        let result = suspend();
        if is_syscall_error(result) {
            write_stdout(b"suspend: ACPI S3 unavailable\n");
        } else {
            write_stdout(b"suspend: resumed\n");
        }
        write_prompt(recovery_mode, state);
    } else if let Some(value) = argument_after(line, b"echo ") {
        write_stdout(value);
        write_stdout(b"\n");
        write_prompt(recovery_mode, state);
    } else if let Some(path) = argument_after(line, b"touch ") {
        touch_file(state, path);
        write_prompt(recovery_mode, state);
    } else if let Some(arguments) = argument_after(line, b"write ") {
        write_file(state, arguments);
        write_prompt(recovery_mode, state);
    } else if let Some(path) = argument_after(line, b"cat ") {
        cat_file(state, path);
        write_prompt(recovery_mode, state);
    } else {
        write_stdout(b"sh: unknown command\n");
        write_prompt(recovery_mode, state);
    }
}

fn pipeline_parts(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let separator = line.iter().position(|byte| *byte == b'|')?;
    if line[separator + 1..].contains(&b'|') {
        return Some((&[], &[]));
    }
    let left = trim_spaces(&line[..separator]);
    let right = trim_spaces(&line[separator + 1..]);
    Some((left, right))
}

fn trim_spaces(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| *byte != b' ')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(start, |index| index + 1);
    &value[start..end]
}

fn run_pipeline(left: &[u8], right: &[u8]) {
    if left != b"worker" && left != b"/bin/worker" || right != b"cat" && right != b"/bin/cat" {
        write_stdout(b"pipe: only `worker | cat` is available in this bounded shell\n");
        return;
    }
    let handles = pipe();
    if is_syscall_error(handles.read) || is_syscall_error(handles.write) {
        write_stdout(b"pipe: create failed\n");
        return;
    }
    let producer = spawn_redirected(WORKER_PATH, SPAWN_INHERIT_FD, handles.write);
    if is_syscall_error(producer) {
        let _ = close(handles.read);
        let _ = close(handles.write);
        write_stdout(b"pipe: producer spawn failed\n");
        return;
    }
    let consumer = spawn_redirected(CAT_PATH, handles.read, SPAWN_INHERIT_FD);
    if is_syscall_error(consumer) {
        let _ = close(handles.read);
        let _ = close(handles.write);
        let _ = waitpid(producer);
        write_stdout(b"pipe: consumer spawn failed\n");
        return;
    }
    let _ = close(handles.read);
    let _ = close(handles.write);
    let producer_result = waitpid(producer);
    let consumer_result = waitpid(consumer);
    if producer_result.status == 0 && consumer_result.status == 0 {
        write_stdout(b"pipe: status=ready producer=0 consumer=0\n");
    } else {
        write_stdout(b"pipe: status=degraded\n");
    }
}

fn initialize_home(state: &mut ShellState) {
    let home = current_home_path();
    if let Some(parent) = resolve(&PathBuf::root(), b"/home") {
        make_directory_absolute(&parent);
    }
    make_directory_absolute(&home);
    if path_kind(&home) == Some(PATH_KIND_DIRECTORY) {
        state.cwd = home;
    }
}

fn current_home_path() -> PathBuf {
    let mut credentials = Credentials::default();
    let uid = if get_credentials(&mut credentials) == CREDENTIALS_LENGTH as u64 {
        credentials.uid
    } else {
        1000
    };
    let mut bytes = [0u8; MAX_PATH_LENGTH];
    let prefix = b"/home/";
    bytes[..prefix.len()].copy_from_slice(prefix);
    let component = if uid == 1000 {
        b"user".as_slice()
    } else {
        let mut digits = [0u8; 20];
        let mut length = 0;
        let mut value = uid;
        loop {
            digits[length] = b'0' + (value % 10) as u8;
            length += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for (index, byte) in digits[..length].iter().rev().copied().enumerate() {
            bytes[prefix.len() + index] = byte;
        }
        return resolve(&PathBuf::root(), &bytes[..prefix.len() + length])
            .unwrap_or_else(PathBuf::root);
    };
    bytes[prefix.len()..prefix.len() + component.len()].copy_from_slice(component);
    resolve(&PathBuf::root(), &bytes[..prefix.len() + component.len()])
        .unwrap_or_else(PathBuf::root)
}

fn path_kind(path: &PathBuf) -> Option<u64> {
    let mut buffer = [0u8; MAX_PATH_LENGTH];
    let bytes = path.write_nul(&mut buffer)?;
    let mut info = PathInfo::default();
    (path_info(bytes, &mut info) == PATH_INFO_LENGTH as u64).then_some(info.kind)
}

fn make_directory_absolute(path: &PathBuf) -> u64 {
    let mut buffer = [0u8; MAX_PATH_LENGTH];
    let Some(bytes) = path.write_nul(&mut buffer) else {
        return u64::MAX - 6;
    };
    mkdir(bytes)
}

fn resolve_command_path(state: &ShellState, input: &[u8]) -> Option<PathBuf> {
    resolve(&state.cwd, input)
}

fn print_working_directory(state: &ShellState) {
    write_stdout(state.cwd.as_bytes());
    write_stdout(b"\n");
    write_stdout(b"shell: pwd path=");
    write_stdout(state.cwd.as_bytes());
    write_stdout(b" status=ready\n");
}

fn change_directory(state: &mut ShellState, input: &[u8]) {
    let Some(path) = resolve_command_path(state, input) else {
        write_stdout(b"cd: path too long\n");
        return;
    };
    if path_kind(&path) != Some(PATH_KIND_DIRECTORY) {
        write_stdout(b"cd: not a directory\n");
        return;
    }
    state.cwd = path;
    write_stdout(b"shell: cwd changed path=");
    write_stdout(state.cwd.as_bytes());
    write_stdout(b" status=ready\n");
}

fn write_prompt(recovery_mode: bool, state: &ShellState) {
    if recovery_mode {
        write_stdout(b"recovery:");
    } else {
        write_stdout(b"rustos:");
    }
    write_stdout(state.cwd.as_bytes());
    if recovery_mode {
        write_stdout(b"# ");
    } else {
        write_stdout(b"$ ");
    }
}

fn run_vm_workload() {
    let pid = spawn(b"/bin/vm\0");
    if is_syscall_error(pid) {
        write_stdout(b"vm: spawn failed\n");
        return;
    }
    let result = waitpid(pid);
    if result.status != 0 {
        write_stdout(b"vm: workload failed\n");
    }
}

fn run_password_change() {
    write_stdout(b"shell: passwd launch status=ready\n");
    let pid = spawn(PASSWD_PATH);
    if is_syscall_error(pid) {
        write_stdout(b"passwd: unavailable\n");
        return;
    }
    let result = waitpid(pid);
    if is_syscall_error(result.pid) || result.status != 0 {
        write_stdout(b"shell: passwd status=failed\n");
    } else {
        write_stdout(b"shell: passwd status=ready\n");
    }
}

fn run_user_add() {
    write_stdout(b"shell: useradd launch status=ready\n");
    let pid = spawn(USERADD_PATH);
    if is_syscall_error(pid) {
        write_stdout(b"useradd: unavailable\n");
        return;
    }
    let result = waitpid(pid);
    if is_syscall_error(result.pid) || result.status != 0 {
        write_stdout(b"shell: useradd status=failed\n");
    } else {
        write_stdout(b"shell: useradd status=ready\n");
    }
}

fn run_lock() {
    write_stdout(b"shell: lock launch status=ready\n");
    let pid = spawn(LOCK_PATH);
    if is_syscall_error(pid) {
        write_stdout(b"lock: unavailable\n");
        return;
    }
    let result = waitpid(pid);
    if is_syscall_error(result.pid) || result.status != 0 {
        write_stdout(b"shell: lock status=failed\n");
    } else {
        write_stdout(b"shell: lock status=ready\n");
    }
}

fn run_external(state: &ShellState, input: &[u8]) {
    let Some(path) = resolve_command_path(state, input) else {
        write_stdout(b"run: path too long\n");
        return;
    };
    let display_path = path.as_bytes();
    let mut path_buffer = [0u8; MAX_PATH_LENGTH];
    let Some(path_bytes) = path.write_nul(&mut path_buffer) else {
        write_stdout(b"run: path too long\n");
        return;
    };
    let pid = spawn(path_bytes);
    if is_syscall_error(pid) {
        write_stdout(b"run: spawn failed\n");
        return;
    }
    let result = waitpid(pid);
    if is_syscall_error(result.pid) || result.status != 0 {
        write_stdout(b"run: child failed\n");
        return;
    }
    write_stdout(b"shell: run path=");
    write_stdout(display_path);
    write_stdout(b" status=ready\n");
}

fn recovery_marker_present() -> bool {
    let handle = open(RECOVERY_MARKER_PATH);
    if is_syscall_error(handle) {
        return false;
    }
    let _ = close(handle);
    true
}

fn recovery_state_present() -> bool {
    recovery_path_present(RECOVERY_ACTIVE_PATH) || recovery_path_present(RECOVERY_HISTORY_PATH)
}

fn recovery_path_present(path: &[u8]) -> bool {
    let handle = open(path);
    if is_syscall_error(handle) {
        return false;
    }
    let _ = close(handle);
    true
}

fn list_catalog(state: &ShellState, input: Option<&[u8]>) {
    let directory = match input {
        Some(input) => match resolve_command_path(state, input) {
            Some(path) if path_kind(&path) == Some(PATH_KIND_DIRECTORY) => path,
            Some(_) => {
                write_stdout(b"ls: not a directory\n");
                return;
            }
            None => {
                write_stdout(b"ls: path too long\n");
                return;
            }
        },
        None => state.cwd,
    };
    let mut buffer = [0u8; SNAPSHOT_BUFFER_LENGTH];
    let count = list_files(&mut buffer);
    if is_syscall_error(count) {
        write_stdout(b"ls: snapshot unavailable\n");
        return;
    }
    write_stdout(b"PATH SIZE TYPE\n");
    let snapshot = &buffer[..count as usize];
    let mut prefix = [0u8; MAX_PATH_LENGTH];
    let prefix_length = if directory.as_bytes() == b"/" {
        1
    } else {
        let Some(length) = directory.as_bytes().len().checked_add(1) else {
            return;
        };
        if length > prefix.len() {
            return;
        }
        prefix[..directory.as_bytes().len()].copy_from_slice(directory.as_bytes());
        prefix[directory.as_bytes().len()] = b'/';
        length
    };
    if directory.as_bytes() == b"/" {
        prefix[0] = b'/';
    }

    let mut seen_directories = [[0u8; MAX_PATH_LENGTH]; 16];
    let mut seen_lengths = [0usize; 16];
    let mut cursor = 0;
    while cursor < snapshot.len() {
        let line_end = snapshot[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(snapshot.len(), |offset| cursor + offset);
        let line = &snapshot[cursor..line_end];
        let Some(path_end) = line.iter().position(|byte| *byte == b' ') else {
            cursor = line_end.saturating_add(1);
            continue;
        };
        let path = &line[..path_end];
        if path == b"PATH" || !ascii_case_insensitive_starts_with(path, &prefix[..prefix_length]) {
            cursor = line_end.saturating_add(1);
            continue;
        }
        let relative = &path[prefix_length..];
        if relative.is_empty() {
            cursor = line_end.saturating_add(1);
            continue;
        }
        if let Some(separator) = relative.iter().position(|byte| *byte == b'/') {
            let child = &relative[..separator];
            if child.len() < MAX_PATH_LENGTH
                && !seen_lengths[..seen_lengths.len()]
                    .iter()
                    .enumerate()
                    .any(|(index, length)| {
                        *length == child.len() && seen_directories[index][..*length] == *child
                    })
            {
                if let Some(index) = seen_lengths.iter().position(|length| *length == 0) {
                    seen_directories[index][..child.len()].copy_from_slice(child);
                    seen_lengths[index] = child.len();
                    write_stdout(child);
                    write_stdout(b" 0 dir\n");
                }
            }
        } else {
            write_stdout(relative);
            write_stdout(&line[path_end..]);
            write_stdout(b"\n");
        }
        cursor = line_end.saturating_add(1);
    }
    write_stdout(b"shell: ls path=");
    write_stdout(directory.as_bytes());
    write_stdout(b" status=ready\n");
}

fn ascii_case_insensitive_starts_with(value: &[u8], prefix: &[u8]) -> bool {
    value.len() >= prefix.len()
        && value[..prefix.len()]
            .iter()
            .zip(prefix)
            .all(|(value, prefix)| value.eq_ignore_ascii_case(prefix))
}

fn list_process_table() -> bool {
    let mut buffer = [0u8; SNAPSHOT_BUFFER_LENGTH];
    let count = list_processes(&mut buffer);
    if is_syscall_error(count) {
        write_stdout(b"ps: snapshot unavailable\n");
        return false;
    }
    write_stdout(&buffer[..count as usize]);
    true
}

fn show_identity() {
    let mut credentials = Credentials::default();
    if get_credentials(&mut credentials) != CREDENTIALS_LENGTH as u64 {
        write_stdout(b"id: credentials unavailable\n");
        return;
    }
    write_stdout(b"uid=");
    write_decimal(credentials.uid);
    write_stdout(b" gid=");
    write_decimal(credentials.gid);
    write_stdout(b" name=");
    write_user_name(credentials.uid);
    write_stdout(b"\n");
    write_stdout(b"shell: credentials uid=");
    write_decimal(credentials.uid);
    write_stdout(b" gid=");
    write_decimal(credentials.gid);
    write_stdout(b" status=ready\n");
}

fn show_user_name() {
    let mut credentials = Credentials::default();
    if get_credentials(&mut credentials) != CREDENTIALS_LENGTH as u64 {
        write_stdout(b"whoami: credentials unavailable\n");
        return;
    }
    write_user_name(credentials.uid);
    write_stdout(b"\n");
}

fn write_user_name(uid: u64) {
    if uid == 0 {
        write_stdout(b"root");
    } else if let Some(account) = account_for_uid(uid) {
        write_stdout(account.username());
    } else {
        write_stdout(b"unknown");
    }
}

fn account_for_uid(uid: u64) -> Option<rustos_userland::accounts::Account> {
    let handle = open(ACCOUNT_STORE_PATH);
    if is_syscall_error(handle) {
        return None;
    }
    let mut bytes = [0u8; ACCOUNT_DATABASE_LENGTH];
    let mut length = 0usize;
    while length < bytes.len() {
        let end = (length + ACCOUNT_READ_CHUNK_LENGTH).min(bytes.len());
        let count = read(handle, &mut bytes[length..end]);
        if is_syscall_error(count) {
            let _ = close(handle);
            return None;
        }
        if count == 0 {
            break;
        }
        length = length.saturating_add(count as usize).min(bytes.len());
    }
    let _ = close(handle);
    parse(&bytes[..length]).and_then(|store: AccountStore| store.find_uid(uid, uid))
}

fn write_decimal(mut value: u64) {
    let mut bytes = [0u8; 20];
    let mut cursor = bytes.len();
    if value == 0 {
        write_stdout(b"0");
        return;
    }
    while value != 0 {
        cursor -= 1;
        bytes[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    write_stdout(&bytes[cursor..]);
}

fn show_network() {
    let mut buffer = [0u8; rustos_userland::NET_INFO_MAX_LENGTH];
    let count = net_info(&mut buffer);
    if is_syscall_error(count) {
        write_stdout(b"net: unavailable\n");
        return;
    }
    write_stdout(&buffer[..count as usize]);
}

fn show_network_interfaces() {
    let mut buffer = [0u8; rustos_userland::NET_INTERFACES_MAX_LENGTH];
    let count = net_interfaces(&mut buffer);
    if is_syscall_error(count) {
        write_stdout(b"net: interfaces unavailable\n");
        return;
    }
    write_stdout(b"net: interfaces status=ready\n");
    write_stdout(&buffer[..count as usize]);
}

fn renew_network() {
    let mut buffer = [0u8; rustos_userland::NET_RENEW_MAX_LENGTH];
    let count = net_renew(&mut buffer);
    if is_syscall_error(count) {
        write_stdout(b"net: renew unavailable\n");
        return;
    }
    write_stdout(&buffer[..count as usize]);
}

fn probe_network() {
    let sent = net_send(NETWORK_PROBE_IP, NETWORK_PROBE_PORT, NETWORK_PROBE_REQUEST);
    if is_syscall_error(sent) || sent as usize != NETWORK_PROBE_REQUEST.len() {
        write_stdout(b"net: udp probe send failed\n");
        return;
    }
    let mut response = [0u8; NET_MAX_BUFFER_LENGTH];
    for _ in 0..64 {
        let received = net_receive(&mut response);
        if is_syscall_error(received) {
            yield_now();
            continue;
        }
        let received = received as usize;
        if received >= NET_RECEIVE_HEADER_LENGTH
            && response[..4] == NETWORK_PROBE_IP
            && u16::from_be_bytes([response[4], response[5]]) == NETWORK_PROBE_PORT
            && received >= NET_RECEIVE_HEADER_LENGTH + 5
            && response[NET_RECEIVE_HEADER_LENGTH..NET_RECEIVE_HEADER_LENGTH + 5] == *b"RREP3"
        {
            write_stdout(b"net: udp probe received repository status=ready\n");
            return;
        }
    }
    write_stdout(b"net: udp probe receive failed\n");
}

fn read_state() {
    let handle = open(STATE_PATH);
    if is_syscall_error(handle) {
        write_stdout(b"state: open failed\n");
        return;
    }
    let mut buffer = [0u8; STATE_LENGTH];
    let count = read(handle, &mut buffer);
    let _ = close(handle);
    if is_syscall_error(count) || count as usize != STATE_LENGTH {
        write_stdout(b"state: read failed\n");
        return;
    }
    write_stdout(b"state: ");
    write_stdout(&buffer);
    write_stdout(b"shell: state read status=ready\n");
}

fn write_state() {
    let handle = open_write(STATE_PATH);
    if is_syscall_error(handle) {
        write_stdout(b"state: write open failed\n");
        return;
    }
    let count = write(handle, b"boot=1\n");
    let _ = close(handle);
    if is_syscall_error(count) || count != STATE_LENGTH as u64 {
        write_stdout(b"state: write failed\n");
    } else {
        write_stdout(b"state: written\n");
    }
}

fn argument_after<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    line.strip_prefix(prefix)
        .filter(|argument| !argument.is_empty())
}

fn cat_file(state: &ShellState, input: &[u8]) {
    let Some(path) = resolve_command_path(state, input) else {
        write_stdout(b"cat: path too long\n");
        return;
    };
    let handle = open_resolved_path(&path, 0);
    if is_syscall_error(handle) {
        write_stdout(b"cat: open failed\n");
        return;
    }

    let mut complete = true;
    let mut last_byte = None;
    let mut buffer = [0u8; 128];
    loop {
        let count = read(handle, &mut buffer);
        if is_syscall_error(count) {
            write_stdout(b"cat: read failed\n");
            complete = false;
            break;
        }
        if count == 0 {
            break;
        }
        let bytes = &buffer[..count as usize];
        write_stdout(bytes);
        last_byte = bytes.last().copied();
    }
    let _ = close(handle);
    if complete {
        if last_byte != Some(b'\n') {
            write_stdout(b"\n");
        }
        write_stdout(b"shell: relative read path=");
        write_stdout(path.as_bytes());
        write_stdout(b" status=ready\n");
    }
}

fn touch_file(state: &ShellState, input: &[u8]) {
    let Some(path) = resolve_command_path(state, input) else {
        write_stdout(b"touch: path too long\n");
        return;
    };
    let handle = open_resolved_path(&path, OPEN_CREATE);
    if is_syscall_error(handle) {
        write_stdout(b"touch: failed\n");
        return;
    }
    let _ = close(handle);
    write_stdout(b"touch: ok\n");
}

fn make_directory(state: &ShellState, input: &[u8]) {
    let Some(path) = resolve_command_path(state, input) else {
        write_stdout(b"mkdir: path too long\n");
        return;
    };
    let result = make_directory_absolute(&path);
    if is_permission_error(result) {
        write_stdout(b"mkdir: permission denied\n");
        write_permission_marker(&path);
    } else if is_syscall_error(result) {
        write_stdout(b"mkdir: failed\n");
    } else {
        write_stdout(b"mkdir: ok\n");
    }
}

fn run_package_manager(request: Option<&[u8; PACKAGE_REQUEST_LENGTH]>) {
    if let Some(request) = request {
        if !write_package_request(request) {
            write_stdout(b"pkg: request failed\n");
            return;
        }
    }
    let pid = spawn(b"/bin/pkg\0");
    if is_syscall_error(pid) {
        write_stdout(b"pkg: unavailable\n");
        return;
    }
    let result = waitpid(pid);
    if is_syscall_error(result.pid) || result.status != 0 {
        write_stdout(b"pkg: failed\n");
    }
}

fn run_privileged(request: &[u8; PACKAGE_REQUEST_LENGTH], label: &[u8]) {
    let handles = pipe();
    if is_syscall_error(handles.read) || is_syscall_error(handles.write) {
        write_stdout(b"sudo: pipe failed\n");
        return;
    }
    let pid = spawn_privileged_redirected(
        ADMIN_PATH,
        handles.read,
        rustos_userland::SPAWN_INHERIT_PARENT_FD,
    );
    if is_syscall_error(pid) {
        let _ = close(handles.read);
        let _ = close(handles.write);
        write_stdout(b"sudo: helper unavailable\n");
        return;
    }
    let count = write(handles.write, request);
    let _ = close(handles.write);
    let _ = close(handles.read);
    if is_syscall_error(count) || count != PACKAGE_REQUEST_LENGTH as u64 {
        write_stdout(b"sudo: request failed\n");
        return;
    }
    let result = waitpid(pid);
    if is_syscall_error(result.pid) || result.status != 0 {
        write_stdout(b"sudo: command failed\n");
        return;
    }
    write_stdout(b"sudo: ");
    write_stdout(label);
    write_stdout(b" status=ready\n");
}

fn write_package_request(request: &[u8; PACKAGE_REQUEST_LENGTH]) -> bool {
    let _ = mkdir(b"/VAR\0");
    let _ = mkdir(b"/VAR/PKG\0");
    let handle = open_with_flags(PACKAGE_REQUEST_PATH, OPEN_CREATE | OPEN_WRITE);
    if is_syscall_error(handle) {
        return false;
    }
    let count = write(handle, request);
    let closed = close(handle);
    !is_syscall_error(count) && count == PACKAGE_REQUEST_LENGTH as u64 && !is_syscall_error(closed)
}

fn write_file(state: &ShellState, arguments: &[u8]) {
    let Some(separator) = arguments.iter().position(|byte| *byte == b' ') else {
        write_stdout(b"write: usage write /path value\n");
        return;
    };
    let path = &arguments[..separator];
    let value = &arguments[separator + 1..];
    if path.is_empty() {
        write_stdout(b"write: usage write /path value\n");
        return;
    }
    let Some(path) = resolve_command_path(state, path) else {
        write_stdout(b"write: path too long\n");
        return;
    };
    let handle = open_resolved_path(&path, OPEN_CREATE | OPEN_WRITE);
    if is_syscall_error(handle) {
        if is_permission_error(handle) {
            write_stdout(b"write: permission denied\n");
            write_permission_marker(&path);
            return;
        }
        write_stdout(b"write: open failed\n");
        return;
    }
    let count = write(handle, value);
    let _ = close(handle);
    if is_syscall_error(count) || count != value.len() as u64 {
        write_stdout(b"write: failed\n");
    } else {
        write_stdout(b"write: ok\n");
        write_stdout(b"shell: relative write path=");
        write_stdout(path.as_bytes());
        write_stdout(b" status=ready\n");
    }
}

fn write_permission_marker(path: &PathBuf) {
    write_stdout(b"shell: permission denied path=");
    write_stdout(path.as_bytes());
    write_stdout(b" status=ready\n");
}

fn open_resolved_path(path: &PathBuf, flags: u64) -> u64 {
    let mut path_buffer = [0u8; MAX_PATH_LENGTH];
    let Some(path) = path.write_nul(&mut path_buffer) else {
        return u64::MAX;
    };
    open_with_flags(path, flags)
}
