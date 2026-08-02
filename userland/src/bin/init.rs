#![no_std]
#![no_main]

use rustos_userland::{
    close, exit, is_syscall_error, mkdir, open, read, spawn, spawn_as, waitpid, write_stdout,
};

const MAX_SERVICES: usize = 4;
const MAX_PATH_LENGTH: usize = 64;
const CONFIG_BUFFER_LENGTH: usize = 128;
const INIT_CONFIG_PATH: &[u8] = b"/etc/rustos/init.cfg\0";
const HOME_PATH: &[u8] = b"/home\0";
const USER_HOME_PATH: &[u8] = b"/home/user\0";

#[derive(Clone, Copy)]
struct ServiceSpec {
    path: [u8; MAX_PATH_LENGTH],
    path_length: usize,
    retries: u8,
    uid: u32,
    gid: u32,
    credentials_explicit: bool,
}

impl ServiceSpec {
    const EMPTY: Self = Self {
        path: [0; MAX_PATH_LENGTH],
        path_length: 0,
        retries: 0,
        uid: 0,
        gid: 0,
        credentials_explicit: false,
    };

    fn path(&self) -> &[u8] {
        &self.path[..self.path_length]
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_stdout(b"supervisor: starting\n");
    let handle = open(INIT_CONFIG_PATH);
    if is_syscall_error(handle) {
        exit(90);
    }
    let mut buffer = [0u8; CONFIG_BUFFER_LENGTH];
    let length = read(handle, &mut buffer);
    let _ = close(handle);
    if is_syscall_error(length) {
        exit(91);
    }

    let mut services = [ServiceSpec::EMPTY; MAX_SERVICES];
    let service_count = parse_config(
        &buffer[..(length as usize).min(CONFIG_BUFFER_LENGTH)],
        &mut services,
    );
    if service_count == 0 {
        exit(92);
    }
    write_stdout(b"supervisor: config parsed\n");

    let _ = mkdir(HOME_PATH);
    let _ = mkdir(USER_HOME_PATH);

    let mut pids = [0u64; MAX_SERVICES];
    for index in 0..service_count {
        let pid = spawn_service(&services[index]);
        if is_syscall_error(pid) {
            exit(93);
        }
        pids[index] = pid;
    }

    let mut aggregate_status = 0i64;
    for index in 0..service_count {
        let mut restarted = false;
        loop {
            let result = waitpid(pids[index]);
            if is_syscall_error(result.pid) {
                aggregate_status = 94;
                break;
            }
            if result.status != 0 && services[index].retries > 0 {
                services[index].retries -= 1;
                restarted = true;
                write_stdout(b"supervisor: restarting failed service\n");
                let replacement = spawn_service(&services[index]);
                if is_syscall_error(replacement) {
                    aggregate_status = 95;
                    break;
                }
                pids[index] = replacement;
                continue;
            }
            if result.status != 0 && aggregate_status == 0 {
                aggregate_status = result.status;
            } else if result.status == 0 && restarted {
                write_stdout(b"supervisor: service recovered\n");
            }
            break;
        }
    }
    exit(aggregate_status)
}

fn spawn_service(service: &ServiceSpec) -> u64 {
    if service.credentials_explicit {
        spawn_as(
            service.path(),
            u64::from(service.uid),
            u64::from(service.gid),
        )
    } else {
        spawn(service.path())
    }
}

fn parse_config(bytes: &[u8], services: &mut [ServiceSpec; MAX_SERVICES]) -> usize {
    let mut cursor = 0;
    let mut count = 0;
    while cursor < bytes.len() && count < MAX_SERVICES {
        let start = cursor;
        while cursor < bytes.len() && bytes[cursor] != 0 {
            cursor += 1;
        }
        let end = cursor;
        if cursor < bytes.len() {
            cursor += 1;
        }
        let Some(separator) = bytes[start..end].iter().position(|byte| *byte == b'|') else {
            continue;
        };
        let path_end = start + separator;
        let path_length = path_end.saturating_sub(start);
        if path_length == 0 || path_length + 1 >= MAX_PATH_LENGTH {
            continue;
        }
        let fields = &bytes[path_end + 1..end];
        let Some(retries_end) = fields.iter().position(|byte| *byte == b'|') else {
            let Some(retries_value) = parse_number(fields) else {
                continue;
            };
            let Ok(retries) = u8::try_from(retries_value) else {
                continue;
            };
            let mut spec = ServiceSpec::EMPTY;
            spec.path[..path_length].copy_from_slice(&bytes[start..path_end]);
            spec.path[path_length] = 0;
            spec.path_length = path_length + 1;
            spec.retries = retries;
            services[count] = spec;
            count += 1;
            continue;
        };
        let Some(retries_value) = parse_number(&fields[..retries_end]) else {
            continue;
        };
        let Ok(retries) = u8::try_from(retries_value) else {
            continue;
        };
        let credentials = &fields[retries_end + 1..];
        let Some(gid_separator) = credentials.iter().position(|byte| *byte == b'|') else {
            continue;
        };
        if credentials[gid_separator + 1..].contains(&b'|') {
            continue;
        }
        let Some(uid) = parse_number(&credentials[..gid_separator]) else {
            continue;
        };
        let Some(gid) = parse_number(&credentials[gid_separator + 1..]) else {
            continue;
        };
        let mut spec = ServiceSpec::EMPTY;
        spec.path[..path_length].copy_from_slice(&bytes[start..path_end]);
        spec.path[path_length] = 0;
        spec.path_length = path_length + 1;
        spec.retries = retries;
        spec.uid = uid;
        spec.gid = gid;
        spec.credentials_explicit = true;
        services[count] = spec;
        count += 1;
    }
    count
}

fn parse_number(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0u32;
    for byte in bytes.iter().copied() {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}
