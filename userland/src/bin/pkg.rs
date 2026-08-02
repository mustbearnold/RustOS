#![no_std]
#![no_main]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rustos_userland::{
    NET_MAX_BUFFER_LENGTH, NET_RECEIVE_HEADER_LENGTH, OPEN_CREATE, OPEN_WRITE, SYSCALL_EAGAIN,
    close, exit, is_syscall_error, mkdir, net_receive, net_send, open, open_with_flags, read,
    read_nonblocking, write, write_stdout, yield_now,
};
use sha2::{Digest, Sha256};

const REPOSITORY_PATH: &[u8] = b"/RUSTOS.REP\0";
const REPOSITORY_MAGIC: &[u8; 5] = b"RREP3";
const REPOSITORY_VERSION: u8 = 3;
const REPOSITORY_HEADER_LENGTH: usize = 16;
const REPOSITORY_ENTRY_LENGTH: usize = 82;
const REPOSITORY_SIGNATURE_LENGTH: usize = 64;
const REPOSITORY_ROTATION_FLAG: u8 = 1;
const REPOSITORY_ROTATION_MATERIAL_LENGTH: usize = 32 + REPOSITORY_SIGNATURE_LENGTH;
const MAX_REPOSITORY_SIZE: usize = 16 * 1024;
const MAX_REPOSITORY_PACKAGES: usize = 6;
const MAX_REPOSITORY_NAME_LENGTH: usize = 12;
const MAX_REPOSITORY_DEPENDENCIES: usize = 2;
const TRUSTED_ROOT_KEY_ID: [u8; 8] = *b"RUSTKEY1";
const TRUSTED_ROOT_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const TRUSTED_KEY_PATH: &[u8] = b"TRUSTED";
const TRUSTED_KEY_LENGTH: usize = 8 + 32 + REPOSITORY_SIGNATURE_LENGTH;
const KEY_ROTATION_DOMAIN: &[u8] = b"RUSTOS.KEY.ROTATE\0";
const KEY_ROTATION_MESSAGE_LENGTH: usize = KEY_ROTATION_DOMAIN.len() + 8 + 32;
const TARGET_PACKAGE_NAME: &[u8] = b"HELLO";
const REQUEST_LENGTH: usize = 8;
const REQUEST_INSTALL: [u8; REQUEST_LENGTH] = *b"INSTALL\0";
const REQUEST_UPDATE: [u8; REQUEST_LENGTH] = *b"UPDATE\0\0";
const REQUEST_ROLLBACK: [u8; REQUEST_LENGTH] = *b"ROLLBACK";
const REQUEST_SYNC: [u8; REQUEST_LENGTH] = *b"SYNCNET\0";
const REQUEST_RECOVER: [u8; REQUEST_LENGTH] = *b"RECOVER\0";
const REMOTE_REPOSITORY_IP: [u8; 4] = [10, 0, 2, 2];
const REMOTE_REPOSITORY_PORT: u16 = 19_000;
const REMOTE_REPOSITORY_REQUEST: &[u8] = b"RUSTOS.REP2\0";
const PACKAGE_MAGIC: &[u8; 5] = b"RPKG1";
const PACKAGE_VERSION: u8 = 1;
const PACKAGE_HEADER_LENGTH: usize = 16;
const PACKAGE_RECORD_HEADER_LENGTH: usize = 10;
const MAX_PACKAGE_SIZE: usize = 4096;
const MAX_PACKAGE_FILES: usize = 4;
const MAX_PACKAGE_PATH_LENGTH: usize = 40;
const MAX_PACKAGE_FILE_SIZE: usize = MAX_PACKAGE_SIZE;
const MAX_PACKAGE_COMPONENTS: usize = 16;
const MAX_PATH_LENGTH: usize = 64;
const WRITE_CHUNK_LENGTH: usize = 128;
const GENERATION_HISTORY_PATH: &[u8] = b"HISTORY";
const GENERATION_HISTORY_SLOTS: usize = 3;
const GENERATION_HISTORY_LENGTH: usize = GENERATION_HISTORY_SLOTS * 8;
const STDIN_FD: u64 = 0;

#[derive(Clone, Copy)]
struct PackageFile {
    path_start: usize,
    path_length: usize,
    data_start: usize,
    data_length: usize,
    checksum: u32,
}

#[derive(Clone, Copy)]
struct Package {
    id: [u8; 8],
    files: [Option<PackageFile>; MAX_PACKAGE_FILES],
    file_count: usize,
}

#[derive(Clone, Copy)]
struct RepositoryEntry {
    id: [u8; 8],
    version: u32,
    name: [u8; MAX_REPOSITORY_NAME_LENGTH],
    name_length: usize,
    dependencies: [[u8; 8]; MAX_REPOSITORY_DEPENDENCIES],
    dependency_count: usize,
    package_start: usize,
    package_length: usize,
    digest: [u8; 32],
}

#[derive(Clone, Copy)]
struct Repository {
    entries: [Option<RepositoryEntry>; MAX_REPOSITORY_PACKAGES],
    package_count: usize,
}

#[derive(Clone, Copy)]
struct RepositoryTrust {
    id: [u8; 8],
    public_key: [u8; 32],
    rotation_signature: [u8; REPOSITORY_SIGNATURE_LENGTH],
    persisted: bool,
}

#[derive(Clone, Copy)]
struct PathBuffer {
    bytes: [u8; MAX_PATH_LENGTH],
    length: usize,
}

enum ReadStatus {
    Missing,
    Failed,
    Complete(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PackageRequest {
    Install,
    Update,
    Rollback,
    Sync,
    Recover,
}

impl PathBuffer {
    fn root() -> Self {
        let mut bytes = [0; MAX_PATH_LENGTH];
        bytes[0] = b'/';
        Self { bytes, length: 1 }
    }

    fn push(&mut self, component: &[u8]) -> bool {
        if component.is_empty() || self.length >= self.bytes.len() {
            return false;
        }
        let separator = usize::from(self.length > 1);
        let Some(end) = self
            .length
            .checked_add(separator)
            .and_then(|length| length.checked_add(component.len()))
            .and_then(|length| length.checked_add(1))
        else {
            return false;
        };
        if end > self.bytes.len() {
            return false;
        }
        if separator != 0 {
            self.bytes[self.length] = b'/';
            self.length += 1;
        }
        self.bytes[self.length..self.length + component.len()].copy_from_slice(component);
        self.length += component.len();
        true
    }

    fn c_path(&mut self) -> &[u8] {
        self.bytes[self.length] = 0;
        &self.bytes[..=self.length]
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let request = match read_package_request() {
        Ok(request) => request,
        Err(()) => {
            write_stdout(b"pkg: request invalid\n");
            exit(6);
        }
    };
    let mut repository_bytes = [0u8; MAX_REPOSITORY_SIZE];
    let repository_length = if request == PackageRequest::Sync {
        match fetch_remote_repository(&mut repository_bytes) {
            Some(length) => {
                write_stdout(b"pkg: fetched remote repository bytes=");
                write_decimal(length);
                write_stdout(b"\n");
                length
            }
            None => {
                write_stdout(b"pkg: remote repository unavailable\n");
                exit(2);
            }
        }
    } else {
        match read_file(REPOSITORY_PATH, &mut repository_bytes) {
            ReadStatus::Complete(length) => length,
            ReadStatus::Missing | ReadStatus::Failed => {
                write_stdout(b"pkg: repository unavailable\n");
                exit(2);
            }
        }
    };
    let repository_slice = &repository_bytes[..repository_length];
    let trust = match verify_repository_signature(repository_slice) {
        Some(trust) => trust,
        None => {
            write_stdout(b"pkg: repository signature invalid\n");
            exit(3);
        }
    };
    let repository = match parse_repository(repository_slice) {
        Some(repository) => repository,
        None => {
            write_stdout(b"pkg: repository invalid\n");
            exit(5);
        }
    };
    if !persist_trusted_key(trust) {
        write_stdout(b"pkg: trusted key state unavailable\n");
        exit(4);
    }
    write_stdout(b"pkg: repository signature valid key=");
    write_stdout(&trust.id);
    if trust.persisted {
        write_stdout(b" source=persisted");
    } else {
        write_stdout(b" source=rotation");
    }
    write_stdout(b" packages=");
    write_decimal(repository.package_count);
    write_stdout(b"\n");

    let Some(latest) = find_latest_repository_entry(&repository, TARGET_PACKAGE_NAME) else {
        write_stdout(b"pkg: target package missing\n");
        exit(6);
    };
    write_stdout(b"pkg: target ");
    write_stdout(TARGET_PACKAGE_NAME);
    write_stdout(b" latest=");
    write_stdout(&latest.id);
    write_stdout(b" version=");
    write_decimal(latest.version as usize);
    write_stdout(b"\n");

    let mut active_path = store_root();
    if !active_path.push(b"ACTIVE") {
        write_stdout(b"pkg: active path invalid\n");
        exit(7);
    }
    let mut active_id = [0u8; 8];
    let active_status = read_path_file(&mut active_path, &mut active_id);
    match request {
        PackageRequest::Install | PackageRequest::Sync => match active_status {
            ReadStatus::Missing => {
                if !install_initial_generation(&repository, repository_slice, latest) {
                    write_stdout(b"pkg: initial installation failed\n");
                    exit(8);
                }
                active_id = latest.id;
            }
            ReadStatus::Complete(length) if length == active_id.len() => {
                let Some(active) = find_repository_entry_by_id(&repository, active_id) else {
                    write_stdout(b"pkg: active generation is unknown\n");
                    exit(9);
                };
                if active.name[..active.name_length] != TARGET_PACKAGE_NAME[..] {
                    write_stdout(b"pkg: active package is not HELLO\n");
                    exit(10);
                }
                write_stdout(b"pkg: active ");
                write_stdout(&active.id);
                write_stdout(b" version=");
                write_decimal(active.version as usize);
                write_stdout(b"\n");
            }
            ReadStatus::Complete(_) => {
                write_stdout(b"pkg: activation marker invalid\n");
                exit(11);
            }
            ReadStatus::Failed => {
                write_stdout(b"pkg: activation marker unreadable\n");
                exit(12);
            }
        },
        PackageRequest::Update => match active_status {
            ReadStatus::Complete(length) if length == active_id.len() => {
                let Some(active) = find_repository_entry_by_id(&repository, active_id) else {
                    write_stdout(b"pkg: active generation is unknown\n");
                    exit(13);
                };
                if active.id == latest.id {
                    write_stdout(b"pkg: already current ");
                    write_stdout(&active.id);
                    write_stdout(b" version=");
                    write_decimal(active.version as usize);
                    write_stdout(b"\n");
                } else if !update_generation(&repository, repository_slice, active, latest) {
                    write_stdout(b"pkg: update failed\n");
                    exit(14);
                } else {
                    active_id = latest.id;
                }
            }
            ReadStatus::Missing => {
                write_stdout(b"pkg: update requires an installed generation\n");
                exit(15);
            }
            ReadStatus::Complete(_) | ReadStatus::Failed => {
                write_stdout(b"pkg: activation marker invalid\n");
                exit(16);
            }
        },
        PackageRequest::Rollback => match active_status {
            ReadStatus::Complete(length) if length == active_id.len() => {
                let Some(active) = find_repository_entry_by_id(&repository, active_id) else {
                    write_stdout(b"pkg: active generation is unknown\n");
                    exit(17);
                };
                let mut previous_path = store_root();
                if !previous_path.push(b"PREVIOUS") {
                    write_stdout(b"pkg: previous path invalid\n");
                    exit(18);
                }
                let mut previous_id = [0u8; 8];
                if !matches!(
                    read_path_file(&mut previous_path, &mut previous_id),
                    ReadStatus::Complete(length) if length == previous_id.len()
                ) {
                    write_stdout(b"pkg: no rollback generation\n");
                    exit(19);
                }
                let Some(previous) = find_repository_entry_by_id(&repository, previous_id) else {
                    write_stdout(b"pkg: rollback generation is unknown\n");
                    exit(20);
                };
                if !rollback_generation(&repository, repository_slice, active, previous) {
                    write_stdout(b"pkg: rollback failed\n");
                    exit(21);
                }
                active_id = previous.id;
            }
            ReadStatus::Missing => {
                write_stdout(b"pkg: rollback requires an installed generation\n");
                exit(22);
            }
            ReadStatus::Complete(_) | ReadStatus::Failed => {
                write_stdout(b"pkg: activation marker invalid\n");
                exit(23);
            }
        },
        PackageRequest::Recover => {
            let current = match active_status {
                ReadStatus::Complete(length) if length == active_id.len() => Some(active_id),
                ReadStatus::Missing | ReadStatus::Complete(_) | ReadStatus::Failed => None,
            };
            let Some(recovered) = recover_generation(&repository, repository_slice, current) else {
                write_stdout(b"pkg: no verified recovery generation\n");
                exit(27);
            };
            active_id = recovered;
        }
    }

    let Some(active) = find_repository_entry_by_id(&repository, active_id) else {
        write_stdout(b"pkg: active generation is unknown\n");
        exit(24);
    };
    let mut active_order: [Option<RepositoryEntry>; MAX_REPOSITORY_PACKAGES] =
        [None; MAX_REPOSITORY_PACKAGES];
    let mut active_count = 0;
    let mut visiting = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
    if !resolve_dependencies(
        &repository,
        active.id,
        &mut active_order,
        &mut active_count,
        &mut visiting,
        0,
    ) || !verify_active_closure(&repository, repository_slice, &active_order, active_count)
    {
        write_stdout(b"pkg: active payload verification failed\n");
        exit(25);
    }
    if !write_store_marker(b"REQUEST", &REQUEST_INSTALL) {
        write_stdout(b"pkg: request reset failed\n");
        exit(26);
    }
    write_stdout(b"pkg: dependency closure readback verified\n");
    // Give a parent that spawned this short-lived manager a scheduling point before the final
    // exit. This also keeps the waitpid path deterministic when activation is already complete.
    yield_now();
    exit(0)
}

fn read_package_request() -> Result<PackageRequest, ()> {
    let mut request = [0u8; REQUEST_LENGTH];
    for _ in 0..64 {
        let count = read_nonblocking(STDIN_FD, &mut request);
        if count == REQUEST_LENGTH as u64 {
            return parse_package_request(&request);
        }
        if count == SYSCALL_EAGAIN {
            yield_now();
            continue;
        }
        if count == 0 {
            break;
        }
        if is_syscall_error(count) {
            return Err(());
        }
        return Err(());
    }

    let mut path = store_root();
    if !path.push(b"REQUEST") {
        return Err(());
    }
    match read_path_file(&mut path, &mut request) {
        ReadStatus::Missing => Ok(PackageRequest::Install),
        ReadStatus::Complete(length) if length == REQUEST_LENGTH => parse_package_request(&request),
        ReadStatus::Complete(_) | ReadStatus::Failed => Err(()),
    }
}

fn parse_package_request(request: &[u8; REQUEST_LENGTH]) -> Result<PackageRequest, ()> {
    if *request == REQUEST_INSTALL {
        Ok(PackageRequest::Install)
    } else if *request == REQUEST_UPDATE {
        Ok(PackageRequest::Update)
    } else if *request == REQUEST_ROLLBACK {
        Ok(PackageRequest::Rollback)
    } else if *request == REQUEST_SYNC {
        Ok(PackageRequest::Sync)
    } else if *request == REQUEST_RECOVER {
        Ok(PackageRequest::Recover)
    } else {
        Err(())
    }
}

fn fetch_remote_repository(buffer: &mut [u8; MAX_REPOSITORY_SIZE]) -> Option<usize> {
    let sent = net_send(
        REMOTE_REPOSITORY_IP,
        REMOTE_REPOSITORY_PORT,
        REMOTE_REPOSITORY_REQUEST,
    );
    if is_syscall_error(sent) || sent as usize != REMOTE_REPOSITORY_REQUEST.len() {
        return None;
    }
    let mut response = [0u8; NET_MAX_BUFFER_LENGTH];
    for _ in 0..64 {
        let received = net_receive(&mut response);
        if is_syscall_error(received) {
            yield_now();
            continue;
        }
        let received = received as usize;
        if received < NET_RECEIVE_HEADER_LENGTH
            || response[..4] != REMOTE_REPOSITORY_IP
            || u16::from_be_bytes([response[4], response[5]]) != REMOTE_REPOSITORY_PORT
        {
            continue;
        }
        let payload_length = received - NET_RECEIVE_HEADER_LENGTH;
        if payload_length > buffer.len() {
            return None;
        }
        buffer[..payload_length].copy_from_slice(&response[NET_RECEIVE_HEADER_LENGTH..received]);
        return Some(payload_length);
    }
    None
}

fn write_store_marker(name: &[u8], bytes: &[u8]) -> bool {
    let mut path = store_root();
    path.push(name) && write_path_file(&mut path, bytes)
}

fn read_generation_history() -> [[u8; 8]; GENERATION_HISTORY_SLOTS] {
    let mut history = [[0u8; 8]; GENERATION_HISTORY_SLOTS];
    let mut path = store_root();
    if !path.push(GENERATION_HISTORY_PATH) {
        return history;
    }
    let mut bytes = [0u8; GENERATION_HISTORY_LENGTH];
    if !matches!(
        read_path_file(&mut path, &mut bytes),
        ReadStatus::Complete(length) if length == GENERATION_HISTORY_LENGTH
    ) {
        return history;
    }
    for (index, entry) in history.iter_mut().enumerate() {
        let start = index * 8;
        entry.copy_from_slice(&bytes[start..start + 8]);
    }
    history
}

fn write_generation_history(history: &[[u8; 8]; GENERATION_HISTORY_SLOTS]) -> bool {
    let mut bytes = [0u8; GENERATION_HISTORY_LENGTH];
    for (index, entry) in history.iter().enumerate() {
        let start = index * 8;
        bytes[start..start + 8].copy_from_slice(entry);
    }
    write_store_marker(GENERATION_HISTORY_PATH, &bytes)
}

fn valid_generation_id(id: &[u8; 8]) -> bool {
    id.iter().any(|byte| *byte != 0)
}

fn transition_generation_history(
    new_active: [u8; 8],
    previous_active: [u8; 8],
    old_history: [[u8; 8]; GENERATION_HISTORY_SLOTS],
) -> [[u8; 8]; GENERATION_HISTORY_SLOTS] {
    let mut next = [[0u8; 8]; GENERATION_HISTORY_SLOTS];
    let mut count = 0;
    for candidate in [
        new_active,
        previous_active,
        old_history[0],
        old_history[1],
        old_history[2],
    ] {
        if !valid_generation_id(&candidate)
            || next[..count].iter().any(|existing| *existing == candidate)
        {
            continue;
        }
        if count == next.len() {
            break;
        }
        next[count] = candidate;
        count += 1;
    }
    next
}

fn commit_generation_transition(new_active: [u8; 8], previous_active: [u8; 8]) -> bool {
    let history =
        transition_generation_history(new_active, previous_active, read_generation_history());
    if valid_generation_id(&previous_active) && !write_store_marker(b"PREVIOUS", &previous_active) {
        return false;
    }
    write_generation_history(&history) && write_store_marker(b"ACTIVE", &new_active)
}

fn install_initial_generation(
    repository: &Repository,
    repository_bytes: &[u8],
    latest: RepositoryEntry,
) -> bool {
    let mut staged_ids = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
    let mut staged_count = 0;
    let mut previous_id = [0u8; 8];
    let mut older_id = [0u8; 8];
    if let Some(previous) = find_previous_repository_entry(repository, latest) {
        previous_id = previous.id;
        let mut order = [None; MAX_REPOSITORY_PACKAGES];
        let mut count = 0;
        let mut visiting = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
        if !resolve_dependencies(
            repository,
            previous.id,
            &mut order,
            &mut count,
            &mut visiting,
            0,
        ) || !stage_order(
            &order,
            count,
            repository_bytes,
            &mut staged_ids,
            &mut staged_count,
        ) {
            return false;
        }
        if !write_store_marker(b"PREVIOUS", &previous.id) {
            return false;
        }
        write_stdout(b"pkg: rollback candidate ");
        write_stdout(&previous.id);
        write_stdout(b" version=");
        write_decimal(previous.version as usize);
        write_stdout(b"\n");

        if let Some(older) = find_previous_repository_entry(repository, previous) {
            older_id = older.id;
            let mut order = [None; MAX_REPOSITORY_PACKAGES];
            let mut count = 0;
            let mut visiting = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
            if !resolve_dependencies(
                repository,
                older.id,
                &mut order,
                &mut count,
                &mut visiting,
                0,
            ) || !stage_order(
                &order,
                count,
                repository_bytes,
                &mut staged_ids,
                &mut staged_count,
            ) {
                return false;
            }
            write_stdout(b"pkg: recovery candidate ");
            write_stdout(&older.id);
            write_stdout(b" version=");
            write_decimal(older.version as usize);
            write_stdout(b"\n");
        }
    }

    let mut order = [None; MAX_REPOSITORY_PACKAGES];
    let mut count = 0;
    let mut visiting = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
    if !resolve_dependencies(
        repository,
        latest.id,
        &mut order,
        &mut count,
        &mut visiting,
        0,
    ) || !stage_order(
        &order,
        count,
        repository_bytes,
        &mut staged_ids,
        &mut staged_count,
    ) {
        return false;
    }
    let history = [latest.id, previous_id, older_id];
    if !write_generation_history(&history) || !write_store_marker(b"ACTIVE", &latest.id) {
        return false;
    }
    write_stdout(b"pkg: activated ");
    write_stdout(&latest.id);
    write_stdout(b" version=");
    write_decimal(latest.version as usize);
    write_stdout(b"\n");
    true
}

fn update_generation(
    repository: &Repository,
    repository_bytes: &[u8],
    active: RepositoryEntry,
    latest: RepositoryEntry,
) -> bool {
    let mut order = [None; MAX_REPOSITORY_PACKAGES];
    let mut count = 0;
    let mut visiting = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
    let mut staged_ids = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
    let mut staged_count = 0;
    if !resolve_dependencies(
        repository,
        latest.id,
        &mut order,
        &mut count,
        &mut visiting,
        0,
    ) || !stage_order(
        &order,
        count,
        repository_bytes,
        &mut staged_ids,
        &mut staged_count,
    ) {
        return false;
    }
    if !commit_generation_transition(latest.id, active.id) {
        return false;
    }
    write_stdout(b"pkg: updated ");
    write_stdout(&active.id);
    write_stdout(b" -> ");
    write_stdout(&latest.id);
    write_stdout(b" version=");
    write_decimal(latest.version as usize);
    write_stdout(b"\n");
    true
}

fn rollback_generation(
    repository: &Repository,
    repository_bytes: &[u8],
    active: RepositoryEntry,
    previous: RepositoryEntry,
) -> bool {
    let mut order = [None; MAX_REPOSITORY_PACKAGES];
    let mut count = 0;
    let mut visiting = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
    let mut staged_ids = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
    let mut staged_count = 0;
    if !resolve_dependencies(
        repository,
        previous.id,
        &mut order,
        &mut count,
        &mut visiting,
        0,
    ) || !stage_order(
        &order,
        count,
        repository_bytes,
        &mut staged_ids,
        &mut staged_count,
    ) {
        return false;
    }
    if !commit_generation_transition(previous.id, active.id) {
        return false;
    }
    write_stdout(b"pkg: rolled back ");
    write_stdout(&active.id);
    write_stdout(b" -> ");
    write_stdout(&previous.id);
    write_stdout(b" version=");
    write_decimal(previous.version as usize);
    write_stdout(b"\n");
    true
}

fn recover_generation(
    repository: &Repository,
    repository_bytes: &[u8],
    current: Option<[u8; 8]>,
) -> Option<[u8; 8]> {
    let history = read_generation_history();
    for candidate_id in history {
        if !valid_generation_id(&candidate_id) || current == Some(candidate_id) {
            continue;
        }
        let Some(candidate) = find_repository_entry_by_id(repository, candidate_id) else {
            continue;
        };
        let mut order = [None; MAX_REPOSITORY_PACKAGES];
        let mut count = 0;
        let mut visiting = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
        let mut staged_ids = [[0u8; 8]; MAX_REPOSITORY_PACKAGES];
        let mut staged_count = 0;
        if !resolve_dependencies(
            repository,
            candidate.id,
            &mut order,
            &mut count,
            &mut visiting,
            0,
        ) || !stage_order(
            &order,
            count,
            repository_bytes,
            &mut staged_ids,
            &mut staged_count,
        ) || !verify_active_closure(repository, repository_bytes, &order, count)
        {
            continue;
        }

        let previous = current
            .filter(|id| find_repository_entry_by_id(repository, *id).is_some())
            .unwrap_or([0u8; 8]);
        if !commit_generation_transition(candidate.id, previous) {
            return None;
        }
        write_stdout(b"pkg: recovered ");
        write_stdout(&candidate.id);
        write_stdout(b" version=");
        write_decimal(candidate.version as usize);
        write_stdout(b" history_slots=");
        write_decimal(GENERATION_HISTORY_SLOTS);
        write_stdout(b"\n");
        return Some(candidate.id);
    }
    None
}

fn stage_order(
    order: &[Option<RepositoryEntry>; MAX_REPOSITORY_PACKAGES],
    count: usize,
    repository_bytes: &[u8],
    staged_ids: &mut [[u8; 8]; MAX_REPOSITORY_PACKAGES],
    staged_count: &mut usize,
) -> bool {
    for entry in order.iter().flatten().take(count) {
        if staged_ids[..*staged_count]
            .iter()
            .any(|staged| *staged == entry.id)
        {
            continue;
        }
        let Some(package_bytes) = repository_package(entry, repository_bytes) else {
            return false;
        };
        let Some(package) = parse_package(package_bytes) else {
            return false;
        };
        if package.id != entry.id || sha256(package_bytes) != entry.digest {
            return false;
        }
        if !install_package(&package, package_bytes) || *staged_count == staged_ids.len() {
            return false;
        }
        staged_ids[*staged_count] = entry.id;
        *staged_count += 1;
    }
    true
}

fn verify_active_closure(
    repository: &Repository,
    repository_bytes: &[u8],
    order: &[Option<RepositoryEntry>; MAX_REPOSITORY_PACKAGES],
    count: usize,
) -> bool {
    for entry in order.iter().flatten().take(count) {
        let Some(package_bytes) = repository_package(entry, repository_bytes) else {
            return false;
        };
        let Some(package) = parse_package(package_bytes) else {
            return false;
        };
        if package.id != entry.id || sha256(package_bytes) != entry.digest {
            return false;
        }
        if !verify_active_package(&package, package_bytes) {
            return false;
        }
    }
    let _ = repository;
    true
}

fn verify_repository_signature(bytes: &[u8]) -> Option<RepositoryTrust> {
    if bytes.len() < REPOSITORY_HEADER_LENGTH + REPOSITORY_SIGNATURE_LENGTH
        || &bytes[..REPOSITORY_MAGIC.len()] != REPOSITORY_MAGIC
        || bytes[5] != REPOSITORY_VERSION
    {
        return None;
    }
    let flags = bytes[7];
    if flags & !REPOSITORY_ROTATION_FLAG != 0 {
        return None;
    }
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&bytes[8..16]);
    if !valid_identifier(&key_id) {
        return None;
    }

    let stored = load_trusted_key();
    let (public_key, rotation_signature, persisted) = if key_id == TRUSTED_ROOT_KEY_ID {
        // A device that has already accepted a rotated key must not silently downgrade to the
        // bootstrap key. The root remains available to authenticate future rotations.
        if stored.id != TRUSTED_ROOT_KEY_ID {
            return None;
        }
        if flags != 0 {
            return None;
        }
        (
            TRUSTED_ROOT_PUBLIC_KEY,
            [0u8; REPOSITORY_SIGNATURE_LENGTH],
            stored.persisted,
        )
    } else if key_id == stored.id {
        (stored.public_key, stored.rotation_signature, true)
    } else if flags == REPOSITORY_ROTATION_FLAG {
        let rotation_end =
            REPOSITORY_HEADER_LENGTH.checked_add(REPOSITORY_ROTATION_MATERIAL_LENGTH)?;
        if bytes.len() < rotation_end + REPOSITORY_SIGNATURE_LENGTH {
            return None;
        }
        let mut rotated_public_key = [0u8; 32];
        rotated_public_key
            .copy_from_slice(&bytes[REPOSITORY_HEADER_LENGTH..REPOSITORY_HEADER_LENGTH + 32]);
        let rotation_signature_bytes = <[u8; REPOSITORY_SIGNATURE_LENGTH]>::try_from(
            &bytes[REPOSITORY_HEADER_LENGTH + 32..rotation_end],
        )
        .ok()?;
        let rotation_signature = Signature::from_bytes(&rotation_signature_bytes);
        let root = VerifyingKey::from_bytes(&TRUSTED_ROOT_PUBLIC_KEY).ok()?;
        root.verify(
            &key_rotation_message(&key_id, &rotated_public_key),
            &rotation_signature,
        )
        .ok()?;
        (rotated_public_key, rotation_signature_bytes, false)
    } else {
        return None;
    };

    let signed_length = bytes.len() - REPOSITORY_SIGNATURE_LENGTH;
    let key = VerifyingKey::from_bytes(&public_key).ok()?;
    let signature_bytes =
        <[u8; REPOSITORY_SIGNATURE_LENGTH]>::try_from(&bytes[signed_length..]).ok()?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify(&bytes[..signed_length], &signature).ok()?;
    Some(RepositoryTrust {
        id: key_id,
        public_key,
        rotation_signature,
        persisted,
    })
}

fn key_rotation_message(
    key_id: &[u8; 8],
    public_key: &[u8; 32],
) -> [u8; KEY_ROTATION_MESSAGE_LENGTH] {
    let mut message = [0u8; KEY_ROTATION_MESSAGE_LENGTH];
    let mut cursor = 0;
    message[cursor..cursor + KEY_ROTATION_DOMAIN.len()].copy_from_slice(KEY_ROTATION_DOMAIN);
    cursor += KEY_ROTATION_DOMAIN.len();
    message[cursor..cursor + key_id.len()].copy_from_slice(key_id);
    cursor += key_id.len();
    message[cursor..cursor + public_key.len()].copy_from_slice(public_key);
    message
}

fn load_trusted_key() -> RepositoryTrust {
    let root = RepositoryTrust {
        id: TRUSTED_ROOT_KEY_ID,
        public_key: TRUSTED_ROOT_PUBLIC_KEY,
        rotation_signature: [0u8; REPOSITORY_SIGNATURE_LENGTH],
        persisted: false,
    };
    let mut path = store_root();
    if !path.push(TRUSTED_KEY_PATH) {
        return root;
    }
    let mut bytes = [0u8; TRUSTED_KEY_LENGTH];
    if !matches!(
        read_path_file(&mut path, &mut bytes),
        ReadStatus::Complete(length) if length == TRUSTED_KEY_LENGTH
    ) {
        return root;
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes[..8]);
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes[8..40]);
    let mut rotation_signature = [0u8; REPOSITORY_SIGNATURE_LENGTH];
    rotation_signature.copy_from_slice(&bytes[40..]);
    if !valid_identifier(&id) || VerifyingKey::from_bytes(&public_key).is_err() {
        return root;
    }
    if id == TRUSTED_ROOT_KEY_ID {
        if public_key != TRUSTED_ROOT_PUBLIC_KEY
            || rotation_signature != [0u8; REPOSITORY_SIGNATURE_LENGTH]
        {
            return root;
        }
    } else {
        let Ok(root_key) = VerifyingKey::from_bytes(&TRUSTED_ROOT_PUBLIC_KEY) else {
            return root;
        };
        let signature = Signature::from_bytes(&rotation_signature);
        if root_key
            .verify(&key_rotation_message(&id, &public_key), &signature)
            .is_err()
        {
            return root;
        }
    }
    RepositoryTrust {
        id,
        public_key,
        rotation_signature,
        persisted: true,
    }
}

fn persist_trusted_key(trust: RepositoryTrust) -> bool {
    let mut bytes = [0u8; TRUSTED_KEY_LENGTH];
    bytes[..8].copy_from_slice(&trust.id);
    bytes[8..40].copy_from_slice(&trust.public_key);
    bytes[40..].copy_from_slice(&trust.rotation_signature);
    write_store_marker(TRUSTED_KEY_PATH, &bytes)
}

fn parse_repository(bytes: &[u8]) -> Option<Repository> {
    if bytes.len() > MAX_REPOSITORY_SIZE
        || bytes.len() < REPOSITORY_HEADER_LENGTH + REPOSITORY_SIGNATURE_LENGTH
        || &bytes[..REPOSITORY_MAGIC.len()] != REPOSITORY_MAGIC
        || bytes[5] != REPOSITORY_VERSION
        || bytes[7] & !REPOSITORY_ROTATION_FLAG != 0
    {
        return None;
    }
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&bytes[8..16]);
    if !valid_identifier(&key_id) {
        return None;
    }
    let package_count = usize::from(bytes[6]);
    if package_count == 0 || package_count > MAX_REPOSITORY_PACKAGES {
        return None;
    }
    let signed_length = bytes.len() - REPOSITORY_SIGNATURE_LENGTH;
    let entries_start = repository_entries_start(bytes)?;
    let entries_end =
        entries_start.checked_add(package_count.checked_mul(REPOSITORY_ENTRY_LENGTH)?)?;
    if entries_end > signed_length {
        return None;
    }

    let mut entries: [Option<RepositoryEntry>; MAX_REPOSITORY_PACKAGES] =
        [None; MAX_REPOSITORY_PACKAGES];
    for index in 0..package_count {
        let start = entries_start + index * REPOSITORY_ENTRY_LENGTH;
        let name_length = usize::from(bytes[start + 8]);
        let dependency_count = usize::from(bytes[start + 9]);
        if name_length == 0
            || name_length > MAX_REPOSITORY_NAME_LENGTH
            || dependency_count > MAX_REPOSITORY_DEPENDENCIES
            || !valid_repository_name(&bytes[start + 14..start + 26])
        {
            return None;
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&bytes[start..start + 8]);
        if !valid_identifier(&id) {
            return None;
        }
        let version = read_u32(bytes, start + 10);
        if version == 0 {
            return None;
        }
        let mut name = [0u8; MAX_REPOSITORY_NAME_LENGTH];
        name.copy_from_slice(&bytes[start + 14..start + 26]);
        if name[..name_length].iter().any(|byte| *byte == 0)
            || name[name_length..].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let mut dependencies = [[0u8; 8]; MAX_REPOSITORY_DEPENDENCIES];
        for dependency_index in 0..MAX_REPOSITORY_DEPENDENCIES {
            let dependency_start = start + 26 + dependency_index * 8;
            dependencies[dependency_index]
                .copy_from_slice(&bytes[dependency_start..dependency_start + 8]);
            if dependency_index >= dependency_count
                && dependencies[dependency_index].iter().any(|byte| *byte != 0)
            {
                return None;
            }
            if dependency_index < dependency_count
                && !valid_identifier(&dependencies[dependency_index])
            {
                return None;
            }
        }
        let package_start = usize::try_from(read_u32(bytes, start + 42)).ok()?;
        let package_length = usize::try_from(read_u32(bytes, start + 46)).ok()?;
        let package_end = package_start.checked_add(package_length)?;
        if package_start < entries_end
            || package_end > signed_length
            || package_length == 0
            || package_length > MAX_PACKAGE_SIZE
        {
            return None;
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[start + 50..start + 82]);
        let entry = RepositoryEntry {
            id,
            version,
            name,
            name_length,
            dependencies,
            dependency_count,
            package_start,
            package_length,
            digest,
        };
        if entries[..index].iter().flatten().any(|existing| {
            existing.id == entry.id
                || (existing.name[..existing.name_length] == entry.name[..entry.name_length]
                    && existing.version == entry.version)
                || ranges_overlap(
                    existing.package_start,
                    existing.package_length,
                    entry.package_start,
                    entry.package_length,
                )
        }) {
            return None;
        }
        entries[index] = Some(entry);
    }
    Some(Repository {
        entries,
        package_count,
    })
}

fn repository_entries_start(bytes: &[u8]) -> Option<usize> {
    let rotation_material = if bytes.get(7).copied()? & REPOSITORY_ROTATION_FLAG != 0 {
        REPOSITORY_ROTATION_MATERIAL_LENGTH
    } else {
        0
    };
    REPOSITORY_HEADER_LENGTH.checked_add(rotation_material)
}

fn valid_repository_name(bytes: &[u8]) -> bool {
    let mut seen_zero = false;
    for byte in bytes {
        if *byte == 0 {
            seen_zero = true;
        } else if seen_zero || !byte.is_ascii_uppercase() && !byte.is_ascii_digit() {
            return false;
        }
    }
    bytes.iter().any(|byte| *byte != 0)
}

fn ranges_overlap(
    first_start: usize,
    first_length: usize,
    second_start: usize,
    second_length: usize,
) -> bool {
    let Some(first_end) = first_start.checked_add(first_length) else {
        return true;
    };
    let Some(second_end) = second_start.checked_add(second_length) else {
        return true;
    };
    first_start < second_end && second_start < first_end
}

fn find_latest_repository_entry(repository: &Repository, name: &[u8]) -> Option<RepositoryEntry> {
    let mut latest = None;
    for entry in repository.entries.iter().flatten().copied() {
        if entry.name[..entry.name_length] != *name {
            continue;
        }
        if latest
            .map(|candidate: RepositoryEntry| entry.version > candidate.version)
            .unwrap_or(true)
        {
            latest = Some(entry);
        }
    }
    latest
}

fn find_previous_repository_entry(
    repository: &Repository,
    latest: RepositoryEntry,
) -> Option<RepositoryEntry> {
    let mut previous = None;
    for entry in repository.entries.iter().flatten().copied() {
        if entry.name[..entry.name_length] != latest.name[..latest.name_length]
            || entry.version >= latest.version
        {
            continue;
        }
        if previous
            .map(|candidate: RepositoryEntry| entry.version > candidate.version)
            .unwrap_or(true)
        {
            previous = Some(entry);
        }
    }
    previous
}

fn find_repository_entry_by_id(repository: &Repository, id: [u8; 8]) -> Option<RepositoryEntry> {
    repository
        .entries
        .iter()
        .flatten()
        .copied()
        .find(|entry| entry.id == id)
}

fn resolve_dependencies(
    repository: &Repository,
    id: [u8; 8],
    order: &mut [Option<RepositoryEntry>; MAX_REPOSITORY_PACKAGES],
    order_length: &mut usize,
    visiting: &mut [[u8; 8]; MAX_REPOSITORY_PACKAGES],
    depth: usize,
) -> bool {
    if order[..*order_length]
        .iter()
        .flatten()
        .any(|entry| entry.id == id)
    {
        return true;
    }
    if depth >= MAX_REPOSITORY_PACKAGES
        || visiting[..depth].iter().any(|candidate| *candidate == id)
    {
        return false;
    }
    let Some(entry) = find_repository_entry_by_id(repository, id) else {
        return false;
    };
    visiting[depth] = id;
    for dependency in entry.dependencies.iter().take(entry.dependency_count) {
        if !resolve_dependencies(
            repository,
            *dependency,
            order,
            order_length,
            visiting,
            depth + 1,
        ) {
            return false;
        }
    }
    if *order_length == order.len() {
        return false;
    }
    order[*order_length] = Some(entry);
    *order_length += 1;
    true
}

fn repository_package<'a>(entry: &RepositoryEntry, bytes: &'a [u8]) -> Option<&'a [u8]> {
    let end = entry.package_start.checked_add(entry.package_length)?;
    bytes.get(entry.package_start..end)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

fn parse_package(bytes: &[u8]) -> Option<Package> {
    if bytes.len() > MAX_PACKAGE_SIZE
        || bytes.len() < PACKAGE_HEADER_LENGTH
        || &bytes[..PACKAGE_MAGIC.len()] != PACKAGE_MAGIC
        || bytes[5] != PACKAGE_VERSION
        || bytes[7] != 0
    {
        return None;
    }
    let file_count = usize::from(bytes[6]);
    if file_count == 0 || file_count > MAX_PACKAGE_FILES {
        return None;
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes[8..16]);
    if !valid_identifier(&id) {
        return None;
    }

    let mut files: [Option<PackageFile>; MAX_PACKAGE_FILES] = [None; MAX_PACKAGE_FILES];
    let mut cursor = PACKAGE_HEADER_LENGTH;
    for index in 0..file_count {
        let record_end = cursor.checked_add(PACKAGE_RECORD_HEADER_LENGTH)?;
        if record_end > bytes.len() {
            return None;
        }
        let path_length = usize::from(bytes[cursor]);
        if bytes[cursor + 1] != 0 {
            return None;
        }
        let data_length = usize::try_from(read_u32(bytes, cursor + 2)).ok()?;
        let checksum = read_u32(bytes, cursor + 6);
        cursor = record_end;
        let path_end = cursor.checked_add(path_length)?;
        let data_start = path_end;
        let data_end = data_start.checked_add(data_length)?;
        if path_end > bytes.len()
            || data_end > bytes.len()
            || data_length > MAX_PACKAGE_FILE_SIZE
            || !valid_package_path(&bytes[cursor..path_end])
            || crc32(&bytes[data_start..data_end]) != checksum
        {
            return None;
        }
        let file = PackageFile {
            path_start: cursor,
            path_length,
            data_start,
            data_length,
            checksum,
        };
        if files[..index].iter().flatten().any(|existing| {
            existing.path_length == path_length
                && existing.path_start < bytes.len()
                && bytes[existing.path_start..existing.path_start + path_length]
                    == bytes[cursor..path_end]
        }) {
            return None;
        }
        files[index] = Some(file);
        cursor = data_end;
    }
    if cursor != bytes.len() {
        return None;
    }
    Some(Package {
        id,
        files,
        file_count,
    })
}

fn valid_identifier(identifier: &[u8; 8]) -> bool {
    identifier
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn valid_package_path(path: &[u8]) -> bool {
    if path.is_empty() || path.len() > MAX_PACKAGE_PATH_LENGTH || path[0] != b'/' {
        return false;
    }
    let components = path[1..].split(|byte| *byte == b'/');
    let mut count = 0;
    for component in components {
        if count == MAX_PACKAGE_COMPONENTS || !valid_short_component(component) {
            return false;
        }
        count += 1;
    }
    count != 0 && !path.ends_with(b"/")
}

fn valid_short_component(component: &[u8]) -> bool {
    if component.is_empty() || component == b"." || component == b".." {
        return false;
    }
    let (base, extension) = match component.iter().position(|byte| *byte == b'.') {
        Some(dot) => {
            if component[dot + 1..].contains(&b'.') {
                return false;
            }
            (&component[..dot], &component[dot + 1..])
        }
        None => (component, &component[component.len()..]),
    };
    !base.is_empty()
        && base.len() <= 8
        && extension.len() <= 3
        && base
            .iter()
            .chain(extension)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'$'))
}

fn install_package(package: &Package, bytes: &[u8]) -> bool {
    let mut generation = store_root();
    if !generation.push(&package.id) || !mkdir_path(&mut generation) {
        return false;
    }
    for file in package.files.iter().flatten().take(package.file_count) {
        let Some(mut path) = staged_file_path(
            &package.id,
            &bytes[file.path_start..file.path_start + file.path_length],
        ) else {
            return false;
        };
        let data = &bytes[file.data_start..file.data_start + file.data_length];
        if !write_path_file(&mut path, data) {
            return false;
        }
    }

    if !generation.push(b"MANIFEST") || !write_path_file(&mut generation, bytes) {
        return false;
    }
    write_stdout(b"pkg: staged ");
    write_stdout(&package.id);
    write_stdout(b"\n");
    true
}

fn verify_active_package(package: &Package, bytes: &[u8]) -> bool {
    let mut manifest = store_root();
    if !manifest.push(&package.id) || !manifest.push(b"MANIFEST") {
        return false;
    }
    let mut stored_manifest = [0u8; MAX_PACKAGE_SIZE];
    if !matches!(
        read_path_file(&mut manifest, &mut stored_manifest),
        ReadStatus::Complete(length) if length == bytes.len() && stored_manifest[..length] == *bytes
    ) {
        return false;
    }

    for file in package.files.iter().flatten().take(package.file_count) {
        let Some(mut path) = staged_file_path(
            &package.id,
            &bytes[file.path_start..file.path_start + file.path_length],
        ) else {
            return false;
        };
        let data = &bytes[file.data_start..file.data_start + file.data_length];
        if !verify_path_file(&mut path, data, file.checksum) {
            return false;
        }
        write_stdout(b"pkg: verified ");
        write_stdout(&bytes[file.path_start..file.path_start + file.path_length]);
        write_stdout(b"\n");
    }
    true
}

fn store_root() -> PathBuffer {
    let mut path = PathBuffer::root();
    let _ = path.push(b"VAR");
    let _ = mkdir_path(&mut path);
    let _ = path.push(b"PKG");
    let _ = mkdir_path(&mut path);
    path
}

fn staged_file_path(id: &[u8; 8], package_path: &[u8]) -> Option<PathBuffer> {
    let mut path = store_root();
    if !path.push(id) || !mkdir_path(&mut path) {
        return None;
    }
    let components = package_path[1..]
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty());
    let component_count = components.clone().count();
    for (index, component) in components.enumerate() {
        if !path.push(component) {
            return None;
        }
        if index + 1 < component_count && !mkdir_path(&mut path) {
            return None;
        }
    }
    Some(path)
}

fn mkdir_path(path: &mut PathBuffer) -> bool {
    // FAT directory creation reports an existing directory as an error. Every path here is
    // generated from an already validated short-name manifest, so an error means either the
    // directory already exists or a later file operation will expose the real failure.
    let _ = mkdir(path.c_path());
    true
}

fn read_path_file(path: &mut PathBuffer, buffer: &mut [u8]) -> ReadStatus {
    read_file(path.c_path(), buffer)
}

fn read_file(path: &[u8], buffer: &mut [u8]) -> ReadStatus {
    let handle = open(path);
    if is_syscall_error(handle) {
        return ReadStatus::Missing;
    }
    let mut chunk = [0u8; WRITE_CHUNK_LENGTH];
    let mut length = 0;
    let mut failed = false;
    loop {
        if length == buffer.len() {
            let count = read(handle, &mut chunk);
            if is_syscall_error(count) || count != 0 {
                failed = true;
            }
            break;
        }
        let count = read(handle, &mut chunk);
        if is_syscall_error(count) {
            failed = true;
            break;
        }
        let count = count as usize;
        if count == 0 {
            break;
        }
        let Some(end) = length.checked_add(count) else {
            failed = true;
            break;
        };
        if end > buffer.len() {
            failed = true;
            break;
        }
        buffer[length..end].copy_from_slice(&chunk[..count]);
        length = end;
    }
    let _ = close(handle);
    if failed {
        ReadStatus::Failed
    } else {
        ReadStatus::Complete(length)
    }
}

fn write_path_file(path: &mut PathBuffer, bytes: &[u8]) -> bool {
    let handle = open_with_flags(path.c_path(), OPEN_CREATE | OPEN_WRITE);
    if is_syscall_error(handle) {
        return false;
    }
    let mut offset: usize = 0;
    let mut success = true;
    while offset < bytes.len() {
        let length = core::cmp::min(WRITE_CHUNK_LENGTH, bytes.len() - offset);
        let count = write(handle, &bytes[offset..offset + length]);
        if is_syscall_error(count) || count != length as u64 {
            success = false;
            break;
        }
        offset += length;
    }
    if is_syscall_error(close(handle)) {
        success = false;
    }
    success
}

fn verify_path_file(path: &mut PathBuffer, expected: &[u8], checksum: u32) -> bool {
    if crc32(expected) != checksum {
        return false;
    }
    let handle = open(path.c_path());
    if is_syscall_error(handle) {
        return false;
    }
    let mut buffer = [0u8; WRITE_CHUNK_LENGTH];
    let mut offset: usize = 0;
    let mut success = true;
    loop {
        let count = read(handle, &mut buffer);
        if is_syscall_error(count) {
            success = false;
            break;
        }
        let count = count as usize;
        if count == 0 {
            break;
        }
        if offset.checked_add(count).is_none()
            || offset + count > expected.len()
            || buffer[..count] != expected[offset..offset + count]
        {
            success = false;
            break;
        }
        offset += count;
    }
    if is_syscall_error(close(handle)) {
        success = false;
    }
    success && offset == expected.len()
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes.iter().copied() {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn write_decimal(mut value: usize) {
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
