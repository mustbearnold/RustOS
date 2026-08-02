#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

use rustos_userland::{
    PAGE_SIZE, exit, fork, is_syscall_error, mmap, munmap, waitpid, write_stdout,
};

const PAGE_COUNT: usize = 3;
const MAPPING_LENGTH: usize = PAGE_COUNT * PAGE_SIZE;
const STRESS_PAGE_COUNT: usize = 256;
const STRESS_CYCLES: usize = 128;
const STRESS_LENGTH: usize = STRESS_PAGE_COUNT * PAGE_SIZE;
const PATTERN: u64 = 0x5255_5354_4f53_564d;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let first = mmap(MAPPING_LENGTH, true);
    if is_syscall_error(first) || first % PAGE_SIZE as u64 != 0 {
        fail(b"userland: vm mmap failed\n");
    }
    if !write_and_check(first, PAGE_COUNT) {
        fail(b"userland: vm mapped-page readback failed\n");
    }

    let child = fork();
    if is_syscall_error(child) {
        fail(b"userland: vm fork failed\n");
    }
    if child == 0 {
        if !check_pattern(first, PAGE_COUNT) {
            fail(b"userland: vm fork clone readback failed\n");
        }
        exit(17);
    }
    let result = waitpid(child);
    if result.pid != child || result.status != 17 {
        fail(b"userland: vm fork wait failed\n");
    }

    if munmap(first, MAPPING_LENGTH) != 0 {
        fail(b"userland: vm munmap failed\n");
    }

    let second = mmap(MAPPING_LENGTH, true);
    if is_syscall_error(second) || second != first {
        fail(b"userland: vm virtual-range reuse failed\n");
    }
    if !write_and_check(second, PAGE_COUNT) || munmap(second, MAPPING_LENGTH) != 0 {
        fail(b"userland: vm remapped-page lifecycle failed\n");
    }

    write_stdout(b"userland: vm stress=started\n");
    for cycle in 0..STRESS_CYCLES {
        let address = mmap(STRESS_LENGTH, true);
        if is_syscall_error(address) || !write_and_check(address, STRESS_PAGE_COUNT) {
            fail(b"userland: vm physical-reuse stress failed\n");
        }
        if munmap(address, STRESS_LENGTH) != 0 {
            fail(b"userland: vm physical-reuse unmap failed\n");
        }
        if cycle == 15 {
            write_stdout(b"userland: vm stress=16\n");
        } else if cycle == 31 {
            write_stdout(b"userland: vm stress=32\n");
        } else if cycle == 63 {
            write_stdout(b"userland: vm stress=64\n");
        } else if cycle == 95 {
            write_stdout(b"userland: vm stress=96\n");
        }
    }

    write_stdout(
        b"userland: vm map=ready write=ready fork=ready unmap=ready reuse=ready reclaim=ready status=ready\n",
    );
    exit(0);
}

fn write_and_check(base: u64, page_count: usize) -> bool {
    for page in 0..page_count {
        let address = base + (page * PAGE_SIZE) as u64;
        // SAFETY: the kernel just returned a writable, page-aligned mapping for this bounded
        // range, and each access stays within the mapped page.
        unsafe {
            write_volatile(address as *mut u64, PATTERN ^ page as u64);
            if read_volatile(address as *const u64) != PATTERN ^ page as u64 {
                return false;
            }
        }
    }
    true
}

fn check_pattern(base: u64, page_count: usize) -> bool {
    for page in 0..page_count {
        let address = base + (page * PAGE_SIZE) as u64;
        // SAFETY: the parent wrote this bounded mapping before fork, and the child owns a deep
        // copy of the same mapped pages after the fork syscall returns.
        unsafe {
            if read_volatile(address as *const u64) != PATTERN ^ page as u64 {
                return false;
            }
        }
    }
    true
}

fn fail(message: &[u8]) -> ! {
    write_stdout(message);
    exit(1);
}
