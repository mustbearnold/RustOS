use alloc::{boxed::Box, vec, vec::Vec};
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use spin::Mutex;

use crate::acpi::{AcpiInfo, MAX_PROCESSORS};
use crate::process::{ProcessId, ProcessState, ThreadId};

const MAX_LOCAL_APIC_IDS: usize = 256;
const MAX_SCHEDULER_CPUS: usize = 8;
const WORKERS_PER_CPU: usize = 2;
const RUNNABLE_TASKS_PER_CPU: usize = WORKERS_PER_CPU + 1;
const MAX_PROCESSES: usize = 16;
const MAX_THREADS: usize = 16;
const MAX_TASKS: usize = MAX_SCHEDULER_CPUS * RUNNABLE_TASKS_PER_CPU + MAX_PROCESSES + MAX_THREADS;
const TASK_STACK_SIZE: usize = 16 * 1024;

global_asm!(
    r#"
    .section .text.rustos_context_switch,"ax"
    .global rustos_context_switch
rustos_context_switch:
    mov [rdi + 0], rsp
    mov [rdi + 8], rbx
    mov [rdi + 16], rbp
    mov [rdi + 24], r12
    mov [rdi + 32], r13
    mov [rdi + 40], r14
    mov [rdi + 48], r15
    lea rax, [rip + rustos_context_resume]
    mov [rdi + 56], rax

    mov rsp, [rsi + 0]
    mov rbx, [rsi + 8]
    mov rbp, [rsi + 16]
    mov r12, [rsi + 24]
    mov r13, [rsi + 32]
    mov r14, [rsi + 40]
    mov r15, [rsi + 48]
    jmp qword ptr [rsi + 56]

rustos_context_resume:
    ret
    "#
);

unsafe extern "C" {
    fn rustos_context_switch(old: *mut Context, new: *const Context);
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Context {
    rsp: u64,
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
}

impl Context {
    const fn empty() -> Self {
        Self {
            rsp: 0,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
        }
    }

    fn worker(stack: &[u8], task_id: usize) -> Self {
        let stack_top = (stack.as_ptr() as u64 + TASK_STACK_SIZE as u64) & !0xf;
        Self {
            // The initial entry is a jump rather than a call. Reserving one word gives the Rust
            // entry point the same 16-byte ABI alignment it would have after a normal call.
            rsp: stack_top - 8,
            rbx: 0,
            rbp: 0,
            r12: task_id as u64,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: task_entry as *const () as usize as u64,
        }
    }

    fn process(stack: &[u8], task_id: usize, pid: ProcessId) -> Self {
        let stack_top = (stack.as_ptr() as u64 + TASK_STACK_SIZE as u64) & !0xf;
        Self {
            rsp: stack_top - 8,
            rbx: 0,
            rbp: 0,
            r12: task_id as u64,
            r13: u64::from(pid),
            r14: 0,
            r15: 0,
            rip: process_task_entry as *const () as usize as u64,
        }
    }

    fn thread(stack: &[u8], task_id: usize, tid: ThreadId) -> Self {
        let stack_top = (stack.as_ptr() as u64 + TASK_STACK_SIZE as u64) & !0xf;
        Self {
            rsp: stack_top - 8,
            rbx: 0,
            rbp: 0,
            r12: task_id as u64,
            r13: u64::from(tid),
            r14: 0,
            r15: 0,
            rip: thread_task_entry as *const () as usize as u64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskKind {
    Kernel,
    Process(ProcessId),
    Thread { pid: ProcessId, tid: ThreadId },
}

struct Task {
    id: usize,
    context: Context,
    kind: TaskKind,
    _stack: Option<Box<[u8]>>,
}

impl Task {
    fn boot(id: usize) -> Self {
        Self {
            id,
            context: Context::empty(),
            kind: TaskKind::Kernel,
            _stack: None,
        }
    }

    fn worker(id: usize) -> Self {
        let stack = vec![0u8; TASK_STACK_SIZE].into_boxed_slice();
        let context = Context::worker(&stack, id);
        Self {
            id,
            context,
            kind: TaskKind::Kernel,
            _stack: Some(stack),
        }
    }

    fn process(id: usize, pid: ProcessId) -> Self {
        let stack = vec![0u8; TASK_STACK_SIZE].into_boxed_slice();
        let context = Context::process(&stack, id, pid);
        Self {
            id,
            context,
            kind: TaskKind::Process(pid),
            _stack: Some(stack),
        }
    }

    fn thread(id: usize, pid: ProcessId, tid: ThreadId) -> Self {
        let stack = vec![0u8; TASK_STACK_SIZE].into_boxed_slice();
        let context = Context::thread(&stack, id, tid);
        Self {
            id,
            context,
            kind: TaskKind::Thread { pid, tid },
            _stack: Some(stack),
        }
    }

    fn process_id(&self) -> Option<ProcessId> {
        match self.kind {
            TaskKind::Kernel => None,
            TaskKind::Process(pid) => Some(pid),
            TaskKind::Thread { pid, .. } => Some(pid),
        }
    }

    fn thread_id(&self) -> Option<ThreadId> {
        match self.kind {
            TaskKind::Kernel | TaskKind::Process(_) => None,
            TaskKind::Thread { tid, .. } => Some(tid),
        }
    }
}

#[derive(Debug)]
struct CpuSchedule {
    apic_id: u32,
    sequence: Vec<usize>,
}

struct Scheduler {
    bsp_apic_id: u32,
    tasks: Vec<Task>,
    cpus: Vec<CpuSchedule>,
    next_process_cpu: usize,
    processes: Vec<ScheduledProcess>,
    threads: Vec<ScheduledThread>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScheduledProcess {
    pid: ProcessId,
    state: ProcessState,
    apic_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScheduledThread {
    tid: ThreadId,
    pid: ProcessId,
    state: ProcessState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessScheduleStats {
    pub pid: ProcessId,
    pub state: ProcessState,
}

impl Scheduler {
    fn next_task(&self, apic_id: u32, current: usize) -> Option<usize> {
        let cpu = self.cpus.iter().find(|cpu| cpu.apic_id == apic_id)?;
        let position = cpu
            .sequence
            .iter()
            .position(|task_id| *task_id == current)?;
        for offset in 1..=cpu.sequence.len() {
            let task_id = cpu.sequence[(position + offset) % cpu.sequence.len()];
            let task = &self.tasks[task_id];
            let process_runnable = match task.kind {
                TaskKind::Kernel => true,
                TaskKind::Process(pid) => self
                    .processes
                    .iter()
                    .find(|process| process.pid == pid)
                    .is_some_and(|process| {
                        matches!(process.state, ProcessState::Ready | ProcessState::Running)
                    }),
                TaskKind::Thread { pid, .. } => self
                    .processes
                    .iter()
                    .find(|process| process.pid == pid)
                    .is_some_and(|process| {
                        !matches!(process.state, ProcessState::Exited | ProcessState::Faulted)
                    }),
            };
            if !process_runnable {
                continue;
            }
            if let Some(tid) = task.thread_id() {
                let thread_runnable = self
                    .threads
                    .iter()
                    .find(|thread| thread.tid == tid)
                    .is_some_and(|thread| {
                        matches!(thread.state, ProcessState::Ready | ProcessState::Running)
                    });
                if !thread_runnable {
                    continue;
                }
            }
            return Some(task_id);
        }
        None
    }

    fn first_worker(&self, apic_id: u32) -> Option<usize> {
        self.cpus
            .iter()
            .find(|cpu| cpu.apic_id == apic_id)
            .and_then(|cpu| cpu.sequence.get(1).copied())
    }

    fn boot_task(&self, apic_id: u32) -> Option<usize> {
        self.cpus
            .iter()
            .find(|cpu| cpu.apic_id == apic_id)
            .and_then(|cpu| cpu.sequence.first().copied())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerError {
    AlreadyInitialized,
    MissingBsp,
    NoSupportedProcessor,
    TooManyProcessors,
    ProcessAlreadyRegistered,
    ProcessTableFull,
    ProcessNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerStats {
    pub discovered: u32,
    pub enabled: u32,
    pub scheduled_cpus: u32,
    pub tasks: u32,
    pub workers: u32,
    pub unsupported: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeStats {
    pub switches: u64,
    pub heartbeats: u64,
}

static SCHEDULER: Mutex<Option<Scheduler>> = Mutex::new(None);
static CURRENT_TASK: [AtomicUsize; MAX_LOCAL_APIC_IDS] =
    [const { AtomicUsize::new(usize::MAX) }; MAX_LOCAL_APIC_IDS];
static STARTED: [AtomicBool; MAX_LOCAL_APIC_IDS] =
    [const { AtomicBool::new(false) }; MAX_LOCAL_APIC_IDS];
static PREEMPTION_ENABLED: AtomicBool = AtomicBool::new(true);
static HEARTBEATS: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];
static SWITCHES: AtomicU64 = AtomicU64::new(0);
static VOLUNTARY_SWITCHES: AtomicU64 = AtomicU64::new(0);

pub fn init(info: &AcpiInfo) -> Result<SchedulerStats, SchedulerError> {
    let bsp_apic_id = crate::apic::local_apic_id_u32().ok_or(SchedulerError::MissingBsp)?;
    let processor_count = usize::try_from(info.processor_count)
        .unwrap_or(0)
        .min(MAX_PROCESSORS);
    let processors = info
        .processors
        .get(..processor_count)
        .ok_or(SchedulerError::NoSupportedProcessor)?;

    let mut enabled = 0u32;
    let mut unsupported = 0u32;
    let mut supported_processors = Vec::new();
    let mut bsp_supported = false;
    for processor in processors.iter().copied() {
        if !processor.enabled {
            continue;
        }
        enabled += 1;
        if processor.x2apic || processor.apic_id > u32::from(u8::MAX) {
            unsupported += 1;
            continue;
        }
        if processor.apic_id == bsp_apic_id {
            bsp_supported = true;
        }
        supported_processors.push(processor);
    }

    if !bsp_supported || supported_processors.is_empty() {
        return Err(SchedulerError::NoSupportedProcessor);
    }
    if supported_processors.len() > MAX_SCHEDULER_CPUS {
        return Err(SchedulerError::TooManyProcessors);
    }

    let mut guard = SCHEDULER.lock();
    if guard.is_some() {
        return Err(SchedulerError::AlreadyInitialized);
    }

    let mut scheduler = Scheduler {
        bsp_apic_id,
        tasks: Vec::with_capacity(MAX_TASKS),
        cpus: Vec::with_capacity(MAX_SCHEDULER_CPUS),
        next_process_cpu: 0,
        processes: Vec::with_capacity(MAX_PROCESSES),
        threads: Vec::with_capacity(MAX_THREADS),
    };
    for processor in supported_processors {
        let boot_id = scheduler.tasks.len();
        scheduler.tasks.push(Task::boot(boot_id));
        let worker_0 = scheduler.tasks.len();
        scheduler.tasks.push(Task::worker(worker_0));
        let worker_1 = scheduler.tasks.len();
        scheduler.tasks.push(Task::worker(worker_1));
        let mut sequence = Vec::with_capacity(MAX_TASKS);
        sequence.extend([boot_id, worker_0, worker_1]);
        scheduler.cpus.push(CpuSchedule {
            apic_id: processor.apic_id,
            sequence,
        });
        CURRENT_TASK[processor.apic_id as usize].store(boot_id, Ordering::Release);
    }
    scheduler.next_process_cpu = scheduler
        .cpus
        .iter()
        .position(|cpu| cpu.apic_id != bsp_apic_id)
        .unwrap_or(0);

    let stats = SchedulerStats {
        discovered: processors.len() as u32,
        enabled,
        scheduled_cpus: scheduler.cpus.len() as u32,
        tasks: scheduler.tasks.len() as u32,
        workers: (scheduler.tasks.len() - scheduler.cpus.len()) as u32,
        unsupported,
    };
    *guard = Some(scheduler);
    Ok(stats)
}

pub fn is_initialized() -> bool {
    SCHEDULER.lock().is_some()
}

pub fn register_process(pid: ProcessId) -> Result<ProcessScheduleStats, SchedulerError> {
    let mut guard = SCHEDULER.lock();
    let scheduler = guard.as_mut().ok_or(SchedulerError::ProcessNotFound)?;
    if scheduler.processes.iter().any(|process| process.pid == pid) {
        return Err(SchedulerError::ProcessAlreadyRegistered);
    }
    if scheduler.processes.len() == MAX_PROCESSES {
        return Err(SchedulerError::ProcessTableFull);
    }
    if scheduler.tasks.len() == MAX_TASKS {
        return Err(SchedulerError::ProcessTableFull);
    }
    let bsp_index = scheduler
        .cpus
        .iter()
        .position(|cpu| cpu.apic_id == scheduler.bsp_apic_id)
        .ok_or(SchedulerError::MissingBsp)?;
    let cpu_index = if pid == crate::process::INIT_PROCESS_ID {
        bsp_index
    } else {
        let cpu_index = scheduler.next_process_cpu;
        if scheduler.cpus.len() > 1 {
            let bsp_index = scheduler
                .cpus
                .iter()
                .position(|cpu| cpu.apic_id == scheduler.bsp_apic_id)
                .ok_or(SchedulerError::MissingBsp)?;
            let mut next = (cpu_index + 1) % scheduler.cpus.len();
            if next == bsp_index {
                next = (next + 1) % scheduler.cpus.len();
            }
            scheduler.next_process_cpu = next;
        } else {
            scheduler.next_process_cpu = 0;
        }
        cpu_index
    };
    let apic_id = scheduler.cpus[cpu_index].apic_id;
    let process = ScheduledProcess {
        pid,
        state: ProcessState::Ready,
        apic_id,
    };
    let task_id = scheduler.tasks.len();
    scheduler.tasks.push(Task::process(task_id, pid));
    scheduler.cpus[cpu_index].sequence.push(task_id);
    scheduler.processes.push(process);
    Ok(ProcessScheduleStats {
        pid,
        state: process.state,
    })
}

pub fn register_thread(
    pid: ProcessId,
    tid: ThreadId,
) -> Result<ProcessScheduleStats, SchedulerError> {
    let mut guard = SCHEDULER.lock();
    let scheduler = guard.as_mut().ok_or(SchedulerError::ProcessNotFound)?;
    if !scheduler.processes.iter().any(|process| process.pid == pid) {
        return Err(SchedulerError::ProcessNotFound);
    }
    if scheduler.threads.iter().any(|thread| thread.tid == tid) {
        return Err(SchedulerError::ProcessAlreadyRegistered);
    }
    if scheduler.threads.len() == MAX_THREADS || scheduler.tasks.len() == MAX_TASKS {
        return Err(SchedulerError::ProcessTableFull);
    }
    let cpu_index = scheduler
        .processes
        .iter()
        .find(|process| process.pid == pid)
        .and_then(|process| {
            scheduler
                .cpus
                .iter()
                .position(|cpu| cpu.apic_id == process.apic_id)
        })
        .ok_or(SchedulerError::ProcessNotFound)?;
    let thread = ScheduledThread {
        tid,
        pid,
        state: ProcessState::Ready,
    };
    let task_id = scheduler.tasks.len();
    scheduler.tasks.push(Task::thread(task_id, pid, tid));
    scheduler.cpus[cpu_index].sequence.push(task_id);
    scheduler.threads.push(thread);
    Ok(ProcessScheduleStats {
        pid,
        state: thread.state,
    })
}

pub fn set_process_state(
    pid: ProcessId,
    state: ProcessState,
) -> Result<ProcessScheduleStats, SchedulerError> {
    let mut guard = SCHEDULER.lock();
    let scheduler = guard.as_mut().ok_or(SchedulerError::ProcessNotFound)?;
    let process = scheduler
        .processes
        .iter_mut()
        .find(|process| process.pid == pid)
        .ok_or(SchedulerError::ProcessNotFound)?;
    process.state = state;
    Ok(ProcessScheduleStats {
        pid: process.pid,
        state: process.state,
    })
}

pub fn set_thread_state(
    tid: ThreadId,
    state: ProcessState,
) -> Result<ProcessScheduleStats, SchedulerError> {
    let mut guard = SCHEDULER.lock();
    let scheduler = guard.as_mut().ok_or(SchedulerError::ProcessNotFound)?;
    let thread = scheduler
        .threads
        .iter_mut()
        .find(|thread| thread.tid == tid)
        .ok_or(SchedulerError::ProcessNotFound)?;
    thread.state = state;
    Ok(ProcessScheduleStats {
        pid: thread.pid,
        state: thread.state,
    })
}

pub fn process_stats(pid: ProcessId) -> Option<ProcessScheduleStats> {
    SCHEDULER
        .lock()
        .as_ref()?
        .processes
        .iter()
        .find(|process| process.pid == pid)
        .copied()
        .map(|process| ProcessScheduleStats {
            pid: process.pid,
            state: process.state,
        })
}

pub fn thread_stats(tid: ThreadId) -> Option<ProcessScheduleStats> {
    SCHEDULER
        .lock()
        .as_ref()?
        .threads
        .iter()
        .find(|thread| thread.tid == tid)
        .copied()
        .map(|thread| ProcessScheduleStats {
            pid: thread.pid,
            state: thread.state,
        })
}

pub fn start_current_cpu() -> Option<RuntimeStats> {
    let apic_id_u32 = crate::apic::local_apic_id_u32()?;
    let apic_id = usize::try_from(apic_id_u32).ok()?;
    if apic_id >= MAX_LOCAL_APIC_IDS {
        return None;
    }
    if STARTED[apic_id].load(Ordering::Acquire) {
        return Some(snapshot());
    }

    let (old, new) = {
        let mut guard = SCHEDULER.lock();
        let scheduler = guard.as_mut()?;
        let current = CURRENT_TASK[apic_id].load(Ordering::Acquire);
        let boot = scheduler.boot_task(apic_id_u32)?;
        if current != boot {
            STARTED[apic_id].store(false, Ordering::Release);
            return None;
        }
        let next = scheduler.first_worker(apic_id_u32)?;
        // Do not let a local-APIC interrupt observe the new current-task ID before the first
        // context switch has actually moved execution onto that task's stack.
        x86_64::instructions::interrupts::disable();
        STARTED[apic_id].store(true, Ordering::Release);
        CURRENT_TASK[apic_id].store(next, Ordering::Release);
        SWITCHES.fetch_add(1, Ordering::Relaxed);
        // The vector is fully built before any CPU can enter this function, so these task addresses
        // remain stable for the lifetime of the scheduler.
        let tasks = scheduler.tasks.as_mut_ptr();
        let old = unsafe { core::ptr::addr_of_mut!((*tasks.add(current)).context) };
        let new = unsafe { core::ptr::addr_of!((*tasks.add(next)).context) };
        (old, new)
    };

    crate::apic::enable_local_timer();
    // SAFETY: both contexts belong to this CPU's fixed run queue, and the scheduler lock was
    // released only after the raw pointers were obtained from the permanently allocated vector.
    unsafe { rustos_context_switch(old, new) };
    crate::interrupts::enable();
    Some(snapshot())
}

/// Voluntarily hand the current task to the next runnable task.
///
/// The user syscall entry is an interrupt gate, so interrupts are disabled while this function
/// selects and performs the handoff. The saved syscall stack remains the process context and will
/// resume at the return from this function when the process is scheduled again.
pub fn yield_current() {
    let Some(apic_id_u32) = crate::apic::local_apic_id_u32() else {
        return;
    };
    let _ = switch_current_task(apic_id_u32, true);
}

pub fn on_local_timer() {
    if !PREEMPTION_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let Some(apic_id_u32) = crate::apic::local_apic_id_u32() else {
        return;
    };
    let _ = switch_current_task(apic_id_u32, false);
}

fn switch_current_task(apic_id_u32: u32, voluntary: bool) -> bool {
    let Ok(apic_id) = usize::try_from(apic_id_u32) else {
        return false;
    };
    if apic_id >= MAX_LOCAL_APIC_IDS {
        return false;
    }
    if !STARTED[apic_id].load(Ordering::Acquire) {
        return false;
    }

    let Some(mut guard) = SCHEDULER.try_lock() else {
        return false;
    };
    let Some(scheduler) = guard.as_mut() else {
        return false;
    };
    let current = CURRENT_TASK[apic_id].load(Ordering::Acquire);
    let Some(next) = scheduler.next_task(apic_id_u32, current) else {
        return false;
    };
    if current == next {
        return false;
    }
    CURRENT_TASK[apic_id].store(next, Ordering::Release);
    SWITCHES.fetch_add(1, Ordering::Relaxed);
    let next_process = scheduler.tasks[next].process_id();
    let next_thread = scheduler.tasks[next].thread_id();
    let tasks = scheduler.tasks.as_mut_ptr();
    let old = unsafe { core::ptr::addr_of_mut!((*tasks.add(current)).context) };
    let new = unsafe { core::ptr::addr_of!((*tasks.add(next)).context) };
    drop(guard);

    match (next_process, next_thread) {
        (Some(pid), Some(tid)) => {
            crate::process::note_thread_task_switch(tid);
            crate::process::prepare_thread_task_switch(pid, tid);
        }
        (Some(pid), None) => {
            crate::process::note_task_switch(pid, apic_id_u32);
            crate::process::prepare_task_switch(Some(pid));
        }
        (None, None) => crate::process::prepare_task_switch(None),
        (None, Some(_)) => return false,
    }
    if voluntary {
        VOLUNTARY_SWITCHES.fetch_add(1, Ordering::Relaxed);
    }

    // SAFETY: the current task owns the old context, the destination task belongs to this CPU's
    // fixed queue, and both addresses remain allocated after the lock is released.
    unsafe { rustos_context_switch(old, new) };
    true
}

pub fn voluntary_switches() -> u64 {
    VOLUNTARY_SWITCHES.load(Ordering::Acquire)
}

pub fn snapshot() -> RuntimeStats {
    let heartbeats = SCHEDULER
        .lock()
        .as_ref()
        .map(|scheduler| {
            scheduler
                .tasks
                .iter()
                .map(|task| HEARTBEATS[task.id].load(Ordering::Relaxed))
                .sum()
        })
        .unwrap_or(0);
    RuntimeStats {
        switches: SWITCHES.load(Ordering::Relaxed),
        heartbeats,
    }
}

extern "C" fn task_entry() -> ! {
    let task_id: usize;
    // SAFETY: the initial context switch places the task ID in the callee-saved r12 register before
    // entering this function; the register is not otherwise used by the entry shim.
    unsafe {
        asm!(
            "mov {task_id}, r12",
            task_id = out(reg) task_id,
            options(nomem, nostack, preserves_flags)
        );
    }
    task_body(task_id)
}

fn task_body(task_id: usize) -> ! {
    crate::interrupts::enable();
    loop {
        if let Some(heartbeat) = HEARTBEATS.get(task_id) {
            heartbeat.fetch_add(1, Ordering::Relaxed);
        }
        // The first BSP kernel worker owns the bounded timer-driven network service. It is
        // intentionally kept in kernel space so DHCP renewal remains independent of a userland
        // process being scheduled or alive.
        if task_id == 1 {
            crate::network_runtime::service_poll(crate::interrupts::apic_ticks());
        }
        for _ in 0..512 {
            core::hint::spin_loop();
        }
        crate::interrupts::halt();
    }
}

extern "C" fn process_task_entry() -> ! {
    let pid_raw: u64;
    // SAFETY: the initial process context places its PID in callee-saved r13 before entering this
    // function; the context-switch shim preserves that register across every preemption.
    unsafe {
        asm!(
            "mov {pid}, r13",
            pid = out(reg) pid_raw,
            options(nomem, nostack, preserves_flags)
        );
    }
    crate::process::run_registered_process(pid_raw as ProcessId)
}

extern "C" fn thread_task_entry() -> ! {
    let tid_raw: u64;
    // SAFETY: the initial thread context places its TID in callee-saved r13 before entering this
    // function; the context-switch shim preserves that register across every preemption.
    unsafe {
        asm!(
            "mov {tid}, r13",
            tid = out(reg) tid_raw,
            options(nomem, nostack, preserves_flags)
        );
    }
    crate::process::run_registered_thread(tid_raw as ThreadId)
}
