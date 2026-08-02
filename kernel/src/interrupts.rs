use core::sync::atomic::{AtomicU64, Ordering};

use pic8259::ChainedPics;
use spin::{Mutex, Once};
use x86_64::instructions::interrupts;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::{PrivilegeLevel, VirtAddr};

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;
pub const LOCAL_APIC_TIMER_VECTOR: u8 = 48;
pub const IO_APIC_TIMER_VECTOR: u8 = 49;
pub const DEVICE_IRQ_VECTOR_BASE: u8 = 50;
pub const USER_SYSCALL_VECTOR: u8 = 0x80;
const DEVICE_IRQ_SLOT_COUNT: usize = 8;

static IDT: Once<InterruptDescriptorTable> = Once::new();
static PICS: Mutex<ChainedPics> =
    // SAFETY: the offsets are non-overlapping and leave CPU exception vectors 0..31 untouched.
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });
static TICKS: AtomicU64 = AtomicU64::new(0);
static DEVICE_HANDLERS: Mutex<[Option<fn()>; DEVICE_IRQ_SLOT_COUNT]> =
    Mutex::new([None; DEVICE_IRQ_SLOT_COUNT]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceInterruptError {
    NoVectorAvailable,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    LocalApicTimer = LOCAL_APIC_TIMER_VECTOR,
    IoApicTimer = IO_APIC_TIMER_VECTOR,
}

impl InterruptIndex {
    const fn as_u8(self) -> u8 {
        self as u8
    }
}

pub fn init_idt() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.double_fault.set_handler_fn(double_fault_handler);
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt[InterruptIndex::Timer.as_u8()].set_handler_fn(timer_handler);
        idt[InterruptIndex::LocalApicTimer.as_u8()].set_handler_fn(apic_timer_handler);
        idt[InterruptIndex::IoApicTimer.as_u8()].set_handler_fn(io_apic_timer_handler);
        unsafe {
            idt[USER_SYSCALL_VECTOR]
                .set_handler_addr(VirtAddr::new(crate::process::syscall_entry_address()))
        }
        .set_privilege_level(PrivilegeLevel::Ring3);
        idt[DEVICE_IRQ_VECTOR_BASE].set_handler_fn(device_irq_0_handler);
        idt[DEVICE_IRQ_VECTOR_BASE + 1].set_handler_fn(device_irq_1_handler);
        idt[DEVICE_IRQ_VECTOR_BASE + 2].set_handler_fn(device_irq_2_handler);
        idt[DEVICE_IRQ_VECTOR_BASE + 3].set_handler_fn(device_irq_3_handler);
        idt[DEVICE_IRQ_VECTOR_BASE + 4].set_handler_fn(device_irq_4_handler);
        idt[DEVICE_IRQ_VECTOR_BASE + 5].set_handler_fn(device_irq_5_handler);
        idt[DEVICE_IRQ_VECTOR_BASE + 6].set_handler_fn(device_irq_6_handler);
        idt[DEVICE_IRQ_VECTOR_BASE + 7].set_handler_fn(device_irq_7_handler);
        idt
    });
    idt.load();
}

pub fn reload_idt() {
    if let Some(idt) = IDT.get() {
        idt.load();
    }
}

pub fn register_device_handler(handler: fn()) -> Result<u8, DeviceInterruptError> {
    let mut handlers = DEVICE_HANDLERS.lock();
    let Some((slot, entry)) = handlers
        .iter_mut()
        .enumerate()
        .find(|(_, entry)| entry.is_none())
    else {
        return Err(DeviceInterruptError::NoVectorAvailable);
    };
    *entry = Some(handler);
    Ok(DEVICE_IRQ_VECTOR_BASE + slot as u8)
}

pub fn init_pics() {
    let mut pics = PICS.lock();
    // SAFETY: PIC initialization and mask updates are performed before interrupts are enabled.
    unsafe {
        pics.initialize();
        // Keep every legacy IRQ masked until the platform chooses the PIC/PIT fallback.
        pics.write_masks(0b1111_1111, 0b1111_1111);
    }
}

pub fn enable_pic_timer() {
    let mut pics = PICS.lock();
    // SAFETY: only IRQ0 has a registered legacy handler; the slave remains fully masked.
    unsafe { pics.write_masks(0b1111_1110, 0b1111_1111) };
}

pub fn enable() {
    interrupts::enable();
}

pub fn halt() {
    x86_64::instructions::hlt();
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::SeqCst)
}

pub fn apic_ticks() -> u64 {
    APIC_TICKS.load(Ordering::SeqCst)
}

pub fn io_apic_ticks() -> u64 {
    IO_APIC_TICKS.load(Ordering::SeqCst)
}

pub fn wait_until(target: u64) {
    while ticks() < target {
        halt();
    }
}

pub fn wait_until_apic(target: u64) {
    while apic_ticks() < target {
        halt();
    }
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    crate::kprintln!(
        "exception: breakpoint at {:?}",
        stack_frame.instruction_pointer
    );
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    crate::kprintln!(
        "exception: double fault at {:?}, error={:#x}",
        stack_frame.instruction_pointer,
        error_code
    );
    halt_forever()
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!(
        "general protection fault at {:?}, error={:#x}",
        stack_frame.instruction_pointer, error_code
    );
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    panic!(
        "page fault at {:?}, accessed={:?}, error={:?}",
        stack_frame.instruction_pointer,
        Cr2::read(),
        error_code
    );
}

extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    TICKS.fetch_add(1, Ordering::SeqCst);
    let mut pics = PICS.lock();
    // SAFETY: this handler is running for the PIC-owned timer vector.
    unsafe { pics.notify_end_of_interrupt(InterruptIndex::Timer.as_u8()) };
}

static APIC_TICKS: AtomicU64 = AtomicU64::new(0);
static IO_APIC_TICKS: AtomicU64 = AtomicU64::new(0);

extern "x86-interrupt" fn apic_timer_handler(_stack_frame: InterruptStackFrame) {
    APIC_TICKS.fetch_add(1, Ordering::SeqCst);
    crate::apic::end_of_interrupt();
    crate::scheduler::on_local_timer();
}

extern "x86-interrupt" fn io_apic_timer_handler(_stack_frame: InterruptStackFrame) {
    IO_APIC_TICKS.fetch_add(1, Ordering::SeqCst);
    crate::apic::end_of_interrupt();
}

fn dispatch_device_interrupt(slot: usize) {
    let handler = DEVICE_HANDLERS.lock()[slot];
    if let Some(handler) = handler {
        handler();
    }
    crate::apic::end_of_interrupt();
}

extern "x86-interrupt" fn device_irq_0_handler(_stack_frame: InterruptStackFrame) {
    dispatch_device_interrupt(0);
}

extern "x86-interrupt" fn device_irq_1_handler(_stack_frame: InterruptStackFrame) {
    dispatch_device_interrupt(1);
}

extern "x86-interrupt" fn device_irq_2_handler(_stack_frame: InterruptStackFrame) {
    dispatch_device_interrupt(2);
}

extern "x86-interrupt" fn device_irq_3_handler(_stack_frame: InterruptStackFrame) {
    dispatch_device_interrupt(3);
}

extern "x86-interrupt" fn device_irq_4_handler(_stack_frame: InterruptStackFrame) {
    dispatch_device_interrupt(4);
}

extern "x86-interrupt" fn device_irq_5_handler(_stack_frame: InterruptStackFrame) {
    dispatch_device_interrupt(5);
}

extern "x86-interrupt" fn device_irq_6_handler(_stack_frame: InterruptStackFrame) {
    dispatch_device_interrupt(6);
}

extern "x86-interrupt" fn device_irq_7_handler(_stack_frame: InterruptStackFrame) {
    dispatch_device_interrupt(7);
}

fn halt_forever() -> ! {
    interrupts::disable();
    loop {
        halt();
    }
}
