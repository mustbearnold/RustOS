use core::sync::atomic::{AtomicU64, Ordering};

use bootloader_api::info::MemoryRegion;

use crate::memory::{FrameAllocator, PAGE_SIZE};
use crate::pci::{MmioError, MmioRegion, PciDevice, PciDeviceResources, PciResourceError};

const XHCI_MMIO_LENGTH: u64 = 0x10_000;
const XHCI_POLL_SPINS: usize = 2_000_000;
const XHCI_RING_TRBS: usize = 256;
const XHCI_LINK_INDEX: usize = XHCI_RING_TRBS - 1;
const XHCI_CONTEXT_FLAG_SLOT: u32 = 1 << 0;
const XHCI_CONTEXT_FLAG_EP0: u32 = 1 << 1;
const XHCI_TRB_CYCLE: u32 = 1 << 0;
const XHCI_TRB_LINK_TOGGLE: u32 = 1 << 1;
const XHCI_TRB_CHAIN: u32 = 1 << 4;
const XHCI_TRB_INTERRUPT_ON_COMPLETION: u32 = 1 << 5;
const XHCI_TRB_IMMEDIATE_DATA: u32 = 1 << 6;
const XHCI_TRB_DIRECTION_IN: u32 = 1 << 16;
const XHCI_TRB_TYPE_SHIFT: u32 = 10;
const XHCI_TRB_TYPE_MASK: u32 = 0x3f;
const XHCI_TRB_TRANSFER_TYPE_SHIFT: u32 = 16;
const XHCI_TRB_TYPE_NORMAL: u32 = 1;
const XHCI_TRB_TYPE_SETUP: u32 = 2;
const XHCI_TRB_TYPE_DATA: u32 = 3;
const XHCI_TRB_TYPE_STATUS: u32 = 4;
const XHCI_TRB_TYPE_LINK: u32 = 6;
const XHCI_TRB_TYPE_ENABLE_SLOT: u32 = 9;
const XHCI_TRB_TYPE_DISABLE_SLOT: u32 = 10;
const XHCI_TRB_TYPE_ADDRESS_DEVICE: u32 = 11;
const XHCI_TRB_TYPE_CONFIGURE_ENDPOINT: u32 = 12;
const XHCI_TRB_TYPE_EVALUATE_CONTEXT: u32 = 13;
const XHCI_TRB_TYPE_TRANSFER_EVENT: u32 = 32;
const XHCI_TRB_TYPE_COMMAND_COMPLETION: u32 = 33;
const XHCI_TRB_TYPE_PORT_STATUS: u32 = 34;
const XHCI_COMPLETION_SUCCESS: u8 = 1;
const XHCI_COMPLETION_SHORT_PACKET: u8 = 13;

const CAP_LENGTH_VERSION: u64 = 0x00;
const CAP_STRUCTURAL_PARAMETERS_1: u64 = 0x04;
const CAP_STRUCTURAL_PARAMETERS_2: u64 = 0x08;
const CAP_CAPABILITY_PARAMETERS_1: u64 = 0x10;
const CAP_DOORBELL_OFFSET: u64 = 0x14;
const CAP_RUNTIME_OFFSET: u64 = 0x18;

const OP_COMMAND: u64 = 0x00;
const OP_STATUS: u64 = 0x04;
const OP_PAGE_SIZE: u64 = 0x08;
const OP_COMMAND_RING: u64 = 0x18;
const OP_DEVICE_CONTEXT_BASE: u64 = 0x30;
const OP_CONFIG: u64 = 0x38;
const OP_PORTS: u64 = 0x400;
const OP_PORT_STRIDE: u64 = 0x10;

const RUNTIME_INTERRUPTER_0: u64 = 0x20;
const INTERRUPTER_MANAGEMENT: u64 = 0x00;
const INTERRUPTER_MODERATION: u64 = 0x04;
const INTERRUPTER_ERST_SIZE: u64 = 0x08;
const INTERRUPTER_ERST_BASE: u64 = 0x10;
const INTERRUPTER_ERDP: u64 = 0x18;
const INTERRUPTER_INTERRUPT_PENDING: u32 = 1 << 0;
const INTERRUPTER_INTERRUPT_ENABLE: u32 = 1 << 1;

const USB_COMMAND_RUN: u32 = 1 << 0;
const USB_COMMAND_RESET: u32 = 1 << 1;
const USB_COMMAND_INTERRUPT_ENABLE: u32 = 1 << 2;
const USB_STATUS_HALTED: u32 = 1 << 0;
const USB_STATUS_CONTROLLER_NOT_READY: u32 = 1 << 11;
const USB_STATUS_HOST_CONTROLLER_ERROR: u32 = 1 << 12;
const HCC_CONTEXT_SIZE_64: u32 = 1 << 2;
const PORT_CONNECTED: u32 = 1 << 0;
const PORT_ENABLED: u32 = 1 << 1;
const PORT_RESET: u32 = 1 << 4;
const PORT_SPEED_SHIFT: u32 = 10;
const PORT_SPEED_MASK: u32 = 0x0f;
const EVENT_HANDLER_BUSY: u64 = 1 << 3;

const USB_REQUEST_GET_DESCRIPTOR: u8 = 6;
const USB_REQUEST_GET_STATUS: u8 = 0;
const USB_REQUEST_CLEAR_FEATURE: u8 = 1;
const USB_REQUEST_SET_FEATURE: u8 = 3;
const USB_REQUEST_SET_CONFIGURATION: u8 = 9;
const USB_DESCRIPTOR_DEVICE: u8 = 1;
const USB_DESCRIPTOR_CONFIGURATION: u8 = 2;
const USB_DESCRIPTOR_HUB: u8 = 0x29;
const USB_DESCRIPTOR_INTERFACE: u8 = 4;
const USB_DESCRIPTOR_ENDPOINT: u8 = 5;
const USB_CLASS_HID: u8 = 3;
const USB_HID_SUBCLASS_BOOT: u8 = 1;
const USB_HID_PROTOCOL_KEYBOARD: u8 = 1;
const USB_HID_PROTOCOL_MOUSE: u8 = 2;
const USB_ENDPOINT_DIRECTION_IN: u8 = 0x80;
const USB_ENDPOINT_TRANSFER_INTERRUPT: u8 = 3;
const USB_CLASS_HUB: u8 = 9;
const USB_FEATURE_PORT_POWER: u16 = 8;
const USB_FEATURE_PORT_RESET: u16 = 4;
const USB_FEATURE_PORT_C_RESET: u16 = 20;
const USB_HUB_PORT_CONNECTION: u16 = 1 << 0;
const USB_HUB_PORT_ENABLE: u16 = 1 << 1;
const USB_HUB_PORT_LOW_SPEED: u16 = 1 << 9;
const USB_HUB_PORT_HIGH_SPEED: u16 = 1 << 10;
const XHCI_HUB_RESET_SPINS: usize = 100_000;
const XHCI_MAX_ROUTE_DEPTH: u8 = 5;
const USB_HOTPLUG_SCAN_INTERVAL: u8 = 16;
const USB_HOTPLUG_GRACE_SCANS: u8 = 32;
const USB_DEFERRED_EVENT_COUNT: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbError {
    Resources(PciResourceError),
    Mmio(MmioError),
    UnsupportedController {
        class: u8,
        subclass: u8,
        prog_if: u8,
    },
    MemorySpaceDisabled,
    InvalidCapability {
        cap_length: u8,
        version: u16,
        max_slots: u8,
        max_ports: u8,
    },
    UnsupportedInterrupters {
        count: u16,
    },
    UnsupportedScratchpad {
        count: u16,
    },
    UnsupportedPageSize {
        page_size: u32,
    },
    InvalidRegisterOffset {
        offset: u64,
    },
    NoDmaFrame,
    DmaAddressOverflow,
    DmaAddressTooLarge {
        address: u64,
    },
    DmaOutOfBounds {
        offset: u64,
        size: u64,
    },
    DmaUnaligned {
        address: u64,
        alignment: u64,
    },
    ControllerTimeout {
        operation: u8,
        value: u32,
    },
    ControllerError {
        status: u32,
    },
    InterruptRegistration,
    NoHid,
    NoPort,
    PortTimeout {
        port: u8,
        status: u32,
    },
    Completion {
        operation: u8,
        code: u8,
    },
    InvalidDescriptor {
        descriptor_type: u8,
        length: u8,
    },
    UnsupportedDevice,
    InvalidEndpoint {
        address: u8,
        attributes: u8,
        max_packet: u16,
    },
    #[cfg(target_os = "none")]
    IoApic(crate::ioapic::IoApicError),
}

impl From<PciResourceError> for UsbError {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

impl From<MmioError> for UsbError {
    fn from(error: MmioError) -> Self {
        Self::Mmio(error)
    }
}

#[cfg(target_os = "none")]
impl From<crate::ioapic::IoApicError> for UsbError {
    fn from(error: crate::ioapic::IoApicError) -> Self {
        Self::IoApic(error)
    }
}

#[derive(Debug, Clone, Copy)]
struct DmaPage {
    physical_base: u64,
    virtual_base: u64,
}

impl DmaPage {
    fn clear(self) {
        // SAFETY: the page comes from usable firmware memory and the bootloader maps the full
        // physical address range through the configured physical-memory offset.
        unsafe { core::ptr::write_bytes(self.virtual_base as *mut u8, 0, PAGE_SIZE as usize) };
    }

    fn pointer(self, offset: u64, size: u64, alignment: u64) -> Result<u64, UsbError> {
        if self.physical_base % alignment != 0 || offset % alignment != 0 {
            return Err(UsbError::DmaUnaligned {
                address: self.physical_base.saturating_add(offset),
                alignment,
            });
        }
        let end = offset
            .checked_add(size)
            .ok_or(UsbError::DmaAddressOverflow)?;
        if end > PAGE_SIZE {
            return Err(UsbError::DmaOutOfBounds { offset, size });
        }
        self.virtual_base
            .checked_add(offset)
            .ok_or(UsbError::DmaAddressOverflow)
    }

    fn read_u8(self, offset: u64) -> Result<u8, UsbError> {
        let pointer = self.pointer(offset, 1, 1)?;
        // SAFETY: pointer is bounds-checked against the allocated page.
        Ok(unsafe { core::ptr::read_volatile(pointer as *const u8) })
    }

    fn write_u32(self, offset: u64, value: u32) -> Result<(), UsbError> {
        let pointer = self.pointer(offset, 4, 4)?;
        // SAFETY: pointer is bounds-checked and aligned for a 32-bit volatile field.
        unsafe { core::ptr::write_volatile(pointer as *mut u32, value.to_le()) };
        Ok(())
    }

    fn read_u32(self, offset: u64) -> Result<u32, UsbError> {
        let pointer = self.pointer(offset, 4, 4)?;
        // SAFETY: pointer is bounds-checked and aligned for a 32-bit volatile field.
        Ok(u32::from_le(unsafe {
            core::ptr::read_volatile(pointer as *const u32)
        }))
    }

    fn write_u64(self, offset: u64, value: u64) -> Result<(), UsbError> {
        self.write_u32(offset, value as u32)?;
        self.write_u32(offset + 4, (value >> 32) as u32)
    }

    fn read_bytes(self, offset: u64, bytes: &mut [u8]) -> Result<(), UsbError> {
        for (index, byte) in bytes.iter_mut().enumerate() {
            let index = u64::try_from(index).map_err(|_| UsbError::DmaAddressOverflow)?;
            *byte = self.read_u8(
                offset
                    .checked_add(index)
                    .ok_or(UsbError::DmaAddressOverflow)?,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Ring {
    page: DmaPage,
    enqueue_index: usize,
    cycle: bool,
}

impl Ring {
    fn new(page: DmaPage) -> Result<Self, UsbError> {
        page.clear();
        let ring = Self {
            page,
            enqueue_index: 0,
            cycle: true,
        };
        ring.write_link(false, false)?;
        Ok(ring)
    }

    fn write_link(self, cycle: bool, chain: bool) -> Result<(), UsbError> {
        let offset = (XHCI_LINK_INDEX * 16) as u64;
        self.page.write_u64(offset, self.page.physical_base)?;
        self.page.write_u32(offset + 8, 0)?;
        self.page.write_u32(
            offset + 12,
            (XHCI_TRB_TYPE_LINK << XHCI_TRB_TYPE_SHIFT)
                | XHCI_TRB_LINK_TOGGLE
                | if chain { XHCI_TRB_CHAIN } else { 0 }
                | if cycle { XHCI_TRB_CYCLE } else { 0 },
        )
    }

    fn enqueue(&mut self, parameter: u64, status: u32, control: u32) -> Result<u64, UsbError> {
        if self.enqueue_index == XHCI_LINK_INDEX {
            let previous_control = self
                .page
                .read_u32(((XHCI_LINK_INDEX - 1) * 16 + 12) as u64)?;
            let chain = previous_control & XHCI_TRB_CHAIN != 0;
            let link_cycle = self.cycle;
            self.write_link(link_cycle, chain)?;
            self.cycle = !self.cycle;
            self.enqueue_index = 0;
        }
        let offset = (self.enqueue_index * 16) as u64;
        let physical = self
            .page
            .physical_base
            .checked_add(offset)
            .ok_or(UsbError::DmaAddressOverflow)?;
        self.page.write_u64(offset, parameter)?;
        self.page.write_u32(offset + 8, status)?;
        // The cycle bit is written last so the controller cannot own a partially populated TRB.
        self.page
            .write_u32(offset + 12, control & !XHCI_TRB_CYCLE)?;
        self.page.write_u32(
            offset + 12,
            (control & !XHCI_TRB_CYCLE) | if self.cycle { XHCI_TRB_CYCLE } else { 0 },
        )?;
        self.enqueue_index += 1;
        Ok(physical)
    }
}

#[derive(Debug, Clone, Copy)]
struct Event {
    status: u32,
    control: u32,
}

impl Event {
    fn kind(self) -> u32 {
        (self.control >> XHCI_TRB_TYPE_SHIFT) & XHCI_TRB_TYPE_MASK
    }

    fn completion_code(self) -> u8 {
        (self.status >> 24) as u8
    }

    fn slot_id(self) -> u8 {
        (self.control >> 24) as u8
    }

    fn endpoint_id(self) -> u8 {
        ((self.control >> 16) & 0x1f) as u8
    }

    fn residual_length(self) -> usize {
        (self.status & 0x1f_ffff) as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidKind {
    Keyboard,
    Mouse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbInterruptMode {
    Polling,
    Legacy,
    Msi,
    Msix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbInterruptDiagnostics {
    pub ready: bool,
    pub mode: UsbInterruptMode,
    pub vector: Option<u8>,
    pub gsi: Option<u32>,
    pub interrupts: u64,
}

impl UsbInterruptDiagnostics {
    const fn polling() -> Self {
        Self {
            ready: false,
            mode: UsbInterruptMode::Polling,
            vector: None,
            gsi: None,
            interrupts: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HubContext {
    slot_id: u8,
    root_port: u8,
    speed: u8,
    max_packet: u16,
    port_count: u8,
    route_string: u32,
    route_depth: u8,
    ep0_ring: Ring,
    control_data: DmaPage,
    device_context: DmaPage,
}

fn append_hub_route(hub: HubContext, port: u8) -> Result<(u32, u8), UsbError> {
    if port == 0 || port > 15 || hub.route_depth >= XHCI_MAX_ROUTE_DEPTH {
        return Err(UsbError::UnsupportedDevice);
    }
    let shift = u32::from(hub.route_depth) * 4;
    Ok((
        hub.route_string | (u32::from(port) << shift),
        hub.route_depth + 1,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidDiagnostics {
    pub ready: bool,
    pub kind: HidKind,
    pub port: u8,
    pub hub_port: Option<u8>,
    pub slot_id: u8,
    pub endpoint_id: u8,
    pub speed: u8,
    pub max_packet: u16,
    pub route_string: u32,
    pub route_depth: u8,
    pub reports: u64,
    pub bytes: u64,
}

#[derive(Debug)]
pub struct UsbHid {
    mmio: MmioRegion,
    pci_resources: Option<PciDeviceResources>,
    operational_base: u64,
    doorbell_base: u64,
    runtime_base: u64,
    physical_memory_offset: u64,
    capability: u32,
    max_ports: u8,
    dcbaa: DmaPage,
    event_ring: DmaPage,
    command_ring: Ring,
    input_context: DmaPage,
    device_context: DmaPage,
    ep0_ring: Ring,
    interrupt_ring: Ring,
    control_data: DmaPage,
    report_data: DmaPage,
    context_size: usize,
    slot_id: u8,
    port: u8,
    hub_port: Option<u8>,
    route_string: u32,
    route_depth: u8,
    parent_hub_slot: u8,
    parent_hub_port: u8,
    is_hub: bool,
    hub_port_count: u8,
    hub_context: Option<HubContext>,
    parent_hub_context: Option<HubContext>,
    speed: u8,
    endpoint_id: u8,
    max_packet: u16,
    report_length: usize,
    event_index: usize,
    event_cycle: bool,
    pending_completion: Option<Event>,
    deferred_events: [Option<Event>; USB_DEFERRED_EVENT_COUNT],
    interrupt_pending: bool,
    interrupt_vector: Option<u8>,
    interrupt_gsi: Option<u32>,
    interrupt_mode: UsbInterruptMode,
    kind: HidKind,
    hid: HidState,
    reports: u64,
    bytes: u64,
    first_report_logged: bool,
    disabled: bool,
    memory_regions: &'static [MemoryRegion],
    next_frame_address: Option<u64>,
}

impl UsbHid {
    pub fn initialize(
        device: PciDevice,
        physical_memory_offset: u64,
        regions: &'static [MemoryRegion],
        next_frame_address: Option<u64>,
    ) -> Result<Self, UsbError> {
        if device.class_code != 0x0c || device.subclass != 0x03 || device.prog_if != 0x30 {
            return Err(UsbError::UnsupportedController {
                class: device.class_code,
                subclass: device.subclass,
                prog_if: device.prog_if,
            });
        }
        if !device.memory_space_enabled() {
            return Err(UsbError::MemorySpaceDisabled);
        }

        let mut resources = PciDeviceResources::new(device, physical_memory_offset);
        resources.enable_bus_master()?;
        let mmio = resources.claim_mmio(0, XHCI_MMIO_LENGTH)?;
        let capbase = mmio.read_u32(CAP_LENGTH_VERSION)?;
        let cap_length = (capbase & 0xff) as u8;
        let version = (capbase >> 16) as u16;
        let structural = mmio.read_u32(CAP_STRUCTURAL_PARAMETERS_1)?;
        let structural2 = mmio.read_u32(CAP_STRUCTURAL_PARAMETERS_2)?;
        let capability = mmio.read_u32(CAP_CAPABILITY_PARAMETERS_1)?;
        let max_slots = (structural & 0xff) as u8;
        let max_interrupters = ((structural >> 8) & 0x7ff) as u16;
        let max_ports = (structural >> 24) as u8;
        let scratchpads = ((structural2 >> 27) & 0x1f) | ((structural2 >> 16) & 0x3e0);
        if cap_length < 0x20 || max_slots == 0 || max_ports == 0 {
            return Err(UsbError::InvalidCapability {
                cap_length,
                version,
                max_slots,
                max_ports,
            });
        }
        if max_interrupters == 0 {
            return Err(UsbError::UnsupportedInterrupters {
                count: max_interrupters,
            });
        }
        if scratchpads != 0 {
            return Err(UsbError::UnsupportedScratchpad {
                count: scratchpads as u16,
            });
        }
        let page_size = mmio.read_u32(u64::from(cap_length) + OP_PAGE_SIZE)?;
        if page_size & 1 == 0 {
            return Err(UsbError::UnsupportedPageSize { page_size });
        }
        let doorbell_base = u64::from(mmio.read_u32(CAP_DOORBELL_OFFSET)?) & !0x03;
        let runtime_base = u64::from(mmio.read_u32(CAP_RUNTIME_OFFSET)?) & !0x1f;
        let operational_base = u64::from(cap_length);
        validate_register_offset(mmio, doorbell_base + u64::from(max_slots) * 4)?;
        validate_register_offset(mmio, runtime_base + RUNTIME_INTERRUPTER_0 + 0x20)?;
        validate_register_offset(
            mmio,
            operational_base + OP_PORTS + u64::from(max_ports) * OP_PORT_STRIDE,
        )?;

        stop_and_reset(mmio, operational_base)?;

        let mut allocator = FrameAllocator::starting_at(regions, next_frame_address.unwrap_or(0));
        let dcbaa = allocate_page(&mut allocator, physical_memory_offset, capability)?;
        let erst = allocate_page(&mut allocator, physical_memory_offset, capability)?;
        let event_ring = allocate_page(&mut allocator, physical_memory_offset, capability)?;
        let command_page = allocate_page(&mut allocator, physical_memory_offset, capability)?;
        let input_context = allocate_page(&mut allocator, physical_memory_offset, capability)?;
        let device_context = allocate_page(&mut allocator, physical_memory_offset, capability)?;
        let ep0_page = allocate_page(&mut allocator, physical_memory_offset, capability)?;
        let interrupt_page = allocate_page(&mut allocator, physical_memory_offset, capability)?;
        let control_data = allocate_page(&mut allocator, physical_memory_offset, capability)?;
        let report_data = allocate_page(&mut allocator, physical_memory_offset, capability)?;

        let context_size = if capability & HCC_CONTEXT_SIZE_64 != 0 {
            64
        } else {
            32
        };
        let command_ring = Ring::new(command_page)?;
        let ep0_ring = Ring::new(ep0_page)?;
        let interrupt_ring = Ring::new(interrupt_page)?;
        erst.clear();
        erst.write_u64(0, event_ring.physical_base)?;
        erst.write_u32(8, XHCI_RING_TRBS as u32)?;
        erst.write_u32(12, 0)?;

        let operational_base = operational_base;
        write_mmio_u64(
            mmio,
            operational_base + OP_COMMAND_RING,
            command_ring.page.physical_base | XHCI_TRB_CYCLE as u64,
        )?;
        write_mmio_u64(
            mmio,
            operational_base + OP_DEVICE_CONTEXT_BASE,
            dcbaa.physical_base,
        )?;
        mmio.write_u32(operational_base + OP_CONFIG, u32::from(max_slots))?;

        let interrupter = runtime_base + RUNTIME_INTERRUPTER_0;
        mmio.write_u32(interrupter + INTERRUPTER_MANAGEMENT, 0)?;
        mmio.write_u32(interrupter + INTERRUPTER_MODERATION, 0)?;
        mmio.write_u32(interrupter + INTERRUPTER_ERST_SIZE, 1)?;
        write_mmio_u64(
            mmio,
            interrupter + INTERRUPTER_ERST_BASE,
            erst.physical_base,
        )?;
        write_mmio_u64(
            mmio,
            interrupter + INTERRUPTER_ERDP,
            event_ring.physical_base | EVENT_HANDLER_BUSY,
        )?;
        let command = mmio.read_u32(operational_base + OP_COMMAND)? | USB_COMMAND_RUN;
        mmio.write_u32(operational_base + OP_COMMAND, command)?;
        wait_until(mmio, operational_base + OP_STATUS, |status| {
            status & USB_STATUS_HALTED == 0 && status & USB_STATUS_CONTROLLER_NOT_READY == 0
        })?;

        let (port, speed) = find_and_reset_port(mmio, operational_base, max_ports, 0)?;
        let mut hid = Self {
            mmio,
            pci_resources: Some(resources),
            operational_base,
            doorbell_base,
            runtime_base,
            physical_memory_offset,
            capability,
            max_ports,
            dcbaa,
            event_ring,
            command_ring,
            input_context,
            device_context,
            ep0_ring,
            interrupt_ring,
            control_data,
            report_data,
            context_size,
            slot_id: 0,
            port,
            hub_port: None,
            route_string: 0,
            route_depth: 0,
            parent_hub_slot: 0,
            parent_hub_port: 0,
            is_hub: false,
            hub_port_count: 0,
            hub_context: None,
            parent_hub_context: None,
            speed,
            endpoint_id: 0,
            max_packet: 8,
            report_length: 0,
            event_index: 0,
            event_cycle: true,
            pending_completion: None,
            deferred_events: [None; USB_DEFERRED_EVENT_COUNT],
            interrupt_pending: false,
            interrupt_vector: None,
            interrupt_gsi: None,
            interrupt_mode: UsbInterruptMode::Polling,
            kind: HidKind::Keyboard,
            hid: HidState::Keyboard(HidKeyboardState::new()),
            reports: 0,
            bytes: 0,
            first_report_logged: false,
            disabled: false,
            memory_regions: regions,
            next_frame_address: allocator.next_available_address(),
        };
        hid.enumerate_device(&mut allocator)?;
        hid.next_frame_address = allocator.next_available_address();
        Ok(hid)
    }

    pub fn initialize_secondary(
        &mut self,
        next_frame_address: Option<u64>,
    ) -> Result<Self, UsbError> {
        let hub_child = if self.hub_context.is_some() {
            Some(self.find_hub_child(self.hub_port.unwrap_or(0))?)
        } else {
            None
        };
        let hub_context = self.hub_context;
        let (port, speed) = if let Some((_, speed)) = hub_child {
            (self.port, speed)
        } else {
            find_and_reset_port(self.mmio, self.operational_base, self.max_ports, self.port)?
        };
        let mut allocator =
            FrameAllocator::starting_at(self.memory_regions, next_frame_address.unwrap_or(0));
        let input_context =
            allocate_page(&mut allocator, self.physical_memory_offset, self.capability)?;
        let device_context =
            allocate_page(&mut allocator, self.physical_memory_offset, self.capability)?;
        let ep0_page = allocate_page(&mut allocator, self.physical_memory_offset, self.capability)?;
        let interrupt_page =
            allocate_page(&mut allocator, self.physical_memory_offset, self.capability)?;
        let control_data =
            allocate_page(&mut allocator, self.physical_memory_offset, self.capability)?;
        let report_data =
            allocate_page(&mut allocator, self.physical_memory_offset, self.capability)?;
        let mut hid = Self {
            mmio: self.mmio,
            pci_resources: None,
            operational_base: self.operational_base,
            doorbell_base: self.doorbell_base,
            runtime_base: self.runtime_base,
            physical_memory_offset: self.physical_memory_offset,
            capability: self.capability,
            max_ports: self.max_ports,
            dcbaa: self.dcbaa,
            event_ring: self.event_ring,
            command_ring: self.command_ring,
            input_context,
            device_context,
            ep0_ring: Ring::new(ep0_page)?,
            interrupt_ring: Ring::new(interrupt_page)?,
            control_data,
            report_data,
            context_size: self.context_size,
            slot_id: 0,
            port,
            hub_port: None,
            route_string: 0,
            route_depth: 0,
            parent_hub_slot: 0,
            parent_hub_port: 0,
            is_hub: false,
            hub_port_count: 0,
            hub_context,
            parent_hub_context: self.parent_hub_context,
            speed,
            endpoint_id: 0,
            max_packet: 8,
            report_length: 0,
            event_index: self.event_index,
            event_cycle: self.event_cycle,
            pending_completion: None,
            deferred_events: [None; USB_DEFERRED_EVENT_COUNT],
            interrupt_pending: false,
            interrupt_vector: None,
            interrupt_gsi: None,
            interrupt_mode: UsbInterruptMode::Polling,
            kind: HidKind::Keyboard,
            hid: HidState::Keyboard(HidKeyboardState::new()),
            reports: 0,
            bytes: 0,
            first_report_logged: false,
            disabled: false,
            memory_regions: self.memory_regions,
            next_frame_address: allocator.next_available_address(),
        };
        if let Some((hub_port, speed)) = hub_child {
            let hub = hub_context.ok_or(UsbError::NoHid)?;
            hid.port = hub.root_port;
            hid.speed = speed;
            hid.hub_port = Some(hub_port);
            let (route_string, route_depth) = append_hub_route(hub, hub_port)?;
            hid.route_string = route_string;
            hid.route_depth = route_depth;
            hid.parent_hub_slot = hub.slot_id;
            hid.parent_hub_port = hub_port;
        }
        hid.enumerate_device(&mut allocator)?;
        hid.next_frame_address = allocator.next_available_address();
        Ok(hid)
    }

    pub fn sync_shared_state(&mut self, other: &mut Self) {
        self.command_ring = other.command_ring;
        self.event_index = other.event_index;
        self.event_cycle = other.event_cycle;
        self.hub_context = other.hub_context;
        self.next_frame_address = other.next_frame_address;
        while let Some(event) = other.take_deferred_event() {
            self.defer_event(event);
        }
    }

    pub fn next_frame_address(&self) -> Option<u64> {
        self.next_frame_address
    }

    fn defer_event(&mut self, event: Event) {
        if let Some(slot) = self.deferred_events.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(event);
            return;
        }
        for index in 1..USB_DEFERRED_EVENT_COUNT {
            self.deferred_events[index - 1] = self.deferred_events[index];
        }
        self.deferred_events[USB_DEFERRED_EVENT_COUNT - 1] = Some(event);
    }

    fn take_deferred_event(&mut self) -> Option<Event> {
        let event = self.deferred_events[0].take();
        for index in 1..USB_DEFERRED_EVENT_COUNT {
            self.deferred_events[index - 1] = self.deferred_events[index];
        }
        self.deferred_events[USB_DEFERRED_EVENT_COUNT - 1] = None;
        event
    }

    pub fn diagnostics(&self) -> HidDiagnostics {
        HidDiagnostics {
            ready: !self.disabled,
            kind: self.kind,
            port: self.port,
            hub_port: self.hub_port,
            slot_id: self.slot_id,
            endpoint_id: self.endpoint_id,
            speed: self.speed,
            max_packet: self.max_packet,
            route_string: self.route_string,
            route_depth: self.route_depth,
            reports: self.reports,
            bytes: self.bytes,
        }
    }

    pub fn interrupt_diagnostics(&self) -> UsbInterruptDiagnostics {
        UsbInterruptDiagnostics {
            ready: self.interrupt_mode != UsbInterruptMode::Polling,
            mode: self.interrupt_mode,
            vector: self.interrupt_vector,
            gsi: self.interrupt_gsi,
            interrupts: USB_INTERRUPT_COUNT.load(Ordering::SeqCst),
        }
    }

    #[cfg(target_os = "none")]
    fn enable_interrupts(
        &mut self,
        destination_apic_id: u32,
        physical_memory: crate::acpi::PhysicalMemory,
        acpi_info: Option<&crate::acpi::AcpiInfo>,
        legacy_available: bool,
    ) -> Result<UsbInterruptDiagnostics, UsbError> {
        if self.interrupt_mode != UsbInterruptMode::Polling {
            return Ok(self.interrupt_diagnostics());
        }
        let vector = crate::interrupts::register_device_handler(usb_interrupt_handler)
            .map_err(|_| UsbError::InterruptRegistration)?;
        let interrupt_line = self
            .pci_resources
            .as_ref()
            .ok_or(UsbError::NoHid)?
            .device()
            .interrupt_line;
        let mut mode = None;
        {
            let resources = self.pci_resources.as_mut().ok_or(UsbError::NoHid)?;
            match resources.enable_msix(vector, destination_apic_id) {
                Ok(_) => mode = Some(UsbInterruptMode::Msix),
                Err(PciResourceError::MsixNotSupported) => {
                    match resources.enable_msi(vector, destination_apic_id) {
                        Ok(_) => mode = Some(UsbInterruptMode::Msi),
                        Err(PciResourceError::MsiNotSupported) => {}
                        Err(error) => return Err(UsbError::Resources(error)),
                    }
                }
                Err(error) => return Err(UsbError::Resources(error)),
            }
        }

        let mut legacy_route = None;
        if mode.is_none() {
            if !legacy_available {
                return Err(UsbError::InterruptRegistration);
            }
            self.pci_resources
                .as_mut()
                .ok_or(UsbError::NoHid)?
                .enable_legacy_interrupts()
                .map_err(UsbError::Resources)?;
            let acpi_info = acpi_info.ok_or(UsbError::InterruptRegistration)?;
            let Some((gsi, flags)) = acpi_info.legacy_irq_route(interrupt_line) else {
                return Err(UsbError::InterruptRegistration);
            };
            let route = crate::ioapic::route_gsi(physical_memory, acpi_info, gsi, vector, flags)
                .map_err(UsbError::IoApic)?;
            legacy_route = Some((route, gsi));
            mode = Some(UsbInterruptMode::Legacy);
        }
        let Some(mode) = mode else {
            return Err(UsbError::InterruptRegistration);
        };

        USB_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        self.arm_controller_interrupts()?;
        self.interrupt_gsi = legacy_route.map(|(_, gsi)| gsi);
        if let Some((route, _)) = legacy_route {
            route.unmask();
        }
        self.interrupt_vector = Some(vector);
        self.interrupt_mode = mode;
        Ok(self.interrupt_diagnostics())
    }

    #[cfg(target_os = "none")]
    fn arm_controller_interrupts(&self) -> Result<(), UsbError> {
        let interrupter = self.runtime_base + RUNTIME_INTERRUPTER_0;
        self.mmio.write_u32(
            interrupter + INTERRUPTER_MANAGEMENT,
            INTERRUPTER_INTERRUPT_PENDING | INTERRUPTER_INTERRUPT_ENABLE,
        )?;
        let command = self.mmio.read_u32(self.operational_base + OP_COMMAND)?
            | USB_COMMAND_RUN
            | USB_COMMAND_INTERRUPT_ENABLE;
        self.mmio
            .write_u32(self.operational_base + OP_COMMAND, command)?;
        Ok(())
    }

    fn acknowledge_interrupt(&self) {
        if self.interrupt_mode == UsbInterruptMode::Polling {
            return;
        }
        let _ = self.mmio.write_u32(
            self.runtime_base + RUNTIME_INTERRUPTER_0 + INTERRUPTER_MANAGEMENT,
            INTERRUPTER_INTERRUPT_PENDING | INTERRUPTER_INTERRUPT_ENABLE,
        );
    }

    fn disable_slot(&mut self, slot_id: u8) -> Result<(), UsbError> {
        if slot_id == 0 {
            return Ok(());
        }
        self.command(
            0,
            0,
            (XHCI_TRB_TYPE_DISABLE_SLOT << XHCI_TRB_TYPE_SHIFT) | (u32::from(slot_id) << 24),
            7,
        )?;
        Ok(())
    }

    fn enumerate_device(&mut self, allocator: &mut FrameAllocator<'_>) -> Result<(), UsbError> {
        self.start_device()?;
        let device_descriptor = self.read_device_descriptor()?;
        let max_packet = u16::from(device_descriptor[7]);
        if !matches!(max_packet, 8 | 16 | 32 | 64) {
            return Err(UsbError::InvalidEndpoint {
                address: 0,
                attributes: 0,
                max_packet,
            });
        }
        if max_packet != 8 {
            self.evaluate_ep0_context(max_packet, false)?;
        }
        self.max_packet = max_packet;

        let (configuration, config_length) = self.read_configuration()?;
        let configuration = &configuration[..config_length];
        if device_descriptor[4] == USB_CLASS_HUB || configuration_has_hub(configuration) {
            return self.initialize_hub(allocator, configuration);
        }
        self.configure_hid(configuration)
    }

    fn start_device(&mut self) -> Result<(), UsbError> {
        let enable = self.command(0, 0, XHCI_TRB_TYPE_ENABLE_SLOT << XHCI_TRB_TYPE_SHIFT, 1)?;
        self.slot_id = enable.slot_id();
        if self.slot_id == 0 {
            return Err(UsbError::Completion {
                operation: 1,
                code: 0,
            });
        }
        self.dcbaa.write_u64(
            u64::from(self.slot_id) * 8,
            self.device_context.physical_base,
        )?;

        self.input_context.clear();
        self.input_context
            .write_u32(4, XHCI_CONTEXT_FLAG_SLOT | XHCI_CONTEXT_FLAG_EP0)?;
        self.write_slot_context(self.endpoint_id.max(1))?;
        self.write_ep0_context(8)?;
        self.command(
            self.input_context.physical_base,
            0,
            (XHCI_TRB_TYPE_ADDRESS_DEVICE << XHCI_TRB_TYPE_SHIFT) | (u32::from(self.slot_id) << 24),
            2,
        )?;
        Ok(())
    }

    fn read_device_descriptor(&mut self) -> Result<[u8; 18], UsbError> {
        let mut device_descriptor = [0u8; 18];
        self.control_in(
            setup_packet(
                0x80,
                USB_REQUEST_GET_DESCRIPTOR,
                u16::from(USB_DESCRIPTOR_DEVICE) << 8,
                0,
                device_descriptor.len() as u16,
            ),
            &mut device_descriptor,
        )?;
        if device_descriptor[0] < 18 || device_descriptor[1] != USB_DESCRIPTOR_DEVICE {
            return Err(UsbError::InvalidDescriptor {
                descriptor_type: device_descriptor[1],
                length: device_descriptor[0],
            });
        }
        Ok(device_descriptor)
    }

    fn read_configuration(&mut self) -> Result<([u8; 256], usize), UsbError> {
        let mut configuration = [0u8; 256];
        self.control_in(
            setup_packet(
                0x80,
                USB_REQUEST_GET_DESCRIPTOR,
                u16::from(USB_DESCRIPTOR_CONFIGURATION) << 8,
                0,
                configuration.len() as u16,
            ),
            &mut configuration,
        )?;
        let config_length = parse_configuration_length(&configuration)?;
        Ok((configuration, config_length))
    }

    fn configure_hid(&mut self, configuration: &[u8]) -> Result<(), UsbError> {
        let endpoint = find_boot_hid_endpoint(configuration)?;
        self.kind = endpoint.kind;
        self.hid = match endpoint.kind {
            HidKind::Keyboard => HidState::Keyboard(HidKeyboardState::new()),
            HidKind::Mouse => HidState::Mouse(HidMouseState::new()),
        };
        self.endpoint_id = endpoint.endpoint_id;
        self.report_length = usize::from(endpoint.max_packet).min(PAGE_SIZE as usize);
        self.write_interrupt_context(endpoint)?;
        self.command(
            self.input_context.physical_base,
            0,
            (XHCI_TRB_TYPE_CONFIGURE_ENDPOINT << XHCI_TRB_TYPE_SHIFT)
                | (u32::from(self.slot_id) << 24),
            4,
        )?;
        self.control_no_data(setup_packet(
            0,
            USB_REQUEST_SET_CONFIGURATION,
            u16::from(endpoint.configuration_value),
            0,
            0,
        ))?;
        self.report_data.clear();
        Ok(())
    }

    fn evaluate_ep0_context(&mut self, max_packet: u16, update_slot: bool) -> Result<(), UsbError> {
        self.input_context.clear();
        self.input_context.write_u32(
            4,
            XHCI_CONTEXT_FLAG_EP0
                | if update_slot {
                    XHCI_CONTEXT_FLAG_SLOT
                } else {
                    0
                },
        )?;
        if update_slot {
            self.write_slot_context(1)?;
        }
        self.write_ep0_context(max_packet)?;
        self.command(
            self.input_context.physical_base,
            0,
            (XHCI_TRB_TYPE_EVALUATE_CONTEXT << XHCI_TRB_TYPE_SHIFT)
                | (u32::from(self.slot_id) << 24),
            3,
        )?;
        Ok(())
    }

    fn initialize_hub(
        &mut self,
        allocator: &mut FrameAllocator<'_>,
        configuration: &[u8],
    ) -> Result<(), UsbError> {
        let mut descriptor = [0u8; 64];
        self.control_in(
            setup_packet(
                0xa0,
                USB_REQUEST_GET_DESCRIPTOR,
                u16::from(USB_DESCRIPTOR_HUB) << 8,
                0,
                descriptor.len() as u16,
            ),
            &mut descriptor,
        )?;
        if descriptor[0] < 3 || descriptor[1] != USB_DESCRIPTOR_HUB || descriptor[2] == 0 {
            return Err(UsbError::InvalidDescriptor {
                descriptor_type: descriptor[1],
                length: descriptor[0],
            });
        }
        let port_count = descriptor[2];
        if port_count > 15 {
            return Err(UsbError::UnsupportedDevice);
        }
        let configuration_value = configuration_value(configuration).unwrap_or(1);

        let parent_hub_context = self.hub_context;
        self.parent_hub_context = parent_hub_context;
        self.is_hub = true;
        self.hub_port_count = port_count;
        self.evaluate_ep0_context(self.max_packet, true)?;
        self.control_no_data(setup_packet(
            0,
            USB_REQUEST_SET_CONFIGURATION,
            u16::from(configuration_value),
            0,
            0,
        ))?;
        self.hub_context = Some(HubContext {
            slot_id: self.slot_id,
            root_port: self.port,
            speed: self.speed,
            max_packet: self.max_packet,
            port_count,
            route_string: self.route_string,
            route_depth: self.route_depth,
            ep0_ring: self.ep0_ring,
            control_data: self.control_data,
            device_context: self.device_context,
        });
        #[cfg(target_os = "none")]
        crate::kprintln!(
            "usb: hub root_port={} slot={} ports={} speed={} max_packet={} route=0x{:x} depth={} status=ready",
            self.port,
            self.slot_id,
            port_count,
            self.speed,
            self.max_packet,
            self.route_string,
            self.route_depth
        );
        self.prepare_hid_resources(allocator)?;
        let (hub_port, speed) = self.find_hub_child(0)?;
        let hub = self.hub_context.ok_or(UsbError::NoHid)?;
        self.port = hub.root_port;
        self.speed = speed;
        self.hub_port = Some(hub_port);
        let (route_string, route_depth) = append_hub_route(hub, hub_port)?;
        self.route_string = route_string;
        self.route_depth = route_depth;
        self.parent_hub_slot = hub.slot_id;
        self.parent_hub_port = hub_port;
        self.enumerate_device(allocator)
    }

    fn hub_control_in(&mut self, setup: u64, bytes: &mut [u8]) -> Result<(), UsbError> {
        let hub = self.hub_context.ok_or(UsbError::NoHid)?;
        let child_slot = self.slot_id;
        let child_ep0_ring = self.ep0_ring;
        let child_control_data = self.control_data;
        self.slot_id = hub.slot_id;
        self.ep0_ring = hub.ep0_ring;
        self.control_data = hub.control_data;
        let result = self.control_in(setup, bytes);
        let hub_ep0_ring = self.ep0_ring;
        let hub_control_data = self.control_data;
        self.slot_id = child_slot;
        self.ep0_ring = child_ep0_ring;
        self.control_data = child_control_data;
        self.hub_context = Some(HubContext {
            ep0_ring: hub_ep0_ring,
            control_data: hub_control_data,
            ..hub
        });
        result
    }

    fn hub_control_no_data(&mut self, setup: u64) -> Result<(), UsbError> {
        let hub = self.hub_context.ok_or(UsbError::NoHid)?;
        let child_slot = self.slot_id;
        let child_ep0_ring = self.ep0_ring;
        let child_control_data = self.control_data;
        self.slot_id = hub.slot_id;
        self.ep0_ring = hub.ep0_ring;
        self.control_data = hub.control_data;
        let result = self.control_no_data(setup);
        let hub_ep0_ring = self.ep0_ring;
        let hub_control_data = self.control_data;
        self.slot_id = child_slot;
        self.ep0_ring = child_ep0_ring;
        self.control_data = child_control_data;
        self.hub_context = Some(HubContext {
            ep0_ring: hub_ep0_ring,
            control_data: hub_control_data,
            ..hub
        });
        result
    }

    fn hub_port_status(&mut self, port: u8) -> Result<u16, UsbError> {
        let mut status = [0u8; 4];
        self.hub_control_in(
            setup_packet(0xa3, USB_REQUEST_GET_STATUS, 0, u16::from(port), 4),
            &mut status,
        )?;
        Ok(u16::from_le_bytes([status[0], status[1]]))
    }

    fn hub_port_feature(&mut self, request: u8, feature: u16, port: u8) -> Result<(), UsbError> {
        self.hub_control_no_data(setup_packet(0x23, request, feature, u16::from(port), 0))
    }

    fn find_hub_child(&mut self, after_port: u8) -> Result<(u8, u8), UsbError> {
        let hub = self.hub_context.ok_or(UsbError::NoHid)?;
        if hub.speed == 0
            || !matches!(hub.max_packet, 8 | 16 | 32 | 64)
            || hub.device_context.physical_base == 0
        {
            return Err(UsbError::UnsupportedDevice);
        }
        let first_port = after_port.saturating_add(1);
        if first_port > hub.port_count {
            return Err(UsbError::NoPort);
        }
        for port in first_port..=hub.port_count {
            self.hub_port_feature(USB_REQUEST_SET_FEATURE, USB_FEATURE_PORT_POWER, port)?;
            let status = self.hub_port_status(port)?;
            if status & USB_HUB_PORT_CONNECTION == 0 {
                continue;
            }
            self.hub_port_feature(USB_REQUEST_SET_FEATURE, USB_FEATURE_PORT_RESET, port)?;
            let mut last_status = status;
            let mut enabled = false;
            for _ in 0..XHCI_HUB_RESET_SPINS {
                last_status = self.hub_port_status(port)?;
                if last_status & USB_HUB_PORT_ENABLE != 0 {
                    enabled = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !enabled {
                return Err(UsbError::PortTimeout {
                    port,
                    status: u32::from(last_status),
                });
            }
            self.hub_port_feature(USB_REQUEST_CLEAR_FEATURE, USB_FEATURE_PORT_C_RESET, port)?;
            #[cfg(target_os = "none")]
            crate::kprintln!(
                "usb: hub child root_port={} port={} speed={} parent_route=0x{:x} parent_depth={} status=ready",
                hub.root_port,
                port,
                hub_port_speed(last_status),
                hub.route_string,
                hub.route_depth
            );
            return Ok((port, hub_port_speed(last_status)));
        }
        Err(UsbError::NoPort)
    }

    fn prepare_hid_resources(
        &mut self,
        allocator: &mut FrameAllocator<'_>,
    ) -> Result<(), UsbError> {
        let route_string = self.hub_context.map_or(0, |hub| hub.route_string);
        let route_depth = self.hub_context.map_or(0, |hub| hub.route_depth);
        self.input_context =
            allocate_page(allocator, self.physical_memory_offset, self.capability)?;
        self.device_context =
            allocate_page(allocator, self.physical_memory_offset, self.capability)?;
        self.ep0_ring = Ring::new(allocate_page(
            allocator,
            self.physical_memory_offset,
            self.capability,
        )?)?;
        self.interrupt_ring = Ring::new(allocate_page(
            allocator,
            self.physical_memory_offset,
            self.capability,
        )?)?;
        self.control_data = allocate_page(allocator, self.physical_memory_offset, self.capability)?;
        self.report_data = allocate_page(allocator, self.physical_memory_offset, self.capability)?;
        self.slot_id = 0;
        self.endpoint_id = 0;
        self.max_packet = 8;
        self.report_length = 0;
        self.pending_completion = None;
        self.deferred_events = [None; USB_DEFERRED_EVENT_COUNT];
        self.interrupt_pending = false;
        self.hub_port = None;
        self.route_string = route_string;
        self.route_depth = route_depth;
        self.parent_hub_slot = 0;
        self.parent_hub_port = 0;
        self.hub_port_count = 0;
        self.is_hub = false;
        Ok(())
    }

    fn context_offset(&self, context_index: usize) -> Result<u64, UsbError> {
        let bytes = self
            .context_size
            .checked_mul(context_index)
            .ok_or(UsbError::DmaAddressOverflow)?;
        u64::try_from(bytes).map_err(|_| UsbError::DmaAddressOverflow)
    }

    fn write_slot_context(&self, last_context: u8) -> Result<(), UsbError> {
        let offset = self.context_offset(1)?;
        let mut slot = (self.route_string & 0x000f_ffff)
            | (u32::from(self.speed) << 20)
            | (u32::from(last_context) << 27);
        if self.is_hub {
            slot |= 1 << 26;
        }
        self.input_context.write_u32(offset, slot)?;
        self.input_context.write_u32(
            offset + 4,
            (u32::from(self.port) << 16)
                | if self.is_hub {
                    u32::from(self.hub_port_count) << 24
                } else {
                    0
                },
        )?;
        self.input_context.write_u32(
            offset + 8,
            u32::from(self.parent_hub_slot) | (u32::from(self.parent_hub_port) << 8),
        )?;
        self.input_context.write_u32(offset + 12, 0)
    }

    fn write_ep0_context(&self, max_packet: u16) -> Result<(), UsbError> {
        let offset = self.context_offset(2)?;
        self.input_context.write_u32(offset, 0)?;
        self.input_context.write_u32(
            offset + 4,
            (3 << 1) | (4 << 3) | (u32::from(max_packet) << 16),
        )?;
        self.input_context
            .write_u64(offset + 8, self.ep0_ring.page.physical_base | 1)?;
        self.input_context.write_u32(offset + 16, 8)
    }

    fn write_interrupt_context(&mut self, endpoint: HidEndpoint) -> Result<(), UsbError> {
        self.input_context.clear();
        self.input_context
            .write_u32(4, XHCI_CONTEXT_FLAG_SLOT | (1 << endpoint.endpoint_id))?;
        let slot_offset = self.context_offset(1)?;
        let current_slot = self.device_context.read_u32(0)?;
        let current_slot_1 = self.device_context.read_u32(4)?;
        let current_slot_2 = self.device_context.read_u32(8)?;
        let current_slot_3 = self.device_context.read_u32(12)?;
        self.input_context.write_u32(
            slot_offset,
            (current_slot & !(0x1f << 27)) | (u32::from(endpoint.endpoint_id) << 27),
        )?;
        self.input_context
            .write_u32(slot_offset + 4, current_slot_1)?;
        self.input_context
            .write_u32(slot_offset + 8, current_slot_2)?;
        self.input_context
            .write_u32(slot_offset + 12, current_slot_3)?;

        let endpoint_offset = self.context_offset(1 + usize::from(endpoint.endpoint_id))?;
        self.input_context
            .write_u32(endpoint_offset, u32::from(endpoint.interval) << 16)?;
        self.input_context.write_u32(
            endpoint_offset + 4,
            (3 << 1) | (7 << 3) | (u32::from(endpoint.max_packet) << 16),
        )?;
        self.input_context.write_u64(
            endpoint_offset + 8,
            self.interrupt_ring.page.physical_base | 1,
        )?;
        self.input_context
            .write_u32(endpoint_offset + 16, u32::from(endpoint.max_packet))?;
        self.max_packet = endpoint.max_packet;
        Ok(())
    }

    fn command(
        &mut self,
        parameter: u64,
        status: u32,
        control: u32,
        operation: u8,
    ) -> Result<Event, UsbError> {
        self.command_ring.enqueue(parameter, status, control)?;
        self.ring_doorbell(0, 0)?;
        for _ in 0..XHCI_POLL_SPINS {
            if let Some(event) = self.next_event()? {
                self.acknowledge_interrupt();
                if event.kind() == XHCI_TRB_TYPE_PORT_STATUS {
                    continue;
                }
                if event.kind() != XHCI_TRB_TYPE_COMMAND_COMPLETION {
                    if event.kind() == XHCI_TRB_TYPE_TRANSFER_EVENT {
                        self.defer_event(event);
                    }
                    continue;
                }
                if event.completion_code() != XHCI_COMPLETION_SUCCESS {
                    return Err(UsbError::Completion {
                        operation,
                        code: event.completion_code(),
                    });
                }
                return Ok(event);
            }
            core::hint::spin_loop();
        }
        let status = self.mmio.read_u32(self.operational_base + OP_STATUS)?;
        if status & USB_STATUS_HOST_CONTROLLER_ERROR != 0 {
            return Err(UsbError::ControllerError { status });
        }
        Err(UsbError::ControllerTimeout {
            operation,
            value: status,
        })
    }

    fn control_in(&mut self, setup: u64, bytes: &mut [u8]) -> Result<(), UsbError> {
        if bytes.len() > PAGE_SIZE as usize {
            return Err(UsbError::DmaOutOfBounds {
                offset: 0,
                size: bytes.len() as u64,
            });
        }
        self.control_data.clear();
        self.ep0_ring.enqueue(
            setup,
            8,
            (XHCI_TRB_TYPE_SETUP << XHCI_TRB_TYPE_SHIFT)
                | XHCI_TRB_IMMEDIATE_DATA
                | (3 << XHCI_TRB_TRANSFER_TYPE_SHIFT)
                | XHCI_TRB_CHAIN,
        )?;
        self.ep0_ring.enqueue(
            self.control_data.physical_base,
            bytes.len() as u32,
            (XHCI_TRB_TYPE_DATA << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_DIRECTION_IN | XHCI_TRB_CHAIN,
        )?;
        self.ep0_ring.enqueue(
            0,
            0,
            (XHCI_TRB_TYPE_STATUS << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_INTERRUPT_ON_COMPLETION,
        )?;
        self.ring_doorbell(self.slot_id, 1)?;
        let event = self.wait_for_transfer(1, 2)?;
        if !matches!(
            event.completion_code(),
            XHCI_COMPLETION_SUCCESS | XHCI_COMPLETION_SHORT_PACKET
        ) {
            return Err(UsbError::Completion {
                operation: 5,
                code: event.completion_code(),
            });
        }
        let _residual = event.residual_length();
        self.control_data.read_bytes(0, bytes)
    }

    fn control_no_data(&mut self, setup: u64) -> Result<(), UsbError> {
        self.ep0_ring.enqueue(
            setup,
            8,
            (XHCI_TRB_TYPE_SETUP << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_IMMEDIATE_DATA | XHCI_TRB_CHAIN,
        )?;
        self.ep0_ring.enqueue(
            0,
            0,
            (XHCI_TRB_TYPE_STATUS << XHCI_TRB_TYPE_SHIFT)
                | XHCI_TRB_DIRECTION_IN
                | XHCI_TRB_INTERRUPT_ON_COMPLETION,
        )?;
        self.ring_doorbell(self.slot_id, 1)?;
        let event = self.wait_for_transfer(1, 6)?;
        if event.completion_code() != XHCI_COMPLETION_SUCCESS {
            return Err(UsbError::Completion {
                operation: 6,
                code: event.completion_code(),
            });
        }
        Ok(())
    }

    fn wait_for_transfer(&mut self, endpoint_id: u8, operation: u8) -> Result<Event, UsbError> {
        for _ in 0..XHCI_POLL_SPINS {
            if let Some(event) = self.next_event()? {
                self.acknowledge_interrupt();
                if event.kind() != XHCI_TRB_TYPE_TRANSFER_EVENT {
                    continue;
                }
                if event.slot_id() != self.slot_id || event.endpoint_id() != endpoint_id {
                    self.defer_event(event);
                    continue;
                }
                return Ok(event);
            }
            core::hint::spin_loop();
        }
        let status = self.mmio.read_u32(self.operational_base + OP_STATUS)?;
        Err(UsbError::ControllerTimeout {
            operation,
            value: status,
        })
    }

    fn next_event(&mut self) -> Result<Option<Event>, UsbError> {
        let offset = (self.event_index * 16) as u64;
        let status = self.event_ring.read_u32(offset + 8)?;
        let control = self.event_ring.read_u32(offset + 12)?;
        let owned = control & XHCI_TRB_CYCLE != 0;
        if owned != self.event_cycle {
            return Ok(None);
        }
        let event = Event { status, control };
        self.event_index += 1;
        if self.event_index == XHCI_RING_TRBS {
            self.event_index = 0;
            self.event_cycle = !self.event_cycle;
        }
        let dequeue = self
            .event_ring
            .physical_base
            .checked_add((self.event_index * 16) as u64)
            .ok_or(UsbError::DmaAddressOverflow)?;
        write_mmio_u64(
            self.mmio,
            self.runtime_base + RUNTIME_INTERRUPTER_0 + INTERRUPTER_ERDP,
            dequeue | EVENT_HANDLER_BUSY,
        )?;
        Ok(Some(event))
    }

    fn ring_doorbell(&self, slot_id: u8, endpoint_id: u8) -> Result<(), UsbError> {
        let value = u32::from(endpoint_id);
        self.mmio
            .write_u32(
                self.doorbell_base
                    .checked_add(u64::from(slot_id) * 4)
                    .ok_or(UsbError::DmaAddressOverflow)?,
                value,
            )
            .map_err(UsbError::from)
    }

    fn poll_input_from_set(&mut self) -> Option<crate::input::InputEvent> {
        if self.disabled {
            return None;
        }
        if self.interrupt_pending {
            let Some(event) = self.pending_completion.take() else {
                return None;
            };
            if !self.accepts_completion(event) {
                return None;
            }
            self.interrupt_pending = false;
            return self.consume_completion(event);
        }
        self.start_input_transfer();
        None
    }

    fn accepts_completion(&self, event: Event) -> bool {
        event.kind() == XHCI_TRB_TYPE_TRANSFER_EVENT
            && event.slot_id() == self.slot_id
            && event.endpoint_id() == self.endpoint_id
    }

    fn consume_completion(&mut self, event: Event) -> Option<crate::input::InputEvent> {
        if !matches!(
            event.completion_code(),
            XHCI_COMPLETION_SUCCESS | XHCI_COMPLETION_SHORT_PACKET
        ) {
            self.disabled = true;
            return None;
        }
        let mut report = [0u8; 64];
        let length = self.report_length.min(report.len());
        if self
            .report_data
            .read_bytes(0, &mut report[..length])
            .is_err()
        {
            self.disabled = true;
            return None;
        }
        self.reports = self.reports.saturating_add(1);
        if let Some(input) = self.hid.translate(&report[..length]) {
            self.bytes = self.bytes.saturating_add(match self.kind {
                HidKind::Keyboard => 1,
                HidKind::Mouse => length as u64,
            });
            if !self.first_report_logged {
                self.first_report_logged = true;
                #[cfg(target_os = "none")]
                crate::kprintln!(
                    "usb: hid={:?} first-report kind={} dx={} dy={} buttons={} status=ready",
                    self.kind,
                    input.kind,
                    input.dx,
                    input.dy,
                    input.buttons
                );
            }
            return Some(input);
        }
        None
    }

    fn start_input_transfer(&mut self) {
        if self
            .interrupt_ring
            .enqueue(
                self.report_data.physical_base,
                self.report_length as u32,
                (XHCI_TRB_TYPE_NORMAL << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_INTERRUPT_ON_COMPLETION,
            )
            .is_err()
        {
            self.disabled = true;
            return;
        }
        if self.ring_doorbell(self.slot_id, self.endpoint_id).is_err() {
            self.disabled = true;
            return;
        }
        self.interrupt_pending = true;
    }
}

#[derive(Debug, Clone, Copy)]
struct HidEndpoint {
    kind: HidKind,
    configuration_value: u8,
    endpoint_id: u8,
    interval: u8,
    max_packet: u16,
}

fn allocate_page(
    allocator: &mut FrameAllocator<'_>,
    physical_memory_offset: u64,
    capability: u32,
) -> Result<DmaPage, UsbError> {
    let frame = allocator.next().ok_or(UsbError::NoDmaFrame)?;
    let physical_base = frame.start_address();
    if capability & 1 == 0 && physical_base > u64::from(u32::MAX) {
        return Err(UsbError::DmaAddressTooLarge {
            address: physical_base,
        });
    }
    let virtual_base = physical_memory_offset
        .checked_add(physical_base)
        .ok_or(UsbError::DmaAddressOverflow)?;
    let page = DmaPage {
        physical_base,
        virtual_base,
    };
    page.clear();
    Ok(page)
}

fn validate_register_offset(mmio: MmioRegion, offset: u64) -> Result<(), UsbError> {
    if offset.checked_add(4).is_none() || offset + 4 > mmio.length() {
        return Err(UsbError::InvalidRegisterOffset { offset });
    }
    Ok(())
}

fn write_mmio_u64(mmio: MmioRegion, offset: u64, value: u64) -> Result<(), UsbError> {
    mmio.write_u32(offset, value as u32)?;
    mmio.write_u32(offset + 4, (value >> 32) as u32)?;
    Ok(())
}

fn stop_and_reset(mmio: MmioRegion, operational_base: u64) -> Result<(), UsbError> {
    let command = mmio.read_u32(operational_base + OP_COMMAND)? & !USB_COMMAND_RUN;
    mmio.write_u32(operational_base + OP_COMMAND, command)?;
    wait_until(mmio, operational_base + OP_STATUS, |status| {
        status & USB_STATUS_HALTED != 0
    })?;
    mmio.write_u32(operational_base + OP_COMMAND, command | USB_COMMAND_RESET)?;
    for _ in 0..XHCI_POLL_SPINS {
        let command = mmio.read_u32(operational_base + OP_COMMAND)?;
        let status = mmio.read_u32(operational_base + OP_STATUS)?;
        if command & USB_COMMAND_RESET == 0 && status & USB_STATUS_CONTROLLER_NOT_READY == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(UsbError::ControllerTimeout {
        operation: 0,
        value: mmio.read_u32(operational_base + OP_STATUS)?,
    })
}

fn wait_until(
    mmio: MmioRegion,
    register: u64,
    predicate: impl Fn(u32) -> bool,
) -> Result<(), UsbError> {
    let mut last = 0;
    for _ in 0..XHCI_POLL_SPINS {
        last = mmio.read_u32(register)?;
        if predicate(last) {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(UsbError::ControllerTimeout {
        operation: 0,
        value: last,
    })
}

fn find_and_reset_port(
    mmio: MmioRegion,
    operational_base: u64,
    max_ports: u8,
    after_port: u8,
) -> Result<(u8, u8), UsbError> {
    for port in after_port.saturating_add(1)..=max_ports {
        let offset = operational_base + OP_PORTS + (u64::from(port) - 1) * OP_PORT_STRIDE;
        let status = mmio.read_u32(offset)?;
        if status & PORT_CONNECTED == 0 {
            continue;
        }
        mmio.write_u32(offset, status | PORT_RESET)?;
        for _ in 0..XHCI_POLL_SPINS {
            let updated = mmio.read_u32(offset)?;
            if updated & PORT_RESET == 0 && updated & PORT_ENABLED != 0 {
                let speed = ((updated >> PORT_SPEED_SHIFT) & PORT_SPEED_MASK) as u8;
                if speed == 0 {
                    return Err(UsbError::PortTimeout {
                        port,
                        status: updated,
                    });
                }
                return Ok((port, speed));
            }
            core::hint::spin_loop();
        }
        return Err(UsbError::PortTimeout {
            port,
            status: mmio.read_u32(offset)?,
        });
    }
    Err(UsbError::NoPort)
}

fn setup_packet(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> u64 {
    u64::from(request_type)
        | (u64::from(request) << 8)
        | (u64::from(value) << 16)
        | (u64::from(index) << 32)
        | (u64::from(length) << 48)
}

fn parse_configuration_length(configuration: &[u8; 256]) -> Result<usize, UsbError> {
    if configuration[0] < 9 || configuration[1] != USB_DESCRIPTOR_CONFIGURATION {
        return Err(UsbError::InvalidDescriptor {
            descriptor_type: configuration[1],
            length: configuration[0],
        });
    }
    let total_length = usize::from(u16::from_le_bytes([configuration[2], configuration[3]]));
    if !(9..=configuration.len()).contains(&total_length) {
        return Err(UsbError::InvalidDescriptor {
            descriptor_type: configuration[1],
            length: configuration[0],
        });
    }
    Ok(total_length)
}

fn configuration_value(configuration: &[u8]) -> Option<u8> {
    if configuration.len() >= 6
        && configuration[0] >= 6
        && configuration[1] == USB_DESCRIPTOR_CONFIGURATION
    {
        Some(configuration[5])
    } else {
        None
    }
}

fn configuration_has_hub(configuration: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + 2 <= configuration.len() {
        let length = usize::from(configuration[offset]);
        let descriptor_type = configuration[offset + 1];
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        if length < 2 || end > configuration.len() {
            return false;
        }
        if descriptor_type == USB_DESCRIPTOR_INTERFACE
            && length >= 9
            && configuration[offset + 5] == USB_CLASS_HUB
        {
            return true;
        }
        offset = end;
    }
    false
}

fn hub_port_speed(status: u16) -> u8 {
    if status & USB_HUB_PORT_HIGH_SPEED != 0 {
        3
    } else if status & USB_HUB_PORT_LOW_SPEED != 0 {
        2
    } else {
        1
    }
}

fn find_boot_hid_endpoint(configuration: &[u8]) -> Result<HidEndpoint, UsbError> {
    let mut offset = 0usize;
    let mut hid_kind = None;
    let mut configuration_value = None;
    while offset + 2 <= configuration.len() {
        let length = usize::from(configuration[offset]);
        let descriptor_type = configuration[offset + 1];
        if length < 2 || offset + length > configuration.len() {
            return Err(UsbError::InvalidDescriptor {
                descriptor_type,
                length: length as u8,
            });
        }
        match descriptor_type {
            USB_DESCRIPTOR_CONFIGURATION if length >= 6 => {
                configuration_value = Some(configuration[offset + 5]);
            }
            USB_DESCRIPTOR_INTERFACE if length >= 9 => {
                hid_kind = if configuration[offset + 5] == USB_CLASS_HID
                    && configuration[offset + 6] == USB_HID_SUBCLASS_BOOT
                {
                    match configuration[offset + 7] {
                        USB_HID_PROTOCOL_KEYBOARD => Some(HidKind::Keyboard),
                        USB_HID_PROTOCOL_MOUSE => Some(HidKind::Mouse),
                        _ => None,
                    }
                } else {
                    None
                };
            }
            USB_DESCRIPTOR_ENDPOINT if hid_kind.is_some() && length >= 7 => {
                let address = configuration[offset + 2];
                let attributes = configuration[offset + 3] & 0x03;
                let max_packet =
                    u16::from_le_bytes([configuration[offset + 4], configuration[offset + 5]])
                        & 0x07ff;
                if address & USB_ENDPOINT_DIRECTION_IN != 0
                    && attributes == USB_ENDPOINT_TRANSFER_INTERRUPT
                    && (1..=64).contains(&max_packet)
                {
                    let endpoint_number = address & 0x0f;
                    if endpoint_number == 0 {
                        return Err(UsbError::InvalidEndpoint {
                            address,
                            attributes,
                            max_packet,
                        });
                    }
                    return Ok(HidEndpoint {
                        kind: hid_kind.unwrap_or(HidKind::Keyboard),
                        configuration_value: configuration_value.unwrap_or(1),
                        endpoint_id: endpoint_number.saturating_mul(2).saturating_add(1),
                        interval: xhci_interval(configuration[offset + 6]),
                        max_packet,
                    });
                }
            }
            _ => {}
        }
        offset += length;
    }
    Err(UsbError::UnsupportedDevice)
}

fn xhci_interval(usb_interval: u8) -> u8 {
    let microframes = u32::from(usb_interval.max(1)) * 8;
    let mut interval = 0u8;
    let mut value = 1u32;
    while value < microframes && interval < 15 {
        value <<= 1;
        interval += 1;
    }
    interval.max(3)
}

#[derive(Debug, Clone, Copy)]
enum HidState {
    Keyboard(HidKeyboardState),
    Mouse(HidMouseState),
}

impl HidState {
    fn translate(self: &mut Self, report: &[u8]) -> Option<crate::input::InputEvent> {
        match self {
            Self::Keyboard(keyboard) => {
                keyboard
                    .translate(report)
                    .map(|code| crate::input::InputEvent {
                        kind: crate::input::INPUT_EVENT_KEYBOARD,
                        buttons: 0,
                        dx: 0,
                        dy: 0,
                        wheel: 0,
                        code: u32::from(code),
                    })
            }
            Self::Mouse(mouse) => mouse.translate(report),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct HidMouseState;

impl HidMouseState {
    const fn new() -> Self {
        Self
    }

    fn translate(self, report: &[u8]) -> Option<crate::input::InputEvent> {
        if report.len() < 3 {
            return None;
        }
        let wheel = report
            .get(3)
            .copied()
            .map_or(0, |value| i32::from(i8::from_ne_bytes([value])));
        Some(crate::input::InputEvent {
            kind: crate::input::INPUT_EVENT_MOUSE,
            buttons: u32::from(report[0] & 0x07),
            dx: i32::from(i8::from_ne_bytes([report[1]])),
            dy: i32::from(i8::from_ne_bytes([report[2]])),
            wheel,
            code: 0,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct HidKeyboardState {
    previous: [u8; 6],
    caps_lock: bool,
}

impl HidKeyboardState {
    const fn new() -> Self {
        Self {
            previous: [0; 6],
            caps_lock: false,
        }
    }

    fn translate(&mut self, report: &[u8]) -> Option<u8> {
        if report.len() < 2 {
            return None;
        }
        let shift = report[0] & 0x22 != 0;
        let mut current = [0u8; 6];
        let key_count = (report.len() - 2).min(current.len());
        current[..key_count].copy_from_slice(&report[2..2 + key_count]);

        let mut result = None;
        for usage in current {
            if usage == 0 || usage == 1 || self.previous.contains(&usage) {
                continue;
            }
            if usage == 0x39 {
                self.caps_lock = !self.caps_lock;
                continue;
            }
            if result.is_none() {
                result = hid_usage_to_ascii(usage, shift, self.caps_lock);
            }
        }
        self.previous = current;
        result
    }
}

fn hid_usage_to_ascii(usage: u8, shift: bool, caps_lock: bool) -> Option<u8> {
    if (0x04..=0x1d).contains(&usage) {
        let normal = b'a' + usage - 0x04;
        return Some(if shift != caps_lock {
            normal - (b'a' - b'A')
        } else {
            normal
        });
    }
    let (normal, shifted) = match usage {
        0x1e => (b'1', b'!'),
        0x1f => (b'2', b'@'),
        0x20 => (b'3', b'#'),
        0x21 => (b'4', b'$'),
        0x22 => (b'5', b'%'),
        0x23 => (b'6', b'^'),
        0x24 => (b'7', b'&'),
        0x25 => (b'8', b'*'),
        0x26 => (b'9', b'('),
        0x27 => (b'0', b')'),
        0x2d => (b'-', b'_'),
        0x2e => (b'=', b'+'),
        0x2f => (b'[', b'{'),
        0x30 => (b']', b'}'),
        0x31 => (b'\\', b'|'),
        0x33 => (b';', b':'),
        0x34 => (b'\'', b'"'),
        0x35 => (b'`', b'~'),
        0x36 => (b',', b'<'),
        0x37 => (b'.', b'>'),
        0x38 => (b'/', b'?'),
        0x28 => return Some(b'\r'),
        0x2a => return Some(8),
        0x2b => return Some(b'\t'),
        0x2c => return Some(b' '),
        _ => return None,
    };
    Some(if shift { shifted } else { normal })
}

const USB_HID_INPUT_QUEUE_LENGTH: usize = 16;

struct UsbInputQueue {
    events: [Option<crate::input::InputEvent>; USB_HID_INPUT_QUEUE_LENGTH],
    head: usize,
    tail: usize,
    count: usize,
}

impl UsbInputQueue {
    fn new() -> Self {
        Self {
            events: [None; USB_HID_INPUT_QUEUE_LENGTH],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn push(&mut self, event: crate::input::InputEvent) {
        if self.count == USB_HID_INPUT_QUEUE_LENGTH {
            self.events[self.head] = None;
            self.head = (self.head + 1) % USB_HID_INPUT_QUEUE_LENGTH;
            self.count -= 1;
        }
        self.events[self.tail] = Some(event);
        self.tail = (self.tail + 1) % USB_HID_INPUT_QUEUE_LENGTH;
        self.count += 1;
    }

    fn pop(&mut self) -> Option<crate::input::InputEvent> {
        let event = self.events[self.head].take()?;
        self.head = (self.head + 1) % USB_HID_INPUT_QUEUE_LENGTH;
        self.count -= 1;
        Some(event)
    }

    fn pop_keyboard(&mut self) -> Option<u8> {
        for offset in 0..self.count {
            let index = (self.head + offset) % USB_HID_INPUT_QUEUE_LENGTH;
            let Some(event) = self.events[index] else {
                continue;
            };
            if event.kind != crate::input::INPUT_EVENT_KEYBOARD {
                continue;
            }
            for shift in offset..self.count.saturating_sub(1) {
                let current = (self.head + shift) % USB_HID_INPUT_QUEUE_LENGTH;
                let next = (self.head + shift + 1) % USB_HID_INPUT_QUEUE_LENGTH;
                self.events[current] = self.events[next];
            }
            self.tail = (self.head + self.count.saturating_sub(1)) % USB_HID_INPUT_QUEUE_LENGTH;
            self.events[self.tail] = None;
            self.count -= 1;
            return Some(event.code as u8);
        }
        None
    }
}

struct UsbHidSet {
    first: UsbHid,
    second: Option<UsbHid>,
    input_queue: UsbInputQueue,
    hotplug_scan_count: u8,
    hotplug_grace_scans: u8,
}

impl UsbHidSet {
    fn new(first: UsbHid) -> Self {
        let hotplug_scan_count = if first.hub_context.is_some() {
            USB_HOTPLUG_SCAN_INTERVAL.saturating_sub(1)
        } else {
            0
        };
        Self {
            first,
            second: None,
            input_queue: UsbInputQueue::new(),
            hotplug_scan_count,
            hotplug_grace_scans: 0,
        }
    }

    fn install_secondary(&mut self, second: UsbHid) {
        if self.second.is_none() {
            self.second = Some(second);
        }
    }

    fn push_input(&mut self, event: crate::input::InputEvent) {
        self.input_queue.push(event);
    }

    fn route_event(&mut self, event: Event) {
        if event.kind() != XHCI_TRB_TYPE_TRANSFER_EVENT {
            return;
        }
        if self.first.accepts_completion(event) {
            self.first.pending_completion = Some(event);
        } else if let Some(second) = self.second.as_mut() {
            if second.accepts_completion(event) {
                second.pending_completion = Some(event);
            }
        }
    }

    fn route_deferred_events(&mut self) {
        while let Some(event) = self.first.take_deferred_event() {
            self.route_event(event);
        }
        loop {
            let event = self.second.as_mut().and_then(UsbHid::take_deferred_event);
            let Some(event) = event else {
                break;
            };
            self.route_event(event);
        }
    }

    fn pump_events(&mut self) {
        self.route_deferred_events();
        loop {
            loop {
                let Ok(Some(event)) = self.first.next_event() else {
                    break;
                };
                self.route_event(event);
            }
            self.first.acknowledge_interrupt();
            let Ok(Some(event)) = self.first.next_event() else {
                break;
            };
            self.route_event(event);
        }
    }

    fn hotplug_scan_due(&mut self) -> bool {
        if self.first.hub_context.is_none() {
            return false;
        }
        self.hotplug_scan_count = self.hotplug_scan_count.saturating_add(1);
        if self.hotplug_scan_count < USB_HOTPLUG_SCAN_INTERVAL {
            return false;
        }
        self.hotplug_scan_count = 0;
        true
    }

    fn scan_hotplug(&mut self) {
        if self.first.hub_context.is_none() {
            return;
        }

        if let Some(second_port) = self.second.as_ref().and_then(|second| second.hub_port) {
            let status = match self.first.hub_port_status(second_port) {
                Ok(status) => status,
                Err(error) => {
                    #[cfg(target_os = "none")]
                    crate::kprintln!(
                        "usb: hotplug status port={} failed ({:?}) status=degraded",
                        second_port,
                        error
                    );
                    #[cfg(not(target_os = "none"))]
                    let _ = error;
                    return;
                }
            };
            if status & USB_HUB_PORT_CONNECTION == 0 {
                let Some(second) = self.second.take() else {
                    return;
                };
                let slot_id = second.slot_id;
                let result = self.first.disable_slot(slot_id);
                #[cfg(target_os = "none")]
                crate::kprintln!(
                    "usb: hotplug detached port={} slot={} disable={:?} status=ready",
                    second_port,
                    slot_id,
                    result
                );
                #[cfg(not(target_os = "none"))]
                let _ = result;
                self.route_deferred_events();
                drop(second);
            }
            return;
        }

        let next_frame_address = self.first.next_frame_address();
        match self.first.initialize_secondary(next_frame_address) {
            Ok(mut second) => {
                let diagnostics = second.diagnostics();
                self.first.sync_shared_state(&mut second);
                self.route_deferred_events();
                #[cfg(target_os = "none")]
                crate::process::update_frame_allocator(second.next_frame_address());
                #[cfg(target_os = "none")]
                crate::kprintln!(
                    "usb: hotplug attached hid={:?} port={} hub_port={:?} slot={} route=0x{:x} depth={} status=ready",
                    diagnostics.kind,
                    diagnostics.port,
                    diagnostics.hub_port,
                    diagnostics.slot_id,
                    diagnostics.route_string,
                    diagnostics.route_depth
                );
                #[cfg(not(target_os = "none"))]
                let _ = diagnostics;
                self.hotplug_grace_scans = 0;
                self.second = Some(second);
            }
            Err(UsbError::NoPort) => {
                self.hotplug_grace_scans = self
                    .hotplug_grace_scans
                    .saturating_add(1)
                    .min(USB_HOTPLUG_GRACE_SCANS);
            }
            Err(error) => {
                #[cfg(target_os = "none")]
                crate::kprintln!("usb: hotplug attach failed ({:?}) status=degraded", error);
                #[cfg(not(target_os = "none"))]
                let _ = error;
                self.hotplug_grace_scans = USB_HOTPLUG_GRACE_SCANS;
            }
        }
    }

    fn poll_devices(&mut self) {
        let hotplug_due = self.hotplug_scan_due();
        let transfer_needed = !self.first.interrupt_pending
            || self
                .second
                .as_ref()
                .is_some_and(|second| !second.interrupt_pending);
        if self.first.interrupt_mode != UsbInterruptMode::Polling {
            let notified = USB_INTERRUPT_COUNT.swap(0, Ordering::SeqCst) != 0;
            if !notified && !transfer_needed && !hotplug_due {
                return;
            }
        }
        self.pump_events();

        let first_pending = self.first.interrupt_pending;
        let first_event = first_pending
            .then(|| self.first.poll_input_from_set())
            .flatten();
        if let Some(event) = first_event {
            self.push_input(event);
        }

        let second_pending = self
            .second
            .as_ref()
            .is_some_and(|second| second.interrupt_pending);
        let second_event = second_pending
            .then(|| self.second.as_mut().and_then(UsbHid::poll_input_from_set))
            .flatten();
        if let Some(event) = second_event {
            self.push_input(event);
        }

        if hotplug_due {
            self.scan_hotplug();
        }

        let waiting_for_hotplug = self.first.hub_context.is_some()
            && self.second.is_none()
            && self.hotplug_grace_scans < USB_HOTPLUG_GRACE_SCANS;
        if !self.first.interrupt_pending && !waiting_for_hotplug {
            self.first.start_input_transfer();
        }
        if let Some(second) = self.second.as_mut() {
            if !second.interrupt_pending {
                second.start_input_transfer();
            }
        }
    }

    fn read_input_event(&mut self) -> Option<crate::input::InputEvent> {
        if let Some(event) = self.input_queue.pop() {
            return Some(event);
        }
        self.poll_devices();
        self.input_queue.pop()
    }

    fn read_keyboard_byte(&mut self) -> Option<u8> {
        if let Some(code) = self.input_queue.pop_keyboard() {
            return Some(code);
        }
        self.poll_devices();
        self.input_queue.pop_keyboard()
    }
}

static USB_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "none")]
fn usb_interrupt_handler() {
    USB_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);
}

static USB_HID: spin::Once<spin::Mutex<UsbHidSet>> = spin::Once::new();

pub fn install_hid(hid: UsbHid) {
    USB_HID.call_once(|| spin::Mutex::new(UsbHidSet::new(hid)));
}

pub fn install_hid_secondary(hid: UsbHid) {
    if let Some(set) = USB_HID.get() {
        set.lock().install_secondary(hid);
    }
}

pub fn hid_present() -> bool {
    USB_HID.get().is_some()
}

#[cfg(target_os = "none")]
pub fn configure_interrupts(
    destination_apic_id: u32,
    physical_memory: crate::acpi::PhysicalMemory,
    acpi_info: Option<&crate::acpi::AcpiInfo>,
    legacy_available: bool,
) -> Result<UsbInterruptDiagnostics, UsbError> {
    let set = USB_HID.get().ok_or(UsbError::NoHid)?;
    set.lock().first.enable_interrupts(
        destination_apic_id,
        physical_memory,
        acpi_info,
        legacy_available,
    )
}

pub fn interrupt_diagnostics() -> UsbInterruptDiagnostics {
    USB_HID
        .get()
        .map_or(UsbInterruptDiagnostics::polling(), |hid| {
            hid.lock().first.interrupt_diagnostics()
        })
}

pub fn keyboard_ready() -> bool {
    USB_HID.get().is_some_and(|hid| {
        let hid = hid.lock();
        (hid.first.kind == HidKind::Keyboard && !hid.first.disabled)
            || hid
                .second
                .as_ref()
                .is_some_and(|second| second.kind == HidKind::Keyboard && !second.disabled)
    })
}

pub fn read_keyboard_byte() -> Option<u8> {
    USB_HID
        .get()
        .and_then(|hid| hid.lock().read_keyboard_byte())
}

pub fn read_input_event() -> Option<crate::input::InputEvent> {
    USB_HID.get().and_then(|hid| hid.lock().read_input_event())
}

pub fn hid_diagnostics() -> [Option<HidDiagnostics>; 2] {
    USB_HID.get().map_or([None, None], |hid| {
        let hid = hid.lock();
        [
            Some(hid.first.diagnostics()),
            hid.second.as_ref().map(UsbHid::diagnostics),
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DmaPage, HidKeyboardState, HidKind, HidMouseState, HubContext, Ring, UsbInputQueue,
        XHCI_LINK_INDEX, XHCI_TRB_CHAIN, XHCI_TRB_CYCLE, append_hub_route, configuration_has_hub,
        configuration_value, find_boot_hid_endpoint, hid_usage_to_ascii, hub_port_speed,
    };
    use crate::input::{INPUT_EVENT_KEYBOARD, INPUT_EVENT_MOUSE, InputEvent};

    #[repr(align(4096))]
    struct TestDmaPage([u8; 4096]);

    #[test]
    fn transfer_ring_wrap_preserves_link_phase_and_chain() {
        let mut backing = TestDmaPage([0; 4096]);
        let page = DmaPage {
            physical_base: 0x1000,
            virtual_base: backing.0.as_mut_ptr() as u64,
        };
        let mut ring = Ring::new(page).unwrap();

        assert_eq!(
            page.read_u32((XHCI_LINK_INDEX * 16 + 12) as u64).unwrap() & XHCI_TRB_CYCLE,
            0
        );
        for _ in 0..254 {
            ring.enqueue(0, 0, 0).unwrap();
        }
        ring.enqueue(0, 0, XHCI_TRB_CHAIN).unwrap();
        ring.enqueue(0, 0, 0).unwrap();

        let link_control = page.read_u32((XHCI_LINK_INDEX * 16 + 12) as u64).unwrap();
        assert_ne!(link_control & XHCI_TRB_CYCLE, 0);
        assert_ne!(link_control & XHCI_TRB_CHAIN, 0);
        assert!(!ring.cycle);
        assert_eq!(
            page.read_u32(12).unwrap() & XHCI_TRB_CYCLE,
            0,
            "the first TRB after the link uses the toggled producer cycle"
        );
    }

    #[test]
    fn appends_nested_hub_routes_in_xhci_nibble_order() {
        let mut backing = TestDmaPage([0; 4096]);
        let page = DmaPage {
            physical_base: 0x1000,
            virtual_base: backing.0.as_mut_ptr() as u64,
        };
        let hub = HubContext {
            slot_id: 1,
            root_port: 5,
            speed: 3,
            max_packet: 64,
            port_count: 4,
            route_string: 1,
            route_depth: 1,
            ep0_ring: Ring::new(page).unwrap(),
            control_data: page,
            device_context: page,
        };

        assert_eq!(append_hub_route(hub, 1).unwrap(), (0x11, 2));
        assert_eq!(append_hub_route(hub, 2).unwrap(), (0x21, 2));
        assert_eq!(
            append_hub_route(hub, 0),
            Err(super::UsbError::UnsupportedDevice)
        );
        assert_eq!(
            append_hub_route(hub, 16),
            Err(super::UsbError::UnsupportedDevice)
        );
        assert_eq!(
            append_hub_route(
                HubContext {
                    route_depth: 5,
                    ..hub
                },
                1
            ),
            Err(super::UsbError::UnsupportedDevice)
        );
    }

    fn keyboard_event(code: u32) -> InputEvent {
        InputEvent {
            kind: INPUT_EVENT_KEYBOARD,
            code,
            ..InputEvent::default()
        }
    }

    fn mouse_event(dx: i32) -> InputEvent {
        InputEvent {
            kind: INPUT_EVENT_MOUSE,
            dx,
            ..InputEvent::default()
        }
    }

    #[test]
    fn usb_input_queue_keeps_mouse_events_when_console_reads_keyboard() {
        let mut queue = UsbInputQueue::new();
        queue.push(mouse_event(7));
        queue.push(keyboard_event(0x1e));
        queue.push(mouse_event(-3));

        assert_eq!(queue.pop_keyboard(), Some(0x1e));
        assert_eq!(queue.pop(), Some(mouse_event(7)));
        assert_eq!(queue.pop(), Some(mouse_event(-3)));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn parses_boot_keyboard_endpoint_from_configuration() {
        let configuration = [
            9, 2, 34, 0, 1, 1, 0, 0xa0, 50, 9, 4, 0, 0, 1, 3, 1, 1, 0, 9, 0x21, 0x11, 1, 0, 1,
            0x22, 63, 0, 7, 5, 0x81, 3, 8, 0, 10,
        ];
        let endpoint = find_boot_hid_endpoint(&configuration).unwrap();
        assert_eq!(endpoint.kind, HidKind::Keyboard);
        assert_eq!(endpoint.configuration_value, 1);
        assert_eq!(endpoint.endpoint_id, 3);
        assert_eq!(endpoint.max_packet, 8);
        assert_eq!(endpoint.interval, 7);
    }

    #[test]
    fn parses_boot_mouse_endpoint_from_configuration() {
        let configuration = [
            9, 2, 34, 0, 1, 1, 0, 0xa0, 50, 9, 4, 0, 0, 1, 3, 1, 2, 0, 9, 0x21, 0x11, 1, 0, 1,
            0x22, 63, 0, 7, 5, 0x81, 3, 4, 0, 10,
        ];
        let endpoint = find_boot_hid_endpoint(&configuration).unwrap();
        assert_eq!(endpoint.kind, HidKind::Mouse);
        assert_eq!(endpoint.endpoint_id, 3);
        assert_eq!(endpoint.max_packet, 4);
    }

    #[test]
    fn detects_a_hub_interface_and_configuration_value() {
        let configuration = [9, 2, 18, 0, 1, 3, 0, 0xe0, 50, 9, 4, 0, 0, 1, 9, 0, 0, 0];
        assert!(configuration_has_hub(&configuration));
        assert_eq!(configuration_value(&configuration), Some(3));
    }

    #[test]
    fn maps_hub_port_speed_status_to_xhci_speed_codes() {
        assert_eq!(hub_port_speed(0), 1);
        assert_eq!(hub_port_speed(1 << 9), 2);
        assert_eq!(hub_port_speed(1 << 10), 3);
    }

    #[test]
    fn translates_hid_reports_and_tracks_key_releases() {
        let mut state = HidKeyboardState::new();
        assert_eq!(state.translate(&[0, 0, 0x04, 0, 0, 0, 0, 0]), Some(b'a'));
        assert_eq!(state.translate(&[0, 0, 0x04, 0, 0, 0, 0, 0]), None);
        assert_eq!(state.translate(&[0, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(state.translate(&[0x02, 0, 0x05, 0, 0, 0, 0, 0]), Some(b'B'));
        assert_eq!(state.translate(&[0, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(state.translate(&[0, 0, 0x39, 0, 0, 0, 0, 0]), None);
        assert_eq!(state.translate(&[0, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(state.translate(&[0, 0, 0x04, 0, 0, 0, 0, 0]), Some(b'A'));
    }

    #[test]
    fn maps_control_and_shifted_symbols() {
        assert_eq!(hid_usage_to_ascii(0x28, false, false), Some(b'\r'));
        assert_eq!(hid_usage_to_ascii(0x2c, false, false), Some(b' '));
        assert_eq!(hid_usage_to_ascii(0x1f, true, false), Some(b'@'));
        assert_eq!(hid_usage_to_ascii(0x37, true, false), Some(b'>'));
    }

    #[test]
    fn translates_boot_mouse_reports_into_pointer_events() {
        let state = HidMouseState::new();
        assert_eq!(
            state.translate(&[5, 0xfe, 3, 0xff]),
            Some(crate::input::InputEvent {
                kind: crate::input::INPUT_EVENT_MOUSE,
                buttons: 5,
                dx: -2,
                dy: 3,
                wheel: -1,
                code: 0,
            })
        );
    }
}
