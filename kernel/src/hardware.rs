use core::fmt::{self, Write};

use spin::Mutex;

use crate::{
    framebuffer::GraphicsInfo,
    igc::I225Probe,
    pci::{PciAddress, PciDevice, PciInventory, PciRoleCounts},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphicsBackend {
    None,
    FirmwareFramebuffer,
    VirtioGpu,
}

impl GraphicsBackend {
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FirmwareFramebuffer => "firmware-framebuffer",
            Self::VirtioGpu => "virtio-gpu",
        }
    }

    pub const fn compositor(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FirmwareFramebuffer | Self::VirtioGpu => "rust-cpu-raster",
        }
    }

    pub const fn acceleration(self) -> &'static str {
        match self {
            Self::None => "unavailable",
            Self::FirmwareFramebuffer => "unavailable",
            Self::VirtioGpu => "scanout-transport",
        }
    }

    pub const fn status(self) -> &'static str {
        match self {
            Self::None => "degraded",
            Self::FirmwareFramebuffer | Self::VirtioGpu => "ready",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDisplaySnapshot {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
}

impl PciDisplaySnapshot {
    fn from_device(device: PciDevice) -> Self {
        Self {
            address: device.address,
            vendor_id: device.vendor_id,
            device_id: device.device_id,
            class_code: device.class_code,
            subclass: device.subclass,
        }
    }

    fn vendor_name(self) -> &'static str {
        match self.vendor_id {
            0x1002 => "amd",
            0x10de => "nvidia",
            0x8086 => "intel",
            0x1af4 => "virtio",
            0x1234 => "qemu",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareSnapshot {
    pub pci: PciRoleCounts,
    pub framebuffer: Option<GraphicsInfo>,
    pub primary_display: Option<PciDisplaySnapshot>,
    pub i225: Option<I225Probe>,
    pub graphics_backend: GraphicsBackend,
}

impl HardwareSnapshot {
    const fn empty() -> Self {
        Self {
            pci: PciRoleCounts {
                total: 0,
                host_bridges: 0,
                bridges: 0,
                mass_storage: 0,
                network: 0,
                display: 0,
                audio: 0,
                usb: 0,
                other: 0,
            },
            framebuffer: None,
            primary_display: None,
            i225: None,
            graphics_backend: GraphicsBackend::None,
        }
    }
}

static SNAPSHOT: Mutex<HardwareSnapshot> = Mutex::new(HardwareSnapshot::empty());

pub fn init(inventory: &PciInventory, framebuffer: Option<GraphicsInfo>) {
    let primary_display = inventory
        .first_display()
        .map(PciDisplaySnapshot::from_device);
    let graphics_backend = if framebuffer.is_some() {
        GraphicsBackend::FirmwareFramebuffer
    } else {
        GraphicsBackend::None
    };
    *SNAPSHOT.lock() = HardwareSnapshot {
        pci: inventory.role_counts(),
        framebuffer,
        primary_display,
        i225: None,
        graphics_backend,
    };
}

pub fn set_i225(probe: I225Probe) {
    SNAPSHOT.lock().i225 = Some(probe);
}

pub fn set_graphics_backend(graphics_backend: GraphicsBackend) {
    SNAPSHOT.lock().graphics_backend = graphics_backend;
}

pub fn snapshot() -> HardwareSnapshot {
    *SNAPSHOT.lock()
}

pub fn write_text<W: Write>(writer: &mut W) -> fmt::Result {
    let snapshot = snapshot();
    let counts = snapshot.pci;
    writeln!(
        writer,
        "pci: devices={} storage={} network={} display={} audio={} usb={} host_bridges={} bridges={} other={} status={}",
        counts.total,
        counts.mass_storage,
        counts.network,
        counts.display,
        counts.audio,
        counts.usb,
        counts.host_bridges,
        counts.bridges,
        counts.other,
        if counts.total == 0 {
            "degraded"
        } else {
            "ready"
        }
    )?;
    if let Some(framebuffer) = snapshot.framebuffer {
        writeln!(
            writer,
            "framebuffer: {}x{} stride={} bytes_per_pixel={} status=ready",
            framebuffer.width, framebuffer.height, framebuffer.stride, framebuffer.bytes_per_pixel
        )?;
    } else {
        writeln!(writer, "framebuffer: none status=degraded")?;
    }
    if let Some(display) = snapshot.primary_display {
        writeln!(
            writer,
            "display: pci={:02x}:{:02x}.{} vendor={} vendor_id=0x{:04x} device_id=0x{:04x} class=0x{:02x}{:02x} status=present",
            display.address.bus,
            display.address.device,
            display.address.function,
            display.vendor_name(),
            display.vendor_id,
            display.device_id,
            display.class_code,
            display.subclass
        )?;
    } else {
        writeln!(writer, "display: pci=none status=absent")?;
    }
    if let Some(network) = snapshot.i225 {
        writeln!(
            writer,
            "network: driver=igc probe=i225-v pci={:02x}:{:02x}.{} mmio=0x{:x} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link_up={} speed_mbps={} full_duplex={} busmaster={} status=ready",
            network.address.bus,
            network.address.device,
            network.address.function,
            network.mmio_base,
            network.mac_address[0],
            network.mac_address[1],
            network.mac_address[2],
            network.mac_address[3],
            network.mac_address[4],
            network.mac_address[5],
            network.link.up,
            network.link.speed.mbps(),
            network.link.full_duplex,
            network.bus_master_enabled
        )?;
    } else {
        writeln!(writer, "network: driver=igc probe=i225-v status=absent")?;
    }
    writeln!(
        writer,
        "graphics: backend={} compositor={} acceleration={} status={}",
        snapshot.graphics_backend.name(),
        snapshot.graphics_backend.compositor(),
        snapshot.graphics_backend.acceleration(),
        snapshot.graphics_backend.status()
    )?;
    Ok(())
}
