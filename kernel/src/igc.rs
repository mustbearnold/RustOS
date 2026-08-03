use crate::pci::{
    MmioError, MmioRegion, PciDevice, PciDeviceResources, PciInventory, PciResourceError,
};

const INTEL_VENDOR_ID: u16 = 0x8086;
pub const I225_V_DEVICE_ID: u16 = 0x15f3;
pub const I225_MMIO_LENGTH: u64 = 0x10_0000;

const REG_STATUS: u64 = 0x0008;
const REG_RAL0: u64 = 0x5400;
const REG_RAH0: u64 = 0x5404;

const STATUS_FULL_DUPLEX: u32 = 1 << 0;
const STATUS_LINK_UP: u32 = 1 << 1;
const STATUS_SPEED_100: u32 = 1 << 6;
const STATUS_SPEED_1000: u32 = 1 << 7;
const STATUS_SPEED_2500: u32 = 1 << 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgcError {
    Resources(PciResourceError),
    Mmio(MmioError),
    MemorySpaceDisabled,
    InvalidMac,
}

impl From<PciResourceError> for IgcError {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

impl From<MmioError> for IgcError {
    fn from(error: MmioError) -> Self {
        Self::Mmio(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSpeed {
    Unknown,
    Mbps100,
    Mbps1000,
    Mbps2500,
}

impl LinkSpeed {
    pub const fn mbps(self) -> u16 {
        match self {
            Self::Unknown => 0,
            Self::Mbps100 => 100,
            Self::Mbps1000 => 1000,
            Self::Mbps2500 => 2500,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatus {
    pub up: bool,
    pub full_duplex: bool,
    pub speed: LinkSpeed,
}

impl LinkStatus {
    pub const fn from_register(status: u32) -> Self {
        let up = status & STATUS_LINK_UP != 0;
        let speed = if !up {
            LinkSpeed::Unknown
        } else if status & STATUS_SPEED_2500 != 0 {
            LinkSpeed::Mbps2500
        } else if status & STATUS_SPEED_1000 != 0 {
            LinkSpeed::Mbps1000
        } else if status & STATUS_SPEED_100 != 0 {
            LinkSpeed::Mbps100
        } else {
            LinkSpeed::Unknown
        };
        Self {
            up,
            full_duplex: up && status & STATUS_FULL_DUPLEX != 0,
            speed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I225Probe {
    pub address: crate::pci::PciAddress,
    pub mmio_base: u64,
    pub status: u32,
    pub mac_address: [u8; 6],
    pub link: LinkStatus,
    pub bus_master_enabled: bool,
}

pub fn probe(
    inventory: &PciInventory,
    physical_memory_offset: u64,
) -> Result<Option<I225Probe>, IgcError> {
    let Some(device) = find_device(inventory) else {
        return Ok(None);
    };
    if !device.memory_space_enabled() {
        return Err(IgcError::MemorySpaceDisabled);
    }

    let mut resources = PciDeviceResources::new(device, physical_memory_offset);
    let mmio = resources.claim_mmio(0, I225_MMIO_LENGTH)?;
    let status = mmio.read_u32(REG_STATUS)?;
    let mac_address = read_mac_address(mmio)?;
    if !valid_mac_address(mac_address) {
        return Err(IgcError::InvalidMac);
    }

    Ok(Some(I225Probe {
        address: device.address,
        mmio_base: mmio.physical_base(),
        status,
        mac_address,
        link: LinkStatus::from_register(status),
        bus_master_enabled: device.bus_master_enabled(),
    }))
}

fn find_device(inventory: &PciInventory) -> Option<PciDevice> {
    inventory
        .devices()
        .iter()
        .copied()
        .find(|device| is_supported_device(*device))
}

fn is_supported_device(device: PciDevice) -> bool {
    device.vendor_id == INTEL_VENDOR_ID && device.device_id == I225_V_DEVICE_ID
}

fn read_mac_address(mmio: MmioRegion) -> Result<[u8; 6], MmioError> {
    let low = mmio.read_u32(REG_RAL0)?;
    let high = mmio.read_u32(REG_RAH0)?;
    Ok([
        low as u8,
        (low >> 8) as u8,
        (low >> 16) as u8,
        (low >> 24) as u8,
        high as u8,
        (high >> 8) as u8,
    ])
}

fn valid_mac_address(mac_address: [u8; 6]) -> bool {
    let all_zero = mac_address.iter().all(|byte| *byte == 0);
    let all_ones = mac_address.iter().all(|byte| *byte == u8::MAX);
    !all_zero && !all_ones
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_live_2500_mbps_full_duplex_link() {
        let link =
            LinkStatus::from_register(STATUS_LINK_UP | STATUS_FULL_DUPLEX | STATUS_SPEED_2500);
        assert_eq!(
            link,
            LinkStatus {
                up: true,
                full_duplex: true,
                speed: LinkSpeed::Mbps2500,
            }
        );
        assert_eq!(link.speed.mbps(), 2500);
    }

    #[test]
    fn reports_unknown_speed_when_the_link_is_down() {
        let link = LinkStatus::from_register(STATUS_SPEED_2500 | STATUS_FULL_DUPLEX);
        assert_eq!(
            link,
            LinkStatus {
                up: false,
                full_duplex: false,
                speed: LinkSpeed::Unknown,
            }
        );
    }

    #[test]
    fn recognizes_only_the_target_i225_v_device() {
        let device = |vendor_id, device_id| PciDevice {
            address: crate::pci::PciAddress::new(0, 0, 0),
            vendor_id,
            device_id,
            revision_id: 0,
            prog_if: 0,
            command: 0,
            status: 0,
            subclass: 0,
            class_code: 0x02,
            header_type: 0,
            interrupt_line: 0,
            interrupt_pin: 0,
            bars: [crate::pci::PciBar::Unassigned; 6],
            capabilities: crate::pci::PciCapabilities {
                msi: None,
                msix: None,
                virtio: [None; 5],
            },
        };

        assert!(is_supported_device(device(
            INTEL_VENDOR_ID,
            I225_V_DEVICE_ID
        )));
        assert!(!is_supported_device(device(INTEL_VENDOR_ID, 0x15f2)));
        assert!(!is_supported_device(device(0x10de, I225_V_DEVICE_ID)));
    }

    #[test]
    fn rejects_invalid_mac_addresses() {
        assert!(!valid_mac_address([0; 6]));
        assert!(!valid_mac_address([u8::MAX; 6]));
        assert!(valid_mac_address([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    }
}
