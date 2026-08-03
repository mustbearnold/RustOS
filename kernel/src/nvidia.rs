use crate::pci::{
    MmioRegion, PciAddress, PciBar, PciDevice, PciDeviceResources, PciInventory, PciResourceError,
};

pub const NVIDIA_VENDOR_ID: u16 = 0x10de;
pub const RTX_5070_DEVICE_ID: u16 = 0x2f04;
pub const NVIDIA_PROBE_MMIO_LENGTH: u64 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvidiaArchitecture {
    Blackwell,
    Unknown,
}

impl NvidiaArchitecture {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Blackwell => "blackwell",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvidiaError {
    Resources(PciResourceError),
    MemorySpaceDisabled,
    MissingBar0,
}

impl From<PciResourceError> for NvidiaError {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvidiaProbe {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision_id: u8,
    pub architecture: NvidiaArchitecture,
    pub bar0_base: u64,
    pub bar1_base: Option<u64>,
    pub bar3_base: Option<u64>,
    pub bar5_io_base: Option<u64>,
    pub mmio_base: u64,
    pub mmio_length: u64,
    pub memory_space_enabled: bool,
    pub bus_master_enabled: bool,
    pub msi: bool,
    pub msix: bool,
    pub bar0_mapped: bool,
}

impl NvidiaProbe {
    fn from_device(device: PciDevice, bar0: MmioRegion) -> Result<Self, NvidiaError> {
        Self::from_device_mapping(device, bar0.physical_base(), bar0.length(), true)
    }

    fn from_device_mapping(
        device: PciDevice,
        mmio_base: u64,
        mmio_length: u64,
        bar0_mapped: bool,
    ) -> Result<Self, NvidiaError> {
        let Some(bar0_base) = memory_bar_base(device.bars[0]) else {
            return Err(NvidiaError::MissingBar0);
        };
        Ok(Self {
            address: device.address,
            vendor_id: device.vendor_id,
            device_id: device.device_id,
            revision_id: device.revision_id,
            architecture: architecture_for(device.device_id),
            bar0_base,
            bar1_base: memory_bar_base(device.bars[1]),
            bar3_base: memory_bar_base(device.bars[3]),
            bar5_io_base: io_bar_base(device.bars[5]),
            mmio_base,
            mmio_length,
            memory_space_enabled: device.memory_space_enabled(),
            bus_master_enabled: device.bus_master_enabled(),
            msi: device.capabilities.msi.is_some(),
            msix: device.capabilities.msix.is_some(),
            bar0_mapped,
        })
    }
}

pub fn initialize(
    inventory: &PciInventory,
    physical_memory_offset: u64,
) -> Result<Option<NvidiaProbe>, NvidiaError> {
    let Some(device) = find_device(inventory) else {
        return Ok(None);
    };
    if !device.memory_space_enabled() {
        return Err(NvidiaError::MemorySpaceDisabled);
    }
    if memory_bar_base(device.bars[0]).is_none() {
        return Err(NvidiaError::MissingBar0);
    }

    let mut resources = PciDeviceResources::new(device, physical_memory_offset);
    let bar0 = resources.claim_mmio(0, NVIDIA_PROBE_MMIO_LENGTH)?;
    NvidiaProbe::from_device(resources.device(), bar0).map(Some)
}

fn find_device(inventory: &PciInventory) -> Option<PciDevice> {
    inventory
        .devices()
        .iter()
        .copied()
        .find(|device| is_supported_device(*device))
}

pub fn is_supported_device(device: PciDevice) -> bool {
    device.vendor_id == NVIDIA_VENDOR_ID
        && device.device_id == RTX_5070_DEVICE_ID
        && device.class_code == 0x03
}

fn architecture_for(device_id: u16) -> NvidiaArchitecture {
    match device_id {
        RTX_5070_DEVICE_ID => NvidiaArchitecture::Blackwell,
        _ => NvidiaArchitecture::Unknown,
    }
}

fn memory_bar_base(bar: PciBar) -> Option<u64> {
    match bar {
        PciBar::Memory32 { base, .. } => Some(u64::from(base)),
        PciBar::Memory64 { base, .. } => Some(base),
        _ => None,
    }
}

fn io_bar_base(bar: PciBar) -> Option<u64> {
    match bar {
        PciBar::Io { base } => Some(u64::from(base)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::PciCapabilities;

    fn device(device_id: u16, bars: [PciBar; 6]) -> PciDevice {
        PciDevice {
            address: PciAddress::new(0x0b, 0, 0),
            vendor_id: NVIDIA_VENDOR_ID,
            device_id,
            revision_id: 0xa1,
            prog_if: 0,
            command: (1 << 1) | (1 << 2),
            status: 1 << 4,
            subclass: 0,
            class_code: 0x03,
            header_type: 0,
            interrupt_line: 0,
            interrupt_pin: 2,
            bars,
            capabilities: PciCapabilities {
                msi: None,
                msix: None,
                virtio: [None; 5],
            },
        }
    }

    #[test]
    fn recognizes_the_rtx_5070_blackwell_device() {
        let device = device(
            RTX_5070_DEVICE_ID,
            [
                PciBar::Memory32 {
                    base: 0xf800_0000,
                    prefetchable: false,
                },
                PciBar::Memory64 {
                    base: 0x7800_0000_00,
                    prefetchable: true,
                },
                PciBar::UpperHalf,
                PciBar::Memory64 {
                    base: 0x7c00_0000_00,
                    prefetchable: true,
                },
                PciBar::UpperHalf,
                PciBar::Io { base: 0xf000 },
            ],
        );

        assert!(is_supported_device(device));
        assert_eq!(
            architecture_for(device.device_id),
            NvidiaArchitecture::Blackwell
        );
        let bar0 = memory_bar_base(device.bars[0]);
        assert_eq!(bar0, Some(0xf800_0000));
        assert_eq!(memory_bar_base(device.bars[1]), Some(0x7800_0000_00));
        assert_eq!(memory_bar_base(device.bars[3]), Some(0x7c00_0000_00));
        assert_eq!(io_bar_base(device.bars[5]), Some(0xf000));
    }

    #[test]
    fn rejects_other_display_devices() {
        let device = device(0x1234, [PciBar::Unassigned; 6]);
        assert!(!is_supported_device(device));
    }

    #[test]
    fn probe_snapshot_preserves_pci_capability_state() {
        let mut device = device(
            RTX_5070_DEVICE_ID,
            [
                PciBar::Memory32 {
                    base: 0xf800_0000,
                    prefetchable: false,
                },
                PciBar::Unassigned,
                PciBar::Unassigned,
                PciBar::Unassigned,
                PciBar::Unassigned,
                PciBar::Unassigned,
            ],
        );
        device.capabilities = PciCapabilities {
            msi: Some(crate::pci::PciMsiCapability {
                offset: 0x50,
                is_64_bit: true,
                multiple_message_capable: 0,
                per_vector_masking: false,
            }),
            msix: Some(crate::pci::PciMsixCapability {
                offset: 0x60,
                table_size: 8,
                function_masked: false,
                table_bar: 0,
                table_offset: 0,
                pba_bar: 0,
                pba_offset: 0x100,
            }),
            virtio: [None; 5],
        };
        let probe =
            NvidiaProbe::from_device_mapping(device, 0xf800_0000, NVIDIA_PROBE_MMIO_LENGTH, true)
                .expect("probe");
        assert_eq!(probe.address, PciAddress::new(0x0b, 0, 0));
        assert_eq!(probe.mmio_base, 0xf800_0000);
        assert_eq!(probe.mmio_length, NVIDIA_PROBE_MMIO_LENGTH);
        assert!(probe.memory_space_enabled);
        assert!(probe.bus_master_enabled);
        assert!(probe.msi);
        assert!(probe.msix);
        assert!(probe.bar0_mapped);
    }
}
