use crate::pci::{
    MmioError, MmioRegion, PciAddress, PciBar, PciDevice, PciDeviceResources, PciInventory,
    PciResourceError,
};

pub const GSP_RPC_PAGE_SIZE: usize = rustos_gpu_protocol::NVIDIA_GSP_PAGE_SIZE;
pub const GSP_RPC_MAX_MESSAGE_PAGES: usize = rustos_gpu_protocol::NVIDIA_GSP_MAX_MESSAGE_PAGES;
pub const GSP_SHARED_MEMORY_BYTES: usize =
    rustos_gpu_protocol::GspSharedMemoryLayout::standard().total_bytes;
pub const GSP_SHARED_MEMORY_PTES: usize =
    rustos_gpu_protocol::GspSharedMemoryLayout::standard().page_table_entry_count;
pub const GSP_QUEUE_ENTRY_COUNT: usize =
    rustos_gpu_protocol::GspSharedMemoryLayout::standard().queue_entry_count;

pub const NVIDIA_VENDOR_ID: u16 = 0x10de;
pub const RTX_5070_DEVICE_ID: u16 = 0x2f04;
pub const NVIDIA_PROBE_MMIO_LENGTH: u64 = rustos_gpu_protocol::NVIDIA_GSP_FSP_BAR0_REQUIRED_LENGTH;
#[allow(dead_code)]
const NVIDIA_GSP_FSP_POLL_SPINS: usize = 10_000_000;

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
#[allow(dead_code)]
pub enum NvidiaError {
    Resources(PciResourceError),
    Mmio(MmioError),
    MemorySpaceDisabled,
    MissingBar0,
    FspPacketEmpty,
    FspPacketUnaligned { size: usize },
    FspPacketTooLarge { size: usize },
    FspQueuePointerInvalid { head: u32, tail: u32 },
    FspQueueTimeout,
    FspResponseTimeout,
    FspResponseBufferTooSmall { required: usize, actual: usize },
    FspResponse(rustos_gpu_protocol::GspFspResponseError),
}

impl From<PciResourceError> for NvidiaError {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

impl From<MmioError> for NvidiaError {
    fn from(error: MmioError) -> Self {
        Self::Mmio(error)
    }
}

impl From<rustos_gpu_protocol::GspFspResponseError> for NvidiaError {
    fn from(error: rustos_gpu_protocol::GspFspResponseError) -> Self {
        Self::FspResponse(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvidiaFspSnapshot {
    pub secure_boot_status: u32,
    pub queue_head: u32,
    pub queue_tail: u32,
    pub message_queue_head: u32,
    pub message_queue_tail: u32,
    pub mailbox0: u32,
    pub mailbox1: u32,
    pub riscv_lockdown: bool,
}

impl NvidiaFspSnapshot {
    const fn unavailable() -> Self {
        Self {
            secure_boot_status: 0,
            queue_head: 0,
            queue_tail: 0,
            message_queue_head: 0,
            message_queue_tail: 0,
            mailbox0: 0,
            mailbox1: 0,
            riscv_lockdown: true,
        }
    }

    fn read(mmio: MmioRegion) -> Result<Self, NvidiaError> {
        let hwcfg2 = mmio.read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_FALCON_HWCFG2))?;
        Ok(Self {
            secure_boot_status: mmio.read_u32(0x0002_00bc)?,
            queue_head: mmio.read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_QUEUE_HEAD))?,
            queue_tail: mmio.read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_QUEUE_TAIL))?,
            message_queue_head: mmio
                .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_HEAD))?,
            message_queue_tail: mmio
                .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_TAIL))?,
            mailbox0: mmio.read_u32(u64::from(
                rustos_gpu_protocol::NVIDIA_GSP_FSP_FALCON_MAILBOX0,
            ))?,
            mailbox1: mmio.read_u32(u64::from(
                rustos_gpu_protocol::NVIDIA_GSP_FSP_FALCON_MAILBOX1,
            ))?,
            riscv_lockdown: hwcfg2
                & (1 << rustos_gpu_protocol::NVIDIA_GSP_FSP_FALCON_HWCFG2_LOCKDOWN_BIT)
                != 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct NvidiaFspTransport {
    mmio: MmioRegion,
}

#[allow(dead_code)]
impl NvidiaFspTransport {
    // Deliberately opt-in: probing must remain read-only until firmware staging is complete.
    fn new(mmio: MmioRegion) -> Self {
        Self { mmio }
    }

    pub fn send(&self, packet: &[u8]) -> Result<(), NvidiaError> {
        validate_packet(packet)?;
        for _ in 0..NVIDIA_GSP_FSP_POLL_SPINS {
            let head = self
                .mmio
                .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_QUEUE_HEAD))?;
            let tail = self
                .mmio
                .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_QUEUE_TAIL))?;
            if head == tail {
                self.write_emem(packet)?;
                self.mmio.write_u32(
                    u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_QUEUE_TAIL),
                    u32::try_from(packet.len() - core::mem::size_of::<u32>())
                        .map_err(|_| NvidiaError::FspPacketTooLarge { size: packet.len() })?,
                )?;
                self.mmio
                    .write_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_QUEUE_HEAD), 0)?;
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(NvidiaError::FspQueueTimeout)
    }

    pub fn try_receive(&self, buffer: &mut [u8]) -> Result<Option<usize>, NvidiaError> {
        let head = self
            .mmio
            .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_HEAD))?;
        let tail = self
            .mmio
            .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_TAIL))?;
        if head == tail {
            return Ok(None);
        }
        let packet_size = tail
            .checked_sub(head)
            .and_then(|size| size.checked_add(4))
            .ok_or(NvidiaError::FspQueuePointerInvalid { head, tail })?;
        if packet_size % 4 != 0 {
            return Err(NvidiaError::FspQueuePointerInvalid { head, tail });
        }
        let packet_size =
            usize::try_from(packet_size).map_err(|_| NvidiaError::FspResponseBufferTooSmall {
                required: usize::MAX,
                actual: buffer.len(),
            })?;
        if packet_size > buffer.len() {
            return Err(NvidiaError::FspResponseBufferTooSmall {
                required: packet_size,
                actual: buffer.len(),
            });
        }
        self.read_emem(&mut buffer[..packet_size])?;
        self.mmio
            .write_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_TAIL), 0)?;
        self.mmio
            .write_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_HEAD), 0)?;
        Ok(Some(packet_size))
    }

    pub fn send_sync(
        &self,
        command_nvdm_type: u32,
        packet: &[u8],
    ) -> Result<rustos_gpu_protocol::GspFspResponse, NvidiaError> {
        self.send(packet)?;
        let mut response = [0u8; rustos_gpu_protocol::NVIDIA_GSP_FSP_RESPONSE_PACKET_SIZE];
        for _ in 0..NVIDIA_GSP_FSP_POLL_SPINS {
            if let Some(size) = self.try_receive(&mut response)? {
                return rustos_gpu_protocol::GspFspResponse::parse(
                    &response[..size],
                    command_nvdm_type,
                )
                .map_err(NvidiaError::from);
            }
            core::hint::spin_loop();
        }
        Err(NvidiaError::FspResponseTimeout)
    }

    fn write_emem(&self, packet: &[u8]) -> Result<(), NvidiaError> {
        let mut offset = 0usize;
        while offset < packet.len() {
            let chunk_size = core::cmp::min(
                rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_MAX_BYTES,
                packet.len() - offset,
            );
            let emem_offset = u32::try_from(offset)
                .map_err(|_| NvidiaError::FspPacketTooLarge { size: packet.len() })?;
            self.mmio.write_u32(
                u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_ADDRESS),
                rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_WRITE_BIT | emem_offset,
            )?;
            for word_offset in (0..chunk_size).step_by(4) {
                let word_start = offset + word_offset;
                let word = u32::from_le_bytes([
                    packet[word_start],
                    packet[word_start + 1],
                    packet[word_start + 2],
                    packet[word_start + 3],
                ]);
                self.mmio.write_u32(
                    u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_DATA),
                    word,
                )?;
            }
            offset += chunk_size;
        }
        Ok(())
    }

    fn read_emem(&self, packet: &mut [u8]) -> Result<(), NvidiaError> {
        let mut offset = 0usize;
        while offset < packet.len() {
            let chunk_size = core::cmp::min(
                rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_MAX_BYTES,
                packet.len() - offset,
            );
            let emem_offset =
                u32::try_from(offset).map_err(|_| NvidiaError::FspResponseBufferTooSmall {
                    required: packet.len(),
                    actual: 0,
                })?;
            self.mmio.write_u32(
                u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_ADDRESS),
                rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_READ_BIT | emem_offset,
            )?;
            for word_offset in (0..chunk_size).step_by(4) {
                let word = self
                    .mmio
                    .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_DATA))?;
                packet[offset + word_offset..offset + word_offset + 4]
                    .copy_from_slice(&word.to_le_bytes());
            }
            offset += chunk_size;
        }
        Ok(())
    }
}

#[allow(dead_code)]
fn validate_packet(packet: &[u8]) -> Result<(), NvidiaError> {
    if packet.is_empty() {
        return Err(NvidiaError::FspPacketEmpty);
    }
    if packet.len() % core::mem::size_of::<u32>() != 0 {
        return Err(NvidiaError::FspPacketUnaligned { size: packet.len() });
    }
    if packet.len() > u32::MAX as usize {
        return Err(NvidiaError::FspPacketTooLarge { size: packet.len() });
    }
    Ok(())
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
    pub fsp: NvidiaFspSnapshot,
    bar0: Option<MmioRegion>,
}

impl NvidiaProbe {
    fn from_device(device: PciDevice, bar0: MmioRegion) -> Result<Self, NvidiaError> {
        let mut probe =
            Self::from_device_mapping(device, bar0.physical_base(), bar0.length(), true)?;
        probe.fsp = NvidiaFspSnapshot::read(bar0)?;
        probe.bar0 = Some(bar0);
        Ok(probe)
    }

    pub fn fsp_transport(&self) -> Option<NvidiaFspTransport> {
        self.bar0.map(NvidiaFspTransport::new)
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
            fsp: NvidiaFspSnapshot::unavailable(),
            bar0: None,
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
    use alloc::vec;

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
        assert!(probe.fsp_transport().is_none());
    }

    #[test]
    fn validates_fsp_transport_packet_alignment() {
        assert_eq!(validate_packet(&[]), Err(NvidiaError::FspPacketEmpty));
        assert_eq!(
            validate_packet(&[0; 3]),
            Err(NvidiaError::FspPacketUnaligned { size: 3 })
        );
        assert_eq!(validate_packet(&[0; 4]), Ok(()));
    }

    #[test]
    fn sends_fsp_packet_in_emem_chunks_and_updates_queue() {
        let mut mmio_bytes = vec![0u8; NVIDIA_PROBE_MMIO_LENGTH as usize];
        let mmio = MmioRegion::for_test(mmio_bytes.as_mut_ptr() as u64, NVIDIA_PROBE_MMIO_LENGTH);
        let transport = NvidiaFspTransport::new(mmio);
        let packet = [0xa5u8; rustos_gpu_protocol::NVIDIA_GSP_FSP_COT_PACKET_SIZE];

        transport.send(&packet).expect("FSP packet");

        let read_u32 = |offset: u32| {
            u32::from_le_bytes(
                mmio_bytes[offset as usize..offset as usize + 4]
                    .try_into()
                    .expect("u32"),
            )
        };
        assert_eq!(
            read_u32(rustos_gpu_protocol::NVIDIA_GSP_FSP_QUEUE_TAIL),
            (packet.len() - 4) as u32
        );
        assert_eq!(read_u32(rustos_gpu_protocol::NVIDIA_GSP_FSP_QUEUE_HEAD), 0);
        assert_eq!(
            read_u32(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_ADDRESS),
            rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_WRITE_BIT | 768
        );
        assert_eq!(
            read_u32(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_DATA),
            u32::from_le_bytes(packet[864..868].try_into().expect("last word"))
        );
    }
}
