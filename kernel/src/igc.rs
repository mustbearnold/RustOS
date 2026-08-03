use bootloader_api::info::MemoryRegion;
use core::sync::atomic::{AtomicU16, Ordering, fence};
#[cfg(target_os = "none")]
use spin::Mutex;

use crate::dhcp::{
    self, DHCP_ACK, DHCP_CLIENT_PORT, DHCP_MESSAGE_BUFFER_LENGTH, DHCP_OFFER, DHCP_SERVER_PORT,
};
use crate::memory::{FrameAllocator, PAGE_SIZE};
use crate::net::{
    EthernetFrame, EthernetFrameError, Ipv4PacketError, NetworkInterface, UdpDatagramError,
};
use crate::pci::{
    MmioError, MmioRegion, PciDevice, PciDeviceResources, PciInterruptMode, PciInventory,
    PciResourceError,
};
#[cfg(target_os = "none")]
use crate::pci::{PciMsiRoute, PciMsixRoute};

const INTEL_VENDOR_ID: u16 = 0x8086;
pub const I225_V_DEVICE_ID: u16 = 0x15f3;
pub const I225_MMIO_LENGTH: u64 = 0x10_0000;

const REG_STATUS: u64 = 0x0008;
const REG_CTRL: u64 = 0x0000;
const REG_ICR: u64 = 0x1500;
const REG_IMS: u64 = 0x1508;
const REG_IMC: u64 = 0x150c;
const REG_RCTL: u64 = 0x0100;
const REG_TCTL: u64 = 0x0400;
const REG_SRRCTL0: u64 = 0x0c00c;
const REG_RDBAL0: u64 = 0x0c000;
const REG_RDBAH0: u64 = 0x0c004;
const REG_RDLEN0: u64 = 0x0c008;
const REG_RDH0: u64 = 0x0c010;
const REG_RDT0: u64 = 0x0c018;
const REG_RXDCTL0: u64 = 0x0c028;
const REG_TDBAL0: u64 = 0x0e000;
const REG_TDBAH0: u64 = 0x0e004;
const REG_TDLEN0: u64 = 0x0e008;
const REG_TDH0: u64 = 0x0e010;
const REG_TDT0: u64 = 0x0e018;
const REG_TXDCTL0: u64 = 0x0e028;
const REG_RAL0: u64 = 0x5400;
const REG_RAH0: u64 = 0x5404;

const STATUS_FULL_DUPLEX: u32 = 1 << 0;
const STATUS_LINK_UP: u32 = 1 << 1;
const STATUS_SPEED_100: u32 = 1 << 6;
const STATUS_SPEED_1000: u32 = 1 << 7;
const STATUS_SPEED_2500: u32 = 1 << 22;

const IGC_CTRL_SLU: u32 = 1 << 6;
const IGC_CTRL_FRCSPD: u32 = 1 << 11;
const IGC_CTRL_FRCDPX: u32 = 1 << 12;
const IGC_CTRL_RST: u32 = 1 << 26;
const IGC_RAH_AV: u32 = 1 << 31;
const IGC_RCTL_ENABLE: u32 = 1 << 1;
const IGC_RCTL_BROADCAST_ACCEPT: u32 = 1 << 15;
const IGC_RCTL_LONG_PACKET_ENABLE: u32 = 1 << 5;
const IGC_RCTL_STRIP_CRC: u32 = 1 << 26;
const IGC_TCTL_ENABLE: u32 = 1 << 1;
const IGC_TCTL_PAD_SHORT_PACKETS: u32 = 1 << 3;
const IGC_TCTL_COLLISION_THRESHOLD: u32 = 15 << 4;
const IGC_TCTL_RETRANSMIT_LATE_COLLISION: u32 = 1 << 24;
const IGC_RXDCTL_QUEUE_ENABLE: u32 = 1 << 25;
const IGC_TXDCTL_QUEUE_ENABLE: u32 = 1 << 25;
const IGC_RXDCTL_PTHRESH: u32 = 8;
const IGC_RXDCTL_HTHRESH: u32 = 8 << 8;
const IGC_RXDCTL_WTHRESH: u32 = 4 << 16;
const IGC_TXDCTL_PTHRESH: u32 = 8;
const IGC_TXDCTL_HTHRESH: u32 = 1 << 8;
const IGC_TXDCTL_WTHRESH: u32 = 16 << 16;

const TX_RING_SIZE: usize = 8;
const RX_RING_SIZE: usize = 8;
const DESCRIPTOR_SIZE: u64 = 16;
const RX_BUFFER_SIZE: usize = 2048;
const POLL_SPINS: usize = 1_000_000;

const TX_DESCRIPTOR_DATA_TYPE: u32 = 0x0030_0000;
const TX_DESCRIPTOR_END_OF_PACKET: u32 = 0x0100_0000;
const TX_DESCRIPTOR_INSERT_FCS: u32 = 0x0200_0000;
const TX_DESCRIPTOR_REPORT_STATUS: u32 = 0x0800_0000;
const TX_DESCRIPTOR_EXTENSION: u32 = 0x2000_0000;
const TX_DESCRIPTOR_DONE: u32 = 1;
const TX_PAYLOAD_LENGTH_SHIFT: u32 = 14;
const RX_DESCRIPTOR_DONE: u32 = 0x01;
const RX_DESCRIPTOR_END_OF_PACKET: u32 = 0x02;
const RX_DESCRIPTOR_ERROR_MASK: u32 = 0x8000_0000;
const RX_DESCRIPTOR_TYPE_ONE_BUFFER: u32 = 1 << 25;
const RX_DESCRIPTOR_PACKET_BUFFER_2048: u32 = (RX_BUFFER_SIZE as u32) / 1024;

const DEFAULT_NETWORK_SUBNET_MASK: crate::net::Ipv4Address = [255, 255, 255, 0];
const DEFAULT_NETWORK_GATEWAY: crate::net::Ipv4Address = [10, 0, 2, 2];
const DEFAULT_NETWORK_DNS: crate::net::Ipv4Address = [10, 0, 2, 3];
const DHCP_ZERO_IP: crate::net::Ipv4Address = [0, 0, 0, 0];
const DHCP_BROADCAST_IP: crate::net::Ipv4Address = [255, 255, 255, 255];
const ETHERNET_BROADCAST: [u8; 6] = [u8::MAX; 6];
const NETWORK_SOURCE_PORT: u16 = 49_000;
const NETWORK_RECEIVE_HEADER_LENGTH: usize = 6;
const MAX_NETWORK_PAYLOAD_LENGTH: usize = 1024;

const IGC_INTERRUPT_TXDW: u32 = 1 << 0;
const IGC_INTERRUPT_RXT0: u32 = 1 << 7;
const IGC_INTERRUPT_LSC: u32 = 1 << 2;
const IGC_INTERRUPT_MASK: u32 = IGC_INTERRUPT_TXDW | IGC_INTERRUPT_RXT0 | IGC_INTERRUPT_LSC;

const NETWORK_INTERFACE_NAME: &str = "igc0";

#[cfg(target_os = "none")]
static IGC_INTERRUPT_MMIO: Mutex<Option<MmioRegion>> = Mutex::new(None);
static IGC_INTERRUPT_CAUSE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static IGC_INTERRUPT_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static NETWORK_IDENTIFICATION: AtomicU16 = AtomicU16::new(0x2250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgcError {
    Resources(PciResourceError),
    Mmio(MmioError),
    Dma(IgcDmaError),
    Frame(EthernetFrameError),
    Ipv4(Ipv4PacketError),
    Udp(UdpDatagramError),
    Dhcp(crate::dhcp::DhcpError),
    MemorySpaceDisabled,
    InvalidMac,
    ResetTimeout {
        control: u32,
    },
    TxRingFull,
    TxCompletionTimeout {
        descriptor: usize,
        status: u32,
    },
    RxFrameTooLarge {
        length: u16,
    },
    RxPacketNotSingleDescriptor {
        status: u32,
    },
    RxError {
        status: u32,
    },
    NoPacket,
    #[cfg(target_os = "none")]
    InterruptsNotPrepared,
    InterruptTimeout {
        cause: u32,
        rctl: u32,
        tdh: u32,
        rdh: u32,
        rdt: u32,
    },
    ExternalNetworkNotEnabled,
    NetworkBufferTooSmall {
        required: usize,
        available: usize,
    },
    #[cfg(target_os = "none")]
    InterruptRegistration(crate::interrupts::DeviceInterruptError),
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

impl From<IgcDmaError> for IgcError {
    fn from(error: IgcDmaError) -> Self {
        Self::Dma(error)
    }
}

impl From<EthernetFrameError> for IgcError {
    fn from(error: EthernetFrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<Ipv4PacketError> for IgcError {
    fn from(error: Ipv4PacketError) -> Self {
        Self::Ipv4(error)
    }
}

impl From<UdpDatagramError> for IgcError {
    fn from(error: UdpDatagramError) -> Self {
        Self::Udp(error)
    }
}

impl From<crate::dhcp::DhcpError> for IgcError {
    fn from(error: crate::dhcp::DhcpError) -> Self {
        Self::Dhcp(error)
    }
}

#[cfg(target_os = "none")]
impl From<crate::interrupts::DeviceInterruptError> for IgcError {
    fn from(error: crate::interrupts::DeviceInterruptError) -> Self {
        Self::InterruptRegistration(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgcDmaError {
    NoFrame,
    AddressOverflow,
    Unaligned { offset: u64, alignment: u64 },
    OutOfBounds { offset: u64, size: u64 },
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
    pub tx_queue_ready: bool,
    pub rx_queue_ready: bool,
    pub interrupt_ready: bool,
}

impl I225Probe {
    fn from_device(
        device: PciDevice,
        mmio: MmioRegion,
        status: u32,
        mac_address: [u8; 6],
        tx_queue_ready: bool,
        rx_queue_ready: bool,
        interrupt_ready: bool,
    ) -> Self {
        Self {
            address: device.address,
            mmio_base: mmio.physical_base(),
            status,
            mac_address,
            link: LinkStatus::from_register(status),
            bus_master_enabled: device.bus_master_enabled(),
            tx_queue_ready,
            rx_queue_ready,
            interrupt_ready,
        }
    }
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

    Ok(Some(I225Probe::from_device(
        device,
        mmio,
        status,
        mac_address,
        false,
        false,
        false,
    )))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IgcInitFailure {
    pub error: IgcError,
    pub next_frame_address: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkConfiguration {
    pub address: crate::net::Ipv4Address,
    pub subnet_mask: crate::net::Ipv4Address,
    pub gateway: crate::net::Ipv4Address,
    pub dns: crate::net::Ipv4Address,
    pub dhcp_server: crate::net::Ipv4Address,
    pub lease_seconds: u32,
    pub dhcp: bool,
}

impl NetworkConfiguration {
    const fn static_default() -> Self {
        Self {
            address: DHCP_ZERO_IP,
            subnet_mask: DEFAULT_NETWORK_SUBNET_MASK,
            gateway: DEFAULT_NETWORK_GATEWAY,
            dns: DEFAULT_NETWORK_DNS,
            dhcp_server: DEFAULT_NETWORK_GATEWAY,
            lease_seconds: 0,
            dhcp: false,
        }
    }
}

#[derive(Debug)]
pub struct IgcRuntime {
    pub address: crate::pci::PciAddress,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub mmio_base: u64,
    pub mmio_length: u64,
    pub control: u32,
    pub status: u32,
    pub bus_master_enabled: bool,
    pub mac_address: [u8; 6],
    pub tx_queue_ready: bool,
    pub rx_queue_ready: bool,
    pub tx_completed: bool,
    pub tx_frames: u64,
    pub rx_frames: u64,
    pub rx_packet_length: u16,
    pub failure: Option<IgcError>,
    pub interrupt_gsi: Option<u32>,
    pub interrupt_vector: Option<u8>,
    pub interrupt_mode: PciInterruptMode,
    pub interrupt_count: u64,
    pub interrupt_cause: u32,
    pub interrupt_driven: bool,
    pub external_network: bool,
    pub network: NetworkConfiguration,
    next_frame_address: Option<u64>,
    pci_resources: PciDeviceResources,
    mmio: MmioRegion,
    tx_ring: DmaPage,
    rx_ring: DmaPage,
    tx_buffer: DmaPage,
    rx_buffers: [DmaPage; RX_RING_SIZE],
    tx_next_index: usize,
    rx_next_index: usize,
    pending_interrupt_cause: u32,
    gateway_mac: Option<[u8; 6]>,
    external_receive_diagnostics: u8,
}

impl IgcRuntime {
    pub const fn interface_name() -> &'static str {
        NETWORK_INTERFACE_NAME
    }

    pub fn next_frame_address(&self) -> Option<u64> {
        self.next_frame_address
    }

    pub fn is_ready(&self) -> bool {
        self.failure.is_none() && self.tx_queue_ready && self.rx_queue_ready
    }

    pub fn probe_snapshot(&self) -> I225Probe {
        I225Probe::from_device(
            self.pci_resources.device(),
            self.mmio,
            self.status,
            self.mac_address,
            self.tx_queue_ready,
            self.rx_queue_ready,
            self.interrupt_driven,
        )
    }

    #[cfg(target_os = "none")]
    pub fn prepare_interrupts(&mut self) -> Result<u8, IgcError> {
        if let Some(vector) = self.interrupt_vector {
            return Ok(vector);
        }

        let vector = crate::interrupts::register_device_handler(igc_interrupt_handler)
            .map_err(IgcError::InterruptRegistration)?;
        *IGC_INTERRUPT_MMIO.lock() = Some(self.mmio);
        let _ = self.mmio.read_u32(REG_ICR)?;
        IGC_INTERRUPT_CAUSE.store(0, Ordering::SeqCst);
        IGC_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        self.interrupt_vector = Some(vector);
        Ok(vector)
    }

    #[cfg(target_os = "none")]
    pub fn enable_msi(&mut self, destination_apic_id: u32) -> Result<PciMsiRoute, IgcError> {
        let vector = self
            .interrupt_vector
            .ok_or(IgcError::InterruptsNotPrepared)?;
        self.pci_resources
            .enable_msi(vector, destination_apic_id)
            .map_err(Into::into)
    }

    #[cfg(target_os = "none")]
    pub fn enable_msix(&mut self, destination_apic_id: u32) -> Result<PciMsixRoute, IgcError> {
        let vector = self
            .interrupt_vector
            .ok_or(IgcError::InterruptsNotPrepared)?;
        self.pci_resources
            .enable_msix(vector, destination_apic_id)
            .map_err(Into::into)
    }

    #[cfg(target_os = "none")]
    pub fn arm_interrupts(&mut self, gsi: u32) -> Result<(), IgcError> {
        self.arm_interrupts_with_mode(PciInterruptMode::Legacy, Some(gsi))
    }

    #[cfg(target_os = "none")]
    pub fn arm_msi_interrupts(&mut self, route: PciMsiRoute) -> Result<(), IgcError> {
        if self.interrupt_vector != Some(route.vector) {
            return Err(IgcError::InterruptsNotPrepared);
        }
        self.arm_interrupts_with_mode(PciInterruptMode::Msi, None)
    }

    #[cfg(target_os = "none")]
    pub fn arm_msix_interrupts(&mut self, route: PciMsixRoute) -> Result<(), IgcError> {
        if self.interrupt_vector != Some(route.vector) {
            return Err(IgcError::InterruptsNotPrepared);
        }
        self.arm_interrupts_with_mode(PciInterruptMode::Msix, None)
    }

    #[cfg(target_os = "none")]
    fn arm_interrupts_with_mode(
        &mut self,
        mode: PciInterruptMode,
        gsi: Option<u32>,
    ) -> Result<(), IgcError> {
        if self.interrupt_vector.is_none() {
            return Err(IgcError::InterruptsNotPrepared);
        }
        if self.interrupt_driven {
            return Ok(());
        }

        self.mmio.write_u32(REG_IMC, u32::MAX)?;
        let _ = self.mmio.read_u32(REG_ICR)?;
        IGC_INTERRUPT_CAUSE.store(0, Ordering::SeqCst);
        IGC_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        self.pending_interrupt_cause = 0;
        self.mmio.write_u32(REG_IMS, IGC_INTERRUPT_MASK)?;
        self.interrupt_gsi = gsi;
        self.interrupt_mode = mode;
        self.interrupt_driven = true;
        Ok(())
    }

    pub fn sync_interrupt_state(&mut self) {
        self.pending_interrupt_cause |= IGC_INTERRUPT_CAUSE.swap(0, Ordering::SeqCst);
        self.interrupt_cause |= self.pending_interrupt_cause;
        self.interrupt_count = IGC_INTERRUPT_COUNT.load(Ordering::SeqCst);
    }

    pub fn enable_external_network(&mut self) -> Result<(), IgcError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if !self.interrupt_driven {
            return Err(IgcError::ExternalNetworkNotEnabled);
        }
        self.status = self.mmio.read_u32(REG_STATUS)?;
        self.external_network = true;
        self.gateway_mac = None;
        self.external_receive_diagnostics = 0;
        self.network = NetworkConfiguration::static_default();
        Ok(())
    }

    pub fn acquire_dhcp(&mut self) -> Result<NetworkConfiguration, IgcError> {
        if !self.external_network {
            return Err(IgcError::ExternalNetworkNotEnabled);
        }

        let transaction_id = 0x5255_5354u32
            .wrapping_add(NETWORK_IDENTIFICATION.fetch_add(1, Ordering::AcqRel) as u32);
        for _attempt in 0..3 {
            let (discover, discover_length) =
                dhcp::build_discover(transaction_id, self.mac_address);
            self.transmit_dhcp(&discover[..discover_length])?;
            let Ok(offer) = self.receive_dhcp_reply(transaction_id, DHCP_OFFER) else {
                continue;
            };
            let Some(server) = offer.server else {
                continue;
            };

            let (request, request_length) =
                dhcp::build_request(transaction_id, self.mac_address, offer.address, server);
            self.transmit_dhcp(&request[..request_length])?;
            let Ok(ack) = self.receive_dhcp_reply(transaction_id, DHCP_ACK) else {
                continue;
            };
            if ack.address != offer.address {
                continue;
            }

            let configuration = NetworkConfiguration {
                address: ack.address,
                subnet_mask: ack.subnet_mask.unwrap_or(DEFAULT_NETWORK_SUBNET_MASK),
                gateway: ack.gateway.unwrap_or(DEFAULT_NETWORK_GATEWAY),
                dns: ack.dns.unwrap_or(DEFAULT_NETWORK_DNS),
                dhcp_server: ack.server.unwrap_or(server),
                lease_seconds: ack.lease_seconds.unwrap_or(0),
                dhcp: true,
            };
            self.network = configuration;
            self.gateway_mac = None;
            return Ok(configuration);
        }
        Err(IgcError::NoPacket)
    }

    pub fn renew_dhcp(&mut self) -> Result<NetworkConfiguration, IgcError> {
        if !self.external_network {
            return Err(IgcError::ExternalNetworkNotEnabled);
        }
        if !self.network.dhcp {
            return Err(IgcError::NoPacket);
        }

        let transaction_id = 0x5255_5354u32
            .wrapping_add(NETWORK_IDENTIFICATION.fetch_add(1, Ordering::AcqRel) as u32);
        let (request, request_length) =
            dhcp::build_renew_request(transaction_id, self.mac_address, self.network.address);
        self.transmit_dhcp_renewal(&request[..request_length])?;
        let ack = self.receive_dhcp_reply(transaction_id, DHCP_ACK)?;
        if ack.address != self.network.address {
            return Err(IgcError::NoPacket);
        }

        let previous = self.network;
        let configuration = NetworkConfiguration {
            address: previous.address,
            subnet_mask: ack.subnet_mask.unwrap_or(previous.subnet_mask),
            gateway: ack.gateway.unwrap_or(previous.gateway),
            dns: ack.dns.unwrap_or(previous.dns),
            dhcp_server: ack.server.unwrap_or(previous.dhcp_server),
            lease_seconds: ack.lease_seconds.unwrap_or(previous.lease_seconds),
            dhcp: true,
        };
        self.network = configuration;
        self.gateway_mac = None;
        Ok(configuration)
    }

    fn transmit_dhcp(&mut self, payload: &[u8]) -> Result<(), IgcError> {
        if payload.len() > DHCP_MESSAGE_BUFFER_LENGTH {
            return Err(IgcError::NetworkBufferTooSmall {
                required: payload.len(),
                available: DHCP_MESSAGE_BUFFER_LENGTH,
            });
        }
        let udp = crate::net::UdpDatagram::new(
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            DHCP_ZERO_IP,
            DHCP_BROADCAST_IP,
            payload,
        )?;
        let packet = crate::net::Ipv4Packet::new(
            DHCP_ZERO_IP,
            DHCP_BROADCAST_IP,
            crate::net::IP_PROTOCOL_UDP,
            udp.as_bytes(),
            NETWORK_IDENTIFICATION.fetch_add(1, Ordering::AcqRel),
        )?;
        let frame = EthernetFrame::new(
            ETHERNET_BROADCAST,
            self.mac_address,
            crate::net::ETHER_TYPE_IPV4,
            packet.as_bytes(),
        )?;
        self.transmit(&frame)
    }

    fn transmit_dhcp_renewal(&mut self, payload: &[u8]) -> Result<(), IgcError> {
        if payload.len() > DHCP_MESSAGE_BUFFER_LENGTH {
            return Err(IgcError::NetworkBufferTooSmall {
                required: payload.len(),
                available: DHCP_MESSAGE_BUFFER_LENGTH,
            });
        }
        let udp = crate::net::UdpDatagram::new(
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            self.network.address,
            self.network.dhcp_server,
            payload,
        )?;
        let packet = crate::net::Ipv4Packet::new(
            self.network.address,
            self.network.dhcp_server,
            crate::net::IP_PROTOCOL_UDP,
            udp.as_bytes(),
            NETWORK_IDENTIFICATION.fetch_add(1, Ordering::AcqRel),
        )?;
        let frame = EthernetFrame::new(
            ETHERNET_BROADCAST,
            self.mac_address,
            crate::net::ETHER_TYPE_IPV4,
            packet.as_bytes(),
        )?;
        self.transmit(&frame)
    }

    fn receive_dhcp_reply(
        &mut self,
        transaction_id: u32,
        expected_message_type: u8,
    ) -> Result<crate::dhcp::DhcpReply, IgcError> {
        for _ in 0..8 {
            let frame = match self.receive() {
                Ok(frame) => frame,
                Err(IgcError::InterruptTimeout { .. }) => return Err(IgcError::NoPacket),
                Err(error) => return Err(error),
            };
            if frame.ether_type() != crate::net::ETHER_TYPE_IPV4 {
                continue;
            }
            let Ok(packet) = crate::net::Ipv4Packet::parse(frame.payload()) else {
                continue;
            };
            if packet.protocol() != crate::net::IP_PROTOCOL_UDP {
                continue;
            }
            let Ok(datagram) = crate::net::UdpDatagram::parse(
                packet.payload(),
                packet.source(),
                packet.destination(),
            ) else {
                continue;
            };
            if datagram.source_port() != DHCP_SERVER_PORT
                || datagram.destination_port() != DHCP_CLIENT_PORT
            {
                continue;
            }
            let Ok(reply) = dhcp::parse_reply(datagram.payload(), transaction_id, self.mac_address)
            else {
                continue;
            };
            if reply.message_type == expected_message_type {
                return Ok(reply);
            }
        }
        Err(IgcError::NoPacket)
    }

    pub fn network_configuration(&self) -> NetworkConfiguration {
        self.network
    }

    pub fn transmit(&mut self, frame: &EthernetFrame) -> Result<(), IgcError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if !self.tx_queue_ready {
            return Err(IgcError::TxRingFull);
        }

        let index = self.tx_next_index;
        let descriptor_offset = index as u64 * DESCRIPTOR_SIZE;
        self.tx_buffer.write_bytes(0, frame.as_bytes())?;
        write_advanced_tx_descriptor(
            self.tx_ring,
            descriptor_offset,
            self.tx_buffer.physical_base,
            frame.len(),
        )?;
        fence(Ordering::Release);
        self.mmio
            .write_u32(REG_TDT0, ((index + 1) % TX_RING_SIZE) as u32)?;

        #[cfg(target_os = "none")]
        if self.interrupt_driven {
            wait_for_tx_completion(self, index)?;
        } else {
            poll_for_tx_completion(self, descriptor_offset)?;
        }
        #[cfg(not(target_os = "none"))]
        poll_for_tx_completion(self, descriptor_offset)?;

        let status = self.tx_ring.read_u32(descriptor_offset + 12)?;
        if status & TX_DESCRIPTOR_DONE == 0 {
            return Err(IgcError::TxCompletionTimeout {
                descriptor: index,
                status,
            });
        }
        self.tx_next_index = (index + 1) % TX_RING_SIZE;
        self.tx_completed = true;
        self.tx_frames = self.tx_frames.saturating_add(1);
        Ok(())
    }

    pub fn receive(&mut self) -> Result<EthernetFrame, IgcError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if !self.rx_queue_ready {
            return Err(IgcError::NoPacket);
        }

        let index = self.rx_next_index;
        let descriptor_offset = index as u64 * DESCRIPTOR_SIZE;
        fence(Ordering::Acquire);
        #[allow(unused_mut)]
        let mut status = self.rx_ring.read_u32(descriptor_offset + 8)?;
        if status & RX_DESCRIPTOR_DONE == 0 {
            #[cfg(target_os = "none")]
            if self.interrupt_driven {
                wait_for_interrupt(self, IGC_INTERRUPT_RXT0)?;
                status = self.rx_ring.read_u32(descriptor_offset + 8)?;
            }
            if status & RX_DESCRIPTOR_DONE == 0 {
                return Err(IgcError::NoPacket);
            }
        }
        let packet_length = self.rx_ring.read_u16(descriptor_offset + 12)?;
        if status & RX_DESCRIPTOR_ERROR_MASK != 0 {
            recycle_rx_descriptor(self, index)?;
            return Err(IgcError::RxError { status });
        }
        if status & RX_DESCRIPTOR_END_OF_PACKET == 0 {
            recycle_rx_descriptor(self, index)?;
            return Err(IgcError::RxPacketNotSingleDescriptor { status });
        }
        if usize::from(packet_length) > crate::net::ETHERNET_MAX_FRAME_LENGTH {
            recycle_rx_descriptor(self, index)?;
            return Err(IgcError::RxFrameTooLarge {
                length: packet_length,
            });
        }

        let mut bytes = [0u8; crate::net::ETHERNET_MAX_FRAME_LENGTH];
        self.rx_buffers[index].read_bytes(0, &mut bytes[..usize::from(packet_length)])?;
        recycle_rx_descriptor(self, index)?;
        let frame = EthernetFrame::parse(&bytes[..usize::from(packet_length)])?;
        self.rx_packet_length = packet_length;
        self.rx_frames = self.rx_frames.saturating_add(1);
        Ok(frame)
    }

    pub fn send_udp(
        &mut self,
        destination: crate::net::Ipv4Address,
        destination_port: u16,
        payload: &[u8],
    ) -> Result<usize, IgcError> {
        if !self.external_network {
            return Err(IgcError::ExternalNetworkNotEnabled);
        }
        if payload.len() > MAX_NETWORK_PAYLOAD_LENGTH {
            return Err(IgcError::NetworkBufferTooSmall {
                required: payload.len(),
                available: MAX_NETWORK_PAYLOAD_LENGTH,
            });
        }
        let gateway_mac = self.resolve_gateway_mac()?;
        let udp = crate::net::UdpDatagram::new(
            NETWORK_SOURCE_PORT,
            destination_port,
            self.network.address,
            destination,
            payload,
        )?;
        let packet = crate::net::Ipv4Packet::new(
            self.network.address,
            destination,
            crate::net::IP_PROTOCOL_UDP,
            udp.as_bytes(),
            NETWORK_IDENTIFICATION.fetch_add(1, Ordering::AcqRel),
        )?;
        let frame = EthernetFrame::new(
            gateway_mac,
            self.mac_address,
            crate::net::ETHER_TYPE_IPV4,
            packet.as_bytes(),
        )?;
        self.transmit(&frame)?;
        Ok(payload.len())
    }

    fn resolve_gateway_mac(&mut self) -> Result<[u8; 6], IgcError> {
        if let Some(mac) = self.gateway_mac {
            return Ok(mac);
        }
        let mut request = [0u8; 28];
        request[0..2].copy_from_slice(&1u16.to_be_bytes());
        request[2..4].copy_from_slice(&crate::net::ETHER_TYPE_IPV4.to_be_bytes());
        request[4] = 6;
        request[5] = 4;
        request[6..8].copy_from_slice(&1u16.to_be_bytes());
        request[8..14].copy_from_slice(&self.mac_address);
        request[14..18].copy_from_slice(&self.network.address);
        request[24..28].copy_from_slice(&self.network.gateway);
        let frame = EthernetFrame::new(
            ETHERNET_BROADCAST,
            self.mac_address,
            crate::net::ETHER_TYPE_ARP,
            &request,
        )?;
        for _ in 0..2 {
            self.transmit(&frame)?;
            for _ in 0..2 {
                let received = match self.receive() {
                    Ok(frame) => frame,
                    Err(IgcError::InterruptTimeout { .. }) => break,
                    Err(error) => return Err(error),
                };
                if received.ether_type() != crate::net::ETHER_TYPE_ARP {
                    continue;
                }
                let payload = received.payload();
                if payload.len() < 28
                    || u16::from_be_bytes([payload[0], payload[1]]) != 1
                    || u16::from_be_bytes([payload[2], payload[3]]) != crate::net::ETHER_TYPE_IPV4
                    || payload[4] != 6
                    || payload[5] != 4
                    || u16::from_be_bytes([payload[6], payload[7]]) != 2
                    || payload[14..18] != self.network.gateway
                    || payload[24..28] != self.network.address
                {
                    continue;
                }
                let mac: [u8; 6] = payload[8..14]
                    .try_into()
                    .expect("validated ARP gateway MAC");
                self.gateway_mac = Some(mac);
                #[cfg(target_os = "none")]
                crate::kprintln!(
                    "net: arp gateway resolved interface=igc0 mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} status=ready",
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                );
                return Ok(mac);
            }
        }
        Err(IgcError::NoPacket)
    }

    pub fn receive_udp(&mut self, buffer: &mut [u8]) -> Result<usize, IgcError> {
        if !self.external_network {
            return Err(IgcError::ExternalNetworkNotEnabled);
        }
        if buffer.len() < NETWORK_RECEIVE_HEADER_LENGTH {
            return Err(IgcError::NetworkBufferTooSmall {
                required: NETWORK_RECEIVE_HEADER_LENGTH,
                available: buffer.len(),
            });
        }
        loop {
            let frame = match self.receive() {
                Ok(frame) => frame,
                Err(error @ IgcError::InterruptTimeout { .. }) => {
                    if self.external_receive_diagnostics < 4 {
                        self.external_receive_diagnostics += 1;
                        #[cfg(not(target_os = "none"))]
                        let _ = error;
                        #[cfg(target_os = "none")]
                        crate::kprintln!(
                            "net: external rx timeout interface=igc0 detail={:?} status=degraded",
                            error
                        );
                    }
                    return Err(IgcError::NoPacket);
                }
                Err(error) => return Err(error),
            };
            if frame.ether_type() == crate::net::ETHER_TYPE_ARP {
                self.respond_to_arp(&frame)?;
                continue;
            }
            if frame.ether_type() != crate::net::ETHER_TYPE_IPV4 {
                continue;
            }
            let Ok(packet) = crate::net::Ipv4Packet::parse(frame.payload()) else {
                continue;
            };
            if packet.destination() != self.network.address
                || packet.protocol() != crate::net::IP_PROTOCOL_UDP
            {
                continue;
            }
            let Ok(datagram) = crate::net::UdpDatagram::parse(
                packet.payload(),
                packet.source(),
                packet.destination(),
            ) else {
                continue;
            };
            if datagram.destination_port() != NETWORK_SOURCE_PORT {
                continue;
            }
            let required = NETWORK_RECEIVE_HEADER_LENGTH + datagram.payload().len();
            if required > buffer.len() {
                return Err(IgcError::NetworkBufferTooSmall {
                    required,
                    available: buffer.len(),
                });
            }
            buffer[..4].copy_from_slice(&packet.source());
            buffer[4..6].copy_from_slice(&datagram.source_port().to_be_bytes());
            buffer[NETWORK_RECEIVE_HEADER_LENGTH..required].copy_from_slice(datagram.payload());
            return Ok(required);
        }
    }

    fn respond_to_arp(&mut self, frame: &EthernetFrame) -> Result<(), IgcError> {
        let payload = frame.payload();
        if payload.len() < 28
            || u16::from_be_bytes([payload[0], payload[1]]) != 1
            || u16::from_be_bytes([payload[2], payload[3]]) != crate::net::ETHER_TYPE_IPV4
            || payload[4] != 6
            || payload[5] != 4
            || u16::from_be_bytes([payload[6], payload[7]]) != 1
            || payload[24..28] != self.network.address
        {
            return Ok(());
        }
        let sender_mac: [u8; 6] = payload[8..14].try_into().expect("validated ARP sender MAC");
        let sender_ip: [u8; 4] = payload[14..18].try_into().expect("validated ARP sender IP");
        let mut response = [0u8; 28];
        response[0..2].copy_from_slice(&1u16.to_be_bytes());
        response[2..4].copy_from_slice(&crate::net::ETHER_TYPE_IPV4.to_be_bytes());
        response[4] = 6;
        response[5] = 4;
        response[6..8].copy_from_slice(&2u16.to_be_bytes());
        response[8..14].copy_from_slice(&self.mac_address);
        response[14..18].copy_from_slice(&self.network.address);
        response[18..24].copy_from_slice(&sender_mac);
        response[24..28].copy_from_slice(&sender_ip);
        let response_frame = EthernetFrame::new(
            sender_mac,
            self.mac_address,
            crate::net::ETHER_TYPE_ARP,
            &response,
        )?;
        self.transmit(&response_frame)
    }
}

impl NetworkInterface for IgcRuntime {
    type Error = IgcError;

    fn mac_address(&self) -> crate::net::MacAddress {
        self.mac_address
    }

    fn transmit(&mut self, frame: &EthernetFrame) -> Result<(), Self::Error> {
        IgcRuntime::transmit(self, frame)
    }

    fn receive(&mut self) -> Result<EthernetFrame, Self::Error> {
        IgcRuntime::receive(self)
    }
}

pub fn initialize(
    inventory: &PciInventory,
    physical_memory_offset: u64,
    regions: &[MemoryRegion],
    next_frame_address: Option<u64>,
) -> Result<Option<IgcRuntime>, IgcInitFailure> {
    let Some(device) = find_device(inventory) else {
        return Ok(None);
    };
    if !device.memory_space_enabled() {
        return Err(IgcInitFailure {
            error: IgcError::MemorySpaceDisabled,
            next_frame_address,
        });
    }

    let mut resources = PciDeviceResources::new(device, physical_memory_offset);
    resources
        .enable_bus_master()
        .map_err(|error| IgcInitFailure {
            error: error.into(),
            next_frame_address,
        })?;
    let device = resources.device();
    let mmio = resources
        .claim_mmio(0, I225_MMIO_LENGTH)
        .map_err(|error| IgcInitFailure {
            error: error.into(),
            next_frame_address,
        })?;
    let control = mmio.read_u32(REG_CTRL).map_err(|error| IgcInitFailure {
        error: error.into(),
        next_frame_address,
    })?;
    let status = mmio.read_u32(REG_STATUS).map_err(|error| IgcInitFailure {
        error: error.into(),
        next_frame_address,
    })?;
    let mac_address = read_mac_address(mmio).map_err(|error| IgcInitFailure {
        error: error.into(),
        next_frame_address,
    })?;
    if !valid_mac_address(mac_address) {
        return Err(IgcInitFailure {
            error: IgcError::InvalidMac,
            next_frame_address,
        });
    }

    let mut frame_allocator = FrameAllocator::starting_at(regions, next_frame_address.unwrap_or(0));
    let layout =
        allocate_layout(&mut frame_allocator, physical_memory_offset).map_err(|error| {
            IgcInitFailure {
                error: error.into(),
                next_frame_address: frame_allocator.next_available_address(),
            }
        })?;

    let mut runtime = IgcRuntime {
        address: device.address,
        interrupt_line: device.interrupt_line,
        interrupt_pin: device.interrupt_pin,
        mmio_base: mmio.physical_base(),
        mmio_length: mmio.length(),
        control,
        status,
        bus_master_enabled: device.bus_master_enabled(),
        mac_address,
        tx_queue_ready: false,
        rx_queue_ready: false,
        tx_completed: false,
        tx_frames: 0,
        rx_frames: 0,
        rx_packet_length: 0,
        failure: None,
        interrupt_gsi: None,
        interrupt_vector: None,
        interrupt_mode: PciInterruptMode::None,
        interrupt_count: 0,
        interrupt_cause: 0,
        interrupt_driven: false,
        external_network: false,
        network: NetworkConfiguration::static_default(),
        next_frame_address: frame_allocator.next_available_address(),
        pci_resources: resources,
        mmio,
        tx_ring: layout.tx_ring,
        rx_ring: layout.rx_ring,
        tx_buffer: layout.tx_buffer,
        rx_buffers: layout.rx_buffers,
        tx_next_index: 0,
        rx_next_index: 0,
        pending_interrupt_cause: 0,
        gateway_mac: None,
        external_receive_diagnostics: 0,
    };

    if let Err(error) = configure(&mut runtime) {
        runtime.failure = Some(error);
    }
    runtime.status = runtime.mmio.read_u32(REG_STATUS).unwrap_or(runtime.status);
    runtime.next_frame_address = frame_allocator.next_available_address();
    Ok(Some(runtime))
}

fn allocate_layout(
    allocator: &mut FrameAllocator<'_>,
    physical_memory_offset: u64,
) -> Result<DmaLayout, IgcDmaError> {
    let tx_ring = allocate_page(allocator, physical_memory_offset)?;
    let rx_ring = allocate_page(allocator, physical_memory_offset)?;
    let tx_buffer = allocate_page(allocator, physical_memory_offset)?;
    let first_rx_buffer = allocate_page(allocator, physical_memory_offset)?;
    let mut rx_buffers = [first_rx_buffer; RX_RING_SIZE];
    for buffer in rx_buffers.iter_mut().skip(1) {
        *buffer = allocate_page(allocator, physical_memory_offset)?;
    }

    Ok(DmaLayout {
        tx_ring,
        rx_ring,
        tx_buffer,
        rx_buffers,
    })
}

fn allocate_page(
    allocator: &mut FrameAllocator<'_>,
    physical_memory_offset: u64,
) -> Result<DmaPage, IgcDmaError> {
    let physical_base = allocator
        .next()
        .ok_or(IgcDmaError::NoFrame)?
        .start_address();
    let virtual_base = physical_memory_offset
        .checked_add(physical_base)
        .ok_or(IgcDmaError::AddressOverflow)?;
    virtual_base
        .checked_add(PAGE_SIZE)
        .ok_or(IgcDmaError::AddressOverflow)?;
    let page = DmaPage {
        physical_base,
        virtual_base,
    };
    page.clear();
    Ok(page)
}

fn configure(runtime: &mut IgcRuntime) -> Result<(), IgcError> {
    reset_device(runtime.mmio)?;
    runtime.mmio.write_u32(REG_IMC, u32::MAX)?;
    let _ = runtime.mmio.read_u32(REG_ICR)?;
    runtime.mmio.write_u32(REG_RCTL, 0)?;
    runtime.mmio.write_u32(REG_TCTL, 0)?;
    runtime.mmio.write_u32(REG_RXDCTL0, 0)?;
    runtime.mmio.write_u32(REG_TXDCTL0, 0)?;

    let mut control = runtime.mmio.read_u32(REG_CTRL)?;
    control &= !(IGC_CTRL_FRCSPD | IGC_CTRL_FRCDPX);
    control |= IGC_CTRL_SLU;
    runtime.mmio.write_u32(REG_CTRL, control)?;
    runtime.control = control;

    write_mac_filter(runtime.mmio, runtime.mac_address)?;
    configure_tx_ring(runtime)?;
    configure_rx_ring(runtime)?;

    runtime.mmio.write_u32(
        REG_TCTL,
        IGC_TCTL_ENABLE
            | IGC_TCTL_PAD_SHORT_PACKETS
            | IGC_TCTL_COLLISION_THRESHOLD
            | IGC_TCTL_RETRANSMIT_LATE_COLLISION,
    )?;
    runtime.mmio.write_u32(
        REG_RCTL,
        IGC_RCTL_ENABLE
            | IGC_RCTL_BROADCAST_ACCEPT
            | IGC_RCTL_LONG_PACKET_ENABLE
            | IGC_RCTL_STRIP_CRC,
    )?;
    runtime.tx_queue_ready = true;
    runtime.rx_queue_ready = true;
    Ok(())
}

fn reset_device(mmio: MmioRegion) -> Result<(), IgcError> {
    mmio.write_u32(REG_IMC, u32::MAX)?;
    mmio.write_u32(REG_RCTL, 0)?;
    mmio.write_u32(REG_TCTL, IGC_TCTL_PAD_SHORT_PACKETS)?;
    let control = mmio.read_u32(REG_CTRL)?;
    mmio.write_u32(REG_CTRL, control | IGC_CTRL_RST)?;

    for _ in 0..POLL_SPINS {
        let control = mmio.read_u32(REG_CTRL)?;
        if control & IGC_CTRL_RST == 0 {
            let _ = mmio.read_u32(REG_ICR)?;
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(IgcError::ResetTimeout {
        control: mmio.read_u32(REG_CTRL)?,
    })
}

fn configure_tx_ring(runtime: &mut IgcRuntime) -> Result<(), IgcError> {
    write_ring_base(
        runtime.mmio,
        REG_TDBAL0,
        REG_TDBAH0,
        runtime.tx_ring.physical_base,
    )?;
    runtime
        .mmio
        .write_u32(REG_TDLEN0, TX_RING_SIZE as u32 * DESCRIPTOR_SIZE as u32)?;
    runtime.mmio.write_u32(REG_TDH0, 0)?;
    runtime.mmio.write_u32(REG_TDT0, 0)?;
    runtime.mmio.write_u32(
        REG_TXDCTL0,
        IGC_TXDCTL_PTHRESH | IGC_TXDCTL_HTHRESH | IGC_TXDCTL_WTHRESH | IGC_TXDCTL_QUEUE_ENABLE,
    )?;
    Ok(())
}

fn configure_rx_ring(runtime: &mut IgcRuntime) -> Result<(), IgcError> {
    for (index, buffer) in runtime.rx_buffers.iter().copied().enumerate() {
        let offset = index as u64 * DESCRIPTOR_SIZE;
        runtime.rx_ring.write_u64(offset, buffer.physical_base)?;
        runtime.rx_ring.write_u64(offset + 8, 0)?;
    }
    fence(Ordering::Release);
    write_ring_base(
        runtime.mmio,
        REG_RDBAL0,
        REG_RDBAH0,
        runtime.rx_ring.physical_base,
    )?;
    runtime
        .mmio
        .write_u32(REG_RDLEN0, RX_RING_SIZE as u32 * DESCRIPTOR_SIZE as u32)?;
    runtime.mmio.write_u32(REG_RDH0, 0)?;
    runtime.mmio.write_u32(REG_RDT0, 0)?;
    runtime.mmio.write_u32(
        REG_SRRCTL0,
        RX_DESCRIPTOR_PACKET_BUFFER_2048 | RX_DESCRIPTOR_TYPE_ONE_BUFFER,
    )?;
    runtime.mmio.write_u32(
        REG_RXDCTL0,
        IGC_RXDCTL_PTHRESH | IGC_RXDCTL_HTHRESH | IGC_RXDCTL_WTHRESH | IGC_RXDCTL_QUEUE_ENABLE,
    )?;
    fence(Ordering::Release);
    runtime
        .mmio
        .write_u32(REG_RDT0, (RX_RING_SIZE - 1) as u32)?;
    Ok(())
}

fn write_ring_base(
    mmio: MmioRegion,
    low_register: u64,
    high_register: u64,
    physical_base: u64,
) -> Result<(), IgcError> {
    mmio.write_u32(low_register, physical_base as u32)?;
    mmio.write_u32(high_register, (physical_base >> 32) as u32)?;
    Ok(())
}

fn write_mac_filter(mmio: MmioRegion, mac_address: [u8; 6]) -> Result<(), IgcError> {
    let low = u32::from_le_bytes([
        mac_address[0],
        mac_address[1],
        mac_address[2],
        mac_address[3],
    ]);
    let high = u32::from(u16::from_le_bytes([mac_address[4], mac_address[5]])) | IGC_RAH_AV;
    mmio.write_u32(REG_RAL0, low)?;
    mmio.write_u32(REG_RAH0, high)?;
    Ok(())
}

fn write_advanced_tx_descriptor(
    ring: DmaPage,
    offset: u64,
    buffer_physical_base: u64,
    packet_length: usize,
) -> Result<(), IgcError> {
    let command = advanced_tx_command(packet_length)?;
    let packet_length = u32::try_from(packet_length).map_err(|_| IgcDmaError::AddressOverflow)?;
    ring.write_u64(offset, buffer_physical_base)?;
    ring.write_u32(offset + 8, command)?;
    ring.write_u32(offset + 12, packet_length << TX_PAYLOAD_LENGTH_SHIFT)?;
    Ok(())
}

fn poll_for_tx_completion(runtime: &IgcRuntime, descriptor_offset: u64) -> Result<(), IgcError> {
    for _ in 0..POLL_SPINS {
        fence(Ordering::Acquire);
        if runtime.tx_ring.read_u32(descriptor_offset + 12)? & TX_DESCRIPTOR_DONE != 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(IgcError::TxCompletionTimeout {
        descriptor: (descriptor_offset / DESCRIPTOR_SIZE) as usize,
        status: runtime.tx_ring.read_u32(descriptor_offset + 12)?,
    })
}

fn advanced_tx_command(packet_length: usize) -> Result<u32, IgcDmaError> {
    let packet_length = u32::try_from(packet_length).map_err(|_| IgcDmaError::AddressOverflow)?;
    Ok(TX_DESCRIPTOR_DATA_TYPE
        | TX_DESCRIPTOR_END_OF_PACKET
        | TX_DESCRIPTOR_INSERT_FCS
        | TX_DESCRIPTOR_REPORT_STATUS
        | TX_DESCRIPTOR_EXTENSION
        | packet_length)
}

fn recycle_rx_descriptor(runtime: &mut IgcRuntime, index: usize) -> Result<(), IgcError> {
    let offset = index as u64 * DESCRIPTOR_SIZE;
    runtime
        .rx_ring
        .write_u64(offset, runtime.rx_buffers[index].physical_base)?;
    runtime.rx_ring.write_u64(offset + 8, 0)?;
    fence(Ordering::Release);
    runtime.mmio.write_u32(REG_RDT0, index as u32)?;
    runtime.rx_next_index = (index + 1) % RX_RING_SIZE;
    Ok(())
}

#[cfg(target_os = "none")]
fn igc_interrupt_handler() {
    let mmio = IGC_INTERRUPT_MMIO.lock().as_ref().copied();
    let Some(mmio) = mmio else {
        return;
    };
    let Ok(cause) = mmio.read_u32(REG_ICR) else {
        return;
    };
    if cause != 0 {
        IGC_INTERRUPT_CAUSE.fetch_or(cause, Ordering::SeqCst);
        IGC_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(target_os = "none")]
fn wait_for_interrupt(runtime: &mut IgcRuntime, required_cause: u32) -> Result<u32, IgcError> {
    let mut cause = runtime.pending_interrupt_cause;
    for _ in 0..POLL_SPINS {
        runtime.pending_interrupt_cause |= IGC_INTERRUPT_CAUSE.swap(0, Ordering::SeqCst);
        cause = runtime.pending_interrupt_cause;
        if cause & required_cause != 0 {
            runtime.pending_interrupt_cause &= !required_cause;
            runtime.interrupt_cause |= cause;
            runtime.interrupt_count = IGC_INTERRUPT_COUNT.load(Ordering::SeqCst);
            return Ok(cause);
        }
        if x86_64::instructions::interrupts::are_enabled() {
            crate::interrupts::halt();
        } else {
            core::hint::spin_loop();
        }
    }
    Err(IgcError::InterruptTimeout {
        cause,
        rctl: runtime.mmio.read_u32(REG_RCTL)?,
        tdh: runtime.mmio.read_u32(REG_TDH0)?,
        rdh: runtime.mmio.read_u32(REG_RDH0)?,
        rdt: runtime.mmio.read_u32(REG_RDT0)?,
    })
}

#[cfg(target_os = "none")]
fn wait_for_tx_completion(runtime: &mut IgcRuntime, index: usize) -> Result<u32, IgcError> {
    let mut cause = runtime.pending_interrupt_cause;
    let descriptor_offset = index as u64 * DESCRIPTOR_SIZE;
    for _ in 0..POLL_SPINS {
        runtime.pending_interrupt_cause |= IGC_INTERRUPT_CAUSE.swap(0, Ordering::SeqCst);
        cause = runtime.pending_interrupt_cause;
        if runtime.tx_ring.read_u32(descriptor_offset + 12)? & TX_DESCRIPTOR_DONE != 0 {
            runtime.pending_interrupt_cause &= !IGC_INTERRUPT_TXDW;
            runtime.interrupt_cause |= cause;
            runtime.interrupt_count = IGC_INTERRUPT_COUNT.load(Ordering::SeqCst);
            return Ok(cause);
        }
        if x86_64::instructions::interrupts::are_enabled() {
            crate::interrupts::halt();
        } else {
            core::hint::spin_loop();
        }
    }
    Err(IgcError::InterruptTimeout {
        cause,
        rctl: runtime.mmio.read_u32(REG_RCTL)?,
        tdh: runtime.mmio.read_u32(REG_TDH0)?,
        rdh: runtime.mmio.read_u32(REG_RDH0)?,
        rdt: runtime.mmio.read_u32(REG_RDT0)?,
    })
}

#[derive(Debug, Clone, Copy)]
struct DmaLayout {
    tx_ring: DmaPage,
    rx_ring: DmaPage,
    tx_buffer: DmaPage,
    rx_buffers: [DmaPage; RX_RING_SIZE],
}

#[derive(Debug, Clone, Copy)]
struct DmaPage {
    physical_base: u64,
    virtual_base: u64,
}

impl DmaPage {
    fn clear(self) {
        // SAFETY: the page comes from a usable physical frame and the bootloader's physical
        // memory mapping makes the complete page accessible at `virtual_base`.
        unsafe { core::ptr::write_bytes(self.virtual_base as *mut u8, 0, PAGE_SIZE as usize) };
    }

    fn write_u32(self, offset: u64, value: u32) -> Result<(), IgcDmaError> {
        let pointer = self.pointer(offset, 4, 4)?;
        // SAFETY: `pointer` was bounds-checked and aligned for a 32-bit DMA field.
        unsafe { core::ptr::write_volatile(pointer as *mut u32, value.to_le()) };
        Ok(())
    }

    fn write_u64(self, offset: u64, value: u64) -> Result<(), IgcDmaError> {
        let pointer = self.pointer(offset, 8, 8)?;
        // SAFETY: `pointer` was bounds-checked and aligned for a 64-bit DMA field.
        unsafe { core::ptr::write_volatile(pointer as *mut u64, value.to_le()) };
        Ok(())
    }

    fn read_u32(self, offset: u64) -> Result<u32, IgcDmaError> {
        let pointer = self.pointer(offset, 4, 4)?;
        // SAFETY: `pointer` was bounds-checked and aligned for a 32-bit DMA field.
        Ok(u32::from_le(unsafe {
            core::ptr::read_volatile(pointer as *const u32)
        }))
    }

    fn read_u16(self, offset: u64) -> Result<u16, IgcDmaError> {
        let pointer = self.pointer(offset, 2, 2)?;
        // SAFETY: `pointer` was bounds-checked and aligned for a 16-bit DMA field.
        Ok(u16::from_le(unsafe {
            core::ptr::read_volatile(pointer as *const u16)
        }))
    }

    fn write_bytes(self, offset: u64, bytes: &[u8]) -> Result<(), IgcDmaError> {
        for (index, byte) in bytes.iter().copied().enumerate() {
            let index = u64::try_from(index).map_err(|_| IgcDmaError::AddressOverflow)?;
            let offset = offset
                .checked_add(index)
                .ok_or(IgcDmaError::AddressOverflow)?;
            let pointer = self.pointer(offset, 1, 1)?;
            // SAFETY: `pointer` was bounds-checked against this DMA page.
            unsafe { core::ptr::write_volatile(pointer as *mut u8, byte) };
        }
        Ok(())
    }

    fn read_bytes(self, offset: u64, bytes: &mut [u8]) -> Result<(), IgcDmaError> {
        for (index, byte) in bytes.iter_mut().enumerate() {
            let index = u64::try_from(index).map_err(|_| IgcDmaError::AddressOverflow)?;
            let offset = offset
                .checked_add(index)
                .ok_or(IgcDmaError::AddressOverflow)?;
            let pointer = self.pointer(offset, 1, 1)?;
            // SAFETY: `pointer` was bounds-checked against this DMA page.
            *byte = unsafe { core::ptr::read_volatile(pointer as *const u8) };
        }
        Ok(())
    }

    fn pointer(self, offset: u64, size: u64, alignment: u64) -> Result<u64, IgcDmaError> {
        if offset % alignment != 0 {
            return Err(IgcDmaError::Unaligned { offset, alignment });
        }
        let end = offset
            .checked_add(size)
            .ok_or(IgcDmaError::AddressOverflow)?;
        if end > PAGE_SIZE {
            return Err(IgcDmaError::OutOfBounds { offset, size });
        }
        self.virtual_base
            .checked_add(offset)
            .ok_or(IgcDmaError::AddressOverflow)
    }
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
            subsystem_vendor_id: 0,
            subsystem_device_id: 0,
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

    #[test]
    fn encodes_an_advanced_tx_descriptor_for_a_padded_frame() {
        assert_eq!(advanced_tx_command(60), Ok(0x2b30_003c));
        assert_eq!(60u32 << TX_PAYLOAD_LENGTH_SHIFT, 0x000f_0000);
    }

    #[test]
    fn keeps_i225_ring_sizes_at_the_required_multiple() {
        assert_eq!(TX_RING_SIZE % 8, 0);
        assert_eq!(RX_RING_SIZE % 8, 0);
        assert_eq!(DESCRIPTOR_SIZE, 16);
    }

    #[test]
    fn decodes_one_buffer_rx_writeback_fields_at_the_advanced_offsets() {
        let status_error = RX_DESCRIPTOR_DONE | RX_DESCRIPTOR_END_OF_PACKET;
        let packet_length = 128u16;
        assert_ne!(status_error & RX_DESCRIPTOR_DONE, 0);
        assert_ne!(status_error & RX_DESCRIPTOR_END_OF_PACKET, 0);
        assert_eq!(packet_length, 128);
        assert_eq!(core::mem::size_of::<[u8; 16]>(), 16);
    }

    #[test]
    fn enables_tx_rx_and_link_status_interrupts() {
        assert_eq!(
            IGC_INTERRUPT_MASK,
            IGC_INTERRUPT_TXDW | IGC_INTERRUPT_RXT0 | IGC_INTERRUPT_LSC
        );
    }
}
