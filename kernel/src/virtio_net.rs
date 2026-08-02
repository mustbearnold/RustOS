use core::sync::atomic::{AtomicU16, Ordering, fence};

#[cfg(target_os = "none")]
use core::sync::atomic::AtomicU64;

use bootloader_api::info::MemoryRegion;

use crate::dhcp::{
    self, DHCP_ACK, DHCP_CLIENT_PORT, DHCP_MESSAGE_BUFFER_LENGTH, DHCP_OFFER, DHCP_SERVER_PORT,
};
use crate::memory::{FrameAllocator, PAGE_SIZE};
use crate::net::{
    EthernetFrame, EthernetFrameError, Ipv4PacketError, NetworkInterface, UdpDatagramError,
};
use crate::pci::{
    MmioError, MmioRegion, PciAddress, PciDevice, PciDeviceResources, PciInterruptMode,
    PciInventory, PciResourceError,
};

#[cfg(target_os = "none")]
use crate::pci::{PciMsiRoute, PciMsixRoute};

const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_NET_DEVICE_ID: u16 = 0x1041;

const VIRTIO_PCI_CAP_COMMON_CONFIG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CONFIG: u8 = 2;
const VIRTIO_PCI_CAP_DEVICE_CONFIG: u8 = 4;

const DEVICE_FEATURE_SELECT: u64 = 0x00;
const DEVICE_FEATURE: u64 = 0x04;
const DRIVER_FEATURE_SELECT: u64 = 0x08;
const DRIVER_FEATURE: u64 = 0x0c;
const COMMON_MSIX_CONFIG: u64 = 0x10;
const NUM_QUEUES: u64 = 0x12;
const DEVICE_STATUS: u64 = 0x14;
const QUEUE_SELECT: u64 = 0x16;
const QUEUE_SIZE: u64 = 0x18;
const QUEUE_MSIX_VECTOR: u64 = 0x1a;
const QUEUE_ENABLE: u64 = 0x1c;
const QUEUE_NOTIFY_OFFSET: u64 = 0x1e;
const QUEUE_DESC_LOW: u64 = 0x20;
const QUEUE_DRIVER_LOW: u64 = 0x28;
const QUEUE_DEVICE_LOW: u64 = 0x30;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;

const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
const VIRTIO_NET_S_LINK_UP: u16 = 1 << 0;

const VIRTQ_DESC_F_WRITE: u16 = 1 << 1;
const QUEUE_SIZE_LIMIT: usize = 8;
const RX_QUEUE_INDEX: u16 = 0;
const TX_QUEUE_INDEX: u16 = 1;
// QEMU's modern virtio-net path uses the v1 header layout, which reserves the
// num_buffers field even when mergeable RX buffers are not negotiated.
const VIRTIO_NET_HEADER_LENGTH: u64 = 12;
const POLL_SPINS: usize = 10_000_000;
const INTERRUPT_WAIT_SPINS: usize = 64;
const DMA_ALLOCATION_FLOOR: u64 = 8 * 1024 * 1024;
const DEFAULT_NETWORK_GUEST_IP: crate::net::Ipv4Address = [10, 0, 2, 15];
const DEFAULT_NETWORK_SUBNET_MASK: crate::net::Ipv4Address = [255, 255, 255, 0];
const DEFAULT_NETWORK_GATEWAY_IP: crate::net::Ipv4Address = [10, 0, 2, 2];
const DEFAULT_NETWORK_DNS_IP: crate::net::Ipv4Address = [10, 0, 2, 3];
const DHCP_ZERO_IP: crate::net::Ipv4Address = [0, 0, 0, 0];
const DHCP_BROADCAST_IP: crate::net::Ipv4Address = [255, 255, 255, 255];
const ETHERNET_BROADCAST: [u8; 6] = [u8::MAX; 6];
const NETWORK_SOURCE_PORT: u16 = 49_000;
const NETWORK_RECEIVE_HEADER_LENGTH: usize = 6;
const MAX_NETWORK_PAYLOAD_LENGTH: usize = 1024;
const RX_DIAGNOSTIC_LIMIT: u8 = 4;

static NETWORK_IDENTIFICATION: AtomicU16 = AtomicU16::new(0x3000);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    NoFrame,
    AddressOverflow,
    Unaligned { offset: u64, alignment: u64 },
    OutOfBounds { offset: u64, size: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioNetError {
    Resources(PciResourceError),
    Mmio(MmioError),
    Dma(DmaError),
    Frame(EthernetFrameError),
    Ipv4(Ipv4PacketError),
    Udp(UdpDatagramError),
    Dhcp(crate::dhcp::DhcpError),
    MemorySpaceDisabled,
    MissingCapability {
        cfg_type: u8,
    },
    InvalidMac,
    FeatureNegotiationFailed,
    QueueUnavailable {
        queue: u16,
    },
    QueueTooSmall {
        queue: u16,
        size: u16,
    },
    QueueAddressOverflow,
    QueueDescriptorInvalid {
        descriptor: u32,
    },
    TxTimeout,
    RxFrameTooLarge {
        length: u32,
    },
    NetworkUnavailable,
    ExternalNetworkNotEnabled,
    #[cfg(target_os = "none")]
    InterruptRegistration(crate::interrupts::DeviceInterruptError),
    InterruptsNotPrepared,
    NoPacket,
    NetworkBufferTooSmall {
        required: usize,
        available: usize,
    },
}

impl From<PciResourceError> for VirtioNetError {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

impl From<MmioError> for VirtioNetError {
    fn from(error: MmioError) -> Self {
        Self::Mmio(error)
    }
}

impl From<DmaError> for VirtioNetError {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

impl From<EthernetFrameError> for VirtioNetError {
    fn from(error: EthernetFrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<Ipv4PacketError> for VirtioNetError {
    fn from(error: Ipv4PacketError) -> Self {
        Self::Ipv4(error)
    }
}

impl From<UdpDatagramError> for VirtioNetError {
    fn from(error: UdpDatagramError) -> Self {
        Self::Udp(error)
    }
}

impl From<crate::dhcp::DhcpError> for VirtioNetError {
    fn from(error: crate::dhcp::DhcpError) -> Self {
        Self::Dhcp(error)
    }
}

#[cfg(target_os = "none")]
impl From<crate::interrupts::DeviceInterruptError> for VirtioNetError {
    fn from(error: crate::interrupts::DeviceInterruptError) -> Self {
        Self::InterruptRegistration(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioNetInitFailure {
    pub error: VirtioNetError,
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
            address: DEFAULT_NETWORK_GUEST_IP,
            subnet_mask: DEFAULT_NETWORK_SUBNET_MASK,
            gateway: DEFAULT_NETWORK_GATEWAY_IP,
            dns: DEFAULT_NETWORK_DNS_IP,
            dhcp_server: DEFAULT_NETWORK_GATEWAY_IP,
            lease_seconds: 0,
            dhcp: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DmaPage {
    physical_base: u64,
    virtual_base: u64,
}

impl DmaPage {
    const fn empty() -> Self {
        Self {
            physical_base: 0,
            virtual_base: 0,
        }
    }

    fn clear(self) {
        unsafe { core::ptr::write_bytes(self.virtual_base as *mut u8, 0, PAGE_SIZE as usize) };
    }

    fn write_u8(self, offset: u64, value: u8) -> Result<(), DmaError> {
        let pointer = self.pointer(offset, 1, 1)?;
        unsafe { core::ptr::write_volatile(pointer as *mut u8, value) };
        Ok(())
    }

    fn write_u16(self, offset: u64, value: u16) -> Result<(), DmaError> {
        let pointer = self.pointer(offset, 2, 2)?;
        unsafe { core::ptr::write_volatile(pointer as *mut u16, value.to_le()) };
        Ok(())
    }

    fn write_u32(self, offset: u64, value: u32) -> Result<(), DmaError> {
        let pointer = self.pointer(offset, 4, 4)?;
        unsafe { core::ptr::write_volatile(pointer as *mut u32, value.to_le()) };
        Ok(())
    }

    fn write_u64(self, offset: u64, value: u64) -> Result<(), DmaError> {
        let pointer = self.pointer(offset, 8, 8)?;
        unsafe { core::ptr::write_volatile(pointer as *mut u64, value.to_le()) };
        Ok(())
    }

    fn read_u16(self, offset: u64) -> Result<u16, DmaError> {
        let pointer = self.pointer(offset, 2, 2)?;
        Ok(u16::from_le(unsafe {
            core::ptr::read_volatile(pointer as *const u16)
        }))
    }

    fn read_u32(self, offset: u64) -> Result<u32, DmaError> {
        let pointer = self.pointer(offset, 4, 4)?;
        Ok(u32::from_le(unsafe {
            core::ptr::read_volatile(pointer as *const u32)
        }))
    }

    fn write_bytes(self, offset: u64, bytes: &[u8]) -> Result<(), DmaError> {
        for (index, byte) in bytes.iter().copied().enumerate() {
            let index = u64::try_from(index).map_err(|_| DmaError::AddressOverflow)?;
            let offset = offset.checked_add(index).ok_or(DmaError::AddressOverflow)?;
            self.write_u8(offset, byte)?;
        }
        Ok(())
    }

    fn read_bytes(self, offset: u64, bytes: &mut [u8]) -> Result<(), DmaError> {
        for (index, byte) in bytes.iter_mut().enumerate() {
            let index = u64::try_from(index).map_err(|_| DmaError::AddressOverflow)?;
            let offset = offset.checked_add(index).ok_or(DmaError::AddressOverflow)?;
            let pointer = self.pointer(offset, 1, 1)?;
            *byte = unsafe { core::ptr::read_volatile(pointer as *const u8) };
        }
        Ok(())
    }

    fn pointer(self, offset: u64, size: u64, alignment: u64) -> Result<u64, DmaError> {
        if offset % alignment != 0 {
            return Err(DmaError::Unaligned { offset, alignment });
        }
        let end = offset.checked_add(size).ok_or(DmaError::AddressOverflow)?;
        if end > PAGE_SIZE {
            return Err(DmaError::OutOfBounds { offset, size });
        }
        self.virtual_base
            .checked_add(offset)
            .ok_or(DmaError::AddressOverflow)
    }
}

#[derive(Debug, Clone, Copy)]
struct VirtQueue {
    descriptors: DmaPage,
    available: DmaPage,
    used: DmaPage,
    size: u16,
    available_index: u16,
    last_used_index: u16,
}

impl VirtQueue {
    fn allocate(
        allocator: &mut FrameAllocator<'_>,
        physical_memory_offset: u64,
    ) -> Result<Self, VirtioNetError> {
        Ok(Self {
            descriptors: allocate_page(allocator, physical_memory_offset)?,
            available: allocate_page(allocator, physical_memory_offset)?,
            used: allocate_page(allocator, physical_memory_offset)?,
            size: 0,
            available_index: 0,
            last_used_index: 0,
        })
    }

    fn set_descriptor(
        self,
        index: usize,
        address: u64,
        length: u32,
        flags: u16,
    ) -> Result<(), VirtioNetError> {
        let offset = u64::try_from(index)
            .map_err(|_| VirtioNetError::QueueAddressOverflow)?
            .checked_mul(16)
            .ok_or(VirtioNetError::QueueAddressOverflow)?;
        self.descriptors.write_u64(offset, address)?;
        self.descriptors.write_u32(offset + 8, length)?;
        self.descriptors.write_u16(offset + 12, flags)?;
        self.descriptors.write_u16(offset + 14, 0)?;
        Ok(())
    }

    fn push_available(&mut self, descriptor: u16) -> Result<(), VirtioNetError> {
        let ring_offset = 4u64
            .checked_add(
                u64::from(self.available_index % self.size)
                    .checked_mul(2)
                    .ok_or(VirtioNetError::QueueAddressOverflow)?,
            )
            .ok_or(VirtioNetError::QueueAddressOverflow)?;
        self.available.write_u16(ring_offset, descriptor)?;
        fence(Ordering::Release);
        self.available_index = self.available_index.wrapping_add(1);
        self.available.write_u16(2, self.available_index)?;
        Ok(())
    }

    fn used_index(self) -> Result<u16, VirtioNetError> {
        fence(Ordering::Acquire);
        Ok(self.used.read_u16(2)?)
    }

    fn used_element(self, index: u16) -> Result<(u32, u32), VirtioNetError> {
        let offset = 4u64
            .checked_add(
                u64::from(index % self.size)
                    .checked_mul(8)
                    .ok_or(VirtioNetError::QueueAddressOverflow)?,
            )
            .ok_or(VirtioNetError::QueueAddressOverflow)?;
        Ok((self.used.read_u32(offset)?, self.used.read_u32(offset + 4)?))
    }
}

#[derive(Debug)]
pub struct VirtioNetRuntime {
    pub address: PciAddress,
    pub mmio_base: u64,
    pub common_config_length: u32,
    pub notify_multiplier: u32,
    pub device_config_length: u32,
    pub bus_master_enabled: bool,
    pub mac_address: [u8; 6],
    pub link_up: bool,
    pub features: u64,
    pub rx_queue_size: u16,
    pub tx_queue_size: u16,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub network: NetworkConfiguration,
    pub external_network: bool,
    pub interrupt_vector: Option<u8>,
    pub interrupt_mode: PciInterruptMode,
    pub interrupt_count: u64,
    pub interrupt_driven: bool,
    pub failure: Option<VirtioNetError>,
    next_frame_address: Option<u64>,
    common: MmioRegion,
    notify: MmioRegion,
    device_config: MmioRegion,
    pci_resources: PciDeviceResources,
    notify_offsets: [u16; 2],
    rx_queue: VirtQueue,
    tx_queue: VirtQueue,
    rx_buffers: [DmaPage; QUEUE_SIZE_LIMIT],
    tx_buffer: DmaPage,
    gateway_mac: Option<[u8; 6]>,
    external_receive_diagnostics: u8,
}

#[cfg(target_os = "none")]
static VIRTIO_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "none")]
fn virtio_interrupt_handler() {
    VIRTIO_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);
}

impl VirtioNetRuntime {
    pub fn next_frame_address(&self) -> Option<u64> {
        self.next_frame_address
    }

    pub fn is_ready(&self) -> bool {
        self.failure.is_none()
            && self.features & VIRTIO_F_VERSION_1 != 0
            && self.features & VIRTIO_NET_F_MAC != 0
            && self.rx_queue_size != 0
            && self.tx_queue_size != 0
    }

    #[cfg(target_os = "none")]
    pub fn prepare_interrupts(&mut self) -> Result<u8, VirtioNetError> {
        if let Some(vector) = self.interrupt_vector {
            return Ok(vector);
        }
        let vector = crate::interrupts::register_device_handler(virtio_interrupt_handler)?;
        VIRTIO_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        self.interrupt_vector = Some(vector);
        Ok(vector)
    }

    #[cfg(target_os = "none")]
    pub fn enable_msi(&mut self, destination_apic_id: u32) -> Result<PciMsiRoute, VirtioNetError> {
        let vector = self
            .interrupt_vector
            .ok_or(VirtioNetError::InterruptsNotPrepared)?;
        self.pci_resources
            .enable_msi(vector, destination_apic_id)
            .map_err(Into::into)
    }

    #[cfg(target_os = "none")]
    pub fn enable_msix(
        &mut self,
        destination_apic_id: u32,
    ) -> Result<PciMsixRoute, VirtioNetError> {
        let vector = self
            .interrupt_vector
            .ok_or(VirtioNetError::InterruptsNotPrepared)?;
        self.pci_resources
            .enable_msix(vector, destination_apic_id)
            .map_err(Into::into)
    }

    #[cfg(target_os = "none")]
    pub fn arm_msi_interrupts(&mut self, route: PciMsiRoute) -> Result<(), VirtioNetError> {
        if self.interrupt_vector != Some(route.vector) {
            return Err(VirtioNetError::InterruptsNotPrepared);
        }
        self.interrupt_mode = PciInterruptMode::Msi;
        self.interrupt_driven = true;
        VIRTIO_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(target_os = "none")]
    pub fn arm_msix_interrupts(&mut self, route: PciMsixRoute) -> Result<(), VirtioNetError> {
        if self.interrupt_vector != Some(route.vector) {
            return Err(VirtioNetError::InterruptsNotPrepared);
        }
        self.configure_queue_interrupts()?;
        self.interrupt_mode = PciInterruptMode::Msix;
        self.interrupt_driven = true;
        VIRTIO_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(target_os = "none")]
    fn configure_queue_interrupts(&mut self) -> Result<(), VirtioNetError> {
        // Use one MSI-X table entry for both queues. The common-config vector remains disabled;
        // only RX/TX queue completions need to wake the shared handler.
        self.common.write_u16(COMMON_MSIX_CONFIG, u16::MAX)?;
        for queue in [RX_QUEUE_INDEX, TX_QUEUE_INDEX] {
            self.common.write_u16(QUEUE_SELECT, queue)?;
            self.common.write_u16(QUEUE_MSIX_VECTOR, 0)?;
        }
        Ok(())
    }

    pub fn enable_external_network(&mut self) -> Result<(), VirtioNetError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if !self.is_ready() {
            return Err(VirtioNetError::NetworkUnavailable);
        }
        self.external_network = true;
        self.network = NetworkConfiguration::static_default();
        self.gateway_mac = None;
        self.external_receive_diagnostics = 0;
        Ok(())
    }

    pub fn network_configuration(&self) -> NetworkConfiguration {
        self.network
    }

    pub fn acquire_dhcp(&mut self) -> Result<NetworkConfiguration, VirtioNetError> {
        let transaction_id = 0x5255_5354u32.wrapping_add(u32::from(
            NETWORK_IDENTIFICATION.fetch_add(1, Ordering::AcqRel),
        ));
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
                gateway: ack.gateway.unwrap_or(DEFAULT_NETWORK_GATEWAY_IP),
                dns: ack.dns.unwrap_or(DEFAULT_NETWORK_DNS_IP),
                dhcp_server: ack.server.unwrap_or(server),
                lease_seconds: ack.lease_seconds.unwrap_or(0),
                dhcp: true,
            };
            self.network = configuration;
            self.gateway_mac = None;
            return Ok(configuration);
        }
        Err(VirtioNetError::NoPacket)
    }

    /// Renew the currently active DHCP lease without dropping the configured address.
    pub fn renew_dhcp(&mut self) -> Result<NetworkConfiguration, VirtioNetError> {
        if !self.external_network {
            return Err(VirtioNetError::ExternalNetworkNotEnabled);
        }
        if !self.network.dhcp {
            return Err(VirtioNetError::NoPacket);
        }

        let transaction_id = 0x5255_5354u32.wrapping_add(u32::from(
            NETWORK_IDENTIFICATION.fetch_add(1, Ordering::AcqRel),
        ));
        let (request, request_length) =
            dhcp::build_renew_request(transaction_id, self.mac_address, self.network.address);
        self.transmit_dhcp_renewal(&request[..request_length])?;
        let ack = self.receive_dhcp_reply(transaction_id, DHCP_ACK)?;
        if ack.address != self.network.address {
            return Err(VirtioNetError::NoPacket);
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

    fn transmit_dhcp(&mut self, payload: &[u8]) -> Result<(), VirtioNetError> {
        if payload.len() > DHCP_MESSAGE_BUFFER_LENGTH {
            return Err(VirtioNetError::NetworkBufferTooSmall {
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
        self.transmit_frame(&frame)
    }

    fn receive_dhcp_reply(
        &mut self,
        transaction_id: u32,
        expected_message_type: u8,
    ) -> Result<crate::dhcp::DhcpReply, VirtioNetError> {
        for _ in 0..8 {
            let Ok(frame) = self.receive_frame() else {
                continue;
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
        Err(VirtioNetError::NoPacket)
    }

    fn transmit_frame(&mut self, frame: &EthernetFrame) -> Result<(), VirtioNetError> {
        let frame_length = u64::try_from(frame.len()).map_err(|_| DmaError::AddressOverflow)?;
        let total_length = VIRTIO_NET_HEADER_LENGTH
            .checked_add(frame_length)
            .ok_or(DmaError::AddressOverflow)?;
        if total_length > PAGE_SIZE {
            return Err(VirtioNetError::NetworkBufferTooSmall {
                required: usize::try_from(total_length).unwrap_or(usize::MAX),
                available: PAGE_SIZE as usize,
            });
        }
        let header = [0u8; VIRTIO_NET_HEADER_LENGTH as usize];
        self.tx_buffer.clear();
        self.tx_buffer.write_bytes(0, &header)?;
        self.tx_buffer
            .write_bytes(VIRTIO_NET_HEADER_LENGTH, frame.as_bytes())?;
        self.tx_queue.set_descriptor(
            0,
            self.tx_buffer.physical_base,
            u32::try_from(total_length).map_err(|_| DmaError::AddressOverflow)?,
            0,
        )?;
        self.tx_queue.push_available(0)?;
        self.notify_queue(TX_QUEUE_INDEX, self.notify_offsets[1])?;

        let wait_spins = if self.interrupt_driven {
            INTERRUPT_WAIT_SPINS
        } else {
            POLL_SPINS
        };
        for _ in 0..wait_spins {
            let used_index = self.tx_queue.used_index()?;
            if used_index != self.tx_queue.last_used_index {
                let (descriptor, _) = self.tx_queue.used_element(self.tx_queue.last_used_index)?;
                if descriptor != 0 {
                    return Err(VirtioNetError::QueueDescriptorInvalid { descriptor });
                }
                self.tx_queue.last_used_index = used_index;
                self.tx_packets = self.tx_packets.saturating_add(1);
                self.refresh_interrupt_count();
                return Ok(());
            }
            self.wait_for_completion();
        }
        Err(VirtioNetError::TxTimeout)
    }

    fn transmit_dhcp_renewal(&mut self, payload: &[u8]) -> Result<(), VirtioNetError> {
        if payload.len() > DHCP_MESSAGE_BUFFER_LENGTH {
            return Err(VirtioNetError::NetworkBufferTooSmall {
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
        self.transmit_frame(&frame)
    }

    fn receive_frame(&mut self) -> Result<EthernetFrame, VirtioNetError> {
        let wait_spins = if self.interrupt_driven {
            INTERRUPT_WAIT_SPINS
        } else {
            POLL_SPINS
        };
        for _ in 0..wait_spins {
            let used_index = self.rx_queue.used_index()?;
            if used_index == self.rx_queue.last_used_index {
                self.wait_for_completion();
                continue;
            }

            let (descriptor, length) = self.rx_queue.used_element(self.rx_queue.last_used_index)?;
            self.rx_queue.last_used_index = self.rx_queue.last_used_index.wrapping_add(1);
            let descriptor = usize::try_from(descriptor)
                .map_err(|_| VirtioNetError::QueueDescriptorInvalid { descriptor })?;
            if descriptor >= self.rx_queue_size as usize || descriptor >= self.rx_buffers.len() {
                return Err(VirtioNetError::QueueDescriptorInvalid {
                    descriptor: descriptor as u32,
                });
            }
            let frame_length = length
                .checked_sub(VIRTIO_NET_HEADER_LENGTH as u32)
                .ok_or(VirtioNetError::RxFrameTooLarge { length })?;
            if usize::try_from(frame_length).unwrap_or(usize::MAX)
                > crate::net::ETHERNET_MAX_FRAME_LENGTH
            {
                self.recycle_rx_descriptor(descriptor)?;
                return Err(VirtioNetError::RxFrameTooLarge { length });
            }
            let mut bytes = [0u8; crate::net::ETHERNET_MAX_FRAME_LENGTH];
            self.rx_buffers[descriptor].read_bytes(
                VIRTIO_NET_HEADER_LENGTH,
                &mut bytes[..usize::try_from(frame_length).unwrap_or(0)],
            )?;
            let frame = EthernetFrame::parse(&bytes[..usize::try_from(frame_length).unwrap_or(0)]);
            self.recycle_rx_descriptor(descriptor)?;
            let frame = frame?;
            self.rx_packets = self.rx_packets.saturating_add(1);
            self.refresh_interrupt_count();
            return Ok(frame);
        }
        Err(VirtioNetError::NoPacket)
    }

    fn recycle_rx_descriptor(&mut self, descriptor: usize) -> Result<(), VirtioNetError> {
        self.rx_queue.set_descriptor(
            descriptor,
            self.rx_buffers[descriptor].physical_base,
            PAGE_SIZE as u32,
            VIRTQ_DESC_F_WRITE,
        )?;
        self.rx_queue.push_available(descriptor as u16)?;
        self.notify_queue(RX_QUEUE_INDEX, self.notify_offsets[0])
    }

    pub fn send_udp(
        &mut self,
        destination: crate::net::Ipv4Address,
        destination_port: u16,
        payload: &[u8],
    ) -> Result<usize, VirtioNetError> {
        if !self.external_network {
            return Err(VirtioNetError::ExternalNetworkNotEnabled);
        }
        if payload.len() > MAX_NETWORK_PAYLOAD_LENGTH {
            return Err(VirtioNetError::NetworkBufferTooSmall {
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
        self.transmit_frame(&frame)?;
        Ok(payload.len())
    }

    fn resolve_gateway_mac(&mut self) -> Result<[u8; 6], VirtioNetError> {
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
            self.transmit_frame(&frame)?;
            for _ in 0..2 {
                let received = match self.receive_frame() {
                    Ok(frame) => frame,
                    Err(VirtioNetError::NoPacket) => break,
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
                return Ok(mac);
            }
        }
        Err(VirtioNetError::NoPacket)
    }

    pub fn receive_udp(&mut self, buffer: &mut [u8]) -> Result<usize, VirtioNetError> {
        if !self.external_network {
            return Err(VirtioNetError::ExternalNetworkNotEnabled);
        }
        if buffer.len() < NETWORK_RECEIVE_HEADER_LENGTH {
            return Err(VirtioNetError::NetworkBufferTooSmall {
                required: NETWORK_RECEIVE_HEADER_LENGTH,
                available: buffer.len(),
            });
        }
        loop {
            let frame = match self.receive_frame() {
                Ok(frame) => frame,
                Err(VirtioNetError::NoPacket) => return Err(VirtioNetError::NoPacket),
                Err(error) => return Err(error),
            };
            if self.external_receive_diagnostics < RX_DIAGNOSTIC_LIMIT {
                self.external_receive_diagnostics += 1;
            }
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
                return Err(VirtioNetError::NetworkBufferTooSmall {
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

    fn respond_to_arp(&mut self, frame: &EthernetFrame) -> Result<(), VirtioNetError> {
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
        self.transmit_frame(&response_frame)
    }

    fn notify_queue(&self, queue: u16, notify_offset: u16) -> Result<(), VirtioNetError> {
        let offset = u64::from(notify_offset)
            .checked_mul(u64::from(self.notify_multiplier))
            .ok_or(VirtioNetError::QueueAddressOverflow)?;
        self.notify.write_u16(offset, queue)?;
        Ok(())
    }

    fn refresh_interrupt_count(&mut self) {
        #[cfg(target_os = "none")]
        {
            self.interrupt_count = VIRTIO_INTERRUPT_COUNT.load(Ordering::Acquire);
        }
    }

    fn wait_for_completion(&self) {
        #[cfg(target_os = "none")]
        if self.interrupt_driven && x86_64::instructions::interrupts::are_enabled() {
            crate::interrupts::halt();
            return;
        }
        core::hint::spin_loop();
    }

    fn start(&mut self) -> Result<(), VirtioNetError> {
        self.common.write_u8(DEVICE_STATUS, 0)?;
        self.common.write_u8(DEVICE_STATUS, STATUS_ACKNOWLEDGE)?;
        self.common
            .write_u8(DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER)?;

        self.negotiate_features()?;
        self.common.write_u8(
            DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        )?;
        if self.common.read_u8(DEVICE_STATUS)? & STATUS_FEATURES_OK == 0 {
            self.common.write_u8(DEVICE_STATUS, STATUS_FAILED)?;
            return Err(VirtioNetError::FeatureNegotiationFailed);
        }
        if self.common.read_u16(NUM_QUEUES)? < 2 {
            return Err(VirtioNetError::QueueUnavailable { queue: 1 });
        }
        self.rx_queue_size = Self::setup_queue(self.common, RX_QUEUE_INDEX, &mut self.rx_queue)?;
        self.tx_queue_size = Self::setup_queue(self.common, TX_QUEUE_INDEX, &mut self.tx_queue)?;
        self.notify_offsets[0] = self.queue_notify_offset(RX_QUEUE_INDEX)?;
        self.notify_offsets[1] = self.queue_notify_offset(TX_QUEUE_INDEX)?;

        for descriptor in 0..self.rx_queue_size as usize {
            self.rx_buffers[descriptor].clear();
            self.rx_queue.set_descriptor(
                descriptor,
                self.rx_buffers[descriptor].physical_base,
                PAGE_SIZE as u32,
                VIRTQ_DESC_F_WRITE,
            )?;
            self.rx_queue.push_available(descriptor as u16)?;
        }
        self.notify_queue(RX_QUEUE_INDEX, self.notify_offsets[0])?;
        self.common.write_u8(
            DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        )?;
        self.link_up = if self.features & VIRTIO_NET_F_STATUS != 0 {
            self.device_config.read_u16(6)? & VIRTIO_NET_S_LINK_UP != 0
        } else {
            true
        };
        Ok(())
    }

    fn negotiate_features(&mut self) -> Result<(), VirtioNetError> {
        self.common.write_u32(DEVICE_FEATURE_SELECT, 0)?;
        let low = self.common.read_u32(DEVICE_FEATURE)? as u64;
        self.common.write_u32(DEVICE_FEATURE_SELECT, 1)?;
        let high = u64::from(self.common.read_u32(DEVICE_FEATURE)?) << 32;
        let available = low | high;
        if available & VIRTIO_F_VERSION_1 == 0 || available & VIRTIO_NET_F_MAC == 0 {
            self.common.write_u8(DEVICE_STATUS, STATUS_FAILED)?;
            return Err(VirtioNetError::FeatureNegotiationFailed);
        }
        let features = VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC | (available & VIRTIO_NET_F_STATUS);
        self.common.write_u32(DRIVER_FEATURE_SELECT, 0)?;
        self.common.write_u32(DRIVER_FEATURE, features as u32)?;
        self.common.write_u32(DRIVER_FEATURE_SELECT, 1)?;
        self.common
            .write_u32(DRIVER_FEATURE, (features >> 32) as u32)?;
        self.features = features;
        Ok(())
    }

    fn setup_queue(
        common: MmioRegion,
        queue_index: u16,
        queue: &mut VirtQueue,
    ) -> Result<u16, VirtioNetError> {
        common.write_u16(QUEUE_SELECT, queue_index)?;
        let max_size = common.read_u16(QUEUE_SIZE)?;
        if max_size == 0 {
            return Err(VirtioNetError::QueueUnavailable { queue: queue_index });
        }
        let size = max_size.min(QUEUE_SIZE_LIMIT as u16);
        if size < 2 {
            return Err(VirtioNetError::QueueTooSmall {
                queue: queue_index,
                size,
            });
        }
        queue.size = size;
        common.write_u16(QUEUE_SIZE, size)?;
        common.write_u16(QUEUE_MSIX_VECTOR, u16::MAX)?;
        write_address(&common, QUEUE_DESC_LOW, queue.descriptors.physical_base)?;
        write_address(&common, QUEUE_DRIVER_LOW, queue.available.physical_base)?;
        write_address(&common, QUEUE_DEVICE_LOW, queue.used.physical_base)?;
        common.write_u16(QUEUE_ENABLE, 1)?;
        Ok(size)
    }

    fn queue_notify_offset(&self, queue_index: u16) -> Result<u16, VirtioNetError> {
        self.common.write_u16(QUEUE_SELECT, queue_index)?;
        Ok(self.common.read_u16(QUEUE_NOTIFY_OFFSET)?)
    }
}

impl NetworkInterface for VirtioNetRuntime {
    type Error = VirtioNetError;

    fn mac_address(&self) -> crate::net::MacAddress {
        self.mac_address
    }

    fn transmit(&mut self, frame: &EthernetFrame) -> Result<(), Self::Error> {
        self.transmit_frame(frame)
    }

    fn receive(&mut self) -> Result<EthernetFrame, Self::Error> {
        self.receive_frame()
    }
}

pub fn initialize(
    inventory: &PciInventory,
    physical_memory_offset: u64,
    regions: &[MemoryRegion],
    next_frame_address: Option<u64>,
) -> Result<Option<VirtioNetRuntime>, VirtioNetInitFailure> {
    let Some(device) = find_device(inventory) else {
        return Ok(None);
    };
    if !device.memory_space_enabled() {
        return Err(VirtioNetInitFailure {
            error: VirtioNetError::MemorySpaceDisabled,
            next_frame_address,
        });
    }

    let common_cap = match device.virtio_capability(VIRTIO_PCI_CAP_COMMON_CONFIG) {
        Some(capability) => capability,
        None => {
            return Err(VirtioNetInitFailure {
                error: VirtioNetError::MissingCapability {
                    cfg_type: VIRTIO_PCI_CAP_COMMON_CONFIG,
                },
                next_frame_address,
            });
        }
    };
    let notify_cap = match device.virtio_capability(VIRTIO_PCI_CAP_NOTIFY_CONFIG) {
        Some(capability) => capability,
        None => {
            return Err(VirtioNetInitFailure {
                error: VirtioNetError::MissingCapability {
                    cfg_type: VIRTIO_PCI_CAP_NOTIFY_CONFIG,
                },
                next_frame_address,
            });
        }
    };
    let device_cap = match device.virtio_capability(VIRTIO_PCI_CAP_DEVICE_CONFIG) {
        Some(capability) => capability,
        None => {
            return Err(VirtioNetInitFailure {
                error: VirtioNetError::MissingCapability {
                    cfg_type: VIRTIO_PCI_CAP_DEVICE_CONFIG,
                },
                next_frame_address,
            });
        }
    };

    let mut resources = PciDeviceResources::new(device, physical_memory_offset);
    if let Err(error) = resources.enable_bus_master() {
        return Err(VirtioNetInitFailure {
            error: error.into(),
            next_frame_address,
        });
    }
    let device = resources.device();
    let common = match resources.claim_mmio_subregion(
        usize::from(common_cap.bar),
        u64::from(common_cap.region_offset),
        u64::from(common_cap.region_length),
    ) {
        Ok(region) => region,
        Err(error) => {
            return Err(VirtioNetInitFailure {
                error: error.into(),
                next_frame_address,
            });
        }
    };
    let notify = match resources.claim_mmio_subregion(
        usize::from(notify_cap.bar),
        u64::from(notify_cap.region_offset),
        u64::from(notify_cap.region_length),
    ) {
        Ok(region) => region,
        Err(error) => {
            return Err(VirtioNetInitFailure {
                error: error.into(),
                next_frame_address,
            });
        }
    };
    let device_config = match resources.claim_mmio_subregion(
        usize::from(device_cap.bar),
        u64::from(device_cap.region_offset),
        u64::from(device_cap.region_length),
    ) {
        Ok(region) => region,
        Err(error) => {
            return Err(VirtioNetInitFailure {
                error: error.into(),
                next_frame_address,
            });
        }
    };
    if device_config.length() < 6 {
        return Err(VirtioNetInitFailure {
            error: VirtioNetError::InvalidMac,
            next_frame_address,
        });
    }
    let mac_address = match read_mac_address(device_config) {
        Ok(mac) if valid_mac_address(mac) => mac,
        Ok(_) => {
            return Err(VirtioNetInitFailure {
                error: VirtioNetError::InvalidMac,
                next_frame_address,
            });
        }
        Err(error) => {
            return Err(VirtioNetInitFailure {
                error: error.into(),
                next_frame_address,
            });
        }
    };

    let dma_start = next_frame_address.unwrap_or(0).max(DMA_ALLOCATION_FLOOR);
    let mut frame_allocator = FrameAllocator::starting_at(regions, dma_start);
    let rx_queue = match VirtQueue::allocate(&mut frame_allocator, physical_memory_offset) {
        Ok(queue) => queue,
        Err(error) => {
            return Err(VirtioNetInitFailure {
                error,
                next_frame_address: frame_allocator.next_available_address(),
            });
        }
    };
    let tx_queue = match VirtQueue::allocate(&mut frame_allocator, physical_memory_offset) {
        Ok(queue) => queue,
        Err(error) => {
            return Err(VirtioNetInitFailure {
                error,
                next_frame_address: frame_allocator.next_available_address(),
            });
        }
    };
    let mut rx_buffers = [DmaPage::empty(); QUEUE_SIZE_LIMIT];
    for buffer in &mut rx_buffers {
        *buffer = match allocate_page(&mut frame_allocator, physical_memory_offset) {
            Ok(page) => page,
            Err(error) => {
                return Err(VirtioNetInitFailure {
                    error,
                    next_frame_address: frame_allocator.next_available_address(),
                });
            }
        };
    }
    let tx_buffer = match allocate_page(&mut frame_allocator, physical_memory_offset) {
        Ok(page) => page,
        Err(error) => {
            return Err(VirtioNetInitFailure {
                error,
                next_frame_address: frame_allocator.next_available_address(),
            });
        }
    };

    let mut runtime = VirtioNetRuntime {
        address: device.address,
        mmio_base: common.physical_base(),
        common_config_length: common_cap.region_length,
        notify_multiplier: notify_cap.notify_off_multiplier,
        device_config_length: device_cap.region_length,
        bus_master_enabled: device.bus_master_enabled(),
        mac_address,
        link_up: false,
        features: 0,
        rx_queue_size: 0,
        tx_queue_size: 0,
        rx_packets: 0,
        tx_packets: 0,
        network: NetworkConfiguration::static_default(),
        external_network: false,
        interrupt_vector: None,
        interrupt_mode: PciInterruptMode::None,
        interrupt_count: 0,
        interrupt_driven: false,
        failure: None,
        next_frame_address: frame_allocator.next_available_address(),
        common,
        notify,
        device_config,
        pci_resources: resources,
        notify_offsets: [0; 2],
        rx_queue,
        tx_queue,
        rx_buffers,
        tx_buffer,
        gateway_mac: None,
        external_receive_diagnostics: 0,
    };
    if let Err(error) = runtime.start() {
        runtime.failure = Some(error);
    }
    runtime.next_frame_address = frame_allocator.next_available_address();
    Ok(Some(runtime))
}

fn find_device(inventory: &PciInventory) -> Option<PciDevice> {
    inventory
        .devices()
        .iter()
        .find(|device| {
            device.vendor_id == VIRTIO_VENDOR_ID
                && device.device_id == VIRTIO_NET_DEVICE_ID
                && device.class_code == 0x02
        })
        .copied()
}

fn allocate_page(
    allocator: &mut FrameAllocator<'_>,
    physical_memory_offset: u64,
) -> Result<DmaPage, VirtioNetError> {
    let frame = allocator.next().ok_or(DmaError::NoFrame)?;
    let physical_base = frame.start_address();
    let virtual_base = physical_memory_offset
        .checked_add(physical_base)
        .ok_or(DmaError::AddressOverflow)?;
    let page = DmaPage {
        physical_base,
        virtual_base,
    };
    page.clear();
    Ok(page)
}

fn write_address(region: &MmioRegion, offset: u64, address: u64) -> Result<(), VirtioNetError> {
    region.write_u32(offset, address as u32)?;
    region.write_u32(offset + 4, (address >> 32) as u32)?;
    Ok(())
}

fn read_mac_address(device_config: MmioRegion) -> Result<[u8; 6], MmioError> {
    Ok([
        device_config.read_u8(0)?,
        device_config.read_u8(1)?,
        device_config.read_u8(2)?,
        device_config.read_u8(3)?,
        device_config.read_u8(4)?,
        device_config.read_u8(5)?,
    ])
}

fn valid_mac_address(mac_address: [u8; 6]) -> bool {
    let all_zero = mac_address.iter().all(|byte| *byte == 0);
    let all_ones = mac_address.iter().all(|byte| *byte == u8::MAX);
    !all_zero && !all_ones
}

#[cfg(test)]
mod tests {
    use super::valid_mac_address;

    #[test]
    fn rejects_invalid_mac_addresses() {
        assert!(!valid_mac_address([0; 6]));
        assert!(!valid_mac_address([u8::MAX; 6]));
        assert!(valid_mac_address([0x52, 0x54, 0, 0x12, 0x34, 0x56]));
    }
}
