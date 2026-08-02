use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

use bootloader_api::info::MemoryRegion;
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
    PciMsiRoute, PciMsixRoute, PciResourceError,
};

const INTEL_VENDOR_ID: u16 = 0x8086;
const E1000_DEVICE_ID: u16 = 0x100e;
const E1000E_DEVICE_ID: u16 = 0x10d3;
const E1000_MMIO_LENGTH: u64 = 0x20_000;

const REG_CTRL: u64 = 0x0000;
const REG_STATUS: u64 = 0x0008;
const REG_MDIC: u64 = 0x0020;
const REG_ICR: u64 = 0x00c0;
const REG_IMS: u64 = 0x00d0;
const REG_IMC: u64 = 0x00d8;
const REG_RCTL: u64 = 0x0100;
const REG_TCTL: u64 = 0x0400;
const REG_TIPG: u64 = 0x0410;
const REG_RDBAL: u64 = 0x2800;
const REG_RDBAH: u64 = 0x2804;
const REG_RDLEN: u64 = 0x2808;
const REG_RDH: u64 = 0x2810;
const REG_RDT: u64 = 0x2818;
const REG_TDBAL: u64 = 0x3800;
const REG_TDBAH: u64 = 0x3804;
const REG_TDLEN: u64 = 0x3808;
const REG_TDH: u64 = 0x3810;
const REG_TDT: u64 = 0x3818;
const REG_TXDCTL: u64 = 0x3828;
const REG_RAL0: u64 = 0x5400;
const REG_RAH0: u64 = 0x5404;

const TX_RING_SIZE: usize = 8;
const RX_RING_SIZE: usize = 8;
const DESCRIPTOR_SIZE: u64 = 16;

const TXD_CMD_EOP: u8 = 1 << 0;
const TXD_CMD_IFCS: u8 = 1 << 1;
const TXD_CMD_RS: u8 = 1 << 3;
const TXD_STATUS_DD: u8 = 1 << 0;
const RXD_STATUS_DD: u8 = 1 << 0;
const RXD_STATUS_EOP: u8 = 1 << 1;

const TCTL_ENABLE: u32 = 1 << 1;
const TCTL_PAD_SHORT_PACKETS: u32 = 1 << 3;
const TCTL_COLLISION_THRESHOLD: u32 = 0x10 << 4;
const TCTL_COLLISION_DISTANCE: u32 = 0x40 << 12;
const TIPG_DEFAULT: u32 = 0x0060_200a;

const RCTL_ENABLE: u32 = 1 << 1;
const RCTL_BROADCAST_ACCEPT: u32 = 1 << 15;
const RCTL_STRIP_CRC: u32 = 1 << 26;

const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
const MDIC_WRITE: u32 = 1 << 26;
const MDIC_PHY_ADDRESS: u32 = 1 << 21;
const E1000_INTERRUPT_TXDW: u32 = 1 << 0;
const E1000_INTERRUPT_RXDW: u32 = 1 << 7;
const E1000_INTERRUPT_MASK: u32 = E1000_INTERRUPT_TXDW | E1000_INTERRUPT_RXDW;
const PHY_BASIC_MODE_LOOPBACK: u16 = 1 << 14;
const PHY_BASIC_MODE_FULL_DUPLEX: u16 = 1 << 8;
const PHY_BASIC_MODE_SPEED_1000: u16 = 1 << 6;
const PHY_BASIC_MODE_AUTONEGOTIATION: u16 = 1 << 12;
const PHY_LOOPBACK_COMMAND: u16 = PHY_BASIC_MODE_LOOPBACK
    | PHY_BASIC_MODE_FULL_DUPLEX
    | PHY_BASIC_MODE_SPEED_1000
    | PHY_BASIC_MODE_AUTONEGOTIATION;

const POLL_SPINS: usize = 1_000_000;
const RX_SETTLE_SPINS: usize = 5_000_000;
pub const NETWORK_RECEIVE_HEADER_LENGTH: usize = 6;
pub const MAX_NETWORK_PAYLOAD_LENGTH: usize = 1024;
const DEFAULT_NETWORK_GUEST_IP: crate::net::Ipv4Address = [10, 0, 2, 15];
const DEFAULT_NETWORK_SUBNET_MASK: crate::net::Ipv4Address = [255, 255, 255, 0];
const DEFAULT_NETWORK_GATEWAY_IP: crate::net::Ipv4Address = [10, 0, 2, 2];
const DEFAULT_NETWORK_DNS_IP: crate::net::Ipv4Address = [10, 0, 2, 3];
const DHCP_ZERO_IP: crate::net::Ipv4Address = [0, 0, 0, 0];
const DHCP_BROADCAST_IP: crate::net::Ipv4Address = [255, 255, 255, 255];
const ETHERNET_BROADCAST: [u8; 6] = [u8::MAX; 6];
const NETWORK_SOURCE_PORT: u16 = 49_000;

static E1000_INTERRUPT_MMIO: Mutex<Option<MmioRegion>> = Mutex::new(None);
static E1000_INTERRUPT_CAUSE: AtomicU32 = AtomicU32::new(0);
static E1000_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);
static NETWORK_IDENTIFICATION: AtomicU16 = AtomicU16::new(0x2000);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    NoFrame,
    AddressOverflow,
    Unaligned { offset: u64, alignment: u64 },
    OutOfBounds { offset: u64, size: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E1000Error {
    Resources(PciResourceError),
    Mmio(MmioError),
    Dma(DmaError),
    Frame(EthernetFrameError),
    Ipv4(Ipv4PacketError),
    Udp(UdpDatagramError),
    Dhcp(crate::dhcp::DhcpError),
    MemorySpaceDisabled,
    InvalidMac,
    MdicTimeout,
    MdicError(u32),
    InterruptRegistration(crate::interrupts::DeviceInterruptError),
    InterruptsNotPrepared,
    InterruptsNotArmed,
    InterruptTimeout {
        cause: u32,
        rctl: u32,
        tdh: u32,
        rdh: u32,
        rdt: u32,
        mdic: u32,
    },
    TxCompletionMissing,
    RxFrameTooLarge {
        length: u16,
    },
    RxPacketMismatch,
    ExternalNetworkNotEnabled,
    NoPacket,
    NetworkBufferTooSmall {
        required: usize,
        available: usize,
    },
}

impl From<PciResourceError> for E1000Error {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

impl From<MmioError> for E1000Error {
    fn from(error: MmioError) -> Self {
        Self::Mmio(error)
    }
}

impl From<DmaError> for E1000Error {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

impl From<EthernetFrameError> for E1000Error {
    fn from(error: EthernetFrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<Ipv4PacketError> for E1000Error {
    fn from(error: Ipv4PacketError) -> Self {
        Self::Ipv4(error)
    }
}

impl From<UdpDatagramError> for E1000Error {
    fn from(error: UdpDatagramError) -> Self {
        Self::Udp(error)
    }
}

impl From<crate::dhcp::DhcpError> for E1000Error {
    fn from(error: crate::dhcp::DhcpError) -> Self {
        Self::Dhcp(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E1000InitFailure {
    pub error: E1000Error,
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

#[derive(Debug)]
pub struct E1000Runtime {
    pub address: crate::pci::PciAddress,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub mmio_base: u64,
    pub mmio_length: u64,
    pub control: u32,
    pub status: u32,
    pub bus_master_enabled: bool,
    pub mac_address: [u8; 6],
    pub tx_completed: bool,
    pub rx_loopback: bool,
    pub packet_length: u16,
    pub rx_frames: u64,
    pub received_ether_type: Option<u16>,
    pub interrupt_gsi: Option<u32>,
    pub interrupt_vector: Option<u8>,
    pub interrupt_mode: PciInterruptMode,
    pub interrupt_count: u64,
    pub interrupt_cause: u32,
    pub interrupt_driven: bool,
    pub external_network: bool,
    pub network: NetworkConfiguration,
    pub failure: Option<E1000Error>,
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

impl E1000Runtime {
    pub fn next_frame_address(&self) -> Option<u64> {
        self.next_frame_address
    }

    pub fn is_ready(&self) -> bool {
        self.failure.is_none() && self.interrupt_driven && self.tx_completed && self.rx_loopback
    }

    pub fn enable_external_network(&mut self) -> Result<(), E1000Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if !self.interrupt_driven {
            return Err(E1000Error::InterruptsNotArmed);
        }
        set_phy_basic_mode(
            self.mmio,
            PHY_BASIC_MODE_FULL_DUPLEX | PHY_BASIC_MODE_SPEED_1000 | PHY_BASIC_MODE_AUTONEGOTIATION,
        )?;
        // Keep the already-live descriptor rings when leaving PHY loopback. Reprogramming TDH
        // and TDT without resetting the device can make QEMU advance the head while omitting
        // descriptor writeback. The software tail advances to the next descriptor instead.
        for _ in 0..RX_SETTLE_SPINS {
            core::hint::spin_loop();
        }
        // The loopback validation consumed and recycled descriptor 0. The receive head has
        // advanced to descriptor 1, so keep the software cursor aligned with that next slot.
        self.rx_next_index = 1;
        let _ = self.mmio.read_u32(REG_ICR)?;
        self.pending_interrupt_cause = 0;
        self.external_receive_diagnostics = 0;
        E1000_INTERRUPT_CAUSE.store(0, Ordering::SeqCst);
        E1000_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        self.external_network = true;
        self.gateway_mac = None;
        self.network = NetworkConfiguration::static_default();
        Ok(())
    }

    pub fn acquire_dhcp(&mut self) -> Result<NetworkConfiguration, E1000Error> {
        if !self.external_network {
            return Err(E1000Error::ExternalNetworkNotEnabled);
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
        Err(E1000Error::NoPacket)
    }

    /// Renew the currently active DHCP lease without dropping the configured address.
    pub fn renew_dhcp(&mut self) -> Result<NetworkConfiguration, E1000Error> {
        if !self.external_network {
            return Err(E1000Error::ExternalNetworkNotEnabled);
        }
        if !self.network.dhcp {
            return Err(E1000Error::NoPacket);
        }

        let transaction_id = 0x5255_5354u32
            .wrapping_add(NETWORK_IDENTIFICATION.fetch_add(1, Ordering::AcqRel) as u32);
        let (request, request_length) =
            dhcp::build_renew_request(transaction_id, self.mac_address, self.network.address);
        self.transmit_dhcp_renewal(&request[..request_length])?;
        let ack = self.receive_dhcp_reply(transaction_id, DHCP_ACK)?;
        if ack.address != self.network.address {
            return Err(E1000Error::NoPacket);
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

    fn transmit_dhcp(&mut self, payload: &[u8]) -> Result<(), E1000Error> {
        if payload.len() > DHCP_MESSAGE_BUFFER_LENGTH {
            return Err(E1000Error::NetworkBufferTooSmall {
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

    fn transmit_dhcp_renewal(&mut self, payload: &[u8]) -> Result<(), E1000Error> {
        if payload.len() > DHCP_MESSAGE_BUFFER_LENGTH {
            return Err(E1000Error::NetworkBufferTooSmall {
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

    fn receive_dhcp_reply(
        &mut self,
        transaction_id: u32,
        expected_message_type: u8,
    ) -> Result<crate::dhcp::DhcpReply, E1000Error> {
        for _ in 0..8 {
            let frame = match self.receive_frame() {
                Ok(frame) => frame,
                Err(E1000Error::InterruptTimeout { .. }) => return Err(E1000Error::NoPacket),
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
        Err(E1000Error::NoPacket)
    }

    pub fn network_configuration(&self) -> NetworkConfiguration {
        self.network
    }

    pub fn prepare_interrupts(&mut self) -> Result<u8, E1000Error> {
        if let Some(vector) = self.interrupt_vector {
            return Ok(vector);
        }

        let vector = crate::interrupts::register_device_handler(e1000_interrupt_handler)
            .map_err(E1000Error::InterruptRegistration)?;
        *E1000_INTERRUPT_MMIO.lock() = Some(self.mmio);
        let _ = self.mmio.read_u32(REG_ICR)?;
        E1000_INTERRUPT_CAUSE.store(0, Ordering::SeqCst);
        E1000_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        self.interrupt_vector = Some(vector);
        Ok(vector)
    }

    pub fn enable_msi(&mut self, destination_apic_id: u32) -> Result<PciMsiRoute, E1000Error> {
        let vector = self
            .interrupt_vector
            .ok_or(E1000Error::InterruptsNotPrepared)?;
        self.pci_resources
            .enable_msi(vector, destination_apic_id)
            .map_err(Into::into)
    }

    pub fn enable_msix(&mut self, destination_apic_id: u32) -> Result<PciMsixRoute, E1000Error> {
        let vector = self
            .interrupt_vector
            .ok_or(E1000Error::InterruptsNotPrepared)?;
        self.pci_resources
            .enable_msix(vector, destination_apic_id)
            .map_err(Into::into)
    }

    pub fn arm_interrupts(&mut self, gsi: u32) -> Result<(), E1000Error> {
        self.arm_interrupts_with_mode(PciInterruptMode::Legacy, Some(gsi))
    }

    pub fn arm_msi_interrupts(&mut self, route: PciMsiRoute) -> Result<(), E1000Error> {
        if self.interrupt_vector != Some(route.vector) {
            return Err(E1000Error::InterruptsNotPrepared);
        }
        self.arm_interrupts_with_mode(PciInterruptMode::Msi, None)
    }

    pub fn arm_msix_interrupts(&mut self, route: PciMsixRoute) -> Result<(), E1000Error> {
        if self.interrupt_vector != Some(route.vector) {
            return Err(E1000Error::InterruptsNotPrepared);
        }
        self.arm_interrupts_with_mode(PciInterruptMode::Msix, None)
    }

    fn arm_interrupts_with_mode(
        &mut self,
        mode: PciInterruptMode,
        gsi: Option<u32>,
    ) -> Result<(), E1000Error> {
        if self.interrupt_vector.is_none() {
            return Err(E1000Error::InterruptsNotPrepared);
        }
        if self.interrupt_driven {
            return Ok(());
        }

        self.mmio.write_u32(REG_IMC, u32::MAX)?;
        let _ = self.mmio.read_u32(REG_ICR)?;
        E1000_INTERRUPT_CAUSE.store(0, Ordering::SeqCst);
        E1000_INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        self.mmio.write_u32(REG_IMS, E1000_INTERRUPT_MASK)?;
        self.interrupt_gsi = gsi;
        self.interrupt_mode = mode;
        self.interrupt_driven = true;
        Ok(())
    }

    pub fn send_loopback(&mut self, frame: &EthernetFrame) -> Result<EthernetFrame, E1000Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if !self.interrupt_driven {
            return Err(E1000Error::InterruptsNotArmed);
        }
        // QEMU defers its receive queue for one virtual second after RCTL is enabled. Let that
        // transition settle before the loopback frame is submitted, so this exercises the normal
        // RX path rather than being discarded by the emulated queue guard.
        for _ in 0..RX_SETTLE_SPINS {
            core::hint::spin_loop();
        }
        let expected_mac = <Self as NetworkInterface>::mac_address(self);
        match <Self as NetworkInterface>::transmit(self, frame)
            .and_then(|()| <Self as NetworkInterface>::receive(self))
        {
            Ok(received)
                if received.as_bytes() == frame.as_bytes()
                    && received.destination() == expected_mac
                    && received.source() == expected_mac =>
            {
                self.rx_loopback = true;
                Ok(received)
            }
            Ok(_) => {
                let error = E1000Error::RxPacketMismatch;
                self.failure = Some(error);
                Err(error)
            }
            Err(error) => {
                self.failure = Some(error);
                Err(error)
            }
        }
    }

    fn transmit_frame(&mut self, frame: &EthernetFrame) -> Result<(), E1000Error> {
        self.tx_buffer.write_bytes(0, frame.as_bytes())?;
        let index = self.tx_next_index;
        let descriptor_offset = (index as u64) * DESCRIPTOR_SIZE;
        write_tx_descriptor(
            self.tx_ring,
            descriptor_offset,
            self.tx_buffer.physical_base,
            frame.len(),
        )?;
        self.mmio
            .write_u32(REG_TDT, ((index + 1) % TX_RING_SIZE) as u32)?;
        wait_for_tx_completion(self, index)?;

        let tx_status = self.tx_ring.read_u8(descriptor_offset + 12)?;
        if tx_status & TXD_STATUS_DD == 0 {
            return Err(E1000Error::TxCompletionMissing);
        }
        self.tx_next_index = (index + 1) % TX_RING_SIZE;
        self.tx_completed = true;
        Ok(())
    }

    fn receive_frame(&mut self) -> Result<EthernetFrame, E1000Error> {
        loop {
            let index = self.rx_next_index;
            let descriptor_offset = (index as u64) * DESCRIPTOR_SIZE;
            let status = self.rx_ring.read_u8(descriptor_offset + 12)?;
            let packet_length = self.rx_ring.read_u16(descriptor_offset + 8)?;
            if status & (RXD_STATUS_DD | RXD_STATUS_EOP) != (RXD_STATUS_DD | RXD_STATUS_EOP) {
                wait_for_interrupt(self, E1000_INTERRUPT_RXDW)?;
                // A TX completion can arrive with a stale RX cause while the emulated link is
                // transitioning out of PHY loopback. Recheck the descriptor instead of treating
                // the interrupt as a packet.
                if self.external_network && self.external_receive_diagnostics < 4 {
                    self.external_receive_diagnostics += 1;
                    crate::kprintln!(
                        "net: external rx stale descriptor index={} status=0x{:02x} length={} rdh={} rdt={} status=degraded",
                        index,
                        status,
                        packet_length,
                        self.mmio.read_u32(REG_RDH).unwrap_or(u32::MAX),
                        self.mmio.read_u32(REG_RDT).unwrap_or(u32::MAX)
                    );
                }
                continue;
            }
            if usize::from(packet_length) > crate::net::ETHERNET_MAX_FRAME_LENGTH {
                recycle_rx_descriptor(self, index)?;
                return Err(E1000Error::RxFrameTooLarge {
                    length: packet_length,
                });
            }

            let mut bytes = [0u8; crate::net::ETHERNET_MAX_FRAME_LENGTH];
            self.rx_buffers[index].read_bytes(0, &mut bytes[..usize::from(packet_length)])?;
            let frame = EthernetFrame::parse(&bytes[..usize::from(packet_length)]);
            recycle_rx_descriptor(self, index)?;
            let frame = frame?;
            self.packet_length = packet_length;
            self.rx_frames = self.rx_frames.saturating_add(1);
            self.received_ether_type = Some(frame.ether_type());
            return Ok(frame);
        }
    }

    pub fn send_udp(
        &mut self,
        destination: crate::net::Ipv4Address,
        destination_port: u16,
        payload: &[u8],
    ) -> Result<usize, E1000Error> {
        if !self.external_network {
            return Err(E1000Error::ExternalNetworkNotEnabled);
        }
        if payload.len() > MAX_NETWORK_PAYLOAD_LENGTH {
            return Err(E1000Error::NetworkBufferTooSmall {
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
        let frame = crate::net::EthernetFrame::new(
            gateway_mac,
            self.mac_address,
            crate::net::ETHER_TYPE_IPV4,
            packet.as_bytes(),
        )?;
        self.transmit_frame(&frame)?;
        Ok(payload.len())
    }

    fn resolve_gateway_mac(&mut self) -> Result<[u8; 6], E1000Error> {
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
            [u8::MAX; 6],
            self.mac_address,
            crate::net::ETHER_TYPE_ARP,
            &request,
        )?;
        for _ in 0..2 {
            self.transmit_frame(&frame)?;
            for _ in 0..2 {
                let received = match self.receive_frame() {
                    Ok(frame) => frame,
                    Err(E1000Error::InterruptTimeout { .. }) => break,
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
                crate::kprintln!(
                    "net: arp gateway resolved mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} status=ready",
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
        Err(E1000Error::NoPacket)
    }

    pub fn receive_udp(&mut self, buffer: &mut [u8]) -> Result<usize, E1000Error> {
        if !self.external_network {
            return Err(E1000Error::ExternalNetworkNotEnabled);
        }
        if buffer.len() < NETWORK_RECEIVE_HEADER_LENGTH {
            return Err(E1000Error::NetworkBufferTooSmall {
                required: NETWORK_RECEIVE_HEADER_LENGTH,
                available: buffer.len(),
            });
        }
        loop {
            let frame = match self.receive_frame() {
                Ok(frame) => frame,
                Err(error @ E1000Error::InterruptTimeout { .. }) => {
                    if self.external_receive_diagnostics < 4 {
                        self.external_receive_diagnostics += 1;
                        crate::kprintln!(
                            "net: external rx timeout detail={:?} status=degraded",
                            error
                        );
                    }
                    return Err(E1000Error::NoPacket);
                }
                Err(error) => return Err(error),
            };
            if self.rx_frames <= 8 {
                crate::kprintln!(
                    "net: external rx ether_type=0x{:04x} length={} status=ready",
                    frame.ether_type(),
                    frame.len()
                );
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
                return Err(E1000Error::NetworkBufferTooSmall {
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

    fn respond_to_arp(&mut self, frame: &EthernetFrame) -> Result<(), E1000Error> {
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
        crate::kprintln!(
            "net: arp request from {}.{}.{}.{} status=ready",
            sender_ip[0],
            sender_ip[1],
            sender_ip[2],
            sender_ip[3]
        );
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
        self.transmit_frame(&response_frame)?;
        crate::kprintln!("net: arp response sent status=ready");
        Ok(())
    }
}

impl NetworkInterface for E1000Runtime {
    type Error = E1000Error;

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
) -> Result<Option<E1000Runtime>, E1000InitFailure> {
    let Some(device) = find_device(inventory) else {
        return Ok(None);
    };

    if !device.memory_space_enabled() {
        return Err(E1000InitFailure {
            error: E1000Error::MemorySpaceDisabled,
            next_frame_address,
        });
    }

    let mut resources = PciDeviceResources::new(device, physical_memory_offset);
    resources
        .enable_bus_master()
        .map_err(|error| E1000InitFailure {
            error: error.into(),
            next_frame_address,
        })?;
    let device = resources.device();
    let mmio = resources
        .claim_mmio(0, E1000_MMIO_LENGTH)
        .map_err(|error| E1000InitFailure {
            error: error.into(),
            next_frame_address,
        })?;
    let control = mmio.read_u32(REG_CTRL).map_err(|error| E1000InitFailure {
        error: error.into(),
        next_frame_address,
    })?;
    let status = mmio
        .read_u32(REG_STATUS)
        .map_err(|error| E1000InitFailure {
            error: error.into(),
            next_frame_address,
        })?;
    let mac_address = read_mac_address(mmio).map_err(|error| E1000InitFailure {
        error: error.into(),
        next_frame_address,
    })?;
    if !valid_mac_address(mac_address) {
        return Err(E1000InitFailure {
            error: E1000Error::InvalidMac,
            next_frame_address,
        });
    }

    let mut frame_allocator = FrameAllocator::starting_at(regions, next_frame_address.unwrap_or(0));
    let layout =
        allocate_layout(&mut frame_allocator, physical_memory_offset).map_err(|error| {
            E1000InitFailure {
                error: error.into(),
                next_frame_address: frame_allocator.next_available_address(),
            }
        })?;

    let mut runtime = E1000Runtime {
        address: device.address,
        interrupt_line: device.interrupt_line,
        interrupt_pin: device.interrupt_pin,
        mmio_base: mmio.physical_base(),
        mmio_length: mmio.length(),
        control,
        status,
        bus_master_enabled: device.bus_master_enabled(),
        mac_address,
        tx_completed: false,
        rx_loopback: false,
        packet_length: 0,
        rx_frames: 0,
        received_ether_type: None,
        interrupt_gsi: None,
        interrupt_vector: None,
        interrupt_mode: PciInterruptMode::None,
        interrupt_count: 0,
        interrupt_cause: 0,
        interrupt_driven: false,
        external_network: false,
        network: NetworkConfiguration::static_default(),
        failure: None,
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
    runtime.next_frame_address = frame_allocator.next_available_address();
    Ok(Some(runtime))
}

fn find_device(inventory: &PciInventory) -> Option<PciDevice> {
    inventory
        .devices()
        .iter()
        .find(|device| {
            device.vendor_id == INTEL_VENDOR_ID
                && matches!(device.device_id, E1000_DEVICE_ID | E1000E_DEVICE_ID)
        })
        .copied()
}

fn e1000_interrupt_handler() {
    let mmio = E1000_INTERRUPT_MMIO.lock().as_ref().copied();
    let Some(mmio) = mmio else {
        return;
    };
    let Ok(cause) = mmio.read_u32(REG_ICR) else {
        return;
    };
    if cause != 0 {
        E1000_INTERRUPT_CAUSE.fetch_or(cause, Ordering::SeqCst);
        E1000_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);
    }
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

    fn write_u8(self, offset: u64, value: u8) -> Result<(), DmaError> {
        let pointer = self.pointer(offset, 1, 1)?;
        // SAFETY: `pointer` was bounds-checked against this DMA page.
        unsafe { core::ptr::write_volatile(pointer as *mut u8, value) };
        Ok(())
    }

    fn write_u16(self, offset: u64, value: u16) -> Result<(), DmaError> {
        let pointer = self.pointer(offset, 2, 2)?;
        // SAFETY: `pointer` was bounds-checked and aligned for a 16-bit DMA field.
        unsafe { core::ptr::write_volatile(pointer as *mut u16, value.to_le()) };
        Ok(())
    }

    fn write_u64(self, offset: u64, value: u64) -> Result<(), DmaError> {
        let pointer = self.pointer(offset, 8, 8)?;
        // SAFETY: `pointer` was bounds-checked and aligned for a 64-bit DMA field.
        unsafe { core::ptr::write_volatile(pointer as *mut u64, value.to_le()) };
        Ok(())
    }

    fn read_u8(self, offset: u64) -> Result<u8, DmaError> {
        let pointer = self.pointer(offset, 1, 1)?;
        // SAFETY: `pointer` was bounds-checked against this DMA page.
        Ok(unsafe { core::ptr::read_volatile(pointer as *const u8) })
    }

    fn read_u16(self, offset: u64) -> Result<u16, DmaError> {
        let pointer = self.pointer(offset, 2, 2)?;
        // SAFETY: `pointer` was bounds-checked and aligned for a 16-bit DMA field.
        Ok(u16::from_le(unsafe {
            core::ptr::read_volatile(pointer as *const u16)
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
            *byte = self.read_u8(offset)?;
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

struct DmaLayout {
    tx_ring: DmaPage,
    rx_ring: DmaPage,
    tx_buffer: DmaPage,
    rx_buffers: [DmaPage; RX_RING_SIZE],
}

fn allocate_layout(
    allocator: &mut FrameAllocator<'_>,
    physical_memory_offset: u64,
) -> Result<DmaLayout, DmaError> {
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
) -> Result<DmaPage, DmaError> {
    let physical_base = allocator.next().ok_or(DmaError::NoFrame)?.start_address();
    let virtual_base = physical_memory_offset
        .checked_add(physical_base)
        .ok_or(DmaError::AddressOverflow)?;
    virtual_base
        .checked_add(PAGE_SIZE)
        .ok_or(DmaError::AddressOverflow)?;
    let page = DmaPage {
        physical_base,
        virtual_base,
    };
    page.clear();
    Ok(page)
}

fn configure(runtime: &mut E1000Runtime) -> Result<(), E1000Error> {
    runtime.mmio.write_u32(REG_RCTL, 0)?;
    runtime.mmio.write_u32(REG_TCTL, 0)?;
    configure_tx_ring(runtime)?;
    configure_rx_ring(runtime)?;
    runtime.mmio.write_u32(REG_TIPG, TIPG_DEFAULT)?;
    runtime.mmio.write_u32(
        REG_TCTL,
        TCTL_ENABLE | TCTL_PAD_SHORT_PACKETS | TCTL_COLLISION_THRESHOLD | TCTL_COLLISION_DISTANCE,
    )?;
    runtime.mmio.write_u32(
        REG_RCTL,
        RCTL_ENABLE | RCTL_BROADCAST_ACCEPT | RCTL_STRIP_CRC,
    )?;
    enable_phy_loopback(runtime.mmio)?;
    Ok(())
}

fn configure_tx_ring(runtime: &mut E1000Runtime) -> Result<(), E1000Error> {
    write_ring_base(
        runtime.mmio,
        REG_TDBAL,
        REG_TDBAH,
        runtime.tx_ring.physical_base,
    )?;
    runtime
        .mmio
        .write_u32(REG_TDLEN, (TX_RING_SIZE as u32) * DESCRIPTOR_SIZE as u32)?;
    runtime.mmio.write_u32(REG_TDH, 0)?;
    runtime.mmio.write_u32(REG_TDT, 0)?;
    runtime.mmio.write_u32(REG_TXDCTL, 1)?;
    Ok(())
}

fn configure_rx_ring(runtime: &mut E1000Runtime) -> Result<(), E1000Error> {
    for (index, buffer) in runtime.rx_buffers.iter().copied().enumerate() {
        let offset = (index as u64) * DESCRIPTOR_SIZE;
        runtime.rx_ring.write_u64(offset, buffer.physical_base)?;
        runtime.rx_ring.write_u16(offset + 8, 0)?;
        runtime.rx_ring.write_u16(offset + 10, 0)?;
        runtime.rx_ring.write_u8(offset + 12, 0)?;
        runtime.rx_ring.write_u8(offset + 13, 0)?;
        runtime.rx_ring.write_u16(offset + 14, 0)?;
    }
    write_ring_base(
        runtime.mmio,
        REG_RDBAL,
        REG_RDBAH,
        runtime.rx_ring.physical_base,
    )?;
    runtime
        .mmio
        .write_u32(REG_RDLEN, (RX_RING_SIZE as u32) * DESCRIPTOR_SIZE as u32)?;
    runtime.mmio.write_u32(REG_RDH, 0)?;
    runtime.mmio.write_u32(REG_RDT, (RX_RING_SIZE - 1) as u32)?;
    Ok(())
}

fn write_ring_base(
    mmio: MmioRegion,
    low_register: u64,
    high_register: u64,
    physical_base: u64,
) -> Result<(), E1000Error> {
    mmio.write_u32(low_register, physical_base as u32)?;
    mmio.write_u32(high_register, (physical_base >> 32) as u32)?;
    Ok(())
}

fn enable_phy_loopback(mmio: MmioRegion) -> Result<(), E1000Error> {
    set_phy_basic_mode(mmio, PHY_LOOPBACK_COMMAND)
}

fn set_phy_basic_mode(mmio: MmioRegion, mode: u16) -> Result<(), E1000Error> {
    mmio.write_u32(REG_MDIC, MDIC_WRITE | MDIC_PHY_ADDRESS | u32::from(mode))?;
    for _ in 0..POLL_SPINS {
        let value = mmio.read_u32(REG_MDIC)?;
        if value & MDIC_READY != 0 {
            if value & MDIC_ERROR != 0 {
                return Err(E1000Error::MdicError(value));
            }
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(E1000Error::MdicTimeout)
}

fn wait_for_interrupt(runtime: &mut E1000Runtime, required_cause: u32) -> Result<u32, E1000Error> {
    let mut cause = runtime.pending_interrupt_cause;
    for _ in 0..POLL_SPINS {
        runtime.pending_interrupt_cause |= E1000_INTERRUPT_CAUSE.swap(0, Ordering::SeqCst);
        cause = runtime.pending_interrupt_cause;
        if cause & required_cause != 0 {
            runtime.pending_interrupt_cause &= !required_cause;
            runtime.interrupt_cause |= cause;
            runtime.interrupt_count = E1000_INTERRUPT_COUNT.load(Ordering::SeqCst);
            return Ok(cause);
        }
        if x86_64::instructions::interrupts::are_enabled() {
            crate::interrupts::halt();
        } else {
            core::hint::spin_loop();
        }
    }
    Err(E1000Error::InterruptTimeout {
        cause,
        rctl: runtime.mmio.read_u32(REG_RCTL)?,
        tdh: runtime.mmio.read_u32(REG_TDH)?,
        rdh: runtime.mmio.read_u32(REG_RDH)?,
        rdt: runtime.mmio.read_u32(REG_RDT)?,
        mdic: runtime.mmio.read_u32(REG_MDIC)?,
    })
}

fn wait_for_tx_completion(runtime: &mut E1000Runtime, index: usize) -> Result<u32, E1000Error> {
    let mut cause = runtime.pending_interrupt_cause;
    let descriptor_offset = (index as u64) * DESCRIPTOR_SIZE;
    for _ in 0..POLL_SPINS {
        runtime.pending_interrupt_cause |= E1000_INTERRUPT_CAUSE.swap(0, Ordering::SeqCst);
        cause = runtime.pending_interrupt_cause;
        if runtime.tx_ring.read_u8(descriptor_offset + 12)? & TXD_STATUS_DD != 0 {
            runtime.pending_interrupt_cause &= !E1000_INTERRUPT_TXDW;
            runtime.interrupt_cause |= cause;
            runtime.interrupt_count = E1000_INTERRUPT_COUNT.load(Ordering::SeqCst);
            return Ok(cause);
        }
        if x86_64::instructions::interrupts::are_enabled() {
            crate::interrupts::halt();
        } else {
            core::hint::spin_loop();
        }
    }
    Err(E1000Error::InterruptTimeout {
        cause,
        rctl: runtime.mmio.read_u32(REG_RCTL)?,
        tdh: runtime.mmio.read_u32(REG_TDH)?,
        rdh: runtime.mmio.read_u32(REG_RDH)?,
        rdt: runtime.mmio.read_u32(REG_RDT)?,
        mdic: runtime.mmio.read_u32(REG_MDIC)?,
    })
}

fn recycle_rx_descriptor(runtime: &mut E1000Runtime, index: usize) -> Result<(), E1000Error> {
    let offset = (index as u64) * DESCRIPTOR_SIZE;
    runtime.rx_ring.write_u16(offset + 8, 0)?;
    runtime.rx_ring.write_u16(offset + 10, 0)?;
    runtime.rx_ring.write_u8(offset + 12, 0)?;
    runtime.rx_ring.write_u8(offset + 13, 0)?;
    runtime.rx_ring.write_u16(offset + 14, 0)?;
    runtime.mmio.write_u32(REG_RDT, index as u32)?;
    runtime.rx_next_index = (index + 1) % RX_RING_SIZE;
    Ok(())
}

fn write_tx_descriptor(
    ring: DmaPage,
    offset: u64,
    buffer_physical_base: u64,
    packet_length: usize,
) -> Result<(), E1000Error> {
    ring.write_u64(offset, buffer_physical_base)?;
    ring.write_u16(
        offset + 8,
        u16::try_from(packet_length).map_err(|_| DmaError::AddressOverflow)?,
    )?;
    ring.write_u8(offset + 10, 0)?;
    ring.write_u8(offset + 11, TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS)?;
    ring.write_u8(offset + 12, 0)?;
    ring.write_u8(offset + 13, 0)?;
    ring.write_u16(offset + 14, 0)?;
    Ok(())
}
