pub const ETHERNET_HEADER_LENGTH: usize = 14;
pub const ETHERNET_MIN_FRAME_LENGTH: usize = 60;
pub const ETHERNET_MAX_FRAME_LENGTH: usize = 1518;
pub const ETHERNET_MAX_PAYLOAD_LENGTH: usize = ETHERNET_MAX_FRAME_LENGTH - ETHERNET_HEADER_LENGTH;

pub type MacAddress = [u8; 6];
pub type Ipv4Address = [u8; 4];

pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const IP_PROTOCOL_UDP: u8 = 17;
pub const IPV4_HEADER_LENGTH: usize = 20;
pub const IPV4_MAX_PACKET_LENGTH: usize = 1500;
pub const UDP_HEADER_LENGTH: usize = 8;
pub const UDP_MAX_PACKET_LENGTH: usize = IPV4_MAX_PACKET_LENGTH - IPV4_HEADER_LENGTH;
pub const UDP_MAX_PAYLOAD_LENGTH: usize = UDP_MAX_PACKET_LENGTH - UDP_HEADER_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthernetFrameError {
    TooShort { length: usize },
    TooLarge { length: usize },
    PayloadTooLarge { length: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    bytes: [u8; ETHERNET_MAX_FRAME_LENGTH],
    length: usize,
}

impl EthernetFrame {
    pub fn new(
        destination: MacAddress,
        source: MacAddress,
        ether_type: u16,
        payload: &[u8],
    ) -> Result<Self, EthernetFrameError> {
        if payload.len() > ETHERNET_MAX_PAYLOAD_LENGTH {
            return Err(EthernetFrameError::PayloadTooLarge {
                length: payload.len(),
            });
        }

        let unpadded_length = ETHERNET_HEADER_LENGTH + payload.len();
        let length = unpadded_length.max(ETHERNET_MIN_FRAME_LENGTH);
        let mut bytes = [0u8; ETHERNET_MAX_FRAME_LENGTH];
        bytes[..6].copy_from_slice(&destination);
        bytes[6..12].copy_from_slice(&source);
        bytes[12..14].copy_from_slice(&ether_type.to_be_bytes());
        bytes[ETHERNET_HEADER_LENGTH..unpadded_length].copy_from_slice(payload);
        Ok(Self { bytes, length })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, EthernetFrameError> {
        if bytes.len() < ETHERNET_MIN_FRAME_LENGTH {
            return Err(EthernetFrameError::TooShort {
                length: bytes.len(),
            });
        }
        if bytes.len() > ETHERNET_MAX_FRAME_LENGTH {
            return Err(EthernetFrameError::TooLarge {
                length: bytes.len(),
            });
        }

        let mut frame_bytes = [0u8; ETHERNET_MAX_FRAME_LENGTH];
        frame_bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: frame_bytes,
            length: bytes.len(),
        })
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub fn destination(&self) -> MacAddress {
        self.bytes[..6]
            .try_into()
            .expect("Ethernet destination is six bytes")
    }

    pub fn source(&self) -> MacAddress {
        self.bytes[6..12]
            .try_into()
            .expect("Ethernet source is six bytes")
    }

    pub fn ether_type(&self) -> u16 {
        u16::from_be_bytes([self.bytes[12], self.bytes[13]])
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[ETHERNET_HEADER_LENGTH..self.length]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4PacketError {
    TooShort { length: usize },
    TooLarge { length: usize },
    InvalidVersion { version: u8 },
    InvalidHeaderLength { length: usize },
    LengthMismatch { declared: usize, available: usize },
    PayloadTooLarge { length: usize },
    InvalidChecksum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet {
    bytes: [u8; IPV4_MAX_PACKET_LENGTH],
    length: usize,
    header_length: usize,
}

impl Ipv4Packet {
    pub fn new(
        source: Ipv4Address,
        destination: Ipv4Address,
        protocol: u8,
        payload: &[u8],
        identification: u16,
    ) -> Result<Self, Ipv4PacketError> {
        if payload.len() > IPV4_MAX_PACKET_LENGTH - IPV4_HEADER_LENGTH {
            return Err(Ipv4PacketError::PayloadTooLarge {
                length: payload.len(),
            });
        }
        let length = IPV4_HEADER_LENGTH + payload.len();
        let mut bytes = [0u8; IPV4_MAX_PACKET_LENGTH];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        bytes[4..6].copy_from_slice(&identification.to_be_bytes());
        bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&source);
        bytes[16..20].copy_from_slice(&destination);
        bytes[IPV4_HEADER_LENGTH..length].copy_from_slice(payload);
        let checksum = internet_checksum(&bytes[..IPV4_HEADER_LENGTH]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        Ok(Self {
            bytes,
            length,
            header_length: IPV4_HEADER_LENGTH,
        })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Ipv4PacketError> {
        if bytes.len() < IPV4_HEADER_LENGTH {
            return Err(Ipv4PacketError::TooShort {
                length: bytes.len(),
            });
        }
        let version = bytes[0] >> 4;
        if version != 4 {
            return Err(Ipv4PacketError::InvalidVersion { version });
        }
        let header_length = usize::from(bytes[0] & 0x0f) * 4;
        if header_length < IPV4_HEADER_LENGTH || header_length > bytes.len() {
            return Err(Ipv4PacketError::InvalidHeaderLength {
                length: header_length,
            });
        }
        let declared_length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if declared_length > IPV4_MAX_PACKET_LENGTH {
            return Err(Ipv4PacketError::TooLarge {
                length: declared_length,
            });
        }
        if declared_length < header_length || declared_length > bytes.len() {
            return Err(Ipv4PacketError::LengthMismatch {
                declared: declared_length,
                available: bytes.len(),
            });
        }
        if internet_checksum(&bytes[..header_length]) != 0 {
            return Err(Ipv4PacketError::InvalidChecksum);
        }

        let mut packet_bytes = [0u8; IPV4_MAX_PACKET_LENGTH];
        packet_bytes[..declared_length].copy_from_slice(&bytes[..declared_length]);
        Ok(Self {
            bytes: packet_bytes,
            length: declared_length,
            header_length,
        })
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub fn source(&self) -> Ipv4Address {
        self.bytes[12..16]
            .try_into()
            .expect("IPv4 source is four bytes")
    }

    pub fn destination(&self) -> Ipv4Address {
        self.bytes[16..20]
            .try_into()
            .expect("IPv4 destination is four bytes")
    }

    pub fn protocol(&self) -> u8 {
        self.bytes[9]
    }

    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.header_length..self.length]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDatagramError {
    TooShort { length: usize },
    TooLarge { length: usize },
    LengthMismatch { declared: usize, available: usize },
    PayloadTooLarge { length: usize },
    InvalidChecksum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    bytes: [u8; UDP_MAX_PACKET_LENGTH],
    length: usize,
}

impl UdpDatagram {
    pub fn new(
        source_port: u16,
        destination_port: u16,
        source: Ipv4Address,
        destination: Ipv4Address,
        payload: &[u8],
    ) -> Result<Self, UdpDatagramError> {
        if payload.len() > UDP_MAX_PAYLOAD_LENGTH {
            return Err(UdpDatagramError::PayloadTooLarge {
                length: payload.len(),
            });
        }
        let length = UDP_HEADER_LENGTH + payload.len();
        let mut bytes = [0u8; UDP_MAX_PACKET_LENGTH];
        bytes[0..2].copy_from_slice(&source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&destination_port.to_be_bytes());
        bytes[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        bytes[UDP_HEADER_LENGTH..length].copy_from_slice(payload);
        let mut checksum = udp_checksum(source, destination, &bytes[..length]);
        if checksum == 0 {
            checksum = u16::MAX;
        }
        bytes[6..8].copy_from_slice(&checksum.to_be_bytes());
        Ok(Self { bytes, length })
    }

    pub fn parse(
        bytes: &[u8],
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> Result<Self, UdpDatagramError> {
        if bytes.len() < UDP_HEADER_LENGTH {
            return Err(UdpDatagramError::TooShort {
                length: bytes.len(),
            });
        }
        let declared_length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if declared_length > UDP_MAX_PACKET_LENGTH {
            return Err(UdpDatagramError::TooLarge {
                length: declared_length,
            });
        }
        if declared_length < UDP_HEADER_LENGTH || declared_length > bytes.len() {
            return Err(UdpDatagramError::LengthMismatch {
                declared: declared_length,
                available: bytes.len(),
            });
        }
        let checksum = u16::from_be_bytes([bytes[6], bytes[7]]);
        if checksum != 0 && udp_checksum(source, destination, &bytes[..declared_length]) != 0 {
            return Err(UdpDatagramError::InvalidChecksum);
        }

        let mut datagram_bytes = [0u8; UDP_MAX_PACKET_LENGTH];
        datagram_bytes[..declared_length].copy_from_slice(&bytes[..declared_length]);
        Ok(Self {
            bytes: datagram_bytes,
            length: declared_length,
        })
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[6], self.bytes[7]])
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[UDP_HEADER_LENGTH..self.length]
    }
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = bytes.chunks_exact(2).remainder().first() {
        sum += u32::from(byte) << 8;
    }
    fold_checksum(sum)
}

fn udp_checksum(source: Ipv4Address, destination: Ipv4Address, datagram: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += u32::from(u16::from_be_bytes([source[0], source[1]]));
    sum += u32::from(u16::from_be_bytes([source[2], source[3]]));
    sum += u32::from(u16::from_be_bytes([destination[0], destination[1]]));
    sum += u32::from(u16::from_be_bytes([destination[2], destination[3]]));
    sum += u32::from(IP_PROTOCOL_UDP);
    sum += u32::from(datagram.len() as u16);
    for chunk in datagram.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = datagram.chunks_exact(2).remainder().first() {
        sum += u32::from(byte) << 8;
    }
    fold_checksum(sum)
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub trait NetworkInterface {
    type Error;

    fn mac_address(&self) -> MacAddress;

    fn transmit(&mut self, frame: &EthernetFrame) -> Result<(), Self::Error>;

    fn receive(&mut self) -> Result<EthernetFrame, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_and_parses_padded_frame() {
        let frame = EthernetFrame::new(
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
            [0x20, 0x21, 0x22, 0x23, 0x24, 0x25],
            0x88b5,
            b"RustOS",
        )
        .unwrap();
        assert_eq!(frame.len(), ETHERNET_MIN_FRAME_LENGTH);
        assert_eq!(frame.destination(), [0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
        assert_eq!(frame.source(), [0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
        assert_eq!(frame.ether_type(), 0x88b5);
        assert!(frame.payload().starts_with(b"RustOS"));
        assert_eq!(EthernetFrame::parse(frame.as_bytes()).unwrap(), frame);
    }

    #[test]
    fn rejects_frames_outside_ethernet_bounds() {
        assert_eq!(
            EthernetFrame::parse(&[0u8; ETHERNET_MIN_FRAME_LENGTH - 1]),
            Err(EthernetFrameError::TooShort {
                length: ETHERNET_MIN_FRAME_LENGTH - 1,
            })
        );
        assert_eq!(
            EthernetFrame::parse(&[0u8; ETHERNET_MAX_FRAME_LENGTH + 1]),
            Err(EthernetFrameError::TooLarge {
                length: ETHERNET_MAX_FRAME_LENGTH + 1,
            })
        );
        assert_eq!(
            EthernetFrame::new(
                [0; 6],
                [0; 6],
                0x0800,
                &[0; ETHERNET_MAX_PAYLOAD_LENGTH + 1]
            ),
            Err(EthernetFrameError::PayloadTooLarge {
                length: ETHERNET_MAX_PAYLOAD_LENGTH + 1,
            })
        );
    }

    #[test]
    fn accepts_the_maximum_frame_without_fcs() {
        let frame =
            EthernetFrame::new([0; 6], [1; 6], 0x0800, &[0xa5; ETHERNET_MAX_PAYLOAD_LENGTH])
                .unwrap();
        assert_eq!(frame.len(), ETHERNET_MAX_FRAME_LENGTH);
    }

    #[test]
    fn constructs_and_parses_ipv4_udp_through_padded_ethernet() {
        let source_ip = [192, 0, 2, 1];
        let destination_ip = [192, 0, 2, 2];
        let udp =
            UdpDatagram::new(4242, 4243, source_ip, destination_ip, b"RustOS IPv4 UDP").unwrap();
        let ip = Ipv4Packet::new(
            source_ip,
            destination_ip,
            IP_PROTOCOL_UDP,
            udp.as_bytes(),
            0x1234,
        )
        .unwrap();
        let frame = EthernetFrame::new([0; 6], [1; 6], ETHER_TYPE_IPV4, ip.as_bytes()).unwrap();

        assert_eq!(frame.len(), ETHERNET_MIN_FRAME_LENGTH);
        assert_eq!(frame.payload().len(), 46);
        assert!(ip.len() < frame.payload().len());

        let parsed_frame = EthernetFrame::parse(frame.as_bytes()).unwrap();
        let parsed_ip = Ipv4Packet::parse(parsed_frame.payload()).unwrap();
        let parsed_udp = UdpDatagram::parse(
            parsed_ip.payload(),
            parsed_ip.source(),
            parsed_ip.destination(),
        )
        .unwrap();

        assert_eq!(parsed_ip, ip);
        assert_eq!(parsed_ip.source(), source_ip);
        assert_eq!(parsed_ip.destination(), destination_ip);
        assert_eq!(parsed_ip.protocol(), IP_PROTOCOL_UDP);
        assert_eq!(parsed_ip.identification(), 0x1234);
        assert_eq!(parsed_udp, udp);
        assert_eq!(parsed_udp.source_port(), 4242);
        assert_eq!(parsed_udp.destination_port(), 4243);
        assert_eq!(parsed_udp.payload(), b"RustOS IPv4 UDP");
    }

    #[test]
    fn rejects_corrupt_ipv4_and_udp_checksums() {
        let source_ip = [198, 51, 100, 1];
        let destination_ip = [198, 51, 100, 2];
        let udp = UdpDatagram::new(1000, 1001, source_ip, destination_ip, b"checksum").unwrap();
        let ip = Ipv4Packet::new(
            source_ip,
            destination_ip,
            IP_PROTOCOL_UDP,
            udp.as_bytes(),
            7,
        )
        .unwrap();

        let mut corrupt_ip = [0u8; IPV4_MAX_PACKET_LENGTH];
        corrupt_ip[..ip.len()].copy_from_slice(ip.as_bytes());
        corrupt_ip[8] ^= 1;
        assert_eq!(
            Ipv4Packet::parse(&corrupt_ip[..ip.len()]),
            Err(Ipv4PacketError::InvalidChecksum)
        );

        let mut corrupt_udp = [0u8; UDP_MAX_PACKET_LENGTH];
        corrupt_udp[..udp.len()].copy_from_slice(udp.as_bytes());
        corrupt_udp[UDP_HEADER_LENGTH] ^= 1;
        assert_eq!(
            UdpDatagram::parse(&corrupt_udp[..udp.len()], source_ip, destination_ip),
            Err(UdpDatagramError::InvalidChecksum)
        );
    }

    #[test]
    fn rejects_oversized_ipv4_and_udp_payloads() {
        assert_eq!(
            UdpDatagram::new(
                1,
                2,
                [192, 0, 2, 1],
                [192, 0, 2, 2],
                &[0u8; UDP_MAX_PAYLOAD_LENGTH + 1]
            ),
            Err(UdpDatagramError::PayloadTooLarge {
                length: UDP_MAX_PAYLOAD_LENGTH + 1,
            })
        );

        assert_eq!(
            Ipv4Packet::new(
                [192, 0, 2, 1],
                [192, 0, 2, 2],
                IP_PROTOCOL_UDP,
                &[0u8; IPV4_MAX_PACKET_LENGTH - IPV4_HEADER_LENGTH + 1],
                0
            ),
            Err(Ipv4PacketError::PayloadTooLarge {
                length: IPV4_MAX_PACKET_LENGTH - IPV4_HEADER_LENGTH + 1,
            })
        );
    }
}
