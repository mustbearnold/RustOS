use crate::net::Ipv4Address;

pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_MESSAGE_BUFFER_LENGTH: usize = 300;
const DHCP_OPTIONS_OFFSET: usize = 240;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpError {
    TooShort { length: usize },
    InvalidHeader,
    TransactionMismatch,
    ClientMismatch,
    InvalidCookie,
    MissingMessageType,
    MalformedOptions,
    MissingAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpReply {
    pub message_type: u8,
    pub address: Ipv4Address,
    pub subnet_mask: Option<Ipv4Address>,
    pub gateway: Option<Ipv4Address>,
    pub dns: Option<Ipv4Address>,
    pub server: Option<Ipv4Address>,
    pub lease_seconds: Option<u32>,
}

pub fn build_discover(
    transaction_id: u32,
    mac_address: [u8; 6],
) -> ([u8; DHCP_MESSAGE_BUFFER_LENGTH], usize) {
    let mut message = base_message(transaction_id, mac_address);
    let mut cursor = DHCP_OPTIONS_OFFSET;
    append_option(&mut message, &mut cursor, 53, &[DHCP_DISCOVER]);
    append_option(&mut message, &mut cursor, 55, &[1, 3, 6, 51, 54]);
    finish_options(&mut message, cursor)
}

pub fn build_request(
    transaction_id: u32,
    mac_address: [u8; 6],
    requested_address: Ipv4Address,
    server: Ipv4Address,
) -> ([u8; DHCP_MESSAGE_BUFFER_LENGTH], usize) {
    let mut message = base_message(transaction_id, mac_address);
    let mut cursor = DHCP_OPTIONS_OFFSET;
    append_option(&mut message, &mut cursor, 53, &[DHCP_REQUEST]);
    append_option(&mut message, &mut cursor, 50, &requested_address);
    append_option(&mut message, &mut cursor, 54, &server);
    append_option(&mut message, &mut cursor, 55, &[1, 3, 6, 51, 54]);
    finish_options(&mut message, cursor)
}

/// Build a DHCPREQUEST for the RENEWING state.
///
/// Unlike the initial discover/request exchange, a renewing client identifies its current lease
/// in `ciaddr` and does not include a requested-address or server-identifier option.
pub fn build_renew_request(
    transaction_id: u32,
    mac_address: [u8; 6],
    address: Ipv4Address,
) -> ([u8; DHCP_MESSAGE_BUFFER_LENGTH], usize) {
    let mut message = base_message(transaction_id, mac_address);
    message[10..12].copy_from_slice(&0u16.to_be_bytes());
    message[12..16].copy_from_slice(&address);
    let mut cursor = DHCP_OPTIONS_OFFSET;
    append_option(&mut message, &mut cursor, 53, &[DHCP_REQUEST]);
    append_option(&mut message, &mut cursor, 55, &[1, 3, 6, 51, 54]);
    finish_options(&mut message, cursor)
}

pub fn parse_reply(
    message: &[u8],
    transaction_id: u32,
    mac_address: [u8; 6],
) -> Result<DhcpReply, DhcpError> {
    if message.len() < DHCP_OPTIONS_OFFSET {
        return Err(DhcpError::TooShort {
            length: message.len(),
        });
    }
    if message[0] != 2 || message[1] != 1 || message[2] != 6 {
        return Err(DhcpError::InvalidHeader);
    }
    if message[4..8] != transaction_id.to_be_bytes() {
        return Err(DhcpError::TransactionMismatch);
    }
    if message[28..34] != mac_address {
        return Err(DhcpError::ClientMismatch);
    }
    if message[236..240] != DHCP_MAGIC_COOKIE {
        return Err(DhcpError::InvalidCookie);
    }

    let mut message_type = None;
    let mut subnet_mask = None;
    let mut gateway = None;
    let mut dns = None;
    let mut server = None;
    let mut lease_seconds = None;
    let mut cursor = DHCP_OPTIONS_OFFSET;
    while cursor < message.len() {
        let code = message[cursor];
        cursor += 1;
        match code {
            0 => continue,
            255 => break,
            _ => {}
        }
        if cursor >= message.len() {
            return Err(DhcpError::MalformedOptions);
        }
        let length = usize::from(message[cursor]);
        cursor += 1;
        let end = cursor
            .checked_add(length)
            .ok_or(DhcpError::MalformedOptions)?;
        if end > message.len() {
            return Err(DhcpError::MalformedOptions);
        }
        let value = &message[cursor..end];
        match code {
            1 => subnet_mask = parse_ipv4_option(value),
            3 => gateway = parse_ipv4_option(value),
            6 => dns = parse_ipv4_option(value),
            51 if value.len() == 4 => {
                lease_seconds = Some(u32::from_be_bytes(value.try_into().unwrap()));
            }
            53 if value.len() == 1 => message_type = Some(value[0]),
            54 => server = parse_ipv4_option(value),
            _ => {}
        }
        cursor = end;
    }

    let Some(message_type) = message_type else {
        return Err(DhcpError::MissingMessageType);
    };
    let offered_address: Ipv4Address = message[16..20]
        .try_into()
        .expect("DHCP yiaddr is four bytes");
    let client_address: Ipv4Address = message[12..16]
        .try_into()
        .expect("DHCP ciaddr is four bytes");
    let address = if offered_address != [0; 4] {
        offered_address
    } else {
        client_address
    };
    if address == [0; 4] {
        return Err(DhcpError::MissingAddress);
    }
    Ok(DhcpReply {
        message_type,
        address,
        subnet_mask,
        gateway,
        dns,
        server,
        lease_seconds,
    })
}

fn base_message(transaction_id: u32, mac_address: [u8; 6]) -> [u8; DHCP_MESSAGE_BUFFER_LENGTH] {
    let mut message = [0u8; DHCP_MESSAGE_BUFFER_LENGTH];
    message[0] = 1;
    message[1] = 1;
    message[2] = 6;
    message[4..8].copy_from_slice(&transaction_id.to_be_bytes());
    message[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    message[28..34].copy_from_slice(&mac_address);
    message[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    message
}

fn append_option(
    message: &mut [u8; DHCP_MESSAGE_BUFFER_LENGTH],
    cursor: &mut usize,
    code: u8,
    value: &[u8],
) {
    message[*cursor] = code;
    *cursor += 1;
    message[*cursor] = value.len() as u8;
    *cursor += 1;
    message[*cursor..*cursor + value.len()].copy_from_slice(value);
    *cursor += value.len();
}

fn finish_options(
    message: &mut [u8; DHCP_MESSAGE_BUFFER_LENGTH],
    cursor: usize,
) -> ([u8; DHCP_MESSAGE_BUFFER_LENGTH], usize) {
    message[cursor] = 255;
    (*message, cursor + 1)
}

fn parse_ipv4_option(value: &[u8]) -> Option<Ipv4Address> {
    (value.len() >= 4).then(|| [value[0], value[1], value[2], value[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_broadcast_discover_with_requested_options() {
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        let (message, length) = build_discover(0x5255_5354, mac);
        assert_eq!(length, 251);
        assert_eq!(&message[..4], &[1, 1, 6, 0]);
        assert_eq!(&message[4..8], &0x5255_5354u32.to_be_bytes());
        assert_eq!(&message[28..34], &mac);
        assert_eq!(&message[236..240], &DHCP_MAGIC_COOKIE);
        assert_eq!(&message[240..243], &[53, 1, DHCP_DISCOVER]);
        assert_eq!(&message[243..250], &[55, 5, 1, 3, 6, 51, 54]);
        assert_eq!(message[250], 255);
    }

    #[test]
    fn parses_ack_lease_options_and_ignores_unknown_options() {
        let xid = 0x1122_3344;
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        let mut message = base_message(xid, mac);
        message[0] = 2;
        message[16..20].copy_from_slice(&[10, 0, 2, 15]);
        let mut cursor = DHCP_OPTIONS_OFFSET;
        append_option(&mut message, &mut cursor, 53, &[DHCP_ACK]);
        append_option(&mut message, &mut cursor, 1, &[255, 255, 255, 0]);
        append_option(&mut message, &mut cursor, 3, &[10, 0, 2, 2]);
        append_option(&mut message, &mut cursor, 6, &[10, 0, 2, 3]);
        append_option(&mut message, &mut cursor, 51, &3600u32.to_be_bytes());
        append_option(&mut message, &mut cursor, 54, &[10, 0, 2, 2]);
        append_option(&mut message, &mut cursor, 99, &[1, 2, 3]);
        let (message, length) = finish_options(&mut message, cursor);

        let reply = parse_reply(&message[..length], xid, mac).unwrap();
        assert_eq!(reply.message_type, DHCP_ACK);
        assert_eq!(reply.address, [10, 0, 2, 15]);
        assert_eq!(reply.subnet_mask, Some([255, 255, 255, 0]));
        assert_eq!(reply.gateway, Some([10, 0, 2, 2]));
        assert_eq!(reply.dns, Some([10, 0, 2, 3]));
        assert_eq!(reply.server, Some([10, 0, 2, 2]));
        assert_eq!(reply.lease_seconds, Some(3600));
    }

    #[test]
    fn rejects_a_reply_for_another_transaction_or_client() {
        let xid = 7;
        let mac = [1, 2, 3, 4, 5, 6];
        let (mut message, length) = build_discover(xid, mac);
        message[0] = 2;
        message[16..20].copy_from_slice(&[10, 0, 2, 15]);
        message[250] = 53;
        message[251] = 1;
        message[252] = DHCP_OFFER;
        message[253] = 255;
        assert_eq!(
            parse_reply(&message[..length], xid + 1, mac),
            Err(DhcpError::TransactionMismatch)
        );
        assert_eq!(
            parse_reply(&message[..length], xid, [1, 2, 3, 4, 5, 7]),
            Err(DhcpError::ClientMismatch)
        );
    }

    #[test]
    fn builds_a_renew_request_with_ciaddr_and_no_broadcast_flag() {
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        let address = [10, 0, 2, 15];
        let (message, length) = build_renew_request(0x5255_5354, mac, address);
        assert_eq!(length, 251);
        assert_eq!(&message[10..12], &[0, 0]);
        assert_eq!(&message[12..16], &address);
        assert_eq!(&message[240..243], &[53, 1, DHCP_REQUEST]);
        assert_eq!(&message[243..250], &[55, 5, 1, 3, 6, 51, 54]);
        assert_eq!(message[250], 255);
    }

    #[test]
    fn accepts_a_renewal_ack_that_only_returns_ciaddr() {
        let xid = 0x1122_3344;
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        let address = [10, 0, 2, 15];
        let (mut message, _) = build_renew_request(xid, mac, address);
        message[0] = 2;
        message[16..20].copy_from_slice(&[0, 0, 0, 0]);
        let mut cursor = DHCP_OPTIONS_OFFSET;
        append_option(&mut message, &mut cursor, 53, &[DHCP_ACK]);
        append_option(&mut message, &mut cursor, 51, &3600u32.to_be_bytes());
        let (message, length) = finish_options(&mut message, cursor);

        let reply = parse_reply(&message[..length], xid, mac).unwrap();
        assert_eq!(reply.address, address);
        assert_eq!(reply.lease_seconds, Some(3600));
    }
}
