pub const NVIDIA_GSP_FSP_FALCON_BASE: u32 = 0x008f_2000;
pub const NVIDIA_GSP_FSP_QUEUE_HEAD: u32 = 0x008f_2c00;
pub const NVIDIA_GSP_FSP_QUEUE_TAIL: u32 = 0x008f_2c04;
pub const NVIDIA_GSP_FSP_MSGQ_HEAD: u32 = 0x008f_2c80;
pub const NVIDIA_GSP_FSP_MSGQ_TAIL: u32 = 0x008f_2c84;
pub const NVIDIA_GSP_FSP_EMEM_PIO_ADDRESS: u32 = NVIDIA_GSP_FSP_FALCON_BASE + 0x0ac0;
pub const NVIDIA_GSP_FSP_EMEM_PIO_DATA: u32 = NVIDIA_GSP_FSP_FALCON_BASE + 0x0ac4;
pub const NVIDIA_GSP_FSP_FALCON_MAILBOX0: u32 = NVIDIA_GSP_FSP_FALCON_BASE + 0x0040;
pub const NVIDIA_GSP_FSP_FALCON_MAILBOX1: u32 = NVIDIA_GSP_FSP_FALCON_BASE + 0x0044;
pub const NVIDIA_GSP_FSP_FALCON_HWCFG2: u32 = NVIDIA_GSP_FSP_FALCON_BASE + 0x00f4;
pub const NVIDIA_GSP_FSP_FALCON_HWCFG2_LOCKDOWN_BIT: u32 = 13;
pub const NVIDIA_GSP_FSP_BAR0_REQUIRED_LENGTH: u64 = 0x008f_4000;

pub const NVIDIA_GSP_FSP_COT_VERSION_GB20X: u16 = 2;
pub const NVIDIA_GSP_FSP_COT_HASH_BYTES: usize = 48;
pub const NVIDIA_GSP_FSP_COT_PUBLIC_KEY_BYTES: usize = 97;
pub const NVIDIA_GSP_FSP_COT_SIGNATURE_BYTES: usize = 96;
pub const NVIDIA_GSP_FSP_COT_PUBLIC_KEY_SLOT_BYTES: usize = 96 * 4;
pub const NVIDIA_GSP_FSP_COT_SIGNATURE_SLOT_BYTES: usize = 96 * 4;
pub const NVIDIA_GSP_FSP_COT_PAYLOAD_SIZE: usize = 860;
pub const NVIDIA_GSP_FSP_COT_PACKET_SIZE: usize = 8 + NVIDIA_GSP_FSP_COT_PAYLOAD_SIZE;

const MCTP_HEADER_SOM: u32 = 1 << 31;
const MCTP_HEADER_EOM: u32 = 1 << 30;
const MCTP_MSG_HEADER_TYPE_VENDOR_PCI: u32 = 0x7e;
const MCTP_MSG_HEADER_VENDOR_ID_NVIDIA: u32 = 0x10de;
const NVDM_TYPE_COT: u32 = 0x14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspFspCotError {
    InvalidHashSize { actual: usize },
    InvalidPublicKeySize { actual: usize },
    InvalidSignatureSize { actual: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspFspCot<'a> {
    pub gsp_fmc_sysmem_offset: u64,
    pub frts_sysmem_offset: u64,
    pub frts_sysmem_size: u32,
    pub frts_vidmem_offset: u64,
    pub frts_vidmem_size: u32,
    pub gsp_boot_args_sysmem_offset: u64,
    pub hash: &'a [u8],
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
}

impl<'a> GspFspCot<'a> {
    pub const fn gb20x(
        gsp_fmc_sysmem_offset: u64,
        gsp_boot_args_sysmem_offset: u64,
        frts_vidmem_offset: u64,
        frts_vidmem_size: u32,
        hash: &'a [u8],
        public_key: &'a [u8],
        signature: &'a [u8],
    ) -> Self {
        Self {
            gsp_fmc_sysmem_offset,
            frts_sysmem_offset: 0,
            frts_sysmem_size: 0,
            frts_vidmem_offset,
            frts_vidmem_size,
            gsp_boot_args_sysmem_offset,
            hash,
            public_key,
            signature,
        }
    }

    pub fn encode(self) -> Result<[u8; NVIDIA_GSP_FSP_COT_PACKET_SIZE], GspFspCotError> {
        if self.hash.len() != NVIDIA_GSP_FSP_COT_HASH_BYTES {
            return Err(GspFspCotError::InvalidHashSize {
                actual: self.hash.len(),
            });
        }
        if self.public_key.len() != NVIDIA_GSP_FSP_COT_PUBLIC_KEY_BYTES {
            return Err(GspFspCotError::InvalidPublicKeySize {
                actual: self.public_key.len(),
            });
        }
        if self.signature.len() != NVIDIA_GSP_FSP_COT_SIGNATURE_BYTES {
            return Err(GspFspCotError::InvalidSignatureSize {
                actual: self.signature.len(),
            });
        }

        let mut packet = [0u8; NVIDIA_GSP_FSP_COT_PACKET_SIZE];
        write_le_u32(&mut packet, 0, MCTP_HEADER_SOM | MCTP_HEADER_EOM);
        write_le_u32(
            &mut packet,
            4,
            (NVDM_TYPE_COT << 24)
                | (MCTP_MSG_HEADER_VENDOR_ID_NVIDIA << 8)
                | MCTP_MSG_HEADER_TYPE_VENDOR_PCI,
        );
        write_le_u16(&mut packet, 8, NVIDIA_GSP_FSP_COT_VERSION_GB20X);
        write_le_u16(&mut packet, 10, NVIDIA_GSP_FSP_COT_PAYLOAD_SIZE as u16);
        write_le_u64(&mut packet, 12, self.gsp_fmc_sysmem_offset);
        write_le_u64(&mut packet, 20, self.frts_sysmem_offset);
        write_le_u32(&mut packet, 28, self.frts_sysmem_size);
        write_le_u64(&mut packet, 32, self.frts_vidmem_offset);
        write_le_u32(&mut packet, 40, self.frts_vidmem_size);
        packet[44..44 + self.hash.len()].copy_from_slice(self.hash);
        packet[92..92 + self.public_key.len()].copy_from_slice(self.public_key);
        packet[476..476 + self.signature.len()].copy_from_slice(self.signature);
        write_le_u64(&mut packet, 860, self.gsp_boot_args_sysmem_offset);
        Ok(packet)
    }
}

fn write_le_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_le_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_le_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u16(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("u16"))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32"))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64"))
    }

    #[test]
    fn encodes_gb20x_cot_packet_at_the_fsp_wire_offsets() {
        let hash = [0x11; NVIDIA_GSP_FSP_COT_HASH_BYTES];
        let public_key = [0x22; NVIDIA_GSP_FSP_COT_PUBLIC_KEY_BYTES];
        let signature = [0x33; NVIDIA_GSP_FSP_COT_SIGNATURE_BYTES];
        let packet = GspFspCot::gb20x(
            0x2000_0000,
            0x1000_0000,
            0x0040_0000,
            0x0010_0000,
            &hash,
            &public_key,
            &signature,
        )
        .encode()
        .expect("COT packet");

        assert_eq!(packet.len(), NVIDIA_GSP_FSP_COT_PACKET_SIZE);
        assert_eq!(read_u32(&packet, 0), MCTP_HEADER_SOM | MCTP_HEADER_EOM);
        assert_eq!(read_u32(&packet, 4), 0x1410_de7e);
        assert_eq!(read_u16(&packet, 8), NVIDIA_GSP_FSP_COT_VERSION_GB20X);
        assert_eq!(
            read_u16(&packet, 10),
            NVIDIA_GSP_FSP_COT_PAYLOAD_SIZE as u16
        );
        assert_eq!(read_u64(&packet, 12), 0x2000_0000);
        assert_eq!(read_u64(&packet, 20), 0);
        assert_eq!(read_u32(&packet, 28), 0);
        assert_eq!(read_u64(&packet, 32), 0x0040_0000);
        assert_eq!(read_u32(&packet, 40), 0x0010_0000);
        assert_eq!(&packet[44..92], &hash);
        assert_eq!(&packet[92..189], &public_key);
        assert!(packet[189..476].iter().all(|byte| *byte == 0));
        assert_eq!(&packet[476..572], &signature);
        assert!(packet[572..860].iter().all(|byte| *byte == 0));
        assert_eq!(read_u64(&packet, 860), 0x1000_0000);
    }

    #[test]
    fn rejects_wrong_authentication_material_sizes() {
        let hash = [0u8; NVIDIA_GSP_FSP_COT_HASH_BYTES - 1];
        let public_key = [0u8; NVIDIA_GSP_FSP_COT_PUBLIC_KEY_BYTES];
        let signature = [0u8; NVIDIA_GSP_FSP_COT_SIGNATURE_BYTES];
        assert_eq!(
            GspFspCot::gb20x(0, 0, 0, 0, &hash, &public_key, &signature).encode(),
            Err(GspFspCotError::InvalidHashSize {
                actual: NVIDIA_GSP_FSP_COT_HASH_BYTES - 1,
            })
        );

        let hash = [0u8; NVIDIA_GSP_FSP_COT_HASH_BYTES];
        let public_key = [0u8; NVIDIA_GSP_FSP_COT_PUBLIC_KEY_BYTES - 1];
        assert_eq!(
            GspFspCot::gb20x(0, 0, 0, 0, &hash, &public_key, &signature).encode(),
            Err(GspFspCotError::InvalidPublicKeySize {
                actual: NVIDIA_GSP_FSP_COT_PUBLIC_KEY_BYTES - 1,
            })
        );

        let public_key = [0u8; NVIDIA_GSP_FSP_COT_PUBLIC_KEY_BYTES];
        let signature = [0u8; NVIDIA_GSP_FSP_COT_SIGNATURE_BYTES - 1];
        assert_eq!(
            GspFspCot::gb20x(0, 0, 0, 0, &hash, &public_key, &signature).encode(),
            Err(GspFspCotError::InvalidSignatureSize {
                actual: NVIDIA_GSP_FSP_COT_SIGNATURE_BYTES - 1,
            })
        );
    }
}
