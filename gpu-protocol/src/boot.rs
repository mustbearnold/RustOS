use alloc::vec::Vec;

use super::{FirmwareSection, GspFirmware, GspFirmwareError, GspFmc, GspFmcError};

pub const NVIDIA_GSP_BOOTLOADER_MAX_SIZE: usize = 4 * 1024 * 1024;
pub const NVIDIA_GSP_BIN_HEADER_SIZE: usize = 24;
pub const NVIDIA_GSP_RM_UCODE_DESCRIPTOR_SIZE: usize = 84;
pub const NVIDIA_GSP_FMC_BOOT_PARAMS_SIZE: usize = 80;
pub const NVIDIA_GSP_WPR_META_SIZE: usize = 256;
pub const NVIDIA_GSP_BIN_MAGIC: u32 = 0x0000_10de;
pub const NVIDIA_GSP_BIN_VERSION: u32 = 1;
pub const NVIDIA_GSP_WPR_META_MAGIC: u64 = 0xdc3a_ae21_371a_60b3;
pub const NVIDIA_GSP_WPR_META_REVISION: u64 = 1;
pub const NVIDIA_GSP_DMA_TARGET_COHERENT_SYSTEM: u32 = 1;
pub const NVIDIA_GSP_DMA_TARGET_NONCOHERENT_SYSTEM: u32 = 2;

const GSP_RM_UCODE_DESCRIPTOR_MAX_VERSION: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspBootloaderError {
    TooLarge { size: usize, limit: usize },
    Truncated { offset: usize, size: usize },
    InvalidMagic { value: u32 },
    UnsupportedVersion { value: u32 },
    InvalidHeader,
    InvalidPayload,
    InvalidDescriptor,
    InvalidDescriptorRange { field: GspRmDescriptorField },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspRmDescriptorField {
    Bootloader,
    BootloaderParameters,
    RiscvElf,
    Manifest,
    MonitorData,
    MonitorCode,
    SwbromCode,
    SwbromData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspRmUcodeDescriptor {
    pub version: u32,
    pub bootloader_offset: u32,
    pub bootloader_size: u32,
    pub bootloader_param_offset: u32,
    pub bootloader_param_size: u32,
    pub riscv_elf_offset: u32,
    pub riscv_elf_size: u32,
    pub app_version: u32,
    pub manifest_offset: u32,
    pub manifest_size: u32,
    pub monitor_data_offset: u32,
    pub monitor_data_size: u32,
    pub monitor_code_offset: u32,
    pub monitor_code_size: u32,
    pub monitor_enabled: u32,
    pub swbrom_code_offset: u32,
    pub swbrom_code_size: u32,
    pub swbrom_data_offset: u32,
    pub swbrom_data_size: u32,
    pub framebuffer_reserved_size: u32,
    pub signed_as_code: u32,
}

impl GspRmUcodeDescriptor {
    fn parse(bytes: &[u8], offset: usize) -> Result<Self, GspBootloaderError> {
        let values = (0..NVIDIA_GSP_RM_UCODE_DESCRIPTOR_SIZE / 4)
            .map(|index| read_u32(bytes, offset + index * 4))
            .collect::<Result<Vec<_>, _>>()?;
        let descriptor = Self {
            version: values[0],
            bootloader_offset: values[1],
            bootloader_size: values[2],
            bootloader_param_offset: values[3],
            bootloader_param_size: values[4],
            riscv_elf_offset: values[5],
            riscv_elf_size: values[6],
            app_version: values[7],
            manifest_offset: values[8],
            manifest_size: values[9],
            monitor_data_offset: values[10],
            monitor_data_size: values[11],
            monitor_code_offset: values[12],
            monitor_code_size: values[13],
            monitor_enabled: values[14],
            swbrom_code_offset: values[15],
            swbrom_code_size: values[16],
            swbrom_data_offset: values[17],
            swbrom_data_size: values[18],
            framebuffer_reserved_size: values[19],
            signed_as_code: values[20],
        };
        if !(1..=GSP_RM_UCODE_DESCRIPTOR_MAX_VERSION).contains(&descriptor.version) {
            return Err(GspBootloaderError::InvalidDescriptor);
        }
        Ok(descriptor)
    }

    fn validate_ranges(self, payload_size: usize) -> Result<(), GspBootloaderError> {
        for (field, offset, size) in [
            (
                GspRmDescriptorField::Bootloader,
                self.bootloader_offset,
                self.bootloader_size,
            ),
            (
                GspRmDescriptorField::BootloaderParameters,
                self.bootloader_param_offset,
                self.bootloader_param_size,
            ),
            (
                GspRmDescriptorField::RiscvElf,
                self.riscv_elf_offset,
                self.riscv_elf_size,
            ),
            (
                GspRmDescriptorField::Manifest,
                self.manifest_offset,
                self.manifest_size,
            ),
            (
                GspRmDescriptorField::MonitorData,
                self.monitor_data_offset,
                self.monitor_data_size,
            ),
            (
                GspRmDescriptorField::MonitorCode,
                self.monitor_code_offset,
                self.monitor_code_size,
            ),
            (
                GspRmDescriptorField::SwbromCode,
                self.swbrom_code_offset,
                self.swbrom_code_size,
            ),
            (
                GspRmDescriptorField::SwbromData,
                self.swbrom_data_offset,
                self.swbrom_data_size,
            ),
        ] {
            let end = usize::try_from(offset).ok().and_then(|offset| {
                usize::try_from(size)
                    .ok()
                    .and_then(|size| offset.checked_add(size))
            });
            if end.is_none_or(|end| end > payload_size) {
                return Err(GspBootloaderError::InvalidDescriptorRange { field });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspBootloader {
    pub bin_size: usize,
    pub header_offset: usize,
    pub data_offset: usize,
    pub data_size: usize,
    pub payload: FirmwareSection,
    pub descriptor: GspRmUcodeDescriptor,
}

impl GspBootloader {
    pub fn parse(bytes: &[u8]) -> Result<Self, GspBootloaderError> {
        if bytes.len() > NVIDIA_GSP_BOOTLOADER_MAX_SIZE {
            return Err(GspBootloaderError::TooLarge {
                size: bytes.len(),
                limit: NVIDIA_GSP_BOOTLOADER_MAX_SIZE,
            });
        }
        if bytes.len() < NVIDIA_GSP_BIN_HEADER_SIZE {
            return Err(GspBootloaderError::Truncated {
                offset: 0,
                size: NVIDIA_GSP_BIN_HEADER_SIZE,
            });
        }

        let magic = read_u32(bytes, 0)?;
        if magic != NVIDIA_GSP_BIN_MAGIC {
            return Err(GspBootloaderError::InvalidMagic { value: magic });
        }
        let version = read_u32(bytes, 4)?;
        if version != NVIDIA_GSP_BIN_VERSION {
            return Err(GspBootloaderError::UnsupportedVersion { value: version });
        }
        let bin_size =
            usize::try_from(read_u32(bytes, 8)?).map_err(|_| GspBootloaderError::InvalidHeader)?;
        let header_offset =
            usize::try_from(read_u32(bytes, 12)?).map_err(|_| GspBootloaderError::InvalidHeader)?;
        let data_offset =
            usize::try_from(read_u32(bytes, 16)?).map_err(|_| GspBootloaderError::InvalidHeader)?;
        let data_size =
            usize::try_from(read_u32(bytes, 20)?).map_err(|_| GspBootloaderError::InvalidHeader)?;

        let descriptor_end = header_offset
            .checked_add(NVIDIA_GSP_RM_UCODE_DESCRIPTOR_SIZE)
            .ok_or(GspBootloaderError::InvalidHeader)?;
        if header_offset < NVIDIA_GSP_BIN_HEADER_SIZE || descriptor_end > data_offset {
            return Err(GspBootloaderError::InvalidHeader);
        }
        let payload_end = data_offset
            .checked_add(data_size)
            .ok_or(GspBootloaderError::InvalidPayload)?;
        if payload_end > bytes.len() || bin_size < payload_end {
            return Err(GspBootloaderError::InvalidPayload);
        }

        let descriptor = GspRmUcodeDescriptor::parse(bytes, header_offset)?;
        descriptor.validate_ranges(data_size)?;
        Ok(Self {
            bin_size,
            header_offset,
            data_offset,
            data_size,
            payload: FirmwareSection {
                offset: data_offset,
                size: data_size,
            },
            descriptor,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspWprMeta {
    pub sysmem_addr_of_radix3_elf: u64,
    pub size_of_radix3_elf: u64,
    pub sysmem_addr_of_bootloader: u64,
    pub size_of_bootloader: u64,
    pub bootloader_code_offset: u64,
    pub bootloader_data_offset: u64,
    pub bootloader_manifest_offset: u64,
    pub sysmem_addr_of_signature: u64,
    pub size_of_signature: u64,
    pub gsp_fw_rsvd_start: u64,
    pub non_wpr_heap_offset: u64,
    pub non_wpr_heap_size: u64,
    pub gsp_fw_wpr_start: u64,
    pub gsp_fw_heap_offset: u64,
    pub gsp_fw_heap_size: u64,
    pub gsp_fw_offset: u64,
    pub boot_bin_offset: u64,
    pub frts_offset: u64,
    pub frts_size: u64,
    pub gsp_fw_wpr_end: u64,
    pub fb_size: u64,
    pub vga_workspace_offset: u64,
    pub vga_workspace_size: u64,
    pub boot_count: u64,
    pub partition_rpc_addr: u64,
    pub partition_rpc_request_offset: u16,
    pub partition_rpc_reply_offset: u16,
    pub elf_code_offset: u32,
    pub elf_data_offset: u32,
    pub elf_code_size: u32,
    pub elf_data_size: u32,
    pub ls_ucode_version: u32,
    pub gsp_fw_heap_vf_partition_count: u8,
    pub flags: u8,
    pub pmu_reserved_size: u32,
    pub verified: u64,
}

impl GspWprMeta {
    pub const fn zeroed() -> Self {
        Self {
            sysmem_addr_of_radix3_elf: 0,
            size_of_radix3_elf: 0,
            sysmem_addr_of_bootloader: 0,
            size_of_bootloader: 0,
            bootloader_code_offset: 0,
            bootloader_data_offset: 0,
            bootloader_manifest_offset: 0,
            sysmem_addr_of_signature: 0,
            size_of_signature: 0,
            gsp_fw_rsvd_start: 0,
            non_wpr_heap_offset: 0,
            non_wpr_heap_size: 0,
            gsp_fw_wpr_start: 0,
            gsp_fw_heap_offset: 0,
            gsp_fw_heap_size: 0,
            gsp_fw_offset: 0,
            boot_bin_offset: 0,
            frts_offset: 0,
            frts_size: 0,
            gsp_fw_wpr_end: 0,
            fb_size: 0,
            vga_workspace_offset: 0,
            vga_workspace_size: 0,
            boot_count: 0,
            partition_rpc_addr: 0,
            partition_rpc_request_offset: 0,
            partition_rpc_reply_offset: 0,
            elf_code_offset: 0,
            elf_data_offset: 0,
            elf_code_size: 0,
            elf_data_size: 0,
            ls_ucode_version: 0,
            gsp_fw_heap_vf_partition_count: 0,
            flags: 0,
            pmu_reserved_size: 0,
            verified: 0,
        }
    }

    pub fn encode(self) -> [u8; NVIDIA_GSP_WPR_META_SIZE] {
        let mut bytes = [0u8; NVIDIA_GSP_WPR_META_SIZE];
        write_le_u64(&mut bytes, 0, NVIDIA_GSP_WPR_META_MAGIC);
        write_le_u64(&mut bytes, 8, NVIDIA_GSP_WPR_META_REVISION);
        write_le_u64(&mut bytes, 16, self.sysmem_addr_of_radix3_elf);
        write_le_u64(&mut bytes, 24, self.size_of_radix3_elf);
        write_le_u64(&mut bytes, 32, self.sysmem_addr_of_bootloader);
        write_le_u64(&mut bytes, 40, self.size_of_bootloader);
        write_le_u64(&mut bytes, 48, self.bootloader_code_offset);
        write_le_u64(&mut bytes, 56, self.bootloader_data_offset);
        write_le_u64(&mut bytes, 64, self.bootloader_manifest_offset);
        write_le_u64(&mut bytes, 72, self.sysmem_addr_of_signature);
        write_le_u64(&mut bytes, 80, self.size_of_signature);
        write_le_u64(&mut bytes, 88, self.gsp_fw_rsvd_start);
        write_le_u64(&mut bytes, 96, self.non_wpr_heap_offset);
        write_le_u64(&mut bytes, 104, self.non_wpr_heap_size);
        write_le_u64(&mut bytes, 112, self.gsp_fw_wpr_start);
        write_le_u64(&mut bytes, 120, self.gsp_fw_heap_offset);
        write_le_u64(&mut bytes, 128, self.gsp_fw_heap_size);
        write_le_u64(&mut bytes, 136, self.gsp_fw_offset);
        write_le_u64(&mut bytes, 144, self.boot_bin_offset);
        write_le_u64(&mut bytes, 152, self.frts_offset);
        write_le_u64(&mut bytes, 160, self.frts_size);
        write_le_u64(&mut bytes, 168, self.gsp_fw_wpr_end);
        write_le_u64(&mut bytes, 176, self.fb_size);
        write_le_u64(&mut bytes, 184, self.vga_workspace_offset);
        write_le_u64(&mut bytes, 192, self.vga_workspace_size);
        write_le_u64(&mut bytes, 200, self.boot_count);
        write_le_u64(&mut bytes, 208, self.partition_rpc_addr);
        write_le_u16(&mut bytes, 216, self.partition_rpc_request_offset);
        write_le_u16(&mut bytes, 218, self.partition_rpc_reply_offset);
        write_le_u32(&mut bytes, 220, self.elf_code_offset);
        write_le_u32(&mut bytes, 224, self.elf_data_offset);
        write_le_u32(&mut bytes, 228, self.elf_code_size);
        write_le_u32(&mut bytes, 232, self.elf_data_size);
        write_le_u32(&mut bytes, 236, self.ls_ucode_version);
        bytes[240] = self.gsp_fw_heap_vf_partition_count;
        bytes[241] = self.flags;
        write_le_u32(&mut bytes, 244, self.pmu_reserved_size);
        write_le_u64(&mut bytes, 248, self.verified);
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspFmcBootParams {
    pub registry_keys: u32,
    pub boot_gsp_rm_target: u32,
    pub gsp_rm_desc_size: u32,
    pub gsp_rm_desc_offset: u64,
    pub wpr_carveout_offset: u64,
    pub wpr_carveout_size: u32,
    pub is_gsp_rm_boot: bool,
    pub gsp_rm_target: u32,
    pub boot_args_offset: u64,
    pub spdm_target: u32,
    pub spdm_payload_buffer_offset: u64,
    pub spdm_payload_buffer_size: u32,
}

impl GspFmcBootParams {
    pub const fn r570(
        gsp_rm_desc_offset: u64,
        gsp_rm_desc_size: u32,
        boot_args_offset: u64,
    ) -> Self {
        Self {
            registry_keys: 0,
            boot_gsp_rm_target: NVIDIA_GSP_DMA_TARGET_COHERENT_SYSTEM,
            gsp_rm_desc_size,
            gsp_rm_desc_offset,
            wpr_carveout_offset: 0,
            wpr_carveout_size: 0,
            is_gsp_rm_boot: true,
            gsp_rm_target: NVIDIA_GSP_DMA_TARGET_NONCOHERENT_SYSTEM,
            boot_args_offset,
            spdm_target: 0,
            spdm_payload_buffer_offset: 0,
            spdm_payload_buffer_size: 0,
        }
    }

    pub fn encode(self) -> [u8; NVIDIA_GSP_FMC_BOOT_PARAMS_SIZE] {
        let mut bytes = [0u8; NVIDIA_GSP_FMC_BOOT_PARAMS_SIZE];
        write_le_u32(&mut bytes, 0, self.registry_keys);
        write_le_u32(&mut bytes, 8, self.boot_gsp_rm_target);
        write_le_u32(&mut bytes, 12, self.gsp_rm_desc_size);
        write_le_u64(&mut bytes, 16, self.gsp_rm_desc_offset);
        write_le_u64(&mut bytes, 24, self.wpr_carveout_offset);
        write_le_u32(&mut bytes, 32, self.wpr_carveout_size);
        write_le_u32(&mut bytes, 36, u32::from(self.is_gsp_rm_boot));
        write_le_u32(&mut bytes, 40, self.gsp_rm_target);
        write_le_u64(&mut bytes, 48, self.boot_args_offset);
        write_le_u32(&mut bytes, 56, self.spdm_target);
        write_le_u64(&mut bytes, 64, self.spdm_payload_buffer_offset);
        write_le_u32(&mut bytes, 72, self.spdm_payload_buffer_size);
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GspFirmwareBundleError {
    Gsp(GspFirmwareError),
    Fmc(GspFmcError),
    Bootloader(GspBootloaderError),
    VersionMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GspFirmwareBundle {
    pub gsp: GspFirmware,
    pub fmc: GspFmc,
    pub bootloader: GspBootloader,
}

impl GspFirmwareBundle {
    pub fn parse(
        gsp_bytes: &[u8],
        fmc_bytes: &[u8],
        bootloader_bytes: &[u8],
        expected_version: &[u8],
    ) -> Result<Self, GspFirmwareBundleError> {
        let gsp = GspFirmware::parse(gsp_bytes).map_err(GspFirmwareBundleError::Gsp)?;
        if gsp.version_bytes(gsp_bytes) != expected_version {
            return Err(GspFirmwareBundleError::VersionMismatch);
        }
        let fmc = GspFmc::parse(fmc_bytes).map_err(GspFirmwareBundleError::Fmc)?;
        let bootloader =
            GspBootloader::parse(bootloader_bytes).map_err(GspFirmwareBundleError::Bootloader)?;
        Ok(Self {
            gsp,
            fmc,
            bootloader,
        })
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, GspBootloaderError> {
    let end = offset
        .checked_add(4)
        .ok_or(GspBootloaderError::Truncated { offset, size: 4 })?;
    let value = bytes
        .get(offset..end)
        .ok_or(GspBootloaderError::Truncated { offset, size: 4 })?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
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
    use alloc::vec;

    use super::*;

    const DATA_OFFSET: usize = NVIDIA_GSP_BIN_HEADER_SIZE + NVIDIA_GSP_RM_UCODE_DESCRIPTOR_SIZE;
    const DATA_SIZE: usize = 64;

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_bootloader() -> alloc::vec::Vec<u8> {
        let mut bytes = vec![0u8; DATA_OFFSET + DATA_SIZE];
        write_u32(&mut bytes, 0, NVIDIA_GSP_BIN_MAGIC);
        write_u32(&mut bytes, 4, NVIDIA_GSP_BIN_VERSION);
        let bin_size = bytes.len() as u32;
        write_u32(&mut bytes, 8, bin_size);
        write_u32(&mut bytes, 12, NVIDIA_GSP_BIN_HEADER_SIZE as u32);
        write_u32(&mut bytes, 16, DATA_OFFSET as u32);
        write_u32(&mut bytes, 20, DATA_SIZE as u32);

        let descriptor = NVIDIA_GSP_BIN_HEADER_SIZE;
        write_u32(&mut bytes, descriptor, 5);
        write_u32(&mut bytes, descriptor + 7 * 4, 0x1234);
        write_u32(&mut bytes, descriptor + 8 * 4, 0);
        write_u32(&mut bytes, descriptor + 9 * 4, 16);
        write_u32(&mut bytes, descriptor + 10 * 4, 16);
        write_u32(&mut bytes, descriptor + 11 * 4, 32);
        write_u32(&mut bytes, descriptor + 12 * 4, 48);
        write_u32(&mut bytes, descriptor + 13 * 4, 16);
        bytes
    }

    #[test]
    fn parses_riscv_bootloader_envelope_and_descriptor() {
        let bytes = synthetic_bootloader();
        let bootloader = GspBootloader::parse(&bytes).expect("bootloader");
        assert_eq!(bootloader.descriptor.version, 5);
        assert_eq!(bootloader.descriptor.app_version, 0x1234);
        assert_eq!(bootloader.descriptor.manifest_size, 16);
        assert_eq!(bootloader.descriptor.monitor_data_size, 32);
        assert_eq!(bootloader.payload.size, DATA_SIZE);
    }

    #[test]
    fn rejects_descriptor_range_outside_payload() {
        let mut bytes = synthetic_bootloader();
        write_u32(
            &mut bytes,
            NVIDIA_GSP_BIN_HEADER_SIZE + 9 * 4,
            (DATA_SIZE + 1) as u32,
        );
        assert_eq!(
            GspBootloader::parse(&bytes),
            Err(GspBootloaderError::InvalidDescriptorRange {
                field: GspRmDescriptorField::Manifest,
            })
        );
    }

    #[test]
    fn rejects_payload_truncated_before_declared_end() {
        let mut bytes = synthetic_bootloader();
        bytes.truncate(bytes.len() - 1);
        assert_eq!(
            GspBootloader::parse(&bytes),
            Err(GspBootloaderError::InvalidPayload)
        );
    }

    #[test]
    fn encodes_r570_fmc_boot_params_with_c_layout_padding() {
        let params = GspFmcBootParams::r570(0x1234_5000, 256, 0x9876_0000).encode();
        assert_eq!(params.len(), NVIDIA_GSP_FMC_BOOT_PARAMS_SIZE);
        assert_eq!(read_test_u32(&params, 0), 0);
        assert_eq!(
            read_test_u32(&params, 8),
            NVIDIA_GSP_DMA_TARGET_COHERENT_SYSTEM
        );
        assert_eq!(read_test_u32(&params, 12), 256);
        assert_eq!(read_test_u64(&params, 16), 0x1234_5000);
        assert_eq!(read_test_u64(&params, 24), 0);
        assert_eq!(read_test_u32(&params, 32), 0);
        assert_eq!(read_test_u32(&params, 36), 1);
        assert_eq!(
            read_test_u32(&params, 40),
            NVIDIA_GSP_DMA_TARGET_NONCOHERENT_SYSTEM
        );
        assert_eq!(read_test_u64(&params, 48), 0x9876_0000);
        assert_eq!(read_test_u32(&params, 56), 0);
        assert_eq!(read_test_u64(&params, 64), 0);
        assert_eq!(read_test_u32(&params, 72), 0);
        assert!(params[76..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn encodes_r570_wpr_meta_at_the_256_byte_wire_offsets() {
        let mut meta = GspWprMeta::zeroed();
        meta.sysmem_addr_of_radix3_elf = 0x1000;
        meta.size_of_radix3_elf = 0x2000;
        meta.sysmem_addr_of_signature = 0x3000;
        meta.size_of_signature = 0x100;
        meta.gsp_fw_wpr_end = 0x4000;
        meta.partition_rpc_addr = 0x5000;
        meta.partition_rpc_request_offset = 0x12;
        meta.partition_rpc_reply_offset = 0x34;
        meta.elf_code_offset = 0x56;
        meta.elf_data_offset = 0x78;
        meta.elf_code_size = 0x90;
        meta.elf_data_size = 0xab;
        meta.ls_ucode_version = 0xcd;
        meta.gsp_fw_heap_vf_partition_count = 2;
        meta.flags = 3;
        meta.pmu_reserved_size = 0x1000;
        meta.verified = 0xa0a0_a0a0_a0a0_a0a0;
        let bytes = meta.encode();

        assert_eq!(bytes.len(), NVIDIA_GSP_WPR_META_SIZE);
        assert_eq!(read_test_u64(&bytes, 0), NVIDIA_GSP_WPR_META_MAGIC);
        assert_eq!(read_test_u64(&bytes, 8), NVIDIA_GSP_WPR_META_REVISION);
        assert_eq!(read_test_u64(&bytes, 16), 0x1000);
        assert_eq!(read_test_u64(&bytes, 24), 0x2000);
        assert_eq!(read_test_u64(&bytes, 72), 0x3000);
        assert_eq!(read_test_u64(&bytes, 80), 0x100);
        assert_eq!(read_test_u64(&bytes, 168), 0x4000);
        assert_eq!(read_test_u64(&bytes, 208), 0x5000);
        assert_eq!(read_test_u16(&bytes, 216), 0x12);
        assert_eq!(read_test_u16(&bytes, 218), 0x34);
        assert_eq!(read_test_u32(&bytes, 220), 0x56);
        assert_eq!(read_test_u32(&bytes, 224), 0x78);
        assert_eq!(read_test_u32(&bytes, 228), 0x90);
        assert_eq!(read_test_u32(&bytes, 232), 0xab);
        assert_eq!(read_test_u32(&bytes, 236), 0xcd);
        assert_eq!(bytes[240], 2);
        assert_eq!(bytes[241], 3);
        assert_eq!(read_test_u32(&bytes, 244), 0x1000);
        assert_eq!(read_test_u64(&bytes, 248), 0xa0a0_a0a0_a0a0_a0a0);
    }

    fn read_test_u16(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    fn read_test_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32"))
    }

    fn read_test_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64"))
    }
}
