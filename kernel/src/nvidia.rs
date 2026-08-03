#[cfg(target_os = "none")]
use alloc::vec::Vec;

#[cfg(target_os = "none")]
use bootloader_api::info::MemoryRegion;

#[cfg(target_os = "none")]
use crate::memory::PhysicalRange;
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
pub const NVIDIA_GB20X_FRAMEBUFFER_SIZE: u64 = 16 * (1u64 << 30);
pub const NVIDIA_GB20X_BIOS_ADDRESS: u64 = NVIDIA_GB20X_FRAMEBUFFER_SIZE - 0x20_000;
pub const NVIDIA_TARGET_MIN_USABLE_MEMORY_BYTES: u64 = 30 * (1u64 << 30);

const NVIDIA_GSP_FIRMWARE_PATH: &[u8] = b"/GSP.BIN";
const NVIDIA_FMC_FIRMWARE_PATH: &[u8] = b"/FMC.BIN";
const NVIDIA_BOOTLOADER_FIRMWARE_PATH: &[u8] = b"/BOOT.BIN";
const NVIDIA_FSP_BOOT_REQUEST_PATH: &[u8] = b"/NVIDIA.FSP";

pub const NVIDIA_VENDOR_ID: u16 = 0x10de;
pub const RTX_5070_DEVICE_ID: u16 = 0x2f04;
pub const NVIDIA_PROBE_MMIO_LENGTH: u64 = rustos_gpu_protocol::NVIDIA_GSP_FSP_BAR0_REQUIRED_LENGTH;
#[allow(dead_code)]
const NVIDIA_GSP_FSP_POLL_SPINS: usize = 10_000_000;
const NVIDIA_GSP_FMC_POLL_SPINS: usize = 10_000_000;
const NVIDIA_GSP_RPC_POLL_SPINS: usize = 10_000_000;

pub fn target_platform_matches(
    cpu_vendor: &str,
    cpu_brand: &str,
    hypervisor_present: bool,
    usable_memory_bytes: u64,
) -> bool {
    cpu_vendor == "AuthenticAMD"
        && cpu_brand == "AMD Ryzen 7 5800X 8-Core Processor"
        && !hypervisor_present
        && usable_memory_bytes >= NVIDIA_TARGET_MIN_USABLE_MEMORY_BYTES
}

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
    FspPacketUnaligned {
        size: usize,
    },
    FspPacketTooLarge {
        size: usize,
    },
    FspQueuePointerInvalid {
        head: u32,
        tail: u32,
    },
    FspQueueTimeout,
    FspSecureBootTimeout,
    FspUnavailable,
    FspOptInRequired,
    FspResponseTimeout,
    FspResponseBufferTooSmall {
        required: usize,
        actual: usize,
    },
    FspResponse(rustos_gpu_protocol::GspFspResponseError),
    GspRpc(rustos_gpu_protocol::GspRpcError),
    GspQueue(rustos_gpu_protocol::GspQueueError),
    GspSharedMemoryOutOfRange {
        offset: usize,
        size: usize,
        available: usize,
    },
    GspRpcTimeout {
        function: u32,
    },
    GspRpcFailed {
        function: u32,
        result: u32,
        private_result: u32,
    },
    GspRpcSequenceMismatch {
        function: u32,
        expected_rpc: u32,
        actual_rpc: u32,
    },
    GspRpcTransportSequenceMismatch {
        expected: u32,
        actual: u32,
    },
    GspStaticInfo(rustos_gpu_protocol::GspStaticInfoError),
    GspFmcBootTimeout,
    GspFmcBootFailed {
        mailbox0: u32,
        mailbox1: u32,
    },
    GspRiscvInactiveTimeout,
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
pub enum NvidiaFirmwarePart {
    Gsp,
    Fmc,
    Bootloader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvidiaGspStageError {
    StorageUnavailable,
    MissingFirmwarePart {
        part: NvidiaFirmwarePart,
    },
    InvalidFirmwareSize {
        part: NvidiaFirmwarePart,
        size: usize,
        limit: usize,
    },
    FirmwareRead {
        part: NvidiaFirmwarePart,
        expected: usize,
        actual: usize,
    },
    AllocationUnavailable {
        bytes: usize,
    },
    AddressOverflow,
    Gsp(rustos_gpu_protocol::GspFirmwareError),
    Bundle(rustos_gpu_protocol::GspFirmwareBundleError),
    SystemMemoryPlan(rustos_gpu_protocol::GspSystemMemoryPlanError),
    Framebuffer(rustos_gpu_protocol::GspFramebufferLayoutError),
    Materialization(rustos_gpu_protocol::GspMaterializationError),
    FspCot(rustos_gpu_protocol::GspFspCotError),
}

#[cfg(target_os = "none")]
#[derive(Debug)]
pub struct NvidiaGspStaging {
    system_memory: PhysicalBuffer,
    pub plan: rustos_gpu_protocol::GspBootSystemMemoryPlan,
    pub framebuffer: rustos_gpu_protocol::GspFramebufferLayout,
    pub fsp_cot: [u8; rustos_gpu_protocol::NVIDIA_GSP_FSP_COT_PACKET_SIZE],
    pub fsp_boot_requested: bool,
    pub gsp_bytes: usize,
    pub fmc_bytes: usize,
    pub bootloader_bytes: usize,
    gsp_status_sequence: u32,
    next_frame_address: u64,
}

#[cfg(target_os = "none")]
impl NvidiaGspStaging {
    pub fn system_base(&self) -> u64 {
        self.plan.system_base
    }

    pub fn system_bytes(&self) -> usize {
        self.plan.total_bytes
    }

    pub fn system_pages(&self) -> usize {
        self.system_memory.range.page_count()
    }

    pub fn system_end(&self) -> u64 {
        self.plan.end_address
    }

    pub fn next_frame_address(&self) -> u64 {
        self.next_frame_address
    }

    fn shared_memory_mut(&mut self) -> Result<&mut [u8], NvidiaError> {
        let available = self.system_memory.range.byte_length();
        let offset = self
            .plan
            .shared_memory
            .address
            .checked_sub(self.plan.system_base)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(NvidiaError::GspSharedMemoryOutOfRange {
                offset: usize::MAX,
                size: self.plan.shared_memory.size,
                available,
            })?;
        let size = self.plan.shared_memory.size;
        let end = offset
            .checked_add(size)
            .ok_or(NvidiaError::GspSharedMemoryOutOfRange {
                offset,
                size,
                available,
            })?;
        let bytes = self.system_memory.as_mut_slice();
        match bytes.get_mut(offset..end) {
            Some(shared) => Ok(shared),
            None => Err(NvidiaError::GspSharedMemoryOutOfRange {
                offset,
                size,
                available,
            }),
        }
    }

    fn shared_queue_pair(&mut self) -> Result<rustos_gpu_protocol::GspQueuePair<'_>, NvidiaError> {
        let layout = self.plan.layout.shared_memory;
        let queue_size = rustos_gpu_protocol::NVIDIA_GSP_SHARED_QUEUE_BYTES;
        let command_end = layout.command_queue_offset.checked_add(queue_size).ok_or(
            NvidiaError::GspSharedMemoryOutOfRange {
                offset: layout.command_queue_offset,
                size: queue_size,
                available: layout.total_bytes,
            },
        )?;
        let status_end = layout.status_queue_offset.checked_add(queue_size).ok_or(
            NvidiaError::GspSharedMemoryOutOfRange {
                offset: layout.status_queue_offset,
                size: queue_size,
                available: layout.total_bytes,
            },
        )?;
        let shared = self.shared_memory_mut()?;
        let available = shared.len();
        if status_end > available {
            return Err(NvidiaError::GspSharedMemoryOutOfRange {
                offset: layout.status_queue_offset,
                size: queue_size,
                available,
            });
        }
        let (before_status, status_region) = shared.split_at_mut(layout.status_queue_offset);
        let command_queue = before_status
            .get_mut(layout.command_queue_offset..command_end)
            .ok_or(NvidiaError::GspSharedMemoryOutOfRange {
                offset: layout.command_queue_offset,
                size: queue_size,
                available,
            })?;
        let status_queue =
            status_region
                .get_mut(..queue_size)
                .ok_or(NvidiaError::GspSharedMemoryOutOfRange {
                    offset: layout.status_queue_offset,
                    size: queue_size,
                    available,
                })?;
        rustos_gpu_protocol::GspQueuePair::new(command_queue, status_queue)
            .map_err(NvidiaError::GspQueue)
    }
}

#[cfg(target_os = "none")]
#[derive(Debug)]
struct PhysicalBuffer {
    range: PhysicalRange,
    mapped_address: usize,
}

#[cfg(target_os = "none")]
impl PhysicalBuffer {
    fn allocate(
        regions: &[MemoryRegion],
        physical_memory_offset: u64,
        starting_at: Option<u64>,
        byte_length: usize,
    ) -> Result<Self, NvidiaGspStageError> {
        let range = crate::memory::find_contiguous_usable_range(regions, starting_at, byte_length)
            .ok_or(NvidiaGspStageError::AllocationUnavailable { bytes: byte_length })?;
        let mapped_address = physical_memory_offset
            .checked_add(range.start_address())
            .ok_or(NvidiaGspStageError::AddressOverflow)?;
        let mapped_address =
            usize::try_from(mapped_address).map_err(|_| NvidiaGspStageError::AddressOverflow)?;
        Ok(Self {
            range,
            mapped_address,
        })
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: bootloader maps the complete physical memory range at `mapped_address`; the
        // range came from usable page-aligned firmware memory and owns no overlapping allocation.
        unsafe {
            core::slice::from_raw_parts(self.mapped_address as *const u8, self.range.byte_length())
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: same mapping and ownership guarantee as `as_slice`; caller has unique access to
        // this physical buffer while firmware bytes are loaded or materialized.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.mapped_address as *mut u8,
                self.range.byte_length(),
            )
        }
    }

    fn end_address(&self) -> Result<u64, NvidiaGspStageError> {
        self.range
            .end_address()
            .ok_or(NvidiaGspStageError::AddressOverflow)
    }
}

#[cfg(target_os = "none")]
fn firmware_size(
    part: NvidiaFirmwarePart,
    path: &[u8],
    limit: usize,
) -> Result<Option<usize>, NvidiaGspStageError> {
    let size = crate::storage::runtime_file_size(path)
        .map_err(|_| NvidiaGspStageError::StorageUnavailable)?;
    let Some(size) = size else {
        return Ok(None);
    };
    if size == 0 || size > limit {
        return Err(NvidiaGspStageError::InvalidFirmwareSize { part, size, limit });
    }
    Ok(Some(size))
}

#[cfg(target_os = "none")]
fn load_firmware_part(
    part: NvidiaFirmwarePart,
    path: &[u8],
    buffer: &mut PhysicalBuffer,
) -> Result<(), NvidiaGspStageError> {
    let expected = buffer.range.byte_length();
    let actual =
        crate::storage::read_runtime_file(path, 0, buffer.as_mut_slice()).map_err(|_| {
            NvidiaGspStageError::FirmwareRead {
                part,
                expected,
                actual: 0,
            }
        })?;
    if actual != expected {
        return Err(NvidiaGspStageError::FirmwareRead {
            part,
            expected,
            actual,
        });
    }
    Ok(())
}

#[cfg(target_os = "none")]
pub fn stage_external_gsp(
    physical_memory_offset: u64,
    regions: &[MemoryRegion],
    starting_at: Option<u64>,
) -> Result<Option<NvidiaGspStaging>, NvidiaGspStageError> {
    let gsp_size = firmware_size(
        NvidiaFirmwarePart::Gsp,
        NVIDIA_GSP_FIRMWARE_PATH,
        rustos_gpu_protocol::NVIDIA_GSP_MAX_FIRMWARE_SIZE,
    )?;
    let fmc_size = firmware_size(
        NvidiaFirmwarePart::Fmc,
        NVIDIA_FMC_FIRMWARE_PATH,
        rustos_gpu_protocol::NVIDIA_GSP_FMC_MAX_SIZE,
    )?;
    let bootloader_size = firmware_size(
        NvidiaFirmwarePart::Bootloader,
        NVIDIA_BOOTLOADER_FIRMWARE_PATH,
        rustos_gpu_protocol::NVIDIA_GSP_BOOTLOADER_MAX_SIZE,
    )?;
    if gsp_size.is_none() && fmc_size.is_none() && bootloader_size.is_none() {
        return Ok(None);
    }
    let gsp_size = gsp_size.ok_or(NvidiaGspStageError::MissingFirmwarePart {
        part: NvidiaFirmwarePart::Gsp,
    })?;
    let fmc_size = fmc_size.ok_or(NvidiaGspStageError::MissingFirmwarePart {
        part: NvidiaFirmwarePart::Fmc,
    })?;
    let bootloader_size = bootloader_size.ok_or(NvidiaGspStageError::MissingFirmwarePart {
        part: NvidiaFirmwarePart::Bootloader,
    })?;

    let mut next = starting_at;
    let mut gsp_source = PhysicalBuffer::allocate(regions, physical_memory_offset, next, gsp_size)?;
    next = Some(gsp_source.end_address()?);
    let mut fmc_source = PhysicalBuffer::allocate(regions, physical_memory_offset, next, fmc_size)?;
    next = Some(fmc_source.end_address()?);
    let mut bootloader_source =
        PhysicalBuffer::allocate(regions, physical_memory_offset, next, bootloader_size)?;
    next = Some(bootloader_source.end_address()?);

    load_firmware_part(
        NvidiaFirmwarePart::Gsp,
        NVIDIA_GSP_FIRMWARE_PATH,
        &mut gsp_source,
    )?;
    load_firmware_part(
        NvidiaFirmwarePart::Fmc,
        NVIDIA_FMC_FIRMWARE_PATH,
        &mut fmc_source,
    )?;
    load_firmware_part(
        NvidiaFirmwarePart::Bootloader,
        NVIDIA_BOOTLOADER_FIRMWARE_PATH,
        &mut bootloader_source,
    )?;

    let gsp = rustos_gpu_protocol::GspFirmware::parse(gsp_source.as_slice())
        .map_err(NvidiaGspStageError::Gsp)?;
    let expected_version = gsp.version_bytes(gsp_source.as_slice());
    let bundle = rustos_gpu_protocol::GspFirmwareBundle::parse(
        gsp_source.as_slice(),
        fmc_source.as_slice(),
        bootloader_source.as_slice(),
        expected_version,
    )
    .map_err(NvidiaGspStageError::Bundle)?;
    let sizing_plan = rustos_gpu_protocol::GspBootSystemMemoryPlan::r570_gb20x(bundle, 0)
        .map_err(NvidiaGspStageError::SystemMemoryPlan)?;
    let mut system_memory = PhysicalBuffer::allocate(
        regions,
        physical_memory_offset,
        next,
        sizing_plan.total_bytes,
    )?;
    let plan = rustos_gpu_protocol::GspBootSystemMemoryPlan::r570_gb20x(
        bundle,
        system_memory.range.start_address(),
    )
    .map_err(NvidiaGspStageError::SystemMemoryPlan)?;
    if plan.total_bytes != sizing_plan.total_bytes {
        return Err(NvidiaGspStageError::AddressOverflow);
    }
    let framebuffer = rustos_gpu_protocol::GspFramebufferLayout::r570_gb20x(
        NVIDIA_GB20X_FRAMEBUFFER_SIZE,
        NVIDIA_GB20X_BIOS_ADDRESS,
        plan.gsp_image_bytes,
        plan.bootloader_bytes,
    )
    .map_err(NvidiaGspStageError::Framebuffer)?;
    let frts_vidmem_offset = framebuffer
        .frts_vidmem_offset()
        .map_err(NvidiaGspStageError::Framebuffer)?;
    let fsp_cot = rustos_gpu_protocol::GspFspCot::gb20x(
        plan.fmc_image.address,
        plan.fmc_args.address,
        frts_vidmem_offset,
        u32::try_from(framebuffer.frts_size).map_err(|_| NvidiaGspStageError::AddressOverflow)?,
        bundle.fmc.hash.bytes(fmc_source.as_slice()),
        bundle.fmc.public_key.bytes(fmc_source.as_slice()),
        bundle.fmc.signature.bytes(fmc_source.as_slice()),
    )
    .encode()
    .map_err(NvidiaGspStageError::FspCot)?;
    plan.materialize_bundle_into(
        bundle,
        gsp_source.as_slice(),
        fmc_source.as_slice(),
        bootloader_source.as_slice(),
        framebuffer,
        system_memory.as_mut_slice(),
    )
    .map_err(NvidiaGspStageError::Materialization)?;
    let next_frame_address = system_memory.end_address()?;
    let fsp_boot_requested = crate::storage::runtime_file_size(NVIDIA_FSP_BOOT_REQUEST_PATH)
        .map_err(|_| NvidiaGspStageError::StorageUnavailable)?
        .is_some();
    Ok(Some(NvidiaGspStaging {
        system_memory,
        plan,
        framebuffer,
        fsp_cot,
        fsp_boot_requested,
        gsp_bytes: gsp_size,
        fmc_bytes: fmc_size,
        bootloader_bytes: bootloader_size,
        gsp_status_sequence: 0,
        next_frame_address,
    }))
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
    pub gsp_hwcfg2: u32,
    pub gsp_mailbox0: u32,
    pub gsp_mailbox1: u32,
    pub gsp_riscv_active: bool,
    pub gsp_riscv_lockdown: bool,
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
            gsp_hwcfg2: 0,
            gsp_mailbox0: 0,
            gsp_mailbox1: 0,
            gsp_riscv_active: false,
            gsp_riscv_lockdown: true,
        }
    }

    fn read(mmio: MmioRegion) -> Result<Self, NvidiaError> {
        let hwcfg2 = mmio.read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_FALCON_HWCFG2))?;
        let gsp_hwcfg2 = mmio.read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FALCON_HWCFG2))?;
        Ok(Self {
            secure_boot_status: mmio.read_u32(u64::from(
                rustos_gpu_protocol::NVIDIA_GSP_FSP_BOOT_COMPLETE_REGISTER_GB20X,
            ))?,
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
            gsp_hwcfg2,
            gsp_mailbox0: mmio.read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FALCON_MAILBOX0))?,
            gsp_mailbox1: mmio.read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FALCON_MAILBOX1))?,
            gsp_riscv_active: mmio.read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FALCON_CPUCTL))?
                & (1 << rustos_gpu_protocol::NVIDIA_GSP_FALCON_CPUCTL_RISCV_ACTIVE_BIT)
                != 0,
            gsp_riscv_lockdown: gsp_hwcfg2
                & (1 << rustos_gpu_protocol::NVIDIA_GSP_FALCON_HWCFG2_RISCV_BRANCH_PRIVILEGE_LOCKDOWN_BIT)
                != 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvidiaGspReady {
    pub hwcfg2: u32,
    pub mailbox0: u32,
    pub mailbox1: u32,
    pub riscv_active: bool,
    pub riscv_lockdown: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvidiaGspBootResult {
    pub fsp_response: rustos_gpu_protocol::GspFspResponse,
    pub gsp: NvidiaGspReady,
    pub static_info: rustos_gpu_protocol::GspStaticInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NvidiaGspFmcPollState {
    TargetMaskLocked,
    WaitingForBootParams,
    BootFailed { mailbox0: u32, mailbox1: u32 },
    RiscvLockdown,
    RiscvInactive,
    Ready(NvidiaGspReady),
}

fn classify_gsp_fmc_state(
    hwcfg2: u32,
    mailbox0: u32,
    mailbox1: u32,
    fmc_args_address: u64,
    cpuctl: u32,
) -> NvidiaGspFmcPollState {
    let target_mask = rustos_gpu_protocol::NVIDIA_GSP_FALCON_HWCFG2_TARGET_MASK;
    if hwcfg2 & target_mask == rustos_gpu_protocol::NVIDIA_GSP_FALCON_HWCFG2_TARGET_MASK_LOCKED {
        return NvidiaGspFmcPollState::TargetMaskLocked;
    }

    let mailbox_address = u64::from(mailbox0) | (u64::from(mailbox1) << 32);
    if mailbox0 != 0 {
        if mailbox_address != fmc_args_address {
            return NvidiaGspFmcPollState::BootFailed { mailbox0, mailbox1 };
        }
        return NvidiaGspFmcPollState::WaitingForBootParams;
    }

    let riscv_lockdown = hwcfg2
        & (1 << rustos_gpu_protocol::NVIDIA_GSP_FALCON_HWCFG2_RISCV_BRANCH_PRIVILEGE_LOCKDOWN_BIT)
        != 0;
    if riscv_lockdown {
        return NvidiaGspFmcPollState::RiscvLockdown;
    }

    let riscv_active =
        cpuctl & (1 << rustos_gpu_protocol::NVIDIA_GSP_FALCON_CPUCTL_RISCV_ACTIVE_BIT) != 0;
    if !riscv_active {
        return NvidiaGspFmcPollState::RiscvInactive;
    }

    NvidiaGspFmcPollState::Ready(NvidiaGspReady {
        hwcfg2,
        mailbox0,
        mailbox1,
        riscv_active,
        riscv_lockdown,
    })
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

    fn wait_secure_boot(&self) -> Result<u32, NvidiaError> {
        for _ in 0..NVIDIA_GSP_FSP_POLL_SPINS {
            let status = self.mmio.read_u32(u64::from(
                rustos_gpu_protocol::NVIDIA_GSP_FSP_BOOT_COMPLETE_REGISTER_GB20X,
            ))?;
            if status == rustos_gpu_protocol::NVIDIA_GSP_FSP_BOOT_COMPLETE_STATUS_SUCCESS {
                return Ok(status);
            }
            core::hint::spin_loop();
        }
        Err(NvidiaError::FspSecureBootTimeout)
    }

    fn wait_gsp_fmc_ready(&self, fmc_args_address: u64) -> Result<NvidiaGspReady, NvidiaError> {
        let mut last_state = NvidiaGspFmcPollState::TargetMaskLocked;
        for _ in 0..NVIDIA_GSP_FMC_POLL_SPINS {
            let hwcfg2 = self
                .mmio
                .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FALCON_HWCFG2))?;
            let mailbox0 = self
                .mmio
                .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FALCON_MAILBOX0))?;
            let mailbox1 = self
                .mmio
                .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FALCON_MAILBOX1))?;
            let cpuctl = self
                .mmio
                .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FALCON_CPUCTL))?;
            last_state =
                classify_gsp_fmc_state(hwcfg2, mailbox0, mailbox1, fmc_args_address, cpuctl);
            match last_state {
                NvidiaGspFmcPollState::BootFailed { mailbox0, mailbox1 } => {
                    return Err(NvidiaError::GspFmcBootFailed { mailbox0, mailbox1 });
                }
                NvidiaGspFmcPollState::Ready(ready) => return Ok(ready),
                NvidiaGspFmcPollState::TargetMaskLocked
                | NvidiaGspFmcPollState::WaitingForBootParams
                | NvidiaGspFmcPollState::RiscvLockdown
                | NvidiaGspFmcPollState::RiscvInactive => core::hint::spin_loop(),
            }
        }
        match last_state {
            NvidiaGspFmcPollState::RiscvInactive => Err(NvidiaError::GspRiscvInactiveTimeout),
            NvidiaGspFmcPollState::BootFailed { mailbox0, mailbox1 } => {
                Err(NvidiaError::GspFmcBootFailed { mailbox0, mailbox1 })
            }
            NvidiaGspFmcPollState::TargetMaskLocked
            | NvidiaGspFmcPollState::WaitingForBootParams
            | NvidiaGspFmcPollState::RiscvLockdown
            | NvidiaGspFmcPollState::Ready(_) => Err(NvidiaError::GspFmcBootTimeout),
        }
    }

    // Wire-ready GSP-RM transport. Boot keeps this uncalled until the r570 RM bootstrap
    // supplies SetSystemInfo and SetRegistry; queue writes are still explicit opt-in.
    #[cfg(target_os = "none")]
    fn send_gsp_rpc(
        &self,
        staging: &mut NvidiaGspStaging,
        function: u32,
        transport_sequence: u32,
        rpc_sequence: u32,
        payload: &[u8],
    ) -> Result<(), NvidiaError> {
        if !staging.fsp_boot_requested {
            return Err(NvidiaError::FspOptInRequired);
        }
        let message = rustos_gpu_protocol::encode_gsp_rpc_with_sequences(
            function,
            transport_sequence,
            rpc_sequence,
            payload,
        )
        .map_err(NvidiaError::GspRpc)?;
        let mut queues = staging.shared_queue_pair()?;
        queues
            .write_command_message(&message)
            .map_err(NvidiaError::GspQueue)?;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.mmio.write_u32(
            u64::from(rustos_gpu_protocol::NVIDIA_GSP_FALCON_QUEUE_HEAD),
            0,
        )?;
        Ok(())
    }

    #[cfg(target_os = "none")]
    fn try_receive_gsp_rpc(
        &self,
        staging: &mut NvidiaGspStaging,
    ) -> Result<Option<Vec<u8>>, NvidiaError> {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let mut queues = staging.shared_queue_pair()?;
        let message = queues
            .try_receive_status_message()
            .map_err(NvidiaError::GspQueue)?;
        let Some(message) = message else {
            return Ok(None);
        };
        let parsed =
            rustos_gpu_protocol::GspRpcMessage::parse(&message).map_err(NvidiaError::GspRpc)?;
        validate_gsp_rpc_transport_sequence(parsed, staging.gsp_status_sequence)?;
        staging.gsp_status_sequence = staging.gsp_status_sequence.wrapping_add(1);
        Ok(Some(message))
    }

    #[cfg(target_os = "none")]
    fn wait_for_gsp_function(
        &self,
        staging: &mut NvidiaGspStaging,
        function: u32,
    ) -> Result<Vec<u8>, NvidiaError> {
        for _ in 0..NVIDIA_GSP_RPC_POLL_SPINS {
            if let Some(message) = self.try_receive_gsp_rpc(staging)? {
                let parsed = rustos_gpu_protocol::GspRpcMessage::parse(&message)
                    .map_err(NvidiaError::GspRpc)?;
                if parsed.function() == function {
                    return Ok(message);
                }
            }
            core::hint::spin_loop();
        }
        Err(NvidiaError::GspRpcTimeout { function })
    }

    fn send(&self, packet: &[u8]) -> Result<(), NvidiaError> {
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

    fn try_receive(&self, buffer: &mut [u8]) -> Result<Option<usize>, NvidiaError> {
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
        self.mmio.write_u32(
            u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_TAIL),
            head,
        )?;
        self.mmio.write_u32(
            u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_HEAD),
            head,
        )?;
        Ok(Some(packet_size))
    }

    fn send_sync(
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
        validate_packet(packet)?;
        self.mmio.write_u32(
            u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_ADDRESS),
            rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_WRITE_BIT,
        )?;
        for word in packet.chunks_exact(4) {
            self.mmio.write_u32(
                u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_DATA),
                u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
            )?;
        }
        Ok(())
    }

    fn read_emem(&self, packet: &mut [u8]) -> Result<(), NvidiaError> {
        if packet.is_empty() {
            return Err(NvidiaError::FspResponseBufferTooSmall {
                required: 4,
                actual: 0,
            });
        }
        if packet.len() % core::mem::size_of::<u32>() != 0 {
            return Err(NvidiaError::FspResponseBufferTooSmall {
                required: packet.len() + (4 - packet.len() % 4),
                actual: packet.len(),
            });
        }
        self.mmio.write_u32(
            u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_ADDRESS),
            rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_READ_BIT,
        )?;
        for word in packet.chunks_exact_mut(4) {
            let value = self
                .mmio
                .read_u32(u64::from(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_DATA))?;
            word.copy_from_slice(&value.to_le_bytes());
        }
        Ok(())
    }
}

#[cfg(target_os = "none")]
pub fn boot_external_gsp(
    probe: &NvidiaProbe,
    staging: &mut NvidiaGspStaging,
) -> Result<NvidiaGspBootResult, NvidiaError> {
    if !staging.fsp_boot_requested {
        return Err(NvidiaError::FspOptInRequired);
    }
    let transport = probe.fsp_transport().ok_or(NvidiaError::FspUnavailable)?;
    transport.wait_secure_boot()?;
    let fsp_response = transport.send_sync(
        rustos_gpu_protocol::NVIDIA_GSP_FSP_NVDM_TYPE_COT,
        &staging.fsp_cot,
    )?;
    let gsp = transport.wait_gsp_fmc_ready(staging.plan.fmc_args.address)?;
    let system_info = rustos_gpu_protocol::GspSystemInfoR570::r570_gb20x(
        probe.bar0_base,
        probe.bar1_base.unwrap_or(0),
        probe.bar3_base.unwrap_or(0),
        probe.address.dev_id(),
        probe.device_id,
        probe.vendor_id,
        probe.subsystem_device_id,
        probe.subsystem_vendor_id,
        probe.revision_id,
    )
    .encode();
    transport.send_gsp_rpc(
        staging,
        rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_GSP_SET_SYSTEM_INFO,
        0,
        0,
        &system_info,
    )?;
    crate::kprintln!(
        "driver: nvidia GSP-RM command function={} transport_sequence=0 rpc_sequence=0 payload_bytes={} queue=shared status=sent",
        rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_GSP_SET_SYSTEM_INFO,
        system_info.len(),
    );
    let registry = rustos_gpu_protocol::encode_gsp_registry();
    transport.send_gsp_rpc(
        staging,
        rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_SET_REGISTRY,
        1,
        0,
        &registry,
    )?;
    crate::kprintln!(
        "driver: nvidia GSP-RM command function={} transport_sequence=1 rpc_sequence=0 payload_bytes={} queue=shared status=sent",
        rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_SET_REGISTRY,
        registry.len(),
    );
    let init_done = transport
        .wait_for_gsp_function(staging, rustos_gpu_protocol::NVIDIA_GSP_EVENT_GSP_INIT_DONE)?;
    let init_done =
        rustos_gpu_protocol::GspRpcMessage::parse(&init_done).map_err(NvidiaError::GspRpc)?;
    crate::kprintln!(
        "driver: nvidia GSP-RM event function={} transport_sequence={} rpc_sequence={} result=0x{:08x} private_result=0x{:08x} status=consumed",
        init_done.function(),
        init_done.transport_sequence(),
        init_done.rpc_sequence(),
        init_done.rpc_result(),
        init_done.rpc_result_private(),
    );
    validate_gsp_rpc_sequence_zero(init_done)?;
    validate_gsp_rpc_result(init_done)?;
    let static_info_request = rustos_gpu_protocol::encode_gsp_static_info_request();
    transport.send_gsp_rpc(
        staging,
        rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO,
        2,
        0,
        &static_info_request,
    )?;
    crate::kprintln!(
        "driver: nvidia GSP-RM command function={} transport_sequence=2 rpc_sequence=0 payload_bytes={} queue=shared status=sent",
        rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO,
        static_info_request.len(),
    );
    let static_info_message = transport.wait_for_gsp_function(
        staging,
        rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO,
    )?;
    let static_info_message = rustos_gpu_protocol::GspRpcMessage::parse(&static_info_message)
        .map_err(NvidiaError::GspRpc)?;
    crate::kprintln!(
        "driver: nvidia GSP-RM reply function={} transport_sequence={} rpc_sequence={} result=0x{:08x} private_result=0x{:08x} status=received",
        static_info_message.function(),
        static_info_message.transport_sequence(),
        static_info_message.rpc_sequence(),
        static_info_message.rpc_result(),
        static_info_message.rpc_result_private(),
    );
    validate_gsp_rpc_sequence_zero(static_info_message)?;
    validate_gsp_rpc_result(static_info_message)?;
    let static_info = rustos_gpu_protocol::parse_gsp_static_info(static_info_message.payload())
        .map_err(NvidiaError::GspStaticInfo)?;
    Ok(NvidiaGspBootResult {
        fsp_response,
        gsp,
        static_info,
    })
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
    pub subsystem_vendor_id: u16,
    pub subsystem_device_id: u16,
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

    #[cfg(target_os = "none")]
    pub fn enable_bus_master(&mut self) -> Result<(), NvidiaError> {
        if self.bus_master_enabled {
            return Ok(());
        }
        let command = crate::pci::enable_bus_master(self.address)?;
        self.bus_master_enabled = command & (1 << 2) != 0;
        if !self.bus_master_enabled {
            return Err(NvidiaError::Resources(
                PciResourceError::BusMasterEnableFailed,
            ));
        }
        Ok(())
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
            subsystem_vendor_id: device.subsystem_vendor_id,
            subsystem_device_id: device.subsystem_device_id,
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

fn validate_gsp_rpc_sequence_zero(
    message: rustos_gpu_protocol::GspRpcMessage<'_>,
) -> Result<(), NvidiaError> {
    if message.rpc_sequence() != 0 {
        return Err(NvidiaError::GspRpcSequenceMismatch {
            function: message.function(),
            expected_rpc: 0,
            actual_rpc: message.rpc_sequence(),
        });
    }
    Ok(())
}

fn validate_gsp_rpc_result(
    message: rustos_gpu_protocol::GspRpcMessage<'_>,
) -> Result<(), NvidiaError> {
    if message.rpc_result() != 0 {
        return Err(NvidiaError::GspRpcFailed {
            function: message.function(),
            result: message.rpc_result(),
            private_result: message.rpc_result_private(),
        });
    }
    Ok(())
}

fn validate_gsp_rpc_transport_sequence(
    message: rustos_gpu_protocol::GspRpcMessage<'_>,
    expected: u32,
) -> Result<(), NvidiaError> {
    if message.transport_sequence() != expected {
        return Err(NvidiaError::GspRpcTransportSequenceMismatch {
            expected,
            actual: message.transport_sequence(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::pci::PciCapabilities;

    fn put_u32(bytes: &mut [u8], offset: u32, value: u32) {
        bytes[offset as usize..offset as usize + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn device(device_id: u16, bars: [PciBar; 6]) -> PciDevice {
        PciDevice {
            address: PciAddress::new(0x0b, 0, 0),
            vendor_id: NVIDIA_VENDOR_ID,
            device_id,
            subsystem_vendor_id: 0,
            subsystem_device_id: 0,
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
    fn native_gsp_status_requires_exact_target_platform() {
        assert!(target_platform_matches(
            "AuthenticAMD",
            "AMD Ryzen 7 5800X 8-Core Processor",
            false,
            NVIDIA_TARGET_MIN_USABLE_MEMORY_BYTES,
        ));
        assert!(!target_platform_matches(
            "AuthenticAMD",
            "AMD Ryzen 7 5800X 8-Core Processor",
            true,
            NVIDIA_TARGET_MIN_USABLE_MEMORY_BYTES,
        ));
        assert!(!target_platform_matches(
            "AuthenticAMD",
            "AMD Ryzen 7 5800X3D 8-Core Processor",
            false,
            NVIDIA_TARGET_MIN_USABLE_MEMORY_BYTES,
        ));
        assert!(!target_platform_matches(
            "AuthenticAMD",
            "AMD Ryzen 7 5800X 8-Core Processor",
            false,
            NVIDIA_TARGET_MIN_USABLE_MEMORY_BYTES - 1,
        ));
    }

    #[test]
    fn requires_zero_rpc_sequence_and_success_result() {
        let mut valid = rustos_gpu_protocol::encode_gsp_rpc_with_sequences(
            rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO,
            2,
            0,
            &[],
        )
        .expect("static info reply");
        let result_offset = rustos_gpu_protocol::NVIDIA_GSP_MESSAGE_HEADER_SIZE + 16;
        valid[result_offset..result_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        let valid = rustos_gpu_protocol::GspRpcMessage::parse(&valid).expect("parse reply");
        assert_eq!(validate_gsp_rpc_sequence_zero(valid), Ok(()));
        assert_eq!(validate_gsp_rpc_result(valid), Ok(()));

        let wrong = rustos_gpu_protocol::encode_gsp_rpc_with_sequences(
            rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO,
            2,
            2,
            &[],
        )
        .expect("static info reply");
        let wrong = rustos_gpu_protocol::GspRpcMessage::parse(&wrong).expect("parse reply");
        assert_eq!(
            validate_gsp_rpc_sequence_zero(wrong),
            Err(NvidiaError::GspRpcSequenceMismatch {
                function: rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO,
                expected_rpc: 0,
                actual_rpc: 2,
            })
        );

        let mut failed = rustos_gpu_protocol::encode_gsp_rpc_with_sequences(
            rustos_gpu_protocol::NVIDIA_GSP_EVENT_GSP_INIT_DONE,
            0,
            0,
            &[],
        )
        .expect("GSP_INIT_DONE event");
        failed[result_offset..result_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        let private_result_offset = rustos_gpu_protocol::NVIDIA_GSP_MESSAGE_HEADER_SIZE + 20;
        failed[private_result_offset..private_result_offset + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        let failed = rustos_gpu_protocol::GspRpcMessage::parse(&failed).expect("parse event");
        assert_eq!(validate_gsp_rpc_sequence_zero(failed), Ok(()));
        assert_eq!(
            validate_gsp_rpc_result(failed),
            Err(NvidiaError::GspRpcFailed {
                function: rustos_gpu_protocol::NVIDIA_GSP_EVENT_GSP_INIT_DONE,
                result: 1,
                private_result: 0,
            })
        );
    }

    #[test]
    fn requires_monotonic_status_queue_transport_sequence() {
        let valid = rustos_gpu_protocol::encode_gsp_rpc_with_sequences(
            rustos_gpu_protocol::NVIDIA_GSP_EVENT_GSP_INIT_DONE,
            0,
            0,
            &[],
        )
        .expect("event");
        let valid = rustos_gpu_protocol::GspRpcMessage::parse(&valid).expect("parse event");
        assert_eq!(validate_gsp_rpc_transport_sequence(valid, 0), Ok(()));

        let wrong = rustos_gpu_protocol::encode_gsp_rpc_with_sequences(
            rustos_gpu_protocol::NVIDIA_GSP_FUNCTION_GET_GSP_STATIC_INFO,
            5,
            0,
            &[],
        )
        .expect("reply");
        let wrong = rustos_gpu_protocol::GspRpcMessage::parse(&wrong).expect("parse reply");
        assert_eq!(
            validate_gsp_rpc_transport_sequence(wrong, 1),
            Err(NvidiaError::GspRpcTransportSequenceMismatch {
                expected: 1,
                actual: 5,
            })
        );
    }

    #[test]
    fn waits_for_the_gb20x_fsp_secure_boot_status() {
        let mut mmio_bytes = vec![0u8; NVIDIA_PROBE_MMIO_LENGTH as usize];
        let status_offset = rustos_gpu_protocol::NVIDIA_GSP_FSP_BOOT_COMPLETE_REGISTER_GB20X;
        mmio_bytes[status_offset as usize..status_offset as usize + 4].copy_from_slice(
            &rustos_gpu_protocol::NVIDIA_GSP_FSP_BOOT_COMPLETE_STATUS_SUCCESS.to_le_bytes(),
        );
        let mmio = MmioRegion::for_test(mmio_bytes.as_mut_ptr() as u64, NVIDIA_PROBE_MMIO_LENGTH);
        let transport = NvidiaFspTransport::new(mmio);

        assert_eq!(
            transport.wait_secure_boot(),
            Ok(rustos_gpu_protocol::NVIDIA_GSP_FSP_BOOT_COMPLETE_STATUS_SUCCESS)
        );
    }

    #[test]
    fn classifies_the_gb20x_post_cot_state_machine() {
        let fmc_args_address = 0x0000_0001_2345_6000;
        let locked = rustos_gpu_protocol::NVIDIA_GSP_FALCON_HWCFG2_TARGET_MASK_LOCKED;
        assert_eq!(
            classify_gsp_fmc_state(locked, 0, 0, fmc_args_address, 0),
            NvidiaGspFmcPollState::TargetMaskLocked
        );
        assert_eq!(
            classify_gsp_fmc_state(
                0,
                fmc_args_address as u32,
                (fmc_args_address >> 32) as u32,
                fmc_args_address,
                0,
            ),
            NvidiaGspFmcPollState::WaitingForBootParams
        );
        assert_eq!(
            classify_gsp_fmc_state(0, 0x1234, 0, fmc_args_address, 0),
            NvidiaGspFmcPollState::BootFailed {
                mailbox0: 0x1234,
                mailbox1: 0,
            }
        );
        assert_eq!(
            classify_gsp_fmc_state(
                1 << rustos_gpu_protocol::NVIDIA_GSP_FALCON_HWCFG2_RISCV_BRANCH_PRIVILEGE_LOCKDOWN_BIT,
                0,
                0,
                fmc_args_address,
                1 << rustos_gpu_protocol::NVIDIA_GSP_FALCON_CPUCTL_RISCV_ACTIVE_BIT,
            ),
            NvidiaGspFmcPollState::RiscvLockdown
        );
        assert_eq!(
            classify_gsp_fmc_state(0, 0, 0, fmc_args_address, 0),
            NvidiaGspFmcPollState::RiscvInactive
        );
        assert_eq!(
            classify_gsp_fmc_state(
                0,
                0,
                0,
                fmc_args_address,
                1 << rustos_gpu_protocol::NVIDIA_GSP_FALCON_CPUCTL_RISCV_ACTIVE_BIT,
            ),
            NvidiaGspFmcPollState::Ready(NvidiaGspReady {
                hwcfg2: 0,
                mailbox0: 0,
                mailbox1: 0,
                riscv_active: true,
                riscv_lockdown: false,
            })
        );
    }

    #[test]
    fn waits_for_gb20x_gsp_fmc_release_and_riscv_activity() {
        let mut mmio_bytes = vec![0u8; NVIDIA_PROBE_MMIO_LENGTH as usize];
        put_u32(
            &mut mmio_bytes,
            rustos_gpu_protocol::NVIDIA_GSP_FALCON_HWCFG2,
            0,
        );
        put_u32(
            &mut mmio_bytes,
            rustos_gpu_protocol::NVIDIA_GSP_FALCON_CPUCTL,
            1 << rustos_gpu_protocol::NVIDIA_GSP_FALCON_CPUCTL_RISCV_ACTIVE_BIT,
        );
        let mmio = MmioRegion::for_test(mmio_bytes.as_mut_ptr() as u64, NVIDIA_PROBE_MMIO_LENGTH);
        let transport = NvidiaFspTransport::new(mmio);

        assert_eq!(
            transport.wait_gsp_fmc_ready(0x0000_0001_2345_6000),
            Ok(NvidiaGspReady {
                hwcfg2: 0,
                mailbox0: 0,
                mailbox1: 0,
                riscv_active: true,
                riscv_lockdown: false,
            })
        );
    }

    #[test]
    fn rejects_a_gb20x_gsp_fmc_error_mailbox() {
        let mut mmio_bytes = vec![0u8; NVIDIA_PROBE_MMIO_LENGTH as usize];
        put_u32(
            &mut mmio_bytes,
            rustos_gpu_protocol::NVIDIA_GSP_FALCON_MAILBOX0,
            0x1234,
        );
        let mmio = MmioRegion::for_test(mmio_bytes.as_mut_ptr() as u64, NVIDIA_PROBE_MMIO_LENGTH);
        let transport = NvidiaFspTransport::new(mmio);

        assert_eq!(
            transport.wait_gsp_fmc_ready(0x0000_0001_2345_6000),
            Err(NvidiaError::GspFmcBootFailed {
                mailbox0: 0x1234,
                mailbox1: 0,
            })
        );
    }

    #[test]
    fn sends_fsp_packet_in_one_auto_incrementing_emem_burst() {
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
            rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_WRITE_BIT
        );
        assert_eq!(
            read_u32(rustos_gpu_protocol::NVIDIA_GSP_FSP_EMEM_PIO_DATA),
            u32::from_le_bytes(packet[864..868].try_into().expect("last word"))
        );
    }

    #[test]
    fn consumes_fsp_response_without_resetting_nonzero_message_queue_head() {
        let mut mmio_bytes = vec![0u8; NVIDIA_PROBE_MMIO_LENGTH as usize];
        put_u32(
            &mut mmio_bytes,
            rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_HEAD,
            16,
        );
        put_u32(
            &mut mmio_bytes,
            rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_TAIL,
            32,
        );
        let mmio = MmioRegion::for_test(mmio_bytes.as_mut_ptr() as u64, NVIDIA_PROBE_MMIO_LENGTH);
        let transport = NvidiaFspTransport::new(mmio);
        let mut response = [0u8; 20];

        assert_eq!(transport.try_receive(&mut response), Ok(Some(20)));
        let read_u32 = |offset: u32| {
            u32::from_le_bytes(
                mmio_bytes[offset as usize..offset as usize + 4]
                    .try_into()
                    .expect("u32"),
            )
        };
        assert_eq!(read_u32(rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_HEAD), 16);
        assert_eq!(read_u32(rustos_gpu_protocol::NVIDIA_GSP_FSP_MSGQ_TAIL), 16);
    }
}
