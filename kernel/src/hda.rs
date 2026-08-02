use bootloader_api::info::MemoryRegion;

use crate::memory::{FrameAllocator, PAGE_SIZE};
use crate::pci::{
    MmioError, MmioRegion, PciAddress, PciDevice, PciDeviceResources, PciInventory,
    PciResourceError,
};

const HDA_BAR: usize = 0;
const HDA_MMIO_LENGTH: u64 = 0x4000;

const REG_GCAP: u64 = 0x00;
const REG_GCTL: u64 = 0x08;
const REG_STATESTS: u64 = 0x0e;
const REG_IC: u64 = 0x60;
const REG_IR: u64 = 0x64;
const REG_IRS: u64 = 0x68;
const REG_STREAM_BASE: u64 = 0x80;
const REG_STREAM_STRIDE: u64 = 0x20;
const REG_SD_CTL: u64 = 0x00;
const REG_SD_STS: u64 = 0x03;
const REG_SD_CBL: u64 = 0x08;
const REG_SD_LVI: u64 = 0x0c;
const REG_SD_FORMAT: u64 = 0x12;
const REG_SD_BDLPL: u64 = 0x18;
const REG_SD_BDLPU: u64 = 0x1c;

const GCTL_RESET: u32 = 1 << 0;
const IRS_VALID: u16 = 1 << 1;
const IRS_BUSY: u16 = 1 << 0;
const SD_CTL_DMA_START: u32 = 1 << 1;
const SD_CTL_STREAM_TAG_SHIFT: u32 = 20;
const SD_INT_DESC_ERR: u8 = 0x10;
const SD_INT_FIFO_ERR: u8 = 0x08;
const HDA_FORMAT_STEREO_S16_48K: u16 = 0x11;

const GET_PARAMETERS: u32 = 0x0f00;
const GET_CONNECT_LIST: u32 = 0x0f02;
const SET_STREAM_FORMAT: u32 = 0x0200;
const SET_AMP_GAIN_MUTE: u32 = 0x0300;
const SET_CONNECT_SEL: u32 = 0x0701;
const SET_CHANNEL_STREAMID: u32 = 0x0706;
const SET_PIN_WIDGET_CONTROL: u32 = 0x0707;

const AC_PAR_FUNCTION_TYPE: u16 = 0x05;
const AC_PAR_AUDIO_WIDGET_CAP: u16 = 0x09;
const AC_PAR_PIN_CAP: u16 = 0x0c;
const AC_PAR_AMP_OUT_CAP: u16 = 0x12;
const AC_PAR_CONNLIST_LEN: u16 = 0x0e;
const AC_PAR_NODE_COUNT: u16 = 0x04;
const AC_GRP_AUDIO_FUNCTION: u8 = 0x01;
const AC_WID_AUD_OUT: u8 = 0x00;
const AC_WID_PIN: u8 = 0x04;
const AC_WCAP_OUT_AMP: u32 = 1 << 2;
const AC_WCAP_CONN_LIST: u32 = 1 << 8;
const AC_WCAP_TYPE_SHIFT: u32 = 20;
const AC_PINCAP_OUT: u32 = 1 << 4;
const AC_PINCTL_OUT_EN: u16 = 1 << 6;
const AC_AMPCAP_NUM_STEPS_SHIFT: u32 = 8;
const AC_AMP_SET_OUTPUT: u16 = 1 << 15;
const AC_AMP_SET_LEFT: u16 = 1 << 13;
const AC_AMP_SET_RIGHT: u16 = 1 << 12;
const AC_AMP_GAIN_MASK: u16 = 0x7f;

const BDL_IOC: u32 = 1;
const BDL_ENTRY_BYTES: u64 = 16;
const BDL_ENTRIES: usize = 32;
const PCM_PAGE_COUNT: usize = BDL_ENTRIES;
const PCM_BYTES_PER_FRAME: u64 = 4;
const PCM_FRAMES_PER_PAGE: u64 = PAGE_SIZE / PCM_BYTES_PER_FRAME;
const PCM_FRAME_COUNT: u64 = PCM_FRAMES_PER_PAGE * PCM_PAGE_COUNT as u64;
const OUTPUT_STREAM_INDEX: u8 = 4;
const STREAM_TAG: u8 = 1;
const COMMAND_TIMEOUT_SPINS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdaError {
    MemorySpaceDisabled,
    Resources(PciResourceError),
    Mmio(MmioError),
    NoOutputStreams,
    ResetFailed,
    NoCodec,
    CommandTimeout {
        command: u32,
    },
    InvalidNodeRange,
    NoAudioFunctionGroup,
    NoOutputConverter,
    NoOutputPin,
    NoFrame,
    AddressOverflow,
    RegisterVerification {
        register: u64,
        expected: u32,
        actual: u32,
    },
}

impl From<PciResourceError> for HdaError {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

impl From<MmioError> for HdaError {
    fn from(error: MmioError) -> Self {
        Self::Mmio(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HdaInitFailure {
    pub error: HdaError,
    pub next_frame_address: Option<u64>,
}

#[derive(Debug)]
pub struct HdaRuntime {
    address: PciAddress,
    vendor_id: u16,
    device_id: u16,
    mmio: MmioRegion,
    _resources: PciDeviceResources,
    _bdl: DmaPage,
    _pcm: [DmaPage; PCM_PAGE_COUNT],
    codec_address: u8,
    function_group: u8,
    converter_node: u8,
    pin_node: u8,
    stream_index: u8,
    sample_rate: u32,
    frames: u64,
    next_frame_address: Option<u64>,
}

impl HdaRuntime {
    pub fn address(&self) -> PciAddress {
        self.address
    }

    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    pub fn device_id(&self) -> u16 {
        self.device_id
    }

    pub fn mmio_base(&self) -> u64 {
        self.mmio.physical_base()
    }

    pub fn codec_address(&self) -> u8 {
        self.codec_address
    }

    pub fn function_group(&self) -> u8 {
        self.function_group
    }

    pub fn converter_node(&self) -> u8 {
        self.converter_node
    }

    pub fn pin_node(&self) -> u8 {
        self.pin_node
    }

    pub fn stream_index(&self) -> u8 {
        self.stream_index
    }

    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    pub fn frames(&self) -> u64 {
        self.frames
    }

    pub fn next_frame_address(&self) -> Option<u64> {
        self.next_frame_address
    }
}

#[derive(Debug, Clone, Copy)]
struct DmaPage {
    physical_base: u64,
    virtual_base: u64,
}

impl DmaPage {
    fn write_u16(self, offset: u64, value: u16) -> Result<(), HdaError> {
        let pointer = self.pointer(offset, 2, 2)?;
        // SAFETY: `pointer` is bounds-checked against a page allocated from usable memory and
        // aligned for the 16-bit field being written.
        unsafe { core::ptr::write_volatile(pointer as *mut u16, value.to_le()) };
        Ok(())
    }

    fn write_u32(self, offset: u64, value: u32) -> Result<(), HdaError> {
        let pointer = self.pointer(offset, 4, 4)?;
        // SAFETY: `pointer` is bounds-checked against a page allocated from usable memory and
        // aligned for the 32-bit field being written.
        unsafe { core::ptr::write_volatile(pointer as *mut u32, value.to_le()) };
        Ok(())
    }

    fn write_u64(self, offset: u64, value: u64) -> Result<(), HdaError> {
        let pointer = self.pointer(offset, 8, 8)?;
        // SAFETY: `pointer` is bounds-checked against a page allocated from usable memory and
        // aligned for the 64-bit field being written.
        unsafe { core::ptr::write_volatile(pointer as *mut u64, value.to_le()) };
        Ok(())
    }

    fn pointer(self, offset: u64, size: u64, alignment: u64) -> Result<u64, HdaError> {
        if offset % alignment != 0 {
            return Err(HdaError::AddressOverflow);
        }
        let end = offset.checked_add(size).ok_or(HdaError::AddressOverflow)?;
        if end > PAGE_SIZE {
            return Err(HdaError::AddressOverflow);
        }
        self.virtual_base
            .checked_add(offset)
            .ok_or(HdaError::AddressOverflow)
    }
}

#[derive(Debug, Clone, Copy)]
struct OutputPath {
    function_group: u8,
    converter: u8,
    pin: u8,
    connection_index: Option<u8>,
    amp_gain: Option<u16>,
}

pub fn initialize(
    inventory: &PciInventory,
    physical_memory_offset: u64,
    regions: &[MemoryRegion],
    next_frame_address: Option<u64>,
) -> Result<Option<HdaRuntime>, HdaInitFailure> {
    let Some(device) = find_device(inventory) else {
        return Ok(None);
    };

    if !device.memory_space_enabled() {
        return Err(failure(HdaError::MemorySpaceDisabled, next_frame_address));
    }

    let mut resources = PciDeviceResources::new(device, physical_memory_offset);
    resources
        .enable_bus_master()
        .map_err(|error| failure(error.into(), next_frame_address))?;
    let mmio = resources
        .claim_mmio(HDA_BAR, HDA_MMIO_LENGTH)
        .map_err(|error| failure(error.into(), next_frame_address))?;

    let gcap = mmio
        .read_u16(REG_GCAP)
        .map_err(|error| failure(error.into(), next_frame_address))?;
    if gcap & 0xf000 == 0 {
        return Err(failure(HdaError::NoOutputStreams, next_frame_address));
    }
    reset_controller(mmio).map_err(|error| failure(error, next_frame_address))?;

    let state_status = mmio
        .read_u16(REG_STATESTS)
        .map_err(|error| failure(error.into(), next_frame_address))?;
    let Some(codec_address) = (0..15)
        .find(|address| state_status & (1u16 << address) != 0)
        .map(|address| address as u8)
    else {
        return Err(failure(HdaError::NoCodec, next_frame_address));
    };

    let path = discover_output_path(mmio, codec_address)
        .map_err(|error| failure(error, next_frame_address))?;
    let mut allocator = FrameAllocator::starting_at(regions, next_frame_address.unwrap_or(0));
    let bdl = allocate_page(&mut allocator, physical_memory_offset)
        .map_err(|error| failure(error, allocator.next_available_address()))?;
    let first_pcm = allocate_page(&mut allocator, physical_memory_offset)
        .map_err(|error| failure(error, allocator.next_available_address()))?;
    let mut pcm = [first_pcm; PCM_PAGE_COUNT];
    for page in pcm.iter_mut().skip(1) {
        *page = allocate_page(&mut allocator, physical_memory_offset)
            .map_err(|error| failure(error, allocator.next_available_address()))?;
    }

    fill_pcm(&pcm).map_err(|error| failure(error, allocator.next_available_address()))?;
    fill_bdl(bdl, &pcm).map_err(|error| failure(error, allocator.next_available_address()))?;
    configure_codec(mmio, codec_address, path)
        .map_err(|error| failure(error, allocator.next_available_address()))?;
    configure_stream(mmio, bdl)
        .map_err(|error| failure(error, allocator.next_available_address()))?;

    Ok(Some(HdaRuntime {
        address: device.address,
        vendor_id: device.vendor_id,
        device_id: device.device_id,
        mmio,
        _resources: resources,
        _bdl: bdl,
        _pcm: pcm,
        codec_address,
        function_group: path.function_group,
        converter_node: path.converter,
        pin_node: path.pin,
        stream_index: OUTPUT_STREAM_INDEX,
        sample_rate: 48_000,
        frames: PCM_FRAME_COUNT,
        next_frame_address: allocator.next_available_address(),
    }))
}

fn find_device(inventory: &PciInventory) -> Option<PciDevice> {
    inventory
        .devices()
        .iter()
        .find(|device| device.class_code == 0x04 && device.subclass == 0x03)
        .copied()
}

fn reset_controller(mmio: MmioRegion) -> Result<(), HdaError> {
    mmio.write_u32(REG_GCTL, 0)?;
    for _ in 0..COMMAND_TIMEOUT_SPINS {
        if mmio.read_u32(REG_GCTL)? & GCTL_RESET == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    mmio.write_u32(REG_GCTL, GCTL_RESET)?;
    for _ in 0..COMMAND_TIMEOUT_SPINS {
        if mmio.read_u32(REG_GCTL)? & GCTL_RESET != 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(HdaError::ResetFailed)
}

fn discover_output_path(mmio: MmioRegion, codec_address: u8) -> Result<OutputPath, HdaError> {
    let function_group = find_function_group(mmio, codec_address)?;
    let (first_node, node_count) = node_range(mmio, codec_address, function_group)?;
    let mut converter = None;
    let mut fallback_pin = None;

    for node in first_node..first_node.saturating_add(node_count) {
        let capabilities = parameter(mmio, codec_address, node, AC_PAR_AUDIO_WIDGET_CAP)?;
        let widget_type = ((capabilities >> AC_WCAP_TYPE_SHIFT) & 0xf) as u8;
        if widget_type == AC_WID_AUD_OUT && converter.is_none() {
            let amp_capabilities = parameter(mmio, codec_address, node, AC_PAR_AMP_OUT_CAP)?;
            let amp_gain = if capabilities & AC_WCAP_OUT_AMP != 0 {
                let steps = ((amp_capabilities >> AC_AMPCAP_NUM_STEPS_SHIFT) & 0x7f) as u16;
                (steps != 0).then_some(steps.min(AC_AMP_GAIN_MASK))
            } else {
                None
            };
            converter = Some((node, amp_gain));
        }
        if widget_type == AC_WID_PIN {
            let pin_capabilities = parameter(mmio, codec_address, node, AC_PAR_PIN_CAP)?;
            if pin_capabilities & AC_PINCAP_OUT == 0 {
                continue;
            }
            if fallback_pin.is_none() {
                fallback_pin = Some(node);
            }
        }
    }

    let (converter, amp_gain) = converter.ok_or(HdaError::NoOutputConverter)?;
    let fallback_pin = fallback_pin.ok_or(HdaError::NoOutputPin)?;
    let mut connected_pin = None;
    for node in first_node..first_node.saturating_add(node_count) {
        let capabilities = parameter(mmio, codec_address, node, AC_PAR_AUDIO_WIDGET_CAP)?;
        let widget_type = ((capabilities >> AC_WCAP_TYPE_SHIFT) & 0xf) as u8;
        if widget_type != AC_WID_PIN || capabilities & AC_WCAP_CONN_LIST == 0 {
            continue;
        }
        let pin_capabilities = parameter(mmio, codec_address, node, AC_PAR_PIN_CAP)?;
        if pin_capabilities & AC_PINCAP_OUT == 0 {
            continue;
        }
        if let Some(connection_index) = connection_index(mmio, codec_address, node, converter)? {
            connected_pin = Some((node, Some(connection_index)));
            break;
        }
    }
    let (pin, connection_index) = connected_pin.unwrap_or((fallback_pin, None));

    Ok(OutputPath {
        function_group,
        converter,
        pin,
        connection_index,
        amp_gain,
    })
}

fn find_function_group(mmio: MmioRegion, codec_address: u8) -> Result<u8, HdaError> {
    let (first_node, node_count) = node_range(mmio, codec_address, 0)?;
    for node in first_node..first_node.saturating_add(node_count) {
        let function_type = parameter(mmio, codec_address, node, AC_PAR_FUNCTION_TYPE)?;
        if (function_type & 0xff) as u8 == AC_GRP_AUDIO_FUNCTION {
            return Ok(node);
        }
    }
    Err(HdaError::NoAudioFunctionGroup)
}

fn node_range(mmio: MmioRegion, codec_address: u8, node: u8) -> Result<(u8, u8), HdaError> {
    let response = parameter(mmio, codec_address, node, AC_PAR_NODE_COUNT)?;
    let first = ((response >> 16) & 0x7f) as u8;
    let count = (response & 0xffff) as u16;
    let count = u8::try_from(count).map_err(|_| HdaError::InvalidNodeRange)?;
    if count == 0 || first.saturating_add(count) > 0x7f {
        return Err(HdaError::InvalidNodeRange);
    }
    Ok((first, count))
}

fn parameter(
    mmio: MmioRegion,
    codec_address: u8,
    node: u8,
    parameter_id: u16,
) -> Result<u32, HdaError> {
    command(mmio, codec_address, node, GET_PARAMETERS, parameter_id)
}

fn connection_index(
    mmio: MmioRegion,
    codec_address: u8,
    node: u8,
    converter: u8,
) -> Result<Option<u8>, HdaError> {
    let length = parameter(mmio, codec_address, node, AC_PAR_CONNLIST_LEN)?;
    let length = (length & 0x7f) as u8;
    let mut start = 0u8;
    while start < length {
        let response = command(
            mmio,
            codec_address,
            node,
            GET_CONNECT_LIST,
            u16::from(start),
        )?;
        let chunk_length = (length - start).min(4);
        for offset in 0..chunk_length {
            if ((response >> (u32::from(offset) * 8)) & 0xff) as u8 == converter {
                return Ok(Some(start + offset));
            }
        }
        start = start.saturating_add(4);
    }
    Ok(None)
}

fn configure_codec(mmio: MmioRegion, codec_address: u8, path: OutputPath) -> Result<(), HdaError> {
    command(
        mmio,
        codec_address,
        path.pin,
        SET_PIN_WIDGET_CONTROL,
        AC_PINCTL_OUT_EN,
    )?;
    if let Some(connection_index) = path.connection_index {
        command(
            mmio,
            codec_address,
            path.pin,
            SET_CONNECT_SEL,
            u16::from(connection_index),
        )?;
    }
    command(
        mmio,
        codec_address,
        path.converter,
        SET_CHANNEL_STREAMID,
        u16::from(STREAM_TAG) << 4,
    )?;
    command(
        mmio,
        codec_address,
        path.converter,
        SET_STREAM_FORMAT,
        HDA_FORMAT_STEREO_S16_48K,
    )?;
    if let Some(gain) = path.amp_gain {
        command(
            mmio,
            codec_address,
            path.converter,
            SET_AMP_GAIN_MUTE,
            AC_AMP_SET_OUTPUT | AC_AMP_SET_LEFT | AC_AMP_SET_RIGHT | (gain & AC_AMP_GAIN_MASK),
        )?;
    }
    Ok(())
}

fn configure_stream(mmio: MmioRegion, bdl: DmaPage) -> Result<(), HdaError> {
    let stream_base = REG_STREAM_BASE + u64::from(OUTPUT_STREAM_INDEX) * REG_STREAM_STRIDE;
    mmio.write_u32(
        stream_base + REG_SD_CTL,
        u32::from(STREAM_TAG) << SD_CTL_STREAM_TAG_SHIFT,
    )?;
    mmio.write_u32(
        stream_base + REG_SD_CBL,
        u32::try_from(PCM_FRAME_COUNT * PCM_BYTES_PER_FRAME)
            .map_err(|_| HdaError::AddressOverflow)?,
    )?;
    mmio.write_u16(stream_base + REG_SD_LVI, (BDL_ENTRIES - 1) as u16)?;
    mmio.write_u16(stream_base + REG_SD_FORMAT, HDA_FORMAT_STEREO_S16_48K)?;
    mmio.write_u32(stream_base + REG_SD_BDLPL, bdl.physical_base as u32)?;
    mmio.write_u32(stream_base + REG_SD_BDLPU, (bdl.physical_base >> 32) as u32)?;
    let control = (u32::from(STREAM_TAG) << SD_CTL_STREAM_TAG_SHIFT) | SD_CTL_DMA_START;
    mmio.write_u32(stream_base + REG_SD_CTL, control)?;
    let actual_control = mmio.read_u32(stream_base + REG_SD_CTL)?;
    let status = mmio.read_u8(stream_base + REG_SD_STS)?;
    if actual_control & SD_CTL_DMA_START == 0 || status & (SD_INT_DESC_ERR | SD_INT_FIFO_ERR) != 0 {
        return Err(HdaError::RegisterVerification {
            register: stream_base + REG_SD_CTL,
            expected: control,
            actual: actual_control,
        });
    }
    Ok(())
}

fn command(
    mmio: MmioRegion,
    codec_address: u8,
    node: u8,
    verb: u32,
    payload: u16,
) -> Result<u32, HdaError> {
    let data = (verb << 8) | u32::from(payload);
    let command = (u32::from(codec_address) << 28) | (u32::from(node) << 20) | data;
    mmio.write_u32(REG_IC, command)?;
    mmio.write_u16(REG_IRS, IRS_BUSY)?;
    for _ in 0..COMMAND_TIMEOUT_SPINS {
        let status = mmio.read_u16(REG_IRS)?;
        if status & IRS_VALID != 0 {
            let response = mmio.read_u32(REG_IR)?;
            mmio.write_u16(REG_IRS, IRS_VALID)?;
            return Ok(response);
        }
        core::hint::spin_loop();
    }
    Err(HdaError::CommandTimeout { command })
}

fn fill_bdl(bdl: DmaPage, pcm: &[DmaPage; PCM_PAGE_COUNT]) -> Result<(), HdaError> {
    for (index, page) in pcm.iter().enumerate() {
        let offset = u64::try_from(index)
            .map_err(|_| HdaError::AddressOverflow)?
            .checked_mul(BDL_ENTRY_BYTES)
            .ok_or(HdaError::AddressOverflow)?;
        bdl.write_u64(offset, page.physical_base)?;
        bdl.write_u32(offset + 8, PAGE_SIZE as u32)?;
        bdl.write_u32(offset + 12, BDL_IOC)?;
    }
    Ok(())
}

fn fill_pcm(pcm: &[DmaPage; PCM_PAGE_COUNT]) -> Result<(), HdaError> {
    for (page_index, page) in pcm.iter().enumerate() {
        let page_index = u64::try_from(page_index).map_err(|_| HdaError::AddressOverflow)?;
        for frame_index in 0..PCM_FRAMES_PER_PAGE {
            let sample_index = page_index
                .checked_mul(PCM_FRAMES_PER_PAGE)
                .and_then(|value| value.checked_add(frame_index))
                .ok_or(HdaError::AddressOverflow)?;
            let sample = tone_sample(sample_index);
            let offset = frame_index
                .checked_mul(PCM_BYTES_PER_FRAME)
                .ok_or(HdaError::AddressOverflow)?;
            page.write_u16(offset, sample as u16)?;
            page.write_u16(offset + 2, sample as u16)?;
        }
    }
    Ok(())
}

fn tone_sample(sample_index: u64) -> i16 {
    const AMPLITUDE: i32 = 12_000;
    const CYCLE: u64 = 48_000;
    const FREQUENCY: u64 = 440;
    let phase = sample_index.wrapping_mul(FREQUENCY) % CYCLE;
    let distance = if phase < CYCLE / 2 {
        phase
    } else {
        CYCLE - phase
    };
    let value = (distance as i32 * 2 * AMPLITUDE / (CYCLE as i32 / 2)) - AMPLITUDE;
    value as i16
}

fn allocate_page(
    allocator: &mut FrameAllocator<'_>,
    physical_memory_offset: u64,
) -> Result<DmaPage, HdaError> {
    let physical_base = allocator.next().ok_or(HdaError::NoFrame)?.start_address();
    let virtual_base = physical_memory_offset
        .checked_add(physical_base)
        .ok_or(HdaError::AddressOverflow)?;
    virtual_base
        .checked_add(PAGE_SIZE)
        .ok_or(HdaError::AddressOverflow)?;
    Ok(DmaPage {
        physical_base,
        virtual_base,
    })
}

fn failure(error: HdaError, next_frame_address: Option<u64>) -> HdaInitFailure {
    HdaInitFailure {
        error,
        next_frame_address,
    }
}

#[cfg(test)]
mod tests {
    use super::tone_sample;

    #[test]
    fn tone_is_audible_and_bounded() {
        let samples = [tone_sample(0), tone_sample(1_000), tone_sample(2_000)];
        assert!(samples.iter().any(|sample| *sample != 0));
        assert!(
            samples
                .iter()
                .all(|sample| i32::from((*sample).abs()) <= 12_000)
        );
    }

    #[test]
    fn tone_phase_changes_at_the_requested_rate() {
        assert_ne!(tone_sample(0), tone_sample(1));
        assert_eq!(tone_sample(0), tone_sample(48_000));
    }
}
