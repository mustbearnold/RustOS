use bootloader_api::info::MemoryRegion;

use crate::memory::{FrameAllocator, PAGE_SIZE};
use crate::pci::{
    IoPortError, IoRegion, PciAddress, PciDevice, PciDeviceResources, PciInventory,
    PciResourceError,
};

const NAM_BAR: usize = 0;
const NABM_BAR: usize = 1;
const NAM_LENGTH: u64 = 0x400;
const NABM_LENGTH: u64 = 0x100;

const NAM_MASTER_VOLUME: u64 = 0x02;
const NAM_PCM_OUT_VOLUME: u64 = 0x18;
const NAM_EXTENDED_AUDIO_ID: u64 = 0x28;
const NAM_EXTENDED_AUDIO_CONTROL: u64 = 0x2a;
const NAM_PCM_FRONT_DAC_RATE: u64 = 0x2c;
const NAM_VENDOR_ID_1: u64 = 0x7c;
const NAM_VENDOR_ID_2: u64 = 0x7e;

const EACS_VARIABLE_RATE_AUDIO: u16 = 1 << 0;
const PCM_RATE: u16 = 48_000;

const PO_BDBAR: u64 = 0x10;
const PO_LVI: u64 = 0x15;
const PO_STATUS: u64 = 0x16;
const PO_CONTROL: u64 = 0x1b;
const PO_STATUS_FIFO_ERROR: u16 = 1 << 4;
const PO_STATUS_BUFFER_COMPLETION: u16 = 1 << 3;
const PO_STATUS_LAST_VALID_BUFFER: u16 = 1 << 2;
const PO_STATUS_DMA_HALTED: u16 = 1 << 0;
const PO_CONTROL_IOC_ENABLE: u8 = 1 << 4;
const PO_CONTROL_RUN: u8 = 1 << 0;

const BDL_IOC: u32 = 1 << 31;
const BDL_ENTRY_BYTES: u64 = 8;
const BDL_ENTRIES: usize = 32;
const PCM_PAGE_COUNT: usize = BDL_ENTRIES;
const PCM_BYTES_PER_FRAME: u64 = 4;
const PCM_FRAMES_PER_PAGE: u64 = PAGE_SIZE / PCM_BYTES_PER_FRAME;
const PCM_FRAME_COUNT: u64 = PCM_FRAMES_PER_PAGE * PCM_PAGE_COUNT as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ac97Error {
    IoSpaceDisabled,
    Resources(PciResourceError),
    Io(IoPortError),
    NoFrame,
    AddressOverflow,
    DmaAddressOutOfRange {
        address: u64,
    },
    RegisterVerification {
        register: u64,
        expected: u32,
        actual: u32,
    },
}

impl From<PciResourceError> for Ac97Error {
    fn from(error: PciResourceError) -> Self {
        Self::Resources(error)
    }
}

impl From<IoPortError> for Ac97Error {
    fn from(error: IoPortError) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ac97InitFailure {
    pub error: Ac97Error,
    pub next_frame_address: Option<u64>,
}

#[derive(Debug)]
pub struct Ac97Runtime {
    address: PciAddress,
    vendor_id: u16,
    device_id: u16,
    nam: IoRegion,
    nabm: IoRegion,
    _resources: PciDeviceResources,
    _bdl: DmaPage,
    _pcm: [DmaPage; PCM_PAGE_COUNT],
    sample_rate: u16,
    frames: u64,
    next_frame_address: Option<u64>,
}

impl Ac97Runtime {
    pub fn address(&self) -> PciAddress {
        self.address
    }

    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    pub fn device_id(&self) -> u16 {
        self.device_id
    }

    pub fn nam_base(&self) -> u16 {
        self.nam.base()
    }

    pub fn nabm_base(&self) -> u16 {
        self.nabm.base()
    }

    pub fn sample_rate(&self) -> u16 {
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
    fn write_u16(self, offset: u64, value: u16) -> Result<(), Ac97Error> {
        let pointer = self.pointer(offset, 2, 2)?;
        // SAFETY: `pointer` is bounds-checked against a page allocated from usable memory and
        // aligned for the 16-bit field being written.
        unsafe { core::ptr::write_volatile(pointer as *mut u16, value.to_le()) };
        Ok(())
    }

    fn write_u32(self, offset: u64, value: u32) -> Result<(), Ac97Error> {
        let pointer = self.pointer(offset, 4, 4)?;
        // SAFETY: `pointer` is bounds-checked against a page allocated from usable memory and
        // aligned for the 32-bit field being written.
        unsafe { core::ptr::write_volatile(pointer as *mut u32, value.to_le()) };
        Ok(())
    }

    fn pointer(self, offset: u64, size: u64, alignment: u64) -> Result<u64, Ac97Error> {
        if offset % alignment != 0 {
            return Err(Ac97Error::AddressOverflow);
        }
        let end = offset.checked_add(size).ok_or(Ac97Error::AddressOverflow)?;
        if end > PAGE_SIZE {
            return Err(Ac97Error::AddressOverflow);
        }
        self.virtual_base
            .checked_add(offset)
            .ok_or(Ac97Error::AddressOverflow)
    }
}

pub fn initialize(
    inventory: &PciInventory,
    physical_memory_offset: u64,
    regions: &[MemoryRegion],
    next_frame_address: Option<u64>,
) -> Result<Option<Ac97Runtime>, Ac97InitFailure> {
    let Some(device) = find_device(inventory) else {
        return Ok(None);
    };

    if device.command & 1 == 0 {
        return Err(failure(Ac97Error::IoSpaceDisabled, next_frame_address));
    }

    let mut resources = PciDeviceResources::new(device, physical_memory_offset);
    resources
        .enable_bus_master()
        .map_err(|error| failure(error.into(), next_frame_address))?;
    let nam = resources
        .claim_io(NAM_BAR, NAM_LENGTH)
        .map_err(|error| failure(error.into(), next_frame_address))?;
    let nabm = resources
        .claim_io(NABM_BAR, NABM_LENGTH)
        .map_err(|error| failure(error.into(), next_frame_address))?;

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

    let codec_vendor_id = nam
        .read_u16(NAM_VENDOR_ID_1)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    let codec_vendor_id_2 = nam
        .read_u16(NAM_VENDOR_ID_2)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    let extended_audio_id = nam
        .read_u16(NAM_EXTENDED_AUDIO_ID)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    let extended_audio_control = nam
        .read_u16(NAM_EXTENDED_AUDIO_CONTROL)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;

    nam.write_u16(NAM_MASTER_VOLUME, 0)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    nam.write_u16(NAM_PCM_OUT_VOLUME, 0)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    nam.write_u16(
        NAM_EXTENDED_AUDIO_CONTROL,
        extended_audio_control | EACS_VARIABLE_RATE_AUDIO,
    )
    .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    nam.write_u16(NAM_PCM_FRONT_DAC_RATE, PCM_RATE)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;

    let configured_rate = nam
        .read_u16(NAM_PCM_FRONT_DAC_RATE)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    if configured_rate != PCM_RATE {
        return Err(failure(
            Ac97Error::RegisterVerification {
                register: NAM_PCM_FRONT_DAC_RATE,
                expected: u32::from(PCM_RATE),
                actual: u32::from(configured_rate),
            },
            allocator.next_available_address(),
        ));
    }

    let bdl_address = dma_address(bdl.physical_base)
        .map_err(|error| failure(error, allocator.next_available_address()))?;
    nabm.write_u32(PO_BDBAR, bdl_address)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    nabm.write_u8(PO_LVI, (BDL_ENTRIES - 1) as u8)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    nabm.write_u16(
        PO_STATUS,
        PO_STATUS_FIFO_ERROR | PO_STATUS_BUFFER_COMPLETION | PO_STATUS_LAST_VALID_BUFFER,
    )
    .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    nabm.write_u8(PO_CONTROL, PO_CONTROL_IOC_ENABLE | PO_CONTROL_RUN)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;

    let control = nabm
        .read_u8(PO_CONTROL)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    let status = nabm
        .read_u16(PO_STATUS)
        .map_err(|error| failure(error.into(), allocator.next_available_address()))?;
    if control & PO_CONTROL_RUN == 0 || status & PO_STATUS_DMA_HALTED != 0 {
        return Err(failure(
            Ac97Error::RegisterVerification {
                register: PO_CONTROL,
                expected: u32::from(PO_CONTROL_RUN),
                actual: u32::from(control),
            },
            allocator.next_available_address(),
        ));
    }

    let _ = (codec_vendor_id, codec_vendor_id_2, extended_audio_id);
    Ok(Some(Ac97Runtime {
        address: device.address,
        vendor_id: device.vendor_id,
        device_id: device.device_id,
        nam,
        nabm,
        _resources: resources,
        _bdl: bdl,
        _pcm: pcm,
        sample_rate: configured_rate,
        frames: PCM_FRAME_COUNT,
        next_frame_address: allocator.next_available_address(),
    }))
}

fn find_device(inventory: &PciInventory) -> Option<PciDevice> {
    inventory
        .devices()
        .iter()
        .find(|device| {
            device.class_code == 0x04 && device.subclass == 0x01 && device.prog_if == 0x00
        })
        .copied()
}

fn fill_bdl(bdl: DmaPage, pcm: &[DmaPage; PCM_PAGE_COUNT]) -> Result<(), Ac97Error> {
    let sample_words = u32::try_from(PAGE_SIZE / 2).map_err(|_| Ac97Error::AddressOverflow)?;
    for (index, page) in pcm.iter().enumerate() {
        let index = u64::try_from(index).map_err(|_| Ac97Error::AddressOverflow)?;
        let offset = index
            .checked_mul(BDL_ENTRY_BYTES)
            .ok_or(Ac97Error::AddressOverflow)?;
        bdl.write_u32(offset, dma_address(page.physical_base)?)?;
        bdl.write_u32(offset + 4, BDL_IOC | sample_words)?;
    }
    Ok(())
}

fn fill_pcm(pcm: &[DmaPage; PCM_PAGE_COUNT]) -> Result<(), Ac97Error> {
    for (page_index, page) in pcm.iter().enumerate() {
        let page_index = u64::try_from(page_index).map_err(|_| Ac97Error::AddressOverflow)?;
        for frame_index in 0..PCM_FRAMES_PER_PAGE {
            let sample_index = page_index
                .checked_mul(PCM_FRAMES_PER_PAGE)
                .and_then(|value| value.checked_add(frame_index))
                .ok_or(Ac97Error::AddressOverflow)?;
            let sample = tone_sample(sample_index);
            let offset = frame_index
                .checked_mul(PCM_BYTES_PER_FRAME)
                .ok_or(Ac97Error::AddressOverflow)?;
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

fn dma_address(address: u64) -> Result<u32, Ac97Error> {
    u32::try_from(address).map_err(|_| Ac97Error::DmaAddressOutOfRange { address })
}

fn allocate_page(
    allocator: &mut FrameAllocator<'_>,
    physical_memory_offset: u64,
) -> Result<DmaPage, Ac97Error> {
    let physical_base = allocator.next().ok_or(Ac97Error::NoFrame)?.start_address();
    let virtual_base = physical_memory_offset
        .checked_add(physical_base)
        .ok_or(Ac97Error::AddressOverflow)?;
    virtual_base
        .checked_add(PAGE_SIZE)
        .ok_or(Ac97Error::AddressOverflow)?;
    let page = DmaPage {
        physical_base,
        virtual_base,
    };
    dma_address(physical_base)?;
    Ok(page)
}

fn failure(error: Ac97Error, next_frame_address: Option<u64>) -> Ac97InitFailure {
    Ac97InitFailure {
        error,
        next_frame_address,
    }
}

#[cfg(test)]
mod tests {
    use super::{PCM_RATE, tone_sample};

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
        assert_eq!(tone_sample(0), tone_sample(u64::from(PCM_RATE)));
    }
}
