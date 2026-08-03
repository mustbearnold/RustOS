use bootloader_api::info::{MemoryRegion, MemoryRegionKind};

pub const PAGE_SIZE: u64 = 4096;
pub const ALLOCATABLE_MEMORY_START: u64 = 0x100000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemorySummary {
    pub usable_regions: usize,
    pub usable_bytes: u64,
    pub reserved_regions: usize,
    pub reserved_bytes: u64,
}

pub fn summarize(regions: &[MemoryRegion]) -> MemorySummary {
    let mut summary = MemorySummary::default();

    for region in regions {
        let bytes = region.end.saturating_sub(region.start);
        if region.kind == MemoryRegionKind::Usable {
            summary.usable_regions += 1;
            summary.usable_bytes = summary.usable_bytes.saturating_add(bytes);
        } else {
            summary.reserved_regions += 1;
            summary.reserved_bytes = summary.reserved_bytes.saturating_add(bytes);
        }
    }

    summary
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PhysicalFrame {
    start_address: u64,
}

impl PhysicalFrame {
    pub const fn start_address(self) -> u64 {
        self.start_address
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRange {
    start_address: u64,
    byte_length: usize,
    page_count: usize,
}

impl PhysicalRange {
    pub const fn start_address(self) -> u64 {
        self.start_address
    }

    pub const fn byte_length(self) -> usize {
        self.byte_length
    }

    pub const fn page_count(self) -> usize {
        self.page_count
    }

    pub fn end_address(self) -> Option<u64> {
        self.start_address.checked_add(
            u64::try_from(self.page_count)
                .ok()?
                .checked_mul(PAGE_SIZE)?,
        )
    }
}

/// Find page-contiguous usable memory for a device-visible buffer.
///
/// The caller owns reservation ordering: pass the next unallocated physical address from the
/// device allocator, then advance it to `end_address` before allocating another buffer. This
/// keeps this pure search helper usable by early boot and host tests without global allocator
/// state.
pub fn find_contiguous_usable_range(
    regions: &[MemoryRegion],
    starting_at: Option<u64>,
    byte_length: usize,
) -> Option<PhysicalRange> {
    if byte_length == 0 {
        return None;
    }
    let page_count = byte_length
        .checked_add(PAGE_SIZE as usize - 1)?
        .checked_div(PAGE_SIZE as usize)?;
    let aligned_bytes = page_count.checked_mul(PAGE_SIZE as usize)?;
    let minimum_address = starting_at.unwrap_or(ALLOCATABLE_MEMORY_START);

    for region in regions {
        if region.kind != MemoryRegionKind::Usable || region.start >= region.end {
            continue;
        }
        let candidate = region.start.max(minimum_address);
        let candidate = candidate.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
        let region_end = region.end & !(PAGE_SIZE - 1);
        let end = candidate.checked_add(u64::try_from(aligned_bytes).ok()?)?;
        if candidate < region_end && end <= region_end {
            return Some(PhysicalRange {
                start_address: candidate,
                byte_length,
                page_count,
            });
        }
    }
    None
}

pub struct FrameAllocator<'a> {
    regions: &'a [MemoryRegion],
    region_index: usize,
    next_address: Option<u64>,
}

impl<'a> FrameAllocator<'a> {
    pub const fn new(regions: &'a [MemoryRegion]) -> Self {
        Self {
            regions,
            region_index: 0,
            next_address: None,
        }
    }

    pub const fn starting_at(regions: &'a [MemoryRegion], address: u64) -> Self {
        let address = if address < ALLOCATABLE_MEMORY_START {
            ALLOCATABLE_MEMORY_START
        } else {
            address
        };
        Self {
            regions,
            region_index: 0,
            next_address: Some(address & !(PAGE_SIZE - 1)),
        }
    }

    pub fn next_available_address(&self) -> Option<u64> {
        let mut region_index = self.region_index;
        let next_address = self.next_address;
        loop {
            let region = self.regions.get(region_index)?;
            let Some((start, end)) = usable_frame_range(region) else {
                region_index += 1;
                continue;
            };
            let address = next_address.unwrap_or(start).max(start);
            if address < end {
                return Some(address);
            }
            region_index += 1;
        }
    }
}

impl Iterator for FrameAllocator<'_> {
    type Item = PhysicalFrame;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let region = self.regions.get(self.region_index)?;
            let Some((start, end)) = usable_frame_range(region) else {
                self.region_index += 1;
                continue;
            };

            let address = self.next_address.unwrap_or(start).max(start);
            if address >= end {
                self.region_index += 1;
                continue;
            }

            self.next_address = address.checked_add(PAGE_SIZE);
            return Some(PhysicalFrame {
                start_address: address,
            });
        }
    }
}

pub fn usable_frame_count(regions: &[MemoryRegion]) -> u64 {
    regions.iter().fold(0, |count, region| {
        let Some((start, end)) = usable_frame_range(region) else {
            return count;
        };
        count.saturating_add((end - start) / PAGE_SIZE)
    })
}

pub fn first_usable_frame_in_range(
    regions: &[MemoryRegion],
    range_start: u64,
    range_end: u64,
) -> Option<PhysicalFrame> {
    let range_start = range_start.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
    let range_end = range_end & !(PAGE_SIZE - 1);
    if range_start >= range_end {
        return None;
    }

    regions.iter().find_map(|region| {
        if region.kind != MemoryRegionKind::Usable {
            return None;
        }
        let start = region.start.max(range_start);
        let end = region.end.min(range_end) & !(PAGE_SIZE - 1);
        let start = start.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
        (start < end).then_some(PhysicalFrame {
            start_address: start,
        })
    })
}

fn usable_frame_range(region: &MemoryRegion) -> Option<(u64, u64)> {
    if region.kind != MemoryRegionKind::Usable || region.start >= region.end {
        return None;
    }

    let start = region
        .start
        .max(ALLOCATABLE_MEMORY_START)
        .checked_add(PAGE_SIZE - 1)?
        & !(PAGE_SIZE - 1);
    let end = region.end & !(PAGE_SIZE - 1);
    (start < end).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_usable_and_reserved_memory() {
        let regions = [
            MemoryRegion {
                start: 0x1000,
                end: 0x5000,
                kind: MemoryRegionKind::Usable,
            },
            MemoryRegion {
                start: 0x5000,
                end: 0x6000,
                kind: MemoryRegionKind::Bootloader,
            },
            MemoryRegion {
                start: 0x8000,
                end: 0x9000,
                kind: MemoryRegionKind::UnknownBios(2),
            },
        ];

        assert_eq!(
            summarize(&regions),
            MemorySummary {
                usable_regions: 1,
                usable_bytes: 0x4000,
                reserved_regions: 2,
                reserved_bytes: 0x2000,
            }
        );
    }

    #[test]
    fn clamps_inverted_regions_instead_of_underflowing() {
        let regions = [MemoryRegion {
            start: 10,
            end: 5,
            kind: MemoryRegionKind::Usable,
        }];

        assert_eq!(summarize(&regions).usable_bytes, 0);
    }

    #[test]
    fn allocator_aligns_regions_and_excludes_the_end() {
        let regions = [MemoryRegion {
            start: 0x100003,
            end: 0x109001,
            kind: MemoryRegionKind::Usable,
        }];

        let mut allocator = FrameAllocator::new(&regions);
        let mut frames = [0; 8];
        for frame in &mut frames {
            *frame = allocator.next().unwrap().start_address();
        }
        assert_eq!(
            frames,
            [
                0x101000, 0x102000, 0x103000, 0x104000, 0x105000, 0x106000, 0x107000, 0x108000,
            ]
        );
        assert_eq!(allocator.next(), None);
        assert_eq!(usable_frame_count(&regions), 8);
    }

    #[test]
    fn allocator_skips_reserved_regions_and_continues_across_usable_regions() {
        let regions = [
            MemoryRegion {
                start: 0x101000,
                end: 0x103000,
                kind: MemoryRegionKind::Usable,
            },
            MemoryRegion {
                start: 0x3000,
                end: 0x9000,
                kind: MemoryRegionKind::Bootloader,
            },
            MemoryRegion {
                start: 0x10a000,
                end: 0x10c000,
                kind: MemoryRegionKind::Usable,
            },
        ];

        let mut allocator = FrameAllocator::new(&regions);
        assert_eq!(allocator.next().unwrap().start_address(), 0x101000);
        assert_eq!(allocator.next().unwrap().start_address(), 0x102000);
        assert_eq!(allocator.next().unwrap().start_address(), 0x10a000);
        assert_eq!(allocator.next().unwrap().start_address(), 0x10b000);
        assert_eq!(allocator.next(), None);
    }

    #[test]
    fn allocator_skips_the_lower_megabyte() {
        let regions = [MemoryRegion {
            start: 0,
            end: 0x102000,
            kind: MemoryRegionKind::Usable,
        }];

        let mut allocator = FrameAllocator::new(&regions);
        assert_eq!(allocator.next().unwrap().start_address(), 0x100000);
        assert_eq!(allocator.next().unwrap().start_address(), 0x101000);
        assert_eq!(allocator.next(), None);
    }

    #[test]
    fn starting_at_survives_reserved_regions_before_usable_memory() {
        let regions = [
            MemoryRegion {
                start: 0,
                end: 0x540000,
                kind: MemoryRegionKind::Bootloader,
            },
            MemoryRegion {
                start: 0x540000,
                end: 0x550000,
                kind: MemoryRegionKind::Usable,
            },
        ];

        assert_eq!(
            FrameAllocator::starting_at(&regions, 0x544000)
                .next()
                .unwrap()
                .start_address(),
            0x544000
        );
    }

    #[test]
    fn next_available_address_preserves_cursor_across_regions() {
        let regions = [
            MemoryRegion {
                start: 0x900000,
                end: 0x902000,
                kind: MemoryRegionKind::Usable,
            },
            MemoryRegion {
                start: 0x800000,
                end: 0x802000,
                kind: MemoryRegionKind::Usable,
            },
        ];

        let mut allocator = FrameAllocator::starting_at(&regions, 0x900000);
        assert_eq!(allocator.next_available_address(), Some(0x900000));
        assert_eq!(allocator.next().unwrap().start_address(), 0x900000);
        assert_eq!(allocator.next_available_address(), Some(0x901000));
        assert_eq!(allocator.next().unwrap().start_address(), 0x901000);
        assert_eq!(allocator.next_available_address(), None);
    }

    #[test]
    fn allocator_ignores_unrepresentable_alignment() {
        let regions = [MemoryRegion {
            start: u64::MAX - 1023,
            end: u64::MAX,
            kind: MemoryRegionKind::Usable,
        }];

        assert_eq!(usable_frame_count(&regions), 0);
        assert_eq!(FrameAllocator::new(&regions).next(), None);
    }

    #[test]
    fn finds_a_page_only_inside_a_usable_range() {
        let regions = [
            MemoryRegion {
                start: 0x1000,
                end: 0x5000,
                kind: MemoryRegionKind::Usable,
            },
            MemoryRegion {
                start: 0x8000,
                end: 0xa000,
                kind: MemoryRegionKind::Bootloader,
            },
            MemoryRegion {
                start: 0xc000,
                end: 0x11000,
                kind: MemoryRegionKind::Usable,
            },
        ];

        assert_eq!(
            first_usable_frame_in_range(&regions, 0x8001, 0x10000)
                .map(PhysicalFrame::start_address),
            Some(0xc000)
        );
        assert_eq!(first_usable_frame_in_range(&regions, 0x5000, 0x8000), None);
    }

    #[test]
    fn finds_a_page_contiguous_device_buffer_after_the_allocator_cursor() {
        let regions = [
            MemoryRegion {
                start: 0x100000,
                end: 0x108000,
                kind: MemoryRegionKind::Usable,
            },
            MemoryRegion {
                start: 0x108000,
                end: 0x110000,
                kind: MemoryRegionKind::Bootloader,
            },
            MemoryRegion {
                start: 0x200003,
                end: 0x212345,
                kind: MemoryRegionKind::Usable,
            },
        ];

        let range = find_contiguous_usable_range(&regions, Some(0x205001), 0x5001)
            .expect("contiguous buffer");
        assert_eq!(range.start_address(), 0x206000);
        assert_eq!(range.byte_length(), 0x5001);
        assert_eq!(range.page_count(), 6);
        assert_eq!(range.end_address(), Some(0x20c000));
    }

    #[test]
    fn skips_usable_regions_that_cannot_fit_the_full_buffer() {
        let regions = [
            MemoryRegion {
                start: 0x100000,
                end: 0x104000,
                kind: MemoryRegionKind::Usable,
            },
            MemoryRegion {
                start: 0x200000,
                end: 0x20c000,
                kind: MemoryRegionKind::Usable,
            },
        ];

        let range = find_contiguous_usable_range(&regions, None, 0x9000).expect("second region");
        assert_eq!(range.start_address(), 0x200000);
        assert_eq!(range.page_count(), 9);
        assert_eq!(range.end_address(), Some(0x209000));
    }

    #[test]
    fn rejects_empty_or_overflowing_contiguous_ranges() {
        let regions = [MemoryRegion {
            start: 0x100000,
            end: 0x200000,
            kind: MemoryRegionKind::Usable,
        }];
        assert_eq!(find_contiguous_usable_range(&regions, None, 0), None);
        assert_eq!(
            find_contiguous_usable_range(&regions, Some(u64::MAX - 1), 0x1000),
            None
        );
    }
}
