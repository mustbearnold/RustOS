#![cfg_attr(target_os = "none", no_main)]
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", feature(abi_x86_interrupt))]
#![cfg_attr(not(target_os = "none"), allow(dead_code))]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(target_os = "none", test))]
extern crate alloc;

#[cfg(any(target_os = "none", test))]
mod ac97;
mod acpi;
#[cfg(target_os = "none")]
mod ahci;
#[cfg(target_os = "none")]
mod apic;
#[cfg(target_os = "none")]
mod console;
mod dhcp;
#[cfg(target_os = "none")]
mod e1000;
#[cfg(any(target_os = "none", test))]
mod framebuffer;
#[cfg(any(target_os = "none", test))]
mod hardware;
#[cfg(any(target_os = "none", test))]
mod hda;
#[cfg(target_os = "none")]
mod heap;
#[cfg(any(target_os = "none", test))]
mod igc;
mod initramfs;
#[cfg(any(target_os = "none", test))]
mod input;
#[cfg(target_os = "none")]
mod interrupts;
#[cfg(target_os = "none")]
mod ioapic;
mod keyboard;
mod memory;
mod net;
#[cfg(target_os = "none")]
mod network_runtime;
#[cfg(any(target_os = "none", test))]
mod nvidia;
#[cfg(any(target_os = "none", test))]
mod nvme;
#[cfg(any(target_os = "none", test))]
mod pci;
#[cfg(target_os = "none")]
mod power;
mod process;
#[cfg(target_os = "none")]
mod scheduler;
#[cfg(target_os = "none")]
mod smp;
mod storage;
#[cfg(target_os = "none")]
mod timer;
#[cfg(any(target_os = "none", test))]
mod usb;
mod vfs;
#[cfg(any(target_os = "none", test))]
mod virtio_gpu;
#[cfg(any(target_os = "none", test))]
mod virtio_net;
#[cfg(target_os = "none")]
mod vm;
mod window_policy;

#[cfg(target_os = "none")]
use alloc::{boxed::Box, vec::Vec};
#[cfg(target_os = "none")]
use bootloader_api::config::{BootloaderConfig, Mapping};
#[cfg(target_os = "none")]
use bootloader_api::{BootInfo, entry_point};

#[cfg(target_os = "none")]
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.kernel_stack_size = 256 * 1024;
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.mappings.dynamic_range_start = Some(0x1000_0000_0000);
    config.mappings.dynamic_range_end = Some(0x4000_0000_0000);
    config
};

#[cfg(target_os = "none")]
entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

#[cfg(target_os = "none")]
fn configure_e1000_interrupts(
    runtime: &mut e1000::E1000Runtime,
    physical_memory: acpi::PhysicalMemory,
    acpi_info: &acpi::AcpiInfo,
    legacy_available: bool,
) -> bool {
    let vector = match runtime.prepare_interrupts() {
        Ok(vector) => vector,
        Err(error) => {
            runtime.failure = Some(error);
            kprintln!(
                "driver: e1000 interrupt registration failed ({:?}) status=degraded",
                error
            );
            return false;
        }
    };

    let msix_attempt =
        apic::local_apic_id_u32().map(|destination| runtime.enable_msix(destination));
    match msix_attempt {
        Some(Ok(route)) => match runtime.arm_msix_interrupts(route) {
            Ok(()) => {
                kprintln!(
                    "driver: e1000 interrupt mode=msix irq_line={} vector={} destination_apic={} table_bar={} table_offset=0x{:x} address=0x{:x} data=0x{:04x} status=ready",
                    runtime.interrupt_line,
                    route.vector,
                    route.destination_apic_id,
                    route.table_bar,
                    route.table_offset,
                    route.address,
                    route.data
                );
                return true;
            }
            Err(error) => {
                runtime.failure = Some(error);
                kprintln!(
                    "driver: e1000 MSI-X interrupt arm failed ({:?}) status=degraded",
                    error
                );
                return false;
            }
        },
        Some(Err(e1000::E1000Error::Resources(error))) => {
            kprintln!(
                "driver: e1000 MSI-X unavailable ({:?}); evaluating MSI fallback",
                error
            );
        }
        None => {
            kprintln!(
                "driver: e1000 MSI-X unavailable (no APIC destination); evaluating MSI fallback"
            );
        }
        Some(Err(error)) => {
            runtime.failure = Some(error);
            kprintln!(
                "driver: e1000 MSI-X configuration failed ({:?}) status=degraded",
                error
            );
            return false;
        }
    }

    let msi_attempt = apic::local_apic_id_u32().map(|destination| runtime.enable_msi(destination));
    match msi_attempt {
        Some(Ok(route)) => match runtime.arm_msi_interrupts(route) {
            Ok(()) => {
                kprintln!(
                    "driver: e1000 interrupt mode=msi irq_line={} vector={} destination_apic={} address=0x{:x} data=0x{:04x} status=ready",
                    runtime.interrupt_line,
                    route.vector,
                    route.destination_apic_id,
                    route.address,
                    route.data
                );
                return true;
            }
            Err(error) => {
                runtime.failure = Some(error);
                kprintln!(
                    "driver: e1000 MSI interrupt arm failed ({:?}) status=degraded",
                    error
                );
                return false;
            }
        },
        Some(Err(e1000::E1000Error::Resources(pci::PciResourceError::MsiNotSupported))) | None => {
            kprintln!(
                "driver: e1000 MSI unavailable; evaluating legacy IO-APIC fallback status=degraded"
            );
        }
        Some(Err(error)) => {
            runtime.failure = Some(error);
            kprintln!(
                "driver: e1000 MSI configuration failed ({:?}) status=degraded",
                error
            );
            return false;
        }
    }

    if !legacy_available {
        kprintln!("driver: e1000 has no MSI or legacy IO-APIC route status=degraded");
        return false;
    }
    let Some((gsi, flags)) = acpi_info.legacy_irq_route(runtime.interrupt_line) else {
        kprintln!(
            "driver: e1000 interrupt line {} has no ACPI legacy route status=degraded",
            runtime.interrupt_line
        );
        return false;
    };
    let route = match ioapic::route_gsi(physical_memory, acpi_info, gsi, vector, flags) {
        Ok(route) => route,
        Err(error) => {
            kprintln!(
                "driver: e1000 legacy interrupt route failed ({:?}) status=degraded",
                error
            );
            return false;
        }
    };
    match runtime.arm_interrupts(gsi) {
        Ok(()) => {
            route.unmask();
            kprintln!(
                "driver: e1000 interrupt mode=legacy irq_line={} gsi={} vector={} flags=0x{:04x} status=ready",
                runtime.interrupt_line,
                gsi,
                vector,
                flags
            );
            true
        }
        Err(error) => {
            runtime.failure = Some(error);
            kprintln!(
                "driver: e1000 legacy interrupt arm failed ({:?}) status=degraded",
                error
            );
            false
        }
    }
}

#[cfg(target_os = "none")]
fn configure_igc_interrupts(
    runtime: &mut igc::IgcRuntime,
    physical_memory: acpi::PhysicalMemory,
    acpi_info: &acpi::AcpiInfo,
    legacy_available: bool,
) -> bool {
    let vector = match runtime.prepare_interrupts() {
        Ok(vector) => vector,
        Err(error) => {
            runtime.failure = Some(error);
            kprintln!(
                "driver: igc interrupt registration failed ({:?}) status=degraded",
                error
            );
            return false;
        }
    };

    let msix_attempt =
        apic::local_apic_id_u32().map(|destination| runtime.enable_msix(destination));
    match msix_attempt {
        Some(Ok(route)) => match runtime.arm_msix_interrupts(route) {
            Ok(()) => {
                kprintln!(
                    "driver: igc interrupt mode=msix vector={} destination_apic={} table_bar={} table_offset=0x{:x} address=0x{:x} data=0x{:04x} status=ready",
                    route.vector,
                    route.destination_apic_id,
                    route.table_bar,
                    route.table_offset,
                    route.address,
                    route.data
                );
                return true;
            }
            Err(error) => {
                runtime.failure = Some(error);
                kprintln!(
                    "driver: igc MSI-X interrupt arm failed ({:?}) status=degraded",
                    error
                );
                return false;
            }
        },
        Some(Err(igc::IgcError::Resources(error))) => kprintln!(
            "driver: igc MSI-X unavailable ({:?}); evaluating MSI fallback",
            error
        ),
        None => kprintln!(
            "driver: igc MSI-X unavailable (no APIC destination); evaluating MSI fallback"
        ),
        Some(Err(error)) => {
            runtime.failure = Some(error);
            kprintln!(
                "driver: igc MSI-X configuration failed ({:?}) status=degraded",
                error
            );
            return false;
        }
    }

    let msi_attempt = apic::local_apic_id_u32().map(|destination| runtime.enable_msi(destination));
    match msi_attempt {
        Some(Ok(route)) => match runtime.arm_msi_interrupts(route) {
            Ok(()) => {
                kprintln!(
                    "driver: igc interrupt mode=msi vector={} destination_apic={} address=0x{:x} data=0x{:04x} status=ready",
                    route.vector,
                    route.destination_apic_id,
                    route.address,
                    route.data
                );
                return true;
            }
            Err(error) => {
                runtime.failure = Some(error);
                kprintln!(
                    "driver: igc MSI interrupt arm failed ({:?}) status=degraded",
                    error
                );
                return false;
            }
        },
        Some(Err(igc::IgcError::Resources(error))) => kprintln!(
            "driver: igc MSI unavailable ({:?}); evaluating legacy IO-APIC fallback status=degraded",
            error
        ),
        None => kprintln!(
            "driver: igc MSI unavailable (no APIC destination); evaluating legacy IO-APIC fallback status=degraded"
        ),
        Some(Err(error)) => {
            runtime.failure = Some(error);
            kprintln!(
                "driver: igc MSI configuration failed ({:?}) status=degraded",
                error
            );
            return false;
        }
    }

    if !legacy_available {
        kprintln!("driver: igc has no MSI or legacy IO-APIC route status=degraded");
        return false;
    }
    let Some((gsi, flags)) = acpi_info.legacy_irq_route(runtime.interrupt_line) else {
        kprintln!("driver: igc interrupt line unavailable for legacy routing status=degraded");
        return false;
    };
    let route = match ioapic::route_gsi(physical_memory, acpi_info, gsi, vector, flags) {
        Ok(route) => route,
        Err(error) => {
            kprintln!(
                "driver: igc legacy interrupt route failed ({:?}) status=degraded",
                error
            );
            return false;
        }
    };
    match runtime.arm_interrupts(gsi) {
        Ok(()) => {
            route.unmask();
            kprintln!(
                "driver: igc interrupt mode=legacy irq_line={} gsi={} vector={} flags=0x{:04x} status=ready",
                runtime.interrupt_line,
                gsi,
                vector,
                flags
            );
            true
        }
        Err(error) => {
            runtime.failure = Some(error);
            kprintln!(
                "driver: igc legacy interrupt arm failed ({:?}) status=degraded",
                error
            );
            false
        }
    }
}

#[cfg(target_os = "none")]
fn configure_virtio_interrupts(runtime: &mut virtio_net::VirtioNetRuntime) -> bool {
    match runtime.prepare_interrupts() {
        Ok(_) => {}
        Err(error) => {
            kprintln!(
                "driver: virtio-net interrupt registration failed ({:?}) fallback=polling status=degraded",
                error
            );
            return false;
        }
    };

    let msix_attempt =
        apic::local_apic_id_u32().map(|destination| runtime.enable_msix(destination));
    match msix_attempt {
        Some(Ok(route)) => match runtime.arm_msix_interrupts(route) {
            Ok(()) => {
                kprintln!(
                    "driver: virtio-net interrupt mode=msix vector={} destination_apic={} table_bar={} table_offset=0x{:x} address=0x{:x} data=0x{:04x} status=ready",
                    route.vector,
                    route.destination_apic_id,
                    route.table_bar,
                    route.table_offset,
                    route.address,
                    route.data
                );
                return true;
            }
            Err(error) => kprintln!(
                "driver: virtio-net MSI-X interrupt arm failed ({:?}) fallback=polling status=degraded",
                error
            ),
        },
        Some(Err(virtio_net::VirtioNetError::Resources(
            pci::PciResourceError::MsixNotSupported,
        )))
        | None => kprintln!("driver: virtio-net MSI-X unavailable; evaluating MSI fallback"),
        Some(Err(error)) => kprintln!(
            "driver: virtio-net MSI-X configuration failed ({:?}); evaluating MSI fallback",
            error
        ),
    }

    let msi_attempt = apic::local_apic_id_u32().map(|destination| runtime.enable_msi(destination));
    match msi_attempt {
        Some(Ok(route)) => match runtime.arm_msi_interrupts(route) {
            Ok(()) => {
                kprintln!(
                    "driver: virtio-net interrupt mode=msi vector={} destination_apic={} address=0x{:x} data=0x{:04x} status=ready",
                    route.vector,
                    route.destination_apic_id,
                    route.address,
                    route.data
                );
                true
            }
            Err(error) => {
                kprintln!(
                    "driver: virtio-net MSI interrupt arm failed ({:?}) fallback=polling status=degraded",
                    error
                );
                false
            }
        },
        Some(Err(virtio_net::VirtioNetError::Resources(
            pci::PciResourceError::MsiNotSupported,
        )))
        | None => {
            kprintln!(
                "driver: virtio-net MSI unavailable; retaining polling fallback status=degraded"
            );
            false
        }
        Some(Err(error)) => {
            kprintln!(
                "driver: virtio-net MSI configuration failed ({:?}) fallback=polling status=degraded",
                error
            );
            false
        }
    }
}

#[cfg(target_os = "none")]
fn copy_cpuid_register(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(target_os = "none")]
fn cpuid_text(bytes: &[u8]) -> &str {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end])
        .unwrap_or("unknown")
        .trim()
}

#[cfg(target_os = "none")]
fn platform_identity() -> ([u8; 12], [u8; 48], bool) {
    let basic = core::arch::x86_64::__cpuid(0);
    let mut vendor = [0u8; 12];
    copy_cpuid_register(&mut vendor, 0, basic.ebx);
    copy_cpuid_register(&mut vendor, 4, basic.edx);
    copy_cpuid_register(&mut vendor, 8, basic.ecx);

    let features = core::arch::x86_64::__cpuid(1);
    let hypervisor_present = features.ecx & (1 << 31) != 0;

    let mut brand = [0u8; 48];
    let extended = core::arch::x86_64::__cpuid(0x8000_0000);
    if extended.eax >= 0x8000_0004 {
        for (index, leaf) in (0x8000_0002..=0x8000_0004).enumerate() {
            let result = core::arch::x86_64::__cpuid(leaf);
            let offset = index * 16;
            copy_cpuid_register(&mut brand, offset, result.eax);
            copy_cpuid_register(&mut brand, offset + 4, result.ebx);
            copy_cpuid_register(&mut brand, offset + 8, result.ecx);
            copy_cpuid_register(&mut brand, offset + 12, result.edx);
        }
    }
    (vendor, brand, hypervisor_present)
}

#[cfg(target_os = "none")]
fn log_platform_identity(summary: memory::MemorySummary) -> bool {
    let (vendor, brand, hypervisor_present) = platform_identity();
    let vendor = cpuid_text(&vendor);
    let brand = cpuid_text(&brand);
    kprintln!(
        "platform: cpu_vendor={} cpu_brand={} usable_memory_kib={} hypervisor={} status=present",
        vendor,
        brand,
        summary.usable_bytes / 1024,
        if hypervisor_present {
            "present"
        } else {
            "none"
        }
    );
    nvidia::target_platform_matches(vendor, brand, hypervisor_present, summary.usable_bytes)
}

#[cfg(target_os = "none")]
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    console::init();
    let user_mode = process::init_user_mode();
    kprintln!("RustOS kernel 0.1.0");
    kprintln!(
        "process: kernel_cs=0x{:x} user_cs=0x{:x} user_ss=0x{:x} tss=0x{:x} status=ready",
        user_mode.kernel_code,
        user_mode.user_code,
        user_mode.user_data,
        user_mode.tss
    );
    kprintln!(
        "boot: bootloader API {}.{}.{}",
        boot_info.api_version.version_major(),
        boot_info.api_version.version_minor(),
        boot_info.api_version.version_patch()
    );

    let summary = memory::summarize(&boot_info.memory_regions);
    kprintln!(
        "memory: {} usable regions ({} KiB), {} reserved regions ({} KiB)",
        summary.usable_regions,
        summary.usable_bytes / 1024,
        summary.reserved_regions,
        summary.reserved_bytes / 1024
    );
    let nvidia_target_platform_ready = log_platform_identity(summary);

    let frame_count = memory::usable_frame_count(&boot_info.memory_regions);
    let mut frame_allocator = memory::FrameAllocator::new(&boot_info.memory_regions);
    let first_frame = frame_allocator
        .next()
        .map(memory::PhysicalFrame::start_address);
    let second_frame = frame_allocator
        .next()
        .map(memory::PhysicalFrame::start_address);
    match (first_frame, second_frame) {
        (Some(first), Some(second)) => {
            let valid =
                first % memory::PAGE_SIZE == 0 && second % memory::PAGE_SIZE == 0 && second > first;
            kprintln!(
                "allocator: {} usable 4 KiB frames, first=0x{:x}, second=0x{:x}, self-check={}",
                frame_count,
                first,
                second,
                if valid { "ok" } else { "failed" }
            );
            if !valid {
                panic!("physical frame allocator returned invalid frames");
            }
        }
        _ => panic!("physical frame allocator found fewer than two frames"),
    }

    let physical_memory_offset = boot_info
        .physical_memory_offset
        .into_option()
        .unwrap_or_else(|| panic!("bootloader did not map physical memory"));
    let rsdp_address = boot_info.rsdp_addr.into_option();
    let physical_memory = acpi::PhysicalMemory::new(physical_memory_offset);
    let heap_stats = heap::init(physical_memory_offset, &boot_info.memory_regions)
        .unwrap_or_else(|error| panic!("kernel heap initialization failed: {:?}", error));
    kprintln!(
        "heap: mapped {} pages at 0x{:x} ({} KiB)",
        heap_stats.pages,
        heap_stats.start,
        heap_stats.size / 1024
    );

    let mut allocation_smoke_test = Vec::with_capacity(64);
    for value in 0..64u64 {
        allocation_smoke_test.push(value);
    }
    let checksum: u64 = allocation_smoke_test.iter().copied().sum();
    kprintln!(
        "heap: alloc smoke len={} checksum={} status=ok",
        allocation_smoke_test.len(),
        checksum
    );
    drop(allocation_smoke_test);

    let vm_stats = vm::init(
        physical_memory_offset,
        &boot_info.memory_regions,
        heap_stats.next_frame_address,
    )
    .unwrap_or_else(|error| panic!("virtual-memory initialization failed: {:?}", error));
    kprintln!(
        "vm: page=0x{:x} frame=0x{:x} readback=0x{:x} next_frame={:?} status=ok",
        vm_stats.virtual_address,
        vm_stats.physical_address,
        vm_stats.read_back,
        vm_stats.next_frame_address
    );

    process::init_process_factory(
        physical_memory_offset,
        &boot_info.memory_regions,
        vm_stats.next_frame_address,
    );
    let init_process = Box::leak(Box::new(process::Process::new_init(
        process::load_user_image(&process::USER_INIT_ELF).unwrap_or_else(|error| {
            panic!("user address-space initialization failed: {:?}", error)
        }),
    )));
    process::register_runtime_process(init_process)
        .unwrap_or_else(|error| panic!("init process registration failed: {:?}", error));
    kprintln!(
        "process: pid={} state={:?} root=0x{:x} entry=0x{:x} stack_top=0x{:x} executable_pages={} next_frame={:?} status=ready",
        init_process.pid(),
        init_process.state(),
        init_process
            .address_space()
            .root_frame()
            .start_address()
            .as_u64(),
        init_process.address_space().entry(),
        init_process.address_space().stack_top(),
        init_process.address_space().executable_pages(),
        init_process.address_space().next_frame_address()
    );

    match boot_info.framebuffer.take() {
        Some(framebuffer) => {
            let info = framebuffer.info();
            kprintln!(
                "framebuffer: {}x{} stride={} format={:?}",
                info.width,
                info.height,
                info.stride,
                info.pixel_format
            );
            framebuffer::init(framebuffer);
            kprintln!("display: framebuffer initialized");
        }
        None => kprintln!("display: no framebuffer reported by firmware"),
    }
    input::init_mouse();
    kprintln!(
        "input: ps2-mouse polling={} status={}",
        if input::mouse_ready() {
            "enabled"
        } else {
            "disabled"
        },
        if input::mouse_ready() {
            "ready"
        } else {
            "degraded"
        }
    );

    interrupts::init_idt();
    interrupts::init_pics();
    let acpi_info = match acpi::discover(physical_memory, rsdp_address) {
        Ok(acpi_info) => {
            kprintln!(
                "acpi: rev={} RSDP=0x{:x} MADT=0x{:x} LAPIC=0x{:x} CPUs={}/{} IOAPICs={}",
                acpi_info.revision,
                acpi_info.rsdp_address,
                acpi_info.madt_address,
                acpi_info.local_apic_address,
                acpi_info.enabled_processor_count,
                acpi_info.processor_count,
                acpi_info.io_apic_count
            );
            Some(acpi_info)
        }
        Err(error) => {
            kprintln!("acpi: discovery failed ({:?})", error);
            None
        }
    };
    power::init(
        acpi_info.as_ref().and_then(|info| info.power),
        physical_memory_offset,
    );
    let power_diagnostics = power::diagnostics();
    kprintln!(
        "power: acpi evt=0x{:x}/0x{:x}/{} pm1a=0x{:x} pm1b=0x{:x} sleep_type={}/{} s3={:?}/{:?} facs=0x{:x}/{}v{} reset=0x{:x}/0x{:02x} poweroff={} suspend={} suspend_vector={} reboot={}",
        power_diagnostics.pm1a_event_block,
        power_diagnostics.pm1b_event_block,
        power_diagnostics.pm1_event_length,
        power_diagnostics.pm1a_control_block,
        power_diagnostics.pm1b_control_block,
        power_diagnostics.sleep_type_a,
        power_diagnostics.sleep_type_b,
        power_diagnostics.sleep_type_s3_a,
        power_diagnostics.sleep_type_s3_b,
        power_diagnostics.facs_address,
        power_diagnostics.facs_length,
        power_diagnostics.facs_version,
        power_diagnostics.reset_register,
        power_diagnostics.reset_value,
        if power_diagnostics.ready {
            "ready"
        } else {
            "degraded"
        },
        if power_diagnostics.suspend_ready {
            "ready"
        } else {
            "degraded"
        },
        if power_diagnostics.native_wake_ready {
            "native"
        } else {
            "legacy"
        },
        if power_diagnostics.reboot_ready {
            "ready"
        } else {
            "degraded"
        }
    );

    let apic_active =
        acpi_info
            .as_ref()
            .is_some_and(|acpi_info| match apic::init(physical_memory, acpi_info) {
                Ok(apic_stats) => {
                    process::init_user_mode_current_cpu();
                    kprintln!(
                        "apic: base=0x{:x} version=0x{:x} timer_initial={} status=ready",
                        apic_stats.physical_base,
                        apic_stats.version,
                        apic_stats.timer_initial_count
                    );
                    true
                }
                Err(error) => {
                    kprintln!("apic: initialization failed ({:?})", error);
                    false
                }
            });

    let pci_inventory = pci::PciInventory::enumerate()
        .unwrap_or_else(|error| panic!("PCI enumeration failed: {:?}", error));
    kprintln!(
        "pci: scanned_buses={} devices={} status={}",
        pci_inventory.scanned_buses(),
        pci_inventory.len(),
        if pci_inventory.is_empty() {
            "degraded"
        } else {
            "ready"
        }
    );
    for device in pci_inventory.devices().iter().take(16) {
        kprintln!(
            "pci: {:02x}:{:02x}.{} vendor=0x{:04x} device=0x{:04x} class=0x{:02x}{:02x} ({:?}) driver={:?} cmd=0x{:04x} irq_line={} irq_pin={} multi={} msi={} msix={} bar0={:?}",
            device.address.bus,
            device.address.device,
            device.address.function,
            device.vendor_id,
            device.device_id,
            device.class_code,
            device.subclass,
            device.class(),
            device.driver_kind(),
            device.command,
            device.interrupt_line,
            device.interrupt_pin,
            device.is_multifunction(),
            device.capabilities.msi.is_some(),
            device.capabilities.msix.is_some(),
            device.bars[0]
        );
    }
    hardware::init(&pci_inventory, framebuffer::info());
    let pci_roles = pci_inventory.role_counts();
    kprintln!(
        "hardware: pci storage={} network={} display={} audio={} usb={} host_bridges={} bridges={} other={} status=ready",
        pci_roles.mass_storage,
        pci_roles.network,
        pci_roles.display,
        pci_roles.audio,
        pci_roles.usb,
        pci_roles.host_bridges,
        pci_roles.bridges,
        pci_roles.other
    );
    if let Some(display) = pci_inventory.first_display() {
        kprintln!(
            "hardware: display {:02x}:{:02x}.{} vendor={} vendor_id=0x{:04x} device_id=0x{:04x} status=present",
            display.address.bus,
            display.address.device,
            display.address.function,
            display.vendor_name(),
            display.vendor_id,
            display.device_id
        );
    }
    let mut nvidia_probe = match nvidia::initialize(&pci_inventory, physical_memory_offset) {
        Ok(Some(probe)) => {
            hardware::set_nvidia(probe);
            kprintln!(
                "driver: nvidia probe {:02x}:{:02x}.{} device=0x{:04x} revision=0x{:02x} architecture={} bar0=0x{:x} bar1={:?} bar3={:?} bar5_io={:?} mmio=0x{:x}+0x{:x} memory_space={} busmaster={} msi={} msix={} fsp_transport={} fsp_secure_boot=0x{:08x} fsp_queue={}/{} fsp_msgq={}/{} fsp_mailbox=0x{:08x}:0x{:08x} fsp_riscv_lockdown={} gsp_hwcfg2=0x{:08x} gsp_mailbox=0x{:08x}:0x{:08x} gsp_riscv_active={} gsp_riscv_lockdown={} gsp=external-firmware-riscv64 rpc_page={} rpc_max_pages={} shared_bytes={} shared_ptes={} queue_entries={} acceleration=unavailable status=probe-ready",
                probe.address.bus,
                probe.address.device,
                probe.address.function,
                probe.device_id,
                probe.revision_id,
                probe.architecture.name(),
                probe.bar0_base,
                probe.bar1_base,
                probe.bar3_base,
                probe.bar5_io_base,
                probe.mmio_base,
                probe.mmio_length,
                probe.memory_space_enabled,
                probe.bus_master_enabled,
                probe.msi,
                probe.msix,
                if probe.fsp_transport().is_some() {
                    "emem-queue"
                } else {
                    "unavailable"
                },
                probe.fsp.secure_boot_status,
                probe.fsp.queue_head,
                probe.fsp.queue_tail,
                probe.fsp.message_queue_head,
                probe.fsp.message_queue_tail,
                probe.fsp.mailbox0,
                probe.fsp.mailbox1,
                probe.fsp.riscv_lockdown,
                probe.fsp.gsp_hwcfg2,
                probe.fsp.gsp_mailbox0,
                probe.fsp.gsp_mailbox1,
                probe.fsp.gsp_riscv_active,
                probe.fsp.gsp_riscv_lockdown,
                nvidia::GSP_RPC_PAGE_SIZE,
                nvidia::GSP_RPC_MAX_MESSAGE_PAGES,
                nvidia::GSP_SHARED_MEMORY_BYTES,
                nvidia::GSP_SHARED_MEMORY_PTES,
                nvidia::GSP_QUEUE_ENTRY_COUNT
            );
            Some(probe)
        }
        Ok(None) => {
            kprintln!("driver: nvidia RTX 5070 not present status=absent");
            None
        }
        Err(error) => {
            kprintln!(
                "driver: nvidia probe failed ({:?}) acceleration=unavailable status=degraded",
                error
            );
            None
        }
    };
    match igc::probe(&pci_inventory, physical_memory_offset) {
        Ok(Some(probe)) => {
            hardware::set_i225(probe);
            kprintln!(
                "driver: igc probe {:02x}:{:02x}.{} mmio=0x{:x} status=0x{:08x} link_up={} speed_mbps={} full_duplex={} busmaster={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} status=ready",
                probe.address.bus,
                probe.address.device,
                probe.address.function,
                probe.mmio_base,
                probe.status,
                probe.link.up,
                probe.link.speed.mbps(),
                probe.link.full_duplex,
                probe.bus_master_enabled,
                probe.mac_address[0],
                probe.mac_address[1],
                probe.mac_address[2],
                probe.mac_address[3],
                probe.mac_address[4],
                probe.mac_address[5]
            );
        }
        Ok(None) => kprintln!("driver: igc I225-V not present status=absent"),
        Err(error) => kprintln!(
            "driver: igc I225-V probe failed ({:?}) status=degraded",
            error
        ),
    }

    if apic_active {
        // NVMe completion interrupts are needed while the boot filesystem is still being
        // discovered. The IDT and local APIC are ready, but scheduler preemption remains off.
        interrupts::enable();
    }

    let mut storage_frame_address = init_process.address_space().next_frame_address();
    let nvme_device = pci_inventory.devices().iter().copied().find(|device| {
        device.class_code == 0x01 && device.subclass == 0x08 && device.prog_if == 0x02
    });
    let ahci_device = pci_inventory.devices().iter().copied().find(|device| {
        device.class_code == 0x01 && device.subclass == 0x06 && device.prog_if == 0x01
    });
    let ata_device_present = pci_inventory
        .devices()
        .iter()
        .any(|device| device.class_code == 0x01 && device.subclass == 0x01);
    let mut storage_disk = None;
    if let Some(device) = nvme_device {
        match nvme::NvmeDisk::initialize(
            device,
            physical_memory_offset,
            &boot_info.memory_regions,
            storage_frame_address,
        ) {
            Ok(disk) => {
                kprintln!(
                    "storage: nvme ns={} mmio=0x{:x} version=0x{:08x} capacity_sectors={} queue_entries={} doorbell_stride={} interrupt_mode={:?} interrupt_vector={:?} interrupt_count={} interrupt_driven={} interrupt_error={:?} status=ready",
                    disk.namespace_id(),
                    disk.mmio_base(),
                    disk.controller_version(),
                    disk.capacity_sectors(),
                    disk.queue_entries(),
                    disk.doorbell_stride(),
                    disk.interrupt_mode(),
                    disk.interrupt_vector(),
                    disk.interrupt_count(),
                    disk.interrupt_driven(),
                    disk.interrupt_error
                );
                storage_frame_address = disk.next_frame_address();
                storage_disk = Some(storage::StorageDisk::Nvme(disk));
            }
            Err(error) => {
                kprintln!(
                    "storage: nvme initialization failed ({:?}); evaluating ahci/ata fallback",
                    error
                );
            }
        }
    }
    if storage_disk.is_none() {
        if let Some(device) = ahci_device {
            match ahci::AhciDisk::initialize(
                device,
                physical_memory_offset,
                &boot_info.memory_regions,
                storage_frame_address,
            ) {
                Ok(disk) => {
                    kprintln!(
                        "storage: ahci port={} signature=0x{:08x} mmio=0x{:x} capacity_sectors={} dma64={} interrupt_mode={:?} interrupt_vector={:?} interrupt_count={} interrupt_driven={} interrupt_error={:?} status=ready",
                        disk.port_index(),
                        disk.signature(),
                        disk.mmio_base(),
                        disk.capacity_sectors(),
                        disk.supports_64bit_dma(),
                        disk.interrupt_mode(),
                        disk.interrupt_vector(),
                        disk.interrupt_count(),
                        disk.interrupt_driven(),
                        disk.interrupt_error()
                    );
                    storage_frame_address = disk.next_frame_address();
                    storage_disk = Some(storage::StorageDisk::Ahci(disk));
                }
                Err(error) => {
                    kprintln!(
                        "storage: ahci initialization failed ({:?}); evaluating ata-pio fallback",
                        error
                    );
                }
            }
        }
    }
    if storage_disk.is_none() && ata_device_present {
        match storage::AtaPioDisk::initialize() {
            Ok(disk) => storage_disk = Some(storage::StorageDisk::AtaPio(disk)),
            Err(error) => {
                kprintln!(
                    "storage: ata-pio initialization failed ({:?}) status=degraded",
                    error
                );
            }
        }
    }
    let storage_disk = storage_disk;
    let xhci_device = pci_inventory.devices().iter().copied().find(|device| {
        device.class_code == 0x0c && device.subclass == 0x03 && device.prog_if == 0x30
    });
    let mut dma_frame_address = storage_frame_address;
    if let Some(device) = xhci_device {
        match usb::UsbHid::initialize(
            device,
            physical_memory_offset,
            &boot_info.memory_regions,
            dma_frame_address,
        ) {
            Ok(mut first_hid) => {
                let diagnostics = first_hid.diagnostics();
                dma_frame_address = first_hid.next_frame_address();
                let secondary = match first_hid.initialize_secondary(dma_frame_address) {
                    Ok(mut second_hid) => {
                        first_hid.sync_shared_state(&mut second_hid);
                        dma_frame_address = second_hid.next_frame_address();
                        Some(second_hid)
                    }
                    Err(usb::UsbError::NoPort) => None,
                    Err(error) => {
                        kprintln!(
                            "usb: additional HID initialization failed ({:?}) status=degraded",
                            error
                        );
                        None
                    }
                };
                usb::install_hid(first_hid);
                if let Some(second_hid) = secondary {
                    let second_diagnostics = second_hid.diagnostics();
                    usb::install_hid_secondary(second_hid);
                    kprintln!(
                        "usb: xhci additional hid={:?} port={} hub_port={:?} slot={} endpoint={} speed={} max_packet={} route=0x{:x} depth={} status=ready",
                        second_diagnostics.kind,
                        second_diagnostics.port,
                        second_diagnostics.hub_port,
                        second_diagnostics.slot_id,
                        second_diagnostics.endpoint_id,
                        second_diagnostics.speed,
                        second_diagnostics.max_packet,
                        second_diagnostics.route_string,
                        second_diagnostics.route_depth
                    );
                }
                kprintln!(
                    "usb: xhci hid={:?} port={} hub_port={:?} slot={} endpoint={} speed={} max_packet={} route=0x{:x} depth={} status=ready",
                    diagnostics.kind,
                    diagnostics.port,
                    diagnostics.hub_port,
                    diagnostics.slot_id,
                    diagnostics.endpoint_id,
                    diagnostics.speed,
                    diagnostics.max_packet,
                    diagnostics.route_string,
                    diagnostics.route_depth
                );
            }
            Err(error) => kprintln!(
                "usb: xhci HID initialization failed ({:?}) fallback=ps2 status=degraded",
                error
            ),
        }
    } else {
        kprintln!("usb: xhci controller absent fallback=ps2 status=absent");
    }

    let mut hda_ready = false;
    let _hda_runtime = match hda::initialize(
        &pci_inventory,
        physical_memory_offset,
        &boot_info.memory_regions,
        dma_frame_address,
    ) {
        Ok(Some(runtime)) => {
            kprintln!(
                "audio: hda {:02x}:{:02x}.{} vendor=0x{:04x} device=0x{:04x} mmio=0x{:x} codec={} fg={} dac={} pin={} stream={} rate={} frames={} status=ready",
                runtime.address().bus,
                runtime.address().device,
                runtime.address().function,
                runtime.vendor_id(),
                runtime.device_id(),
                runtime.mmio_base(),
                runtime.codec_address(),
                runtime.function_group(),
                runtime.converter_node(),
                runtime.pin_node(),
                runtime.stream_index(),
                runtime.sample_rate(),
                runtime.frames(),
            );
            hda_ready = true;
            dma_frame_address = runtime.next_frame_address();
            Some(runtime)
        }
        Ok(None) => {
            kprintln!("audio: hda controller absent status=absent");
            None
        }
        Err(failure) => {
            kprintln!(
                "audio: hda initialization failed ({:?}) status=degraded",
                failure.error
            );
            dma_frame_address = failure.next_frame_address;
            None
        }
    };
    let _ac97_runtime = if hda_ready {
        kprintln!("audio: ac97 skipped reason=hda-ready status=absent");
        None
    } else {
        match ac97::initialize(
            &pci_inventory,
            physical_memory_offset,
            &boot_info.memory_regions,
            dma_frame_address,
        ) {
            Ok(Some(runtime)) => {
                kprintln!(
                    "audio: ac97 {:02x}:{:02x}.{} vendor=0x{:04x} device=0x{:04x} nam=0x{:04x} nabm=0x{:04x} rate={} frames={} status=ready",
                    runtime.address().bus,
                    runtime.address().device,
                    runtime.address().function,
                    runtime.vendor_id(),
                    runtime.device_id(),
                    runtime.nam_base(),
                    runtime.nabm_base(),
                    runtime.sample_rate(),
                    runtime.frames(),
                );
                dma_frame_address = runtime.next_frame_address();
                Some(runtime)
            }
            Ok(None) => {
                kprintln!("audio: ac97 controller absent status=absent");
                None
            }
            Err(failure) => {
                kprintln!(
                    "audio: ac97 initialization failed ({:?}) status=degraded",
                    failure.error
                );
                dma_frame_address = failure.next_frame_address;
                None
            }
        }
    };
    process::update_frame_allocator(dma_frame_address);

    let storage_ready = if let Some(mut disk) = storage_disk {
        let transport = disk.kind();
        match storage::probe_disk(&mut disk) {
            Ok(probe) => match storage::probe_kernel_file(disk, probe) {
                Ok(file) => {
                    let storage::StorageFileProbe {
                        metadata,
                        bytes_read,
                        magic,
                        skipped_files,
                        initramfs_size,
                        initramfs_entries,
                        state_before,
                        state_after,
                        files,
                    } = file;
                    let init_image_size = files
                        .iter()
                        .find(|file| file.path == b"/sbin/init")
                        .map_or(0, |file| file.image.len());
                    let shell_image_size = files
                        .iter()
                        .find(|file| file.path == b"/bin/sh")
                        .map_or(0, |file| file.image.len());
                    let worker_image_size = files
                        .iter()
                        .find(|file| file.path == b"/bin/worker")
                        .map_or(0, |file| file.image.len());
                    let service_image_size = files
                        .iter()
                        .find(|file| file.path == b"/bin/service")
                        .map_or(0, |file| file.image.len());
                    let replaced_image_size = files
                        .iter()
                        .find(|file| file.path == b"/bin/replaced")
                        .map_or(0, |file| file.image.len());
                    let restart_image_size = files
                        .iter()
                        .find(|file| file.path == b"/bin/restart")
                        .map_or(0, |file| file.image.len());
                    let config_file_size = files
                        .iter()
                        .find(|file| file.path == b"/etc/rustos/config.txt")
                        .map_or(0, |file| file.image.len());
                    let init_config_file_size = files
                        .iter()
                        .find(|file| file.path == b"/etc/rustos/init.cfg")
                        .map_or(0, |file| file.image.len());
                    let file_count = files.len();
                    let filesystem_files = files
                        .into_iter()
                        .map(|file| process::FilesystemFile {
                            path: file.path,
                            image: file.image,
                            mode: file.mode,
                            persistent: file.persistent,
                        })
                        .collect();
                    let file_catalog_ready = match process::install_filesystem_files(
                        filesystem_files,
                    ) {
                        Ok(()) => true,
                        Err(error) => {
                            kprintln!(
                                "process: filesystem catalog installation failed ({:?}) status=degraded",
                                error
                            );
                            false
                        }
                    };
                    kprintln!(
                        "storage: transport={} capacity_sectors={} table={:?} partition_start={} partition_sectors={} fat={:?} fat_total={} data_start={} clusters={} files={} skipped_files={} initramfs_size={} initramfs_entries={} path=/KERNEL~1 file_size={} read={} magic={:?} state_path=/RUSTOS.ST state_before={:?} state_after={:?} init_path=/sbin/init init_file_size={} shell_path=/bin/sh shell_file_size={} worker_path=/bin/worker worker_file_size={} service_path=/bin/service service_file_size={} replaced_path=/bin/replaced replaced_file_size={} restart_path=/bin/restart restart_file_size={} init_config_path=/etc/rustos/init.cfg init_config_file_size={} config_path=/etc/rustos/config.txt config_file_size={} status={}",
                        transport,
                        probe.capacity_sectors,
                        probe.table,
                        probe.partition.first_lba,
                        probe.partition.sector_count,
                        probe.fat.fat_type,
                        probe.fat.total_sectors,
                        probe.fat.data_start_sector,
                        probe.fat.cluster_count,
                        file_count,
                        skipped_files,
                        initramfs_size,
                        initramfs_entries,
                        metadata.size,
                        bytes_read,
                        magic,
                        state_before,
                        state_after,
                        init_image_size,
                        shell_image_size,
                        worker_image_size,
                        service_image_size,
                        replaced_image_size,
                        restart_image_size,
                        init_config_file_size,
                        config_file_size,
                        if file_catalog_ready {
                            "ready"
                        } else {
                            "degraded"
                        }
                    );
                    file_catalog_ready
                }
                Err(error) => {
                    kprintln!(
                        "storage: transport={} filesystem file probe failed ({:?}) status=degraded",
                        transport,
                        error
                    );
                    false
                }
            },
            Err(error) => {
                kprintln!(
                    "storage: transport={} partition/filesystem probe failed ({:?}) status=degraded",
                    transport,
                    error
                );
                false
            }
        }
    } else {
        kprintln!("storage: ahci/ata controller absent status=absent");
        false
    };

    if apic_active {
        x86_64::instructions::interrupts::disable();
    }

    let (mut virtio_net_runtime, virtio_dma_next_frame_address) = match virtio_net::initialize(
        &pci_inventory,
        physical_memory_offset,
        &boot_info.memory_regions,
        dma_frame_address,
    ) {
        Ok(Some(runtime)) => {
            let next_frame_address = runtime.next_frame_address();
            (Some(runtime), next_frame_address)
        }
        Ok(None) => {
            kprintln!("driver: virtio-net not present status=absent");
            (None, dma_frame_address)
        }
        Err(failure) => {
            kprintln!(
                "driver: virtio-net initialization failed ({:?}) status=degraded",
                failure.error
            );
            (None, failure.next_frame_address)
        }
    };
    process::update_frame_allocator(virtio_dma_next_frame_address);

    let (mut e1000_runtime, dma_next_frame_address) = match e1000::initialize(
        &pci_inventory,
        physical_memory_offset,
        &boot_info.memory_regions,
        virtio_dma_next_frame_address,
    ) {
        Ok(Some(runtime)) => {
            let next_frame_address = runtime.next_frame_address();
            (Some(runtime), next_frame_address)
        }
        Ok(None) => {
            kprintln!("driver: e1000 not present status=absent");
            (None, virtio_dma_next_frame_address)
        }
        Err(failure) => {
            kprintln!(
                "driver: e1000 initialization failed ({:?}) status=degraded",
                failure.error
            );
            (None, failure.next_frame_address)
        }
    };
    process::update_frame_allocator(dma_next_frame_address);

    let (mut igc_runtime, igc_dma_next_frame_address) = match igc::initialize(
        &pci_inventory,
        physical_memory_offset,
        &boot_info.memory_regions,
        dma_next_frame_address,
    ) {
        Ok(Some(runtime)) => {
            let next_frame_address = runtime.next_frame_address();
            (Some(runtime), next_frame_address)
        }
        Ok(None) => {
            kprintln!("driver: igc I225-V not present status=absent");
            (None, dma_next_frame_address)
        }
        Err(failure) => {
            kprintln!(
                "driver: igc I225-V initialization failed ({:?}) status=degraded",
                failure.error
            );
            (None, failure.next_frame_address)
        }
    };
    process::update_frame_allocator(igc_dma_next_frame_address);
    if let Some(runtime) = igc_runtime.as_ref() {
        let probe = runtime.probe_snapshot();
        hardware::set_i225(probe);
        kprintln!(
            "driver: igc transport={} {:02x}:{:02x}.{} mmio=0x{:x}+0x{:x} tx_queue={} rx_queue={} busmaster={} failure={:?} status={}",
            igc::IgcRuntime::interface_name(),
            runtime.address.bus,
            runtime.address.device,
            runtime.address.function,
            runtime.mmio_base,
            runtime.mmio_length,
            runtime.tx_queue_ready,
            runtime.rx_queue_ready,
            runtime.bus_master_enabled,
            runtime.failure,
            if runtime.is_ready() {
                "ready"
            } else {
                "degraded"
            }
        );
    }

    let (virtio_gpu_runtime, gpu_dma_next_frame_address) = match virtio_gpu::initialize(
        &pci_inventory,
        physical_memory_offset,
        &boot_info.memory_regions,
        igc_dma_next_frame_address,
        framebuffer::info(),
    ) {
        Ok(Some(runtime)) => {
            let next_frame_address = runtime.next_frame_address();
            (Some(runtime), next_frame_address)
        }
        Ok(None) => {
            kprintln!("driver: virtio-gpu not present status=absent");
            (None, igc_dma_next_frame_address)
        }
        Err(failure) => {
            kprintln!(
                "driver: virtio-gpu initialization failed ({:?}) status=degraded",
                failure.error
            );
            (None, failure.next_frame_address)
        }
    };
    process::update_frame_allocator(gpu_dma_next_frame_address);
    if let Some(runtime) = virtio_gpu_runtime {
        if runtime.is_ready() {
            hardware::set_graphics_backend(hardware::GraphicsBackend::VirtioGpu);
            kprintln!(
                "driver: virtio-gpu {:02x}:{:02x}.{} mmio=0x{:x} common_len=0x{:x} device_len=0x{:x} notify_multiplier={} features=0x{:x} queue={} scanouts={} bus_master={} status=ready",
                runtime.address.bus,
                runtime.address.device,
                runtime.address.function,
                runtime.mmio_base,
                runtime.common_config_length,
                runtime.device_config_length,
                runtime.notify_multiplier,
                runtime.features,
                runtime.queue_size,
                runtime.num_scanouts,
                runtime.bus_master_enabled
            );
            kprintln!(
                "gpu: scanout={} resource={} width={} height={} status=ready",
                0,
                runtime.resource_id,
                runtime.width,
                runtime.height
            );
            virtio_gpu::install(runtime);
        } else {
            kprintln!(
                "driver: virtio-gpu {:02x}:{:02x}.{} queue={} scanouts={} failure={:?} status=degraded",
                runtime.address.bus,
                runtime.address.device,
                runtime.address.function,
                runtime.queue_size,
                runtime.num_scanouts,
                runtime.failure
            );
        }
    }
    let nvidia_gsp_staging = if storage_ready && nvidia_probe.is_some() {
        match nvidia::stage_external_gsp(
            physical_memory_offset,
            &boot_info.memory_regions,
            gpu_dma_next_frame_address,
        ) {
            Ok(Some(mut staging)) => {
                let fsp_status = if staging.fsp_boot_requested {
                    if !nvidia_target_platform_ready {
                        hardware::set_nvidia_gsp_status(hardware::NvidiaGspStatus::Failed);
                        kprintln!(
                            "driver: nvidia GSP target platform gate failed required=AuthenticAMD/AMD Ryzen 7 5800X 8-Core Processor/30GiB/no-hypervisor device_writes=disabled status=degraded"
                        );
                        "target-platform-failed"
                    } else {
                        hardware::set_nvidia_gsp_status(hardware::NvidiaGspStatus::Staged);
                        let nvidia_is_primary = nvidia_probe.as_ref().is_some_and(|probe| {
                            pci_inventory
                                .first_display()
                                .is_some_and(|display| display.address == probe.address)
                        });
                        match nvidia_probe.as_mut() {
                            Some(probe) => match probe.enable_bus_master() {
                                Ok(()) => {
                                    hardware::set_nvidia(*probe);
                                    match nvidia::boot_external_gsp(
                                        probe,
                                        &mut staging,
                                        nvidia_is_primary,
                                    ) {
                                        Ok(boot) => {
                                            hardware::set_nvidia_gsp_status(
                                                hardware::NvidiaGspStatus::Ready,
                                            );
                                            kprintln!(
                                                "driver: nvidia FSP COT response task_id=0x{:08x} command=0x{:08x} error=0x{:08x} status=accepted",
                                                boot.fsp_response.task_id,
                                                boot.fsp_response.command_nvdm_type,
                                                boot.fsp_response.error_code,
                                            );
                                            kprintln!(
                                                "driver: nvidia GSP-FMC ready hwcfg2=0x{:08x} mailbox=0x{:08x}:0x{:08x} riscv_active={} riscv_lockdown={} status=ready",
                                                boot.gsp.hwcfg2,
                                                boot.gsp.mailbox0,
                                                boot.gsp.mailbox1,
                                                boot.gsp.riscv_active,
                                                boot.gsp.riscv_lockdown,
                                            );
                                            kprintln!(
                                                "driver: nvidia GSP-RM ready function_flow=set-system-info,set-registry,gsp-init-done,get-static-info gpu_name={:?} acceleration=unavailable status=ready",
                                                boot.static_info.gpu_name,
                                            );
                                            "gsp-rm-ready"
                                        }
                                        Err(error) => {
                                            hardware::set_nvidia_gsp_status(
                                                hardware::NvidiaGspStatus::Failed,
                                            );
                                            kprintln!(
                                                "driver: nvidia GSP-RM bootstrap failed ({:?}) status=degraded",
                                                error
                                            );
                                            "gsp-rm-failed"
                                        }
                                    }
                                }
                                Err(error) => {
                                    hardware::set_nvidia_gsp_status(
                                        hardware::NvidiaGspStatus::Failed,
                                    );
                                    kprintln!(
                                        "driver: nvidia bus-master enable failed ({:?}) device_writes=opt-in status=degraded",
                                        error
                                    );
                                    "bus-master-failed"
                                }
                            },
                            None => {
                                hardware::set_nvidia_gsp_status(hardware::NvidiaGspStatus::Failed);
                                "probe-unavailable"
                            }
                        }
                    }
                } else {
                    "disabled"
                };
                kprintln!(
                    "driver: nvidia GSP staging system_base=0x{:x} system_bytes={} system_pages={} system_end=0x{:x} gsp_bytes={} fmc_bytes={} bootloader_bytes={} fsp_cot_bytes={} framebuffer_size={} frts=0x{:x}+0x{:x} gsp_rm_status={} device_writes={} status=ready",
                    staging.system_base(),
                    staging.system_bytes(),
                    staging.system_pages(),
                    staging.system_end(),
                    staging.gsp_bytes,
                    staging.fmc_bytes,
                    staging.bootloader_bytes,
                    staging.fsp_cot.len(),
                    nvidia::NVIDIA_GB20X_FRAMEBUFFER_SIZE,
                    staging.framebuffer.frts_address,
                    staging.framebuffer.frts_size,
                    fsp_status,
                    if staging.fsp_boot_requested && nvidia_target_platform_ready {
                        "opt-in"
                    } else {
                        "disabled"
                    },
                );
                Some(staging)
            }
            Ok(None) => {
                kprintln!(
                    "driver: nvidia GSP firmware carrier absent paths=/GSP.BIN,/FMC.BIN,/BOOT.BIN status=absent"
                );
                None
            }
            Err(error) => {
                kprintln!(
                    "driver: nvidia GSP staging failed ({:?}) device_writes=disabled status=degraded",
                    error
                );
                None
            }
        }
    } else {
        None
    };
    let nvidia_dma_next_frame_address = nvidia_gsp_staging
        .as_ref()
        .map_or(gpu_dma_next_frame_address, |staging| {
            Some(staging.next_frame_address())
        });
    process::update_frame_allocator(nvidia_dma_next_frame_address);
    let graphics_backend = hardware::snapshot().graphics_backend;
    kprintln!(
        "graphics: backend={} compositor={} acceleration={} status={}",
        graphics_backend.name(),
        graphics_backend.compositor(),
        graphics_backend.acceleration(),
        graphics_backend.status()
    );

    let mut e1000_interrupt_ready = false;
    let mut igc_interrupt_ready = false;
    if apic_active {
        if let Some(acpi_info) = acpi_info.as_ref() {
            match scheduler::init(acpi_info) {
                Ok(stats) => {
                    kprintln!(
                        "scheduler: discovered={} enabled={} cpus={} tasks={} workers={} unsupported={} status={}",
                        stats.discovered,
                        stats.enabled,
                        stats.scheduled_cpus,
                        stats.tasks,
                        stats.workers,
                        stats.unsupported,
                        if stats.unsupported == 0 {
                            "ready"
                        } else {
                            "degraded"
                        }
                    );
                    let pid = init_process.pid();
                    match scheduler::register_process(pid) {
                        Ok(process_stats) => kprintln!(
                            "scheduler: process pid={} state={:?} status=ready",
                            process_stats.pid,
                            process_stats.state
                        ),
                        Err(error) => kprintln!(
                            "scheduler: process pid={} registration failed ({:?}) status=degraded",
                            pid,
                            error
                        ),
                    }
                }
                Err(error) => {
                    kprintln!("scheduler: initialization failed ({:?})", error);
                }
            }
        }

        let io_apic_active = acpi_info.as_ref().is_some_and(|acpi_info| {
            match ioapic::init(physical_memory, acpi_info) {
                Ok(io_apic_stats) => {
                    kprintln!(
                        "ioapic: base=0x{:x} id={} version=0x{:x} entries={} GSI={} vector={} dest_apic={} status=ready",
                        io_apic_stats.physical_base,
                        io_apic_stats.id,
                        io_apic_stats.version,
                        io_apic_stats.redirection_entries,
                        io_apic_stats.timer_gsi,
                        io_apic_stats.timer_vector,
                        io_apic_stats.destination_apic_id
                    );
                    true
                }
                Err(error) => {
                    kprintln!("ioapic: initialization failed ({:?})", error);
                    false
                }
            }
        });

        if io_apic_active {
            if let Some(acpi_info) = acpi_info.as_ref() {
                if let Some((gsi, flags)) = acpi_info.legacy_irq_route(storage::ATA_PRIMARY_IRQ) {
                    match ioapic::mask_gsi(physical_memory, acpi_info, gsi, flags) {
                        Ok(()) => kprintln!(
                            "ioapic: masked polling ATA IRQ={} gsi={} status=ready",
                            storage::ATA_PRIMARY_IRQ,
                            gsi
                        ),
                        Err(error) => kprintln!(
                            "ioapic: ATA IRQ={} mask failed ({:?}) status=degraded",
                            storage::ATA_PRIMARY_IRQ,
                            error
                        ),
                    }
                }
            }
        }

        if let Some(runtime) = virtio_net_runtime.as_mut() {
            if runtime.failure.is_none() {
                configure_virtio_interrupts(runtime);
            }
        }

        if let (Some(acpi_info), Some(runtime)) = (acpi_info.as_ref(), e1000_runtime.as_mut()) {
            if runtime.failure.is_none() {
                e1000_interrupt_ready =
                    configure_e1000_interrupts(runtime, physical_memory, acpi_info, io_apic_active);
            }
        }

        if let Some(runtime) = igc_runtime.as_mut() {
            if runtime.failure.is_none() {
                if let Some(acpi_info) = acpi_info.as_ref() {
                    igc_interrupt_ready = configure_igc_interrupts(
                        runtime,
                        physical_memory,
                        acpi_info,
                        io_apic_active,
                    );
                }
            }
        }

        if usb::hid_present() {
            match apic::local_apic_id_u32() {
                Some(destination_apic_id) => match usb::configure_interrupts(
                    destination_apic_id,
                    physical_memory,
                    acpi_info.as_ref(),
                    io_apic_active,
                ) {
                    Ok(diagnostics) => kprintln!(
                        "usb: xhci interrupt mode={:?} vector={:?} gsi={:?} destination_apic={} status=ready",
                        diagnostics.mode,
                        diagnostics.vector,
                        diagnostics.gsi,
                        destination_apic_id
                    ),
                    Err(error) => kprintln!(
                        "usb: xhci interrupt setup failed ({:?}) fallback=polling status=degraded",
                        error
                    ),
                },
                None => kprintln!(
                    "usb: xhci interrupt setup unavailable (no APIC destination) fallback=polling status=degraded"
                ),
            }
        }

        if let Some(acpi_info) = acpi_info.as_ref() {
            match smp::init(
                physical_memory,
                &boot_info.memory_regions,
                nvidia_dma_next_frame_address,
                acpi_info,
            ) {
                Ok(stats) => {
                    kprintln!(
                        "smp: discovered={} enabled={} online={} failed={} bsp_apic={} trampoline=0x{:x} resume_trampoline=0x{:x} status={}",
                        stats.discovered,
                        stats.enabled,
                        stats.online,
                        stats.failed,
                        stats.bsp_apic_id,
                        stats.trampoline_address,
                        stats.resume_trampoline_address,
                        if stats.failed == 0 && stats.online == stats.enabled {
                            "ready"
                        } else {
                            "degraded"
                        }
                    );
                    process::update_frame_allocator(stats.next_frame_address);
                    let power_diagnostics = power::diagnostics();
                    kprintln!(
                        "power: acpi S3 resume_trampoline=0x{:x} suspend={}",
                        stats.resume_trampoline_address,
                        if power_diagnostics.suspend_ready {
                            "ready"
                        } else {
                            "degraded"
                        }
                    );
                }
                Err(error) => {
                    kprintln!("smp: initialization failed ({:?})", error);
                }
            }
        }

        let target_tick = interrupts::apic_ticks().saturating_add(5);
        if io_apic_active {
            let timer = timer::init(100);
            let io_target_tick = interrupts::io_apic_ticks().saturating_add(3);
            interrupts::enable();
            while interrupts::apic_ticks() < target_tick
                || interrupts::io_apic_ticks() < io_target_tick
            {
                interrupts::halt();
            }
            kprintln!(
                "timer: local-apic tick={} ioapic-pit tick={} PIT={} Hz divisor={} status={}",
                interrupts::apic_ticks(),
                interrupts::io_apic_ticks(),
                timer.frequency_hz,
                timer.divisor,
                if interrupts::apic_ticks() >= target_tick
                    && interrupts::io_apic_ticks() >= io_target_tick
                {
                    "ok"
                } else {
                    "failed"
                }
            );
        } else {
            interrupts::enable();
            interrupts::wait_until_apic(target_tick);
            kprintln!(
                "timer: source=local-apic reached tick {} status={}",
                interrupts::apic_ticks(),
                if interrupts::apic_ticks() >= target_tick {
                    "ok"
                } else {
                    "failed"
                }
            );
        }

        if scheduler::is_initialized() {
            if let Some(runtime) = scheduler::start_current_cpu() {
                kprintln!(
                    "scheduler: switches={} heartbeats={} status={}",
                    runtime.switches,
                    runtime.heartbeats,
                    if runtime.switches >= 3 && runtime.heartbeats > 0 {
                        "ok"
                    } else {
                        "failed"
                    }
                );
            }
        }
    } else {
        let timer = timer::init(100);
        interrupts::enable_pic_timer();
        kprintln!(
            "interrupts: using PIC/PIT fallback={} Hz divisor={}",
            timer.frequency_hz,
            timer.divisor
        );
        interrupts::enable();
        let target_tick = interrupts::ticks().saturating_add(10);
        interrupts::wait_until(target_tick);
        kprintln!(
            "timer: source=pit reached tick {} status={}",
            interrupts::ticks(),
            if interrupts::ticks() >= target_tick {
                "ok"
            } else {
                "failed"
            }
        );
    }

    if let Some(runtime) = virtio_net_runtime.as_mut() {
        if runtime.is_ready() {
            match runtime.enable_external_network() {
                Ok(()) => match runtime.acquire_dhcp() {
                    Ok(configuration) => kprintln!(
                        "net: virtio dhcp lease ip={}.{}.{}.{} mask={}.{}.{}.{} gateway={}.{}.{}.{} dns={}.{}.{}.{} server={}.{}.{}.{} lease_seconds={} rx_packets={} tx_packets={} status=ready",
                        configuration.address[0],
                        configuration.address[1],
                        configuration.address[2],
                        configuration.address[3],
                        configuration.subnet_mask[0],
                        configuration.subnet_mask[1],
                        configuration.subnet_mask[2],
                        configuration.subnet_mask[3],
                        configuration.gateway[0],
                        configuration.gateway[1],
                        configuration.gateway[2],
                        configuration.gateway[3],
                        configuration.dns[0],
                        configuration.dns[1],
                        configuration.dns[2],
                        configuration.dns[3],
                        configuration.dhcp_server[0],
                        configuration.dhcp_server[1],
                        configuration.dhcp_server[2],
                        configuration.dhcp_server[3],
                        configuration.lease_seconds,
                        runtime.rx_packets,
                        runtime.tx_packets
                    ),
                    Err(error) => kprintln!(
                        "net: virtio dhcp unavailable ({:?}) fallback=static status=degraded",
                        error
                    ),
                },
                Err(error) => kprintln!(
                    "net: virtio external mode failed ({:?}) status=degraded",
                    error
                ),
            }
        }
        let mac = runtime.mac_address;
        kprintln!(
            "driver: virtio-net {:02x}:{:02x}.{} mmio=0x{:x} common_len=0x{:x} device_len=0x{:x} notify_multiplier={} features=0x{:x} link_up={} rx_queue={} tx_queue={} rx_packets={} tx_packets={} busmaster={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} interrupt_mode={:?} interrupt_vector={:?} interrupt_count={} interrupt_driven={} failure={:?} status={}",
            runtime.address.bus,
            runtime.address.device,
            runtime.address.function,
            runtime.mmio_base,
            runtime.common_config_length,
            runtime.device_config_length,
            runtime.notify_multiplier,
            runtime.features,
            runtime.link_up,
            runtime.rx_queue_size,
            runtime.tx_queue_size,
            runtime.rx_packets,
            runtime.tx_packets,
            runtime.bus_master_enabled,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
            runtime.interrupt_mode,
            runtime.interrupt_vector,
            runtime.interrupt_count,
            runtime.interrupt_driven,
            runtime.failure,
            if runtime.is_ready() {
                "ready"
            } else {
                "degraded"
            }
        );
    }

    if let Some(runtime) = e1000_runtime.as_mut() {
        if e1000_interrupt_ready {
            let source_ip = [192, 0, 2, 1];
            let destination_ip = [192, 0, 2, 2];
            let udp_payload = b"RustOS UDP over IPv4";
            let protocol_packet: Result<(net::EthernetFrame, net::UdpDatagram), e1000::E1000Error> =
                (|| {
                    let udp =
                        net::UdpDatagram::new(4242, 4243, source_ip, destination_ip, udp_payload)
                            .map_err(e1000::E1000Error::Udp)?;
                    let ip = net::Ipv4Packet::new(
                        source_ip,
                        destination_ip,
                        net::IP_PROTOCOL_UDP,
                        udp.as_bytes(),
                        0x1234,
                    )
                    .map_err(e1000::E1000Error::Ipv4)?;
                    let frame = net::EthernetFrame::new(
                        runtime.mac_address,
                        runtime.mac_address,
                        net::ETHER_TYPE_IPV4,
                        ip.as_bytes(),
                    )
                    .map_err(e1000::E1000Error::Frame)?;
                    Ok((frame, udp))
                })();

            match protocol_packet {
                Ok((frame, udp)) => {
                    let loopback: Result<
                        (net::EthernetFrame, net::Ipv4Packet, net::UdpDatagram),
                        e1000::E1000Error,
                    > = (|| {
                        let received = runtime.send_loopback(&frame)?;
                        if received.ether_type() != net::ETHER_TYPE_IPV4 {
                            return Err(e1000::E1000Error::RxPacketMismatch);
                        }
                        let received_ip = net::Ipv4Packet::parse(received.payload())
                            .map_err(e1000::E1000Error::Ipv4)?;
                        if received_ip.source() != source_ip
                            || received_ip.destination() != destination_ip
                            || received_ip.protocol() != net::IP_PROTOCOL_UDP
                        {
                            return Err(e1000::E1000Error::RxPacketMismatch);
                        }
                        let received_udp = net::UdpDatagram::parse(
                            received_ip.payload(),
                            received_ip.source(),
                            received_ip.destination(),
                        )
                        .map_err(e1000::E1000Error::Udp)?;
                        if received_udp.source_port() != 4242
                            || received_udp.destination_port() != 4243
                            || received_udp.payload() != udp_payload
                            || received_udp.as_bytes() != udp.as_bytes()
                        {
                            return Err(e1000::E1000Error::RxPacketMismatch);
                        }
                        Ok((received, received_ip, received_udp))
                    })();

                    match loopback {
                        Ok((received, received_ip, received_udp)) => {
                            kprintln!(
                                "net: e1000 ipv4 src={}.{}.{}.{} dst={}.{}.{}.{} udp_src={} udp_dst={} frame_len={} ip_len={} ip_id=0x{:04x} udp_len={} udp_checksum=0x{:04x} payload_len={} rx_frames={} checksums=valid status=ready",
                                received_ip.source()[0],
                                received_ip.source()[1],
                                received_ip.source()[2],
                                received_ip.source()[3],
                                received_ip.destination()[0],
                                received_ip.destination()[1],
                                received_ip.destination()[2],
                                received_ip.destination()[3],
                                received_udp.source_port(),
                                received_udp.destination_port(),
                                received.len(),
                                received_ip.len(),
                                received_ip.identification(),
                                received_udp.len(),
                                received_udp.checksum(),
                                received_udp.payload().len(),
                                runtime.rx_frames
                            );
                        }
                        Err(error) => {
                            runtime.failure = Some(error);
                            kprintln!(
                                "net: e1000 ipv4/udp loopback validation failed ({:?}) status=degraded",
                                error
                            );
                        }
                    }
                }
                Err(error) => {
                    runtime.failure = Some(error);
                    kprintln!(
                        "net: e1000 ipv4/udp construction failed ({:?}) status=degraded",
                        error
                    );
                }
            }
        }
        if runtime.is_ready() {
            match runtime.enable_external_network() {
                Ok(()) => {
                    match runtime.acquire_dhcp() {
                        Ok(configuration) => kprintln!(
                            "net: dhcp lease ip={}.{}.{}.{} mask={}.{}.{}.{} gateway={}.{}.{}.{} dns={}.{}.{}.{} server={}.{}.{}.{} lease_seconds={} status=ready",
                            configuration.address[0],
                            configuration.address[1],
                            configuration.address[2],
                            configuration.address[3],
                            configuration.subnet_mask[0],
                            configuration.subnet_mask[1],
                            configuration.subnet_mask[2],
                            configuration.subnet_mask[3],
                            configuration.gateway[0],
                            configuration.gateway[1],
                            configuration.gateway[2],
                            configuration.gateway[3],
                            configuration.dns[0],
                            configuration.dns[1],
                            configuration.dns[2],
                            configuration.dns[3],
                            configuration.dhcp_server[0],
                            configuration.dhcp_server[1],
                            configuration.dhcp_server[2],
                            configuration.dhcp_server[3],
                            configuration.lease_seconds
                        ),
                        Err(error) => {
                            let configuration = runtime.network_configuration();
                            kprintln!(
                                "net: dhcp unavailable ({:?}) fallback=static ip={}.{}.{}.{} gateway={}.{}.{}.{} status=degraded",
                                error,
                                configuration.address[0],
                                configuration.address[1],
                                configuration.address[2],
                                configuration.address[3],
                                configuration.gateway[0],
                                configuration.gateway[1],
                                configuration.gateway[2],
                                configuration.gateway[3]
                            );
                        }
                    }
                    kprintln!(
                        "net: e1000 switched from PHY loopback to external UDP mode port=49000 status=ready"
                    );
                }
                Err(error) => {
                    runtime.failure = Some(error);
                    kprintln!(
                        "net: e1000 external mode failed ({:?}) status=degraded",
                        error
                    );
                }
            }
        }
        let mac = runtime.mac_address;
        kprintln!(
            "driver: e1000 {:02x}:{:02x}.{} mmio=0x{:x}+0x{:x} ctrl=0x{:08x} status=0x{:08x} irq_line={} irq_pin={} irq_gsi={:?} irq_vector={:?} irq_mode={:?} irq_count={} irq_cause=0x{:08x} interrupt_driven={} external_network={} dhcp={} busmaster={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} tx_complete={} rx_loopback={} packet_len={} status={} failure={:?}",
            runtime.address.bus,
            runtime.address.device,
            runtime.address.function,
            runtime.mmio_base,
            runtime.mmio_length,
            runtime.control,
            runtime.status,
            runtime.interrupt_line,
            runtime.interrupt_pin,
            runtime.interrupt_gsi,
            runtime.interrupt_vector,
            runtime.interrupt_mode,
            runtime.interrupt_count,
            runtime.interrupt_cause,
            runtime.interrupt_driven,
            runtime.external_network,
            runtime.network.dhcp,
            runtime.bus_master_enabled,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
            runtime.tx_completed,
            runtime.rx_loopback,
            runtime.packet_length,
            if runtime.is_ready() {
                "ready"
            } else {
                "degraded"
            },
            runtime.failure
        );
    }
    if let Some(runtime) = igc_runtime.as_mut() {
        if runtime.is_ready() && igc_interrupt_ready {
            match runtime.enable_external_network() {
                Ok(()) => match runtime.acquire_dhcp() {
                    Ok(configuration) => kprintln!(
                        "net: igc dhcp lease ip={}.{}.{}.{} mask={}.{}.{}.{} gateway={}.{}.{}.{} dns={}.{}.{}.{} server={}.{}.{}.{} lease_seconds={} tx_frames={} rx_frames={} status=ready",
                        configuration.address[0],
                        configuration.address[1],
                        configuration.address[2],
                        configuration.address[3],
                        configuration.subnet_mask[0],
                        configuration.subnet_mask[1],
                        configuration.subnet_mask[2],
                        configuration.subnet_mask[3],
                        configuration.gateway[0],
                        configuration.gateway[1],
                        configuration.gateway[2],
                        configuration.gateway[3],
                        configuration.dns[0],
                        configuration.dns[1],
                        configuration.dns[2],
                        configuration.dns[3],
                        configuration.dhcp_server[0],
                        configuration.dhcp_server[1],
                        configuration.dhcp_server[2],
                        configuration.dhcp_server[3],
                        configuration.lease_seconds,
                        runtime.tx_frames,
                        runtime.rx_frames
                    ),
                    Err(error) => kprintln!(
                        "net: igc dhcp unavailable ({:?}) fallback=static status=degraded",
                        error
                    ),
                },
                Err(error) => kprintln!(
                    "net: igc external mode failed ({:?}) status=degraded",
                    error
                ),
            }
        }
        runtime.sync_interrupt_state();
        hardware::set_i225(runtime.probe_snapshot());
        kprintln!(
            "driver: igc {:02x}:{:02x}.{} mmio=0x{:x}+0x{:x} irq_line={} irq_pin={} irq_gsi={:?} irq_vector={:?} irq_mode={:?} irq_count={} irq_cause=0x{:08x} interrupt_driven={} external_network={} dhcp={} busmaster={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} tx_queue={} rx_queue={} tx_frames={} rx_frames={} status={} failure={:?}",
            runtime.address.bus,
            runtime.address.device,
            runtime.address.function,
            runtime.mmio_base,
            runtime.mmio_length,
            runtime.interrupt_line,
            runtime.interrupt_pin,
            runtime.interrupt_gsi,
            runtime.interrupt_vector,
            runtime.interrupt_mode,
            runtime.interrupt_count,
            runtime.interrupt_cause,
            runtime.interrupt_driven,
            runtime.external_network,
            runtime.network.dhcp,
            runtime.bus_master_enabled,
            runtime.mac_address[0],
            runtime.mac_address[1],
            runtime.mac_address[2],
            runtime.mac_address[3],
            runtime.mac_address[4],
            runtime.mac_address[5],
            runtime.tx_queue_ready,
            runtime.rx_queue_ready,
            runtime.tx_frames,
            runtime.rx_frames,
            if runtime.is_ready() && igc_interrupt_ready {
                if runtime.external_network && runtime.network.dhcp {
                    "dhcp-ready"
                } else {
                    "interrupt-ready"
                }
            } else if runtime.is_ready() {
                "queue-ready-polling"
            } else {
                "degraded"
            },
            runtime.failure
        );
    }
    let mut default_network_backend = None;
    let mut secondary_network_backend = None;
    if let Some(runtime) = virtio_net_runtime.take() {
        if runtime.external_network && runtime.network.dhcp && runtime.is_ready() {
            default_network_backend = Some(network_runtime::NetworkBackend::Virtio(runtime));
        }
    }
    if let Some(runtime) = e1000_runtime.take() {
        if runtime.external_network && runtime.is_ready() {
            let backend = network_runtime::NetworkBackend::E1000(runtime);
            if default_network_backend.is_some() {
                secondary_network_backend = Some(backend);
            } else {
                default_network_backend = Some(backend);
            }
        }
    }
    if let Some(runtime) = igc_runtime.take() {
        if runtime.external_network && runtime.network.dhcp && runtime.is_ready() {
            let backend = network_runtime::NetworkBackend::Igc(runtime);
            if default_network_backend.is_some() {
                if secondary_network_backend.is_none() {
                    secondary_network_backend = Some(backend);
                }
            } else {
                default_network_backend = Some(backend);
            }
        }
    }

    if let Some(default_network_backend) = default_network_backend {
        network_runtime::install_manager(default_network_backend, secondary_network_backend);
        let default_interface = network_runtime::default_interface_name().unwrap_or("unknown");
        let default_backend = network_runtime::backend_name().unwrap_or("unknown");
        kprintln!(
            "net: manager interfaces={} default={} backend={} routes=1 status=ready",
            network_runtime::interface_count(),
            default_interface,
            default_backend
        );
        kprintln!(
            "net: selected backend={} userland UDP service installed status=ready",
            default_backend
        );
    } else {
        kprintln!("net: no userland network backend selected status=degraded");
    }

    x86_64::instructions::interrupts::without_interrupts(|| {
        let released_application_processors = smp::release_application_processors();
        kprintln!(
            "smp: scheduler release={} application_processors status=ready",
            released_application_processors
        );
    });

    let process_ready = if scheduler::is_initialized() {
        const DEFAULT_EXPECTED_PROCESS_COUNT: usize = 6;
        const SHELL_EXPECTED_PROCESS_COUNT: usize = 2;
        let deadline = interrupts::apic_ticks().saturating_add(32768);
        while interrupts::apic_ticks() < deadline {
            let ids = process::runtime_process_ids();
            let process_count = ids.iter().flatten().count();
            let shell_mode = ids.iter().flatten().copied().any(|pid| {
                process::runtime_process_stats(pid).is_some_and(|stats| stats.origin == "/bin/sh")
            });
            let expected_process_count = if shell_mode {
                SHELL_EXPECTED_PROCESS_COUNT
            } else {
                DEFAULT_EXPECTED_PROCESS_COUNT
            };
            let all_exited = process_count >= expected_process_count
                && ids.iter().flatten().copied().all(|pid| {
                    scheduler::process_stats(pid)
                        .is_some_and(|stats| stats.state == process::ProcessState::Exited)
                });
            if all_exited {
                break;
            }
            interrupts::halt();
        }

        let ids = process::runtime_process_ids();
        for pid in ids.iter().flatten().copied() {
            let Some(runtime) = process::runtime_process_stats(pid) else {
                continue;
            };
            let state = scheduler::process_stats(pid)
                .map(|stats| stats.state)
                .unwrap_or(runtime.state);
            kprintln!(
                "process: pid={} parent={} uid={} gid={} origin={} executable={} execs={} forks={} state={:?} root=0x{:x} address_space_id={} reclaimed={} entry=0x{:x} syscalls={} opens={} reads={} read_bytes={} data_reads={} closes={} writes={} write_bytes={} creates={} process_snapshots={} file_snapshots={} yields={} waits={} wait_statuses={} nonzero_waits={} last_wait_status={} blocked={} threads_created={} threads_joined={} last_return={} task_switches={} last_cpu_apic={} exit_code={:?} status={}",
                runtime.pid,
                runtime.parent_pid,
                runtime.uid,
                runtime.gid,
                runtime.origin,
                runtime.executable,
                runtime.exec_count,
                runtime.fork_count,
                state,
                runtime.root_frame,
                runtime.address_space_id,
                runtime.address_space_reclaimed,
                runtime.entry,
                runtime.syscall_count,
                runtime.open_count,
                runtime.read_count,
                runtime.read_bytes,
                runtime.data_read_count,
                runtime.close_count,
                runtime.file_write_count,
                runtime.file_write_bytes,
                runtime.file_create_count,
                runtime.process_snapshot_count,
                runtime.file_snapshot_count,
                runtime.yield_count,
                runtime.wait_count,
                runtime.wait_status_count,
                runtime.nonzero_wait_statuses,
                runtime.last_wait_status,
                runtime.wait_blocks,
                runtime.thread_create_count,
                runtime.thread_join_count,
                runtime.last_return_result,
                runtime.task_switches,
                runtime.last_cpu_apic_id,
                runtime.exit_code,
                if state == process::ProcessState::Exited {
                    "ready"
                } else {
                    "degraded"
                }
            );
        }
        let thread_ids = process::runtime_thread_ids();
        for tid in thread_ids.iter().flatten().copied() {
            let Some(thread) = process::runtime_thread_stats(tid) else {
                continue;
            };
            let state = scheduler::thread_stats(tid)
                .map(|stats| stats.state)
                .unwrap_or(thread.state);
            kprintln!(
                "thread: tid={} pid={} state={:?} entry=0x{:x} stack_top=0x{:x} syscalls={} yields={} task_switches={} exit_code={:?} status={}",
                thread.tid,
                thread.pid,
                state,
                thread.entry,
                thread.stack_top,
                thread.syscall_count,
                thread.yield_count,
                thread.task_switches,
                thread.exit_code,
                if state == process::ProcessState::Exited {
                    "ready"
                } else {
                    "degraded"
                }
            );
        }
        let process_count = ids.iter().flatten().count();
        let shell_mode = ids.iter().flatten().copied().any(|pid| {
            process::runtime_process_stats(pid).is_some_and(|stats| stats.origin == "/bin/sh")
        });
        let expected_process_count = if shell_mode {
            SHELL_EXPECTED_PROCESS_COUNT
        } else {
            DEFAULT_EXPECTED_PROCESS_COUNT
        };
        let all_exited = process_count >= expected_process_count
            && ids.iter().flatten().copied().all(|pid| {
                scheduler::process_stats(pid)
                    .is_some_and(|stats| stats.state == process::ProcessState::Exited)
            });
        let all_address_spaces_reclaimed = all_exited
            && ids.iter().flatten().copied().all(|pid| {
                process::runtime_process_stats(pid)
                    .is_some_and(|stats| stats.address_space_reclaimed)
            });
        kprintln!(
            "process: address_spaces_reclaimed={} count={} status={}",
            all_address_spaces_reclaimed,
            ids.iter()
                .flatten()
                .copied()
                .filter(|pid| {
                    process::runtime_process_stats(*pid)
                        .is_some_and(|stats| stats.address_space_reclaimed)
                })
                .count(),
            if all_address_spaces_reclaimed {
                "ready"
            } else {
                "degraded"
            }
        );
        let init_config_io =
            process::runtime_process_stats(init_process.pid()).is_some_and(|stats| {
                stats.open_count >= 1
                    && stats.read_count >= 1
                    && stats.read_bytes
                        >= u64::from(if shell_mode {
                            process::USER_SHELL_CONFIG_READ_LENGTH
                        } else {
                            process::USER_INIT_CONFIG_READ_LENGTH
                        })
                    && stats.data_read_count >= 1
                    && stats.close_count >= 1
            });
        let mut child_count = 0;
        let mut shell_child = None;
        let mut service_child = None;
        let mut worker_child = None;
        let mut restart_count = 0;
        let mut restart_failed = None;
        let mut restart_recovered = None;
        for pid in ids.iter().flatten().copied() {
            let Some(runtime) = process::runtime_process_stats(pid) else {
                continue;
            };
            if runtime.parent_pid != init_process.pid() {
                continue;
            }
            child_count += 1;
            match runtime.origin {
                "/bin/sh" => shell_child = Some(runtime),
                "/bin/service" => service_child = Some(runtime),
                "/bin/worker" => worker_child = Some(runtime),
                "/bin/restart" => {
                    restart_count += 1;
                    match runtime.exit_code {
                        Some(42) => restart_failed = Some(runtime),
                        Some(0) => restart_recovered = Some(runtime),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        let fork_child = service_child.and_then(|service| {
            ids.iter()
                .flatten()
                .copied()
                .filter_map(process::runtime_process_stats)
                .find(|candidate| {
                    candidate.parent_pid == service.pid && candidate.pid != service.pid
                })
        });
        let voluntary_switches = scheduler::voluntary_switches();
        let restart_roots_distinct = match (restart_failed, restart_recovered) {
            (Some(failed), Some(recovered)) => {
                failed.address_space_id != recovered.address_space_id
            }
            _ => false,
        };
        let restart_policy = restart_count == 2
            && restart_failed.is_some()
            && restart_recovered.is_some()
            && restart_roots_distinct;
        let shell_runtime = shell_child.is_some_and(|stats| {
            stats.state == process::ProcessState::Exited
                && stats.exit_code == Some(0)
                && stats.read_count >= 1
                && stats.read_bytes >= 1
                && stats.yield_count >= 1
                && stats.process_snapshot_count >= 1
                && stats.file_snapshot_count >= 1
                && stats.file_write_count >= 1
                && stats.file_write_bytes >= 7
        });
        let child_spawned = if shell_mode {
            shell_runtime
        } else {
            child_count >= 4 && service_child.is_some() && worker_child.is_some() && restart_policy
        };
        let child_preempted = service_child.is_some_and(|stats| stats.task_switches >= 2)
            && worker_child.is_some_and(|stats| stats.task_switches >= 2);
        let child_yielded = service_child.is_some_and(|stats| stats.yield_count >= 1)
            && worker_child.is_some_and(|stats| stats.yield_count >= 1);
        let child_io = service_child.is_some_and(|stats| {
            stats.open_count >= 1
                && stats.read_count >= 1
                && stats.data_read_count >= 1
                && stats.close_count >= 1
        }) && worker_child.is_some_and(|stats| {
            stats.open_count >= 1
                && stats.read_count >= 1
                && stats.data_read_count >= 1
                && stats.close_count >= 1
        });
        let service_thread = service_child.and_then(|child| {
            thread_ids
                .iter()
                .flatten()
                .copied()
                .filter_map(process::runtime_thread_stats)
                .find(|thread| thread.pid == child.pid)
        });
        let worker_thread = worker_child.and_then(|child| {
            thread_ids
                .iter()
                .flatten()
                .copied()
                .filter_map(process::runtime_thread_stats)
                .find(|thread| thread.pid == child.pid)
        });
        let child_threads = service_thread.is_some_and(|thread| {
            thread.state == process::ProcessState::Exited
                && thread.exit_code == Some(0)
                && thread.yield_count >= 1
                && thread.task_switches >= 1
        }) && service_child
            .is_some_and(|child| child.thread_create_count >= 1 && child.thread_join_count >= 1)
            && worker_thread.is_some_and(|thread| {
                thread.state == process::ProcessState::Exited
                    && thread.exit_code == Some(0)
                    && thread.yield_count >= 1
                    && thread.task_switches >= 1
            })
            && worker_child.is_some_and(|child| {
                child.thread_create_count >= 1 && child.thread_join_count >= 1
            });
        let child_replaced = service_child
            .is_some_and(|child| child.exec_count >= 1 && child.executable == "/bin/replaced");
        let forked_child = service_child.is_some_and(|service| service.fork_count >= 1)
            && fork_child.is_some_and(|child| {
                child.parent_pid == service_child.map_or(0, |service| service.pid)
                    && child.state == process::ProcessState::Exited
                    && child.exit_code == Some(17)
                    && child.origin == "/bin/service"
            });
        let fork_roots_distinct = match (service_child, fork_child) {
            (Some(service), Some(child)) => service.address_space_id != child.address_space_id,
            _ => false,
        };
        let fork_parent_waited = service_child.is_some_and(|service| service.wait_count >= 1)
            && service_child.is_some_and(|service| {
                service.wait_status_count >= 1
                    && service.nonzero_wait_statuses >= 1
                    && service.last_wait_status == 17
            })
            && fork_child.is_some_and(|child| child.state == process::ProcessState::Exited);
        let child_thread_joins = service_child.map_or(0, |child| child.thread_join_count)
            + worker_child.map_or(0, |child| child.thread_join_count);
        let child_roots_distinct = match (service_child, worker_child) {
            (Some(service), Some(worker)) => service.address_space_id != worker.address_space_id,
            _ => false,
        };
        let selected_children_exited = service_child.is_some_and(|stats| {
            stats.state == process::ProcessState::Exited
                && stats.exit_code == Some(0)
                && stats.exec_count >= 1
        }) && worker_child.is_some_and(|stats| {
            stats.state == process::ProcessState::Exited && stats.exit_code == Some(0)
        });
        let supervisor_status_propagated = if shell_mode {
            init_process.wait_status_count() >= 1
                && init_process.nonzero_wait_statuses() == 0
                && init_process.last_wait_status() == 0
        } else {
            init_process.wait_status_count() >= 4
                && init_process.nonzero_wait_statuses() >= 1
                && init_process.last_wait_status() == 0
        };
        let parent_reaped_both = if shell_mode {
            shell_child.is_some()
                && init_process.wait_count() >= 1
                && init_process.last_wait_status() == 0
                && init_process.exit_code() == Some(0)
        } else {
            worker_child.is_some_and(|_| {
                init_process.wait_count() >= 4
                    && restart_recovered.is_some()
                    && init_process.last_wait_status() == 0
                    && init_process.exit_code() == Some(0)
            })
        };
        let default_workload_ready = child_preempted
            && child_yielded
            && child_io
            && child_threads
            && forked_child
            && fork_roots_distinct
            && fork_parent_waited
            && child_replaced
            && child_roots_distinct
            && selected_children_exited;
        let workload_ready = if shell_mode {
            shell_runtime
        } else {
            default_workload_ready
        };
        kprintln!(
            "scheduler: mode={} runtime_processes={} children={} threads={} init_config_io={} child_spawned={} shell_pid={:?} shell_runtime={} shell_snapshots={}/{} shell_writes={}/{} restart_attempts={} restart_failed={} restart_recovered={} restart_roots_distinct={} supervisor_status_propagated={} service_pid={:?} worker_pid={:?} fork_child_pid={:?} service_tid={:?} worker_tid={:?} init_switches={} service_switches={} worker_switches={} preempted={} child_yields={} child_io={} child_threads={} child_forked={} fork_roots_distinct={} fork_parent_waited={} child_replaced={} child_roots_distinct={} parent_waits={} parent_blocks={} parent_thread_joins={} reaped_both={} address_spaces_reclaimed={} voluntary_switches={} status={}",
            if shell_mode { "shell" } else { "default" },
            process_count,
            child_count,
            thread_ids.iter().flatten().count(),
            init_config_io,
            child_spawned,
            shell_child.map_or(0, |stats| stats.pid),
            shell_runtime,
            shell_child.map_or(0, |stats| stats.process_snapshot_count),
            shell_child.map_or(0, |stats| stats.file_snapshot_count),
            shell_child.map_or(0, |stats| stats.file_write_count),
            shell_child.map_or(0, |stats| stats.file_write_bytes),
            restart_count,
            restart_failed.is_some(),
            restart_recovered.is_some(),
            restart_roots_distinct,
            supervisor_status_propagated,
            service_child.map_or(0, |stats| stats.pid),
            worker_child.map_or(0, |stats| stats.pid),
            fork_child.map_or(0, |stats| stats.pid),
            service_thread.map_or(0, |thread| thread.tid),
            worker_thread.map_or(0, |thread| thread.tid),
            init_process.task_switches(),
            service_child.map_or(0, |stats| stats.task_switches),
            worker_child.map_or(0, |stats| stats.task_switches),
            child_preempted,
            child_yielded,
            child_io,
            child_threads,
            forked_child,
            fork_roots_distinct,
            fork_parent_waited,
            child_replaced,
            child_roots_distinct,
            init_process.wait_count(),
            init_process.wait_blocks(),
            child_thread_joins,
            parent_reaped_both,
            all_address_spaces_reclaimed,
            voluntary_switches,
            if all_exited
                && init_config_io
                && child_spawned
                && supervisor_status_propagated
                && workload_ready
                && parent_reaped_both
                && all_address_spaces_reclaimed
                && init_process.wait_blocks() >= 1
                && voluntary_switches >= 3
            {
                "ready"
            } else {
                "degraded"
            }
        );
        all_exited
            && init_config_io
            && child_spawned
            && workload_ready
            && parent_reaped_both
            && all_address_spaces_reclaimed
            && init_process.wait_blocks() >= 1
            && voluntary_switches >= 3
    } else {
        kprintln!("process: scheduler unavailable status=degraded");
        false
    };

    kprintln!(
        "system: RustOS reached interrupt-driven idle state storage={} process={}",
        if storage_ready { "ready" } else { "degraded" },
        if process_ready { "ready" } else { "degraded" }
    );
    let usb_interrupts = usb::interrupt_diagnostics();
    kprintln!(
        "usb: xhci interrupt mode={:?} vector={:?} gsi={:?} interrupts={} status={}",
        usb_interrupts.mode,
        usb_interrupts.vector,
        usb_interrupts.gsi,
        usb_interrupts.interrupts,
        if usb_interrupts.ready {
            "ready"
        } else if usb::hid_present() {
            "polling"
        } else {
            "absent"
        }
    );
    for diagnostics in usb::hid_diagnostics().into_iter().flatten() {
        kprintln!(
            "usb: hid={:?} port={} hub_port={:?} slot={} endpoint={} route=0x{:x} depth={} reports={} bytes={} status={}",
            diagnostics.kind,
            diagnostics.port,
            diagnostics.hub_port,
            diagnostics.slot_id,
            diagnostics.endpoint_id,
            diagnostics.route_string,
            diagnostics.route_depth,
            diagnostics.reports,
            diagnostics.bytes,
            if diagnostics.ready {
                "ready"
            } else {
                "degraded"
            }
        );
    }
    loop {
        interrupts::halt();
    }
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    if smp::is_application_processor() {
        loop {
            // SAFETY: an AP panic is terminal for that AP; avoid concurrent UART writes while the
            // BSP continues booting and records the failed CPU in the SMP startup result.
            unsafe { core::arch::asm!("cli; hlt") };
        }
    }
    console::init();
    kprintln!("PANIC: {}", info);
    loop {
        // SAFETY: halting is the safest terminal behavior after a kernel panic.
        unsafe { core::arch::asm!("hlt") };
    }
}

#[cfg(not(target_os = "none"))]
fn main() {}

#[macro_export]
macro_rules! kprint {
    ($($argument:tt)*) => {{
        $crate::console::write_fmt(core::format_args!($($argument)*));
    }};
}

#[macro_export]
macro_rules! kprintln {
    () => {{
        $crate::kprint!("\n");
    }};
    ($format:literal $(, $argument:expr)* $(,)?) => {{
        $crate::kprint!(concat!($format, "\n") $(, $argument)*);
    }};
}
