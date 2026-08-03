use bootloader::DiskImageBuilder;
use ed25519_dalek::{Signer, SigningKey};
use rustos_gpu_protocol::{
    GspBootSystemMemoryPlan, GspCachedArguments, GspFirmware, GspFirmwareBundle, GspFmc,
    GspFramebufferLayout, GspFspCot, GspRpcMessage, encode_gsp_rpc,
};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{
    collections::BTreeMap,
    env,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::UdpSocket,
    path::Path,
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const TARGET: &str = "x86_64-unknown-none";
const KERNEL_BINARY: &str = "rustos-kernel";
const REPOSITORY_ENTRY_LENGTH: usize = 82;
const REPOSITORY_HEADER_LENGTH: usize = 16;
const REPOSITORY_SIGNATURE_LENGTH: usize = 64;
const REPOSITORY_ROTATION_FLAG: u8 = 1;
const REPOSITORY_ROTATION_MATERIAL_LENGTH: usize = 32 + REPOSITORY_SIGNATURE_LENGTH;
const REPOSITORY_ROTATED_KEY_ID: [u8; 8] = *b"RUSTKEY2";
const REPOSITORY_ROOT_SIGNING_KEY_BYTES: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const REPOSITORY_ROTATED_SIGNING_KEY_BYTES: [u8; 32] = [0x42; 32];
const REPOSITORY_KEY_ROTATION_DOMAIN: &[u8] = b"RUSTOS.KEY.ROTATE\0";
const USERLAND_BINARIES: [&str; 19] = [
    "init",
    "shell",
    "service",
    "worker",
    "cat",
    "vm",
    "replaced",
    "restart",
    "pkg",
    "admin",
    "login",
    "shell-login",
    "passwd",
    "useradd",
    "lock",
    "desktop",
    "terminal",
    "window",
    "window-secondary",
];
const MIB: u64 = 1024 * 1024;
const DEFAULT_PARTITIONED_ROOT_MIB: u64 = 64;
const MIN_PARTITIONED_ROOT_MIB: u64 = 64;
const MAX_PARTITIONED_ROOT_MIB: u64 = 131_072;
const PARTITIONED_ROOT_SIZE: u64 = DEFAULT_PARTITIONED_ROOT_MIB * MIB;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ImageMode {
    Default,
    Shell,
    Recovery,
    Desktop,
}

fn main() {
    if let Err(error) = execute(env::args().skip(1).collect()) {
        eprintln!("rustos: {error}");
        std::process::exit(1);
    }
}

fn execute(arguments: Vec<String>) -> Result<(), String> {
    match arguments.first().map(String::as_str) {
        Some("build") => build(
            arguments.iter().any(|argument| argument == "--release"),
            partitioned_root_size(&arguments)?,
        ),
        Some("check") => check(),
        Some("nvidia-gsp-check") => {
            let path = arguments
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| "nvidia-gsp-check requires a firmware path".to_owned())?;
            nvidia_gsp_check(&path)
        }
        Some("nvidia-fmc-check") => {
            let path = arguments
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| "nvidia-fmc-check requires a firmware path".to_owned())?;
            nvidia_fmc_check(&path)
        }
        Some("nvidia-gsp-bundle-check") => {
            let version = arguments
                .get(1)
                .ok_or_else(|| "nvidia-gsp-bundle-check requires a firmware version".to_owned())?;
            let gsp = arguments
                .get(2)
                .map(PathBuf::from)
                .ok_or_else(|| "nvidia-gsp-bundle-check requires a GSP path".to_owned())?;
            let fmc = arguments
                .get(3)
                .map(PathBuf::from)
                .ok_or_else(|| "nvidia-gsp-bundle-check requires an FMC path".to_owned())?;
            let bootloader = arguments
                .get(4)
                .map(PathBuf::from)
                .ok_or_else(|| "nvidia-gsp-bundle-check requires a bootloader path".to_owned())?;
            nvidia_gsp_bundle_check(version.as_bytes(), &gsp, &fmc, &bootloader)
        }
        Some("run") => {
            let firmware = arguments.get(1).map(String::as_str).ok_or_else(usage)?;
            let release = arguments.iter().any(|argument| argument == "--release");
            let mode = image_mode(&arguments)?;
            let smp = smp_count(&arguments)?;
            let network = arguments.iter().any(|argument| argument == "--network");
            let virtio_network_proof = arguments
                .iter()
                .any(|argument| argument == "--virtio-network-proof");
            if network && virtio_network_proof {
                return Err(
                    "--network and --virtio-network-proof select different network controllers"
                        .to_owned(),
                );
            }
            let partitioned = arguments.iter().any(|argument| argument == "--partitioned");
            let msi = arguments.iter().any(|argument| argument == "--msi");
            let ahci_interrupt_proof = arguments
                .iter()
                .any(|argument| argument == "--ahci-interrupt-proof");
            let vm_proof = arguments.iter().any(|argument| argument == "--vm-proof");
            let smp_proof = arguments.iter().any(|argument| argument == "--smp-proof");
            let mut ahci = arguments.iter().any(|argument| argument == "--ahci");
            if ahci_interrupt_proof {
                ahci = true;
            }
            let nvme_interrupt_proof = arguments
                .iter()
                .any(|argument| argument == "--nvme-interrupt-proof");
            let mut nvme = arguments.iter().any(|argument| argument == "--nvme");
            if nvme_interrupt_proof {
                nvme = true;
            }
            if ahci && nvme {
                return Err("--ahci and --nvme select different QEMU storage transports".to_owned());
            }
            let usb = arguments.iter().any(|argument| argument == "--usb");
            let usb_mouse = arguments.iter().any(|argument| argument == "--usb-mouse");
            let usb_both = arguments.iter().any(|argument| argument == "--usb-both");
            let usb_hub = arguments.iter().any(|argument| argument == "--usb-hub");
            let usb_hotplug = arguments.iter().any(|argument| argument == "--usb-hotplug");
            let usb_legacy = arguments.iter().any(|argument| argument == "--usb-legacy");
            let usb_nested = arguments.iter().any(|argument| argument == "--usb-nested");
            let usb_nested_hotplug = arguments
                .iter()
                .any(|argument| argument == "--usb-nested-hotplug");
            if usize::from(usb)
                + usize::from(usb_mouse)
                + usize::from(usb_both)
                + usize::from(usb_hub)
                + usize::from(usb_hotplug)
                + usize::from(usb_legacy)
                + usize::from(usb_nested)
                + usize::from(usb_nested_hotplug)
                > 1
            {
                return Err(
                    "--usb, --usb-mouse, --usb-both, --usb-hub, --usb-hotplug, --usb-legacy, --usb-nested, and --usb-nested-hotplug select different USB HID layouts".to_owned(),
                );
            }
            if (usb_mouse || usb_both || usb_hub || usb_hotplug || usb_nested || usb_nested_hotplug)
                && mode != ImageMode::Desktop
            {
                return Err(
                    "--usb-mouse, --usb-both, --usb-hub, --usb-hotplug, --usb-nested, and --usb-nested-hotplug currently require --desktop".to_owned(),
                );
            }
            let keyboard_proof = arguments
                .iter()
                .any(|argument| argument == "--keyboard-proof");
            let shell_proof = arguments.iter().any(|argument| argument == "--shell-proof");
            let pipe_proof = arguments.iter().any(|argument| argument == "--pipe-proof");
            let desktop_proof = arguments
                .iter()
                .any(|argument| argument == "--desktop-proof");
            let terminal_proof = arguments
                .iter()
                .any(|argument| argument == "--terminal-proof");
            let account_proof = arguments
                .iter()
                .any(|argument| argument == "--account-proof");
            let logout_proof = arguments
                .iter()
                .any(|argument| argument == "--logout-proof");
            let role_proof = arguments.iter().any(|argument| argument == "--role-proof");
            let virtio_gpu_proof = arguments
                .iter()
                .any(|argument| argument == "--virtio-gpu-proof");
            let poweroff_proof = arguments
                .iter()
                .any(|argument| argument == "--poweroff-proof");
            let reboot_proof = arguments
                .iter()
                .any(|argument| argument == "--reboot-proof");
            let suspend_proof = arguments
                .iter()
                .any(|argument| argument == "--suspend-proof");
            let native_suspend_proof = arguments
                .iter()
                .any(|argument| argument == "--native-suspend-proof");
            let audio_proof = arguments.iter().any(|argument| argument == "--audio-proof");
            let hda_audio_proof = arguments
                .iter()
                .any(|argument| argument == "--hda-audio-proof");
            let any_audio_proof = audio_proof || hda_audio_proof;
            if audio_proof && hda_audio_proof {
                return Err(
                    "--audio-proof and --hda-audio-proof select different audio controllers"
                        .to_owned(),
                );
            }
            if any_audio_proof && virtio_network_proof {
                return Err(
                    "audio proof and --virtio-network-proof are mutually exclusive".to_owned(),
                );
            }
            if keyboard_proof && mode != ImageMode::Shell {
                return Err("--keyboard-proof requires --shell".to_owned());
            }
            if shell_proof && mode != ImageMode::Shell {
                return Err("--shell-proof requires --shell".to_owned());
            }
            if pipe_proof && mode != ImageMode::Shell {
                return Err("--pipe-proof requires --shell".to_owned());
            }
            if virtio_network_proof && mode != ImageMode::Shell {
                return Err("--virtio-network-proof requires --shell".to_owned());
            }
            if nvme_interrupt_proof && mode != ImageMode::Shell {
                return Err("--nvme-interrupt-proof requires --shell".to_owned());
            }
            if ahci_interrupt_proof && mode != ImageMode::Shell {
                return Err("--ahci-interrupt-proof requires --shell".to_owned());
            }
            if vm_proof && mode != ImageMode::Shell {
                return Err("--vm-proof requires --shell".to_owned());
            }
            if smp_proof && mode != ImageMode::Default {
                return Err("--smp-proof requires the default userland workload".to_owned());
            }
            if smp_proof && smp < 2 {
                return Err("--smp-proof requires --smp 2 or more".to_owned());
            }
            if virtio_network_proof && msi {
                return Err("--virtio-network-proof cannot be combined with --msi".to_owned());
            }
            if desktop_proof && mode != ImageMode::Desktop {
                return Err("--desktop-proof requires --desktop".to_owned());
            }
            if terminal_proof && mode != ImageMode::Desktop {
                return Err("--terminal-proof requires --desktop".to_owned());
            }
            if account_proof && mode != ImageMode::Desktop {
                return Err("--account-proof requires --desktop".to_owned());
            }
            if logout_proof && mode != ImageMode::Desktop {
                return Err("--logout-proof requires --desktop".to_owned());
            }
            if role_proof && mode != ImageMode::Desktop {
                return Err("--role-proof requires --desktop".to_owned());
            }
            if virtio_gpu_proof && mode != ImageMode::Desktop {
                return Err("--virtio-gpu-proof requires --desktop".to_owned());
            }
            if poweroff_proof && mode != ImageMode::Shell {
                return Err("--poweroff-proof requires --shell".to_owned());
            }
            if reboot_proof && mode != ImageMode::Shell {
                return Err("--reboot-proof requires --shell".to_owned());
            }
            if suspend_proof && mode != ImageMode::Shell {
                return Err("--suspend-proof requires --shell".to_owned());
            }
            if native_suspend_proof && !suspend_proof {
                return Err("--native-suspend-proof requires --suspend-proof".to_owned());
            }
            if native_suspend_proof && firmware != "uefi" {
                return Err("--native-suspend-proof requires the uefi firmware path".to_owned());
            }
            if (any_audio_proof
                || virtio_network_proof
                || nvme_interrupt_proof
                || ahci_interrupt_proof
                || vm_proof)
                && (keyboard_proof
                    || pipe_proof
                    || desktop_proof
                    || terminal_proof
                    || virtio_gpu_proof
                    || poweroff_proof
                    || reboot_proof
                    || suspend_proof)
            {
                return Err(
                    "audio, network, and storage interrupt proofs cannot be combined with another runtime proof"
                        .to_owned(),
                );
            }
            if usb_legacy && !keyboard_proof {
                return Err("--usb-legacy currently requires --keyboard-proof".to_owned());
            }
            if (usb_hotplug || usb_nested_hotplug) && !desktop_proof {
                return Err(
                    "--usb-hotplug and --usb-nested-hotplug currently require --desktop-proof"
                        .to_owned(),
                );
            }
            if keyboard_proof && desktop_proof {
                return Err(
                    "--keyboard-proof and --desktop-proof are mutually exclusive".to_owned(),
                );
            }
            if terminal_proof && desktop_proof {
                return Err(
                    "--terminal-proof and --desktop-proof are mutually exclusive".to_owned(),
                );
            }
            if account_proof
                && (keyboard_proof
                    || shell_proof
                    || pipe_proof
                    || desktop_proof
                    || terminal_proof
                    || virtio_gpu_proof
                    || poweroff_proof
                    || reboot_proof
                    || suspend_proof
                    || smp_proof
                    || any_audio_proof
                    || virtio_network_proof
                    || nvme_interrupt_proof
                    || ahci_interrupt_proof
                    || vm_proof)
            {
                return Err(
                    "--account-proof cannot be combined with another runtime proof".to_owned(),
                );
            }
            if logout_proof
                && (keyboard_proof
                    || shell_proof
                    || pipe_proof
                    || desktop_proof
                    || terminal_proof
                    || account_proof
                    || virtio_gpu_proof
                    || poweroff_proof
                    || reboot_proof
                    || suspend_proof
                    || smp_proof
                    || any_audio_proof
                    || virtio_network_proof
                    || nvme_interrupt_proof
                    || ahci_interrupt_proof
                    || vm_proof)
            {
                return Err(
                    "--logout-proof cannot be combined with another runtime proof".to_owned(),
                );
            }
            if role_proof
                && (keyboard_proof
                    || shell_proof
                    || pipe_proof
                    || desktop_proof
                    || terminal_proof
                    || account_proof
                    || logout_proof
                    || virtio_gpu_proof
                    || poweroff_proof
                    || reboot_proof
                    || suspend_proof
                    || smp_proof
                    || any_audio_proof
                    || virtio_network_proof
                    || nvme_interrupt_proof
                    || ahci_interrupt_proof
                    || vm_proof)
            {
                return Err("--role-proof cannot be combined with another runtime proof".to_owned());
            }
            if virtio_gpu_proof
                && (keyboard_proof
                    || pipe_proof
                    || desktop_proof
                    || terminal_proof
                    || poweroff_proof
                    || reboot_proof
                    || suspend_proof
                    || smp_proof
                    || any_audio_proof
                    || virtio_network_proof
                    || nvme_interrupt_proof
                    || ahci_interrupt_proof
                    || vm_proof)
            {
                return Err(
                    "--virtio-gpu-proof cannot be combined with another runtime proof".to_owned(),
                );
            }
            if pipe_proof && keyboard_proof {
                return Err("--pipe-proof and --keyboard-proof are mutually exclusive".to_owned());
            }
            if shell_proof
                && (keyboard_proof
                    || pipe_proof
                    || desktop_proof
                    || terminal_proof
                    || virtio_gpu_proof
                    || poweroff_proof
                    || reboot_proof
                    || suspend_proof
                    || smp_proof
                    || any_audio_proof
                    || virtio_network_proof
                    || nvme_interrupt_proof
                    || ahci_interrupt_proof
                    || vm_proof)
            {
                return Err(
                    "--shell-proof cannot be combined with another runtime proof".to_owned(),
                );
            }
            if pipe_proof
                && (desktop_proof
                    || poweroff_proof
                    || reboot_proof
                    || suspend_proof
                    || smp_proof
                    || any_audio_proof
                    || virtio_network_proof
                    || nvme_interrupt_proof
                    || ahci_interrupt_proof
                    || vm_proof)
            {
                return Err("--pipe-proof cannot be combined with another runtime proof".to_owned());
            }
            if poweroff_proof && (keyboard_proof || desktop_proof) {
                return Err(
                    "--poweroff-proof cannot be combined with another runtime proof".to_owned(),
                );
            }
            if reboot_proof && (keyboard_proof || desktop_proof || poweroff_proof) {
                return Err(
                    "--reboot-proof cannot be combined with another runtime proof".to_owned(),
                );
            }
            if suspend_proof && (keyboard_proof || desktop_proof || poweroff_proof || reboot_proof)
            {
                return Err(
                    "--suspend-proof cannot be combined with another runtime proof".to_owned(),
                );
            }
            if smp_proof
                && (keyboard_proof
                    || desktop_proof
                    || poweroff_proof
                    || reboot_proof
                    || suspend_proof
                    || any_audio_proof
                    || virtio_network_proof
                    || nvme_interrupt_proof
                    || ahci_interrupt_proof
                    || vm_proof)
            {
                return Err("--smp-proof cannot be combined with another runtime proof".to_owned());
            }
            if partitioned && firmware != "uefi" {
                return Err("--partitioned currently requires the uefi firmware path".to_owned());
            }
            let image = argument_value(&arguments, "--image")?;
            if image.is_none() {
                build(release, partitioned_root_size(&arguments)?)?;
            }
            run(
                firmware,
                release,
                smp,
                mode,
                network,
                partitioned,
                msi,
                ahci,
                nvme,
                usb,
                usb_mouse,
                usb_both,
                usb_hub,
                usb_hotplug,
                usb_legacy,
                usb_nested,
                usb_nested_hotplug,
                keyboard_proof,
                shell_proof,
                pipe_proof,
                desktop_proof,
                terminal_proof,
                account_proof,
                logout_proof,
                role_proof,
                virtio_gpu_proof,
                poweroff_proof,
                reboot_proof,
                suspend_proof,
                native_suspend_proof,
                audio_proof,
                hda_audio_proof,
                virtio_network_proof,
                nvme_interrupt_proof,
                ahci_interrupt_proof,
                vm_proof,
                smp_proof,
                image,
            )
        }
        Some("install") => {
            let firmware = arguments.get(1).map(String::as_str).ok_or_else(usage)?;
            let target = arguments.get(2).map(PathBuf::from).ok_or_else(usage)?;
            let release = arguments.iter().any(|argument| argument == "--release");
            let mode = image_mode(&arguments)?;
            let force = arguments.iter().any(|argument| argument == "--force");
            let partitioned = arguments.iter().any(|argument| argument == "--partitioned");
            if partitioned && firmware != "uefi" {
                return Err("--partitioned currently requires the uefi firmware path".to_owned());
            }
            build(release, partitioned_root_size(&arguments)?)?;
            let source = target_dir(&workspace_root())
                .join("images")
                .join(if partitioned {
                    partitioned_image_name(firmware, release, mode)
                } else {
                    image_name(firmware, release, mode)
                });
            if partitioned {
                install_partitioned_image(&source, &target, force)
            } else {
                install_image(&source, &target, force)
            }
        }
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(command) => Err(format!("unknown command `{command}`\n\n{}", usage_text())),
    }
}

fn build(release: bool, partitioned_root_size: u64) -> Result<(), String> {
    let root = workspace_root();
    let userland = build_userland(&root, release)?;
    let mut command = Command::new(cargo_binary());
    command
        .current_dir(&root)
        .args(["build", "-p", "rustos-kernel", "--target", TARGET]);
    if release {
        command.arg("--release");
    }
    run_command(&mut command, "building the kernel")?;

    let kernel = kernel_path(&root, release);
    if !kernel.is_file() {
        return Err(format!(
            "kernel artifact was not created: {}",
            kernel.display()
        ));
    }

    let images = target_dir(&root).join("images");
    fs::create_dir_all(&images)
        .map_err(|error| format!("creating {}: {error}", images.display()))?;

    let init = read_userland_image(&userland, "init")?;
    let shell = read_userland_image(&userland, "shell")?;
    let service = read_userland_image(&userland, "service")?;
    let worker = read_userland_image(&userland, "worker")?;
    let cat = read_userland_image(&userland, "cat")?;
    let vm = read_userland_image(&userland, "vm")?;
    let replaced = read_userland_image(&userland, "replaced")?;
    let restart = read_userland_image(&userland, "restart")?;
    let pkg = read_userland_image(&userland, "pkg")?;
    let admin = read_userland_image(&userland, "admin")?;
    let login = read_userland_image(&userland, "login")?;
    let shell_login = read_userland_image(&userland, "shell-login")?;
    let passwd = read_userland_image(&userland, "passwd")?;
    let useradd = read_userland_image(&userland, "useradd")?;
    let lock = read_userland_image(&userland, "lock")?;
    let desktop = read_userland_image(&userland, "desktop")?;
    let terminal = read_userland_image(&userland, "terminal")?;
    let window = read_userland_image(&userland, "window")?;
    let window_secondary = read_userland_image(&userland, "window-secondary")?;

    let default_entries: [(&str, &[u8], u32); 20] = [
        ("sbin/init", &init, 0o100755),
        ("sbin/admin", &admin, 0o100755),
        ("sbin/login", &login, 0o100755),
        ("sbin/shell-login", &shell_login, 0o100755),
        ("bin/passwd", &passwd, 0o100755),
        ("bin/useradd", &useradd, 0o100755),
        ("bin/lock", &lock, 0o100755),
        ("bin/sh", &shell, 0o100755),
        ("bin/service", &service, 0o100755),
        ("bin/worker", &worker, 0o100755),
        ("bin/cat", &cat, 0o100755),
        ("bin/vm", &vm, 0o100755),
        ("bin/replaced", &replaced, 0o100755),
        ("bin/restart", &restart, 0o100755),
        ("bin/pkg", &pkg, 0o100755),
        ("bin/desktop", &desktop, 0o100755),
        ("bin/window", &window, 0o100755),
        ("bin/window-secondary", &window_secondary, 0o100755),
        ("etc/rustos/init.cfg", USER_INIT_CONFIG, 0o100644),
        ("etc/rustos/config.txt", USER_CONFIG_CONTENT, 0o100644),
    ];
    let shell_entries: [(&str, &[u8], u32); 20] = [
        ("sbin/init", &init, 0o100755),
        ("sbin/admin", &admin, 0o100755),
        ("sbin/login", &login, 0o100755),
        ("sbin/shell-login", &shell_login, 0o100755),
        ("bin/passwd", &passwd, 0o100755),
        ("bin/useradd", &useradd, 0o100755),
        ("bin/lock", &lock, 0o100755),
        ("bin/sh", &shell, 0o100755),
        ("bin/service", &service, 0o100755),
        ("bin/worker", &worker, 0o100755),
        ("bin/cat", &cat, 0o100755),
        ("bin/vm", &vm, 0o100755),
        ("bin/replaced", &replaced, 0o100755),
        ("bin/restart", &restart, 0o100755),
        ("bin/pkg", &pkg, 0o100755),
        ("bin/desktop", &desktop, 0o100755),
        ("bin/window", &window, 0o100755),
        ("bin/window-secondary", &window_secondary, 0o100755),
        ("etc/rustos/init.cfg", SHELL_INIT_CONFIG, 0o100644),
        ("etc/rustos/config.txt", USER_CONFIG_CONTENT, 0o100644),
    ];
    let desktop_entries: [(&str, &[u8], u32); 21] = [
        ("sbin/init", &init, 0o100755),
        ("sbin/admin", &admin, 0o100755),
        ("sbin/login", &login, 0o100755),
        ("sbin/shell-login", &shell_login, 0o100755),
        ("bin/passwd", &passwd, 0o100755),
        ("bin/useradd", &useradd, 0o100755),
        ("bin/lock", &lock, 0o100755),
        ("bin/sh", &shell, 0o100755),
        ("bin/service", &service, 0o100755),
        ("bin/worker", &worker, 0o100755),
        ("bin/cat", &cat, 0o100755),
        ("bin/vm", &vm, 0o100755),
        ("bin/replaced", &replaced, 0o100755),
        ("bin/restart", &restart, 0o100755),
        ("bin/pkg", &pkg, 0o100755),
        ("bin/desktop", &desktop, 0o100755),
        ("bin/terminal", &terminal, 0o100755),
        ("bin/window", &window, 0o100755),
        ("bin/window-secondary", &window_secondary, 0o100755),
        ("etc/rustos/init.cfg", DESKTOP_INIT_CONFIG, 0o100644),
        ("etc/rustos/config.txt", USER_CONFIG_CONTENT, 0o100644),
    ];
    let recovery_entries: [(&str, &[u8], u32); 21] = [
        ("sbin/init", &init, 0o100755),
        ("sbin/admin", &admin, 0o100755),
        ("sbin/login", &login, 0o100755),
        ("sbin/shell-login", &shell_login, 0o100755),
        ("bin/passwd", &passwd, 0o100755),
        ("bin/useradd", &useradd, 0o100755),
        ("bin/lock", &lock, 0o100755),
        ("bin/sh", &shell, 0o100755),
        ("bin/service", &service, 0o100755),
        ("bin/worker", &worker, 0o100755),
        ("bin/cat", &cat, 0o100755),
        ("bin/vm", &vm, 0o100755),
        ("bin/replaced", &replaced, 0o100755),
        ("bin/restart", &restart, 0o100755),
        ("bin/pkg", &pkg, 0o100755),
        ("bin/desktop", &desktop, 0o100755),
        ("bin/window", &window, 0o100755),
        ("bin/window-secondary", &window_secondary, 0o100755),
        ("etc/rustos/init.cfg", SHELL_INIT_CONFIG, 0o100644),
        ("etc/rustos/config.txt", USER_CONFIG_CONTENT, 0o100644),
        ("etc/rustos/recovery.cfg", RECOVERY_MARKER_CONTENT, 0o100644),
    ];
    let initramfs = build_initramfs(&default_entries)?;
    let shell_initramfs = build_initramfs(&shell_entries)?;
    let desktop_initramfs = build_initramfs(&desktop_entries)?;
    let recovery_initramfs = build_initramfs(&recovery_entries)?;
    let repository = build_repository();

    let bios = images.join(image_name("bios", release, ImageMode::Default));
    let mut bios_builder = DiskImageBuilder::new(kernel.clone());
    bios_builder.set_file_contents("initrd.cpi".to_owned(), initramfs.clone());
    bios_builder.set_file_contents("rustos.st".to_owned(), PERSISTENT_STATE_CONTENT.to_vec());
    bios_builder.set_file_contents("rustos.rep".to_owned(), repository.clone());
    bios_builder
        .create_bios_image(&bios)
        .map_err(|error| format!("creating BIOS image {}: {error:#}", bios.display()))?;

    let uefi = images.join(image_name("uefi", release, ImageMode::Default));
    let mut uefi_builder = DiskImageBuilder::new(kernel.clone());
    uefi_builder.set_file_contents("initrd.cpi".to_owned(), initramfs.clone());
    uefi_builder.set_file_contents("rustos.st".to_owned(), PERSISTENT_STATE_CONTENT.to_vec());
    uefi_builder.set_file_contents("rustos.rep".to_owned(), repository.clone());
    uefi_builder
        .create_uefi_image(&uefi)
        .map_err(|error| format!("creating UEFI image {}: {error:#}", uefi.display()))?;
    let uefi_partitioned = images.join(partitioned_image_name("uefi", release, ImageMode::Default));
    create_partitioned_uefi_image(
        &kernel,
        &initramfs,
        &repository,
        &uefi_partitioned,
        partitioned_root_size,
    )?;

    let bios_shell = images.join(image_name("bios", release, ImageMode::Shell));
    let mut bios_shell_builder = DiskImageBuilder::new(kernel.clone());
    bios_shell_builder.set_file_contents("initrd.cpi".to_owned(), shell_initramfs.clone());
    bios_shell_builder.set_file_contents("rustos.st".to_owned(), PERSISTENT_STATE_CONTENT.to_vec());
    bios_shell_builder.set_file_contents("rustos.rep".to_owned(), repository.clone());
    bios_shell_builder
        .create_bios_image(&bios_shell)
        .map_err(|error| {
            format!(
                "creating BIOS shell image {}: {error:#}",
                bios_shell.display()
            )
        })?;

    let uefi_shell = images.join(image_name("uefi", release, ImageMode::Shell));
    let mut uefi_shell_builder = DiskImageBuilder::new(kernel.clone());
    uefi_shell_builder.set_file_contents("initrd.cpi".to_owned(), shell_initramfs.clone());
    uefi_shell_builder.set_file_contents("rustos.st".to_owned(), PERSISTENT_STATE_CONTENT.to_vec());
    uefi_shell_builder.set_file_contents("rustos.rep".to_owned(), repository.clone());
    uefi_shell_builder
        .create_uefi_image(&uefi_shell)
        .map_err(|error| {
            format!(
                "creating UEFI shell image {}: {error:#}",
                uefi_shell.display()
            )
        })?;
    let uefi_shell_partitioned =
        images.join(partitioned_image_name("uefi", release, ImageMode::Shell));
    create_partitioned_uefi_image(
        &kernel,
        &shell_initramfs,
        &repository,
        &uefi_shell_partitioned,
        partitioned_root_size,
    )?;

    let bios_desktop = images.join(image_name("bios", release, ImageMode::Desktop));
    let mut bios_desktop_builder = DiskImageBuilder::new(kernel.clone());
    bios_desktop_builder.set_file_contents("initrd.cpi".to_owned(), desktop_initramfs.clone());
    bios_desktop_builder
        .set_file_contents("rustos.st".to_owned(), PERSISTENT_STATE_CONTENT.to_vec());
    bios_desktop_builder.set_file_contents("rustos.rep".to_owned(), repository.clone());
    bios_desktop_builder
        .create_bios_image(&bios_desktop)
        .map_err(|error| {
            format!(
                "creating BIOS desktop image {}: {error:#}",
                bios_desktop.display()
            )
        })?;

    let uefi_desktop = images.join(image_name("uefi", release, ImageMode::Desktop));
    let mut uefi_desktop_builder = DiskImageBuilder::new(kernel.clone());
    uefi_desktop_builder.set_file_contents("initrd.cpi".to_owned(), desktop_initramfs.clone());
    uefi_desktop_builder
        .set_file_contents("rustos.st".to_owned(), PERSISTENT_STATE_CONTENT.to_vec());
    uefi_desktop_builder.set_file_contents("rustos.rep".to_owned(), repository.clone());
    uefi_desktop_builder
        .create_uefi_image(&uefi_desktop)
        .map_err(|error| {
            format!(
                "creating UEFI desktop image {}: {error:#}",
                uefi_desktop.display()
            )
        })?;
    let uefi_desktop_partitioned =
        images.join(partitioned_image_name("uefi", release, ImageMode::Desktop));
    create_partitioned_uefi_image(
        &kernel,
        &desktop_initramfs,
        &repository,
        &uefi_desktop_partitioned,
        partitioned_root_size,
    )?;

    let bios_recovery = images.join(image_name("bios", release, ImageMode::Recovery));
    let mut bios_recovery_builder = DiskImageBuilder::new(kernel.clone());
    bios_recovery_builder.set_file_contents("initrd.cpi".to_owned(), recovery_initramfs.clone());
    bios_recovery_builder
        .set_file_contents("rustos.st".to_owned(), PERSISTENT_STATE_CONTENT.to_vec());
    bios_recovery_builder.set_file_contents("rustos.rep".to_owned(), repository.clone());
    bios_recovery_builder
        .create_bios_image(&bios_recovery)
        .map_err(|error| {
            format!(
                "creating BIOS recovery image {}: {error:#}",
                bios_recovery.display()
            )
        })?;

    let uefi_recovery = images.join(image_name("uefi", release, ImageMode::Recovery));
    let mut uefi_recovery_builder = DiskImageBuilder::new(kernel.clone());
    uefi_recovery_builder.set_file_contents("initrd.cpi".to_owned(), recovery_initramfs.clone());
    uefi_recovery_builder
        .set_file_contents("rustos.st".to_owned(), PERSISTENT_STATE_CONTENT.to_vec());
    uefi_recovery_builder.set_file_contents("rustos.rep".to_owned(), repository.clone());
    uefi_recovery_builder
        .create_uefi_image(&uefi_recovery)
        .map_err(|error| {
            format!(
                "creating UEFI recovery image {}: {error:#}",
                uefi_recovery.display()
            )
        })?;
    let uefi_recovery_partitioned =
        images.join(partitioned_image_name("uefi", release, ImageMode::Recovery));
    create_partitioned_uefi_image(
        &kernel,
        &recovery_initramfs,
        &repository,
        &uefi_recovery_partitioned,
        partitioned_root_size,
    )?;

    println!("kernel: {}", kernel.display());
    println!("BIOS image: {}", bios.display());
    println!("UEFI image: {}", uefi.display());
    println!("UEFI partitioned image: {}", uefi_partitioned.display());
    println!("BIOS shell image: {}", bios_shell.display());
    println!("UEFI shell image: {}", uefi_shell.display());
    println!(
        "UEFI partitioned shell image: {}",
        uefi_shell_partitioned.display()
    );
    println!("BIOS desktop image: {}", bios_desktop.display());
    println!("UEFI desktop image: {}", uefi_desktop.display());
    println!(
        "UEFI partitioned desktop image: {}",
        uefi_desktop_partitioned.display()
    );
    println!("BIOS recovery image: {}", bios_recovery.display());
    println!("UEFI recovery image: {}", uefi_recovery.display());
    println!(
        "UEFI partitioned recovery image: {}",
        uefi_recovery_partitioned.display()
    );
    Ok(())
}

fn create_partitioned_uefi_image(
    kernel: &Path,
    initramfs: &[u8],
    repository: &[u8],
    output: &Path,
    root_size: u64,
) -> Result<(), String> {
    validate_partitioned_root_size(root_size)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let prefix = format!("rustos-partitioned-{}-{timestamp}", std::process::id());
    let esp_path = env::temp_dir().join(format!("{prefix}-esp.img"));
    let root_path = env::temp_dir().join(format!("{prefix}-root.img"));
    let result = (|| {
        let mut esp_builder = DiskImageBuilder::new(kernel.to_owned());
        esp_builder.set_file_contents("initrd.cpi".to_owned(), initramfs.to_vec());
        esp_builder.set_file_contents("rustos.st".to_owned(), PERSISTENT_STATE_CONTENT.to_vec());
        esp_builder.set_file_contents("rustos.rep".to_owned(), repository.to_vec());
        esp_builder
            .create_uefi_fat_partition(&esp_path)
            .map_err(|error| {
                format!(
                    "creating EFI system partition for {}: {error:#}",
                    output.display()
                )
            })?;

        let kernel_image = fs::read(kernel)
            .map_err(|error| format!("reading kernel for {}: {error}", output.display()))?;
        create_fat32_root_partition(
            &root_path,
            root_size,
            &[
                ("kernel-x86_64", kernel_image.as_slice()),
                ("initrd.cpi", initramfs),
                ("rustos.st", PERSISTENT_STATE_CONTENT),
                ("rustos.rep", repository),
            ],
        )?;
        create_gpt_disk_with_root(&esp_path, &root_path, output)
    })();
    let _ = fs::remove_file(&esp_path);
    let _ = fs::remove_file(&root_path);
    result
}

fn create_fat32_root_partition(
    path: &Path,
    root_size: u64,
    files: &[(&str, &[u8])],
) -> Result<(), String> {
    let disk = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("creating FAT32 root partition {}: {error}", path.display()))?;
    disk.set_len(root_size)
        .map_err(|error| format!("sizing FAT32 root partition {}: {error}", path.display()))?;
    fatfs::format_volume(
        &disk,
        fatfs::FormatVolumeOptions::new()
            .fat_type(fatfs::FatType::Fat32)
            .bytes_per_cluster(512)
            .volume_label(*b"RUSTOSROOT "),
    )
    .map_err(|error| {
        format!(
            "formatting FAT32 root partition {}: {error}",
            path.display()
        )
    })?;

    {
        let filesystem = fatfs::FileSystem::new(&disk, fatfs::FsOptions::new())
            .map_err(|error| format!("opening FAT32 root partition {}: {error}", path.display()))?;
        let root = filesystem.root_dir();
        for directory in ["bin", "sbin", "etc", "etc/rustos"] {
            root.create_dir(directory).map_err(|error| {
                format!(
                    "creating FAT32 root directory {directory} in {}: {error}",
                    path.display()
                )
            })?;
        }
        for (file_path, contents) in files.iter().copied() {
            let mut file = root.create_file(file_path).map_err(|error| {
                format!(
                    "creating FAT32 root file {file_path} in {}: {error}",
                    path.display()
                )
            })?;
            file.truncate().map_err(|error| {
                format!(
                    "truncating FAT32 root file {file_path} in {}: {error}",
                    path.display()
                )
            })?;
            file.write_all(contents).map_err(|error| {
                format!(
                    "writing FAT32 root file {file_path} in {}: {error}",
                    path.display()
                )
            })?;
        }
    }
    disk.sync_all()
        .map_err(|error| format!("syncing FAT32 root partition {}: {error}", path.display()))
}

#[derive(Debug, Clone, Copy)]
struct GptLayout {
    disk_size: u64,
    esp_start: u64,
    esp_size: u64,
    root_start: u64,
    root_size: u64,
}

fn create_gpt_disk_with_root(
    esp_path: &Path,
    root_path: &Path,
    output: &Path,
) -> Result<(), String> {
    let esp_size = fs::metadata(esp_path)
        .map_err(|error| {
            format!(
                "reading EFI system partition {}: {error}",
                esp_path.display()
            )
        })?
        .len();
    let root_size = fs::metadata(root_path)
        .map_err(|error| {
            format!(
                "reading RustOS root partition {}: {error}",
                root_path.display()
            )
        })?
        .len();
    let disk_size = esp_size
        .checked_add(root_size)
        .and_then(|size| size.checked_add(4 * 1024 * 1024))
        .ok_or_else(|| format!("GPT disk size overflow for {}", output.display()))?;

    let mut disk = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(output)
        .map_err(|error| format!("creating GPT disk {}: {error}", output.display()))?;
    disk.set_len(disk_size)
        .map_err(|error| format!("sizing GPT disk {}: {error}", output.display()))?;

    let layout = write_gpt_layout(&mut disk, disk_size, esp_path, root_path, output)?;
    disk.sync_all()
        .map_err(|error| format!("syncing GPT disk {}: {error}", output.display()))?;
    print_gpt_layout(output, layout);
    Ok(())
}

fn write_gpt_layout(
    disk: &mut std::fs::File,
    disk_size: u64,
    esp_path: &Path,
    root_path: &Path,
    output: &Path,
) -> Result<GptLayout, String> {
    let esp_size = fs::metadata(esp_path)
        .map_err(|error| {
            format!(
                "reading EFI system partition {}: {error}",
                esp_path.display()
            )
        })?
        .len();
    let root_size = fs::metadata(root_path)
        .map_err(|error| {
            format!(
                "reading RustOS root partition {}: {error}",
                root_path.display()
            )
        })?
        .len();
    let minimum_size = esp_size
        .checked_add(root_size)
        .and_then(|size| size.checked_add(4 * 1024 * 1024))
        .ok_or_else(|| format!("GPT disk size overflow for {}", output.display()))?;
    if disk_size < minimum_size || disk_size % 512 != 0 {
        return Err(format!(
            "GPT target {} is too small or not sector-aligned: capacity={} minimum={} ",
            output.display(),
            disk_size,
            minimum_size
        ));
    }

    let sector_count = disk_size / 512;
    let protective = gpt::mbr::ProtectiveMBR::with_lb_size(
        u32::try_from(sector_count.saturating_sub(1)).unwrap_or(u32::MAX),
    );
    protective
        .overwrite_lba0(disk)
        .map_err(|error| format!("writing GPT protective MBR {}: {error}", output.display()))?;

    let mut table = gpt::GptConfig::new()
        .writable(true)
        .initialized(false)
        .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
        .create_from_device(Box::new(&mut *disk), None)
        .map_err(|error| format!("creating GPT table {}: {error}", output.display()))?;
    table
        .update_partitions(BTreeMap::new())
        .map_err(|error| format!("initializing GPT table {}: {error}", output.display()))?;
    let esp_id = table
        .add_partition(
            "EFI System",
            esp_size,
            gpt::partition_types::EFI,
            0,
            Some(2048),
        )
        .map_err(|error| format!("adding EFI system partition {}: {error}", output.display()))?;
    let root_id = table
        .add_partition(
            "RustOS root",
            root_size,
            gpt::partition_types::LINUX_FS,
            0,
            Some(2048),
        )
        .map_err(|error| format!("adding RustOS root partition {}: {error}", output.display()))?;
    let block_size = gpt::disk::LogicalBlockSize::Lb512;
    let esp_start = table
        .partitions()
        .get(&esp_id)
        .ok_or_else(|| format!("EFI system partition disappeared from {}", output.display()))?
        .bytes_start(block_size)
        .map_err(|error| {
            format!(
                "locating EFI system partition {}: {error}",
                output.display()
            )
        })?;
    let root_start = table
        .partitions()
        .get(&root_id)
        .ok_or_else(|| {
            format!(
                "RustOS root partition disappeared from {}",
                output.display()
            )
        })?
        .bytes_start(block_size)
        .map_err(|error| {
            format!(
                "locating RustOS root partition {}: {error}",
                output.display()
            )
        })?;
    table
        .write_inplace()
        .map_err(|error| format!("writing GPT table {}: {error}", output.display()))?;
    drop(table);

    copy_partition(esp_path, disk, esp_start, output, "EFI system")?;
    copy_partition(root_path, disk, root_start, output, "RustOS root")?;
    Ok(GptLayout {
        disk_size,
        esp_start,
        esp_size,
        root_start,
        root_size,
    })
}

fn print_gpt_layout(output: &Path, layout: GptLayout) {
    println!(
        "installer layout: image={} esp_start={} esp_bytes={} root_start={} root_bytes={} disk_bytes={} table=gpt verification=ready",
        output.display(),
        layout.esp_start / 512,
        layout.esp_size,
        layout.root_start / 512,
        layout.root_size,
        layout.disk_size,
    );
}

fn copy_partition(
    source: &Path,
    disk: &mut std::fs::File,
    start: u64,
    output: &Path,
    label: &str,
) -> Result<(), String> {
    let mut source_file = OpenOptions::new()
        .read(true)
        .open(source)
        .map_err(|error| format!("opening {label} partition {}: {error}", source.display()))?;
    disk.seek(SeekFrom::Start(start))
        .map_err(|error| format!("seeking {label} partition in {}: {error}", output.display()))?;
    std::io::copy(&mut source_file, disk).map_err(|error| {
        format!(
            "copying {label} partition into {}: {error}",
            output.display()
        )
    })?;
    Ok(())
}

fn nvidia_gsp_check(path: &Path) -> Result<(), String> {
    let firmware = read_firmware_blob(path)?;
    let descriptor = GspFirmware::parse(&firmware)
        .map_err(|error| format!("parsing NVIDIA GSP firmware {}: {error:?}", path.display()))?;
    let layout = descriptor
        .boot_layout()
        .map_err(|error| format!("planning NVIDIA GSP boot layout: {error:?}"))?;
    let image_page_addresses: Vec<u64> = (0..layout.radix3.image_pages)
        .map(|index| {
            0x1000_0000_0000u64
                .checked_add((index as u64) * rustos_gpu_protocol::NVIDIA_GSP_PAGE_SIZE as u64)
                .ok_or_else(|| "GSP image page address overflow".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let level2_page_addresses: Vec<u64> = (0..layout.radix3.level2_pages)
        .map(|index| {
            0x2000_0000_0000u64
                .checked_add((index as u64) * rustos_gpu_protocol::NVIDIA_GSP_PAGE_SIZE as u64)
                .ok_or_else(|| "GSP radix-3 level-2 address overflow".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let radix3 = layout
        .radix3
        .materialize(
            0x2000_1000_0000,
            0x2000_1000_1000,
            &level2_page_addresses,
            &image_page_addresses,
        )
        .map_err(|error| format!("materializing GSP radix-3 tables: {error:?}"))?;
    let shared_page_addresses: Vec<u64> = (0..layout.shared_memory.page_table_entry_count)
        .map(|index| {
            0x3000_0000_0000u64
                .checked_add((index as u64) * rustos_gpu_protocol::NVIDIA_GSP_PAGE_SIZE as u64)
                .ok_or_else(|| "GSP shared-memory page address overflow".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let shared_memory = layout
        .shared_memory
        .materialize(&shared_page_addresses)
        .map_err(|error| format!("materializing GSP shared memory: {error:?}"))?;
    let cached_arguments =
        GspCachedArguments::r570(shared_memory.page_table_address, layout.shared_memory)
            .map_err(|error| format!("encoding GSP cached arguments: {error:?}"))?
            .encode();
    let command = encode_gsp_rpc(0, 1, &[])
        .map_err(|error| format!("encoding GSP RPC smoke command: {error:?}"))?;
    let message = GspRpcMessage::parse(&command)
        .map_err(|error| format!("parsing GSP RPC smoke command: {error:?}"))?;
    println!(
        "nvidia-gsp: path={} bytes={} image_offset=0x{:x} image_bytes={} image_pages={} version={} gb20x_signature={} signature_bytes={} radix3_bytes={} radix3_level2_pages={} radix3_tables={} shared_bytes={} shared_ptes={} queue_entries={} queue_header_bytes={} cached_args_bytes={} rpc_pages={} checksum={} status=ready",
        path.display(),
        firmware.len(),
        descriptor.image.offset,
        descriptor.image.size,
        layout.radix3.image_pages,
        String::from_utf8_lossy(descriptor.version_bytes(&firmware)),
        descriptor.supports_gb20x(),
        layout.signature.size,
        layout.radix3.total_bytes,
        layout.radix3.level2_pages,
        radix3.level0.len() + radix3.level1.len() + radix3.level2.len()
            == layout.radix3.total_bytes,
        layout.shared_memory.total_bytes,
        layout.shared_memory.page_table_entry_count,
        layout.shared_memory.queue_entry_count,
        rustos_gpu_protocol::NVIDIA_GSP_QUEUE_HEADER_SIZE,
        cached_arguments.len(),
        message.element_count(),
        message.checksum_valid()
    );
    Ok(())
}

fn nvidia_fmc_check(path: &Path) -> Result<(), String> {
    let firmware = read_firmware_blob(path)?;
    let descriptor = GspFmc::parse(&firmware)
        .map_err(|error| format!("parsing NVIDIA GSP-FMC {}: {error:?}", path.display()))?;
    println!(
        "nvidia-fmc: path={} bytes={} sections={} hash_bytes={} signature_bytes={} public_key_bytes={} image_bytes={} crc=true status=ready",
        path.display(),
        firmware.len(),
        descriptor.section_count,
        descriptor.hash.size,
        descriptor.signature.size,
        descriptor.public_key.size,
        descriptor.image.size,
    );
    Ok(())
}

fn nvidia_gsp_bundle_check(
    expected_version: &[u8],
    gsp_path: &Path,
    fmc_path: &Path,
    bootloader_path: &Path,
) -> Result<(), String> {
    let gsp = read_firmware_blob(gsp_path)?;
    let fmc = read_firmware_blob(fmc_path)?;
    let bootloader = read_firmware_blob(bootloader_path)?;
    let bundle = GspFirmwareBundle::parse(&gsp, &fmc, &bootloader, expected_version)
        .map_err(|error| format!("parsing NVIDIA GSP bundle: {error:?}"))?;
    let layout = bundle
        .gsp
        .boot_layout()
        .map_err(|error| format!("planning NVIDIA GSP bundle layout: {error:?}"))?;
    let staging = GspBootSystemMemoryPlan::r570_gb20x(bundle, 0x1000_0000)
        .map_err(|error| format!("planning NVIDIA GSP system memory staging: {error:?}"))?;
    let framebuffer = GspFramebufferLayout::r570_gb20x(
        16 * (1u64 << 30),
        16 * (1u64 << 30) - 0x20_000,
        staging.gsp_image_bytes,
        staging.bootloader_bytes,
    )
    .map_err(|error| format!("planning NVIDIA GSP framebuffer WPR: {error:?}"))?;
    let mut staged_memory = vec![0u8; staging.total_bytes];
    staging
        .materialize_bundle_into(
            bundle,
            &gsp,
            &fmc,
            &bootloader,
            framebuffer,
            &mut staged_memory,
        )
        .map_err(|error| format!("materializing NVIDIA GSP system image: {error:?}"))?;
    let staged_nonzero_bytes = staged_memory.iter().filter(|byte| **byte != 0).count();
    let radix3 = staging
        .radix3_tables()
        .map_err(|error| format!("materializing NVIDIA GSP staged radix-3 tables: {error:?}"))?;
    let shared_memory = staging
        .shared_memory_image()
        .map_err(|error| format!("materializing NVIDIA GSP staged shared memory: {error:?}"))?;
    let cached_arguments = staging
        .cached_arguments()
        .map_err(|error| format!("encoding NVIDIA GSP staged cached arguments: {error:?}"))?;
    let fmc_boot_params = staging.fmc_boot_params();
    let cot = GspFspCot::gb20x(
        0x2000_0000,
        0x1000_0000,
        0x0040_0000,
        0x0010_0000,
        bundle.fmc.hash.bytes(&fmc),
        bundle.fmc.public_key.bytes(&fmc),
        bundle.fmc.signature.bytes(&fmc),
    )
    .encode()
    .map_err(|error| format!("encoding NVIDIA GSP-FMC COT request: {error:?}"))?;
    println!(
        "nvidia-gsp-bundle: version={} gsp_bytes={} gsp_image_bytes={} gsp_image_pages={} fmc_bytes={} fmc_image_bytes={} bootloader_bytes={} bootloader_payload_bytes={} descriptor_version={} descriptor_app_version={} radix3_bytes={} staged_system_base=0x{:x} staged_system_bytes={} staged_system_end=0x{:x} staged_nonzero_bytes={} staged_radix3_bytes={} staged_shared_bytes={} staged_cached_args_bytes={} staged_fmc_args_bytes={} fsp_cot_bytes={} fsp_cot_version={} fsp_hash_bytes={} fsp_public_key_bytes={} fsp_signature_bytes={} status=ready",
        String::from_utf8_lossy(expected_version),
        gsp.len(),
        bundle.gsp.image.size,
        layout.radix3.image_pages,
        fmc.len(),
        bundle.fmc.image.size,
        bootloader.len(),
        bundle.bootloader.payload.size,
        bundle.bootloader.descriptor.version,
        bundle.bootloader.descriptor.app_version,
        layout.radix3.total_bytes,
        staging.fmc_image.address,
        staging.total_bytes,
        staging.end_address,
        staged_nonzero_bytes,
        radix3.level0.len() + radix3.level1.len() + radix3.level2.len(),
        shared_memory.page_table.len()
            + shared_memory.command_queue.len()
            + shared_memory.status_queue.len(),
        cached_arguments.len(),
        fmc_boot_params.len(),
        cot.len(),
        rustos_gpu_protocol::NVIDIA_GSP_FSP_COT_VERSION_GB20X,
        bundle.fmc.hash.size,
        bundle.fmc.public_key.size,
        bundle.fmc.signature.size,
    );
    Ok(())
}

fn read_firmware_blob(path: &Path) -> Result<Vec<u8>, String> {
    let resolved = fs::canonicalize(path)
        .map_err(|error| format!("resolving firmware {}: {error}", path.display()))?;
    if path.extension().is_some_and(|extension| extension == "zst") {
        let output = Command::new("zstd")
            .args(["--quiet", "--decompress", "--stdout"])
            .arg(&resolved)
            .output()
            .map_err(|error| format!("running zstd for {}: {error}", path.display()))?;
        if !output.status.success() {
            return Err(format!(
                "decompressing {} failed: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        return Ok(output.stdout);
    }
    fs::read(&resolved).map_err(|error| format!("reading firmware {}: {error}", path.display()))
}

fn check() -> Result<(), String> {
    let root = workspace_root();
    let mut host_check = Command::new(cargo_binary());
    host_check.current_dir(&root).args(["check", "--workspace"]);
    run_command(&mut host_check, "checking the workspace")?;

    let mut userland_check = Command::new(cargo_binary());
    userland_check.current_dir(&root).args([
        "check",
        "-p",
        "rustos-userland",
        "--target",
        TARGET,
        "--bins",
    ]);
    run_command(&mut userland_check, "checking the Rust userland target")?;

    let mut target_check = Command::new(cargo_binary());
    target_check
        .current_dir(&root)
        .args(["check", "-p", "rustos-kernel", "--target", TARGET]);
    run_command(&mut target_check, "checking the kernel target")
}

fn build_userland(root: &PathBuf, _release: bool) -> Result<Vec<PathBuf>, String> {
    let linker = root.join("userland/user.ld");
    let mut artifacts = Vec::with_capacity(USERLAND_BINARIES.len());
    for binary in USERLAND_BINARIES {
        let mut command = Command::new(cargo_binary());
        command.current_dir(root).args([
            "rustc",
            "-p",
            "rustos-userland",
            "--bin",
            binary,
            "--target",
            TARGET,
        ]);
        // Userland images are always optimized and stripped of debug metadata so the FAT catalog
        // carries runnable binaries rather than development symbols. The kernel image still
        // follows the caller's debug/release choice.
        command.arg("--release");
        command.env(
            "RUSTFLAGS",
            "-C code-model=large -C relocation-model=static -C debuginfo=0 -C lto=off",
        );
        command.args([
            "--",
            "-C",
            "debuginfo=0",
            "-C",
            "lto=off",
            "-C",
            "link-arg=-z",
            "-C",
            "link-arg=max-page-size=0x1000",
        ]);
        command
            .arg("-C")
            .arg(format!("link-arg=-T{}", linker.display()));
        run_command(&mut command, &format!("building Rust userland `{binary}`"))?;
        let artifact = userland_path(root, true, binary);
        if !artifact.is_file() {
            return Err(format!(
                "Rust userland artifact was not created: {}",
                artifact.display()
            ));
        }
        let mut strip = Command::new("llvm-objcopy");
        strip.args(["--strip-all"]).arg(&artifact);
        run_command(&mut strip, &format!("stripping Rust userland `{binary}`"))?;
        artifacts.push(artifact);
    }
    Ok(artifacts)
}

fn userland_path(root: &PathBuf, release: bool, binary: &str) -> PathBuf {
    target_dir(root)
        .join(TARGET)
        .join(if release { "release" } else { "debug" })
        .join(binary)
}

fn read_userland_image(artifacts: &[PathBuf], binary: &str) -> Result<Vec<u8>, String> {
    let index = USERLAND_BINARIES
        .iter()
        .position(|candidate| *candidate == binary)
        .ok_or_else(|| format!("unknown Rust userland binary `{binary}`"))?;
    fs::read(&artifacts[index])
        .map_err(|error| format!("reading Rust userland `{binary}`: {error}"))
}

fn build_initramfs(entries: &[(&str, &[u8], u32)]) -> Result<Vec<u8>, String> {
    const MAX_ARCHIVE_SIZE: usize = 512 * 1024;

    let mut archive = Vec::new();
    for (path, data, mode) in entries.iter().copied() {
        let name = path.as_bytes();
        validate_initramfs_path(name)?;
        append_newc_record(&mut archive, name, data, mode, 1)?;
    }
    append_newc_record(&mut archive, b"TRAILER!!!", &[], 0, 1)?;
    if archive.len() > MAX_ARCHIVE_SIZE {
        return Err(format!(
            "initramfs exceeds {} bytes: {}",
            MAX_ARCHIVE_SIZE,
            archive.len()
        ));
    }
    Ok(archive)
}

fn build_repository() -> Vec<u8> {
    const BASE_ID: [u8; 8] = *b"BASE0001";
    const HELLO_V1_ID: [u8; 8] = *b"APP00001";
    const HELLO_V2_ID: [u8; 8] = *b"APP00002";
    const HELLO_V3_ID: [u8; 8] = *b"APP00003";

    struct RepositoryPackage<'a> {
        name: &'a [u8],
        id: [u8; 8],
        version: u32,
        dependencies: [[u8; 8]; 2],
        dependency_count: usize,
        bytes: &'a [u8],
    }

    let base = build_package(&BASE_ID, b"/USR/LOCAL/BASE.TXT", b"RustOS base package\n");
    let hello_v1 = build_package(
        &HELLO_V1_ID,
        b"/USR/LOCAL/HELLO.TXT",
        b"RustOS package repository v1\n",
    );
    let hello_v2 = build_package(
        &HELLO_V2_ID,
        b"/USR/LOCAL/HELLO.TXT",
        b"RustOS package repository v2\n",
    );
    let hello_v3 = build_package(
        &HELLO_V3_ID,
        b"/USR/LOCAL/HELLO.TXT",
        b"RustOS package repository v3\n",
    );
    let packages = [
        RepositoryPackage {
            name: b"BASE",
            id: BASE_ID,
            version: 1,
            dependencies: [[0; 8]; 2],
            dependency_count: 0,
            bytes: &base,
        },
        RepositoryPackage {
            name: b"HELLO",
            id: HELLO_V1_ID,
            version: 1,
            dependencies: [BASE_ID, [0; 8]],
            dependency_count: 1,
            bytes: &hello_v1,
        },
        RepositoryPackage {
            name: b"HELLO",
            id: HELLO_V2_ID,
            version: 2,
            dependencies: [BASE_ID, [0; 8]],
            dependency_count: 1,
            bytes: &hello_v2,
        },
        RepositoryPackage {
            name: b"HELLO",
            id: HELLO_V3_ID,
            version: 3,
            dependencies: [BASE_ID, [0; 8]],
            dependency_count: 1,
            bytes: &hello_v3,
        },
    ];

    let root_signing_key = SigningKey::from_bytes(&REPOSITORY_ROOT_SIGNING_KEY_BYTES);
    let rotated_signing_key = SigningKey::from_bytes(&REPOSITORY_ROTATED_SIGNING_KEY_BYTES);
    let rotated_public_key = rotated_signing_key.verifying_key().to_bytes();
    let rotation_signature = root_signing_key.sign(&key_rotation_message(
        &REPOSITORY_ROTATED_KEY_ID,
        &rotated_public_key,
    ));

    let mut repository = Vec::with_capacity(16 * 1024);
    repository.extend_from_slice(b"RREP3");
    repository.push(3);
    repository.push(packages.len() as u8);
    repository.push(REPOSITORY_ROTATION_FLAG);
    repository.extend_from_slice(&REPOSITORY_ROTATED_KEY_ID);
    repository.extend_from_slice(&rotated_public_key);
    repository.extend_from_slice(&rotation_signature.to_bytes());
    repository.resize(
        REPOSITORY_HEADER_LENGTH
            + REPOSITORY_ROTATION_MATERIAL_LENGTH
            + packages.len() * REPOSITORY_ENTRY_LENGTH,
        0,
    );
    for (index, package) in packages.iter().enumerate() {
        let package_start = repository.len();
        repository.extend_from_slice(package.bytes);
        let package_digest = sha256(package.bytes);
        let entry_start = REPOSITORY_HEADER_LENGTH
            + REPOSITORY_ROTATION_MATERIAL_LENGTH
            + index * REPOSITORY_ENTRY_LENGTH;
        repository[entry_start..entry_start + 8].copy_from_slice(&package.id);
        repository[entry_start + 8] = package.name.len() as u8;
        repository[entry_start + 9] = package.dependency_count as u8;
        repository[entry_start + 10..entry_start + 14]
            .copy_from_slice(&package.version.to_le_bytes());
        repository[entry_start + 14..entry_start + 14 + package.name.len()]
            .copy_from_slice(package.name);
        for dependency_index in 0..2 {
            let dependency_start = entry_start + 26 + dependency_index * 8;
            repository[dependency_start..dependency_start + 8]
                .copy_from_slice(&package.dependencies[dependency_index]);
        }
        repository[entry_start + 42..entry_start + 46]
            .copy_from_slice(&(package_start as u32).to_le_bytes());
        repository[entry_start + 46..entry_start + 50]
            .copy_from_slice(&(package.bytes.len() as u32).to_le_bytes());
        repository[entry_start + 50..entry_start + 82].copy_from_slice(&package_digest);
    }
    let signature = rotated_signing_key.sign(&repository);
    repository.extend_from_slice(&signature.to_bytes());
    repository
}

fn key_rotation_message(key_id: &[u8; 8], public_key: &[u8; 32]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(REPOSITORY_KEY_ROTATION_DOMAIN.len() + key_id.len() + public_key.len());
    message.extend_from_slice(REPOSITORY_KEY_ROTATION_DOMAIN);
    message.extend_from_slice(key_id);
    message.extend_from_slice(public_key);
    message
}

fn build_package(package_id: &[u8; 8], file_path: &[u8], file_data: &[u8]) -> Vec<u8> {
    let mut package = Vec::with_capacity(16 + 10 + file_path.len() + file_data.len());
    package.extend_from_slice(b"RPKG1");
    package.push(1);
    package.push(1);
    package.push(0);
    package.extend_from_slice(package_id);
    package.push(file_path.len() as u8);
    package.push(0);
    package.extend_from_slice(&(file_data.len() as u32).to_le_bytes());
    package.extend_from_slice(&crc32(file_data).to_le_bytes());
    package.extend_from_slice(file_path);
    package.extend_from_slice(file_data);
    package
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes.iter().copied() {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn append_newc_record(
    archive: &mut Vec<u8>,
    name: &[u8],
    data: &[u8],
    mode: u32,
    links: u32,
) -> Result<(), String> {
    let name_size = name
        .len()
        .checked_add(1)
        .ok_or_else(|| "initramfs name length overflowed".to_owned())?;
    let data_size = u32::try_from(data.len())
        .map_err(|_| "initramfs file is larger than the newc size field".to_owned())?;
    let name_size = u32::try_from(name_size)
        .map_err(|_| "initramfs name is larger than the newc size field".to_owned())?;
    let mut header = [b'0'; 110];
    header[..6].copy_from_slice(b"070701");
    write_newc_hex(&mut header, 6, 1);
    write_newc_hex(&mut header, 14, mode);
    write_newc_hex(&mut header, 22, 0);
    write_newc_hex(&mut header, 30, 0);
    write_newc_hex(&mut header, 38, links);
    write_newc_hex(&mut header, 46, 0);
    write_newc_hex(&mut header, 54, data_size);
    write_newc_hex(&mut header, 62, 0);
    write_newc_hex(&mut header, 70, 0);
    write_newc_hex(&mut header, 78, 0);
    write_newc_hex(&mut header, 86, 0);
    write_newc_hex(&mut header, 94, name_size);
    write_newc_hex(&mut header, 102, 0);

    archive.extend_from_slice(&header);
    archive.extend_from_slice(name);
    archive.push(0);
    pad_to_four(archive);
    archive.extend_from_slice(data);
    pad_to_four(archive);
    Ok(())
}

fn write_newc_hex(header: &mut [u8; 110], offset: usize, value: u32) {
    for index in 0..8 {
        let shift = (7 - index) * 4;
        let digit = ((value >> shift) & 0xf) as u8;
        header[offset + index] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
    }
}

fn pad_to_four(bytes: &mut Vec<u8>) {
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
}

fn validate_initramfs_path(path: &[u8]) -> Result<(), String> {
    if path.is_empty() || path.len() > 63 || path[0] == b'/' {
        return Err(format!(
            "invalid initramfs path `{}`",
            String::from_utf8_lossy(path)
        ));
    }
    let mut component_start = 0;
    for index in 0..=path.len() {
        if index != path.len() && path[index] != b'/' {
            continue;
        }
        let component = &path[component_start..index];
        if component.is_empty() || component == b"." || component == b".." {
            return Err(format!(
                "invalid initramfs path `{}`",
                String::from_utf8_lossy(path)
            ));
        }
        if component.iter().any(|byte| !(0x21..=0x7e).contains(byte)) {
            return Err(format!(
                "invalid initramfs path `{}`",
                String::from_utf8_lossy(path)
            ));
        }
        component_start = index + 1;
    }
    Ok(())
}

fn run(
    firmware: &str,
    release: bool,
    smp: u32,
    mode: ImageMode,
    network: bool,
    partitioned: bool,
    msi: bool,
    ahci: bool,
    nvme: bool,
    usb: bool,
    usb_mouse: bool,
    usb_both: bool,
    usb_hub: bool,
    usb_hotplug: bool,
    usb_legacy: bool,
    usb_nested: bool,
    usb_nested_hotplug: bool,
    keyboard_proof: bool,
    shell_proof: bool,
    pipe_proof: bool,
    desktop_proof: bool,
    terminal_proof: bool,
    account_proof: bool,
    logout_proof: bool,
    role_proof: bool,
    virtio_gpu_proof: bool,
    poweroff_proof: bool,
    reboot_proof: bool,
    suspend_proof: bool,
    native_suspend_proof: bool,
    audio_proof: bool,
    hda_audio_proof: bool,
    virtio_network_proof: bool,
    nvme_interrupt_proof: bool,
    ahci_interrupt_proof: bool,
    vm_proof: bool,
    smp_proof: bool,
    image_override: Option<PathBuf>,
) -> Result<(), String> {
    let root = workspace_root();
    let image = image_override.unwrap_or_else(|| {
        target_dir(&root).join("images").join(if partitioned {
            partitioned_image_name(firmware, release, mode)
        } else {
            image_name(firmware, release, mode)
        })
    });
    if !image.is_file() {
        return Err(format!("image does not exist: {}", image.display()));
    }
    let any_audio_proof = audio_proof || hda_audio_proof;
    let serial_path = (suspend_proof
        || any_audio_proof
        || virtio_network_proof
        || nvme_interrupt_proof
        || ahci_interrupt_proof
        || vm_proof
        || smp_proof
        || shell_proof
        || pipe_proof
        || virtio_gpu_proof
        || terminal_proof
        || desktop_proof
        || account_proof
        || logout_proof
        || role_proof
        || (mode == ImageMode::Shell && keyboard_proof))
        .then(|| {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            env::temp_dir().join(format!(
                "rustos-proof-{}-{timestamp}.serial.log",
                std::process::id()
            ))
        });
    let wav_path = any_audio_proof.then(|| {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        env::temp_dir().join(format!(
            "rustos-proof-{}-{timestamp}.wav",
            std::process::id()
        ))
    });
    let qemu_binary = env::var_os("RUSTOS_QEMU").unwrap_or_else(|| "qemu-system-x86_64".into());
    if virtio_gpu_proof && !qemu_supports_virtio_gpu(&qemu_binary) {
        return Err(
            "QEMU does not expose virtio-gpu-pci; install qemu-hw-display-virtio-gpu and qemu-hw-display-virtio-gpu-pci or set QEMU_MODULE_DIR".to_owned(),
        );
    }
    let mut qemu = Command::new(qemu_binary);
    if msi
        || ahci
        || nvme
        || usb
        || usb_mouse
        || usb_both
        || usb_hub
        || usb_hotplug
        || usb_legacy
        || usb_nested
        || usb_nested_hotplug
        || poweroff_proof
        || reboot_proof
        || suspend_proof
        || any_audio_proof
        || virtio_network_proof
        || nvme_interrupt_proof
        || ahci_interrupt_proof
        || vm_proof
        || virtio_gpu_proof
    {
        qemu.args(["-M", "q35"]);
    }
    qemu.args(["-display", "none", "-no-reboot"]);
    if shell_proof || pipe_proof {
        qemu.args(["-net", "none"]);
    }
    if !poweroff_proof && !reboot_proof && !suspend_proof && !any_audio_proof {
        qemu.arg("-no-shutdown");
    }
    qemu.args(["-smp"]).arg(smp.to_string());
    if let Some(path) = serial_path.as_ref() {
        qemu.args(["-serial"])
            .arg(format!("file:{}", path.display()));
    } else {
        qemu.args(["-serial", "stdio"]);
    }
    if nvme {
        qemu.args(["-drive"])
            .arg(format!(
                "format=raw,if=none,id=rustosdisk,file={}",
                image.display()
            ))
            .args(["-device", "nvme,drive=rustosdisk,serial=RUSTOSNVME"]);
    } else {
        qemu.args(["-drive"])
            .arg(format!("format=raw,if=ide,file={}", image.display()));
    }
    if virtio_gpu_proof {
        qemu.args(["-device", "virtio-gpu-pci"]);
    }
    if let Some(path) = wav_path.as_ref() {
        qemu.args(["-audiodev"]).arg(format!(
            "driver=wav,id=rustos_audio,out.frequency=48000,path={}",
            path.display()
        ));
        if hda_audio_proof {
            qemu.args([
                "-device",
                "ich9-intel-hda",
                "-device",
                "hda-output,audiodev=rustos_audio",
            ]);
        } else {
            qemu.args(["-device", "AC97,audiodev=rustos_audio"]);
        }
    }
    if usb {
        qemu.args(["-device", "qemu-xhci", "-device", "usb-kbd"]);
    } else if usb_legacy {
        qemu.args([
            "-device",
            "qemu-xhci,id=xhci,msix=off,msi=off",
            "-device",
            "usb-kbd",
        ]);
    } else if usb_mouse {
        qemu.args(["-device", "qemu-xhci", "-device", "usb-mouse"]);
    } else if usb_both {
        qemu.args([
            "-device",
            "qemu-xhci",
            "-device",
            "usb-kbd",
            "-device",
            "usb-mouse",
        ]);
    } else if usb_nested {
        qemu.args([
            "-device",
            "qemu-xhci,id=xhci",
            "-device",
            "usb-hub,bus=xhci.0,port=1,id=hub",
            "-device",
            "usb-hub,bus=xhci.0,port=1.1,id=nested",
            "-device",
            "usb-kbd,bus=xhci.0,port=1.1.1",
            "-device",
            "usb-mouse,bus=xhci.0,port=1.1.2",
        ]);
    } else if usb_nested_hotplug {
        qemu.args([
            "-device",
            "qemu-xhci,id=xhci",
            "-device",
            "usb-hub,bus=xhci.0,port=1,id=hub",
            "-device",
            "usb-hub,bus=xhci.0,port=1.1,id=nested",
            "-device",
            "usb-kbd,bus=xhci.0,port=1.1.1",
        ]);
    } else if usb_hub {
        qemu.args([
            "-device",
            "qemu-xhci,id=xhci",
            "-device",
            "usb-hub,bus=xhci.0,port=1,id=hub",
            "-device",
            "usb-kbd,bus=xhci.0,port=1.1",
            "-device",
            "usb-mouse,bus=xhci.0,port=1.2",
        ]);
    } else if usb_hotplug {
        qemu.args([
            "-device",
            "qemu-xhci,id=xhci",
            "-device",
            "usb-hub,bus=xhci.0,port=1,id=hub",
            "-device",
            "usb-kbd,bus=xhci.0,port=1.1",
        ]);
    }
    let monitor_path = (keyboard_proof
        || shell_proof
        || desktop_proof
        || poweroff_proof
        || reboot_proof
        || suspend_proof
        || any_audio_proof
        || virtio_network_proof
        || nvme_interrupt_proof
        || ahci_interrupt_proof
        || vm_proof
        || smp_proof
        || pipe_proof
        || virtio_gpu_proof
        || terminal_proof
        || account_proof
        || logout_proof
        || role_proof)
        .then(|| {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            env::temp_dir().join(format!(
                "rustos-proof-{}-{timestamp}.sock",
                std::process::id()
            ))
        });
    if let Some(path) = monitor_path.as_ref() {
        qemu.arg("-monitor")
            .arg(format!("unix:{},server=on,wait=off", path.display()));
    }
    let screenshot_path = monitor_path.as_ref().map(|path| path.with_extension("ppm"));
    let server = if virtio_network_proof {
        qemu.args([
            "-netdev",
            "user,id=rustosnet,net=10.0.2.0/24,dhcpstart=10.0.2.15",
            "-device",
            "virtio-net-pci,disable-legacy=on,netdev=rustosnet",
        ]);
        if firmware == "bios" {
            qemu.args([
                "-netdev",
                "user,id=rustose1000,net=10.0.2.0/24,dhcpstart=10.0.2.15",
                "-device",
                "e1000e,netdev=rustose1000",
            ]);
        }
        Some(RepositoryServer::start()?)
    } else if network {
        let device = if msi {
            "e1000e,netdev=rustosnet"
        } else {
            "e1000,netdev=rustosnet"
        };
        qemu.args([
            "-netdev",
            "user,id=rustosnet,net=10.0.2.0/24,dhcpstart=10.0.2.15",
            "-device",
            device,
        ]);
        Some(RepositoryServer::start()?)
    } else {
        if msi {
            qemu.args(["-device", "e1000e"]);
        }
        None
    };
    match firmware {
        "bios" => {}
        "uefi" => {
            let ovmf = ovmf_path()?;
            qemu.arg("-bios").arg(ovmf);
        }
        _ => return Err("QEMU execution supports `bios` and `uefi`".to_owned()),
    }
    let suspend_state = suspend_proof.then(|| Arc::new(AtomicUsize::new(0)));
    let proof_thread =
        monitor_path
            .as_ref()
            .zip(screenshot_path.as_ref())
            .map(|(path, screenshot)| {
                if reboot_proof {
                    spawn_reboot_proof(path.clone(), screenshot.clone())
                } else if poweroff_proof {
                    spawn_poweroff_proof(path.clone(), screenshot.clone())
                } else if suspend_proof {
                    spawn_suspend_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("suspend proof serial path exists")
                            .clone(),
                        suspend_state
                            .as_ref()
                            .expect("suspend state exists")
                            .clone(),
                        native_suspend_proof,
                    )
                } else if audio_proof {
                    spawn_audio_proof(
                        path.clone(),
                        serial_path
                            .as_ref()
                            .expect("audio proof serial path exists")
                            .clone(),
                        "ac97",
                    )
                } else if hda_audio_proof {
                    spawn_audio_proof(
                        path.clone(),
                        serial_path
                            .as_ref()
                            .expect("HDA audio proof serial path exists")
                            .clone(),
                        "hda",
                    )
                } else if virtio_network_proof {
                    spawn_virtio_network_proof(
                        path.clone(),
                        serial_path
                            .as_ref()
                            .expect("virtio network proof serial path exists")
                            .clone(),
                        firmware == "bios",
                    )
                } else if nvme_interrupt_proof {
                    spawn_nvme_interrupt_proof(
                        path.clone(),
                        serial_path
                            .as_ref()
                            .expect("NVMe interrupt proof serial path exists")
                            .clone(),
                    )
                } else if ahci_interrupt_proof {
                    spawn_ahci_interrupt_proof(
                        path.clone(),
                        serial_path
                            .as_ref()
                            .expect("AHCI interrupt proof serial path exists")
                            .clone(),
                    )
                } else if vm_proof {
                    spawn_vm_proof(
                        path.clone(),
                        serial_path
                            .as_ref()
                            .expect("VM proof serial path exists")
                            .clone(),
                    )
                } else if smp_proof {
                    spawn_smp_proof(
                        path.clone(),
                        serial_path
                            .as_ref()
                            .expect("SMP proof serial path exists")
                            .clone(),
                    )
                } else if shell_proof {
                    spawn_shell_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("shell proof serial path exists")
                            .clone(),
                    )
                } else if pipe_proof {
                    spawn_pipe_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("pipe proof serial path exists")
                            .clone(),
                    )
                } else if virtio_gpu_proof {
                    spawn_virtio_gpu_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("virtio GPU proof serial path exists")
                            .clone(),
                    )
                } else if account_proof {
                    spawn_account_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("account proof serial path exists")
                            .clone(),
                    )
                } else if logout_proof {
                    spawn_logout_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("logout proof serial path exists")
                            .clone(),
                        firmware == "uefi",
                    )
                } else if role_proof {
                    spawn_role_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("role proof serial path exists")
                            .clone(),
                    )
                } else if terminal_proof {
                    spawn_terminal_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("terminal proof serial path exists")
                            .clone(),
                    )
                } else if usb_nested_hotplug {
                    spawn_usb_hotplug_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("USB nested hotplug proof serial path exists")
                            .clone(),
                        true,
                    )
                } else if usb_hotplug {
                    spawn_usb_hotplug_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("USB hotplug proof serial path exists")
                            .clone(),
                        false,
                    )
                } else if desktop_proof {
                    spawn_desktop_proof(
                        path.clone(),
                        screenshot.clone(),
                        serial_path
                            .as_ref()
                            .expect("desktop proof serial path exists")
                            .clone(),
                    )
                } else if mode == ImageMode::Shell {
                    spawn_keyboard_proof(path.clone(), screenshot.clone(), serial_path.clone())
                } else {
                    spawn_keyboard_proof(path.clone(), screenshot.clone(), None)
                }
            });
    let mut result = run_command(&mut qemu, &format!("running the {firmware} image in QEMU"));
    if suspend_proof
        || any_audio_proof
        || virtio_network_proof
        || nvme_interrupt_proof
        || ahci_interrupt_proof
        || vm_proof
        || smp_proof
        || shell_proof
        || pipe_proof
        || virtio_gpu_proof
        || terminal_proof
        || account_proof
        || logout_proof
        || role_proof
        || desktop_proof
    {
        if let Some(proof_thread) = proof_thread {
            let _ = proof_thread.join();
        }
    } else {
        drop(proof_thread);
    }
    if let Some(path) = monitor_path {
        let _ = fs::remove_file(path);
    }
    if let Some(path) = screenshot_path.as_ref().filter(|path| path.is_file()) {
        println!("proof screenshot: {}", path.display());
    }
    if let Some(path) = serial_path.as_ref().filter(|path| path.is_file()) {
        println!("proof serial: {}", path.display());
    }
    if let Some(path) = wav_path.as_ref().filter(|path| path.is_file()) {
        println!("proof wav: {}", path.display());
    }
    if let Some(server) = server {
        server.stop()?;
    }
    if result.is_ok() && any_audio_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "audio proof serial path was not created".to_owned())?;
        let wav = wav_path
            .as_deref()
            .ok_or_else(|| "audio proof WAV path was not created".to_owned())?;
        let controller = if hda_audio_proof { "hda" } else { "ac97" };
        if let Err(error) = verify_audio_proof(serial, wav, controller) {
            result = Err(error);
        }
    }
    if result.is_ok() && virtio_network_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "virtio network proof serial path was not created".to_owned())?;
        if let Err(error) = verify_virtio_network_proof(serial, firmware == "bios") {
            result = Err(error);
        }
    }
    if result.is_ok() && nvme_interrupt_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "NVMe interrupt proof serial path was not created".to_owned())?;
        if let Err(error) = verify_nvme_interrupt_proof(serial) {
            result = Err(error);
        }
    }
    if result.is_ok() && ahci_interrupt_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "AHCI interrupt proof serial path was not created".to_owned())?;
        if let Err(error) = verify_ahci_interrupt_proof(serial) {
            result = Err(error);
        }
    }
    if result.is_ok() && vm_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "VM proof serial path was not created".to_owned())?;
        if let Err(error) = verify_vm_proof(serial) {
            result = Err(error);
        }
    }
    if result.is_ok() && smp_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "SMP proof serial path was not created".to_owned())?;
        if let Err(error) = verify_smp_proof(serial) {
            result = Err(error);
        }
    }
    if result.is_ok() && shell_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "shell proof serial path was not created".to_owned())?;
        let screenshot = screenshot_path
            .as_deref()
            .ok_or_else(|| "shell proof screenshot path was not created".to_owned())?;
        if let Err(error) = verify_shell_proof(serial, screenshot) {
            result = Err(error);
        }
    }
    if result.is_ok() && pipe_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "pipe proof serial path was not created".to_owned())?;
        if let Err(error) = verify_pipe_proof(serial) {
            result = Err(error);
        }
    }
    if result.is_ok() && virtio_gpu_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "virtio GPU proof serial path was not created".to_owned())?;
        let screenshot = screenshot_path
            .as_deref()
            .ok_or_else(|| "virtio GPU proof screenshot path was not created".to_owned())?;
        if let Err(error) = verify_virtio_gpu_proof(serial, screenshot) {
            result = Err(error);
        }
    }
    if result.is_ok() && terminal_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "terminal proof serial path was not created".to_owned())?;
        let screenshot = screenshot_path
            .as_deref()
            .ok_or_else(|| "terminal proof screenshot path was not created".to_owned())?;
        if let Err(error) = verify_terminal_proof(serial, screenshot) {
            result = Err(error);
        }
    }
    if result.is_ok() && account_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "account proof serial path was not created".to_owned())?;
        let screenshot = screenshot_path
            .as_deref()
            .ok_or_else(|| "account proof screenshot path was not created".to_owned())?;
        if let Err(error) = verify_account_proof(serial, screenshot) {
            result = Err(error);
        }
    }
    if result.is_ok() && logout_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "logout proof serial path was not created".to_owned())?;
        let screenshot = screenshot_path
            .as_deref()
            .ok_or_else(|| "logout proof screenshot path was not created".to_owned())?;
        if let Err(error) = verify_logout_proof(serial, screenshot) {
            result = Err(error);
        }
    }
    if result.is_ok() && role_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "role proof serial path was not created".to_owned())?;
        let screenshot = screenshot_path
            .as_deref()
            .ok_or_else(|| "role proof screenshot path was not created".to_owned())?;
        if let Err(error) = verify_role_proof(serial, screenshot) {
            result = Err(error);
        }
    }
    if result.is_ok() && desktop_proof {
        let serial = serial_path
            .as_deref()
            .ok_or_else(|| "desktop proof serial path was not created".to_owned())?;
        let screenshot = screenshot_path
            .as_deref()
            .ok_or_else(|| "desktop proof screenshot path was not created".to_owned())?;
        if let Err(error) = verify_desktop_proof(serial, screenshot) {
            result = Err(error);
        }
    }
    if result.is_ok()
        && suspend_state
            .as_ref()
            .is_some_and(|state| state.load(Ordering::Acquire) != 2)
    {
        return Err(
            "ACPI S3 proof did not observe suspended QEMU, guest resume, and a running state"
                .to_owned(),
        );
    }
    result
}

fn qemu_supports_virtio_gpu(binary: &OsStr) -> bool {
    let Ok(output) = Command::new(binary).args(["-device", "help"]).output() else {
        return false;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    output.status.success()
        && (stdout.contains("virtio-gpu-pci") || stderr.contains("virtio-gpu-pci"))
}

#[cfg(unix)]
fn spawn_keyboard_proof(
    path: PathBuf,
    screenshot: PathBuf,
    serial: Option<PathBuf>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(20));
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };
        if let Some(serial) = serial.as_deref()
            && !ensure_shell_login(&mut monitor, serial)
        {
            return;
        }
        for command in ["sendkey n\n", "sendkey e\n", "sendkey t\n", "sendkey ret\n"] {
            if monitor.write_all(command.as_bytes()).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(80));
        }
        thread::sleep(Duration::from_secs(3));
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_millis(500));
        let _ = monitor.write_all(b"sendkey e\nsendkey x\nsendkey i\nsendkey t\nsendkey ret\n");
        thread::sleep(Duration::from_secs(2));
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_shell_proof(path: PathBuf, screenshot: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };
        let ready = ensure_shell_login(&mut monitor, &serial);
        println!("shell proof: shell_ready={ready}");
        if !ready {
            return;
        }
        let steps = [
            ("id", "shell: credentials uid=1000 gid=1000 status=ready"),
            ("pwd", "shell: pwd path=/home/user status=ready"),
            ("mkdir documents", "mkdir: ok"),
            (
                "cd documents",
                "shell: cwd changed path=/home/user/documents status=ready",
            ),
            (
                "write meeting-notes.txt long-name",
                "shell: relative write path=/home/user/documents/meeting-notes.txt status=ready",
            ),
            (
                "cat meeting-notes.txt",
                "shell: relative read path=/home/user/documents/meeting-notes.txt status=ready",
            ),
            ("ls", "shell: ls path=/home/user/documents status=ready"),
            ("cd ..", "shell: cwd changed path=/home/user status=ready"),
            ("ls", "shell: ls path=/home/user status=ready"),
            ("mkdir work", "mkdir: ok"),
            (
                "cd work",
                "shell: cwd changed path=/home/user/work status=ready",
            ),
            (
                "grow",
                "shell: large file path=/home/user/work/large.bin bytes=131072 status=ready",
            ),
            (
                "truncate large.bin 65536",
                "shell: truncate path=/home/user/work/large.bin bytes=65536 status=ready",
            ),
            (
                "append large.bin tail",
                "shell: append path=/home/user/work/large.bin offset=65536 bytes=4 status=ready",
            ),
            (
                "truncate large.bin 131072",
                "shell: truncate path=/home/user/work/large.bin bytes=131072 status=ready",
            ),
            (
                "write note daily-use",
                "shell: relative write path=/home/user/work/note status=ready",
            ),
            (
                "mv note renamed-note",
                "shell: rename from=/home/user/work/note to=/home/user/work/renamed-note status=ready",
            ),
            (
                "cat renamed-note",
                "shell: relative read path=/home/user/work/renamed-note status=ready",
            ),
            (
                "rm renamed-note",
                "shell: remove path=/home/user/work/renamed-note status=ready",
            ),
            ("mkdir empty", "mkdir: ok"),
            (
                "rmdir empty",
                "shell: rmdir path=/home/user/work/empty status=ready",
            ),
            ("mkdir nonempty", "mkdir: ok"),
            ("touch nonempty/child", "touch: ok"),
            ("rmdir nonempty", "rmdir: failed"),
            ("rm nonempty/child", "rm: ok"),
            (
                "rmdir nonempty",
                "shell: rmdir path=/home/user/work/nonempty status=ready",
            ),
            ("open-proof", "shell: open-file lifecycle status=ready"),
            ("ls", "shell: ls path=/home/user/work status=ready"),
            (
                "cat /etc/rustos/config.txt",
                "shell: relative read path=/etc/rustos/config.txt status=ready",
            ),
            ("hw", "shell: hw status=ready"),
            (
                "write /etc/rustos/config.txt denied",
                "shell: permission denied path=/etc/rustos/config.txt status=ready",
            ),
            ("state", "shell: state read status=ready"),
            ("sudo pkg install", "sudo: pkg install status=ready"),
            ("ps", "shell: ps status=ready"),
            (
                "run /bin/replaced",
                "shell: run path=/bin/replaced status=ready",
            ),
            ("pwd", "shell: pwd path=/home/user/work status=ready"),
            ("cd ..", "shell: cwd changed path=/home/user status=ready"),
            ("pwd", "shell: pwd path=/home/user status=ready"),
            ("cd /", "shell: cwd changed path=/ status=ready"),
            ("cd ..", "shell: cwd changed path=/ status=ready"),
            ("pwd", "shell: pwd path=/ status=ready"),
        ];
        let denied = send_shell_privileged_command(
            &mut monitor,
            &serial,
            "sudo state set",
            "wrong",
            1,
            "admin: authorization failed status=denied",
        );
        println!("shell proof: privileged_denied={denied}");
        if !denied {
            let _ = monitor.write_all(b"quit\n");
            return;
        }
        let allowed = send_shell_privileged_command(
            &mut monitor,
            &serial,
            "sudo state set",
            "rustos",
            2,
            "sudo: state set status=ready",
        );
        println!("shell proof: privileged_allowed={allowed}");
        if !allowed {
            let _ = monitor.write_all(b"quit\n");
            return;
        }
        for (command, marker) in steps {
            if !send_shell_command(&mut monitor, command) {
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            let timeout = if command == "sudo pkg install" {
                Duration::from_secs(120)
            } else {
                Duration::from_secs(30)
            };
            if command == "sudo pkg install"
                && (!wait_for_serial_occurrences(
                    &serial,
                    "sudo: password: ",
                    3,
                    Duration::from_secs(30),
                ) || !send_shell_command(&mut monitor, "rustos"))
            {
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            let completed = wait_for_serial_markers(&serial, &[marker], timeout);
            println!("shell proof: command={command} completed={completed}");
            if !completed {
                let _ = monitor.write_all(b"quit\n");
                return;
            }
        }
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_millis(500));
        if !send_shell_command(&mut monitor, "exit") {
            return;
        }
        let exited = wait_for_serial_markers(
            &serial,
            &["shell: exit requested status=ready"],
            Duration::from_secs(30),
        );
        println!("shell proof: exit={exited}");
        thread::sleep(Duration::from_secs(2));
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn send_shell_command(monitor: &mut UnixStream, command: &str) -> bool {
    send_interactive_command(
        monitor,
        command,
        false,
        Duration::from_millis(80),
        Duration::from_millis(200),
    )
}

#[cfg(unix)]
fn ensure_shell_login(monitor: &mut UnixStream, serial: &Path) -> bool {
    let Some(first_marker) = wait_for_serial_any(
        serial,
        &[
            "shell-login: account store setup required status=ready",
            "RustOS shell",
        ],
        Duration::from_secs(90),
    ) else {
        println!("shell login proof: prompt=false");
        return false;
    };
    if first_marker == 0 {
        if !send_shell_command(monitor, "user")
            || !send_shell_command(monitor, "rustos")
            || !send_shell_command(monitor, "rustos")
            || !wait_for_serial_markers(
                serial,
                &["shell-login: account store bootstrapped status=ready"],
                Duration::from_secs(30),
            )
        {
            println!("shell login proof: first-boot-setup=false");
            return false;
        }
    }
    let ready = wait_for_serial_markers(serial, &["RustOS shell"], Duration::from_secs(30));
    println!("shell login proof: ready={ready}");
    ready
}

#[cfg(unix)]
fn send_shell_privileged_command(
    monitor: &mut UnixStream,
    serial: &Path,
    command: &str,
    password: &str,
    prompt_occurrence: usize,
    marker: &str,
) -> bool {
    send_shell_command(monitor, command)
        && wait_for_serial_occurrences(
            serial,
            "sudo: password: ",
            prompt_occurrence,
            Duration::from_secs(30),
        )
        && send_shell_command(monitor, password)
        && wait_for_serial_markers(serial, &[marker], Duration::from_secs(30))
}

#[cfg(unix)]
fn send_account_command(monitor: &mut UnixStream, command: &str) -> bool {
    send_interactive_command(
        monitor,
        command,
        true,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
}

#[cfg(unix)]
fn send_account_input(monitor: &mut UnixStream, input: &str) -> bool {
    send_interactive_command(
        monitor,
        input,
        false,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
}

#[cfg(unix)]
fn send_login_command(monitor: &mut UnixStream, command: &str) -> bool {
    send_interactive_command(
        monitor,
        command,
        false,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
}

#[cfg(unix)]
fn send_interactive_command(
    monitor: &mut UnixStream,
    command: &str,
    refocus: bool,
    key_delay: Duration,
    enter_delay: Duration,
) -> bool {
    if refocus && !focus_terminal(monitor) {
        return false;
    }
    for byte in command.bytes() {
        if let Some(key) = match byte {
            b'/' => Some("slash"),
            b' ' => Some("spc"),
            b'.' => Some("dot"),
            b'-' => Some("minus"),
            b'_' => Some("underscore"),
            b'a'..=b'z' | b'0'..=b'9' => None,
            _ => return false,
        } {
            if monitor
                .write_all(format!("sendkey {key}\n").as_bytes())
                .is_err()
            {
                return false;
            }
            thread::sleep(key_delay);
        } else if !send_shell_key(monitor, byte, key_delay) {
            return false;
        }
    }
    if monitor.write_all(b"sendkey ret\n").is_err() {
        return false;
    }
    thread::sleep(enter_delay);
    true
}

#[cfg(unix)]
fn send_shell_key(monitor: &mut UnixStream, byte: u8, delay: Duration) -> bool {
    if monitor
        .write_all(format!("sendkey {}\n", char::from(byte)).as_bytes())
        .is_err()
    {
        return false;
    }
    thread::sleep(delay);
    true
}

#[cfg(unix)]
fn focus_terminal(monitor: &mut UnixStream) -> bool {
    if monitor
        .write_all(b"mouse_button 1\nmouse_button 0\n")
        .is_err()
    {
        return false;
    }
    thread::sleep(Duration::from_millis(500));
    true
}

#[cfg(unix)]
fn spawn_pipe_proof(path: PathBuf, screenshot: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };
        let ready = ensure_shell_login(&mut monitor, &serial);
        println!("pipe proof: shell_ready={ready}");
        if !ready {
            return;
        }
        if !send_shell_command(&mut monitor, "ps") {
            return;
        }
        if !wait_for_serial_markers(
            &serial,
            &["shell: ps status=ready"],
            Duration::from_secs(30),
        ) {
            return;
        }
        if !send_shell_command(&mut monitor, "pipe") {
            return;
        }
        let pipeline_ready = wait_for_serial_markers(
            &serial,
            &["pipe: status=ready producer=0 consumer=0"],
            Duration::from_secs(30),
        );
        println!("pipe proof: pipeline_completed={pipeline_ready}");
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_millis(500));
        if !send_shell_command(&mut monitor, "exit") {
            return;
        }
        let exited = wait_for_serial_markers(
            &serial,
            &[
                "shell: exit requested status=ready",
                "system: RustOS reached interrupt-driven idle state storage=ready",
            ],
            Duration::from_secs(30),
        );
        println!("pipe proof: shell_exited={exited}");
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_poweroff_proof(path: PathBuf, screenshot: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(20));
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };
        for command in [
            "sendkey p\n",
            "sendkey o\n",
            "sendkey w\n",
            "sendkey e\n",
            "sendkey r\n",
            "sendkey o\n",
            "sendkey f\n",
            "sendkey f\n",
        ] {
            if monitor.write_all(command.as_bytes()).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(80));
        }
        thread::sleep(Duration::from_secs(2));
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_millis(500));
        let _ = monitor.write_all(b"sendkey ret\n");
    })
}

#[cfg(unix)]
fn spawn_reboot_proof(path: PathBuf, screenshot: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(20));
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };
        for command in [
            "sendkey r\n",
            "sendkey e\n",
            "sendkey b\n",
            "sendkey o\n",
            "sendkey o\n",
            "sendkey t\n",
        ] {
            if monitor.write_all(command.as_bytes()).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(80));
        }
        thread::sleep(Duration::from_secs(2));
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_millis(500));
        let _ = monitor.write_all(b"sendkey ret\n");
    })
}

#[cfg(unix)]
fn spawn_suspend_proof(
    path: PathBuf,
    screenshot: PathBuf,
    serial: PathBuf,
    state: Arc<AtomicUsize>,
    native_suspend_proof: bool,
) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(20));
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            state.store(255, Ordering::Release);
            return;
        };
        let _ = monitor.set_read_timeout(Some(Duration::from_millis(500)));
        let _ = read_monitor_response(&mut monitor);

        for command in [
            "sendkey s\n",
            "sendkey u\n",
            "sendkey s\n",
            "sendkey p\n",
            "sendkey e\n",
            "sendkey n\n",
            "sendkey d\n",
            "sendkey ret\n",
        ] {
            if monitor.write_all(command.as_bytes()).is_err() {
                state.store(255, Ordering::Release);
                return;
            }
            thread::sleep(Duration::from_millis(80));
        }
        thread::sleep(Duration::from_secs(2));
        let _ = read_monitor_response(&mut monitor);
        if monitor.write_all(b"info status\n").is_err() {
            state.store(255, Ordering::Release);
            return;
        }
        let suspended = read_monitor_response(&mut monitor).contains("suspended");
        println!("suspend proof: qemu_suspended={suspended}");
        if !suspended {
            state.store(255, Ordering::Release);
            let _ = monitor.write_all(b"quit\n");
            return;
        }
        state.store(1, Ordering::Release);
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        let _ = read_monitor_response(&mut monitor);

        if monitor.write_all(b"system_wakeup\n").is_err() {
            println!("suspend proof: system_wakeup_write=false");
            state.store(255, Ordering::Release);
            return;
        }
        let wake_response = read_monitor_response(&mut monitor);
        println!(
            "suspend proof: system_wakeup_ack={}",
            wake_response.contains("wakeup") || wake_response.contains("Wake")
        );
        thread::sleep(Duration::from_secs(2));
        if monitor.write_all(b"info status\n").is_err() {
            println!("suspend proof: info_status_after_wakeup_write=false");
            state.store(255, Ordering::Release);
            return;
        }
        let running = read_monitor_response(&mut monitor).contains("running");
        println!("suspend proof: qemu_running_after_wakeup={running}");
        if !running {
            state.store(255, Ordering::Release);
            let _ = monitor.write_all(b"quit\n");
            return;
        }
        let guest_resume = if native_suspend_proof {
            wait_for_serial_markers(
                &serial,
                &[
                    "power: ACPI S3 suspend requested status=ready vector=native",
                    "power: ACPI S3 resume status=ready",
                    "suspend: resumed",
                ],
                Duration::from_secs(10),
            )
        } else {
            wait_for_serial_markers(
                &serial,
                &["power: ACPI S3 resume status=ready", "suspend: resumed"],
                Duration::from_secs(10),
            )
        };
        println!("suspend proof: guest_resume={guest_resume}");
        if !guest_resume {
            state.store(255, Ordering::Release);
            let _ = monitor.write_all(b"quit\n");
            return;
        }
        state.store(2, Ordering::Release);
        for command in [
            "sendkey e\n",
            "sendkey x\n",
            "sendkey i\n",
            "sendkey t\n",
            "sendkey ret\n",
        ] {
            if monitor.write_all(command.as_bytes()).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(80));
        }
        thread::sleep(Duration::from_secs(2));
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_millis(500));
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_audio_proof(path: PathBuf, serial: PathBuf, controller: &'static str) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };

        let ready = wait_for_audio_ready(&serial, controller, Duration::from_secs(30));
        println!("{controller} audio proof: guest_audio_ready={ready}");
        if !ready {
            let _ = monitor.write_all(b"quit\n");
            return;
        }

        // The guest publishes the marker immediately after arming the DMA engine. Let the
        // 32-page tone drain into QEMU's WAV backend before asking the machine to exit.
        thread::sleep(Duration::from_secs(1));
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_virtio_network_proof(
    path: PathBuf,
    serial: PathBuf,
    dual_network: bool,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };

        if !ensure_shell_login(&mut monitor, &serial) {
            return;
        }

        let interface_count = if dual_network { 2 } else { 1 };
        let manager_marker = format!(
            "net: manager interfaces={} default=virtio0 backend=virtio routes=1 status=ready",
            interface_count
        );
        let mut ready_markers = vec![
            "driver: virtio-net ",
            "net: virtio dhcp lease ",
            manager_marker.as_str(),
            "net: selected backend=virtio userland UDP service installed status=ready",
        ];
        if dual_network {
            ready_markers.extend(["driver: e1000 ", "net: dhcp lease "]);
        }
        let ready = wait_for_serial_markers(&serial, &ready_markers, Duration::from_secs(30));
        let interrupt_ready = ready
            && wait_for_serial_markers(
                &serial,
                &["interrupt_mode=Msix", "interrupt_driven=true"],
                Duration::from_secs(5),
            );
        println!(
            "virtio network proof: guest_dhcp_ready={} interrupt_ready={}",
            ready, interrupt_ready
        );
        if ready && interrupt_ready {
            for command in ["sendkey n\n", "sendkey e\n", "sendkey t\n", "sendkey ret\n"] {
                if monitor.write_all(command.as_bytes()).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(80));
            }
            let info_ready = wait_for_serial_markers(
                &serial,
                &["net: syscall info backend=virtio status=ready"],
                Duration::from_secs(5),
            );
            println!("virtio network proof: userland_info={info_ready}");

            for command in [
                "sendkey n\n",
                "sendkey e\n",
                "sendkey t\n",
                "sendkey spc\n",
                "sendkey i\n",
                "sendkey n\n",
                "sendkey t\n",
                "sendkey e\n",
                "sendkey r\n",
                "sendkey f\n",
                "sendkey a\n",
                "sendkey c\n",
                "sendkey e\n",
                "sendkey s\n",
                "sendkey ret\n",
            ] {
                if monitor.write_all(command.as_bytes()).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(80));
            }
            let interface_marker = format!(
                "net: syscall interfaces default=virtio0 backend=virtio count={} status=ready",
                interface_count
            );
            let mut interface_markers = vec![
                interface_marker.as_str(),
                "net: interfaces status=ready",
                "interface=virtio0 backend=virtio ",
            ];
            if dual_network {
                interface_markers.push("interface=e1000e0 backend=e1000 ");
            }
            let interfaces_ready =
                wait_for_serial_markers(&serial, &interface_markers, Duration::from_secs(5));
            println!("virtio network proof: userland_interfaces={interfaces_ready}");

            for command in [
                "sendkey n\n",
                "sendkey e\n",
                "sendkey t\n",
                "sendkey spc\n",
                "sendkey r\n",
                "sendkey e\n",
                "sendkey n\n",
                "sendkey e\n",
                "sendkey w\n",
                "sendkey ret\n",
            ] {
                if monitor.write_all(command.as_bytes()).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(80));
            }
            let renew_marker = format!(
                "net: syscall renew interfaces={} status=ready",
                interface_count
            );
            let mut renewal_markers = vec![
                renew_marker.as_str(),
                "manager=rustos interfaces=",
                "timer_service=active status=ready",
                "result=renewed lease_seconds=",
                "interface=virtio0 backend=virtio result=renewed",
            ];
            if dual_network {
                renewal_markers.push("interface=e1000e0 backend=e1000 result=renewed");
            }
            let renew_ready =
                wait_for_serial_markers(&serial, &renewal_markers, Duration::from_secs(10));
            println!("virtio network proof: userland_renew={renew_ready}");

            for command in [
                "sendkey n\n",
                "sendkey e\n",
                "sendkey t\n",
                "sendkey spc\n",
                "sendkey p\n",
                "sendkey r\n",
                "sendkey o\n",
                "sendkey b\n",
                "sendkey e\n",
                "sendkey ret\n",
            ] {
                if monitor.write_all(command.as_bytes()).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(80));
            }
            let udp_ready = wait_for_serial_markers(
                &serial,
                &[
                    "net: syscall send backend=virtio ",
                    "net: syscall receive backend=virtio ",
                    "net: udp probe received repository status=ready",
                ],
                Duration::from_secs(10),
            );
            println!("virtio network proof: userland_udp={udp_ready}");
            for command in [
                "sendkey e\n",
                "sendkey x\n",
                "sendkey i\n",
                "sendkey t\n",
                "sendkey ret\n",
            ] {
                if monitor.write_all(command.as_bytes()).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(80));
            }
            thread::sleep(Duration::from_secs(2));
        }
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_nvme_interrupt_proof(path: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };

        if !ensure_shell_login(&mut monitor, &serial) {
            return;
        }

        let ready = wait_for_serial_markers(
            &serial,
            &[
                "pci: ",
                "class=0x0108",
                "msix=true",
                "storage: nvme ",
                "interrupt_mode=Msix",
                "interrupt_count=",
                "interrupt_driven=true",
                "interrupt_error=None",
                "storage: transport=nvme ",
                "RustOS shell",
            ],
            Duration::from_secs(30),
        );
        println!("nvme interrupt proof: guest_storage_ready={ready}");
        if ready {
            for command in [
                "sendkey e\n",
                "sendkey x\n",
                "sendkey i\n",
                "sendkey t\n",
                "sendkey ret\n",
            ] {
                if monitor.write_all(command.as_bytes()).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(80));
            }
            thread::sleep(Duration::from_secs(2));
        }
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_ahci_interrupt_proof(path: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };

        if !ensure_shell_login(&mut monitor, &serial) {
            return;
        }

        let ready = wait_for_serial_markers(
            &serial,
            &[
                "pci: ",
                "class=0x0106",
                "msi=true",
                "storage: ahci ",
                "interrupt_mode=Msi",
                "interrupt_count=",
                "interrupt_driven=true",
                "interrupt_error=None",
                "storage: transport=ahci ",
                "RustOS shell",
            ],
            Duration::from_secs(30),
        );
        println!("ahci interrupt proof: guest_storage_ready={ready}");
        if ready {
            for command in [
                "sendkey e\n",
                "sendkey x\n",
                "sendkey i\n",
                "sendkey t\n",
                "sendkey ret\n",
            ] {
                if monitor.write_all(command.as_bytes()).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(80));
            }
            thread::sleep(Duration::from_secs(2));
        }
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_vm_proof(path: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };

        let shell_ready = ensure_shell_login(&mut monitor, &serial);
        let mut ready = false;
        if shell_ready {
            for command in ["sendkey v\n", "sendkey m\n", "sendkey ret\n"] {
                if monitor.write_all(command.as_bytes()).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(80));
            }
            ready = wait_for_serial_markers(
                &serial,
                &[
                    "userland: vm map=ready write=ready fork=ready unmap=ready reuse=ready reclaim=ready status=ready",
                ],
                Duration::from_secs(30),
            );
            if ready {
                for command in [
                    "sendkey e\n",
                    "sendkey x\n",
                    "sendkey i\n",
                    "sendkey t\n",
                    "sendkey ret\n",
                ] {
                    if monitor.write_all(command.as_bytes()).is_err() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(80));
                }
                let process_reclaimed = wait_for_serial_markers(
                    &serial,
                    &["process: address_spaces_reclaimed=true count="],
                    Duration::from_secs(30),
                );
                if !process_reclaimed {
                    println!("vm proof: process_reclaimed=false");
                }
                thread::sleep(Duration::from_secs(2));
            }
        }
        println!("vm proof: userland_memory_ready={ready}");
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_smp_proof(path: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut monitor = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    monitor = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        let Some(mut monitor) = monitor else {
            return;
        };

        let ready = wait_for_serial_markers(
            &serial,
            &[
                "smp: discovered=2 enabled=2 online=2 failed=0",
                "timer: local-apic",
                "scheduler: switches=",
                "system: RustOS reached interrupt-driven idle state storage=ready process=ready",
                "smp: scheduler release=1 application_processors status=ready",
            ],
            Duration::from_secs(60),
        );
        println!("smp proof: runtime_ready={ready}");
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn wait_for_serial_markers(path: &Path, markers: &[&str], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let content = fs::read_to_string(path).unwrap_or_default();
        if markers.iter().all(|marker| content.contains(marker)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn wait_for_serial_any(path: &Path, markers: &[&str], timeout: Duration) -> Option<usize> {
    let deadline = Instant::now() + timeout;
    loop {
        let content = fs::read_to_string(path).unwrap_or_default();
        if let Some(index) = markers.iter().position(|marker| content.contains(marker)) {
            return Some(index);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn wait_for_serial_occurrences(
    path: &Path,
    marker: &str,
    occurrences: usize,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let content = fs::read_to_string(path).unwrap_or_default();
        if content.matches(marker).count() >= occurrences {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn wait_for_audio_ready(path: &Path, controller: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .any(|line| {
                line.starts_with(&format!("audio: {controller} ")) && line.ends_with("status=ready")
            })
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn verify_audio_proof(serial: &Path, wav: &Path, controller: &str) -> Result<(), String> {
    let serial_content = fs::read_to_string(serial)
        .map_err(|error| format!("reading audio proof serial {}: {error}", serial.display()))?;
    if !serial_content.lines().any(|line| {
        line.starts_with(&format!("audio: {controller} ")) && line.ends_with("status=ready")
    }) {
        return Err(format!(
            "audio proof serial did not contain a ready {controller} marker: {}",
            serial.display()
        ));
    }

    let bytes = fs::read(wav)
        .map_err(|error| format!("reading audio proof WAV {}: {error}", wav.display()))?;
    let (data, channels, sample_rate) = wav_data(&bytes)?;
    if channels != 2 || sample_rate != 48_000 {
        return Err(format!(
            "audio proof WAV format was channels={} rate={}, expected stereo 48000 Hz",
            channels, sample_rate
        ));
    }
    if data.len() < 4 || data.len() % 2 != 0 {
        return Err(format!(
            "audio proof WAV data chunk is too short or misaligned: {} bytes",
            data.len()
        ));
    }
    let nonzero_samples = data
        .chunks_exact(2)
        .filter(|sample| i16::from_le_bytes([sample[0], sample[1]]) != 0)
        .count();
    if nonzero_samples < 32 {
        return Err(format!(
            "audio proof WAV contains too few nonzero samples: {nonzero_samples}"
        ));
    }
    println!(
        "{controller} audio proof: wav_bytes={} data_bytes={} nonzero_samples={} format=stereo-s16le rate={} status=ready",
        bytes.len(),
        data.len(),
        nonzero_samples,
        sample_rate
    );
    Ok(())
}

fn verify_virtio_gpu_proof(serial: &Path, screenshot: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial).map_err(|error| {
        format!(
            "reading virtio GPU proof serial {}: {error}",
            serial.display()
        )
    })?;
    let driver_ready = content
        .lines()
        .any(|line| line.starts_with("driver: virtio-gpu ") && line.ends_with("status=ready"));
    let scanout_ready = content.contains("gpu: scanout=0 resource=1")
        && content.contains("gpu: scanout=0 resource=1 width=");
    let desktop_ready =
        content.contains("desktop: compositor framebuffer=ready scene=ready status=ready");
    let session_ready = content.contains("login: authentication ok")
        && content.contains("desktop: credentials uid=1000 gid=1000 status=ready");
    let frame_counts = content.lines().find_map(|line| {
        if !line.starts_with("gpu: frame ") || !line.ends_with("status=ready") {
            return None;
        }
        let transfers = line.split_whitespace().find_map(|field| {
            field
                .strip_prefix("transfers=")
                .and_then(|value| value.parse::<u64>().ok())
        })?;
        let flushes = line.split_whitespace().find_map(|field| {
            field
                .strip_prefix("flushes=")
                .and_then(|value| value.parse::<u64>().ok())
        })?;
        Some((transfers, flushes))
    });
    let screenshot_bytes = fs::read(screenshot).map_err(|error| {
        format!(
            "reading virtio GPU proof screenshot {}: {error}",
            screenshot.display()
        )
    })?;
    let screenshot_ready = screenshot_bytes.starts_with(b"P6\n") && screenshot_bytes.len() > 64;
    let (transfers, flushes) = frame_counts.unwrap_or((0, 0));
    if !driver_ready
        || !scanout_ready
        || !desktop_ready
        || !session_ready
        || transfers == 0
        || flushes == 0
        || !screenshot_ready
    {
        return Err(format!(
            "virtio GPU proof did not contain a ready scanout, frame transfer, desktop, and screenshot marker: {}",
            serial.display()
        ));
    }
    println!(
        "virtio-gpu proof: driver_ready={} scanout_ready={} transfers={} flushes={} desktop_ready={} session_ready={} screenshot_bytes={} status=ready",
        driver_ready,
        scanout_ready,
        transfers,
        flushes,
        desktop_ready,
        session_ready,
        screenshot_bytes.len()
    );
    Ok(())
}

fn verify_virtio_network_proof(serial: &Path, dual_network: bool) -> Result<(), String> {
    let content = fs::read_to_string(serial).map_err(|error| {
        format!(
            "reading virtio network proof serial {}: {error}",
            serial.display()
        )
    })?;
    let driver_ready = content
        .lines()
        .any(|line| line.starts_with("driver: virtio-net ") && line.ends_with("status=ready"));
    let interrupt_ready = content.lines().any(|line| {
        line.starts_with("driver: virtio-net ")
            && line.contains("interrupt_mode=Msix")
            && line.contains("interrupt_driven=true")
            && line.ends_with("status=ready")
    }) && virtio_interrupt_count(&content).is_some_and(|count| count > 0);
    let secondary_driver_ready = !dual_network
        || content
            .lines()
            .any(|line| line.starts_with("driver: e1000 ") && line.ends_with("status=ready"));
    let dhcp_ready = content
        .lines()
        .any(|line| line.contains("net: virtio dhcp lease ") && line.ends_with("status=ready"));
    let secondary_dhcp_ready =
        !dual_network || content.contains("net: dhcp lease ") && content.contains("status=ready");
    let interface_count = if dual_network { 2 } else { 1 };
    let manager_marker = format!(
        "net: manager interfaces={} default=virtio0 backend=virtio routes=1 status=ready",
        interface_count
    );
    let selected_backend = content
        .contains("net: selected backend=virtio userland UDP service installed status=ready");
    let manager_ready = content.contains(manager_marker.as_str());
    let userland_info = content.contains("net: syscall info backend=virtio status=ready");
    let interface_marker = format!(
        "net: syscall interfaces default=virtio0 backend=virtio count={} status=ready",
        interface_count
    );
    let userland_interfaces = content.contains(interface_marker.as_str())
        && content.contains("net: interfaces status=ready")
        && content.contains("interface=virtio0 backend=virtio ")
        && (!dual_network || content.contains("interface=e1000e0 backend=e1000 "));
    let renew_marker = format!(
        "net: syscall renew interfaces={} status=ready",
        interface_count
    );
    let userland_renew = content.contains(renew_marker.as_str())
        && content.contains("manager=rustos interfaces=")
        && content.contains("timer_service=active status=ready")
        && content.contains("result=renewed lease_seconds=")
        && content.contains("interface=virtio0 backend=virtio result=renewed")
        && (!dual_network || content.contains("interface=e1000e0 backend=e1000 result=renewed"));
    let userland_send = content.contains("net: syscall send backend=virtio ");
    let userland_receive = content.contains("net: syscall receive backend=virtio ");
    let udp_probe = content.contains("net: udp probe received repository status=ready");
    if !driver_ready
        || !interrupt_ready
        || !dhcp_ready
        || !secondary_driver_ready
        || !secondary_dhcp_ready
        || !selected_backend
        || !manager_ready
        || !userland_info
        || !userland_interfaces
        || !userland_renew
        || !userland_send
        || !userland_receive
        || !udp_probe
    {
        return Err(format!(
            "virtio network proof serial did not contain the interrupt-backed network-manager and userland UDP markers: {}",
            serial.display()
        ));
    }
    println!(
        "virtio network proof: driver_ready={} interrupt_ready={} dhcp_ready={} secondary_driver_ready={} secondary_dhcp_ready={} manager_ready={} selected_backend={} userland_info={} userland_interfaces={} userland_renew={} userland_send={} userland_receive={} udp_probe={} status=ready",
        driver_ready,
        interrupt_ready,
        dhcp_ready,
        secondary_driver_ready,
        secondary_dhcp_ready,
        manager_ready,
        selected_backend,
        userland_info,
        userland_interfaces,
        userland_renew,
        userland_send,
        userland_receive,
        udp_probe
    );
    Ok(())
}

fn verify_nvme_interrupt_proof(serial: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial).map_err(|error| {
        format!(
            "reading NVMe interrupt proof serial {}: {error}",
            serial.display()
        )
    })?;
    let pci_msix = content.lines().any(|line| {
        line.starts_with("pci: ") && line.contains("class=0x0108") && line.contains("msix=true")
    });
    let nvme_ready = content
        .lines()
        .any(|line| line.starts_with("storage: nvme ") && line.ends_with("status=ready"));
    let interrupt_ready = content.lines().any(|line| {
        line.starts_with("storage: nvme ")
            && line.contains("interrupt_mode=Msix")
            && line.contains("interrupt_driven=true")
            && line.contains("interrupt_error=None")
            && line.ends_with("status=ready")
    }) && nvme_interrupt_count(&content).is_some_and(|count| count > 0);
    let filesystem_ready = content
        .lines()
        .any(|line| line.starts_with("storage: transport=nvme ") && line.ends_with("status=ready"));
    if !pci_msix || !nvme_ready || !interrupt_ready || !filesystem_ready {
        return Err(format!(
            "NVMe interrupt proof serial did not contain the MSI-X storage and filesystem markers: {}",
            serial.display()
        ));
    }
    println!(
        "nvme interrupt proof: pci_msix={} nvme_ready={} interrupt_ready={} filesystem_ready={} status=ready",
        pci_msix, nvme_ready, interrupt_ready, filesystem_ready
    );
    Ok(())
}

fn verify_ahci_interrupt_proof(serial: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial).map_err(|error| {
        format!(
            "reading AHCI interrupt proof serial {}: {error}",
            serial.display()
        )
    })?;
    let pci_msi = content.lines().any(|line| {
        line.starts_with("pci: ") && line.contains("class=0x0106") && line.contains("msi=true")
    });
    let ahci_ready = content
        .lines()
        .any(|line| line.starts_with("storage: ahci ") && line.ends_with("status=ready"));
    let interrupt_ready = content.lines().any(|line| {
        line.starts_with("storage: ahci ")
            && line.contains("interrupt_mode=Msi")
            && line.contains("interrupt_driven=true")
            && line.contains("interrupt_error=None")
            && line.ends_with("status=ready")
    }) && ahci_interrupt_count(&content).is_some_and(|count| count > 0);
    let filesystem_ready = content
        .lines()
        .any(|line| line.starts_with("storage: transport=ahci ") && line.ends_with("status=ready"));
    if !pci_msi || !ahci_ready || !interrupt_ready || !filesystem_ready {
        return Err(format!(
            "AHCI interrupt proof serial did not contain the MSI storage and filesystem markers: {}",
            serial.display()
        ));
    }
    println!(
        "ahci interrupt proof: pci_msi={} ahci_ready={} interrupt_ready={} filesystem_ready={} status=ready",
        pci_msi, ahci_ready, interrupt_ready, filesystem_ready
    );
    Ok(())
}

fn ahci_interrupt_count(serial: &str) -> Option<u64> {
    serial.lines().find_map(|line| {
        if !line.starts_with("storage: ahci ") {
            return None;
        }
        line.split_whitespace().find_map(|field| {
            field
                .strip_prefix("interrupt_count=")
                .and_then(|count| count.parse::<u64>().ok())
        })
    })
}

fn verify_vm_proof(serial: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial)
        .map_err(|error| format!("reading VM proof serial {}: {error}", serial.display()))?;
    let userland_memory_ready = content.lines().any(|line| {
        line.contains(
            "userland: vm map=ready write=ready fork=ready unmap=ready reuse=ready reclaim=ready status=ready",
        )
    });
    if !userland_memory_ready {
        return Err(format!(
            "VM proof serial did not contain the anonymous mapping lifecycle marker: {}",
            serial.display()
        ));
    }
    let process_reclaim_ready = content.lines().any(|line| {
        line.contains("process: address_spaces_reclaimed=true") && line.contains("status=ready")
    });
    if !process_reclaim_ready {
        return Err(format!(
            "VM proof serial did not contain the process address-space reclamation marker: {}",
            serial.display()
        ));
    }
    println!(
        "vm proof: userland_memory_ready={} process_reclaim_ready={} status=ready",
        userland_memory_ready, process_reclaim_ready
    );
    Ok(())
}

fn verify_smp_proof(serial: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial)
        .map_err(|error| format!("reading SMP proof serial {}: {error}", serial.display()))?;
    let smp_ready = content.lines().any(|line| {
        line.starts_with("smp: discovered=2 enabled=2 online=2 failed=0 ")
            && line.contains("status=ready")
    });
    let application_processor_user_process = content.lines().any(|line| {
        line.starts_with("process: pid=")
            && line.split_whitespace().any(|field| {
                field
                    .strip_prefix("last_cpu_apic=")
                    .and_then(|value| value.parse::<u32>().ok())
                    .is_some_and(|apic_id| apic_id != 0 && apic_id != u32::MAX)
            })
    });
    let markers = [
        "timer: local-apic",
        "scheduler: switches=",
        "system: RustOS reached interrupt-driven idle state storage=ready process=ready",
        "smp: scheduler release=1 application_processors status=ready",
    ];
    let runtime_ready = smp_ready
        && application_processor_user_process
        && markers.iter().all(|marker| content.contains(marker));
    if !runtime_ready {
        return Err(format!(
            "SMP proof serial did not contain the complete two-vCPU runtime marker set, including AP user execution: {}",
            serial.display()
        ));
    }
    println!("smp proof: runtime_ready=true ap_user_process=true status=ready");
    Ok(())
}

fn verify_pipe_proof(serial: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial)
        .map_err(|error| format!("reading pipe proof serial {}: {error}", serial.display()))?;
    let pipeline_ready = content.contains("pipe: status=ready producer=0 consumer=0");
    let producer_output = content.contains("userland: /bin/worker");
    let consumer_exited = content.lines().any(|line| {
        line.contains("origin=/bin/cat")
            && line.contains("state=Exited")
            && line.contains("reclaimed=true")
            && line.contains("exit_code=Some(0)")
    });
    let parent_reaped_children = content.lines().any(|line| {
        line.contains("origin=/bin/sh")
            && line.contains("wait_statuses=2")
            && line.contains("last_wait_status=0")
    });
    let system_idle =
        content.contains("system: RustOS reached interrupt-driven idle state storage=ready");
    if !pipeline_ready
        || !producer_output
        || !consumer_exited
        || !parent_reaped_children
        || !system_idle
    {
        return Err(format!(
            "pipe proof serial did not contain the complete process-composition marker set: {}",
            serial.display()
        ));
    }
    println!("pipe proof: pipe_ready=true redirected_spawn=true eof_reaped=true status=ready");
    Ok(())
}

fn verify_shell_proof(serial: &Path, screenshot: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial)
        .map_err(|error| format!("reading shell proof serial {}: {error}", serial.display()))?;
    let required = [
        "shell-login: account store ",
        "shell: credentials uid=1000 gid=1000 status=ready",
        "shell: pwd path=/home/user status=ready",
        "shell: cwd changed path=/home/user/documents status=ready",
        "shell: relative write path=/home/user/documents/meeting-notes.txt status=ready",
        "shell: relative read path=/home/user/documents/meeting-notes.txt status=ready",
        "shell: ls path=/home/user/documents status=ready",
        "shell: cwd changed path=/home/user/work status=ready",
        "shell: large file path=/home/user/work/large.bin bytes=131072 status=ready",
        "shell: truncate path=/home/user/work/large.bin bytes=65536 status=ready",
        "shell: append path=/home/user/work/large.bin offset=65536 bytes=4 status=ready",
        "shell: truncate path=/home/user/work/large.bin bytes=131072 status=ready",
        "shell: relative write path=/home/user/work/note status=ready",
        "shell: rename from=/home/user/work/note to=/home/user/work/renamed-note status=ready",
        "shell: relative read path=/home/user/work/renamed-note status=ready",
        "shell: remove path=/home/user/work/renamed-note status=ready",
        "shell: rmdir path=/home/user/work/empty status=ready",
        "shell: rmdir path=/home/user/work/nonempty status=ready",
        "shell: open-file lifecycle status=ready",
        "shell: ls path=/home/user/work status=ready",
        "shell: hw status=ready",
        "shell: ps status=ready",
        "shell: relative read path=/etc/rustos/config.txt status=ready",
        "shell: permission denied path=/etc/rustos/config.txt status=ready",
        "admin: authorization failed status=denied",
        "sudo: state set status=ready",
        "shell: state read status=ready",
        "sudo: pkg install status=ready",
        "shell: run path=/bin/replaced status=ready",
        "shell: pwd path=/home/user/work status=ready",
        "shell: cwd changed path=/home/user status=ready",
        "shell: pwd path=/home/user status=ready",
        "shell: cwd changed path=/ status=ready",
        "shell: pwd path=/ status=ready",
        "shell: exit requested status=ready",
    ];
    if !required.iter().all(|marker| content.contains(marker))
        || !content.contains("daily-use")
        || !content.contains("userland: /bin/replaced")
        || !content.contains("uid=1000 gid=1000 name=user")
        || content
            .lines()
            .any(|line| line.trim_end_matches('\r') == "note 9 data")
        || !content.contains("documents 0 dir")
        || !content.contains("meeting-notes.txt")
        || content
            .lines()
            .any(|line| line.trim_end_matches('\r') == "renamed-note 9 data")
        || content
            .lines()
            .any(|line| line.trim_end_matches('\r') == "empty 0 dir")
        || content
            .lines()
            .any(|line| line.trim_end_matches('\r') == "nonempty 0 dir")
        || content
            .lines()
            .any(|line| line.trim_end_matches('\r') == "open-handle 0 data")
        || content
            .lines()
            .any(|line| line.trim_end_matches('\r') == "renamed-open-handle 0 data")
        || !content.contains("large.bin 131072 data")
        || !content.contains("boot=1")
        || !content.contains("admin: state set status=ready")
        || !content.contains("admin: package operation status=ready")
        || !content.contains("pkg: dependency closure readback verified")
        || !content.contains("uid=0 gid=0 origin=/sbin/admin")
        || !content.contains("exited /bin/pkg /bin/pkg Some(0)")
    {
        return Err(format!(
            "shell proof serial did not contain the complete identity, permission, privilege, and relative-file marker set: {}",
            serial.display()
        ));
    }
    let screenshot_bytes = fs::read(screenshot).map_err(|error| {
        format!(
            "reading shell proof screenshot {}: {error}",
            screenshot.display()
        )
    })?;
    if !screenshot_bytes.starts_with(b"P6\n") || screenshot_bytes.len() <= 64 {
        return Err(format!(
            "shell proof screenshot is not a valid non-empty PPM image: {}",
            screenshot.display()
        ));
    }
    println!(
        "shell proof: identity=true permissions=true privileged_denied=true privileged_admin=true cwd=true long_names=true relative_write=true relative_read=true ls=true screenshot_bytes={} status=ready",
        screenshot_bytes.len()
    );
    Ok(())
}

fn verify_terminal_proof(serial: &Path, screenshot: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial).map_err(|error| {
        format!(
            "reading terminal proof serial {}: {error}",
            serial.display()
        )
    })?;
    let required = [
        "login: account store ",
        "login: authentication ok",
        "desktop: credentials uid=1000 gid=1000 status=ready",
        "desktop: compositor framebuffer=ready scene=ready status=ready",
        "terminal: client surface=ready shell=spawned focus=ready status=ready",
        "terminal: shell credentials uid=1000 gid=1000 status=ready",
        "terminal: keyboard input routed status=ready",
        "terminal: shell command output=help status=ready",
        "terminal: shell id command output=ready",
        "terminal: exit input submitted status=ready",
        "terminal: shell exit acknowledged status=ready",
        "terminal: shell reaped status=ready",
    ];
    if !required.iter().all(|marker| content.contains(marker)) {
        return Err(format!(
            "terminal proof serial did not contain the complete focused shell, redirected output, and child-reap marker set: {}",
            serial.display()
        ));
    }
    let screenshot_bytes = fs::metadata(screenshot)
        .map_err(|error| {
            format!(
                "reading terminal proof screenshot {}: {error}",
                screenshot.display()
            )
        })?
        .len();
    if screenshot_bytes == 0 {
        return Err(format!(
            "terminal proof screenshot is empty: {}",
            screenshot.display()
        ));
    }
    println!(
        "terminal proof: account_store=true focused=true redirected_shell=true help_output=true shell_reaped=true screenshot_bytes={} status=ready",
        screenshot_bytes
    );
    Ok(())
}

fn verify_account_proof(serial: &Path, screenshot: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial)
        .map_err(|error| format!("reading account proof serial {}: {error}", serial.display()))?;
    let bootstrapped = content.contains("login: account store bootstrapped status=ready");
    let first_boot_setup = content.contains("login: account store setup required status=ready")
        && content.contains("login: first account configured username=user status=ready");
    let loaded = content.contains("login: account store loaded status=ready");
    let password_changed = content.contains("terminal: passwd changed status=ready")
        && content.contains("terminal: admin password updated status=ready");
    let account_created = content.contains("terminal: useradd account created status=ready");
    let admin_password_prompt = content.contains("terminal: useradd admin password prompt=ready");
    let non_admin_denied = content.contains("terminal: sudo authentication failed status=denied");
    let password_masked = content.contains("terminal: password input masked status=ready");
    let session_lock = content.contains("terminal: lock prompt=ready")
        && content.contains("terminal: lock authentication failed status=ready")
        && content.contains("terminal: lock unlocked status=ready")
        && content.contains("terminal: lock command status=ready");
    let authentication_failures = content.matches("login: authentication failed").count();
    let authenticated_sessions = content
        .matches("login: session authenticated number=")
        .count();
    let logout_sessions = content
        .matches("login: session exited status=ready")
        .count();
    let desktop_sessions = content
        .matches("desktop: compositor framebuffer=ready scene=ready status=ready")
        .count();
    let terminal_logouts = content
        .matches("terminal: logout requested status=ready")
        .count();
    let client_reaps = content
        .matches("desktop: session clients reaped status=ready")
        .count();
    let screenshot_bytes = fs::metadata(screenshot)
        .map_err(|error| {
            format!(
                "reading account proof screenshot {}: {error}",
                screenshot.display()
            )
        })?
        .len();
    let first_boot_ready = first_boot_setup
        && bootstrapped
        && password_changed
        && account_created
        && admin_password_prompt
        && non_admin_denied
        && password_masked
        && session_lock
        && authentication_failures >= 2
        && content.contains("login: username selected name=alice status=ready")
        && content.contains("login: authenticated username=alice status=ready")
        && non_admin_denied
        && content.contains("desktop: credentials uid=1001 gid=1001 status=ready")
        && content.contains("login: session authenticated number=2 status=ready")
        && authenticated_sessions >= 2
        && desktop_sessions >= 2
        && terminal_logouts >= 2
        && client_reaps >= 2
        && logout_sessions >= 2;
    let reload_ready = loaded
        && authentication_failures >= 1
        && content.contains("login: username selected name=alice status=ready")
        && content.contains("login: username selected name=user status=ready")
        && content.contains("login: authenticated username=alice status=ready")
        && content.contains("login: authenticated username=user status=ready")
        && content.contains("desktop: credentials uid=1001 gid=1001 status=ready")
        && content.contains("desktop: credentials uid=1000 gid=1000 status=ready")
        && content.contains("login: session authenticated number=1 status=ready")
        && content.contains("login: session authenticated number=2 status=ready")
        && authenticated_sessions >= 2
        && desktop_sessions >= 2
        && terminal_logouts >= 2
        && client_reaps >= 2
        && logout_sessions >= 2;
    if (!first_boot_ready && !reload_ready) || screenshot_bytes == 0 {
        return Err(format!(
            "account proof did not verify first-boot account setup, password mutation, multi-account login, session locking, authorization denial, or persistent reload: {}",
            serial.display()
        ));
    }
    let store = if bootstrapped {
        "bootstrapped"
    } else {
        "loaded"
    };
    println!(
        "account proof: store={} first_boot_setup={} password_changed={} account_created={} password_masked={} session_lock={} old_password_rejected={} sessions={} desktop_sessions={} terminal_logouts={} client_reaps={} logout_sessions={} screenshot_bytes={} status=ready",
        store,
        first_boot_setup,
        password_changed,
        account_created,
        password_masked,
        session_lock,
        authentication_failures >= if bootstrapped { 2 } else { 1 },
        authenticated_sessions,
        desktop_sessions,
        terminal_logouts,
        client_reaps,
        logout_sessions,
        screenshot_bytes
    );
    Ok(())
}

fn verify_logout_proof(serial: &Path, screenshot: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial)
        .map_err(|error| format!("reading logout proof serial {}: {error}", serial.display()))?;
    let required = [
        "login: authentication ok",
        "desktop: compositor framebuffer=ready scene=ready status=ready",
        "desktop: logout button pressed status=ready",
        "desktop: logout requested status=ready",
        "desktop: session clients reaped status=ready",
        "desktop: framebuffer released status=ready",
        "login: session exited status=ready",
        "login: ready for next session status=ready",
    ];
    if !required.iter().all(|marker| content.contains(marker)) {
        return Err(format!(
            "logout proof serial did not contain the desktop logout and login-boundary marker set: {}",
            serial.display()
        ));
    }
    let session_exit = content
        .find("login: session exited status=ready")
        .ok_or_else(|| "logout proof has no session-exit marker".to_owned())?;
    let login_ready = content
        .find("login: ready for next session status=ready")
        .ok_or_else(|| "logout proof has no post-logout login marker".to_owned())?;
    if login_ready <= session_exit {
        return Err(format!(
            "logout proof observed the next-login marker before the desktop session exited: {}",
            serial.display()
        ));
    }
    let screenshot_bytes = fs::read(screenshot).map_err(|error| {
        format!(
            "reading logout proof screenshot {}: {error}",
            screenshot.display()
        )
    })?;
    if !screenshot_bytes.starts_with(b"P6\n") || screenshot_bytes.len() <= 64 {
        return Err(format!(
            "logout proof screenshot is not a valid non-empty PPM image: {}",
            screenshot.display()
        ));
    }
    println!(
        "logout proof: button=true clients_reaped=true framebuffer_released=true login_ready=true screenshot_bytes={} status=ready",
        screenshot_bytes.len()
    );
    Ok(())
}

fn verify_role_proof(serial: &Path, screenshot: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial)
        .map_err(|error| format!("reading role proof serial {}: {error}", serial.display()))?;
    let required = [
        "terminal: useradd role prompt=ready",
        "terminal: administrator account created status=ready",
        "login: username selected name=bob status=ready",
        "login: authenticated username=bob status=ready",
        "desktop: credentials uid=1001 gid=1001 status=ready",
        "terminal: sudo state set status=ready",
        "desktop: session clients reaped status=ready",
        "login: session exited status=ready",
    ];
    if !required.iter().all(|marker| content.contains(marker)) {
        return Err(format!(
            "role proof serial did not contain the administrator-role creation, login, authorization, and logout markers: {}",
            serial.display()
        ));
    }
    let screenshot_bytes = fs::read(screenshot).map_err(|error| {
        format!(
            "reading role proof screenshot {}: {error}",
            screenshot.display()
        )
    })?;
    if !screenshot_bytes.starts_with(b"P6\n") || screenshot_bytes.len() <= 64 {
        return Err(format!(
            "role proof screenshot is not a valid non-empty PPM image: {}",
            screenshot.display()
        ));
    }
    println!(
        "role proof: administrator_created=true administrator_login=true privileged_allowed=true logout=true screenshot_bytes={} status=ready",
        screenshot_bytes.len()
    );
    Ok(())
}

fn verify_desktop_proof(serial: &Path, screenshot: &Path) -> Result<(), String> {
    let content = fs::read_to_string(serial)
        .map_err(|error| format!("reading desktop proof serial {}: {error}", serial.display()))?;
    let required = [
        "login: authentication ok",
        "desktop: credentials uid=1000 gid=1000 status=ready",
        "desktop: compositor framebuffer=ready scene=ready status=ready",
        "terminal: client surface=ready shell=spawned focus=ready status=ready",
        "terminal: shell credentials uid=1000 gid=1000 status=ready",
        "window: secondary client surface=ready presented=ready status=ready",
        "window: secondary storage snapshot=ready status=ready",
        "desktop: window focus raised status=ready",
        "window: secondary storage snapshot refreshed status=ready",
    ];
    if !required.iter().all(|marker| content.contains(marker)) {
        return Err(format!(
            "desktop proof serial did not contain the compositor, focused clients, and storage snapshot marker set: {}",
            serial.display()
        ));
    }
    let screenshot_bytes = fs::read(screenshot).map_err(|error| {
        format!(
            "reading desktop proof screenshot {}: {error}",
            screenshot.display()
        )
    })?;
    let screenshot_ready = screenshot_bytes.starts_with(b"P6\n") && screenshot_bytes.len() > 64;
    if !screenshot_ready {
        return Err(format!(
            "desktop proof screenshot is not a valid non-empty PPM image: {}",
            screenshot.display()
        ));
    }
    println!(
        "desktop proof: compositor=true focused_clients=true storage_snapshot=true refresh=true screenshot_bytes={} status=ready",
        screenshot_bytes.len()
    );
    Ok(())
}

fn nvme_interrupt_count(serial: &str) -> Option<u64> {
    serial.lines().find_map(|line| {
        if !line.starts_with("storage: nvme ") {
            return None;
        }
        line.split_whitespace().find_map(|field| {
            field
                .strip_prefix("interrupt_count=")
                .and_then(|count| count.parse::<u64>().ok())
        })
    })
}

fn virtio_interrupt_count(serial: &str) -> Option<u64> {
    serial.lines().find_map(|line| {
        if !line.starts_with("driver: virtio-net ") {
            return None;
        }
        line.split_whitespace().find_map(|field| {
            field
                .strip_prefix("interrupt_count=")
                .and_then(|count| count.parse::<u64>().ok())
        })
    })
}

fn wav_data(bytes: &[u8]) -> Result<(&[u8], u16, u32), String> {
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err("audio proof output is not a RIFF/WAVE file".to_owned());
    }

    let mut cursor = 12usize;
    let mut channels = None;
    let mut sample_rate = None;
    let mut data = None;
    while cursor < bytes.len() {
        let header_end = cursor
            .checked_add(8)
            .ok_or_else(|| "audio proof WAV chunk header overflowed".to_owned())?;
        if header_end > bytes.len() {
            return Err("audio proof WAV ended inside a chunk header".to_owned());
        }
        let chunk_length = usize::try_from(u32::from_le_bytes(
            bytes[cursor + 4..header_end].try_into().unwrap(),
        ))
        .map_err(|_| "audio proof WAV chunk length was not representable".to_owned())?;
        let chunk_end = header_end
            .checked_add(chunk_length)
            .ok_or_else(|| "audio proof WAV chunk length overflowed".to_owned())?;
        if chunk_end > bytes.len() {
            return Err("audio proof WAV ended inside a chunk".to_owned());
        }
        match &bytes[cursor..cursor + 4] {
            b"fmt " if chunk_length >= 16 => {
                let format =
                    u16::from_le_bytes(bytes[header_end..header_end + 2].try_into().unwrap());
                if format != 1 {
                    return Err(format!("audio proof WAV format is not PCM: {format}"));
                }
                channels = Some(u16::from_le_bytes(
                    bytes[header_end + 2..header_end + 4].try_into().unwrap(),
                ));
                sample_rate = Some(u32::from_le_bytes(
                    bytes[header_end + 4..header_end + 8].try_into().unwrap(),
                ));
            }
            b"data" => {
                if chunk_length == 0 {
                    // QEMU's wav backend can leave the data length placeholder at zero when the
                    // monitor `quit` command stops the VM. In that case the file extent is the
                    // only reliable data length, and the data chunk is necessarily last.
                    data = Some(&bytes[header_end..]);
                    break;
                }
                data = Some(&bytes[header_end..chunk_end]);
            }
            _ => {}
        }
        cursor = chunk_end
            .checked_add(chunk_length & 1)
            .ok_or_else(|| "audio proof WAV padding overflowed".to_owned())?;
    }

    let channels = channels.ok_or_else(|| "audio proof WAV has no PCM format chunk".to_owned())?;
    let sample_rate = sample_rate.ok_or_else(|| "audio proof WAV has no sample rate".to_owned())?;
    let data = data.ok_or_else(|| "audio proof WAV has no data chunk".to_owned())?;
    Ok((data, channels, sample_rate))
}

#[cfg(unix)]
fn read_monitor_response(monitor: &mut UnixStream) -> String {
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match monitor.read(&mut buffer) {
            Ok(0) => break,
            Ok(length) => {
                response.extend_from_slice(&buffer[..length]);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&response).into_owned()
}

#[cfg(unix)]
fn connect_monitor(path: &Path) -> Option<UnixStream> {
    for _ in 0..100 {
        match UnixStream::connect(path) {
            Ok(stream) => return Some(stream),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
    None
}

#[cfg(unix)]
fn send_login_credentials(monitor: &mut UnixStream, serial: &Path) -> bool {
    let Some(first_marker) = wait_for_serial_any(
        serial,
        &[
            "login: account store setup required status=ready",
            "RustOS login",
        ],
        Duration::from_secs(90),
    ) else {
        println!("login proof: prompt=false");
        return false;
    };
    if first_marker == 0 {
        if !send_login_keys(
            monitor,
            &[
                "sendkey u\n",
                "sendkey s\n",
                "sendkey e\n",
                "sendkey r\n",
                "sendkey ret\n",
                "sendkey r\n",
                "sendkey u\n",
                "sendkey s\n",
                "sendkey t\n",
                "sendkey o\n",
                "sendkey s\n",
                "sendkey ret\n",
                "sendkey r\n",
                "sendkey u\n",
                "sendkey s\n",
                "sendkey t\n",
                "sendkey o\n",
                "sendkey s\n",
                "sendkey ret\n",
            ],
        ) || !wait_for_serial_markers(
            serial,
            &["login: account store bootstrapped status=ready"],
            Duration::from_secs(30),
        ) {
            println!("login proof: first-boot-setup=false");
            return false;
        }
    }
    if !wait_for_serial_markers(serial, &["RustOS login"], Duration::from_secs(30)) {
        println!("login proof: prompt=false");
        return false;
    }
    if !send_login_keys(
        monitor,
        &[
            "sendkey u\n",
            "sendkey s\n",
            "sendkey e\n",
            "sendkey r\n",
            "sendkey ret\n",
            "sendkey w\n",
            "sendkey r\n",
            "sendkey o\n",
            "sendkey n\n",
            "sendkey g\n",
            "sendkey ret\n",
        ],
    ) {
        println!("login proof: invalid-input=false");
        return false;
    }
    let rejected = wait_for_serial_markers(
        serial,
        &["login: authentication failed"],
        Duration::from_secs(30),
    );
    if !rejected {
        println!("login proof: invalid-password-rejected=false");
        return false;
    }
    if !send_login_keys(
        monitor,
        &[
            "sendkey u\n",
            "sendkey s\n",
            "sendkey e\n",
            "sendkey r\n",
            "sendkey ret\n",
            "sendkey r\n",
            "sendkey u\n",
            "sendkey s\n",
            "sendkey t\n",
            "sendkey o\n",
            "sendkey s\n",
            "sendkey ret\n",
        ],
    ) {
        println!("login proof: input=false");
        return false;
    }
    let authenticated = wait_for_serial_markers(
        serial,
        &["login: authentication ok"],
        Duration::from_secs(30),
    );
    println!(
        "login proof: invalid_password_rejected={} authentication={authenticated}",
        rejected
    );
    authenticated
}

#[cfg(unix)]
fn send_login_keys(monitor: &mut UnixStream, commands: &[&str]) -> bool {
    for command in commands {
        if monitor.write_all(command.as_bytes()).is_err() {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
    true
}

#[cfg(unix)]
fn spawn_virtio_gpu_proof(path: PathBuf, screenshot: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(8));
        let Some(mut monitor) = connect_monitor(&path) else {
            println!("virtio-gpu proof: monitor=false");
            return;
        };
        if !send_login_credentials(&mut monitor, &serial) {
            return;
        }
        let ready = wait_for_serial_markers(
            &serial,
            &[
                "driver: virtio-gpu ",
                "gpu: scanout=0 resource=1",
                "gpu: frame transfers=",
                "desktop: compositor framebuffer=ready scene=ready status=ready",
            ],
            Duration::from_secs(90),
        );
        println!("virtio-gpu proof: guest_ready={ready}");
        if !ready {
            return;
        }
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_secs(1));
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_terminal_proof(path: PathBuf, screenshot: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(8));
        let Some(mut monitor) = connect_monitor(&path) else {
            println!("terminal proof: monitor=false");
            return;
        };
        if !send_login_credentials(&mut monitor, &serial) {
            return;
        }
        let ready = wait_for_serial_markers(
            &serial,
            &[
                "desktop: compositor framebuffer=ready scene=ready status=ready",
                "terminal: client surface=ready shell=spawned focus=ready status=ready",
                "terminal: shell output received status=ready",
            ],
            Duration::from_secs(90),
        );
        println!("terminal proof: guest_ready={ready}");
        if !ready {
            return;
        }
        for command in [
            "sendkey h\n",
            "sendkey e\n",
            "sendkey l\n",
            "sendkey p\n",
            "sendkey ret\n",
            "sendkey ret\n",
        ] {
            if monitor.write_all(command.as_bytes()).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
        let command_ready = wait_for_serial_markers(
            &serial,
            &["terminal: shell command output=help status=ready"],
            Duration::from_secs(30),
        );
        println!("terminal proof: help_command={command_ready}");
        for command in ["sendkey i\n", "sendkey d\n", "sendkey ret\n"] {
            if monitor.write_all(command.as_bytes()).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
        let id_ready = wait_for_serial_markers(
            &serial,
            &["terminal: shell id command output=ready"],
            Duration::from_secs(30),
        );
        println!("terminal proof: id_command={id_ready}");
        thread::sleep(Duration::from_secs(3));
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_secs(2));
        let send_exit = |monitor: &mut UnixStream| {
            for command in [
                "sendkey e\n",
                "sendkey x\n",
                "sendkey i\n",
                "sendkey t\n",
                "sendkey ret\n",
            ] {
                if monitor.write_all(command.as_bytes()).is_err() {
                    return false;
                }
                thread::sleep(Duration::from_millis(500));
            }
            true
        };
        if !send_exit(&mut monitor) {
            return;
        }
        let mut exit_requested = wait_for_serial_markers(
            &serial,
            &[
                "terminal: exit input submitted status=ready",
                "terminal: shell exit acknowledged status=ready",
            ],
            Duration::from_secs(5),
        );
        if !exit_requested {
            if !send_exit(&mut monitor) {
                return;
            }
            exit_requested = wait_for_serial_markers(
                &serial,
                &[
                    "terminal: exit input submitted status=ready",
                    "terminal: shell exit acknowledged status=ready",
                ],
                Duration::from_secs(30),
            );
        }
        println!("terminal proof: exit_command={exit_requested}");
        let shell_exited = wait_for_serial_markers(
            &serial,
            &["terminal: shell reaped status=ready"],
            Duration::from_secs(30),
        );
        println!("terminal proof: shell_reaped={shell_exited}");
        thread::sleep(Duration::from_millis(500));
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_account_proof(path: PathBuf, screenshot: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(8));
        let Some(mut monitor) = connect_monitor(&path) else {
            println!("account proof: monitor=false");
            return;
        };
        let store_ready =
            wait_for_serial_markers(&serial, &["login: account store "], Duration::from_secs(90));
        println!("account proof: store_marker={store_ready}");
        if !store_ready {
            let _ = monitor.write_all(b"quit\n");
            return;
        }
        let serial_before_login = fs::read_to_string(&serial).unwrap_or_default();
        let first_boot = serial_before_login.contains("login: account store setup required");
        if first_boot {
            if !send_login_credentials(&mut monitor, &serial) {
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            let first_session = wait_for_serial_markers(
                &serial,
                &[
                    "login: session authenticated number=1 status=ready",
                    "desktop: compositor framebuffer=ready scene=ready status=ready",
                    "terminal: client surface=ready shell=spawned focus=ready status=ready",
                    "terminal: shell output received status=ready",
                ],
                Duration::from_secs(90),
            );
            println!("account proof: first_session={first_session}");
            thread::sleep(Duration::from_secs(2));
            if !first_session
                || !send_account_command(&mut monitor, "passwd")
                || !wait_for_serial_markers(
                    &serial,
                    &["terminal: passwd current prompt=ready"],
                    Duration::from_secs(30),
                )
                || !send_account_input(&mut monitor, "rustos")
                || !wait_for_serial_markers(
                    &serial,
                    &["terminal: passwd new prompt=ready"],
                    Duration::from_secs(30),
                )
                || !send_account_input(&mut monitor, "daily-use")
                || !wait_for_serial_markers(
                    &serial,
                    &["terminal: passwd confirm prompt=ready"],
                    Duration::from_secs(30),
                )
                || !send_account_input(&mut monitor, "daily-use")
                || !wait_for_serial_markers(
                    &serial,
                    &[
                        "terminal: admin password updated status=ready",
                        "terminal: passwd changed status=ready",
                    ],
                    Duration::from_secs(30),
                )
            {
                println!("account proof: password_change=false");
                capture_account_proof_screenshot(&mut monitor, &screenshot);
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            println!("account proof: password_change=true");
            let account_created = send_account_command(&mut monitor, "sudo useradd")
                && wait_for_serial_markers(
                    &serial,
                    &["terminal: useradd admin password prompt=ready"],
                    Duration::from_secs(30),
                )
                && send_account_input(&mut monitor, "daily-use")
                && wait_for_serial_markers(
                    &serial,
                    &["terminal: useradd username prompt=ready"],
                    Duration::from_secs(30),
                )
                && send_account_command(&mut monitor, "alice")
                && wait_for_serial_markers(
                    &serial,
                    &["terminal: useradd password prompt=ready"],
                    Duration::from_secs(30),
                )
                && send_account_input(&mut monitor, "alice-pass")
                && wait_for_serial_markers(
                    &serial,
                    &["terminal: useradd confirm prompt=ready"],
                    Duration::from_secs(30),
                )
                && send_account_input(&mut monitor, "alice-pass")
                && wait_for_serial_markers(
                    &serial,
                    &["terminal: useradd role prompt=ready"],
                    Duration::from_secs(30),
                )
                && send_account_input(&mut monitor, "user")
                && wait_for_serial_markers(
                    &serial,
                    &["terminal: useradd account created status=ready"],
                    Duration::from_secs(30),
                );
            println!("account proof: account_created={account_created}");
            if !account_created {
                capture_account_proof_screenshot(&mut monitor, &screenshot);
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            let session_lock = send_account_command(&mut monitor, "lock")
                && wait_for_serial_markers(
                    &serial,
                    &["terminal: lock prompt=ready"],
                    Duration::from_secs(30),
                )
                && send_account_input(&mut monitor, "wrong")
                && wait_for_serial_markers(
                    &serial,
                    &["terminal: lock authentication failed status=ready"],
                    Duration::from_secs(30),
                )
                && send_account_input(&mut monitor, "daily-use")
                && wait_for_serial_markers(
                    &serial,
                    &[
                        "terminal: lock unlocked status=ready",
                        "terminal: lock command status=ready",
                    ],
                    Duration::from_secs(30),
                );
            println!("account proof: session_lock={session_lock}");
            if !session_lock {
                capture_account_proof_screenshot(&mut monitor, &screenshot);
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            if !send_account_input(&mut monitor, "exit")
                || !wait_for_serial_occurrences(
                    &serial,
                    "desktop: session clients reaped status=ready",
                    1,
                    Duration::from_secs(30),
                )
                || !wait_for_serial_occurrences(
                    &serial,
                    "login: session exited status=ready",
                    1,
                    Duration::from_secs(30),
                )
            {
                println!("account proof: first_logout=false");
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            if !send_login_command(&mut monitor, "user")
                || !send_login_command(&mut monitor, "rustos")
                || !wait_for_serial_occurrences(
                    &serial,
                    "login: authentication failed",
                    2,
                    Duration::from_secs(30),
                )
            {
                println!("account proof: old_password_rejected=false");
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            println!("account proof: old_password_rejected=true");
            if !send_login_command(&mut monitor, "alice")
                || !send_login_command(&mut monitor, "alice-pass")
                || !wait_for_serial_markers(
                    &serial,
                    &[
                        "login: username selected name=alice status=ready",
                        "login: authenticated username=alice status=ready",
                        "login: session authenticated number=2 status=ready",
                        "desktop: credentials uid=1001 gid=1001 status=ready",
                        "desktop: compositor framebuffer=ready scene=ready status=ready",
                        "terminal: client surface=ready shell=spawned focus=ready status=ready",
                    ],
                    Duration::from_secs(30),
                )
            {
                println!("account proof: alice_login=false");
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            println!("account proof: alice_login=true");
            let alice_denied = prove_non_admin_sudo_denied(&mut monitor, &serial);
            println!("account proof: alice_privileged_denied={alice_denied}");
            if !alice_denied {
                let _ = monitor.write_all(b"quit\n");
                return;
            }
        } else {
            if !send_login_command(&mut monitor, "user")
                || !send_login_command(&mut monitor, "rustos")
                || !wait_for_serial_occurrences(
                    &serial,
                    "login: authentication failed",
                    1,
                    Duration::from_secs(30),
                )
            {
                println!("account proof: reloaded_password_login=false");
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            println!("account proof: reloaded_old_password_rejected=true");
            if !send_login_command(&mut monitor, "alice")
                || !send_login_command(&mut monitor, "alice-pass")
                || !wait_for_serial_markers(
                    &serial,
                    &[
                        "login: username selected name=alice status=ready",
                        "login: authenticated username=alice status=ready",
                        "login: session authenticated number=1 status=ready",
                        "desktop: credentials uid=1001 gid=1001 status=ready",
                        "desktop: compositor framebuffer=ready scene=ready status=ready",
                        "terminal: client surface=ready shell=spawned focus=ready status=ready",
                    ],
                    Duration::from_secs(90),
                )
                || !send_account_input(&mut monitor, "exit")
                || !wait_for_serial_occurrences(
                    &serial,
                    "desktop: session clients reaped status=ready",
                    1,
                    Duration::from_secs(30),
                )
                || !wait_for_serial_occurrences(
                    &serial,
                    "login: session exited status=ready",
                    1,
                    Duration::from_secs(30),
                )
                || !send_login_command(&mut monitor, "user")
                || !send_login_command(&mut monitor, "daily-use")
                || !wait_for_serial_markers(
                    &serial,
                    &[
                        "login: username selected name=user status=ready",
                        "login: authenticated username=user status=ready",
                        "login: session authenticated number=2 status=ready",
                    ],
                    Duration::from_secs(30),
                )
            {
                println!("account proof: reloaded_multi_account_login=false");
                let _ = monitor.write_all(b"quit\n");
                return;
            }
            println!("account proof: reloaded_multi_account_login=true");
            let alice_denied = prove_non_admin_sudo_denied(&mut monitor, &serial);
            println!("account proof: alice_privileged_denied={alice_denied}");
            if !alice_denied {
                let _ = monitor.write_all(b"quit\n");
                return;
            }
        }

        let session_count = 2;
        let desktop_ready = wait_for_serial_occurrences(
            &serial,
            "desktop: compositor framebuffer=ready scene=ready status=ready",
            session_count,
            Duration::from_secs(90),
        ) && wait_for_serial_occurrences(
            &serial,
            "terminal: client surface=ready shell=spawned focus=ready status=ready",
            session_count,
            Duration::from_secs(90),
        ) && wait_for_serial_occurrences(
            &serial,
            "terminal: shell output received status=ready",
            session_count,
            Duration::from_secs(90),
        );
        println!("account proof: desktop_ready={desktop_ready}");
        if desktop_ready {
            let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
            thread::sleep(Duration::from_secs(1));
        }
        let logged_out = desktop_ready
            && send_account_input(&mut monitor, "exit")
            && wait_for_serial_occurrences(
                &serial,
                "desktop: session clients reaped status=ready",
                session_count,
                Duration::from_secs(30),
            )
            && wait_for_serial_occurrences(
                &serial,
                "login: session exited status=ready",
                session_count,
                Duration::from_secs(30),
            );
        println!("account proof: logout={logged_out}");
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn capture_account_proof_screenshot(monitor: &mut UnixStream, screenshot: &Path) {
    let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
    thread::sleep(Duration::from_secs(1));
}

#[cfg(unix)]
fn prove_non_admin_sudo_denied(monitor: &mut UnixStream, serial: &Path) -> bool {
    thread::sleep(Duration::from_secs(1));
    send_account_command(monitor, "sudo state set")
        && wait_for_serial_markers(
            serial,
            &["terminal: sudo password prompt=ready"],
            Duration::from_secs(30),
        )
        && send_account_input(monitor, "alice-pass")
        && wait_for_serial_markers(
            serial,
            &["terminal: sudo authentication failed status=denied"],
            Duration::from_secs(30),
        )
}

#[cfg(unix)]
fn spawn_logout_proof(
    path: PathBuf,
    screenshot: PathBuf,
    serial: PathBuf,
    uefi: bool,
) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(8));
        let Some(mut monitor) = connect_monitor(&path) else {
            println!("logout proof: monitor=false");
            return;
        };
        if !send_login_credentials(&mut monitor, &serial) {
            return;
        }
        let ready = wait_for_serial_markers(
            &serial,
            &[
                "desktop: compositor framebuffer=ready scene=ready status=ready",
                "terminal: client surface=ready shell=spawned focus=ready status=ready",
                "window: secondary client surface=ready presented=ready status=ready",
            ],
            Duration::from_secs(90),
        );
        println!("logout proof: guest_ready={ready}");
        if !ready {
            return;
        }
        thread::sleep(Duration::from_secs(2));
        if monitor
            .write_all(format!("screendump {}\n", screenshot.display()).as_bytes())
            .is_err()
        {
            return;
        }
        thread::sleep(Duration::from_secs(1));
        let vertical_move = if uefi { -360 } else { -320 };
        for command in [
            format!("mouse_move 500 {vertical_move}\n"),
            "mouse_button 1\n".to_owned(),
            "mouse_button 0\n".to_owned(),
        ] {
            if monitor.write_all(command.as_bytes()).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
        let logged_out = wait_for_serial_markers(
            &serial,
            &[
                "desktop: logout button pressed status=ready",
                "desktop: logout requested status=ready",
                "desktop: session clients reaped status=ready",
                "desktop: framebuffer released status=ready",
                "login: session exited status=ready",
                "login: ready for next session status=ready",
            ],
            Duration::from_secs(45),
        );
        println!("logout proof: login_boundary={logged_out}");
        thread::sleep(Duration::from_secs(1));
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_role_proof(path: PathBuf, screenshot: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(8));
        let Some(mut monitor) = connect_monitor(&path) else {
            println!("role proof: monitor=false");
            return;
        };
        if !send_login_credentials(&mut monitor, &serial) {
            return;
        }
        let first_ready = wait_for_serial_markers(
            &serial,
            &[
                "desktop: compositor framebuffer=ready scene=ready status=ready",
                "terminal: client surface=ready shell=spawned focus=ready status=ready",
            ],
            Duration::from_secs(90),
        );
        println!("role proof: first_session={first_ready}");
        if !first_ready {
            let _ = monitor.write_all(b"quit\n");
            return;
        }

        let administrator_created = send_account_command(&mut monitor, "sudo useradd")
            && wait_for_serial_markers(
                &serial,
                &["terminal: useradd admin password prompt=ready"],
                Duration::from_secs(30),
            )
            && send_account_input(&mut monitor, "rustos")
            && wait_for_serial_markers(
                &serial,
                &["terminal: useradd username prompt=ready"],
                Duration::from_secs(30),
            )
            && send_account_input(&mut monitor, "bob")
            && wait_for_serial_markers(
                &serial,
                &["terminal: useradd password prompt=ready"],
                Duration::from_secs(30),
            )
            && send_account_input(&mut monitor, "bob-pass")
            && wait_for_serial_markers(
                &serial,
                &["terminal: useradd confirm prompt=ready"],
                Duration::from_secs(30),
            )
            && send_account_input(&mut monitor, "bob-pass")
            && wait_for_serial_markers(
                &serial,
                &["terminal: useradd role prompt=ready"],
                Duration::from_secs(30),
            )
            && send_account_input(&mut monitor, "admin")
            && wait_for_serial_markers(
                &serial,
                &["terminal: administrator account created status=ready"],
                Duration::from_secs(30),
            );
        println!("role proof: administrator_created={administrator_created}");
        if !administrator_created
            || !send_account_input(&mut monitor, "exit")
            || !wait_for_serial_occurrences(
                &serial,
                "login: session exited status=ready",
                1,
                Duration::from_secs(30),
            )
        {
            let _ = monitor.write_all(b"quit\n");
            return;
        }

        let bob_login = send_login_command(&mut monitor, "bob")
            && send_login_command(&mut monitor, "bob-pass")
            && wait_for_serial_markers(
                &serial,
                &[
                    "login: username selected name=bob status=ready",
                    "login: authenticated username=bob status=ready",
                    "login: session authenticated number=2 status=ready",
                    "desktop: credentials uid=1001 gid=1001 status=ready",
                    "terminal: client surface=ready shell=spawned focus=ready status=ready",
                ],
                Duration::from_secs(90),
            );
        println!("role proof: administrator_login={bob_login}");
        if !bob_login {
            let _ = monitor.write_all(b"quit\n");
            return;
        }
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_secs(1));
        let privileged_allowed = send_account_command(&mut monitor, "sudo state set")
            && wait_for_serial_markers(
                &serial,
                &["terminal: sudo password prompt=ready"],
                Duration::from_secs(30),
            )
            && send_account_input(&mut monitor, "bob-pass")
            && wait_for_serial_markers(
                &serial,
                &["terminal: sudo state set status=ready"],
                Duration::from_secs(30),
            );
        println!("role proof: privileged_allowed={privileged_allowed}");
        if privileged_allowed {
            let _ = send_account_input(&mut monitor, "exit");
            let _ = wait_for_serial_occurrences(
                &serial,
                "desktop: session clients reaped status=ready",
                2,
                Duration::from_secs(30),
            );
            let _ = wait_for_serial_occurrences(
                &serial,
                "login: session exited status=ready",
                2,
                Duration::from_secs(30),
            );
        }
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_desktop_proof(path: PathBuf, screenshot: PathBuf, serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(8));
        let Some(mut monitor) = connect_monitor(&path) else {
            println!("desktop proof: monitor=false");
            return;
        };
        if !send_login_credentials(&mut monitor, &serial) {
            return;
        }
        let ready = wait_for_serial_markers(
            &serial,
            &[
                "desktop: compositor framebuffer=ready scene=ready status=ready",
                "terminal: client surface=ready shell=spawned focus=ready status=ready",
                "window: secondary client surface=ready presented=ready status=ready",
                "window: secondary storage snapshot=ready status=ready",
                "window: secondary storage snapshot refreshed status=ready",
            ],
            Duration::from_secs(90),
        );
        println!("desktop proof: guest_ready={ready}");
        if !ready {
            return;
        }
        thread::sleep(Duration::from_secs(2));
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_secs(2));
        for (index, command) in [
            "mouse_button 1\n",
            "mouse_move 100 50\n",
            "mouse_button 0\n",
            "mouse_move 250 -50\n",
            "mouse_button 1\n",
            "mouse_move 20 0\n",
            "mouse_button 0\n",
            "mouse_move 190 160\n",
            "mouse_button 1\n",
            "mouse_move 100 100\n",
            "mouse_button 0\n",
        ]
        .into_iter()
        .enumerate()
        {
            if monitor.write_all(command.as_bytes()).is_err() {
                return;
            }
            thread::sleep(if index == 2 || index == 8 {
                Duration::from_millis(800)
            } else {
                Duration::from_millis(250)
            });
        }
        thread::sleep(Duration::from_secs(10));
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(unix)]
fn spawn_usb_hotplug_proof(
    path: PathBuf,
    screenshot: PathBuf,
    serial: PathBuf,
    nested: bool,
) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(8));
        let Some(mut monitor) = connect_monitor(&path) else {
            println!("USB hotplug proof: monitor=false");
            return;
        };
        if !send_login_credentials(&mut monitor, &serial) {
            return;
        }
        let add_command = if nested {
            "device_add usb-mouse,bus=xhci.0,port=1.1.2,id=hotmouse\n"
        } else {
            "device_add usb-mouse,bus=xhci.0,port=1.2,id=hotmouse\n"
        };
        if monitor.write_all(add_command.as_bytes()).is_err() {
            return;
        }
        thread::sleep(Duration::from_secs(5));
        for command in [
            "mouse_move -220 -80\n",
            "mouse_button 1\n",
            "mouse_move 100 50\n",
            "mouse_button 0\n",
            "mouse_move 220 30\n",
        ] {
            if monitor.write_all(command.as_bytes()).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
        thread::sleep(Duration::from_secs(4));
        let _ = monitor.write_all(format!("screendump {}\n", screenshot.display()).as_bytes());
        thread::sleep(Duration::from_secs(1));
        let _ = monitor.write_all(b"device_del hotmouse\n");
        thread::sleep(Duration::from_secs(4));
        let _ = monitor.write_all(b"quit\n");
    })
}

#[cfg(not(unix))]
fn spawn_keyboard_proof(
    _path: PathBuf,
    _screenshot: PathBuf,
    _serial: Option<PathBuf>,
) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_poweroff_proof(_path: PathBuf, _screenshot: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_reboot_proof(_path: PathBuf, _screenshot: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_suspend_proof(
    _path: PathBuf,
    _screenshot: PathBuf,
    _state: Arc<AtomicUsize>,
    _native_suspend_proof: bool,
) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_virtio_gpu_proof(
    _path: PathBuf,
    _screenshot: PathBuf,
    _serial: PathBuf,
) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_logout_proof(
    _path: PathBuf,
    _screenshot: PathBuf,
    _serial: PathBuf,
    _uefi: bool,
) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_role_proof(_path: PathBuf, _screenshot: PathBuf, _serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_desktop_proof(_path: PathBuf, _screenshot: PathBuf, _serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_terminal_proof(_path: PathBuf, _screenshot: PathBuf, _serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_usb_hotplug_proof(
    _path: PathBuf,
    _screenshot: PathBuf,
    _serial: PathBuf,
    _nested: bool,
) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_virtio_network_proof(_path: PathBuf, _serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_nvme_interrupt_proof(_path: PathBuf, _serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_ahci_interrupt_proof(_path: PathBuf, _serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_vm_proof(_path: PathBuf, _serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_smp_proof(_path: PathBuf, _serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[cfg(not(unix))]
fn spawn_pipe_proof(_path: PathBuf, _screenshot: PathBuf, _serial: PathBuf) -> JoinHandle<()> {
    thread::spawn(|| {})
}

fn install_image(source: &Path, target: &Path, force: bool) -> Result<(), String> {
    let image = fs::read(source)
        .map_err(|error| format!("reading installer source {}: {error}", source.display()))?;
    if image.is_empty() {
        return Err(format!("installer source is empty: {}", source.display()));
    }
    let digest = sha256(&image);
    let target_exists = target.exists();
    let target_is_block = if target_exists {
        let metadata = fs::metadata(target)
            .map_err(|error| format!("reading installer target {}: {error}", target.display()))?;
        if metadata.is_dir() {
            return Err(format!(
                "installer target is a directory: {}",
                target.display()
            ));
        }
        #[cfg(unix)]
        {
            metadata.file_type().is_block_device()
        }
        #[cfg(not(unix))]
        {
            false
        }
    } else {
        false
    };
    if target_exists && !force {
        return Err(format!(
            "installer target exists; pass --force to replace it: {}",
            target.display()
        ));
    }
    if let Some(parent) = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if !parent.is_dir() {
            return Err(format!(
                "installer target parent is not a directory: {}",
                parent.display()
            ));
        }
    }

    let mut output = if target_is_block {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(target)
            .map_err(|error| {
                format!(
                    "opening installer block target {}: {error}",
                    target.display()
                )
            })?
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(target)
            .map_err(|error| format!("opening installer target {}: {error}", target.display()))?
    };
    output
        .write_all(&image)
        .map_err(|error| format!("writing installer target {}: {error}", target.display()))?;
    output
        .sync_all()
        .map_err(|error| format!("syncing installer target {}: {error}", target.display()))?;

    if target_is_block {
        let sample_length = image.len().min(4096);
        let mut first = vec![0u8; sample_length];
        output
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|error| format!("seeking installer target {}: {error}", target.display()))?;
        output
            .read_exact(&mut first)
            .map_err(|error| format!("reading installer target {}: {error}", target.display()))?;
        if first != image[..sample_length] {
            return Err(format!(
                "installer target verification failed at the first block: {}",
                target.display()
            ));
        }
        let tail_offset = image.len().saturating_sub(sample_length) as u64;
        let mut tail = vec![0u8; sample_length];
        output
            .seek(std::io::SeekFrom::Start(tail_offset))
            .map_err(|error| format!("seeking installer target {}: {error}", target.display()))?;
        output
            .read_exact(&mut tail)
            .map_err(|error| format!("reading installer target {}: {error}", target.display()))?;
        if tail != image[image.len() - sample_length..] {
            return Err(format!(
                "installer target verification failed at the image tail: {}",
                target.display()
            ));
        }
    } else {
        output
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|error| format!("seeking installer target {}: {error}", target.display()))?;
        let mut installed = Vec::with_capacity(image.len());
        output
            .read_to_end(&mut installed)
            .map_err(|error| format!("reading installer target {}: {error}", target.display()))?;
        if installed != image {
            return Err(format!(
                "installer target verification failed: {}",
                target.display()
            ));
        }
    }
    println!(
        "installer: source={} target={} bytes={} sha256={} verification=ready",
        source.display(),
        target.display(),
        image.len(),
        format_digest(&digest)
    );
    Ok(())
}

fn install_partitioned_image(source: &Path, target: &Path, force: bool) -> Result<(), String> {
    let (target_exists, target_is_block) = installer_target_kind(target)?;
    if target_exists && !force {
        return Err(format!(
            "installer target exists; pass --force to repartition it: {}",
            target.display()
        ));
    }
    if let Some(parent) = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if !parent.is_dir() {
            return Err(format!(
                "installer target parent is not a directory: {}",
                parent.display()
            ));
        }
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let prefix = format!("rustos-install-{}-{timestamp}", std::process::id());
    let esp_path = env::temp_dir().join(format!("{prefix}-esp.img"));
    let root_path = env::temp_dir().join(format!("{prefix}-root.img"));
    let result = (|| {
        extract_gpt_partition(source, 1, &esp_path)?;
        extract_gpt_partition(source, 2, &root_path)?;
        let minimum_size = fs::metadata(&esp_path)
            .map_err(|error| format!("reading extracted EFI partition: {error}"))?
            .len()
            .checked_add(
                fs::metadata(&root_path)
                    .map_err(|error| format!("reading extracted RustOS root partition: {error}"))?
                    .len(),
            )
            .and_then(|size| size.checked_add(4 * 1024 * 1024))
            .ok_or_else(|| "partitioned installer size overflowed".to_owned())?;

        let mut output = if target_is_block {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(target)
                .map_err(|error| {
                    format!(
                        "opening installer block target {}: {error}",
                        target.display()
                    )
                })?
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(target)
                .map_err(|error| {
                    format!("opening installer target {}: {error}", target.display())
                })?
        };
        let disk_size = if target_is_block {
            output
                .metadata()
                .map_err(|error| format!("reading installer target capacity: {error}"))?
                .len()
        } else {
            output.set_len(minimum_size).map_err(|error| {
                format!("sizing installer target {}: {error}", target.display())
            })?;
            minimum_size
        };
        if target_is_block && disk_size < minimum_size {
            return Err(format!(
                "installer block target is too small: {} bytes available, {} required",
                disk_size, minimum_size
            ));
        }
        let layout = write_gpt_layout(&mut output, disk_size, &esp_path, &root_path, target)?;
        output
            .sync_all()
            .map_err(|error| format!("syncing installer target {}: {error}", target.display()))?;
        drop(output);

        verify_partitioned_target(target, layout, &esp_path, &root_path)?;
        println!(
            "installer: source={} target={} bytes={} table=gpt esp_sha256={} root_sha256={} repartition=ready verification=ready",
            source.display(),
            target.display(),
            layout.disk_size,
            format_digest(&sha256_file(&esp_path)?),
            format_digest(&sha256_file(&root_path)?),
        );
        Ok(())
    })();
    let _ = fs::remove_file(&esp_path);
    let _ = fs::remove_file(&root_path);
    result
}

fn installer_target_kind(target: &Path) -> Result<(bool, bool), String> {
    if !target.exists() {
        return Ok((false, false));
    }
    let metadata = fs::metadata(target)
        .map_err(|error| format!("reading installer target {}: {error}", target.display()))?;
    if metadata.is_dir() {
        return Err(format!(
            "installer target is a directory: {}",
            target.display()
        ));
    }
    #[cfg(unix)]
    let is_block = metadata.file_type().is_block_device();
    #[cfg(not(unix))]
    let is_block = false;
    Ok((true, is_block))
}

fn extract_gpt_partition(
    source: &Path,
    partition_id: u32,
    destination: &Path,
) -> Result<(), String> {
    let table = gpt::GptConfig::new()
        .writable(false)
        .initialized(true)
        .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
        .open(source)
        .map_err(|error| format!("opening GPT source {}: {error}", source.display()))?;
    let partition = table
        .partitions()
        .get(&partition_id)
        .ok_or_else(|| format!("GPT source is missing partition {partition_id}"))?
        .clone();
    let sectors = partition
        .last_lba
        .checked_sub(partition.first_lba)
        .and_then(|sectors| sectors.checked_add(1))
        .ok_or_else(|| format!("GPT source partition {partition_id} has an invalid range"))?;
    let bytes = sectors
        .checked_mul(512)
        .ok_or_else(|| format!("GPT source partition {partition_id} is too large"))?;
    drop(table);

    let mut input = OpenOptions::new()
        .read(true)
        .open(source)
        .map_err(|error| format!("reading GPT source {}: {error}", source.display()))?;
    input
        .seek(SeekFrom::Start(partition.first_lba * 512))
        .map_err(|error| format!("seeking GPT source {}: {error}", source.display()))?;
    let mut limited = input.take(bytes);
    let mut output = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(destination)
        .map_err(|error| {
            format!(
                "creating extracted partition {}: {error}",
                destination.display()
            )
        })?;
    let copied = std::io::copy(&mut limited, &mut output)
        .map_err(|error| format!("extracting GPT partition {partition_id}: {error}"))?;
    if copied != bytes {
        return Err(format!(
            "extracted GPT partition {partition_id} is short: {} of {} bytes",
            copied, bytes
        ));
    }
    output.sync_all().map_err(|error| {
        format!(
            "syncing extracted partition {}: {error}",
            destination.display()
        )
    })
}

fn verify_partitioned_target(
    target: &Path,
    layout: GptLayout,
    esp_path: &Path,
    root_path: &Path,
) -> Result<(), String> {
    let table = gpt::GptConfig::new()
        .writable(false)
        .initialized(true)
        .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
        .open(target)
        .map_err(|error| format!("reading installed GPT target {}: {error}", target.display()))?;
    let esp = table.partitions().get(&1).ok_or_else(|| {
        format!(
            "installed target has no EFI System Partition: {}",
            target.display()
        )
    })?;
    let root = table.partitions().get(&2).ok_or_else(|| {
        format!(
            "installed target has no RustOS root partition: {}",
            target.display()
        )
    })?;
    if esp.name != "EFI System"
        || root.name != "RustOS root"
        || esp.first_lba != layout.esp_start / 512
        || root.first_lba != layout.root_start / 512
        || esp.last_lba + 1 - esp.first_lba != layout.esp_size / 512
        || root.last_lba + 1 - root.first_lba != layout.root_size / 512
    {
        return Err(format!(
            "installed GPT layout does not match the requested ESP/root geometry: {}",
            target.display()
        ));
    }
    drop(table);

    let expected_esp = sha256_file(esp_path)?;
    let expected_root = sha256_file(root_path)?;
    let actual_esp = sha256_file_range(target, layout.esp_start, layout.esp_size)?;
    let actual_root = sha256_file_range(target, layout.root_start, layout.root_size)?;
    if expected_esp != actual_esp || expected_root != actual_root {
        return Err(format!(
            "installed GPT partition readback hash mismatch: {}",
            target.display()
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| format!("opening {} for hashing: {error}", path.display()))?;
    sha256_reader(&mut file, None, path)
}

fn sha256_file_range(path: &Path, offset: u64, length: u64) -> Result<[u8; 32], String> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| format!("opening {} for readback hashing: {error}", path.display()))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| format!("seeking {} for readback hashing: {error}", path.display()))?;
    sha256_reader(&mut file, Some(length), path)
}

fn sha256_reader<R: Read>(
    reader: &mut R,
    mut remaining: Option<u64>,
    path: &Path,
) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let requested = remaining
            .map(|bytes| bytes.min(buffer.len() as u64) as usize)
            .unwrap_or(buffer.len());
        if requested == 0 {
            break;
        }
        let count = reader
            .read(&mut buffer[..requested])
            .map_err(|error| format!("hashing {}: {error}", path.display()))?;
        if count == 0 {
            if remaining.is_some() {
                return Err(format!("short read while hashing {}", path.display()));
            }
            break;
        }
        hasher.update(&buffer[..count]);
        if let Some(bytes) = remaining.as_mut() {
            *bytes -= count as u64;
        }
    }
    if remaining != Some(0) && remaining.is_some() {
        return Err(format!("short read while hashing {}", path.display()));
    }
    let digest = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    Ok(result)
}

fn format_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

struct RepositoryServer {
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl RepositoryServer {
    fn start() -> Result<Self, String> {
        const PORT: u16 = 19_000;
        let socket = UdpSocket::bind(("0.0.0.0", PORT))
            .map_err(|error| format!("binding repository server UDP port {PORT}: {error}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|error| format!("configuring repository server timeout: {error}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let repository = build_repository();
        let thread = thread::spawn(move || {
            let mut request = [0u8; 64];
            while !thread_stop.load(Ordering::Acquire) {
                match socket.recv_from(&mut request) {
                    Ok((length, source)) => {
                        if &request[..length] == b"RUSTOS.REP2\0" {
                            socket
                                .send_to(&repository, source)
                                .map_err(|error| format!("sending repository response: {error}"))?;
                            thread_requests.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(error) => return Err(format!("receiving repository request: {error}")),
                }
            }
            Ok(())
        });
        println!("network: RustOS repository server listening on 0.0.0.0:{PORT}");
        Ok(Self {
            stop,
            requests,
            thread: Some(thread),
        })
    }

    fn stop(mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| "repository server thread panicked".to_owned())??;
        }
        println!(
            "network: repository server requests={}",
            self.requests.load(Ordering::Acquire)
        );
        Ok(())
    }
}

fn run_command(command: &mut Command, operation: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("{operation}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{operation}: process exited with {status}"))
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live directly under the workspace root")
        .to_path_buf()
}

fn target_dir(root: &PathBuf) -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR") {
        Some(path) => {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                root.join(path)
            }
        }
        None => root.join("target"),
    }
}

fn kernel_path(root: &PathBuf, release: bool) -> PathBuf {
    target_dir(root)
        .join(TARGET)
        .join(if release { "release" } else { "debug" })
        .join(KERNEL_BINARY)
}

fn image_name(firmware: &str, release: bool, mode: ImageMode) -> String {
    let profile = if release { "release" } else { "debug" };
    match mode {
        ImageMode::Default => format!("rustos-{firmware}-{profile}.img"),
        ImageMode::Shell => format!("rustos-{firmware}-shell-{profile}.img"),
        ImageMode::Recovery => format!("rustos-{firmware}-recovery-{profile}.img"),
        ImageMode::Desktop => format!("rustos-{firmware}-desktop-{profile}.img"),
    }
}

fn partitioned_image_name(firmware: &str, release: bool, mode: ImageMode) -> String {
    let profile = if release { "release" } else { "debug" };
    match mode {
        ImageMode::Default => format!("rustos-{firmware}-partitioned-{profile}.img"),
        ImageMode::Shell => format!("rustos-{firmware}-partitioned-shell-{profile}.img"),
        ImageMode::Recovery => format!("rustos-{firmware}-partitioned-recovery-{profile}.img"),
        ImageMode::Desktop => format!("rustos-{firmware}-partitioned-desktop-{profile}.img"),
    }
}

fn image_mode(arguments: &[String]) -> Result<ImageMode, String> {
    let shell = arguments.iter().any(|argument| argument == "--shell");
    let recovery = arguments.iter().any(|argument| argument == "--recovery");
    let desktop = arguments.iter().any(|argument| argument == "--desktop");
    if usize::from(shell) + usize::from(recovery) + usize::from(desktop) > 1 {
        return Err("--shell, --recovery, and --desktop are mutually exclusive".to_owned());
    }
    Ok(if recovery {
        ImageMode::Recovery
    } else if desktop {
        ImageMode::Desktop
    } else if shell {
        ImageMode::Shell
    } else {
        ImageMode::Default
    })
}

fn argument_value(arguments: &[String], name: &str) -> Result<Option<PathBuf>, String> {
    let Some(index) = arguments.iter().position(|argument| argument == name) else {
        return Ok(None);
    };
    let value = arguments
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a path"))?;
    if value.starts_with('-') {
        return Err(format!("{name} requires a path"));
    }
    Ok(Some(PathBuf::from(value)))
}

fn partitioned_root_size(arguments: &[String]) -> Result<u64, String> {
    let Some(index) = arguments
        .iter()
        .position(|argument| argument == "--root-mib")
    else {
        return Ok(PARTITIONED_ROOT_SIZE);
    };
    let value = arguments
        .get(index + 1)
        .ok_or_else(|| "--root-mib requires a size in MiB".to_owned())?;
    if value.starts_with('-') {
        return Err("--root-mib requires a size in MiB".to_owned());
    }
    let mib = value
        .parse::<u64>()
        .map_err(|_| format!("invalid --root-mib value `{value}`"))?;
    if !(MIN_PARTITIONED_ROOT_MIB..=MAX_PARTITIONED_ROOT_MIB).contains(&mib) {
        return Err(format!(
            "--root-mib must be between {MIN_PARTITIONED_ROOT_MIB} and {MAX_PARTITIONED_ROOT_MIB} MiB"
        ));
    }
    mib.checked_mul(MIB)
        .ok_or_else(|| "--root-mib size overflowed".to_owned())
}

fn validate_partitioned_root_size(root_size: u64) -> Result<(), String> {
    if root_size % MIB != 0 {
        return Err(format!(
            "partitioned root size must be aligned to 1 MiB: {root_size} bytes"
        ));
    }
    let mib = root_size / MIB;
    if !(MIN_PARTITIONED_ROOT_MIB..=MAX_PARTITIONED_ROOT_MIB).contains(&mib) {
        return Err(format!(
            "partitioned root size must be between {MIN_PARTITIONED_ROOT_MIB} and {MAX_PARTITIONED_ROOT_MIB} MiB"
        ));
    }
    Ok(())
}

fn cargo_binary() -> PathBuf {
    env::var_os("CARGO")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cargo"))
}

fn usage() -> String {
    usage_text().to_owned()
}

fn usage_text() -> &'static str {
    "usage: cargo run -p rustos-xtask -- <build|check|nvidia-gsp-check|nvidia-fmc-check|nvidia-gsp-bundle-check|run|install> ..."
}

fn print_usage() {
    println!("{usage}", usage = usage_text());
    println!("  build              compile the kernel and create BIOS + UEFI images");
    println!("  check              check the host workspace and bare-metal kernel");
    println!("  nvidia-gsp-check PATH  validate an external NVIDIA GSP ELF and RPC marshalling");
    println!("  nvidia-fmc-check PATH  validate a GB20x GSP-FMC ELF and section CRCs");
    println!(
        "  nvidia-gsp-bundle-check VERSION GSP FMC BOOTLOADER  validate matching GB20x firmware"
    );
    println!("  run bios|uefi      boot the image in QEMU with serial output");
    println!("  --shell            boot the shell-only init configuration");
    println!("  --recovery         boot the standalone recovery configuration");
    println!("  --desktop          boot the Rust userland desktop session");
    println!(
        "  --terminal-proof   type `help` through the desktop terminal and verify shell output"
    );
    println!("  --account-proof    verify first-boot account setup and logout/reload persistence");
    println!(
        "  --logout-proof     click the desktop logout control and verify login-boundary return"
    );
    println!(
        "  --role-proof       create a secondary administrator and verify role-aware sudo authorization"
    );
    println!("  --virtio-gpu-proof require a virtio-gpu scanout and desktop frame proof");
    println!("  --partitioned      use a GPT EFI + FAT32 RustOS root image (UEFI only)");
    println!(
        "  --root-mib N       size the partitioned FAT32 RustOS root (64-131072 MiB; default: 64)"
    );
    println!("  --msi              use Q35 + e1000e to exercise PCI MSI delivery");
    println!("  --ahci             use Q35 SATA/AHCI storage instead of legacy IDE");
    println!("  --nvme             use Q35 PCI NVMe storage instead of legacy IDE");
    println!("  --ahci-interrupt-proof  require AHCI MSI completion delivery and filesystem proof");
    println!(
        "  --nvme-interrupt-proof  require NVMe MSI-X completion delivery and filesystem proof"
    );
    println!(
        "  --vm-proof              require userland mmap/munmap and process-reclamation proof"
    );
    println!("  --smp-proof             require the complete two-vCPU scheduler/runtime proof");
    println!("  --usb              attach a Q35 xHCI controller and USB HID keyboard");
    println!("  --usb-mouse        attach a Q35 xHCI controller and USB HID mouse (desktop)");
    println!("  --usb-both         attach xHCI USB HID keyboard and mouse together (desktop)");
    println!(
        "  --usb-hub          attach one xHCI USB hub with keyboard and mouse children (desktop)"
    );
    println!(
        "  --usb-hotplug      attach a hub with a keyboard, then add/remove a USB mouse (desktop proof)"
    );
    println!("  --usb-legacy       attach an xHCI keyboard with MSI/MSI-X disabled (legacy proof)");
    println!(
        "  --usb-nested       attach two xHCI USB hub tiers with keyboard and mouse children (desktop)"
    );
    println!(
        "  --usb-nested-hotplug attach two hub tiers with a keyboard, then add/remove a mouse (desktop proof)"
    );
    println!("  --image PATH       boot an existing image without rebuilding");
    println!("  --keyboard-proof   inject `net` through the keyboard in shell mode");
    println!("  --shell-proof      verify shell cwd, relative paths, and persistent file I/O");
    println!("  --pipe-proof       verify anonymous pipes and redirected shell children");
    println!("  --desktop-proof    capture the desktop framebuffer and stop QEMU");
    println!("  --poweroff-proof   inject `poweroff` and require ACPI guest shutdown");
    println!("  --reboot-proof     inject `reboot` and require ACPI guest reset");
    println!("  --suspend-proof    inject `suspend`, wake ACPI S3, and require resume");
    println!("  --native-suspend-proof require the ACPI extended 64-bit S3 vector");
    println!("  --audio-proof      play a Rust AC'97 tone and verify a non-silent QEMU WAV");
    println!("  --hda-audio-proof  play a Rust Intel HDA tone and verify a non-silent QEMU WAV");
    println!("  --virtio-network-proof attach modern virtio-net and verify a real DHCP lease");
    println!("  RUSTOS_QEMU=PATH    select the QEMU executable for a run");
    println!("  install FW TARGET  install a selected BIOS/UEFI image to TARGET");
    println!("  --force            allow the installer to replace TARGET");
    println!("  --smp N            boot with N virtual CPUs (default: 1)");
    println!("  --release          use the release kernel and image");
    println!(
        "  --network          attach a Rust UDP repository server through QEMU user networking"
    );
}

fn ovmf_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("RUSTOS_OVMF") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "RUSTOS_OVMF is not a firmware file: {}",
            path.display()
        ));
    }

    [
        "/usr/share/edk2/x64/OVMF.4m.fd",
        "/usr/share/edk2/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
    .ok_or_else(|| "could not find OVMF; set RUSTOS_OVMF to an OVMF firmware file".to_owned())
}

const USER_INIT_CONFIG: &[u8] = b"/bin/service|0\0/bin/worker|0\0/bin/restart|1\0";
const SHELL_INIT_CONFIG: &[u8] = b"/sbin/shell-login|0|0|0\0";
const DESKTOP_INIT_CONFIG: &[u8] = b"/sbin/login|0|0|0\0";
const RECOVERY_MARKER_CONTENT: &[u8] = b"recovery=1\n";
const USER_CONFIG_CONTENT: &[u8] = b"cfg=RustOS\n";
const PERSISTENT_STATE_CONTENT: &[u8] = b"boot=0\n";
fn smp_count(arguments: &[String]) -> Result<u32, String> {
    let mut count = None;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--smp" {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| "--smp requires a positive CPU count".to_owned())?;
            count = Some(
                value
                    .parse::<u32>()
                    .map_err(|_| "--smp requires a positive CPU count".to_owned())?,
            );
            index += 1;
        } else if let Some(value) = arguments[index].strip_prefix("--smp=") {
            count = Some(
                value
                    .parse::<u32>()
                    .map_err(|_| "--smp requires a positive CPU count".to_owned())?,
            );
        }
        index += 1;
    }

    let count = count.unwrap_or(1);
    if count == 0 {
        return Err("--smp requires a positive CPU count".to_owned());
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::{
        MIB, PARTITIONED_ROOT_SIZE, REPOSITORY_ROTATED_KEY_ID,
        REPOSITORY_ROTATED_SIGNING_KEY_BYTES, REPOSITORY_ROTATION_MATERIAL_LENGTH,
        REPOSITORY_SIGNATURE_LENGTH, ahci_interrupt_count, build_repository,
        create_partitioned_uefi_image, install_image, install_partitioned_image,
        key_rotation_message, nvme_interrupt_count, partitioned_root_size,
        validate_partitioned_root_size, virtio_interrupt_count, wav_data,
    };
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };
    const REPOSITORY_PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    #[test]
    fn virtio_interrupt_count_reads_the_runtime_diagnostic() {
        let serial = "driver: virtio-net 00:02.0 interrupt_mode=Msix interrupt_vector=Some(50) interrupt_count=7 interrupt_driven=true failure=None status=ready\n";
        assert_eq!(virtio_interrupt_count(serial), Some(7));
        assert_eq!(
            virtio_interrupt_count(
                "driver: virtio-net 00:02.0 interrupt_mode=Msix interrupt_count=0 status=ready\n"
            ),
            Some(0)
        );
        assert_eq!(
            virtio_interrupt_count("driver: e1000 interrupt_count=7\n"),
            None
        );
    }

    #[test]
    fn nvme_interrupt_count_reads_the_storage_diagnostic() {
        let serial = "storage: nvme ns=1 interrupt_mode=Msix interrupt_vector=Some(50) interrupt_count=5 interrupt_driven=true interrupt_error=None status=ready\n";
        assert_eq!(nvme_interrupt_count(serial), Some(5));
        assert_eq!(
            nvme_interrupt_count("storage: transport=nvme status=ready\n"),
            None
        );
    }

    #[test]
    fn ahci_interrupt_count_reads_the_storage_diagnostic() {
        let serial = "storage: ahci port=0 interrupt_mode=Msi interrupt_vector=Some(50) interrupt_count=3 interrupt_driven=true interrupt_error=None status=ready\n";
        assert_eq!(ahci_interrupt_count(serial), Some(3));
        assert_eq!(
            ahci_interrupt_count("storage: transport=ahci status=ready\n"),
            None
        );
    }

    #[test]
    fn repository_signature_covers_index_and_package_payloads() {
        let repository = build_repository();
        let signed_length = repository.len() - REPOSITORY_SIGNATURE_LENGTH;
        assert_eq!(&repository[..5], b"RREP3");
        assert_eq!(repository[5], 3);
        assert_eq!(repository[7], 1);
        assert_eq!(&repository[8..16], &REPOSITORY_ROTATED_KEY_ID);
        let key = VerifyingKey::from_bytes(
            &ed25519_dalek::SigningKey::from_bytes(&REPOSITORY_ROTATED_SIGNING_KEY_BYTES)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let signature = Signature::from_bytes(repository[signed_length..].try_into().unwrap());
        assert!(key.verify(&repository[..signed_length], &signature).is_ok());

        let mut tampered = repository;
        tampered[signed_length - 1] ^= 1;
        let tampered_signature =
            Signature::from_bytes(tampered[signed_length..].try_into().unwrap());
        assert!(
            key.verify(&tampered[..signed_length], &tampered_signature)
                .is_err()
        );
    }

    #[test]
    fn repository_rotates_from_root_key_through_an_authenticated_certificate() {
        let repository = build_repository();
        let root = VerifyingKey::from_bytes(&REPOSITORY_PUBLIC_KEY).unwrap();
        let rotated = ed25519_dalek::SigningKey::from_bytes(&REPOSITORY_ROTATED_SIGNING_KEY_BYTES)
            .verifying_key()
            .to_bytes();
        assert_eq!(&repository[8..16], &REPOSITORY_ROTATED_KEY_ID);
        assert_eq!(&repository[16..48], &rotated);
        let rotation_signature = Signature::from_bytes(repository[48..112].try_into().unwrap());
        assert!(
            root.verify(
                &key_rotation_message(&REPOSITORY_ROTATED_KEY_ID, &rotated),
                &rotation_signature
            )
            .is_ok()
        );

        let mut tampered_rotation = repository.clone();
        tampered_rotation[16] ^= 1;
        let tampered_rotation_signature =
            Signature::from_bytes(tampered_rotation[48..112].try_into().unwrap());
        assert!(
            root.verify(
                &key_rotation_message(
                    &REPOSITORY_ROTATED_KEY_ID,
                    &tampered_rotation[16..48].try_into().unwrap()
                ),
                &tampered_rotation_signature
            )
            .is_err()
        );
    }

    #[test]
    fn versioned_repository_preserves_history_and_rejects_metadata_tampering() {
        let repository = build_repository();
        assert_eq!(&repository[..5], b"RREP3");
        assert_eq!(repository[5], 3);
        assert_eq!(repository[6], 4);

        let first_hello = 16 + REPOSITORY_ROTATION_MATERIAL_LENGTH + 82;
        let second_hello = 16 + REPOSITORY_ROTATION_MATERIAL_LENGTH + 2 * 82;
        assert_eq!(&repository[first_hello..first_hello + 8], b"APP00001");
        assert_eq!(
            u32::from_le_bytes(
                repository[first_hello + 10..first_hello + 14]
                    .try_into()
                    .unwrap()
            ),
            1
        );
        assert_eq!(&repository[first_hello + 14..first_hello + 19], b"HELLO");
        assert_eq!(&repository[second_hello..second_hello + 8], b"APP00002");
        assert_eq!(
            u32::from_le_bytes(
                repository[second_hello + 10..second_hello + 14]
                    .try_into()
                    .unwrap()
            ),
            2
        );
        assert_eq!(&repository[second_hello + 14..second_hello + 19], b"HELLO");

        let signed_length = repository.len() - REPOSITORY_SIGNATURE_LENGTH;
        let key = VerifyingKey::from_bytes(
            &ed25519_dalek::SigningKey::from_bytes(&REPOSITORY_ROTATED_SIGNING_KEY_BYTES)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let mut tampered = repository;
        tampered[second_hello + 10] ^= 1;
        let tampered_signature =
            Signature::from_bytes(tampered[signed_length..].try_into().unwrap());
        assert!(
            key.verify(&tampered[..signed_length], &tampered_signature)
                .is_err()
        );
    }

    #[test]
    fn installer_writes_and_readback_verifies_a_regular_image() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let source = std::env::temp_dir().join(format!(
            "rustos-installer-test-{}-{suffix}.source",
            std::process::id()
        ));
        let target = std::env::temp_dir().join(format!(
            "rustos-installer-test-{}-{suffix}.img",
            std::process::id()
        ));
        let image = b"RustOS installer readback proof\n";
        fs::write(&source, image).unwrap();

        install_image(&source, &target, false).unwrap();
        assert_eq!(fs::read(&target).unwrap(), image);
        assert!(install_image(&source, &target, false).is_err());
        install_image(&source, &target, true).unwrap();

        fs::remove_file(source).unwrap();
        fs::remove_file(target).unwrap();
    }

    #[test]
    fn partitioned_root_size_is_bounded_and_mib_aligned() {
        assert_eq!(
            partitioned_root_size(&[
                "build".to_owned(),
                "--root-mib".to_owned(),
                "256".to_owned()
            ])
            .unwrap(),
            256 * MIB
        );
        assert_eq!(
            partitioned_root_size(&["build".to_owned()]).unwrap(),
            PARTITIONED_ROOT_SIZE
        );
        assert!(
            partitioned_root_size(&["build".to_owned(), "--root-mib".to_owned(), "63".to_owned()])
                .is_err()
        );
        assert!(
            partitioned_root_size(&[
                "build".to_owned(),
                "--root-mib".to_owned(),
                "not-a-size".to_owned()
            ])
            .is_err()
        );
        assert!(validate_partitioned_root_size(256 * MIB).is_ok());
        assert!(validate_partitioned_root_size(256 * MIB + 512).is_err());
    }

    #[test]
    fn partitioned_uefi_image_contains_efi_and_rustos_root_partitions() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let kernel = std::env::temp_dir().join(format!(
            "rustos-partitioned-test-{}-{suffix}.kernel",
            std::process::id()
        ));
        let image = std::env::temp_dir().join(format!(
            "rustos-partitioned-test-{}-{suffix}.img",
            std::process::id()
        ));
        fs::write(&kernel, b"RustOS test kernel").unwrap();

        create_partitioned_uefi_image(
            &kernel,
            b"initrd",
            b"repository",
            &image,
            PARTITIONED_ROOT_SIZE,
        )
        .unwrap();
        let table = gpt::GptConfig::new()
            .writable(false)
            .initialized(true)
            .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
            .open(&image)
            .unwrap();
        let partitions = table.partitions();
        assert_eq!(partitions.len(), 2);
        assert_eq!(partitions.get(&1).unwrap().name, "EFI System");
        assert_eq!(partitions.get(&2).unwrap().name, "RustOS root");
        assert_eq!(
            partitions.get(&1).unwrap().part_type_guid,
            gpt::partition_types::EFI
        );
        assert_eq!(
            partitions.get(&2).unwrap().part_type_guid,
            gpt::partition_types::LINUX_FS
        );
        drop(table);

        fs::remove_file(kernel).unwrap();
        fs::remove_file(image).unwrap();
    }

    #[test]
    fn partitioned_installer_repartitions_an_existing_regular_target() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let kernel = std::env::temp_dir().join(format!(
            "rustos-repartition-test-{}-{suffix}.kernel",
            std::process::id()
        ));
        let source = std::env::temp_dir().join(format!(
            "rustos-repartition-test-{}-{suffix}.source.img",
            std::process::id()
        ));
        let target = std::env::temp_dir().join(format!(
            "rustos-repartition-test-{}-{suffix}.target.img",
            std::process::id()
        ));
        fs::write(&kernel, b"RustOS test kernel").unwrap();
        create_partitioned_uefi_image(
            &kernel,
            b"initrd",
            b"repository",
            &source,
            PARTITIONED_ROOT_SIZE,
        )
        .unwrap();
        let target_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&target)
            .unwrap();
        target_file.set_len(96 * 1024 * 1024).unwrap();
        drop(target_file);

        assert!(install_partitioned_image(&source, &target, false).is_err());
        install_partitioned_image(&source, &target, true).unwrap();

        let table = gpt::GptConfig::new()
            .writable(false)
            .initialized(true)
            .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
            .open(&target)
            .unwrap();
        assert_eq!(table.partitions().get(&1).unwrap().name, "EFI System");
        assert_eq!(table.partitions().get(&2).unwrap().name, "RustOS root");
        drop(table);

        fs::remove_file(kernel).unwrap();
        fs::remove_file(source).unwrap();
        fs::remove_file(target).unwrap();
    }

    #[test]
    fn wav_parser_accepts_qemu_zero_length_data_placeholder() {
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&0u32.to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&48_000u32.to_le_bytes());
        wav.extend_from_slice(&192_000u32.to_le_bytes());
        wav.extend_from_slice(&4u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&0u32.to_le_bytes());
        wav.extend_from_slice(&[0x34, 0x12, 0x78, 0x56]);

        let (data, channels, sample_rate) = wav_data(&wav).unwrap();
        assert_eq!(channels, 2);
        assert_eq!(sample_rate, 48_000);
        assert_eq!(data, &[0x34, 0x12, 0x78, 0x56]);
    }
}
