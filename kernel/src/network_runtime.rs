use core::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};

use spin::Mutex;

use crate::{
    e1000::{E1000Error, E1000Runtime},
    igc::{IgcError, IgcRuntime},
    net::Ipv4Address,
    virtio_net::{VirtioNetError, VirtioNetRuntime},
};

pub const NETWORK_RECEIVE_HEADER_LENGTH: usize = 6;
pub const MAX_NETWORK_PAYLOAD_LENGTH: usize = 1024;
pub const MAX_NETWORK_BUFFER_LENGTH: usize =
    NETWORK_RECEIVE_HEADER_LENGTH + MAX_NETWORK_PAYLOAD_LENGTH;
pub const NETWORK_INFO_MAX_LENGTH: usize = 320;
pub const NETWORK_INTERFACES_MAX_LENGTH: usize = 1024;
pub const NETWORK_RENEW_MAX_LENGTH: usize = 1024;

const DHCP_TICKS_PER_SECOND: u64 = 100;
const DHCP_RENEWAL_RETRY_TICKS: u64 = DHCP_TICKS_PER_SECOND;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    Unavailable,
    BufferTooSmall { required: usize, available: usize },
    E1000(E1000Error),
    Igc(IgcError),
    Virtio(VirtioNetError),
}

impl From<E1000Error> for NetworkError {
    fn from(error: E1000Error) -> Self {
        Self::E1000(error)
    }
}

impl From<VirtioNetError> for NetworkError {
    fn from(error: VirtioNetError) -> Self {
        Self::Virtio(error)
    }
}

impl From<IgcError> for NetworkError {
    fn from(error: IgcError) -> Self {
        Self::Igc(error)
    }
}

impl NetworkError {
    pub fn is_no_packet(self) -> bool {
        matches!(
            self,
            Self::E1000(E1000Error::NoPacket)
                | Self::Igc(IgcError::NoPacket)
                | Self::Virtio(VirtioNetError::NoPacket)
        )
    }

    pub fn is_unavailable(self) -> bool {
        matches!(
            self,
            Self::Unavailable
                | Self::E1000(E1000Error::ExternalNetworkNotEnabled)
                | Self::Igc(IgcError::ExternalNetworkNotEnabled)
                | Self::Virtio(
                    VirtioNetError::NetworkUnavailable | VirtioNetError::ExternalNetworkNotEnabled
                )
        )
    }

    pub fn is_buffer_too_small(self) -> bool {
        matches!(
            self,
            Self::BufferTooSmall { .. }
                | Self::E1000(E1000Error::NetworkBufferTooSmall { .. })
                | Self::Igc(IgcError::NetworkBufferTooSmall { .. })
                | Self::Virtio(VirtioNetError::NetworkBufferTooSmall { .. })
        )
    }
}

#[derive(Debug)]
pub enum NetworkBackend {
    E1000(E1000Runtime),
    Igc(IgcRuntime),
    Virtio(VirtioNetRuntime),
}

impl NetworkBackend {
    pub fn name(&self) -> &'static str {
        match self {
            Self::E1000(_) => "e1000",
            Self::Igc(_) => "igc",
            Self::Virtio(_) => "virtio",
        }
    }

    fn interface_name(&self) -> &'static str {
        match self {
            Self::E1000(_) => "e1000e0",
            Self::Igc(_) => "igc0",
            Self::Virtio(_) => "virtio0",
        }
    }

    fn mac_address(&self) -> [u8; 6] {
        match self {
            Self::E1000(runtime) => runtime.mac_address,
            Self::Igc(runtime) => runtime.mac_address,
            Self::Virtio(runtime) => runtime.mac_address,
        }
    }

    fn snapshot(&self) -> NetworkSnapshot {
        match self {
            Self::E1000(runtime) => {
                let configuration = runtime.network_configuration();
                NetworkSnapshot {
                    interface_name: self.interface_name(),
                    backend_name: self.name(),
                    mac_address: self.mac_address(),
                    address: configuration.address,
                    subnet_mask: configuration.subnet_mask,
                    gateway: configuration.gateway,
                    dns: configuration.dns,
                    dhcp_server: configuration.dhcp_server,
                    lease_seconds: configuration.lease_seconds,
                    dhcp: configuration.dhcp,
                }
            }
            Self::Igc(runtime) => {
                let configuration = runtime.network_configuration();
                NetworkSnapshot {
                    interface_name: self.interface_name(),
                    backend_name: self.name(),
                    mac_address: self.mac_address(),
                    address: configuration.address,
                    subnet_mask: configuration.subnet_mask,
                    gateway: configuration.gateway,
                    dns: configuration.dns,
                    dhcp_server: configuration.dhcp_server,
                    lease_seconds: configuration.lease_seconds,
                    dhcp: configuration.dhcp,
                }
            }
            Self::Virtio(runtime) => {
                let configuration = runtime.network_configuration();
                NetworkSnapshot {
                    interface_name: self.interface_name(),
                    backend_name: self.name(),
                    mac_address: self.mac_address(),
                    address: configuration.address,
                    subnet_mask: configuration.subnet_mask,
                    gateway: configuration.gateway,
                    dns: configuration.dns,
                    dhcp_server: configuration.dhcp_server,
                    lease_seconds: configuration.lease_seconds,
                    dhcp: configuration.dhcp,
                }
            }
        }
    }

    fn send_udp(
        &mut self,
        destination: Ipv4Address,
        destination_port: u16,
        payload: &[u8],
    ) -> Result<usize, NetworkError> {
        match self {
            Self::E1000(runtime) => runtime
                .send_udp(destination, destination_port, payload)
                .map_err(NetworkError::E1000),
            Self::Igc(runtime) => runtime
                .send_udp(destination, destination_port, payload)
                .map_err(NetworkError::Igc),
            Self::Virtio(runtime) => runtime
                .send_udp(destination, destination_port, payload)
                .map_err(NetworkError::Virtio),
        }
    }

    fn receive_udp(&mut self, buffer: &mut [u8]) -> Result<usize, NetworkError> {
        match self {
            Self::E1000(runtime) => runtime.receive_udp(buffer).map_err(NetworkError::E1000),
            Self::Igc(runtime) => runtime.receive_udp(buffer).map_err(NetworkError::Igc),
            Self::Virtio(runtime) => runtime.receive_udp(buffer).map_err(NetworkError::Virtio),
        }
    }

    fn renew_dhcp(&mut self) -> Result<(), NetworkError> {
        match self {
            Self::E1000(runtime) => runtime
                .renew_dhcp()
                .map(|_| ())
                .map_err(NetworkError::E1000),
            Self::Igc(runtime) => runtime.renew_dhcp().map(|_| ()).map_err(NetworkError::Igc),
            Self::Virtio(runtime) => runtime
                .renew_dhcp()
                .map(|_| ())
                .map_err(NetworkError::Virtio),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkSnapshot {
    interface_name: &'static str,
    backend_name: &'static str,
    mac_address: [u8; 6],
    address: Ipv4Address,
    subnet_mask: Ipv4Address,
    gateway: Ipv4Address,
    dns: Ipv4Address,
    dhcp_server: Ipv4Address,
    lease_seconds: u32,
    dhcp: bool,
}

#[derive(Debug, Clone, Copy)]
struct NetworkLeaseState {
    next_renew_tick: u64,
    renewals: u32,
}

impl NetworkLeaseState {
    fn new(snapshot: NetworkSnapshot, now: u64) -> Self {
        Self {
            next_renew_tick: renewal_deadline(now, snapshot.lease_seconds),
            renewals: 0,
        }
    }

    fn due(self, now: u64) -> bool {
        self.next_renew_tick != u64::MAX && now >= self.next_renew_tick
    }

    fn renewed(&mut self, now: u64, lease_seconds: u32) {
        self.renewals = self.renewals.saturating_add(1);
        self.next_renew_tick = renewal_deadline(now, lease_seconds);
    }

    fn retry(&mut self, now: u64) {
        self.next_renew_tick = now.saturating_add(DHCP_RENEWAL_RETRY_TICKS);
    }
}

fn renewal_deadline(now: u64, lease_seconds: u32) -> u64 {
    if lease_seconds == 0 {
        return u64::MAX;
    }
    now.saturating_add(
        u64::from(lease_seconds)
            .saturating_mul(DHCP_TICKS_PER_SECOND)
            .saturating_div(2),
    )
}

#[derive(Debug)]
struct NetworkManager {
    default: NetworkBackend,
    secondary: Option<NetworkBackend>,
    default_lease: NetworkLeaseState,
    secondary_lease: Option<NetworkLeaseState>,
}

impl NetworkManager {
    fn interface_count(&self) -> usize {
        1 + usize::from(self.secondary.is_some())
    }

    fn default_interface_name(&self) -> &'static str {
        self.default.interface_name()
    }
}

static NETWORK_MANAGER: Mutex<Option<NetworkManager>> = Mutex::new(None);
static NETWORK_SERVICE_POLLS: AtomicU64 = AtomicU64::new(0);

pub fn install_manager(default: NetworkBackend, secondary: Option<NetworkBackend>) {
    let now = crate::interrupts::apic_ticks();
    let default_lease = NetworkLeaseState::new(default.snapshot(), now);
    let secondary_lease = secondary
        .as_ref()
        .map(|backend| NetworkLeaseState::new(backend.snapshot(), now));
    *NETWORK_MANAGER.lock() = Some(NetworkManager {
        default,
        secondary,
        default_lease,
        secondary_lease,
    });
}

pub fn backend_name() -> Option<&'static str> {
    NETWORK_MANAGER
        .lock()
        .as_ref()
        .map(|manager| manager.default.name())
}

pub fn default_interface_name() -> Option<&'static str> {
    NETWORK_MANAGER
        .lock()
        .as_ref()
        .map(NetworkManager::default_interface_name)
}

pub fn interface_count() -> usize {
    NETWORK_MANAGER
        .lock()
        .as_ref()
        .map_or(0, NetworkManager::interface_count)
}

pub fn network_send(
    destination: Ipv4Address,
    destination_port: u16,
    payload: &[u8],
) -> Result<usize, NetworkError> {
    let mut manager = NETWORK_MANAGER.lock();
    let Some(manager) = manager.as_mut() else {
        return Err(NetworkError::Unavailable);
    };
    manager
        .default
        .send_udp(destination, destination_port, payload)
}

pub fn network_receive(buffer: &mut [u8]) -> Result<usize, NetworkError> {
    let mut manager = NETWORK_MANAGER.lock();
    let Some(manager) = manager.as_mut() else {
        return Err(NetworkError::Unavailable);
    };
    manager.default.receive_udp(buffer)
}

pub fn network_info(buffer: &mut [u8]) -> Result<usize, NetworkError> {
    let manager = NETWORK_MANAGER.lock();
    let Some(manager) = manager.as_ref() else {
        return Err(NetworkError::Unavailable);
    };

    let mut writer = NetworkInfoWriter::<NETWORK_INFO_MAX_LENGTH>::new();
    let snapshot = manager.default.snapshot();
    let _ = write!(
        &mut writer,
        "backend={} interface={} route=default metric=10 ",
        snapshot.backend_name, snapshot.interface_name
    );
    write_network_snapshot_fields(&mut writer, snapshot);
    if writer.length > buffer.len() {
        return Err(NetworkError::BufferTooSmall {
            required: writer.length,
            available: buffer.len(),
        });
    }
    buffer[..writer.length].copy_from_slice(&writer.bytes[..writer.length]);
    Ok(writer.length)
}

pub fn network_interfaces(buffer: &mut [u8]) -> Result<usize, NetworkError> {
    let manager = NETWORK_MANAGER.lock();
    let Some(manager) = manager.as_ref() else {
        return Err(NetworkError::Unavailable);
    };

    let mut writer = NetworkInfoWriter::<NETWORK_INTERFACES_MAX_LENGTH>::new();
    let _ = write!(
        &mut writer,
        "manager=rustos default={} interfaces={} routes=1 status=ready\n",
        manager.default_interface_name(),
        manager.interface_count()
    );
    write_network_snapshot_line(&mut writer, manager.default.snapshot(), true, 10);
    if let Some(secondary) = manager.secondary.as_ref() {
        write_network_snapshot_line(&mut writer, secondary.snapshot(), false, 20);
    }
    if writer.length > buffer.len() {
        return Err(NetworkError::BufferTooSmall {
            required: writer.length,
            available: buffer.len(),
        });
    }
    buffer[..writer.length].copy_from_slice(&writer.bytes[..writer.length]);
    Ok(writer.length)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkRenewalReport {
    pub length: usize,
    pub all_ready: bool,
}

fn renew_backend(
    backend: &mut NetworkBackend,
    lease: &mut NetworkLeaseState,
    now: u64,
) -> Result<NetworkSnapshot, NetworkError> {
    match backend.renew_dhcp() {
        Ok(()) => {
            let snapshot = backend.snapshot();
            lease.renewed(now, snapshot.lease_seconds);
            Ok(snapshot)
        }
        Err(error) => {
            lease.retry(now);
            Err(error)
        }
    }
}

fn write_renewal_line<const LENGTH: usize>(
    writer: &mut NetworkInfoWriter<LENGTH>,
    backend: &NetworkBackend,
    result: Result<NetworkSnapshot, NetworkError>,
    renewals: u32,
) {
    match result {
        Ok(snapshot) => {
            let _ = writeln!(
                writer,
                "interface={} backend={} result=renewed lease_seconds={} renewals={} status=ready",
                snapshot.interface_name, snapshot.backend_name, snapshot.lease_seconds, renewals
            );
        }
        Err(error) => {
            let _ = writeln!(
                writer,
                "interface={} backend={} result=failed error={:?} renewals={} status=degraded",
                backend.interface_name(),
                backend.name(),
                error,
                renewals
            );
        }
    }
}

pub fn network_renew(buffer: &mut [u8]) -> Result<NetworkRenewalReport, NetworkError> {
    let mut manager = NETWORK_MANAGER.lock();
    let Some(manager) = manager.as_mut() else {
        return Err(NetworkError::Unavailable);
    };

    let now = crate::interrupts::apic_ticks();
    let default_result = renew_backend(&mut manager.default, &mut manager.default_lease, now);
    let secondary_result = manager
        .secondary
        .as_mut()
        .zip(manager.secondary_lease.as_mut())
        .map(|(backend, lease)| renew_backend(backend, lease, now));
    let renewals_ready =
        default_result.is_ok() && secondary_result.is_none_or(|result| result.is_ok());
    let timer_service_active = NETWORK_SERVICE_POLLS.load(Ordering::Acquire) != 0;
    let all_ready = renewals_ready && timer_service_active;

    let mut writer = NetworkInfoWriter::<NETWORK_RENEW_MAX_LENGTH>::new();
    let _ = writeln!(
        &mut writer,
        "manager=rustos interfaces={} renewals={} timer_service={} status={}",
        manager.interface_count(),
        manager.default_lease.renewals + manager.secondary_lease.map_or(0, |lease| lease.renewals),
        if timer_service_active {
            "active"
        } else {
            "inactive"
        },
        if all_ready { "ready" } else { "degraded" }
    );
    write_renewal_line(
        &mut writer,
        &manager.default,
        default_result,
        manager.default_lease.renewals,
    );
    if let (Some(backend), Some(lease), Some(result)) = (
        manager.secondary.as_ref(),
        manager.secondary_lease,
        secondary_result,
    ) {
        write_renewal_line(&mut writer, backend, result, lease.renewals);
    }
    if writer.length > buffer.len() {
        return Err(NetworkError::BufferTooSmall {
            required: writer.length,
            available: buffer.len(),
        });
    }
    buffer[..writer.length].copy_from_slice(&writer.bytes[..writer.length]);
    Ok(NetworkRenewalReport {
        length: writer.length,
        all_ready,
    })
}

fn renew_due_interface(backend: &mut NetworkBackend, lease: &mut NetworkLeaseState, now: u64) {
    if !lease.due(now) {
        return;
    }
    let interface = backend.interface_name();
    let backend_name = backend.name();
    match renew_backend(backend, lease, now) {
        Ok(snapshot) => crate::kprintln!(
            "net: dhcp renewal interface={} backend={} lease_seconds={} renewals={} status=ready",
            snapshot.interface_name,
            snapshot.backend_name,
            snapshot.lease_seconds,
            lease.renewals
        ),
        Err(error) => crate::kprintln!(
            "net: dhcp renewal interface={} backend={} result=retry error={:?} status=degraded",
            interface,
            backend_name,
            error
        ),
    }
}

/// Run the bounded timer-driven DHCP renewal service from the BSP kernel worker.
pub fn service_poll(now: u64) {
    let Some(mut guard) = NETWORK_MANAGER.try_lock() else {
        return;
    };
    let Some(manager) = guard.as_mut() else {
        return;
    };
    NETWORK_SERVICE_POLLS.fetch_add(1, Ordering::AcqRel);
    let (default, secondary) = (&mut manager.default, &mut manager.secondary);
    renew_due_interface(default, &mut manager.default_lease, now);
    if let (Some(backend), Some(lease)) = (secondary.as_mut(), manager.secondary_lease.as_mut()) {
        renew_due_interface(backend, lease, now);
    }
}

struct NetworkInfoWriter<const LENGTH: usize> {
    bytes: [u8; LENGTH],
    length: usize,
}

impl<const LENGTH: usize> NetworkInfoWriter<LENGTH> {
    const fn new() -> Self {
        Self {
            bytes: [0; LENGTH],
            length: 0,
        }
    }
}

impl<const LENGTH: usize> Write for NetworkInfoWriter<LENGTH> {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        let end = self
            .length
            .checked_add(value.len())
            .ok_or(core::fmt::Error)?;
        if end > LENGTH {
            return Err(core::fmt::Error);
        }
        self.bytes[self.length..end].copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}

fn write_network_snapshot_fields<const LENGTH: usize>(
    writer: &mut NetworkInfoWriter<LENGTH>,
    snapshot: NetworkSnapshot,
) {
    write_mac_address(writer, snapshot.mac_address);
    write_network_address(writer, "ip", snapshot.address);
    write_network_address(writer, "mask", snapshot.subnet_mask);
    write_network_address(writer, "gateway", snapshot.gateway);
    write_network_address(writer, "dns", snapshot.dns);
    write_network_address(writer, "dhcp_server", snapshot.dhcp_server);
    let _ = write!(
        writer,
        "lease_seconds={} source={} status=ready\n",
        snapshot.lease_seconds,
        if snapshot.dhcp {
            "dhcp"
        } else {
            "static-fallback"
        }
    );
}

fn write_network_snapshot_line<const LENGTH: usize>(
    writer: &mut NetworkInfoWriter<LENGTH>,
    snapshot: NetworkSnapshot,
    default_route: bool,
    metric: u16,
) {
    let _ = write!(
        writer,
        "interface={} backend={} ",
        snapshot.interface_name, snapshot.backend_name
    );
    write_mac_address(writer, snapshot.mac_address);
    write_network_address(writer, "ip", snapshot.address);
    write_network_address(writer, "mask", snapshot.subnet_mask);
    write_network_address(writer, "gateway", snapshot.gateway);
    write_network_address(writer, "dns", snapshot.dns);
    write_network_address(writer, "dhcp_server", snapshot.dhcp_server);
    let _ = write!(
        writer,
        "lease_seconds={} state=up route={} metric={} source={} status=ready\n",
        snapshot.lease_seconds,
        if default_route { "default" } else { "none" },
        metric,
        if snapshot.dhcp {
            "dhcp"
        } else {
            "static-fallback"
        }
    );
}

fn write_mac_address<const LENGTH: usize>(writer: &mut NetworkInfoWriter<LENGTH>, mac: [u8; 6]) {
    let _ = write!(
        writer,
        "mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
}

fn write_network_address<const LENGTH: usize>(
    writer: &mut NetworkInfoWriter<LENGTH>,
    name: &str,
    address: Ipv4Address,
) {
    let _ = write!(
        writer,
        "{}={}.{}.{}.{} ",
        name, address[0], address[1], address[2], address[3]
    );
}
