// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Host Model
//!
//! This module defines the [`Host`] entity, which represents a single network
//! equipment or device.
//!
//! The `Host` model is architected as an **aggregate of findings**. It is
//! specifically designed to be enriched over multiple asynchronous scanning
//! stages, leveraging high-performance merging logic to collate reachability,
//! hardware, OS, and service discovery data into a single forensic record.

use crate::models::port::Port;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::IpAddr,
    time::SystemTime,
};

pub mod hardware;
pub mod os;
pub mod status;
pub mod telemetry;

pub use hardware::HardwareInfo;
pub use os::OsFingerprint;
pub use status::{HostStatus, StatusProtocol, StatusReason};
pub use telemetry::HostTelemetry;

/// The absolute maximum number of open ports to record per host.
///
/// This serves as a security boundary against network "tarpits" (devices that
/// report every possible port as open), which could otherwise trigger an
/// Out-Of-Memory (OOM) crash in the scanner.
pub const MAX_PORTS_PER_HOST: usize = 1000;

/// Specialized network roles identified during host discovery.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum NetworkRole {
    /// Identifies the default gateway for a local subnet.
    Gateway,
    /// Identifies a host providing DHCP services.
    DHCP,
    /// Identifies a host providing DNS services.
    DNS,
    /// Identifies a host that has triggered defensive limits (e.g., reporting
    /// an impossible number of open ports).
    Tarpit,
}

/// A comprehensive identity and state record for a network-reachable host.
///
/// A `Host` is the primary unit of work for the Zond scanner. It holds
/// multi-homed IP data, forensic hardware IDs, and a history of network
/// performance metrics.
///
/// Large metadata blocks (like [`OsFingerprint`]) are stored in Boxes to
/// minimize the overall stack size of the `Host` struct.
#[derive(Debug, Clone)]
pub struct Host {
    /// The primary IP address used to target or identify this host.
    primary_ip: IpAddr,

    /// All known IP addresses for this host (multi-homed support).
    ips: BTreeSet<IpAddr>,

    /// The resolved hostname (FQDN or local network name).
    hostname: Option<String>,

    /// The current reachability status.
    status: HostStatus,

    /// Aggregated evidence explaining the current reachability status.
    reasons: HashSet<StatusReason>,

    /// Identified operating system metadata.
    os: Option<Box<OsFingerprint>>,

    /// physical hardware (MAC) and vendor information.
    hardware: Option<HardwareInfo>,

    /// Network performance and path telemetry.
    telemetry: HostTelemetry,

    /// Inferred roles based on network location or discovered services.
    network_roles: HashSet<NetworkRole>,

    /// Extensible map for scan script results (e.g., Nmap NSE output).
    scripts: Option<HashMap<String, String>>,

    /// The timestamp of the first discovery event for this host.
    first_seen: SystemTime,

    /// The timestamp of the most recent discovery or update event.
    last_seen: SystemTime,

    /// Internal map for sorted port discovery. Limited by [`MAX_PORTS_PER_HOST`].
    ports: BTreeMap<u16, Port>,
}

impl Host {
    /// Creates a new `Host` centered around a primary IP address.
    ///
    /// Initial status is always [`HostStatus::Unknown`].
    pub fn new(primary_ip: IpAddr) -> Self {
        let mut ips = BTreeSet::new();
        ips.insert(primary_ip);
        let now = SystemTime::now();

        Self {
            primary_ip,
            ips,
            hostname: None,
            status: HostStatus::Unknown,
            reasons: HashSet::new(),
            os: None,
            hardware: None,
            telemetry: HostTelemetry::default(),
            network_roles: HashSet::new(),
            scripts: None,
            first_seen: now,
            last_seen: now,
            ports: BTreeMap::new(),
        }
    }

    /// Returns the primary IP address for this host.
    pub fn primary_ip(&self) -> IpAddr {
        self.primary_ip
    }

    /// Returns all known IP addresses for this host.
    pub fn ips(&self) -> &BTreeSet<IpAddr> {
        &self.ips
    }

    /// Returns the resolved hostname, if any.
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Returns the current reachability status.
    pub fn status(&self) -> HostStatus {
        self.status
    }

    /// Returns all aggregated evidence for the current status.
    pub fn reasons(&self) -> &HashSet<StatusReason> {
        &self.reasons
    }

    /// Returns the identified operating system, if any.
    pub fn os(&self) -> Option<&OsFingerprint> {
        self.os.as_deref()
    }

    /// Returns physical hardware information, if any.
    pub fn hardware(&self) -> Option<&HardwareInfo> {
        self.hardware.as_ref()
    }

    /// Returns network performance and path telemetry.
    pub fn telemetry(&self) -> &HostTelemetry {
        &self.telemetry
    }

    /// Returns inferred roles based on network location or discovered services.
    pub fn network_roles(&self) -> &HashSet<NetworkRole> {
        &self.network_roles
    }

    /// Returns the map of scan script results.
    pub fn scripts(&self) -> Option<&HashMap<String, String>> {
        self.scripts.as_ref()
    }

    /// Returns the timestamp of the first discovery event.
    pub fn first_seen(&self) -> SystemTime {
        self.first_seen
    }

    /// Returns the timestamp of the most recent discovery or update event.
    pub fn last_seen(&self) -> SystemTime {
        self.last_seen
    }

    /// Updates the primary IP, ensures it exists in the `ips` set,
    /// and bumps the `last_seen` timestamp.
    pub fn set_primary_ip(&mut self, ip: IpAddr) {
        self.primary_ip = ip;
        self.ips.insert(ip);
        self.last_seen = SystemTime::now();
    }

    /// Adds a new IP address to the host's record and bumps `last_seen`.
    /// Returns `true` if the IP was newly added.
    pub fn add_ip(&mut self, ip: IpAddr) -> bool {
        let is_new = self.ips.insert(ip);
        self.last_seen = SystemTime::now();
        is_new
    }

    /// Adds multiple IP addresses to the host's record and bumps `last_seen`.
    pub fn extend_ips(&mut self, ips: impl IntoIterator<Item = IpAddr>) {
        self.ips.extend(ips);
        self.last_seen = SystemTime::now();
    }

    /// Sets the host's hostname and bumps `last_seen`.
    pub fn set_hostname(&mut self, hostname: Option<String>) {
        self.hostname = hostname;
        self.last_seen = SystemTime::now();
    }

    /// Updates the reachability status and bumps `last_seen`.
    pub fn set_status(&mut self, status: HostStatus) {
        self.status = status;
        self.last_seen = SystemTime::now();
    }

    /// Adds a status reason and bumps `last_seen`.
    pub fn add_reason(&mut self, reason: StatusReason) {
        self.reasons.insert(reason);
        self.last_seen = SystemTime::now();
    }

    /// Sets the OS fingerprint and bumps `last_seen`.
    pub fn set_os(&mut self, os: OsFingerprint) {
        self.os = Some(Box::new(os));
        self.last_seen = SystemTime::now();
    }

    /// Sets the hardware info and bumps `last_seen`.
    pub fn set_hardware(&mut self, hardware: HardwareInfo) {
        self.hardware = Some(hardware);
        self.last_seen = SystemTime::now();
    }

    /// Builder method to set the hardware MAC and return Self.
    pub fn with_mac(mut self, mac: crate::utils::mac::MacAddr) -> Self {
        self.set_hardware(HardwareInfo::new(mac));
        self
    }

    /// Adds multiple RTT measurements and bumps `last_seen`.
    pub fn set_rtts(&mut self, rtts: impl IntoIterator<Item = std::time::Duration>) {
        for rtt in rtts {
            self.telemetry.add_rtt(rtt);
        }
        self.last_seen = SystemTime::now();
    }

    /// Adds a network role and bumps `last_seen`.
    pub fn add_network_role(&mut self, role: NetworkRole) {
        self.network_roles.insert(role);
        self.last_seen = SystemTime::now();
    }

    /// Adds or updates a script result and bumps `last_seen`.
    pub fn add_script_result(&mut self, key: String, value: String) {
        self.scripts
            .get_or_insert_with(HashMap::new)
            .insert(key, value);
        self.last_seen = SystemTime::now();
    }

    /// Returns the minimum recorded RTT.
    pub fn min_rtt(&self) -> Option<std::time::Duration> {
        self.telemetry.min_rtt()
    }

    /// Returns the maximum recorded RTT.
    pub fn max_rtt(&self) -> Option<std::time::Duration> {
        self.telemetry.max_rtt()
    }

    /// Returns the average recorded RTT.
    pub fn average_rtt(&self) -> Option<std::time::Duration> {
        self.telemetry.average_rtt()
    }

    /// Returns the most recent MAC address, if hardware info is available.
    pub fn mac(&self) -> Option<crate::utils::mac::MacAddr> {
        self.hardware.as_ref().and_then(|h| h.most_recent_mac())
    }

    /// Returns the hardware vendor, if hardware info is available.
    pub fn vendor(&self) -> Option<&str> {
        self.hardware
            .as_ref()
            .and_then(|h| h.vendor.as_ref())
            .map(|v| &**v)
    }

    /// Returns `true` if this host is confirmed to be on the network
    /// (either fully responding or filtered).
    pub fn is_alive(&self) -> bool {
        self.status.is_alive()
    }

    /// Returns an iterator over all discovered ports in sorted order.
    pub fn ports(&self) -> impl Iterator<Item = &Port> {
        self.ports.values()
    }

    /// Returns the total number of recorded ports for this host.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Ingests a new port finding.
    ///
    /// If the port is already known, it is merged with the existing record.
    /// If the total port count exceeds [`MAX_PORTS_PER_HOST`], the port is ignored
    /// and the host is assigned the [`NetworkRole::Tarpit`] role.
    pub fn add_port(&mut self, new_port: Port) {
        if self.ports.len() >= MAX_PORTS_PER_HOST && !self.ports.contains_key(&new_port.number) {
            self.network_roles.insert(NetworkRole::Tarpit);
            return;
        }

        self.ports
            .entry(new_port.number)
            .and_modify(|p| p.merge(new_port.clone()))
            .or_insert(new_port);

        self.last_seen = SystemTime::now();
    }

    /// Merges architectural findings from another `Host` record.
    ///
    /// This is the core aggregation method of the library, used to combine
    /// results from multiple asynchronous scan stages into a single truth.
    ///
    /// - Status is promoted based on semantic ordering.
    /// - Telemetry and OS data are merged using their respective logic.
    /// - Port caps are enforced during aggregation.
    pub fn merge(&mut self, other: Host) {
        self.ips.extend(other.ips);
        if self.hostname.is_none() {
            self.hostname = other.hostname;
        }

        if other.status > self.status {
            self.status = other.status;
        }
        self.reasons.extend(other.reasons);

        if let Some(other_os) = other.os {
            if let Some(ref mut self_os) = self.os {
                self_os.merge(*other_os);
            } else {
                self.os = Some(other_os);
            }
        }

        if let Some(other_hw) = other.hardware {
            if let Some(ref mut self_hw) = self.hardware {
                self_hw.merge(other_hw);
            } else {
                self.hardware = Some(other_hw);
            }
        }

        self.telemetry.merge(other.telemetry);
        self.network_roles.extend(other.network_roles);

        if let Some(other_scripts) = other.scripts {
            let self_scripts = self.scripts.get_or_insert_with(HashMap::new);
            self_scripts.extend(other_scripts);
        }

        for (_, port) in other.ports {
            self.add_port(port);
        }

        if other.first_seen < self.first_seen {
            self.first_seen = other.first_seen;
        }
        if other.last_seen > self.last_seen {
            self.last_seen = other.last_seen;
        }
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.primary_ip, self.status)?;
        if let Some(ref os) = self.os {
            write!(f, " - {}", os)?;
        }
        if self.network_roles.contains(&NetworkRole::Tarpit) {
            write!(f, " [TARPIT]")?;
        } else {
            write!(f, " [{}]", self.telemetry)?;
        }
        Ok(())
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::port::{Port, PortState, Protocol};
    use std::net::Ipv4Addr;

    static IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100));

    #[test]
    fn host_primary_ip_invariant() {
        let mut host = Host::new(IP_ADDR);
        let fresh_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        host.set_primary_ip(fresh_ip);

        assert_eq!(host.primary_ip(), fresh_ip);
        assert!(host.ips().contains(&fresh_ip));
    }

    #[test]
    fn tarpit_boundary_test() {
        let mut host = Host::new(IP_ADDR);
        for i in 0..MAX_PORTS_PER_HOST {
            host.add_port(Port::new(i as u16, Protocol::Tcp, PortState::Open));
        }
        assert!(!host.network_roles.contains(&NetworkRole::Tarpit));

        host.add_port(Port::new(9999, Protocol::Tcp, PortState::Open));
        assert!(host.network_roles.contains(&NetworkRole::Tarpit));
        assert_eq!(host.port_count(), MAX_PORTS_PER_HOST);
    }

    #[test]
    fn host_merge_promotes_status() {
        let mut h1 = Host::new(IP_ADDR);
        h1.set_status(HostStatus::Down);

        let mut h2 = Host::new(IP_ADDR);
        h2.set_status(HostStatus::Filtered);

        h1.merge(h2);
        assert_eq!(h1.status(), HostStatus::Filtered);
    }

    #[test]
    fn merge_tarpit_collision_test() {
        let mut h1 = Host::new(IP_ADDR);
        for i in 0..600 {
            h1.add_port(Port::new(i, Protocol::Tcp, PortState::Open));
        }

        let mut h2 = Host::new(IP_ADDR);
        // Ports 500-1100. 100 overlap (0-indexed 500-599), 500 new ones.
        // Total should hit cap at 1000.
        for i in 500..1100 {
            h2.add_port(Port::new(i, Protocol::Tcp, PortState::Open));
        }

        h1.merge(h2);
        assert_eq!(h1.port_count(), MAX_PORTS_PER_HOST);
        assert!(h1.network_roles.contains(&NetworkRole::Tarpit));
    }
}
