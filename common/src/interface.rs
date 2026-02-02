// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use crate::info;
#[cfg(target_os = "linux")]
use linux_impl::{is_physical, is_wireless};
#[cfg(target_os = "macos")]
use macos_impl::{is_physical, is_wireless};
use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use rayon::prelude::*;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use crate::models::range::IpCollection;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ViabilityError {
    /// The interface is operationally down.
    IsDown,
    /// The interface was filtered out as "not physical" by the provided logic.
    NotPhysical,
    /// The interface does not have a MAC address.
    NoMacAddress,
    /// The interface does not support broadcast (required for ARP).
    NotBroadcast,
    /// The interface is a point-to-point link (e.g., a VPN).
    IsPointToPoint,
    /// The interface has no IPv4 address (for ARP) AND no IPv6 Link-Local (for NDP).
    NoValidLanIp,
}

/// Finds the primary LAN network and returns the ipv4 network
pub fn get_lan_network() -> anyhow::Result<Option<Ipv4Network>> {
    let interfaces: Vec<NetworkInterface> = pnet::datalink::interfaces();

    let interfaces_str: &str = match interfaces.len() {
        1 => "interface",
        _ => "interfaces",
    };

    info!(
        verbosity = 1,
        "Identified {} network {}, picking the best one...",
        interfaces.len(),
        interfaces_str
    );

    let interfaces: Vec<NetworkInterface> = interfaces
        .into_iter()
        .filter_map(
            |interface| match is_viable_lan_interface(&interface, is_physical) {
                Ok(()) => Some(interface),
                Err(_) => None,
            },
        )
        .collect();

    let interface: NetworkInterface =
        if let Some(interface) = select_best_lan_interface(interfaces, is_wired) {
            info!(
                verbosity = 1,
                "Performing LAN scan on interface {}", interface.name
            );
            interface
        } else {
            anyhow::bail!("No interfaces available for LAN discovery");
        };

    let private_v4_net: Option<Ipv4Network> = interface.ips.iter().find_map(|net| match net {
        IpNetwork::V4(v4) if v4.ip().is_private() => Some(*v4),
        _ => None,
    });

    Ok(private_v4_net)
}

/// Returns a list of prioritized network interfaces (e.g. wired first, then wireless, etc.)
pub fn get_prioritized_interfaces(limit: usize) -> anyhow::Result<Vec<NetworkInterface>> {
    let mut interfaces: Vec<NetworkInterface> = pnet::datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .collect();

    interfaces.sort_by_key(|i| if i.name.starts_with("e") { 0 } else { 1 });

    Ok(interfaces.into_iter().take(limit).collect())
}

pub fn is_layer_2_capable(intf: &NetworkInterface) -> bool {
    !intf.is_point_to_point() && !intf.is_loopback() && intf.mac.is_some()
}

pub fn is_on_link(intf: &NetworkInterface, ips: &IpCollection) -> bool {
    for range in &ips.ranges {
        let mut range_covered = false;
        for iface_ipnet in &intf.ips {
            if let pnet::ipnetwork::IpNetwork::V4(network) = iface_ipnet
                && network.contains(range.start_addr)
                && network.contains(range.end_addr)
            {
                range_covered = true;
                break;
            }
        }
        if !range_covered {
            return false;
        }
    }

    for single_ip in &ips.singles {
        let mut ip_covered = false;
        for iface_ipnet in &intf.ips {
            if iface_ipnet.contains(*single_ip) {
                ip_covered = true;
                break;
            }
        }
        if !ip_covered {
            return false;
        }
    }

    true
}

fn is_viable_lan_interface(
    interface: &NetworkInterface,
    is_physical: impl Fn(&NetworkInterface) -> bool,
) -> Result<(), ViabilityError> {
    if !interface.is_up() {
        return Err(ViabilityError::IsDown);
    }
    if !is_physical(interface) {
        return Err(ViabilityError::NotPhysical);
    }
    if interface.is_loopback() {
        return Err(ViabilityError::NotPhysical);
    }
    if interface.mac.is_none() {
        return Err(ViabilityError::NoMacAddress);
    }
    if !interface.is_broadcast() {
        return Err(ViabilityError::NotBroadcast);
    }
    if interface.is_point_to_point() {
        return Err(ViabilityError::IsPointToPoint);
    }
    let has_valid_ip = interface.ips.iter().any(|net| match net {
        IpNetwork::V4(ipv4) => ipv4.ip().is_private(),
        IpNetwork::V6(ipv6) => ipv6.ip().is_unicast_link_local(),
    });
    if !has_valid_ip {
        return Err(ViabilityError::NoValidLanIp);
    }

    Ok(())
}

fn select_best_lan_interface(
    interfaces: Vec<NetworkInterface>,
    is_wired: impl Fn(&NetworkInterface) -> bool,
) -> Option<NetworkInterface> {
    match interfaces.len() {
        0 => None,
        1 => Some(interfaces[0].clone()),
        _ => interfaces
            .iter()
            .find(|&interface| is_wired(interface))
            .cloned()
            .or(Some(interfaces[0].clone())),
    }
}

/// Maps target IPs to the interface used to reach them, split by Local vs Routed.
/// Returns: Map<Interface, (Local_Targets, Routed_Targets)>
pub fn map_ips_to_interfaces(
    mut collection: IpCollection,
) -> (
    HashMap<NetworkInterface, (IpCollection, IpCollection)>,
    IpCollection,
) {
    let interfaces: Vec<NetworkInterface> = datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .collect();

    let ip_to_idx: HashMap<IpAddr, usize> = interfaces
        .iter()
        .enumerate()
        .flat_map(|(idx, iface)| iface.ips.iter().map(move |ip_net| (ip_net.ip(), idx)))
        .collect();

    let mut result_map: HashMap<usize, (IpCollection, IpCollection)> = HashMap::new();
    let mut unmapped_ips = IpCollection::new();

    // 1. Handle Ranges (IPv4 only currently in IpCollection ranges)
    // Ranges that don't match a local subnet are broken into singles and re-processed
    // or just dumped into unmapped?
    // Current logic: if range not local, all IPs are added to 'singles' to be routed individually.
    // This logic is preserved below.
    for range in collection.ranges {
        let start: Ipv4Addr = range.start_addr;
        let end: Ipv4Addr = range.end_addr;
        let mut owner_idx: Option<usize> = None;

        for (idx, iface) in interfaces.iter().enumerate() {
            let is_local_subnet = iface.ips.iter().any(|ip_net| {
                ip_net.contains(IpAddr::V4(start)) && ip_net.contains(IpAddr::V4(end))
            });

            if is_local_subnet {
                owner_idx = Some(idx);
                break;
            }
        }

        if let Some(idx) = owner_idx {
            result_map.entry(idx).or_default().0.add_range(range);
        } else {
            for ip in range.to_iter() {
                collection.singles.insert(ip);
            }
        }
    }

    type ThreadSockets = (Option<UdpSocket>, Option<UdpSocket>);

    enum RouteType {
        Local,
        Routed,
        Unmapped,
    }

    let singles: Vec<IpAddr> = collection.singles.into_iter().collect();

    let processed_singles: Vec<(Option<usize>, RouteType, IpAddr)> = singles
        .par_iter()
        .map_init(
            || -> ThreadSockets { (None, None) },
            |sockets, &target_ip| {
                if let Some(idx) = find_local_index(&interfaces, target_ip) {
                    return (Some(idx), RouteType::Local, target_ip);
                }

                if let Some(source_ip) = resolve_route_source_ip(target_ip, sockets)
                    && let Some(idx) = ip_to_idx.get(&source_ip).copied()
                {
                    return (Some(idx), RouteType::Routed, target_ip);
                }

                (None, RouteType::Unmapped, target_ip)
            },
        )
        .collect();

    for (idx_opt, route_type, ip) in processed_singles {
        match route_type {
            RouteType::Local => {
                if let Some(idx) = idx_opt {
                    result_map.entry(idx).or_default().0.add_single(ip);
                }
            }
            RouteType::Routed => {
                if let Some(idx) = idx_opt {
                    result_map.entry(idx).or_default().1.add_single(ip);
                }
            }
            RouteType::Unmapped => {
                unmapped_ips.add_single(ip);
            }
        }
    }

    let mapped_interfaces = result_map
        .into_iter()
        .map(|(idx, (local_ips, routed_ips))| (interfaces[idx].clone(), (local_ips, routed_ips)))
        .collect();

    (mapped_interfaces, unmapped_ips)
}

fn find_local_index(interfaces: &[NetworkInterface], target: IpAddr) -> Option<usize> {
    interfaces.iter().position(|iface| {
        iface.ips.iter().any(|ip_net| match (target, ip_net.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                ip_net.contains(target)
            }
            _ => false,
        })
    })
}

fn resolve_route_source_ip(
    target: IpAddr,
    sockets: &mut (Option<UdpSocket>, Option<UdpSocket>),
) -> Option<IpAddr> {
    let socket_opt = if target.is_ipv4() {
        &mut sockets.0
    } else {
        &mut sockets.1
    };

    if socket_opt.is_none() {
        let bind_addr = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        *socket_opt = UdpSocket::bind(bind_addr).ok();
    }

    let socket = socket_opt.as_ref()?;

    socket.connect((target, 53)).ok()?;
    socket.local_addr().ok().map(|s| s.ip())
}

fn is_wired(interface: &NetworkInterface) -> bool {
    is_physical(interface) && !is_wireless(interface)
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::path::Path;

    pub fn is_physical(interface: &NetworkInterface) -> bool {
        Path::new(&format!("/sys/class/net/{}/device", interface.name)).exists()
    }

    pub fn is_wireless(interface: &NetworkInterface) -> bool {
        Path::new(&format!("sys/class/net/{}/wireless", interface.name)).exists()
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use std::collections::HashSet;
    use std::process::Command;
    use std::sync::OnceLock;

    /// A struct to hold the cached hardware information
    struct HardwareInfo {
        physical_devices: HashSet<String>,
        wireless_devices: HashSet<String>,
    }

    /// Singleton that runs the shell commands only once on first access.
    fn get_hardware_info() -> &'static HardwareInfo {
        static HARDWARE_INFO: OnceLock<HardwareInfo> = OnceLock::new();

        HARDWARE_INFO.get_or_init(|| {
            let mut physical = HashSet::new();
            let mut wireless = HashSet::new();

            // Get Physical Ports (Wired & Wireless hardware)
            if let Ok(output) = Command::new("networksetup")
                .arg("-listallhardwareports")
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(device) = line.strip_prefix("Device: ") {
                        physical.insert(device.trim().to_string());
                    }
                }
            }

            // Identify which of those are specifically Wireless
            for device in &physical {
                let is_wifi = Command::new("networksetup")
                    .arg("-getairportnetwork")
                    .arg(device)
                    .output()
                    .map(|out| out.status.success())
                    .unwrap_or(false);

                if is_wifi {
                    wireless.insert(device.clone());
                }
            }

            HardwareInfo {
                physical_devices: physical,
                wireless_devices: wireless,
            }
        })
    }

    pub fn is_physical(interface: &NetworkInterface) -> bool {
        get_hardware_info()
            .physical_devices
            .contains(&interface.name)
    }

    pub fn is_wireless(interface: &NetworkInterface) -> bool {
        get_hardware_info()
            .wireless_devices
            .contains(&interface.name)
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
    use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
    use pnet::util::MacAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const IFF_UP: u32 = 1;
    const IFF_BROADCAST: u32 = 1 << 1;
    const IFF_LOOPBACK: u32 = 1 << 3;
    const IFF_POINTTOPOINT: u32 = 1 << 4;
    //const IFF_RUNNING: u32 = 1 << 6;

    fn create_mock_interface(
        name: &str,
        mac: Option<MacAddr>,
        ips: Vec<IpNetwork>,
        flags: u32,
    ) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            description: "An interface".to_string(),
            index: 0,
            mac,
            ips,
            flags,
        }
    }

    fn default_mac() -> Option<MacAddr> {
        Some(MacAddr(0x1, 0x2, 0x3, 0x4, 0x5, 0x6))
    }

    fn default_ips() -> Vec<IpNetwork> {
        vec![IpNetwork::V4("192.168.1.100".parse().unwrap())]
    }

    #[test]
    fn is_viable_lan_interface_should_succeed() {
        let interface: NetworkInterface =
            create_mock_interface("eth0", default_mac(), default_ips(), IFF_UP | IFF_BROADCAST);
        let is_physical = |_: &NetworkInterface| -> bool { true };
        let result: Result<(), ViabilityError> = is_viable_lan_interface(&interface, is_physical);
        assert_eq!(result, Ok(()))
    }

    #[test]
    fn is_viable_lan_interface_should_succeed_with_ipv6_link_local() {
        let ipv6_ips = vec![IpNetwork::V6("fe80::1234:5678:abcd:ef01".parse().unwrap())];
        let interface: NetworkInterface =
            create_mock_interface("eth0", default_mac(), ipv6_ips, IFF_UP | IFF_BROADCAST);
        let is_physical = |_: &NetworkInterface| -> bool { true };
        let result: Result<(), ViabilityError> = is_viable_lan_interface(&interface, is_physical);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn is_viable_lan_interface_should_fail_with_invalid_ipv6() {
        let invalid_ipv6_ips = vec![IpNetwork::V6("2001:db8::1".parse().unwrap())];
        let interface: NetworkInterface = create_mock_interface(
            "eth0",
            default_mac(),
            invalid_ipv6_ips,
            IFF_UP | IFF_BROADCAST,
        );
        let is_physical = |_: &NetworkInterface| -> bool { true };
        let result: Result<(), ViabilityError> = is_viable_lan_interface(&interface, is_physical);
        assert_eq!(result, Err(ViabilityError::NoValidLanIp));
    }

    #[test]
    fn is_viable_lan_interface_should_fail_non_physical() {
        let interface: NetworkInterface =
            create_mock_interface("eth1", default_mac(), default_ips(), IFF_UP | IFF_BROADCAST);
        let is_physical = |_: &NetworkInterface| -> bool { false };
        let result: Result<(), ViabilityError> = is_viable_lan_interface(&interface, is_physical);
        assert_eq!(result, Err(ViabilityError::NotPhysical))
    }

    #[test]
    fn is_viable_lan_interface_should_fail_no_mac_addr() {
        let interface: NetworkInterface =
            create_mock_interface("eth0", None, default_ips(), IFF_UP | IFF_BROADCAST);
        let is_physical = |_: &NetworkInterface| -> bool { true };
        let result: Result<(), ViabilityError> = is_viable_lan_interface(&interface, is_physical);
        assert_eq!(result, Err(ViabilityError::NoMacAddress))
    }

    #[test]
    fn is_viable_lan_interface_should_fail_no_ips() {
        let interface: NetworkInterface =
            create_mock_interface("eth8", default_mac(), vec![], IFF_UP | IFF_BROADCAST);
        let is_physical = |_: &NetworkInterface| -> bool { true };
        let result: Result<(), ViabilityError> = is_viable_lan_interface(&interface, is_physical);
        assert_eq!(result, Err(ViabilityError::NoValidLanIp))
    }

    #[test]
    fn is_viable_lan_interface_should_fail_when_down() {
        let interface: NetworkInterface =
            create_mock_interface("wlan0", default_mac(), default_ips(), IFF_BROADCAST);
        let is_physical = |_: &NetworkInterface| -> bool { true };
        let result: Result<(), ViabilityError> = is_viable_lan_interface(&interface, is_physical);
        assert_eq!(result, Err(ViabilityError::IsDown))
    }

    #[test]
    fn is_viable_lan_interface_should_fail_loop_back() {
        let interface: NetworkInterface = create_mock_interface(
            "lo",
            default_mac(),
            default_ips(),
            IFF_LOOPBACK | IFF_UP | IFF_BROADCAST,
        );
        let is_physical = |_: &NetworkInterface| -> bool { true };
        let result: Result<(), ViabilityError> = is_viable_lan_interface(&interface, is_physical);
        assert_eq!(result, Err(ViabilityError::NotPhysical))
    }

    #[test]
    fn is_viable_lan_interface_should_fail_not_broadcast() {
        let interface: NetworkInterface =
            create_mock_interface("eth0", default_mac(), default_ips(), IFF_UP);
        let is_physical = |_: &NetworkInterface| -> bool { true };
        let result: Result<(), ViabilityError> = is_viable_lan_interface(&interface, is_physical);
        assert_eq!(result, Err(ViabilityError::NotBroadcast));
    }

    #[test]
    fn is_viable_lan_interface_should_fail_point_to_point() {
        let interface: NetworkInterface = create_mock_interface(
            "tun0",
            default_mac(),
            default_ips(),
            IFF_BROADCAST | IFF_POINTTOPOINT | IFF_UP,
        );
        let is_physical = |_: &NetworkInterface| -> bool { true };
        let result: Result<(), ViabilityError> = is_viable_lan_interface(&interface, is_physical);
        assert_eq!(result, Err(ViabilityError::IsPointToPoint))
    }

    #[test]
    fn select_best_lan_interface_selects_first_interface() {
        let interface: NetworkInterface = create_mock_interface(
            "wlan0",
            default_mac(),
            default_ips(),
            IFF_UP | IFF_BROADCAST,
        );
        let is_wired = |interface: &NetworkInterface| -> bool { interface.name == "eth0" };
        let result = select_best_lan_interface(vec![interface], is_wired);
        assert!(result.is_some(), "Should have selected an interface");
        assert_eq!(result.unwrap().name, "wlan0");
    }

    #[test]
    fn select_best_lan_interface_selects_wired_over_wireless() {
        let wired_interface: NetworkInterface =
            create_mock_interface("eth0", default_mac(), default_ips(), IFF_UP | IFF_BROADCAST);
        let wireless_interface: NetworkInterface = create_mock_interface(
            "wlan0",
            default_mac(),
            default_ips(),
            IFF_UP | IFF_BROADCAST,
        );
        let is_wired = |interface: &NetworkInterface| -> bool { interface.name == "eth0" };
        let interfaces: Vec<NetworkInterface> = vec![wireless_interface, wired_interface];
        let result = select_best_lan_interface(interfaces, is_wired);
        assert!(result.is_some(), "Should have selected an interface");
        assert_eq!(result.unwrap().name, "eth0");
    }

    #[test]
    fn select_best_lan_interface_returns_none() {
        let is_wired = |interface: &NetworkInterface| -> bool { interface.name == "eth0" };
        let interfaces: Vec<NetworkInterface> = vec![];
        let result = select_best_lan_interface(interfaces, is_wired);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_local_index_ipv4() {
        // Mock a network interface: 192.168.1.5/24
        let iface = NetworkInterface {
            name: "eth0".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 5), 24).unwrap(),
            )],
            flags: 0,
        };
        let interfaces = vec![iface];

        // Case 1: IP is inside the subnet (192.168.1.20)
        let target_inside = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!(find_local_index(&interfaces, target_inside), Some(0));

        // Case 2: IP is outside the subnet (192.168.2.20)
        let target_outside = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 20));
        assert_eq!(find_local_index(&interfaces, target_outside), None);
    }

    #[test]
    fn test_find_local_index_ipv6() {
        // Mock a network interface: 2001:db8::1/64
        let ipv6_addr = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let iface = NetworkInterface {
            name: "eth0".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![IpNetwork::V6(Ipv6Network::new(ipv6_addr, 64).unwrap())],
            flags: 0,
        };
        let interfaces = vec![iface];

        // Case 1: IP is inside the subnet
        let target_inside = "2001:db8::5".parse::<IpAddr>().unwrap();
        assert_eq!(find_local_index(&interfaces, target_inside), Some(0));

        // Case 2: IP mismatch (IPv4 vs IPv6)
        let target_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(find_local_index(&interfaces, target_v4), None);
    }

    #[test]
    fn test_resolve_route_source_ip_localhost() {
        // This test ensures the socket logic works without crashing.
        // Routing to 127.0.0.1 should theoretically return 127.0.0.1 or the generic bind address.
        let mut sockets = (None, None);
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let result = resolve_route_source_ip(target, &mut sockets);
        assert!(
            result.is_some(),
            "Should be able to resolve route to localhost"
        );
        assert_eq!(result.unwrap(), target);
    }

    #[test]
    fn test_resolve_route_public_internet() {
        // Try routing to Google DNS (8.8.8.8).
        // This tests if the OS kernel can determine a route for an external IP.
        // NOTE: This test will fail if the machine has no internet connection.
        let mut sockets = (None, None);
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let result = resolve_route_source_ip(target, &mut sockets);

        if let Some(src_ip) = result {
            assert!(src_ip.is_ipv4());
            assert!(!src_ip.is_loopback());
            assert!(!src_ip.is_unspecified());
        } else {
            // If we are offline, we warn rather than fail hard
            eprintln!("WARNING: Could not resolve route to 8.8.8.8 (Are you offline?)");
        }
    }

    #[test]
    fn test_map_ips_smoke_test() {
        // High level smoke test to ensure the parallel pipeline doesn't panic.
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ];

        let mut collection = IpCollection::new();
        for ip in ips {
            collection.add_single(ip);
        }

        let (result_map, _unmapped) = map_ips_to_interfaces(collection);

        for (iface, routed_ips) in result_map {
            println!("Interface {} routes: {:?}", iface.name, routed_ips);
            assert!(!iface.ips.is_empty());
        }
    }
}

// Moving generic interface helpers here
pub trait NetworkInterfaceExtension {
    fn get_ipv4_nets(&self) -> Vec<Ipv4Network>;
    fn get_ipv6_nets(&self) -> Vec<Ipv6Network>;
    fn get_ipv4_range(&self) -> Option<Ipv4Network>;
}

impl NetworkInterfaceExtension for NetworkInterface {
    fn get_ipv4_nets(&self) -> Vec<Ipv4Network> {
        self.ips
            .iter()
            .filter_map(|ip| {
                if let IpNetwork::V4(ipv4) = ip {
                    Some(*ipv4)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_ipv6_nets(&self) -> Vec<Ipv6Network> {
        self.ips
            .iter()
            .filter_map(|ip| {
                if let IpNetwork::V6(ipv6) = ip {
                    Some(*ipv6)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_ipv4_range(&self) -> Option<Ipv4Network> {
        // Simple heuristic: pick the first non-loopback IPv4
        self.get_ipv4_nets()
            .into_iter()
            .find(|net| !net.ip().is_loopback())
    }
}
