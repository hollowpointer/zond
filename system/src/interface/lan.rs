// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use super::os::{is_physical, is_wireless};
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use zond_core::info;

/// Errors arising from network validation constraints during LAN interface selection.
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

/// Identifies the best local area network (LAN) connected to the current host context.
///
/// Under the hood, this iterates over `pnet::datalink::interfaces()` directly.
pub fn get_lan_network() -> anyhow::Result<Option<Ipv4Network>> {
    let interfaces: Vec<NetworkInterface> = pnet::datalink::interfaces();
    get_lan_network_with(interfaces)
}

/// Core LAN selection logic, decoupled from OS interface dependencies for testing.
pub(crate) fn get_lan_network_with(
    interfaces: Vec<NetworkInterface>,
) -> anyhow::Result<Option<Ipv4Network>> {
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

/// Identifies if the specified interface is wired directly to the machine locally.
///
/// Considers virtual and remote connections as non-wired.
pub fn is_wired(interface: &NetworkInterface) -> bool {
    is_physical(interface) && !is_wireless(interface)
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
    use pnet::datalink::MacAddr;
    use pnet::ipnetwork::IpNetwork;
    use std::net::Ipv4Addr;

    fn mock_interface(
        up: bool,
        mac: bool,
        broadcast: bool,
        p2p: bool,
        loopback: bool,
        ip: bool,
    ) -> NetworkInterface {
        NetworkInterface {
            name: "test0".to_string(),
            description: "".to_string(),
            index: 0,
            mac: if mac {
                Some(MacAddr::new(1, 2, 3, 4, 5, 6))
            } else {
                None
            },
            ips: if ip {
                vec![IpNetwork::V4(
                    Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap(),
                )]
            } else {
                vec![]
            },
            flags: {
                let mut flags = 0;
                if up {
                    flags |= 1;
                }
                if broadcast {
                    flags |= 2;
                }
                if p2p {
                    flags |= 16;
                }
                if loopback {
                    flags |= 8;
                } // roughly matching bitmasks
                flags
            },
        }
    }

    #[test]
    fn is_viable_down() {
        let intf = mock_interface(false, true, true, false, false, true);
        assert_eq!(
            is_viable_lan_interface(&intf, |_| true),
            Err(ViabilityError::IsDown)
        );
    }

    #[test]
    fn is_viable_not_physical() {
        let intf = mock_interface(true, true, true, false, false, true);
        assert_eq!(
            is_viable_lan_interface(&intf, |_| false),
            Err(ViabilityError::NotPhysical)
        );
    }

    #[test]
    fn is_viable_no_mac() {
        let intf = mock_interface(true, false, true, false, false, true);
        assert_eq!(
            is_viable_lan_interface(&intf, |_| true),
            Err(ViabilityError::NoMacAddress)
        );
    }

    #[test]
    fn is_viable_success() {
        let intf = mock_interface(true, true, true, false, false, true);
        assert_eq!(is_viable_lan_interface(&intf, |_| true), Ok(()));
    }
}
