// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use crate::models::ip::set::IpSet;
use pnet::datalink::NetworkInterface;

/// Resolves a list of prioritized network interfaces (e.g. wired interfaces first).
///
/// Under the hood, this iterates over `pnet::datalink::interfaces()` directly.
pub fn get_prioritized_interfaces(limit: usize) -> anyhow::Result<Vec<NetworkInterface>> {
    let interfaces: Vec<NetworkInterface> = pnet::datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .collect();

    Ok(get_prioritized_interfaces_with(limit, interfaces))
}

/// Core prioritization logic, decoupled from OS interface dependencies for testing.
pub(crate) fn get_prioritized_interfaces_with(
    limit: usize,
    mut interfaces: Vec<NetworkInterface>,
) -> Vec<NetworkInterface> {
    interfaces.sort_by_key(|i| if i.name.starts_with("e") { 0 } else { 1 });
    interfaces.into_iter().take(limit).collect()
}

/// Determines if the interface is capable of Layer 2 operations (like ARP).
///
/// An interface is capable if it is not point-to-point, not a loopback, and holds a MAC address.
pub fn is_layer_2_capable(intf: &NetworkInterface) -> bool {
    !intf.is_point_to_point() && !intf.is_loopback() && intf.mac.is_some()
}

/// Validates whether the entire set of targets exists on the exact same layer 2 link as the interface.
pub fn is_on_link(intf: &NetworkInterface, ips: &IpSet) -> bool {
    for range in ips.ranges() {
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
    true
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

    fn mock_interface(name: &str, p2p: bool, loopback: bool, mac: bool) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            description: "".to_string(),
            index: 0,
            mac: if mac {
                Some(MacAddr::new(1, 2, 3, 4, 5, 6))
            } else {
                None
            },
            ips: vec![],
            flags: {
                let mut flags = 0;
                if p2p {
                    flags |= 16;
                }
                if loopback {
                    flags |= 8;
                }
                flags
            },
        }
    }

    #[test]
    fn test_is_layer_2_capable() {
        assert!(is_layer_2_capable(&mock_interface(
            "eth0", false, false, true
        )));
        assert!(!is_layer_2_capable(&mock_interface(
            "eth0", true, false, true
        )));
        assert!(!is_layer_2_capable(&mock_interface(
            "eth0", false, true, true
        )));
        assert!(!is_layer_2_capable(&mock_interface(
            "eth0", false, false, false
        )));
    }

    #[test]
    fn test_sorting_prioritizes_eth_interfaces() {
        let interfaces = vec![
            mock_interface("wlan0", false, false, true),
            mock_interface("eth0", false, false, true),
        ];

        let sorted = get_prioritized_interfaces_with(10, interfaces);
        assert_eq!(sorted[0].name, "eth0");
        assert_eq!(sorted[1].name, "wlan0");
    }
}
