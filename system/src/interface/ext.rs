// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

/// Adds IP network extractor utilities to `NetworkInterface`.
pub trait NetworkInterfaceExtension {
    /// Collects all IPv4 properties from the interface.
    fn get_ipv4_nets(&self) -> Vec<Ipv4Network>;
    /// Collects all IPv6 properties from the interface.
    fn get_ipv6_nets(&self) -> Vec<Ipv6Network>;
    /// Extracts a singular, primary non-loopback IPv4 network if present.
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn mock_interface() -> NetworkInterface {
        NetworkInterface {
            name: "test0".to_string(),
            description: "".to_string(),
            index: 0,
            mac: None,
            ips: vec![
                IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(127, 0, 0, 1), 8).unwrap()),
                IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap()),
                IpNetwork::V6(
                    Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128).unwrap(),
                ),
            ],
            flags: 0,
        }
    }

    #[test]
    fn get_ipv4_nets() {
        let intf = mock_interface();
        let v4s = intf.get_ipv4_nets();
        assert_eq!(v4s.len(), 2);
        assert_eq!(v4s[0].ip(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(v4s[1].ip(), Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn get_ipv6_nets() {
        let intf = mock_interface();
        let v6s = intf.get_ipv6_nets();
        assert_eq!(v6s.len(), 1);
        assert_eq!(v6s[0].ip(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn get_ipv4_range_ignores_loopback() {
        let intf = mock_interface();
        let best_range = intf.get_ipv4_range();
        assert!(best_range.is_some());
        assert_eq!(best_range.unwrap().ip(), Ipv4Addr::new(192, 168, 1, 100));
    }
}
