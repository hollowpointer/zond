// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::net::{IpAddr, TcpListener};
use zond_common::config::ZondConfig;
use zond_common::models::ip::set::IpSet;
use zond_core::scanner;
use pnet::datalink;

/// Verifies that Windows hardware heuristics (physical/wireless detection)
/// execute correctly and find plausible adapters.
#[tokio::test]
async fn windows_hardware_heuristics() {
    let interfaces = datalink::interfaces();
    assert!(!interfaces.is_empty(), "No network interfaces found on the system");

    let mut physically_found = 0;
    for iface in interfaces {
        // These calls verify that the GetIfTable2 FFI logic works on the real host
        let physical = zond_common::net::interface::os::is_physical(&iface);
        let wireless = zond_common::net::interface::os::is_wireless(&iface);

        if physical {
            physically_found += 1;
        }

        // Integrity check: Wireless adapters are always physical
        if wireless {
            assert!(physical, "Interface {} identified as wireless but not physical", iface.name);
        }
    }

    // On a real machine, at least one interface (Ethernet or Wi-Fi) should be physical
    assert!(physically_found > 0, "No physical adapters detected - verify Administrator privileges");
}

/// Performs a full unprivileged discovery scan against a local mock listener.
/// This verifies the orchestration path: Dispatcher -> Connect -> Result.
#[tokio::test]
async fn windows_local_discovery_integration() {
    let cfg = ZondConfig {
        no_banner: true,
        no_dns: true,
        quiet: 0,
        ..Default::default()
    };

    // 1. Find a valid local IPv4 interface
    let interfaces = datalink::interfaces();
    let target_ip = interfaces.iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .flat_map(|i| i.ips.iter())
        .find(|ip| ip.is_ipv4())
        .map(|ip| ip.ip())
        .expect("No active local IPv4 interface found for testing");

    // 2. Spawn a mock listener on a random port
    let listener = TcpListener::bind((target_ip, 0)).expect("Failed to bind mock listener");
    let local_addr = listener.local_addr().unwrap();
    let port = local_addr.port();

    // 3. Run discovery targeting that specific IP
    let mut targets = IpSet::new();
    targets.insert(target_ip);

    let handle = tokio::spawn(async move {
        scanner::discover(targets, &cfg).await
    });

    // We give the scanner a moment. Since it's local, RTT is near zero.
    let result = handle.await.unwrap();
    assert!(result.is_ok(), "Scanner failed on Windows: {:?}", result.err());
    
    let hosts = result.unwrap();
    
    // 4. Verify the host was found
    assert!(!hosts.is_empty(), "Scanner did not find the local host on Windows");
    assert_eq!(hosts[0].primary_ip, target_ip);
    
    // Explicitly keep listener alive until here
    drop(listener);
}

/// Verifies loopback discovery on Windows.
#[tokio::test]
async fn windows_loopback_fidelity() {
    let cfg = ZondConfig {
        no_banner: true,
        no_dns: true,
        ..Default::default()
    };

    let mut targets = IpSet::new();
    let localhost = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
    targets.insert(localhost);

    let result = scanner::discover(targets, &cfg).await;
    assert!(result.is_ok());
    let hosts = result.unwrap();

    assert!(!hosts.is_empty(), "Loopback discovery failed on Windows");
    assert_eq!(hosts[0].primary_ip, localhost);
}
