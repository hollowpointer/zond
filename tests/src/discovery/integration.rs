// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

#![cfg(test)]
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::time::Duration;
use zond_common::config::ZondConfig;
use zond_common::models::host::Host;
use zond_common::models::port::PortSet;
use zond_common::models::ip::{set::IpSet, range::Ipv4Range};
use zond_core::scanner::{self, STOP_SIGNAL};

#[cfg(target_os = "linux")]
use crate::utils::NetnsContext;

#[tokio::test]
async fn test_discovery_single_loopback() {
    let config: ZondConfig = ZondConfig {
        no_banner: true,
        no_dns: true,
        ports: PortSet::default(),
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut targets = IpSet::new();
    let localhost: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    targets.insert(localhost);

    let result = scanner::discover(targets, &config).await;

    assert!(result.is_ok(), "Discovery failed: {:?}", result.err());
    let hosts: Vec<Host> = result.unwrap();

    assert!(!hosts.is_empty(), "No hosts found when scanning localhost");
    assert!(hosts[0].min_rtt().is_some(), "No RTT's were recorded");

    let found_ip: IpAddr = hosts[0].primary_ip;
    assert_eq!(
        found_ip, localhost,
        "Found host IP does not match expected localhost IP"
    );
}

#[tokio::test]
async fn test_discovery_range_loopback() {
    let cfg: ZondConfig = ZondConfig {
        no_banner: true,
        no_dns: true,
        ports: PortSet::default(),
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut targets = IpSet::new();
    let start: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    let end: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
    let range: Ipv4Range = Ipv4Range::new(start, end).unwrap();
    targets.insert_range(range);

    let result = scanner::discover(targets, &cfg).await;

    assert!(result.is_ok(), "Discovery failed: {:?}", result.is_err());
    let hosts: Vec<Host> = result.unwrap();

    // macOS defaults to only assigning 127.0.0.1, whereas Linux assigns the full /8 block.
    // So macOS might just find 1, while Linux finds 3.
    assert!(
        hosts.len() >= 1 && hosts.len() <= 3,
        "Found anomalous amount of hosts: {}",
        hosts.len()
    );
}

#[tokio::test]
async fn test_stop_signal_aborts() {
    let mut targets = IpSet::new();
    let start_addr: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    let end_addr: Ipv4Addr = Ipv4Addr::new(127, 0, 255, 255);
    let range: Ipv4Range = Ipv4Range::new(start_addr, end_addr).unwrap();
    targets.insert_range(range);

    let cfg: ZondConfig = ZondConfig {
        no_banner: false,
        no_dns: true,
        ports: PortSet::default(),
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    STOP_SIGNAL.store(false, Ordering::Relaxed);

    let handle = tokio::spawn(async move { scanner::discover(targets, &cfg).await });

    // Give it a moment to boot up the threads
    tokio::time::sleep(Duration::from_millis(50)).await;

    STOP_SIGNAL.store(true, Ordering::Relaxed);

    // Give it a generous allowance to unwind pending connections/timers (macOS is slower with raw sockets)
    let result = tokio::time::timeout(Duration::from_millis(1500), handle).await;

    assert!(result.is_ok(), "Scanner did not stop in time");
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_privileged_discovery_netns() {
    let _ctx: NetnsContext = match NetnsContext::new("test1") {
        Some(c) => c,
        None => {
            eprintln!("Skipping netns test: Requires root privileges or 'ip' command.");
            return;
        }
    };

    let target_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 200, 0, 2));

    let config: ZondConfig = ZondConfig {
        no_banner: true,
        no_dns: true,
        ports: PortSet::default(),
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut collection = IpSet::new();
    collection.insert(target_ip);

    let result = scanner::discover(collection, &config).await;

    match result {
        Ok(hosts) => {
            assert!(!hosts.is_empty(), "Should find the target in the namespace");
            let host = hosts
                .iter()
                .find(|h| h.primary_ip == target_ip)
                .expect("Target IP not found in results");

            assert!(
                host.mac.is_some(),
                "Should resolve MAC address for local neighbor"
            );
            println!("Found host: {:?} with MAC {:?}", host.primary_ip, host.mac);
        }
        Err(e) => panic!("Discovery failed: {}", e),
    }
}

#[test]
fn test_lan_network_resolution() {
    // Assert that the machine running the integration test has at least 1 viable interface 
    // that resolves via our platform agnostics hooks (macOS networksetup, Linux sysfs, Windows GetIfTable2).
    let result = zond_common::net::interface::get_lan_network();
    assert!(result.is_ok(), "Expected no OS or Viability errors during interface parsing");
    
    // Virtualized headless CI runners might return None here since they use virtual bridges,
    // but the FFI/Syscalls must execute safely regardless!
    println!("Resolved LAN network: {:?}", result.unwrap());
}

#[test]
fn test_prioritized_interfaces_resolution() {
    let interfaces_res = zond_common::net::interface::get_prioritized_interfaces(10);
    assert!(interfaces_res.is_ok());
    let interfaces = interfaces_res.unwrap();
    assert!(!interfaces.is_empty(), "Expected at least 1 UP, non-loopback network interface on the host natively");
}
