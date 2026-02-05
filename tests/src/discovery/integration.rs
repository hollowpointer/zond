// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

#![cfg(test)]
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::time::Duration;
use zond_common::config::Config;
use zond_common::models::host::Host;
use zond_common::models::range::{IpCollection, Ipv4Range};
use zond_core::scanner::{self, STOP_SIGNAL};

use crate::utils::NetnsContext;

#[tokio::test]
async fn test_discovery_single_loopback() {
    let config: Config = Config {
        no_banner: true,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut targets: IpCollection = IpCollection::new();
    let localhost: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    targets.add_single(localhost);

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
    let cfg: Config = Config {
        no_banner: true,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut targets: IpCollection = IpCollection::new();
    let start: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    let end: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
    let range: Ipv4Range = Ipv4Range::new(start, end);
    targets.add_range(range);

    let result = scanner::discover(targets, &cfg).await;

    assert!(result.is_ok(), "Discovery failed: {:?}", result.is_err());
    let hosts: Vec<Host> = result.unwrap();

    assert!(
        hosts.len() == 3,
        "Found incorrect amount of hosts: {}",
        hosts.len()
    );
}

#[tokio::test]
async fn test_stop_signal_aborts() {
    let mut targets: IpCollection = IpCollection::new();
    let start_addr: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    let end_addr: Ipv4Addr = Ipv4Addr::new(127, 0, 255, 255);
    let range: Ipv4Range = Ipv4Range::new(start_addr, end_addr);
    targets.add_range(range);

    let cfg: Config = Config {
        no_banner: false,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    STOP_SIGNAL.store(false, Ordering::Relaxed);

    let handle = tokio::spawn(async move { scanner::discover(targets, &cfg).await });

    tokio::time::sleep(Duration::from_millis(10)).await;

    STOP_SIGNAL.store(true, Ordering::Relaxed);

    let result = tokio::time::timeout(Duration::from_millis(50), handle).await;

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

    let config: Config = Config {
        no_banner: true,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut collection: IpCollection = IpCollection::new();
    collection.add_single(target_ip);

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
