// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::time::Duration;
use zond_common::config::ZondConfig;
use zond_common::models::host::Host;
use zond_common::models::ip::{range::Ipv4Range, set::IpSet};
use zond_core::scanner::{self, STOP_SIGNAL};

#[tokio::test]
async fn discovery_single_loopback() {
    let config: ZondConfig = ZondConfig {
        no_banner: true,
        no_dns: true,
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
async fn discovery_range_loopback() {
    let cfg: ZondConfig = ZondConfig {
        no_banner: true,
        no_dns: true,
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
        !hosts.is_empty() && hosts.len() <= 3,
        "Found anomalous amount of hosts: {}",
        hosts.len()
    );
}

#[tokio::test]
async fn stop_signal_aborts() {
    let mut targets = IpSet::new();
    let start_addr: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    let end_addr: Ipv4Addr = Ipv4Addr::new(127, 0, 255, 255);
    let range: Ipv4Range = Ipv4Range::new(start_addr, end_addr).unwrap();
    targets.insert_range(range);

    let cfg: ZondConfig = ZondConfig {
        no_banner: false,
        no_dns: true,
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
async fn discovery_empty_set() {
    let cfg: ZondConfig = ZondConfig {
        no_banner: true,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let targets = IpSet::new();
    let result = scanner::discover(targets, &cfg).await;

    assert!(result.is_ok());
    let hosts = result.unwrap();
    assert!(
        hosts.is_empty(),
        "Scanning empty set should return no hosts"
    );
}

#[tokio::test]
async fn discovery_redundant_ranges() {
    let cfg: ZondConfig = ZondConfig {
        no_banner: true,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut targets = IpSet::new();
    // Overlapping ranges: 127.0.0.1/31 (1, 2) and 127.0.0.1-5 (1, 2, 3, 4, 5)
    targets.insert_range("127.0.0.1/31".parse().unwrap());
    targets.insert_range("127.0.0.1-127.0.0.5".parse().unwrap());

    // IpSet should have merged these into a single range of 6 IPs (0-5)
    assert_eq!(targets.len(), 6);

    let result = scanner::discover(targets, &cfg).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn discovery_loopback_stress() {
    let cfg: ZondConfig = ZondConfig {
        no_banner: true,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut targets = IpSet::new();
    targets.insert_range("127.0.0.0/24".parse().unwrap());

    let start = std::time::Instant::now();
    let result = scanner::discover(targets, &cfg).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok());
    println!("Sweep of 256 IPs took {}ms", elapsed.as_millis());

    assert!(
        elapsed < Duration::from_secs(5),
        "Sweep took too long, concurrency might be broken"
    );
}
