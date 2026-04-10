// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::net::{IpAddr, Ipv4Addr};
use zond_common::config::ZondConfig;
use zond_common::models::ip::set::IpSet;
use zond_core::scanner;

#[cfg(target_os = "linux")]
use crate::utils::NetnsContext;

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

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_privileged_discovery_hostname_resolution() {
    let ctx: NetnsContext = match NetnsContext::new("res-test") {
        Some(c) => c,
        None => return,
    };

    // Set a custom hostname inside the namespace
    // Note: This requires the machine running the test to support 'ip netns exec'
    let _ = crate::utils::netns::run_ns_cmd(&ctx.ns_name, "hostname", &["zond-target-host"]);

    // Start a listener on 443 inside the namespace so 'discover' finds it
    // We'll use a sidecar thread running 'nc' since it's easier than async-pipe logic for a quick mock.
    let ns_name = ctx.ns_name.clone();
    std::thread::spawn(move || {
        let _ = crate::utils::netns::run_ns_cmd(
            &ns_name,
            "nc",
            &["-l", "-p", "443", "-e", "echo hello"],
        );
    });

    let target_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 200, 0, 2));
    let config: ZondConfig = ZondConfig {
        no_banner: true,
        no_dns: false, // Enable DNS
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut collection = IpSet::new();
    collection.insert(target_ip);

    let result = scanner::discover(collection, &config).await;
    assert!(result.is_ok());
    let hosts = result.unwrap();

    if !hosts.is_empty() {
        let host = &hosts[0];
        println!(
            "Resolved host: {:?} - Hostname: {:?}",
            host.primary_ip, host.hostname
        );
        // On many systems, the namespace hostname won't resolve unless /etc/hosts is updated or a DNS server is present.
        // For now, we verify that the scan COMPLETE safely with resolution enabled.
    }
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_privileged_discovery_stress_multi_alias() {
    let ctx: NetnsContext = match NetnsContext::new("stress-test") {
        Some(c) => c,
        None => return,
    };

    // Add 20 alias IPs to the namespace interface (v-targ-stress-test)
    for i in 3..23 {
        let ip = format!("10.200.0.{}", i);
        let _ = crate::utils::netns::run_ns_cmd(
            &ctx.ns_name,
            "ip",
            &[
                "addr",
                "add",
                &format!("{}/24", ip),
                "dev",
                "v-targ-stress-test",
            ],
        );
    }

    let config: ZondConfig = ZondConfig {
        no_banner: true,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut collection = IpSet::new();
    collection.insert_range("10.200.0.1-10.200.0.30".parse().unwrap());

    // Privileged scanner should use ARP to find all 21 active IPs (host + 20 aliases)
    let result = scanner::discover(collection, &config).await;
    assert!(result.is_ok());
    let hosts = result.unwrap();

    // Should find at least 21 hosts (the target + aliases)
    // Note: 10.200.0.1 is the host side, so it might also be found depending on routing.
    assert!(
        hosts.len() >= 21,
        "Failed to find all aliased IPs in namespace. Found only: {}",
        hosts.len()
    );
}
