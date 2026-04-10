// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::net::{IpAddr, Ipv4Addr};
use zond_common::config::ZondConfig;
use zond_common::models::ip::set::IpSet;
use zond_common::models::port::{PortSet, PortState};
use zond_common::models::target::{TargetMap, TargetSet};
use zond_core::scanner;

#[cfg(target_os = "linux")]
use crate::utils::NetnsContext;

#[tokio::test]
#[cfg(target_os = "linux")]
async fn port_state_fidelity_unprivileged() {
    let ctx = match NetnsContext::new("fidelity") {
        Some(c) => c,
        None => return,
    };

    let target_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 200, 0, 2));
    let ns_name = ctx.ns_name.clone();

    // 1. OPEN: Standard listener
    std::thread::spawn({
        let ns = ns_name.clone();
        move || {
            let _ =
                crate::utils::netns::run_ns_cmd(&ns, "nc", &["-l", "-p", "80", "-e", "echo hi"]);
        }
    });

    // 2. FILTERED: Use iptables to DROP port 443
    let _ = crate::utils::netns::run_ns_cmd(
        &ns_name,
        "iptables",
        &["-A", "INPUT", "-p", "tcp", "--dport", "443", "-j", "DROP"],
    );

    // 3. BLOCKED: Use iptables to REJECT port 22
    let _ = crate::utils::netns::run_ns_cmd(
        &ns_name,
        "iptables",
        &[
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            "22",
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ],
    );

    let config = ZondConfig {
        no_banner: true,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut target_map = TargetMap::new();
    let mut ip_set = IpSet::new();
    ip_set.insert(target_ip);

    // Scan 80 (Open), 443 (Filtered/Ghosted), 22 (Blocked), and 8080 (Closed - no listener)
    let port_set = PortSet::try_from("80, 443, 22, 8080").unwrap();
    target_map.add_unit(TargetSet::new(ip_set, port_set));

    // Execution (non-root scan on host can still target namespace IPs)
    let result = scanner::scan(target_map, &config).await;
    assert!(result.is_ok());
    let hosts = result.unwrap();

    assert!(!hosts.is_empty());
    let host = &hosts[0];

    // Verify 80 is OPEN
    let p80 = host.ports().iter().find(|p| p.number == 80).unwrap();
    assert_eq!(p80.state, PortState::Open);

    // Verify 443 is GHOSTED (Filtered)
    let p443 = host.ports().iter().find(|p| p.number == 443).unwrap();
    assert_eq!(p443.state, PortState::Ghosted);

    // Verify 22 is BLOCKED
    let p22 = host.ports().iter().find(|p| p.number == 22).unwrap();
    assert_eq!(p22.state, PortState::Blocked);

    // Verify 8080 is CLOSED
    let p8080 = host.ports().iter().find(|p| p.number == 8080).unwrap();
    assert_eq!(p8080.state, PortState::Closed);
}
