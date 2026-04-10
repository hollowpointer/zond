// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::net::SocketAddr;
use tokio::net::TcpListener;
use zond_common::config::ZondConfig;
use zond_common::models::ip::set::IpSet;
use zond_common::models::port::{PortSet, PortState};
use zond_common::models::target::{TargetMap, TargetSet};
use zond_core::scanner;

#[tokio::test]
async fn test_tcp_connect_scan_open_port() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind listener");
    let addr: SocketAddr = listener.local_addr().expect("Failed to get local addr");
    let port_num = addr.port();

    let config = ZondConfig {
        no_banner: true,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut target_map = TargetMap::new();
    let mut ip_set = IpSet::new();
    ip_set.insert(addr.ip());

    let port_set = PortSet::try_from(port_num.to_string().as_str()).unwrap();

    target_map.add_unit(TargetSet::new(ip_set, port_set));

    let result = scanner::scan(target_map, &config).await;

    assert!(result.is_ok(), "Scan failed: {:?}", result.err());
    let hosts = result.unwrap();

    assert_eq!(hosts.len(), 1, "Expected 1 host to be found");
    assert_eq!(hosts[0].primary_ip, addr.ip());

    let found_port = hosts[0]
        .ports()
        .iter()
        .find(|p| p.number == port_num)
        .expect("Target port not found in results");
    assert_eq!(
        found_port.state,
        PortState::Open,
        "Port should be reported as Open"
    );
}

#[tokio::test]
async fn test_tcp_connect_scan_closed_port() {
    let port_num = {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind");
        listener.local_addr().unwrap().port()
    };

    let config = ZondConfig {
        no_banner: true,
        no_dns: true,
        redact: false,
        quiet: 0,
        disable_input: true,
    };

    let mut target_map = TargetMap::new();
    let mut ip_set = IpSet::new();
    ip_set.insert("127.0.0.1".parse().unwrap());

    let port_set = PortSet::try_from(port_num.to_string().as_str()).unwrap();

    target_map.add_unit(TargetSet::new(ip_set, port_set));

    let result = scanner::scan(target_map, &config).await;

    assert!(result.is_ok());
    let hosts = result.unwrap();

    if !hosts.is_empty() {
        if let Some(port) = hosts[0].ports().iter().find(|p| p.number == port_num) {
            assert_eq!(port.state, PortState::Closed);
        }
    }
}
