// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::str::FromStr;

use anyhow;
use pnet::datalink::NetworkInterface;
use zond_common::models::localhost::{FirewallStatus, IpServiceGroup, Service};

/// Intermediate representation of a socket entry parsed from `ss` output.
#[derive(Debug)]
struct SocketInfo {
    ip: IpAddr,
    port: u16,
    protocol: String, // "tcp" or "udp"
    process_name: String,
}

pub fn get_local_services() -> anyhow::Result<Vec<IpServiceGroup>> {
    let raw_data = retrieve_raw_socket_data()?;
    let entries = parse_socket_data(&raw_data);
    Ok(aggregate_services(entries))
}

fn retrieve_raw_socket_data() -> anyhow::Result<String> {
    let output = Command::new("ss").arg("-lntuH").arg("-p").output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Ok(String::new())
    }
}

fn parse_socket_data(stdout: &str) -> Vec<SocketInfo> {
    stdout.lines().filter_map(parse_socket_line).collect()
}

fn parse_socket_line(line: &str) -> Option<SocketInfo> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let netid = parts[0];
    let state = parts[1];

    // Filter relevant sockets: TCP sets to LISTEN, UDP is usually UNCONN (but listed due to -l)
    if netid == "tcp" && state != "LISTEN" {
        return None;
    }
    if netid != "tcp" && netid != "udp" {
        return None;
    }

    let local_addr_port = parts[4];
    let (ip, port) = parse_address_port(local_addr_port)?;

    // Process info is usually in the last column
    let process_name = if let Some(users_field) = parts.last() {
        parse_process_name(users_field).unwrap_or_else(|| "Unknown".to_string())
    } else {
        "Unknown".to_string()
    };

    Some(SocketInfo {
        ip,
        port,
        protocol: netid.to_string(),
        process_name,
    })
}

fn parse_address_port(addr_port: &str) -> Option<(IpAddr, u16)> {
    let idx = addr_port.rfind(':')?;
    let ip_str = &addr_port[..idx];
    let port_str = &addr_port[idx + 1..];

    let clean_ip_str = ip_str
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_start_matches('*'); // ss sometimes uses * for 0.0.0.0

    let ip = if clean_ip_str.is_empty() || clean_ip_str == "*" {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else if let Ok(addr) = IpAddr::from_str(clean_ip_str) {
        addr
    } else {
        // Handle interface suffix (e.g., fe80::1%eth0)
        let pct_idx = clean_ip_str.find('%')?;
        IpAddr::from_str(&clean_ip_str[..pct_idx]).ok()?
    };

    let port = port_str.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }

    Some((ip, port))
}

fn parse_process_name(users_field: &str) -> Option<String> {
    if !users_field.starts_with("users:((") {
        return None;
    }

    // Format: users:(("name",...))
    let start_quote = users_field.find('"')?;
    let remainder = &users_field[start_quote + 1..];
    let end_quote = remainder.find('"')?;

    Some(remainder[..end_quote].to_string())
}

fn aggregate_services(entries: Vec<SocketInfo>) -> Vec<IpServiceGroup> {
    struct ServiceBuilder {
        tcp_ports: HashMap<String, HashSet<u16>>,
        udp_ports: HashMap<String, HashSet<u16>>,
    }

    let mut ip_groups: HashMap<IpAddr, ServiceBuilder> = HashMap::new();

    for entry in entries {
        let builder = ip_groups.entry(entry.ip).or_insert(ServiceBuilder {
            tcp_ports: HashMap::new(),
            udp_ports: HashMap::new(),
        });

        let target_map = if entry.protocol == "tcp" {
            &mut builder.tcp_ports
        } else {
            &mut builder.udp_ports
        };

        target_map
            .entry(entry.process_name)
            .or_default()
            .insert(entry.port);
    }

    let mut result = Vec::new();
    for (ip, builder) in ip_groups {
        let mut tcp_services = convert_to_services(ip, builder.tcp_ports);
        let mut udp_services = convert_to_services(ip, builder.udp_ports);

        tcp_services.sort_by(|a, b| a.name.cmp(&b.name));
        udp_services.sort_by(|a, b| a.name.cmp(&b.name));

        result.push(IpServiceGroup::new(ip, tcp_services, udp_services));
    }

    result.sort_by_key(|g| g.ip_addr);
    result
}

fn convert_to_services(ip: IpAddr, port_map: HashMap<String, HashSet<u16>>) -> Vec<Service> {
    port_map
        .into_iter()
        .map(|(name, ports)| Service::new(name, ip, ports))
        .collect()
}

pub fn get_firewall_status() -> anyhow::Result<FirewallStatus> {
    #[cfg(target_os = "linux")]
    {
        let ufw_active = Command::new("ufw").arg("status").output().is_ok();
        let firewalld_active = Command::new("firewall-cmd").arg("--state").output().is_ok();

        if ufw_active || firewalld_active {
            Ok(FirewallStatus::Active)
        } else {
            Ok(FirewallStatus::NotDetected)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(FirewallStatus::NotDetected)
    }
}

pub fn get_network_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
    zond_common::interface::get_prioritized_interfaces(10)
}
