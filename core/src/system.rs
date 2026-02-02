// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::process::Command;

use anyhow;

use pnet::datalink::NetworkInterface;

use zond_common::models::localhost::{FirewallStatus, IpServiceGroup};
use zond_common::system::SystemRepository;

pub struct SystemRepo;

impl SystemRepository for SystemRepo {
    fn get_local_services(&self) -> anyhow::Result<Vec<IpServiceGroup>> {
        use std::collections::{HashMap, HashSet};
        use std::net::{IpAddr, Ipv4Addr};
        use std::process::Command;
        use std::str::FromStr;
        use zond_common::models::localhost::{IpServiceGroup, Service};

        let output = Command::new("ss").arg("-lntuH").arg("-p").output();

        let stdout = match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return Ok(Vec::new()),
        };

        // Map: IpAddr -> (ProcessName -> Set<Ports>)
        struct ServiceBuilder {
            tcp_ports: HashMap<String, HashSet<u16>>,
            udp_ports: HashMap<String, HashSet<u16>>,
        }
        let mut ip_groups: HashMap<IpAddr, ServiceBuilder> = HashMap::new();

        for line in stdout.lines() {
            // Expected format (cols): Netid State Recv-Q Send-Q Local_Address:Port Peer_Address:Port Process
            // e.g. "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=123,fd=3))"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            let netid = parts[0];
            let state = parts[1];

            // For TCP, we only care about LISTEN. For UDP, state is usually UNCONN but listed because of -l
            if netid == "tcp" && state != "LISTEN" {
                continue;
            }

            // Local Address:Port can be "0.0.0.0:22", "[::]:22", "127.0.0.1:80", "*:80" (rare in ss -n)
            let local_addr_port = parts[4];

            // Parse IP and Port
            let (ip_str, port_str) = if let Some(idx) = local_addr_port.rfind(':') {
                (&local_addr_port[..idx], &local_addr_port[idx + 1..])
            } else {
                continue;
            };

            // Handle [::] wrapping for IPv6
            let clean_ip_str = ip_str
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_start_matches('*'); // ss sometimes uses * for 0.0.0.0

            let ip: IpAddr = if clean_ip_str.is_empty() || clean_ip_str == "*" {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else if let Ok(addr) = IpAddr::from_str(clean_ip_str) {
                addr
            } else {
                // Sometimes ss output with %interface suffix, e.g. fe80::1%eth0
                if let Some(pct_idx) = clean_ip_str.find('%') {
                    if let Ok(addr) = IpAddr::from_str(&clean_ip_str[..pct_idx]) {
                        addr
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            };

            let port: u16 = port_str.parse().unwrap_or(0);
            if port == 0 {
                continue;
            }

            // Parse Process
            // Last column usually `users:(("name",pid=123,fd=4))`
            // We want "name"
            let process_info = if let Some(last) = parts.last() {
                if last.starts_with("users:((") {
                    // Extract name
                    // Format: users:(("name",...))
                    if let Some(start_quote) = last.find('"') {
                        if let Some(end_quote) = last[start_quote + 1..].find('"') {
                            last[start_quote + 1..start_quote + 1 + end_quote].to_string()
                        } else {
                            "Unknown".to_string()
                        }
                    } else {
                        "Unknown".to_string()
                    }
                } else {
                    "Unknown".to_string()
                }
            } else {
                "Unknown".to_string()
            };

            let entry = ip_groups.entry(ip).or_insert(ServiceBuilder {
                tcp_ports: HashMap::new(),
                udp_ports: HashMap::new(),
            });

            if netid == "tcp" {
                entry
                    .tcp_ports
                    .entry(process_info)
                    .or_default()
                    .insert(port);
            } else if netid == "udp" {
                entry
                    .udp_ports
                    .entry(process_info)
                    .or_default()
                    .insert(port);
            }
        }

        let mut result = Vec::new();
        for (ip, builder) in ip_groups {
            let mut tcp_services: Vec<Service> = builder
                .tcp_ports
                .into_iter()
                .map(|(name, ports)| Service::new(name, ip, ports))
                .collect();
            tcp_services.sort_by(|a, b| a.name.cmp(&b.name));

            let mut udp_services: Vec<Service> = builder
                .udp_ports
                .into_iter()
                .map(|(name, ports)| Service::new(name, ip, ports))
                .collect();
            udp_services.sort_by(|a, b| a.name.cmp(&b.name));

            result.push(IpServiceGroup::new(ip, tcp_services, udp_services));
        }

        result.sort_by_key(|g| g.ip_addr);
        Ok(result)
    }

    fn get_firewall_status(&self) -> anyhow::Result<FirewallStatus> {
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

    fn get_network_interfaces(&self) -> anyhow::Result<Vec<NetworkInterface>> {
        zond_common::interface::get_prioritized_interfaces(10)
    }
}
