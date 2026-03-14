// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::process::Command;

use anyhow;
use pnet::datalink::NetworkInterface;
use zond_common::models::localhost::{FirewallStatus, IpServiceGroup, Service};

/// Intermediate representation of a socket entry.
#[derive(Debug)]
struct SocketInfo {
    ip: IpAddr,
    port: u16,
    protocol: String, // "tcp" or "udp"
    process_name: String,
}

pub fn get_local_services() -> anyhow::Result<Vec<IpServiceGroup>> {
    let entries = retrieve_sockets()?;
    Ok(aggregate_services(entries))
}

#[cfg(not(target_os = "windows"))]
fn retrieve_sockets() -> anyhow::Result<Vec<SocketInfo>> {
    let raw_data = retrieve_raw_socket_data()?;
    Ok(parse_socket_data(&raw_data))
}

#[cfg(target_os = "windows")]
fn retrieve_sockets() -> anyhow::Result<Vec<SocketInfo>> {
    windows_impl::retrieve_native_sockets()
}

#[cfg(not(target_os = "windows"))]
fn retrieve_raw_socket_data() -> anyhow::Result<String> {
    use std::process::Command;
    let output = Command::new("ss").arg("-lntuH").arg("-p").output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Ok(String::new())
    }
}

#[cfg(not(target_os = "windows"))]
fn parse_socket_data(stdout: &str) -> Vec<SocketInfo> {
    stdout.lines().filter_map(parse_socket_line).collect()
}

#[cfg(not(target_os = "windows"))]
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

#[cfg(not(target_os = "windows"))]
fn parse_address_port(addr_port: &str) -> Option<(IpAddr, u16)> {
    use std::net::Ipv4Addr;
    use std::str::FromStr;
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

#[cfg(not(target_os = "windows"))]
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
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("netsh")
            .args(["advfirewall", "show", "allprofiles", "state"])
            .output()?;
        
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.to_lowercase().contains("on") {
                return Ok(FirewallStatus::Active);
            }
        }
        Ok(FirewallStatus::NotDetected)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(FirewallStatus::NotDetected)
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::net::Ipv4Addr;
    use sysinfo::{Pid, ProcessesToUpdate, System};
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_LISTEN,
        TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct MIB_TCPROW_OWNER_PID {
        dwState: u32,
        dwLocalAddr: u32,
        dwLocalPort: u32,
        dwRemoteAddr: u32,
        dwRemotePort: u32,
        dwOwningPid: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct MIB_TCPTABLE_OWNER_PID_INTERNAL {
        dwNumEntries: u32,
        table: [MIB_TCPROW_OWNER_PID; 1],
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct MIB_UDPROW_OWNER_PID {
        dwLocalAddr: u32,
        dwLocalPort: u32,
        dwOwningPid: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct MIB_UDPTABLE_OWNER_PID_INTERNAL {
        dwNumEntries: u32,
        table: [MIB_UDPROW_OWNER_PID; 1],
    }

    pub fn retrieve_native_sockets() -> anyhow::Result<Vec<SocketInfo>> {
        let mut entries = Vec::new();
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        // 1. TCP IPv4
        let tcp_table = get_tcp_ipv4_table()?;
        for i in 0..tcp_table.dwNumEntries as usize {
            let row = unsafe { &*tcp_table.table.as_ptr().add(i) };
            if row.dwState == MIB_TCP_STATE_LISTEN as u32 {
                let pid = row.dwOwningPid;
                let process_name = sys.process(Pid::from(pid as usize))
                    .map(|p| p.name().to_string_lossy().into_owned())
                    .unwrap_or_else(|| "Unknown".to_string());
                
                entries.push(SocketInfo {
                    ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                    port: u16::from_be(row.dwLocalPort as u16),
                    protocol: "tcp".to_string(),
                    process_name,
                });
            }
        }

        // 2. UDP IPv4
        let udp_table = get_udp_ipv4_table()?;
        for i in 0..udp_table.dwNumEntries as usize {
            let row = unsafe { &*udp_table.table.as_ptr().add(i) };
            let pid = row.dwOwningPid;
            let process_name = sys.process(Pid::from(pid as usize))
                .map(|p| p.name().to_string_lossy().into_owned())
                .unwrap_or_else(|| "Unknown".to_string());
            
            entries.push(SocketInfo {
                ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                port: u16::from_be(row.dwLocalPort as u16),
                protocol: "udp".to_string(),
                process_name,
            });
        }

        Ok(entries)
    }

    fn get_tcp_ipv4_table() -> anyhow::Result<Box<MIB_TCPTABLE_OWNER_PID_INTERNAL>> {
        let mut size = 0;
        unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                1,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            );
        }

        let mut buffer = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                1,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };

        if ret == NO_ERROR {
            let ptr = Box::into_raw(buffer.into_boxed_slice()) as *mut MIB_TCPTABLE_OWNER_PID_INTERNAL;
            Ok(unsafe { Box::from_raw(ptr) })
        } else {
            anyhow::bail!("Failed to get TCP table: {}", ret)
        }
    }

    fn get_udp_ipv4_table() -> anyhow::Result<Box<MIB_UDPTABLE_OWNER_PID_INTERNAL>> {
        let mut size = 0;
        unsafe {
            GetExtendedUdpTable(
                std::ptr::null_mut(),
                &mut size,
                1,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }

        let mut buffer = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                1,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };

        if ret == NO_ERROR {
            let ptr = Box::into_raw(buffer.into_boxed_slice()) as *mut MIB_UDPTABLE_OWNER_PID_INTERNAL;
            Ok(unsafe { Box::from_raw(ptr) })
        } else {
            anyhow::bail!("Failed to get UDP table: {}", ret)
        }
    }
}

pub fn get_network_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
    zond_common::interface::get_prioritized_interfaces(10)
}
