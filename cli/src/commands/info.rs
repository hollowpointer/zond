// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use anyhow;
use colored::*;
use is_root::is_root;
use pnet::datalink::NetworkInterface;
use std::env;
use sys_info;

use crate::{
    terminal::{
        colors,
        print::{self, GLOBAL_KEY_WIDTH},
    },
    zprint,
};
use zond_common::{
    config::Config,
    models::localhost::{FirewallStatus, IpServiceGroup, Service},
};
use zond_core::info::InfoService;
use zond_core::system::SystemRepo;

pub fn info(_cfg: &Config) -> anyhow::Result<()> {
    print::Print::header("about the tool");
    zprint!(
        "{}",
        format!(
            "{}",
            "Zond is a quick tool for mapping and exploring networks.".color(colors::TEXT_DEFAULT)
        )
        .as_str()
    );
    zprint!();
    GLOBAL_KEY_WIDTH.set(10);

    let system_repo = Box::new(SystemRepo);
    let service = InfoService::new(system_repo);

    let system_info = service.get_system_info()?;

    if !is_root() {
        print_about_the_tool();
        print_local_system()?;
        let interfaces = zond_common::interface::get_prioritized_interfaces(5)?;
        print_network_interfaces(&interfaces)?;
        print::Print::end_of_program();
        return Ok(());
    }

    let mut longest_name = 0;
    for group in &system_info.services {
        for s in &group.tcp_services {
            if s.name.len() > longest_name {
                longest_name = s.name.len();
            }
        }
        for s in &group.udp_services {
            if s.name.len() > longest_name {
                longest_name = s.name.len();
            }
        }
    }

    GLOBAL_KEY_WIDTH.set(std::cmp::max(longest_name + 6, 10));

    print_about_the_tool();
    print_local_system()?;
    print_firewall_status(system_info.firewall)?;
    print_local_services(system_info.services)?;

    let interfaces = zond_common::interface::get_prioritized_interfaces(5)?;
    print_network_interfaces(&interfaces)?;

    print::Print::end_of_program();
    Ok(())
}

fn print_about_the_tool() {
    print::aligned_line("Version", env!("CARGO_PKG_VERSION"));
    print::aligned_line("Author", "hollowpointer");
    print::aligned_line("E-Mail", "hollowpointer@pm.me");
    print::aligned_line("License", "MPL-2.0");
    print::aligned_line("Repository", "https://github.com/hollowpointer/zond");
}

fn print_local_system() -> anyhow::Result<()> {
    print::Print::header("local system");
    let hostname: String = sys_info::hostname()?;
    print::aligned_line("Hostname", hostname);
    let release = sys_info::os_release().unwrap_or_else(|_| String::from(""));
    let os_name = sys_info::os_type()?;
    print::aligned_line("OS", format!("{} {}", os_name, release).as_str());
    if let Ok(user) = env::var("USER").or_else(|_| env::var("USERNAME")) {
        print::aligned_line("User", user);
    }
    Ok(())
}

fn print_network_interfaces(interfaces: &[NetworkInterface]) -> anyhow::Result<()> {
    print::Print::header("network interfaces");

    for (idx, intf) in interfaces.iter().enumerate() {
        crate::terminal::network_fmt::print_interface(intf, idx);

        if idx + 1 != interfaces.len() {
            zprint!();
        }
    }
    Ok(())
}

fn print_firewall_status(status: FirewallStatus) -> anyhow::Result<()> {
    print::Print::header("firewall status");
    let status_str = match status {
        FirewallStatus::Active => "active".green().bold(),
        FirewallStatus::Inactive => "inactive".red().bold(),
        FirewallStatus::NotDetected => "inactive (not detected)".yellow(),
    };

    print::aligned_line("Status", status_str);

    if status == FirewallStatus::NotDetected {
        let output = format!(
            "{}",
            "No active firewall detected. Services may be exposed to public."
                .color(colors::TEXT_DEFAULT)
        );
        zprint!();
        zprint!("{}", &output);
    }

    Ok(())
}

fn print_local_services(service_groups: Vec<IpServiceGroup>) -> anyhow::Result<()> {
    print::Print::header("local services");

    for (idx, group) in service_groups.iter().enumerate() {
        let ip_addr = group.ip_addr;
        let tcp_services = &group.tcp_services;
        let udp_services = &group.udp_services;

        let has_tcp = !tcp_services.is_empty();
        let has_udp = !udp_services.is_empty();

        if !has_tcp && !has_udp {
            continue;
        }

        // Print IP Address Header
        let ip_addr_colored = if ip_addr.is_ipv4() {
            ip_addr.to_string().color(colors::IPV4_ADDR)
        } else {
            ip_addr.to_string().color(colors::IPV6_ADDR)
        };
        zprint!(
            "{}",
            format!(
                "{}",
                format!("[{}]", ip_addr_colored).color(colors::SEPARATOR)
            )
            .as_str()
        );

        // Print TCP Services
        if has_tcp {
            let tcp_branch = if has_udp { "├─" } else { "└─" };
            let vertical_branch = if has_udp { "│" } else { " " };
            zprint!(
                "{}",
                format!(
                    " {} {}",
                    tcp_branch.color(colors::SEPARATOR),
                    "TCP".color(colors::PRIMARY)
                )
                .as_str()
            );

            for (i, service) in tcp_services.iter().enumerate() {
                print_service_line(i, service, vertical_branch, tcp_services.len());
            }
        }

        // Print UDP Services
        if has_udp {
            let udp_branch = "└─"; // UDP is always the last branch if it exists
            let vertical_branch = " "; // No vertical (│) line needed below UDP
            zprint!(
                "{}",
                format!(
                    " {} {}",
                    udp_branch.color(colors::SEPARATOR),
                    "UDP".color(colors::PRIMARY)
                )
                .as_str()
            );

            for (i, service) in udp_services.iter().enumerate() {
                print_service_line(i, service, vertical_branch, udp_services.len())
            }
        }

        if idx + 1 != service_groups.len() {
            zprint!();
        }
    }
    Ok(())
}

fn print_service_line(idx: usize, service: &Service, vertical_branch: &str, services_len: usize) {
    let last: bool = idx + 1 == services_len;
    let branch: ColoredString = if last {
        "└─".color(colors::SEPARATOR)
    } else {
        "├─".color(colors::SEPARATOR)
    };
    let dashes: i32 = GLOBAL_KEY_WIDTH.get() as i32 - service.name.len() as i32 - 5;
    let dashes = if dashes < 0 { 0 } else { dashes as usize };

    let num_ports = service.local_ports.len();

    let mut port_strings: Vec<String> = service
        .local_ports
        .iter()
        .take(5)
        .map(|p: &u16| p.to_string())
        .collect();

    if num_ports > 5 {
        port_strings.push("...".to_string());
    }
    let ports: String = port_strings.join(", ");

    let output: String = format!(
        " {}   {branch} {}{}{}{}",
        vertical_branch.color(colors::SEPARATOR),
        service.name.color(colors::SECONDARY),
        ".".repeat(dashes).color(colors::SEPARATOR),
        ": ".color(colors::SEPARATOR),
        ports.color(colors::TEXT_DEFAULT)
    );
    zprint!("{}", &output);
}
