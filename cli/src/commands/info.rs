// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Local System Information
//!
//! This module provides the `info` command, which displays detailed information about the
//! local system, including network interfaces, firewall status, and running services.
//!
//! It serves as a diagnostic tool for users to quickly assess their local network configuration
//! and potential security exposure.

use anyhow;
use colored::*;
use is_root::is_root;
use pnet::datalink::NetworkInterface;
use std::{cmp, env};
use sys_info;

use crate::{
    terminal::{colors, print},
    zprint,
};
use zond_engine::{
    config::ZondConfig,
    models::localhost::{FirewallStatus, IpServiceGroup, Service},
};

/// Prints system and network information to the terminal.
///
/// This function gathers data from the system (hostname, OS, etc.) and network interfaces.
/// If run as root, it also performs a deeper analysis of running services and firewall status.
pub fn info(_cfg: &ZondConfig) -> anyhow::Result<()> {
    print::Print::header("about the tool");
    zprint!(
        "{}",
        "Zond is a quick tool for mapping and exploring networks.".color(colors::TEXT_DEFAULT)
    );
    zprint!();

    let system_info = zond_engine::info::get_system_info()?;

    let printer = if is_root() {
        InfoPrinter::new(&system_info.services)
    } else {
        InfoPrinter::default()
    };

    printer.print_about();
    printer.print_system()?;

    if is_root() {
        printer.print_firewall_status(system_info.firewall)?;
        printer.print_local_services(&system_info.services)?;
    }

    let interfaces = zond_core::net::interface::get_prioritized_interfaces(5)?;
    print_network_interfaces(&interfaces)?;

    Ok(())
}

/// Helper struct to manage printing context and alignment.
struct InfoPrinter {
    /// Width of the key column for alignment.
    key_width: usize,
}

impl Default for InfoPrinter {
    fn default() -> Self {
        Self { key_width: 10 }
    }
}

impl InfoPrinter {
    /// Creates a new `InfoPrinter` with a key width calculated from the service names.
    fn new(services: &[IpServiceGroup]) -> Self {
        let mut longest_name = 0;
        for group in services {
            for s in &group.tcp_services {
                longest_name = cmp::max(longest_name, s.name.len());
            }
            for s in &group.udp_services {
                longest_name = cmp::max(longest_name, s.name.len());
            }
        }
        Self {
            key_width: cmp::max(longest_name + 6, 10),
        }
    }

    /// Prints the "About" section with version and author info.
    fn print_about(&self) {
        self.aligned_line("Version", env!("CARGO_PKG_VERSION"));
        self.aligned_line("Author", "hollowpointer");
        self.aligned_line("E-Mail", "hollowpointer@pm.me");
        self.aligned_line("License", "MPL-2.0");
        self.aligned_line("Repository", "https://github.com/hollowpointer/zond");
    }

    /// Prints the "Local System" section with hostname, OS, and user info.
    fn print_system(&self) -> anyhow::Result<()> {
        print::Print::header("local system");
        let hostname: String = sys_info::hostname()?;
        self.aligned_line("Hostname", hostname);

        let release = sys_info::os_release().unwrap_or_else(|_| String::from(""));
        let os_name = sys_info::os_type()?;
        self.aligned_line("OS", format!("{} {}", os_name, release));

        if let Ok(user) = env::var("USER").or_else(|_| env::var("USERNAME")) {
            self.aligned_line("User", user);
        }
        Ok(())
    }

    /// Prints the firewall status.
    fn print_firewall_status(&self, status: FirewallStatus) -> anyhow::Result<()> {
        print::Print::header("firewall status");
        let status_str = match status {
            FirewallStatus::Active => "active".green().bold(),
            FirewallStatus::Inactive => "inactive".red().bold(),
            FirewallStatus::NotDetected => "inactive (not detected)".yellow(),
        };

        self.aligned_line("Status", status_str);

        if status == FirewallStatus::NotDetected {
            zprint!();
            zprint!(
                "{}",
                "No active firewall detected. Services may be exposed to public."
                    .color(colors::TEXT_DEFAULT)
            );
        }

        Ok(())
    }

    /// Prints the list of local services grouped by IP and protocol.
    fn print_local_services(&self, groups: &[IpServiceGroup]) -> anyhow::Result<()> {
        print::Print::header("local services");

        for (idx, group) in groups.iter().enumerate() {
            if group.tcp_services.is_empty() && group.udp_services.is_empty() {
                continue;
            }

            self.print_service_group(group);

            if idx + 1 != groups.len() {
                zprint!();
            }
        }
        Ok(())
    }

    fn print_service_group(&self, group: &IpServiceGroup) {
        let ip_color = if group.ip_addr.is_ipv4() {
            colors::IPV4_ADDR
        } else {
            colors::IPV6_ADDR
        };

        zprint!(
            "{}",
            format!("[{}]", group.ip_addr.to_string().color(ip_color)).color(colors::SEPARATOR)
        );

        let has_tcp = !group.tcp_services.is_empty();
        let has_udp = !group.udp_services.is_empty();

        if has_tcp {
            let branch = if has_udp { "├─" } else { "└─" };
            let vertical = if has_udp { "│" } else { " " };
            self.print_service_category(&group.tcp_services, "TCP", branch, vertical);
        }

        if has_udp {
            self.print_service_category(&group.udp_services, "UDP", "└─", " ");
        }
    }

    fn print_service_category(
        &self,
        services: &[Service],
        label: &str,
        branch_char: &str,
        vertical_char: &str,
    ) {
        zprint!(
            " {} {}",
            branch_char.color(colors::SEPARATOR),
            label.color(colors::PRIMARY)
        );

        for (i, service) in services.iter().enumerate() {
            self.print_service_line(service, i, services.len(), vertical_char);
        }
    }

    fn print_service_line(
        &self,
        service: &Service,
        idx: usize,
        total: usize,
        vertical_branch: &str,
    ) {
        let is_last = idx + 1 == total;
        let branch = if is_last { "└─" } else { "├─" }.color(colors::SEPARATOR);

        // Calculate dynamic padding dots
        let dashes_count = (self.key_width as i32 - service.name.len() as i32 - 5).max(0) as usize;
        let dots = ".".repeat(dashes_count).color(colors::SEPARATOR);

        let ports = self.format_ports(&service.local_ports);

        zprint!(
            " {}   {branch} {}{}{} {}",
            vertical_branch.color(colors::SEPARATOR),
            service.name.color(colors::SECONDARY),
            dots,
            ":".color(colors::SEPARATOR),
            ports.color(colors::TEXT_DEFAULT)
        );
    }

    fn format_ports(&self, ports: &std::collections::HashSet<u16>) -> String {
        let mut port_list: Vec<_> = ports.iter().collect();
        port_list.sort();

        let count = port_list.len();
        let mut port_strings: Vec<String> = port_list
            .into_iter()
            .take(5)
            .map(|p| p.to_string())
            .collect();

        if count > 5 {
            port_strings.push("...".to_string());
        }
        port_strings.join(", ")
    }

    /// Prints a key-value line aligned with dots.
    fn aligned_line<T: std::fmt::Display>(&self, key: &str, value: T) {
        let dots_count = (self.key_width + 1).saturating_sub(key.len());
        let dots = ".".repeat(dots_count).color(colors::SEPARATOR);

        zprint!(
            "{} {}{}{} {}",
            ">".color(colors::SEPARATOR),
            key.color(colors::PRIMARY),
            dots,
            ":".color(colors::SEPARATOR),
            value.to_string().color(colors::TEXT_DEFAULT)
        );
    }
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
