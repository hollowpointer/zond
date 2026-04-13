// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::{net::IpAddr, time::Duration};

use colored::*;
use unicode_width::UnicodeWidthStr;
use zond_core::models::host::Host;
use zond_core::models::port::{Port, PortState, Protocol};

use crate::{
    terminal::{
        colors, format,
        print::{self, Print, TOTAL_WIDTH},
    },
    zprint,
};

/// Provides terminal printing capabilities for network hosts.
///
/// This trait encapsulates the visual formatting and standard output routing
/// for a given host record, ensuring consistent terminal representation.
pub(crate) trait PrintableHost {
    /// Evaluates the host's details and configuration state to print
    /// a formatted tree representation to the standard output.
    ///
    /// # Arguments
    ///
    /// * `index` - The chronological index of the host in the current discovery sequence.
    fn print(&self, index: usize);
}

impl PrintableHost for Host {
    fn print(&self, index: usize) {
        let p = Print::get();
        let primary_ip: IpAddr = self.primary_ip();

        print_host_head(index, &primary_ip, self);

        let mut details = format::ip_to_detail(self, p.redact);

        if let Some(mac_detail) = format::mac_to_detail(self.mac(), p.redact) {
            details.push(mac_detail);
        }

        if let Some(vendor_detail) = format::vendor_to_detail(self.vendor()) {
            details.push(vendor_detail);
        }

        if let Some(hostname_detail) = format::hostname_to_detail(self.hostname(), p.redact) {
            details.push(hostname_detail);
        }

        print::as_tree(details);

        if !self.ports().is_empty() {
            print_services(self.ports());
        }
    }
}

/// Formats and prints the primary header line for a host.
///
/// Constructs the top-level identifier for a host in the terminal tree,
/// aligning the index, primary IP address, and the calculated Round Trip Time (RTT).
///
/// # Arguments
///
/// * `idx` - The enumeration index of the host.
/// * `primary_ip` - The main IP address of the responding host.
/// * `host` - Reference to the host model to extract RTT metrics.
fn print_host_head(idx: usize, primary_ip: &IpAddr, host: &Host) {
    let rtt_string: String = rtt_to_string(host);
    let rtt_width: usize = rtt_string.width();

    let block_width: usize = 20;
    let local_pad: usize = block_width.saturating_sub(rtt_width);
    let right_part: String = format!("{}{}", " ".repeat(local_pad), rtt_string);

    let left_part: String = format!("[{}] {}", idx, primary_ip);
    let used_width: usize = left_part.width() + block_width;

    let padding_len: usize = TOTAL_WIDTH.saturating_sub(used_width + 1);
    let padding: String = " ".repeat(padding_len);

    zprint!(
        "{} {}{}{}",
        format!("[{}]", idx.to_string().color(colors::ACCENT)).color(colors::SEPARATOR),
        primary_ip.to_string().color(colors::PRIMARY),
        padding,
        right_part.color(colors::SECONDARY)
    );
}

/// Computes a formatted string representing the Round Trip Time (RTT) variance.
///
/// Evaluates the minimum, maximum, and average RTT to determine the most accurate
/// representation. Depending on the spread tolerance, this will return an exact
/// duration, an approximate average, or a bounded range.
///
/// # Arguments
///
/// * `host` - The host model containing recorded RTT measurements.
fn rtt_to_string(host: &Host) -> String {
    let (Some(min_rtt), Some(max_rtt), Some(avg_rtt)) =
        (host.min_rtt(), host.max_rtt(), host.average_rtt())
    else {
        return String::new();
    };

    if min_rtt == max_rtt {
        return format!("⌛ {}ms", min_rtt.as_millis());
    }

    let spread = max_rtt.saturating_sub(min_rtt);
    let tolerance = min_rtt.mul_f64(0.05).max(Duration::from_millis(2));

    if tolerance > spread {
        return format!("⌛ ~{}ms", avg_rtt.as_millis());
    }

    format!("⌛ {}ms - {}ms", min_rtt.as_millis(), max_rtt.as_millis())
}

fn print_services(ports: &[Port]) {
    let mut open_c = 0;
    let mut filtered_c = 0;
    let mut closed_c = 0;
    for p in ports {
        match p.state() {
            PortState::Open => open_c += 1,
            PortState::Filtered | PortState::OpenFiltered => filtered_c += 1,
            PortState::Closed => closed_c += 1,
            _ => (),
        }
    }

    let mut stats = Vec::new();
    if open_c > 0 {
        stats.push(format!("{} OPEN", open_c).green().bold().to_string());
    }
    if filtered_c > 0 {
        stats.push(format!("{} FILTERED", filtered_c).cyan().bold().to_string());
    }

    let stats_str = if stats.is_empty() {
        "ALL CHECKS CLOSED".dimmed().to_string()
    } else {
        stats.join(&format!("{}", "  /  ".bright_black().bold()))
    };

    zprint!(
        " {} {}{}{} {}",
        "└─".bright_black(),
        "SERVICES".color(colors::TEXT_DEFAULT),
        ".".repeat(2).color(colors::SEPARATOR),
        ":".color(colors::SEPARATOR),
        stats_str
    );

    for (i, p) in ports.iter().enumerate() {
        let last = i + 1 == ports.len();
        let branch = if !last { "├─" } else { "└─" }.bright_black();

        let proto_str = match p.protocol() {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };
        let port_spec = format!("{}/{}", p.number(), proto_str);
        let port_spec_padded = format!("{:width$}", port_spec, width = 9);

        let (state_str, state_color) = match p.state() {
            PortState::Open => ("OPEN   ", colored::Color::Green),
            PortState::Filtered => ("FILTERED", colored::Color::Cyan),
            PortState::OpenFiltered => ("OPEN|FIL", colored::Color::Yellow),
            PortState::Closed => ("CLOSED ", colored::Color::Red),
            _ => ("UNKNOWN", colored::Color::White),
        };

        let state_fmt = format!("[ {} ]", state_str.color(state_color));
        let svc_name = p.service_name().unwrap_or("???");

        zprint!(
            "      {} {} {}  {}",
            branch,
            port_spec_padded.color(colors::PRIMARY),
            state_fmt,
            svc_name.color(colors::TEXT_DEFAULT)
        );
    }
}
