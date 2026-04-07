// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::{net::IpAddr, sync::OnceLock, time::Duration};

use crate::terminal::{banner, colors, format};
use anyhow::bail;
use colored::*;
use unicode_width::UnicodeWidthStr;
use zond_common::{config::ZondConfig, models::host::Host, success};

#[macro_export]
macro_rules! zprint {
    () => {
        $crate::zprint!("");
    };
    ($($arg:tt)*) => {
        tracing::info!(
            target: "zond::print",
            raw_msg = %format_args!($($arg)*)
        );
    };
}

pub const TOTAL_WIDTH: usize = 64;

static PRINT: OnceLock<Print> = OnceLock::new();

type Detail = (String, ColoredString);

pub struct Print {
    no_banner: bool,
    q_level: u8,
    redact: bool,
}

impl Print {
    fn new(cfg: &ZondConfig) -> Self {
        Self {
            no_banner: cfg.no_banner,
            q_level: cfg.quiet,
            redact: cfg.redact,
        }
    }

    pub fn init(cfg: &ZondConfig) -> anyhow::Result<()> {
        let term = Self::new(cfg);
        if PRINT.set(term).is_err() {
            bail!("terminal has already been initialized")
        }
        Ok(())
    }

    fn get() -> &'static Self {
        PRINT.get().expect("terminal has not been initialized")
    }

    pub fn banner() {
        let p = Self::get();
        if p.no_banner || p.q_level > 0 {
            return;
        }

        let text_content = format!("⟦ ZOND v{} ⟧ ", env!("CARGO_PKG_VERSION"));
        let output = format_centered(&text_content.bright_green().bold(), "═", TOTAL_WIDTH);

        zprint!("{}", output);
        banner::print();
    }

    pub fn header(msg: &str) {
        if Self::get().q_level > 0 {
            zprint!();
            return;
        }

        let formatted_msg = format!("⟦ {} ⟧", msg).to_uppercase().bright_green();
        let output = format_centered(&formatted_msg, "─", TOTAL_WIDTH);

        zprint!("{}", output);
    }

    pub fn hosts(hosts: &[Host]) -> anyhow::Result<()> {
        let p = Self::get();
        for (idx, host) in hosts.iter().enumerate() {
            match p.q_level {
                2 => bail!("-qq is currently unimplemented"),
                _ => Self::host_tree(host, idx),
            }
            if idx + 1 != hosts.len() {
                zprint!();
            }
        }
        Ok(())
    }

    fn host_tree(host: &Host, idx: usize) {
        let p = Self::get();
        let primary_ip: IpAddr = host.primary_ip;
        Print::host_head(idx, &primary_ip, host);
        let mut details: Vec<Detail> = format::ip_to_detail(host, p.redact);

        if let Some(mac_detai) = format::mac_to_detail(&host.mac, p.redact) {
            details.push(mac_detai);
        }

        if let Some(vendor_detail) = format::vendor_to_detail(&host.vendor) {
            details.push(vendor_detail);
        }

        if let Some(hostname_detail) = format::hostname_to_detail(&host.hostname, p.redact) {
            details.push(hostname_detail);
        }

        as_tree(details);
    }

    fn host_head(idx: usize, primary_ip: &IpAddr, host: &Host) {
        let rtt_string: String = Self::rtt_to_string(host);
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

    pub fn discovery_summary(hosts_len: usize, total_time: Duration) {
        let p = Self::get();
        let active_hosts: ColoredString = format!("{hosts_len} active hosts").bold().green();
        let total_time: ColoredString = format!("{:.2}s", total_time.as_secs_f64()).bold().yellow();
        let output: &ColoredString =
            &format!("Discovery Complete: {active_hosts} identified in {total_time}")
                .color(colors::TEXT_DEFAULT);

        match p.q_level {
            0 => {
                divider();
                centerln(output);
            }
            _ => {
                zprint!();
                success!("{output}")
            }
        }
    }

    pub fn no_results() {
        let p = Self::get();
        if p.q_level == 0 && !p.no_banner {
            Self::header("ZERO HOSTS DETECTED");
            zprint!("{}", banner::NO_RESULTS_0.red().bold());
            return;
        }
        zond_common::error!("Scan completed: 0 devices responded.");
    }

    pub fn end_of_program() {
        let p = Self::get();
        if p.q_level > 0 {
            return;
        }
        zprint!("{}", "═".repeat(TOTAL_WIDTH).color(colors::SEPARATOR));
    }
}

pub fn divider() {
    zprint!("{}", format_centered("", "═", TOTAL_WIDTH));
}

pub fn tree_head(idx: usize, name: &str) {
    let idx_str: String = format!("[{}]", idx.to_string().color(colors::ACCENT));
    zprint!(
        "{} {}",
        idx_str.color(colors::SEPARATOR),
        name.color(colors::PRIMARY)
    );
}

pub fn as_tree(details: Vec<(String, ColoredString)>) {
    let padding_width: usize = "Hostname".len();

    for (i, (key, value)) in details.iter().enumerate() {
        let last: bool = i + 1 == details.len();
        let branch: ColoredString = if !last { "├─" } else { "└─" }.bright_black();

        let dots_count: usize = padding_width.saturating_sub(key.len());
        let dots: ColoredString = ".".repeat(dots_count).color(colors::SEPARATOR);

        zprint!(
            " {} {}{}{} {}",
            branch,
            key.color(colors::TEXT_DEFAULT),
            dots,
            ":".color(colors::SEPARATOR),
            value
        );
    }
}

pub fn centerln(msg: &str) {
    zprint!("{}", format_centered(msg, " ", TOTAL_WIDTH));
}

fn format_centered(text: &str, fill_char: &str, total_width: usize) -> String {
    let text_width = console::measure_text_width(text);

    let pad_len = total_width.saturating_sub(text_width);
    let left = pad_len / 2;
    let right = pad_len - left;

    format!(
        "{}{}{}",
        fill_char.repeat(left),
        text,
        fill_char.repeat(right)
    )
}
