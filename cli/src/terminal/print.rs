// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::{cell::Cell, fmt::Display, net::IpAddr, sync::OnceLock, time::Duration};

use crate::terminal::{banner, colors, format};
use anyhow::bail;
use colored::*;
use unicode_width::UnicodeWidthStr;
use zond_common::{config::Config, models::host::Host, success};

pub const TOTAL_WIDTH: usize = 64;

static PRINT: OnceLock<Print> = OnceLock::new();

thread_local! {
    pub static GLOBAL_KEY_WIDTH: Cell<usize> = const { Cell::new(0) }
}

type Detail = (String, ColoredString);

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

pub trait WithDefaultColor {
    fn with_default(self, default_color: Color) -> ColoredString;
}

impl WithDefaultColor for &str {
    fn with_default(self, default_color: Color) -> ColoredString {
        self.color(default_color)
    }
}

impl WithDefaultColor for String {
    fn with_default(self, default_color: Color) -> ColoredString {
        self.color(default_color)
    }
}

impl WithDefaultColor for ColoredString {
    fn with_default(self, _default_color: Color) -> ColoredString {
        self
    }
}

pub struct Print {
    no_banner: bool,
    q_level: u8,
    redact: bool,
}

impl Print {
    fn new(cfg: &Config) -> Self {
        Self {
            no_banner: cfg.no_banner,
            q_level: cfg.quiet,
            redact: cfg.redact,
        }
    }

    pub fn init(cfg: &Config) -> anyhow::Result<()> {
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

        let text_content: String = format!("⟦ ZOND v{} ⟧ ", env!("CARGO_PKG_VERSION"));
        let text_width: usize = UnicodeWidthStr::width(text_content.as_str());
        let text: ColoredString = text_content.bright_green().bold();
        let sep: ColoredString = "═"
            .repeat(TOTAL_WIDTH.saturating_sub(text_width) / 2)
            .bright_black();
        let output: String = format!("{}{}{}", sep, text, sep);

        zprint!("{}", output);
        banner::print();
    }

    pub fn header(msg: &str) {
        let p = Self::get();
        if p.q_level > 0 {
            zprint!();
            return;
        }

        let formatted: String = format!("⟦ {} ⟧", msg);
        let msg_len: usize = formatted.chars().count();

        let dash_count: usize = TOTAL_WIDTH.saturating_sub(msg_len);
        let left: usize = dash_count / 2;
        let right: usize = dash_count - left;

        let line: ColoredString = format!(
            "{}{}{}",
            "─".repeat(left),
            formatted.to_uppercase().bright_green(),
            "─".repeat(right)
        )
        .bright_black();

        zprint!("{}", line);
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
        let min_rtt = host.min_rtt();

        if min_rtt.is_none() {
            return String::new();
        }

        let min_rtt = host.min_rtt().unwrap();
        let max_rtt = host.max_rtt().unwrap();
        let avg_rtt = host.average_rtt().unwrap();

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
    let sep: ColoredString = "═".repeat(TOTAL_WIDTH).bright_black();
    zprint!("{}", sep);
}

pub fn aligned_line<V>(key: &str, value: V)
where
    V: Display + WithDefaultColor,
{
    let whitespace: String = ".".repeat((GLOBAL_KEY_WIDTH.get() + 1).saturating_sub(key.len()));
    let colon: String = format!(
        "{}{}",
        whitespace.color(colors::SEPARATOR),
        ":".color(colors::SEPARATOR)
    );
    let value: ColoredString = value.with_default(colors::TEXT_DEFAULT);
    print_status(format!("{}{} {}", key.color(colors::PRIMARY), colon, value));
}

pub fn print_status<T: AsRef<str>>(msg: T) {
    zprint!(
        "{} {}",
        ">".color(colors::SEPARATOR),
        msg.as_ref().color(colors::TEXT_DEFAULT)
    );
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
    let space = " ".repeat((TOTAL_WIDTH - console::measure_text_width(msg)) / 2);
    zprint!("{}{}{}", space, msg, space);
}
