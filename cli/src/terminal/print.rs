// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::{sync::OnceLock, time::Duration};

use anyhow::bail;
use colored::*;
use zond_common::{config::ZondConfig, models::host::Host, success};

use crate::terminal::{banner, colors, host::PrintableHost};

/// Central logging macro for terminal output.
///
/// Wraps `tracing::info!` targeting the `zond::print` span.
/// Standardizes stdout formatting across the CLI application.
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

/// The absolute maximum character width for standardized terminal blocks.
pub const TOTAL_WIDTH: usize = 64;

static PRINT: OnceLock<Print> = OnceLock::new();

/// Type alias for standardizing key-value pair strings in terminal trees.
pub type Detail = (String, ColoredString);

/// Global terminal state manager.
///
/// Holds the runtime configuration for verbosity, redaction, and visual
/// preferences to ensure consistent output formatting across the application.
pub struct Print {
    pub(crate) no_banner: bool,
    pub(crate) q_level: u8,
    pub(crate) redact: bool,
}

impl Print {
    /// Constructs a new `Print` instance from the global application configuration.
    fn new(cfg: &ZondConfig) -> Self {
        Self {
            no_banner: cfg.no_banner,
            q_level: cfg.quiet,
            redact: cfg.redact,
        }
    }

    /// Initializes the global terminal state.
    ///
    /// # Errors
    /// Returns an error if the terminal state has already been initialized.
    pub fn init(cfg: &ZondConfig) -> anyhow::Result<()> {
        let term = Self::new(cfg);
        if PRINT.set(term).is_err() {
            bail!("terminal has already been initialized")
        }
        Ok(())
    }

    /// Retrieves a reference to the global terminal state.
    ///
    /// # Panics
    /// Panics if called before `Print::init`.
    pub(crate) fn get() -> &'static Self {
        PRINT.get().expect("terminal has not been initialized")
    }

    /// Prints the application banner if permitted by the current configuration.
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

    /// Prints a standardized, centered section header.
    ///
    /// Silenced automatically if quiet mode (`q_level > 0`) is active.
    pub fn header(msg: &str) {
        if Self::get().q_level > 0 {
            zprint!();
            return;
        }

        let formatted_msg = format!("⟦ {} ⟧", msg).to_uppercase().bright_green();
        let output = format_centered(&formatted_msg, "─", TOTAL_WIDTH);

        zprint!("{}", output);
    }

    /// Iterates over discovered hosts and triggers their visual representation.
    ///
    /// # Errors
    /// Returns an error if an unsupported quiet level is requested.
    pub fn hosts(hosts: &[Host]) -> anyhow::Result<()> {
        let p = Self::get();
        for (idx, host) in hosts.iter().enumerate() {
            match p.q_level {
                2 => bail!("-qq is currently unimplemented"),
                _ => host.print(idx),
            }
            if idx + 1 != hosts.len() {
                zprint!();
            }
        }
        Ok(())
    }

    /// Prints the completion summary for the network discovery phase.
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

    /// Prints the fallback output when zero hosts are detected during a scan.
    pub fn no_results() {
        let p = Self::get();
        if p.q_level == 0 && !p.no_banner {
            Self::header("ZERO HOSTS DETECTED");
            zprint!("{}", banner::NO_RESULTS_0.red().bold());
            return;
        }
        zond_common::error!("Scan completed: 0 devices responded.");
    }

    /// Prints the standardized terminating line for the program output.
    pub fn end_of_program() {
        let p = Self::get();
        if p.q_level > 0 {
            return;
        }
        zprint!("{}", "═".repeat(TOTAL_WIDTH).color(colors::SEPARATOR));
    }
}

/// Prints a horizontal divider line across the standard output width.
pub fn divider() {
    zprint!("{}", format_centered("", "═", TOTAL_WIDTH));
}

/// Prints a categorized tree header line with an index identifier.
pub fn tree_head(idx: usize, name: &str) {
    let idx_str: String = format!("[{}]", idx.to_string().color(colors::ACCENT));
    zprint!(
        "{} {}",
        idx_str.color(colors::SEPARATOR),
        name.color(colors::PRIMARY)
    );
}

/// Iterates through a collection of details and prints them as a visual tree structure.
pub fn as_tree(details: Vec<Detail>) {
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

/// Prints a centered line of text padded with blank spaces up to `TOTAL_WIDTH`.
pub fn centerln(msg: &str) {
    zprint!("{}", format_centered(msg, " ", TOTAL_WIDTH));
}

/// Centers a text string dynamically by padding it with a specified fill character.
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
