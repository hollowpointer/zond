// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Discovery Command Implementation
//!
//! Implements the logic for `zond d`.
//!
//! This module wraps the core scanning functionality with the necessary terminal UI.
//! Since the core `scanner` module is silent and purely functional, this module is responsible
//! for "noise" operations: parsing CLI strings, managing the loading spinner, and rendering
//! the final report table.
//!
//! ## Execution Flow
//!
//! 1.  **Parse**: Converts raw target strings (e.g., "10.0.0.0/24") into a valid [`IpCollection`].
//! 2.  **Monitor**: Spawns a background spinner to track progress during the async scan.
//! 3.  **Execute**: Calls [`scanner::discover`] to do the actual scanning.
//! 4.  **Render**: Sorts the resulting host list by IP and prints the summary to stdout.

use std::time::Instant;

use colored::*;
use tracing::info_span;

use crate::terminal::colors;
use crate::terminal::print::Print;
use crate::terminal::spinner::SpinnerGuard;

use zond_common::models::range::IpCollection;
use zond_common::models::target;
use zond_common::{config::Config, models::host::Host};
use zond_core::scanner;

/// Runs the active discovery scan on the provided targets.
///
/// This handles the full scan lifecycle: parsing the target strings, managing the
/// progress spinner, and printing the sorted results to stdout.
///
/// If no hosts are found, it prints a "No results" message and exits cleanly.
///
/// # Arguments
///
/// * `targets` - Raw target strings from the CLI (e.g., `["192.168.1.1", "10.0.0.0/24"]`).
/// * `cfg` - Scan configuration (timeout, ports, etc).
///
/// # Errors
///
/// Returns an error if:
/// * The target strings cannot be parsed into valid IPs or CIDRs.
/// * The underlying scanner encounters a fatal network error.
pub async fn discover(targets: &[String], cfg: &Config) -> anyhow::Result<()> {
    Print::header("performing host discovery");

    let _guard: SpinnerGuard = run_spinner();

    let ips: IpCollection = target::to_collection(targets)?;
    let start_time: Instant = Instant::now();

    let mut hosts: Vec<Host> = scanner::discover(ips, cfg).await?;

    if hosts.is_empty() {
        Print::no_results();
        return Ok(());
    }

    Print::header("Network Discovery");

    hosts.sort_by_key(|host| *host.ips.iter().next().unwrap_or(&host.primary_ip));
    Print::hosts(&hosts)?;
    Print::discovery_summary(hosts.len(), start_time.elapsed());

    Ok(())
}

fn run_spinner() -> SpinnerGuard {
    let span = info_span!("discover", indicatif.pb_show = true);
    let _enter = span.enter();

    SpinnerGuard::with_status(span.clone(), || {
        let count = zond_core::scanner::get_host_count();
        let count_str = count.to_string().green().bold();
        let label = if count == 1 { "host" } else { "hosts" };
        format!("Identified {} {} so far...", count_str, label)
            .color(colors::TEXT_DEFAULT)
            .italic()
    })
}
