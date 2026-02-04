// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::time::{Duration, Instant};

use colored::*;
use tracing::info_span;
use zond_common::models::range::IpCollection;
use zond_common::models::target;

use crate::terminal::colors;
use crate::terminal::print::Print;
use crate::terminal::spinner::SpinnerGuard;
use zond_common::{config::Config, models::host::Host};
use zond_core::scanner;

pub async fn discover(targets: &[String], cfg: &Config) -> anyhow::Result<()> {
    Print::header("performing host discovery");

    let _guard: SpinnerGuard = run_spinner();

    let ips: IpCollection = target::to_collection(targets)?;
    let start_time: Instant = Instant::now();
    let mut hosts: Vec<Host> = scanner::perform_discovery(ips, cfg).await?;

    let total_time: Duration = start_time.elapsed();
    discovery_ends(&mut hosts, total_time)
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

fn discovery_ends(hosts: &mut [Host], total_time: Duration) -> anyhow::Result<()> {
    if hosts.is_empty() {
        Print::no_results();
    }

    Print::header("Network Discovery");

    hosts.sort_by_key(|host| *host.ips.iter().next().unwrap_or(&host.primary_ip));
    Print::hosts(hosts)?;
    Print::summary(hosts.len(), total_time);
    Ok(())
}
