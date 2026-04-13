// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::time::Instant;

use colored::*;
use tracing::info_span;

use crate::terminal::colors;
use crate::terminal::print::Print;
use crate::terminal::spinner::SpinnerGuard;

use zond_engine::{config::ZondConfig, models::port::PortSet, parse};

pub async fn scan(
    targets: &[String],
    global_ports: PortSet,
    cfg: &ZondConfig,
) -> anyhow::Result<()> {
    Print::header("starting scanner");

    let _guard: SpinnerGuard = run_spinner();

    let target_map = parse::to_target_map(targets, global_ports)?;
    let start_time = Instant::now();

    let mut hosts = zond_engine::scanner::scan(target_map, cfg).await?;

    if hosts.is_empty() {
        Print::no_results();
        return Ok(());
    }

    Print::header("Network Scanner");

    hosts.sort_by_key(|host| *host.ips().iter().next().unwrap_or(&host.primary_ip()));

    Print::hosts(&hosts)?;
    Print::discovery_summary(hosts.len(), start_time.elapsed());

    Ok(())
}

fn run_spinner() -> SpinnerGuard {
    let span = info_span!("scan", indicatif.pb_show = true);
    let _enter = span.enter();

    SpinnerGuard::with_status(span.clone(), || {
        let count = zond_engine::scanner::get_host_count();
        let count_str = count.to_string().green().bold();
        let label = if count == 1 { "host" } else { "hosts" };
        format!("Scanned {} {} so far...", count_str, label)
            .color(colors::TEXT_DEFAULT)
            .italic()
    })
}
