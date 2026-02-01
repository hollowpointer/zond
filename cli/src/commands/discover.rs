use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{self, bail};
use colored::*;
use tracing::info_span;
use unicode_width::UnicodeWidthStr;
use zond_common::error;
use zond_common::models::range::IpCollection;
use zond_common::models::target;

use crate::terminal::spinner::SpinnerGuard;
use crate::{
    mprint,
    terminal::{
        colors, format,
        print::{self, TOTAL_WIDTH},
    },
};
use zond_common::{config::Config, models::host::Host, success};
use zond_core::scanner;

type Detail = (String, ColoredString);

pub async fn discover(targets: &[String], cfg: &Config) -> anyhow::Result<()> {
    print::header("performing host discovery", cfg.quiet);

    let _guard: SpinnerGuard = run_spinner();

    let ips: IpCollection = target::to_collection(targets)?;
    let start_time: Instant = Instant::now();
    let mut hosts: Vec<Host> = scanner::perform_discovery(ips, cfg).await?;

    let total_time: Duration = start_time.elapsed();
    discovery_ends(&mut hosts, total_time, cfg)
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

fn discovery_ends(hosts: &mut [Host], total_time: Duration, cfg: &Config) -> anyhow::Result<()> {
    if hosts.is_empty() {
        no_hosts_found(cfg);
        return Ok(());
    }

    if cfg.quiet > 0 {
        mprint!();
    }

    print::header("Network Discovery", cfg.quiet);
    hosts.sort_by_key(|host| *host.ips.iter().next().unwrap_or(&host.primary_ip));
    print_hosts(hosts, cfg)?;
    print_summary(hosts.len(), total_time, cfg);

    Ok(())
}

fn no_hosts_found(cfg: &Config) {
    if cfg.quiet == 0 && !cfg.no_banner {
        print::header("ZERO HOSTS DETECTED", cfg.quiet);
        print::no_results_banner();
        return;
    }
    error!("Scan completed: 0 devices responded.");
}

fn print_hosts(hosts: &mut [Host], cfg: &Config) -> anyhow::Result<()> {
    for (idx, host) in hosts.iter().enumerate() {
        match cfg.quiet {
            2 => bail!("-qq is currently unimplemented"),
            _ => print_host_tree(host, idx, cfg),
        }
        if idx + 1 != hosts.len() {
            mprint!();
        }
    }
    Ok(())
}

fn print_summary(hosts_len: usize, total_time: Duration, cfg: &Config) {
    let active_hosts: ColoredString = format!("{hosts_len} active hosts").bold().green();
    let total_time: ColoredString = format!("{:.2}s", total_time.as_secs_f64()).bold().yellow();
    let output: &ColoredString =
        &format!("Discovery Complete: {active_hosts} identified in {total_time}")
            .color(colors::TEXT_DEFAULT);

    match cfg.quiet {
        0 => {
            print::fat_separator();
            print::centerln(output);
        }
        _ => {
            mprint!();
            success!("{output}")
        }
    }
}

fn print_host_tree(host: &Host, idx: usize, cfg: &Config) {
    let primary_ip: IpAddr = host.primary_ip;
    print_host_head(idx, &primary_ip, host);
    let mut details: Vec<Detail> = format::ip_to_detail(host, cfg);

    if let Some(mac_detai) = format::mac_to_detail(&host.mac, cfg) {
        details.push(mac_detai);
    }

    if let Some(vendor_detail) = format::vendor_to_detail(&host.vendor) {
        details.push(vendor_detail);
    }

    if let Some(hostname_detail) = format::hostname_to_detail(&host.hostname, cfg) {
        details.push(hostname_detail);
    }

    if !host.network_roles.is_empty() {
        let joined_roles: String = host
            .network_roles
            .iter()
            .map(|role| format!("{:?}", role))
            .collect::<Vec<String>>()
            .join(", ");

        let roles_detail: (String, ColoredString) = ("Roles".to_string(), joined_roles.normal());

        details.push(roles_detail);
    }

    print::as_tree(details);
}

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

    let output: String = format!(
        "{} {}{}{}",
        format!("[{}]", idx.to_string().color(colors::ACCENT)).color(colors::SEPARATOR),
        primary_ip.to_string().color(colors::PRIMARY),
        padding,
        right_part.color(colors::SECONDARY)
    );

    mprint!(&output);
}

fn rtt_to_string(host: &Host) -> String {
    let min_rtt: Option<Duration> = host.min_rtt();

    if min_rtt.is_none() {
        return String::new();
    }

    let min_rtt: Duration = host.min_rtt().unwrap();
    let max_rtt: Duration = host.max_rtt().unwrap();
    let avg_rtt: Duration = host.average_rtt().unwrap();

    if min_rtt == max_rtt {
        return format!("⌛ {}ms", min_rtt.as_millis());
    }

    let spread: Duration = max_rtt.saturating_sub(min_rtt);
    let tolerance: Duration = min_rtt.mul_f64(0.05).max(Duration::from_millis(2));

    if tolerance > spread {
        return format!("⌛ ~{}ms", avg_rtt.as_millis());
    }

    format!("⌛ {}ms - {}ms", min_rtt.as_millis(), max_rtt.as_millis())
}
