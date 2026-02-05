// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Orchestration logic for network discovery.
//!
//! This module coordinates the execution of various scanning strategies:
//! - **Privileged**: High-speed raw socket scans ([`LocalScanner`] for ARP/ICMP, [`RoutedScanner`] for TCP SYN).
//! - **Unprivileged**: Standard TCP handshake fallback via [`handshake`].
//!
//! It manages the lifecycle of a scan by partitioning targets by interface,
//! spawning concurrent explorers, and piping results through a background
//! [`HostnameResolver`].use std::net::IpAddr;

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use is_root::is_root;
use zond_common::config::Config;
use zond_common::interface;
use zond_common::models::host::Host;
use zond_common::models::range::IpCollection;
use zond_common::utils::input::InputHandle;
use zond_common::{error, info, success, warn};

mod handshake;
mod local;
mod resolver;
mod routed;

use local::LocalScanner;
use routed::RoutedScanner;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;

use crate::scanner::resolver::HostnameResolver;

pub static FOUND_HOST_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static STOP_SIGNAL: AtomicBool = AtomicBool::new(false);

pub fn increment_host_count() {
    FOUND_HOST_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn get_host_count() -> usize {
    FOUND_HOST_COUNT.load(Ordering::Relaxed)
}

#[async_trait]
trait NetworkExplorer {
    async fn discover_hosts(&mut self) -> anyhow::Result<Vec<Host>>;
}

/// The primary entry point for network discovery.
///
/// ### Capabilities
/// - **Privilege Aware**: Uses raw sockets (ARP/TCP SYN) if root; falls back to standard TCP handshakes if not.
/// - **Multi-Interface**: Automatically partitions targets across available network adapters.
/// - **Parallel Resolver**: Streams found IPs to a background DNS task for zero-latency lookups.
///
/// ### Integration Notes
/// - **State**: Updates [`FOUND_HOST_COUNT`] and reacts to [`STOP_SIGNAL`].
/// - **Concurrency**: Spawns multiple Tokio tasks; ensure the caller is within a multi-threaded runtime.
pub async fn discover(targets: IpCollection, cfg: &Config) -> anyhow::Result<Vec<Host>> {
    if !cfg.disable_input {
        spawn_user_input_listener();
    }

    if !is_root() {
        warn!("Root privileges missing, defaulting to unprivileged TCP scan");
        return handshake::range_discovery(targets, handshake::prober).await;
    }
    success!("Root privileges detected, raw socket scan enabled");

    let (dns_tx, resolver_task) = if !cfg.no_dns {
        let (tx, rx) = mpsc::unbounded_channel();
        let task = spawn_resolver(rx).await;
        (Some(tx), Some(task))
    } else {
        info!("DNS resolution skipped by user flag");
        (None, None)
    };

    let scanner_handles = spawn_explorers(targets, dns_tx).await;

    let mut hosts = Vec::new();
    for handle in scanner_handles {
        match handle.await {
            Ok(Ok(res)) => hosts.extend(res),
            Ok(Err(e)) => error!("Scanner task failed: {e}"),
            Err(e) => error!("Task panicked: {e}"),
        }
    }

    if let Some(task) = resolver_task
        && let Ok(Some(mut resolver)) = task.await
    {
        resolver.resolve_hosts(&mut hosts);
    }

    Ok(hosts)
}

async fn spawn_explorers(
    targets: IpCollection,
    dns_tx: Option<mpsc::UnboundedSender<IpAddr>>,
) -> Vec<JoinHandle<anyhow::Result<Vec<Host>>>> {
    let mut handles = Vec::new();

    let (interface_map, unmapped_ips) = interface::map_ips_to_interfaces(targets);

    for (intf, (local_ips, routed_ips)) in interface_map {
        // Local Scanner (ARP/ICMP)
        if !local_ips.is_empty() {
            info!(verbosity = 1, "Spawning LOCAL scanner for {}", intf.name);
            let tx = dns_tx.clone();
            let intf_c = intf.clone();

            let handle = tokio::spawn(async move {
                let mut scanner = LocalScanner::new(intf_c, local_ips, tx)?;
                scanner.discover_hosts().await
            });
            handles.push(handle);
        }

        // Routed Scanner (TCP Syn Scan)
        if !routed_ips.is_empty() {
            info!(verbosity = 1, "Spawning ROUTED scanner for {}", intf.name);
            let tx = dns_tx.clone();
            let intf_c = intf.clone();

            let handle = tokio::spawn(async move {
                let mut scanner = RoutedScanner::new(intf_c, routed_ips, tx)?;
                scanner.discover_hosts().await
            });
            handles.push(handle);
        }
    }

    // Fallback Scanner (Unprivileged TCP Handshake) for unmapped IPs (e.g. localhost)
    if !unmapped_ips.is_empty() {
        info!(
            verbosity = 1,
            "Spawning FALLBACK scanner for unmapped targets"
        );
        let handle = tokio::spawn(async move {
            handshake::range_discovery(unmapped_ips, handshake::prober).await
        });
        handles.push(handle);
    }

    handles
}

async fn spawn_resolver(dns_rx: UnboundedReceiver<IpAddr>) -> JoinHandle<Option<HostnameResolver>> {
    tokio::spawn(async move {
        match HostnameResolver::new(dns_rx) {
            Ok(resolver) => {
                success!("Successfully initialized hostname resolver");
                Some(resolver.run().await)
            }
            Err(e) => {
                error!("Resolver failed to start: {e}");
                None
            }
        }
    })
}

fn spawn_user_input_listener() {
    std::thread::spawn(|| {
        let mut input_handle = InputHandle::new();
        input_handle.start();
        loop {
            if input_handle.should_interrupt() {
                STOP_SIGNAL.store(true, Ordering::Relaxed);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
}
