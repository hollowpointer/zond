// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;
use zond_common::models::host::Host;
use zond_common::models::ip::set::IpSet;
use zond_common::models::port::{Port, PortSet, PortState, Protocol};
use zond_common::models::target::{Target, TargetMap, TargetSet};

use super::STOP_SIGNAL;
use super::dispatcher::Dispatcher;
use crate::scanner::increment_host_count;

/// Most common ports across Linux, Windows, and Networking gear.
const DISCOVERY_PORTS: &[u16] = &[22, 80, 443, 445, 3389];

/// Performs a high-concurrency, unprivileged port scan.
///
/// This engine is the primary scanning strategy for users without root privileges.
/// It consumes a randomized stream of [`Target`]s from a [`Dispatcher`], maintaining
/// a strictly bounded concurrency set to prevent OS socket exhaustion. Discovered
/// open or filtered ports are aggregated into a collection of [`Host`] entities.
pub async fn scan(
    mut rx: mpsc::Receiver<Target>,
    concurrency_limit: usize,
) -> anyhow::Result<Vec<Host>> {
    let mut set = JoinSet::new();
    let mut results_map: HashMap<IpAddr, Host> = HashMap::new();

    while let Some(target) = rx.recv().await {
        if STOP_SIGNAL.load(Ordering::Relaxed) {
            break;
        }

        while set.len() >= concurrency_limit {
            if let Some(Ok(Ok(Some((ip, port))))) = set.join_next().await {
                let host = results_map.entry(ip).or_insert_with(|| Host::new(ip));
                host.add_port(port);
            }
        }

        set.spawn(async move { port_prober(target).await });
    }

    while let Some(Ok(Ok(Some((ip, port))))) = set.join_next().await {
        let host = results_map.entry(ip).or_insert_with(|| Host::new(ip));
        host.add_port(port);
    }

    Ok(results_map.into_values().collect())
}

/// Probes a specific [`Target`] (IP, Port, Protocol) to accurately determine its state.
///
/// Currently supports standard full TCP connect handshakes.
/// Returns An `Ok(Some((IpAddr, Port)))` if a non-closed port is discovered.
async fn port_prober(target: Target) -> anyhow::Result<Option<(IpAddr, Port)>> {
    if target.protocol == Protocol::Udp {
        // UDP isn't natively handled by standard TCP streams, gracefully skip or assume closed for now.
        return Ok(None);
    }

    let socket_addr = SocketAddr::new(target.ip, target.port);
    let probe_timeout = Duration::from_millis(1000);

    match timeout(probe_timeout, TcpStream::connect(socket_addr)).await {
        Ok(Ok(stream)) => {
            let mut port = Port::new(target.port, Protocol::Tcp, PortState::Open);
            port.set_service(Service::new(
                zond_plugins::lookup_service_name(target.port, Protocol::Tcp).unwrap_or("???"),
                0, // Baseline confidence
            ));
            let port = zond_plugins::fingerprint_tcp(stream, port).await;
            Ok(Some((target.ip, port)))
        }
        Ok(Err(e)) => {
            use std::io::ErrorKind;
            let state = match e.kind() {
                ErrorKind::ConnectionRefused => PortState::Closed,
                _ => PortState::Blocked,
            };

            if state != PortState::Closed {
                let mut port = Port::new(target.port, Protocol::Tcp, state);
                port.set_service(Service::new(
                    zond_plugins::lookup_service_name(target.port, Protocol::Tcp).unwrap_or("???"),
                    0,
                ));
                Ok(Some((target.ip, port)))
            } else {
                Ok(None)
            }
        }
        Err(_) => {
            // Timeout elapsed, implies a DROP -> Ghosted/Filtered
            let mut port = Port::new(target.port, Protocol::Tcp, PortState::Filtered);
            port.set_service(Service::new(
                zond_plugins::lookup_service_name(target.port, Protocol::Tcp).unwrap_or("???"),
                0,
            ));
            Ok(Some((target.ip, port)))
        }
    }
}

/// High-fidelity, multi-port host discovery for unprivileged environments.
///
/// This engine performs a rapid sweep of target networks by probing a curated
/// set of infrastructure ports: SSH (22), HTTP (80), HTTPS (443), SMB (445),
/// and RDP (3389). This multi-port approach ensures high discovery fidelity
/// across Linux, Windows, and embedded network targets.
///
/// ### Characteristics
/// - **Early-Exit**: Probes for an IP are immediately bypassed if the host
///   has already been confirmed alive by a parallel task.
/// - **Randomized**: Target distribution is handled by a shuffling [`Dispatcher`]
///   to minimize local network congestion.
/// - **Fidelity Range**: Uses an adjustable 1000ms timeout window to capture
///   hosts on high-latency or geographically distant links.
pub async fn discover(ips: IpSet) -> anyhow::Result<Vec<Host>> {
    const CONCURRENCY_LIMIT: usize = 2048;

    // 1. Prepare Target Map for all IP x Common Port combinations
    let mut target_map = TargetMap::new();
    let port_set = PortSet::try_from(
        DISCOVERY_PORTS
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
            .as_str(),
    )?;
    target_map.add_unit(TargetSet::new(ips, port_set));

    // 2. Setup Dispatcher and Shared State
    let dispatcher = Dispatcher::new(target_map).with_batch_size(1024);
    let mut rx = dispatcher.run_shuffled();
    let mut set = JoinSet::new();
    let found_hosts = Arc::new(Mutex::new(HashSet::new()));
    let mut hosts = Vec::new();

    // 3. Concurrent Execution Loop
    while let Some(target) = rx.recv().await {
        if STOP_SIGNAL.load(Ordering::Relaxed) {
            break;
        }

        while set.len() >= CONCURRENCY_LIMIT {
            if let Some(Ok(Ok(Some(host)))) = set.join_next().await {
                hosts.push(host);
            }
        }

        let inner_found = Arc::clone(&found_hosts);
        set.spawn(async move { prober(target, inner_found).await });
    }

    // 4. Final Collection
    while let Some(Ok(Ok(Some(host)))) = set.join_next().await {
        hosts.push(host);
    }

    Ok(hosts)
}

/// Concurrent network host prober.
///
/// Attempts a TCP connection to a specific [`Target`]. To minimize unnecessary
/// network traffic and OS resource usage, it employs a thread-safe early-exit
/// mechanism: if the host has already been identified by a parallel probe
/// (e.g., SSH responded before HTTP), this task terminates immediately.
async fn prober(
    target: Target,
    found_set: Arc<Mutex<HashSet<IpAddr>>>,
) -> anyhow::Result<Option<Host>> {
    // 1. Early exit if already discovered
    {
        let set = found_set.lock().unwrap();
        if set.contains(&target.ip) {
            return Ok(None);
        }
    }

    let socket_addr: SocketAddr = SocketAddr::new(target.ip, target.port);
    let probe_timeout: Duration = Duration::from_millis(1000);

    let start: Instant = Instant::now();
    match timeout(probe_timeout, TcpStream::connect(socket_addr)).await {
        Ok(Ok(_)) => {
            // 2. Successful handshake -> Host is alive
            let mut set = found_set.lock().unwrap();
            if set.insert(target.ip) {
                increment_host_count();
                let host: Host = Host::new(target.ip).with_rtt(start.elapsed());
                Ok(Some(host))
            } else {
                Ok(None)
            }
        }
        Ok(Err(e)) => {
            use std::io::ErrorKind;
            // 3. Only specific TCP errors imply the target host responded at the IP/TCP layer
            match e.kind() {
                ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted => {
                    let mut set = found_set.lock().unwrap();
                    if set.insert(target.ip) {
                        increment_host_count();
                        let host: Host = Host::new(target.ip).with_rtt(start.elapsed());
                        Ok(Some(host))
                    } else {
                        Ok(None)
                    }
                }
                _ => {
                    // Ignore local network errors (No route, Permission denied, etc.)
                    Ok(None)
                }
            }
        }
        Err(_elapsed) => Ok(None),
    }
}
