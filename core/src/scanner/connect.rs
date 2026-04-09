// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;
use zond_common::models::host::Host;
use zond_common::models::ip::set::IpSet;
use zond_common::models::port::{Port, PortState, Protocol};
use zond_common::models::target::Target;

use super::STOP_SIGNAL;

use crate::scanner::increment_host_count;

/// Performs an asynchronous, highly-concurrent full TCP connect port scan over a randomized target stream.
///
/// This leverages an [`mpsc::Receiver`] (typically from a [`Dispatcher`]), bounds the number
/// of concurrent connections via `concurrency_limit`, and aggregates the findings into
/// a minimal set of [`Host`]s. IP addresses that return at least one non-closed port
/// will be mapped to a [`Host`] with their discovered [`Port`]s. This is the primary
/// port scanning strategy for users without root privileges.
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
            if let Some(res) = set.join_next().await {
                if let Ok(Ok(Some((ip, port)))) = res {
                    let host = results_map.entry(ip).or_insert_with(|| Host::new(ip));
                    host.add_port(port);
                }
            }
        }

        set.spawn(async move { port_prober(target).await });
    }

    while let Some(res) = set.join_next().await {
        if let Ok(Ok(Some((ip, port)))) = res {
            let host = results_map.entry(ip).or_insert_with(|| Host::new(ip));
            host.add_port(port);
        }
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
        Ok(Ok(_stream)) => {
            let port = Port::new(target.port, Protocol::Tcp, PortState::Open);
            Ok(Some((target.ip, port)))
        }
        Ok(Err(e)) => {
            use std::io::ErrorKind;
            let state = match e.kind() {
                ErrorKind::ConnectionRefused => PortState::Closed,
                _ => PortState::Blocked,
            };

            if state != PortState::Closed {
                let port = Port::new(target.port, Protocol::Tcp, state);
                Ok(Some((target.ip, port)))
            } else {
                Ok(None)
            }
        }
        Err(_) => {
            // Timeout elapsed, implies a DROP -> Ghosted/Filtered
            let port = Port::new(target.port, Protocol::Tcp, PortState::Ghosted);
            Ok(Some((target.ip, port)))
        }
    }
}

/// Discovers live hosts using a standard, unprivileged TCP connect sweep.
///
/// Sweeps through the provided [`IpSet`], attempting a basic connection to port 443.
/// This approach serves as a fallback for users without root privileges where raw
/// socket-based ARP/NDP sweeps are not possible. Returns a [`Vec<Host>`] for all IPs
/// that responded within the timeout window.
pub async fn discover(ips: IpSet) -> anyhow::Result<Vec<Host>> {
    let mut result: Vec<Host> = Vec::new();
    for ip in ips {
        if STOP_SIGNAL.load(Ordering::Relaxed) {
            break;
        }
        if let Some(found) = prober(ip).await? {
            result.push(found);
        }
    }
    Ok(result)
}

/// Attempts a basic TCP connection to port 443 on the specified [`IpAddr`].
///
/// Returns a basic [`Host`] object on success. Times out quickly (`100ms`) since it's
/// primarily intended for rapid host discovery, not deep service enumeration.
async fn prober(ip: IpAddr) -> anyhow::Result<Option<Host>> {
    let socket_addr: SocketAddr = SocketAddr::new(ip, 443);
    let probe_timeout: Duration = Duration::from_millis(100);

    let start: Instant = Instant::now();
    match timeout(probe_timeout, TcpStream::connect(socket_addr)).await {
        Ok(Ok(_)) | Ok(Err(_)) => {
            increment_host_count();
            let host: Host = Host::new(ip).with_rtt(start.elapsed());
            Ok(Some(host))
        }
        Err(_elapsed) => Ok(None),
    }
}
