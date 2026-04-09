// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use zond_common::models::host::Host;
use zond_common::models::ip::set::IpSet;

use super::STOP_SIGNAL;

use crate::scanner::increment_host_count;

pub async fn range_discovery<F, Fut>(ips: IpSet, mut prober: F) -> anyhow::Result<Vec<Host>>
where
    F: FnMut(IpAddr) -> Fut,
    Fut: Future<Output = anyhow::Result<Option<Host>>>,
{
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

pub async fn prober(ip: IpAddr) -> anyhow::Result<Option<Host>> {
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

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use zond_common::models::host::Host;

    #[tokio::test]
    #[ignore]
    async fn handshake_probe_should_find_known_open_port() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let result: Option<Host> = prober(ip).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn handshake_probe_should_timeout_on_unreachable_ip() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let result: Option<Host> = prober(ip).await.unwrap();
        assert!(result.is_none());
    }
}
