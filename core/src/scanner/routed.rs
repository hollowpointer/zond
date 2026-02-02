// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use anyhow::ensure;
use async_trait::async_trait;
use pnet::{datalink::NetworkInterface, packet::tcp::TcpPacket};
use tokio::sync::mpsc::UnboundedSender;
use zond_common::{error, success};

use zond_common::models::{host::Host, range::IpCollection};
use zond_protocols as protocol;

use crate::network::transport::{self, TransportHandle, TransportType};

use super::NetworkExplorer;

// this shit needs improvement
const MIN_SCAN_DURATION: Duration = Duration::from_millis(200);
const MAX_SCAN_DURATION: Duration = Duration::from_millis(3000);
const MS_PER_IP: f64 = 0.5;

type SeqNum = u32;

pub struct RoutedScanner {
    src_v4: Option<Ipv4Addr>,
    src_v6: Option<Ipv6Addr>,
    responded_ips: HashMap<IpAddr, VecDeque<Duration>>,
    ips: IpCollection,
    tcp_handle: TransportHandle,
    dns_tx: Option<UnboundedSender<IpAddr>>,
    rtt_map: HashMap<(IpAddr, SeqNum), Instant>,
}

#[async_trait]
impl NetworkExplorer for RoutedScanner {
    async fn discover_hosts(&mut self) -> anyhow::Result<Vec<Host>> {
        if let Err(e) = self.send_discovery_packets() {
            error!("Failed to send packets: {e}");
        }

        let deadline: Instant = calculate_deadline(self.ips.len());

        loop {
            if super::STOP_SIGNAL.load(Ordering::Relaxed)
                || self.ips.len() == self.responded_ips.len()
            {
                break;
            }

            let remaining: Duration = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            tokio::select! {
                res = self.tcp_handle.rx.recv() => {
                    match res {
                        Some((bytes, ip)) => {
                            if !self.ips.contains(&ip) {
                                continue;
                            }

                            let entry = self.responded_ips.entry(ip);
                            let is_new = matches!(entry, Entry::Vacant(_));
                            let latencies = entry.or_default();

                            if is_new {
                                let _ = self.dns_tx.as_ref().map(|dns| dns.send(ip));
                                super::increment_host_count();
                            }

                            if let Some(tcp_packet) = TcpPacket::new(&bytes) {
                                let ack_num: u32 = tcp_packet.get_acknowledgement();
                                let original_seq: u32 = ack_num.wrapping_sub(1);

                                if let Some(start_time) = self.rtt_map.remove(&(ip, original_seq)) {
                                    let rtt: Duration = start_time.elapsed();
                                    latencies.push_back(rtt);
                                }
                            }
                        },
                        None => break,
                    }
                },
                _ = tokio::time::sleep(remaining) => {
                    break;
                }
            }
        }

        self.rtt_map.clear();
        let hosts: Vec<Host> = self
            .responded_ips
            .drain()
            .map(|(ip, latencies)| {
                let mut host = Host::new(ip);
                host.set_rtts(latencies);
                host
            })
            .collect();

        Ok(hosts)
    }
}

impl RoutedScanner {
    pub fn new(
        intf: NetworkInterface,
        ips: IpCollection,
        dns_tx: Option<UnboundedSender<IpAddr>>,
    ) -> anyhow::Result<Self> {
        let tcp_handle: TransportHandle =
            transport::start_packet_capture(TransportType::TcpLayer4)?;

        let src_v4: Option<Ipv4Addr> = intf.ips.iter().find_map(|ip_net| match ip_net.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None,
        });

        let src_v6: Option<Ipv6Addr> = intf.ips.iter().find_map(|ip_net| match ip_net.ip() {
            IpAddr::V6(ipv6) => Some(ipv6),
            _ => None,
        });

        ensure!(
            src_v4.is_some() || src_v6.is_some(),
            "interface has no ip addresses"
        );

        Ok(Self {
            src_v4,
            src_v6,
            responded_ips: HashMap::new(),
            ips,
            tcp_handle,
            dns_tx,
            rtt_map: HashMap::new(),
        })
    }

    fn send_discovery_packets(&mut self) -> anyhow::Result<()> {
        let src_port: u16 = rand::random_range(50_000..u16::MAX);
        let dst_port: u16 = 443;
        for dst_addr in self.ips.iter() {
            let src_addr: IpAddr = match dst_addr {
                IpAddr::V4(_) => {
                    ensure!(self.src_v4.is_some(), "interface has no ipv4 address");
                    IpAddr::V4(self.src_v4.unwrap())
                }
                IpAddr::V6(_) => {
                    ensure!(self.src_v6.is_some(), "interface has no ipv6 address");
                    IpAddr::V6(self.src_v6.unwrap())
                }
            };

            let seq_num: u32 = rand::random_range(0..=u32::MAX);
            let packet: Vec<u8> =
                protocol::tcp::create_packet(&src_addr, &dst_addr, src_port, dst_port, seq_num)?;

            if let Some(packet) = TcpPacket::new(&packet) {
                let mut tx = self.tcp_handle.tx.lock().unwrap();
                match tx.send_to(packet, dst_addr) {
                    Ok(_) => {
                        success!(verbosity = 2, "Sent discovery packet to {dst_addr}");
                        self.rtt_map.insert((dst_addr, seq_num), Instant::now());
                    }
                    Err(e) => error!(verbosity = 2, "Failed to send packet to {dst_addr}: {e}"),
                }
            }
        }
        Ok(())
    }
}

fn calculate_deadline(ips_len: usize) -> Instant {
    let variable_ms = (ips_len as f64 * MS_PER_IP) as u64;

    let scan_duration = (MIN_SCAN_DURATION + Duration::from_millis(variable_ms))
        .clamp(MIN_SCAN_DURATION, MAX_SCAN_DURATION);

    Instant::now() + scan_duration
}
