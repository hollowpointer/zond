// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use hickory_resolver::system_conf::read_system_conf;
use std::net::SocketAddr;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use anyhow::{Context, ensure};
use pnet::packet::{Packet, udp::UdpPacket};
use tokio::sync::mpsc::UnboundedReceiver;
use zond_common::{models::host::Host, utils};
use zond_protocols::{
    dns,
    mdns::{self, MdnsRecord},
    udp,
};

use crate::network::transport::{self, TransportHandle, TransportType};

const DNS_PORT: u16 = 53;
const MDNS_PORT: u16 = 5353;

type Hostname = String;
type TransID = u16;

pub struct HostnameResolver {
    udp_handle: TransportHandle,
    dns_map: HashMap<TransID, IpAddr>,
    mdns_cache: HashMap<IpAddr, MdnsRecord>,
    hostname_map: HashMap<IpAddr, Hostname>,
    dns_rx: UnboundedReceiver<IpAddr>,
    dns_socket: SocketAddr,
    id_counter: AtomicU16,
}

impl HostnameResolver {
    pub fn new(dns_rx: UnboundedReceiver<IpAddr>) -> anyhow::Result<Self> {
        Ok(Self {
            udp_handle: transport::start_packet_capture(TransportType::UdpLayer4)?,
            dns_map: HashMap::new(),
            mdns_cache: HashMap::new(),
            hostname_map: HashMap::new(),
            dns_rx,
            dns_socket: get_dns_server_socket()?,
            id_counter: AtomicU16::new(0),
        })
    }

    pub async fn run(mut self) -> Self {
        loop {
            tokio::select! {
                res = self.dns_rx.recv() => {
                    match res {
                        Some(ip) => {
                            let _ = self.send_dns_query(&ip).await;
                        }
                        None => break,
                    }
                }
                pkt = self.udp_handle.rx.recv() => {
                    if let Some((bytes, _addr)) = pkt {
                        let _ = self.process_udp_packets(&bytes);
                    }
                }
            }
        }

        if !self.dns_map.is_empty() {
            let _ = tokio::time::timeout(Duration::from_millis(250), async {
                while !self.dns_map.is_empty() {
                    if let Some((bytes, _addr)) = self.udp_handle.rx.recv().await {
                        let _ = self.process_udp_packets(&bytes);
                    }
                }
            })
            .await;
        }

        self
    }

    async fn send_dns_query(&mut self, ip: &IpAddr) -> anyhow::Result<()> {
        ensure!(is_queryable(ip), "{ip} cannot be queried");
        let id: u16 = self.get_next_trans_id();
        self.dns_map.insert(id, *ip);
        let (dns_addr, dns_port) = (self.dns_socket.ip(), self.dns_socket.port());

        let bytes: Vec<u8> = dns::create_ptr_packet(ip, id)?;
        let src_port: u16 = rand::random_range(50_000..u16::MAX);
        let udp_bytes: Vec<u8> = udp::create_packet(src_port, dns_port, bytes)?;
        let tx = self.udp_handle.tx.clone();
        tokio::task::spawn_blocking(move || {
            let udp_pkt = UdpPacket::new(&udp_bytes)
                .context("creating udp packet")
                .unwrap();
            let mut sender = tx.lock().unwrap();
            sender.send_to(udp_pkt, dns_addr)
        })
        .await??;
        Ok(())
    }

    fn process_udp_packets(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let udp_packet = UdpPacket::new(bytes).context("truncated or invalid UDP packet")?;
        match udp_packet.get_source() {
            DNS_PORT => self.process_dns_packet(udp_packet)?,
            MDNS_PORT => self.process_mdns_packet(udp_packet)?,
            _ => {}
        }
        Ok(())
    }

    fn process_dns_packet(&mut self, packet: UdpPacket) -> anyhow::Result<()> {
        let (response_id, hostname) = dns::get_hostname(packet.payload())?;
        if let Some(ip) = self.dns_map.remove(&response_id) {
            self.hostname_map.insert(ip, hostname);
        }
        Ok(())
    }

    fn process_mdns_packet(&mut self, packet: UdpPacket) -> anyhow::Result<()> {
        let mdns_record: MdnsRecord = mdns::extract_resource(packet.payload())?;

        let preferred_ip = mdns_record
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .or_else(|| {
                mdns_record.ips.iter().find(|ip| {
                    if let IpAddr::V6(v6) = ip {
                        v6.is_unicast_link_local()
                    } else {
                        false
                    }
                })
            })
            .or_else(|| mdns_record.ips.iter().next());

        if let Some(ip) = preferred_ip {
            self.mdns_cache.insert(*ip, mdns_record);
        }

        Ok(())
    }

    pub fn resolve_hosts(&mut self, hosts: &mut Vec<Host>) {
        for host in hosts {
            let ips_to_check = host.ips.clone();

            for ip in ips_to_check {
                // Resolve DNS
                if host.hostname.is_none()
                    && let Some(hostname) = self.hostname_map.remove(&ip)
                {
                    host.hostname = Some(hostname);
                }

                // Resolve mDNS
                if let Some(mdns_record) = self.mdns_cache.remove(&ip) {
                    if host.hostname.is_none() && mdns_record.hostname.is_some() {
                        host.hostname = mdns_record.hostname;
                    }

                    host.ips.extend(mdns_record.ips);
                }
            }
        }
    }

    fn get_next_trans_id(&self) -> u16 {
        self.id_counter.fetch_add(1, Ordering::Relaxed)
    }
}

fn is_queryable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(ipv6_addr) => utils::ip::is_global_unicast(ipv6_addr),
        IpAddr::V4(_ipv4_addr) => {
            // Future refinement: check for private ranges/localhost
            true
        }
    }
}

fn get_dns_server_socket() -> anyhow::Result<SocketAddr> {
    let (config, _options) = read_system_conf()?;

    if let Some(ns) = config.name_servers().first() {
        return Ok(ns.socket_addr);
    }

    Ok("1.1.1.1:53".parse()?)
}
