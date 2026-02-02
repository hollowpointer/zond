// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use pnet::{
    packet::{
        Packet,
        ip::IpNextHeaderProtocols
    },
    transport::{
        self, 
        TransportChannelType,
        TransportProtocol,
        TransportReceiver, 
        TransportSender,
    },
};
use tokio::sync::mpsc;
use std::net::IpAddr;

const TRANSPORT_BUFFER_SIZE: usize = 4096;
const CHANNEL_TYPE_UDP: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp));
const CHANNEL_TYPE_TCP: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));

#[derive(Debug, Clone, Copy)]
pub enum TransportType {
    TcpLayer4,
    UdpLayer4
}

pub struct TransportHandle {
    pub tx: std::sync::Arc<std::sync::Mutex<TransportSender>>,
    pub rx: mpsc::UnboundedReceiver<(Vec<u8>, IpAddr)>,
}

macro_rules! spawn_listener {
    ($tx:expr, $rx:expr, $iter_func:path) => {
        std::thread::spawn(move || {
            let mut iterator = $iter_func(&mut $rx);
            loop {
                if let Ok((packet, source_ip)) = iterator.next() {
                    if $tx.send((packet.packet().to_vec(), source_ip)).is_err() {
                        break;
                    }
                }
            }
        })
    };
}

pub fn start_packet_capture(transport_type: TransportType) -> anyhow::Result<TransportHandle> {
    let (tx, mut rx_socket) = open_channel(transport_type)?;
    let (queue_tx, queue_rx) = mpsc::unbounded_channel();

    match transport_type {
        TransportType::TcpLayer4 => spawn_listener!(queue_tx, rx_socket, pnet::transport::tcp_packet_iter),
        TransportType::UdpLayer4 => spawn_listener!(queue_tx, rx_socket, pnet::transport::udp_packet_iter),
    };

    Ok(TransportHandle {
        tx: std::sync::Arc::new(std::sync::Mutex::new(tx)),
        rx: queue_rx,
    })
}

fn open_channel(transport_type: TransportType) -> anyhow::Result<(TransportSender, TransportReceiver)> {
    let channel_type: TransportChannelType = match transport_type {
        TransportType::TcpLayer4 => CHANNEL_TYPE_TCP,
        TransportType::UdpLayer4 => CHANNEL_TYPE_UDP,
    };
    let (tx, rx) = transport::transport_channel(TRANSPORT_BUFFER_SIZE, channel_type)?;
    Ok((tx, rx))
}