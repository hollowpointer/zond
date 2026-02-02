// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

// use crate::adapters::outbound::terminal::print;
use anyhow::{self, Context};
use pnet::datalink;
use pnet::datalink::{Channel, Config, DataLinkReceiver, DataLinkSender, NetworkInterface};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;

const READ_TIMEOUT_MS: u64 = 50;

pub struct EthernetHandle {
    pub tx: Box<dyn DataLinkSender>,
    pub rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

pub fn start_capture(intf: &NetworkInterface) -> anyhow::Result<EthernetHandle> {
    let cfg = Config {
        read_timeout: Some(Duration::from_millis(READ_TIMEOUT_MS)),
        ..Default::default()
    };
    let (tx, rx_socket) = open_eth_channel(intf, datalink::channel, cfg)?;
    let (queue_tx, queue_rx) = mpsc::unbounded_channel();
    spawn_eth_listener(queue_tx, rx_socket);
    Ok(EthernetHandle { tx, rx: queue_rx })
}

pub fn open_eth_channel<F>(
    intf: &NetworkInterface,
    channel_opener: F,
    cfg: Config,
) -> anyhow::Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)>
where
    F: FnOnce(&NetworkInterface, Config) -> std::io::Result<datalink::Channel>,
{
    let ch: Channel =
        channel_opener(intf, cfg).with_context(|| format!("opening on {}", intf.name))?;

    match ch {
        Channel::Ethernet(tx, rx) => Ok((tx, rx)),
        _ => anyhow::bail!("non-ethernet channel for {}", intf.name),
    }
}

pub fn spawn_eth_listener(
    eth_tx: mpsc::UnboundedSender<Vec<u8>>,
    eth_rx: Box<dyn DataLinkReceiver>,
) {
    thread::spawn(move || {
        let mut eth_iter = eth_rx;
        loop {
            if let Ok(frame) = eth_iter.next()
                && eth_tx.send(frame.to_vec()).is_err()
            {
                break;
            }
        }
    });
}

