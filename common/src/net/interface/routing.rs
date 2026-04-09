// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use pnet::datalink::{self, NetworkInterface};
use rayon::prelude::*;

use crate::models::ip::set::IpSet;

/// Maps target IPs to the interface used to reach them, split by Local vs Routed.
/// Returns: Map<Interface, (Local_Targets, Routed_Targets)>
pub fn map_ips_to_interfaces(
    collection: IpSet,
) -> (HashMap<NetworkInterface, (IpSet, IpSet)>, IpSet) {
    let interfaces: Vec<NetworkInterface> = datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .collect();

    let ip_to_idx: HashMap<IpAddr, usize> = interfaces
        .iter()
        .enumerate()
        .flat_map(|(idx, iface)| iface.ips.iter().map(move |ip_net| (ip_net.ip(), idx)))
        .collect();

    let mut result_map: HashMap<usize, (IpSet, IpSet)> = HashMap::new();
    let mut unmapped_ips = IpSet::new();
    let mut singles_to_route = Vec::new();

    // 1. Handle Ranges
    for range in collection.ranges() {
        let start: Ipv4Addr = range.start_addr;
        let end: Ipv4Addr = range.end_addr;
        let mut owner_idx: Option<usize> = None;

        for (idx, iface) in interfaces.iter().enumerate() {
            let is_local_subnet = iface.ips.iter().any(|ip_net| {
                ip_net.contains(IpAddr::V4(start)) && ip_net.contains(IpAddr::V4(end))
            });

            if is_local_subnet {
                owner_idx = Some(idx);
                break;
            }
        }

        if let Some(idx) = owner_idx {
            result_map.entry(idx).or_default().0.insert_range(*range);
        } else {
            for ip in range.to_iter() {
                singles_to_route.push(ip);
            }
        }
    }

    type ThreadSockets = (Option<UdpSocket>, Option<UdpSocket>);

    enum RouteType {
        Local,
        Routed,
        Unmapped,
    }

    let processed_singles: Vec<(Option<usize>, RouteType, IpAddr)> = singles_to_route
        .par_iter()
        .map_init(
            || -> ThreadSockets { (None, None) },
            |sockets, &target_ip| {
                if let Some(idx) = find_local_index(&interfaces, target_ip) {
                    return (Some(idx), RouteType::Local, target_ip);
                }

                if let Some(source_ip) = resolve_route_source_ip(target_ip, sockets)
                    && let Some(idx) = ip_to_idx.get(&source_ip).copied()
                {
                    return (Some(idx), RouteType::Routed, target_ip);
                }

                (None, RouteType::Unmapped, target_ip)
            },
        )
        .collect();

    for (idx_opt, route_type, ip) in processed_singles {
        match route_type {
            RouteType::Local => {
                if let Some(idx) = idx_opt {
                    result_map.entry(idx).or_default().0.insert(ip);
                }
            }
            RouteType::Routed => {
                if let Some(idx) = idx_opt {
                    result_map.entry(idx).or_default().1.insert(ip);
                }
            }
            RouteType::Unmapped => {
                unmapped_ips.insert(ip);
            }
        }
    }

    let mapped_interfaces = result_map
        .into_iter()
        .map(|(idx, (local_ips, routed_ips))| (interfaces[idx].clone(), (local_ips, routed_ips)))
        .collect();

    (mapped_interfaces, unmapped_ips)
}

fn find_local_index(interfaces: &[NetworkInterface], target: IpAddr) -> Option<usize> {
    interfaces.iter().position(|iface| {
        iface.ips.iter().any(|ip_net| match (target, ip_net.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                ip_net.contains(target)
            }
            _ => false,
        })
    })
}

fn resolve_route_source_ip(
    target: IpAddr,
    sockets: &mut (Option<UdpSocket>, Option<UdpSocket>),
) -> Option<IpAddr> {
    let socket_opt = if target.is_ipv4() {
        &mut sockets.0
    } else {
        &mut sockets.1
    };

    if socket_opt.is_none() {
        let bind_addr = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        *socket_opt = UdpSocket::bind(bind_addr).ok();
    }

    let socket = socket_opt.as_ref()?;

    socket.connect((target, 53)).ok()?;
    socket.local_addr().ok().map(|s| s.ip())
}
