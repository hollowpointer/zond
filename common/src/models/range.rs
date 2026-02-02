// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use crate::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Range {
    pub start_addr: Ipv4Addr,
    pub end_addr: Ipv4Addr,
}

impl Ipv4Range {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        let s_u32 = u32::from(start);
        let e_u32 = u32::from(end);

        if s_u32 <= e_u32 {
            Self {
                start_addr: start,
                end_addr: end,
            }
        } else {
            info!(verbosity = 1, "{start} > {end}. Reversing order.");
            Self {
                start_addr: end,
                end_addr: start,
            }
        }
    }

    pub fn to_iter(&self) -> impl Iterator<Item = IpAddr> {
        let start: u32 = self.start_addr.into();
        let end: u32 = self.end_addr.into();
        (start..=end).map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
    }

    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        let start: u32 = self.start_addr.into();
        let end: u32 = self.end_addr.into();
        let ip_u32: u32 = (*ip).into();
        ip_u32 >= start && ip_u32 <= end
    }

    pub fn len(&self) -> u32 {
        let s_u32: u32 = u32::from(self.start_addr);
        let e_u32: u32 = u32::from(self.end_addr);

        if e_u32 >= s_u32 {
            (e_u32 - s_u32) + 1
        } else {
            0
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub fn cidr_range(ip: Ipv4Addr, prefix: u8) -> anyhow::Result<Ipv4Range> {
    let network = pnet::ipnetwork::Ipv4Network::new(ip, prefix)?;
    let start = network.network();
    let end = network.broadcast();

    Ok(Ipv4Range::new(start, end))
}

#[derive(Debug, Clone, Default)]
pub struct IpCollection {
    pub ranges: Vec<Ipv4Range>,
    pub singles: HashSet<IpAddr>,
}

impl IpCollection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_single(&mut self, ip: IpAddr) {
        if !self.singles.insert(ip) {
            info!(verbosity = 2, "{ip} already in collection");
        }
    }

    pub fn add_range(&mut self, range: Ipv4Range) {
        info!(
            verbosity = 2,
            "Adding {} - {} to collection (Size: {})",
            range.start_addr,
            range.end_addr,
            range.len()
        );
        self.ranges.push(range);
    }

    pub fn extend(&mut self, other: IpCollection) {
        info!(
            verbosity = 2,
            "Extending collection: Adding {} ranges and {} singles",
            other.ranges.len(),
            other.singles.len()
        );
        self.ranges.extend(other.ranges);
        self.singles.extend(other.singles);
    }

    pub fn len(&self) -> usize {
        let ranges_count: usize = self.ranges.iter().map(|r| r.len() as usize).sum();

        ranges_count + self.singles.len()
    }

    /// Merges overlapping ranges and combines singles into ranges where possible.
    pub fn compact(&mut self) {
        let mut v4_singles: Vec<Ipv4Addr> = Vec::new();
        self.singles.retain(|ip| {
            if let IpAddr::V4(addr) = ip {
                v4_singles.push(*addr);
                false
            } else {
                true
            }
        });

        for ip in v4_singles {
            self.ranges.push(Ipv4Range::new(ip, ip));
        }

        self.ranges.sort_by_key(|r| r.start_addr);

        if self.ranges.is_empty() {
            return;
        }

        let mut merged: Vec<Ipv4Range> = Vec::new();
        let mut current = self.ranges[0];

        for next in self.ranges.iter().skip(1) {
            let curr_end = u32::from(current.end_addr);
            let next_start = u32::from(next.start_addr);

            if next_start <= curr_end.saturating_add(1) {
                let next_end = u32::from(next.end_addr);
                if next_end > curr_end {
                    current.end_addr = next.end_addr;
                }
            } else {
                merged.push(current);
                current = *next;
            }
        }
        merged.push(current);

        self.ranges = merged;
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        if self.singles.contains(ip) {
            return true;
        }

        if let IpAddr::V4(ipv4_addr) = ip {
            for range in &self.ranges {
                if range.contains(ipv4_addr) {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty() && self.singles.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = IpAddr> + '_ {
        let range_iter = self.ranges.iter().flat_map(|range| range.to_iter());

        let single_iter = self
            .singles
            .iter()
            .filter(|ip| {
                if let IpAddr::V4(v4) = ip {
                    !self.ranges.iter().any(|r| r.contains(v4))
                } else {
                    true
                }
            })
            .copied();

        range_iter.chain(single_iter)
    }
}

impl IntoIterator for IpCollection {
    type Item = IpAddr;
    type IntoIter = std::vec::IntoIter<IpAddr>;

    fn into_iter(self) -> Self::IntoIter {
        let total_size = self.len();
        let mut all_ips = Vec::with_capacity(total_size);

        all_ips.extend(self.singles);

        for range in self.ranges {
            all_ips.extend(range.to_iter());
        }

        all_ips.into_iter()
    }
}

impl FromIterator<IpCollection> for IpCollection {
    fn from_iter<I: IntoIterator<Item = IpCollection>>(iter: I) -> Self {
        let mut master = IpCollection::new();
        for collection in iter {
            master.extend(collection);
        }
        master
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_should_find_singles() {
        let mut collection = IpCollection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        collection.add_single(ip);
        
        assert!(collection.contains(&ip), "Collection should contain the single IP");
    }
}
