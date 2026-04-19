// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Hardware Information
//!
//! This module defines the [`HardwareInfo`] model for identifying physical 
//! network characteristics. It records hardware addresses (MACs) and vendor 
//! metadata derived from the Organiztionally Unique Identifier (OUI).
//!
//! The model handles modern network complexities such as MAC randomization 
//! and multi-homed hosts by tracking a history of all seen addresses.

use std::{collections::BTreeMap, sync::Arc, time::Instant};
use crate::models::mac::MacAddr;

/// Physical hardware identification and auditing data for a network host.
///
/// `HardwareInfo` tracks multiple MAC addresses to support multi-NIC hosts 
/// and to detect "MAC hopping" on randomized devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareInfo {
    /// Discovered MAC addresses and the last time they were observed.
    pub(crate) macs: BTreeMap<MacAddr, Instant>,

    /// The hardware vendor identified from the MAC OUI (e.g., "Apple", "Dell").
    ///
    /// This field should ideally be shared via an `Arc` to minimize heap 
    /// allocations across thousands of identical host records.
    pub vendor: Option<Arc<str>>,
}

impl HardwareInfo {
    /// Creates a new `HardwareInfo` record for a specifically discovered MAC address.
    pub fn new(mac: MacAddr) -> Self {
        let mut macs = BTreeMap::new();
        macs.insert(mac, Instant::now());

        Self { macs, vendor: None }
    }

    /// Records a discovery event for a specific MAC address, updating its 
    /// "last seen" timestamp.
    pub fn add_mac(&mut self, mac: MacAddr) {
        self.macs.insert(mac, Instant::now());
    }

    /// Returns a read-only view of all recorded MAC addresses and their 
    /// last-seen timestamps.
    #[inline]
    pub fn macs(&self) -> &BTreeMap<MacAddr, Instant> {
        &self.macs
    }

    /// Returns the MAC address that was most recently observed.
    ///
    /// This is typically used to identify the primary hardware interface 
    /// currently active on the network.
    pub fn most_recent_mac(&self) -> Option<MacAddr> {
        self.macs
            .iter()
            .max_by_key(|&(_, time)| time)
            .map(|(mac, _)| *mac)
    }

    /// Removes all MAC address records that were last seen before the given `cutoff`.
    ///
    /// This is a critical forensic cleanup step for long-running monitors in 
    /// environments with aggressive MAC randomization, preventing memory 
    /// exhaustion from "ghost" hardware records.
    pub fn prune_stale_macs(&mut self, cutoff: Instant) {
        self.macs.retain(|_, last_seen| *last_seen >= cutoff);
    }

    /// Merges architectural findings from another hardware record.
    ///
    /// MAC addresses are interleaved, with the newest timestamp prevailing 
    /// for each unique address to prevent timeline regressions.
    pub fn merge(&mut self, other: HardwareInfo) {
        for (mac, time) in other.macs {
            self.macs
                .entry(mac)
                .and_modify(|t| {
                    if time > *t {
                        *t = time;
                    }
                })
                .or_insert(time);
        }

        if self.vendor.is_none() {
            self.vendor = other.vendor;
        }
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
    use std::time::Duration;

    #[test]
    fn hardware_vendor_assignment() {
        let mac = MacAddr::new(0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF);
        let mut hw = HardwareInfo::new(mac);
        hw.vendor = Some(Arc::from("VMware, Inc."));

        assert_eq!(hw.vendor.as_deref().unwrap(), "VMware, Inc.");
        assert!(hw.macs().contains_key(&mac));
    }

    #[test]
    fn test_most_recent_mac_selection() {
        let mac_old = MacAddr::new(1, 1, 1, 1, 1, 1);
        let mac_new = MacAddr::new(2, 2, 2, 2, 2, 2);

        let mut hw = HardwareInfo::new(mac_old);
        let future_time = Instant::now() + Duration::from_secs(60);
        hw.macs.insert(mac_new, future_time);

        assert_eq!(hw.most_recent_mac(), Some(mac_new));
    }

    #[test]
    fn most_recent_mac_on_empty() {
        // Construct an empty one manually via the pub(crate) field
        let hw = HardwareInfo { macs: BTreeMap::new(), vendor: None };
        assert_eq!(hw.most_recent_mac(), None);
    }

    #[test]
    fn prune_stale_macs_logic() {
        let mac_keep = MacAddr::new(1, 1, 1, 1, 1, 1);
        let mac_drop = MacAddr::new(2, 2, 2, 2, 2, 2);

        let mut hw = HardwareInfo::new(mac_keep);
        let past_time = Instant::now() - Duration::from_secs(3600);
        hw.macs.insert(mac_drop, past_time);

        let cutoff = Instant::now() - Duration::from_secs(1800);
        hw.prune_stale_macs(cutoff);

        assert_eq!(hw.macs().len(), 1);
        assert!(hw.macs().contains_key(&mac_keep));
    }
}
