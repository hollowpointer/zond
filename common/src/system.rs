// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use crate::models::localhost::{FirewallStatus, IpServiceGroup};
use pnet::datalink::NetworkInterface;

/// Defines the contract for accessing OS-level network information.
///
/// This repository abstracts system calls to query open ports, firewall status,
/// and available network interfaces.
pub trait SystemRepository {
    /// Returns a list of services listening on local ports, grouped by IP.
    fn get_local_services(&self) -> anyhow::Result<Vec<IpServiceGroup>>;

    /// Checks the status of the local firewall (e.g., UFW, iptables, Windows Firewall).
    fn get_firewall_status(&self) -> anyhow::Result<FirewallStatus>;

    /// Retrieves a list of available physical and virtual network interfaces.
    fn get_network_interfaces(&self) -> anyhow::Result<Vec<NetworkInterface>>;
}
