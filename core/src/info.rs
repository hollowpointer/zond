// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Local System Information Service
//!
//! Implements the "System Info" use case.
//!
//! This service acts as a facade for gathering local machine statistics and
//! configuration, useful for debugging or self-awareness context.

use pnet::datalink::NetworkInterface;
use zond_common::models::localhost::{FirewallStatus, IpServiceGroup};

/// Retrieves a comprehensive snapshot of the local system's network state.
pub fn get_system_info() -> anyhow::Result<SystemInfo> {
    let services = crate::system::get_local_services()?;
    let firewall = crate::system::get_firewall_status()?;
    let interfaces = crate::system::get_network_interfaces()?;

    Ok(SystemInfo {
        services,
        firewall,
        interfaces,
    })
}

pub struct SystemInfo {
    pub services: Vec<IpServiceGroup>,
    pub firewall: FirewallStatus,
    pub interfaces: Vec<NetworkInterface>,
}
