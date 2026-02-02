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
use zond_common::system::SystemRepository;

/// Application Service for Local System Information.
///
/// Responsible for gathering and aggregating information about the machine
/// Service for Local System Information.
/// * Network Interfaces (IPs, MACs).
/// * Active Services (Open ports).
/// * Firewall status.
pub struct InfoService {
    system_repo: Box<dyn SystemRepository>,
}

pub struct SystemInfo {
    pub services: Vec<IpServiceGroup>,
    pub firewall: FirewallStatus,
    pub interfaces: Vec<NetworkInterface>,
}

impl InfoService {
    pub fn new(system_repo: Box<dyn SystemRepository>) -> Self {
        Self { system_repo }
    }

    /// Retrieves a comprehensive snapshot of the local system's network state.
    pub fn get_system_info(&self) -> anyhow::Result<SystemInfo> {
        let services = self.system_repo.get_local_services()?;
        let firewall = self.system_repo.get_firewall_status()?;
        let interfaces = self.system_repo.get_network_interfaces()?;

        Ok(SystemInfo {
            services,
            firewall,
            interfaces,
        })
    }
}
