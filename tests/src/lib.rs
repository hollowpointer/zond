// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Zond Integration Tests
//!
//! This crate contains integration tests for the Zond network scanner.
//! It verifies the orchestration logic between `zond-core`, `zond-plugins`,
//! and `zond-common` crates.
//!
//! ## Testing Philosophy
//!
//! 1. **Isolation**: Tests should avoid touching the host's primary network stack.
//!    We use Linux Network Namespaces (`ip netns`) via [`utils::NetnsContext`]
//!    to simulate isolated network environments.
//! 2. **Privilege Awareness**: Tests are categorized by their required permissions.
//!    Some tests (like ARP discovery) require root to run raw socket operations.
//! 3. **Scalability**: The testing structure is modular to allow adding new
//!    protocol verifications without cluttering the entry point.
//!
//! ## Modules
//!
//! - [`discovery`]: Verifies host and service identification (Phase 0).
//! - [`port_scan`]: Verifies port state fidelity (Open/Closed/Filtered) (Phase 0).
//! - [`utils`]: Shared infrastructure, including namespace and mock management.

#[cfg(test)]
pub mod discovery;
#[cfg(test)]
pub mod platform;
#[cfg(test)]
pub mod port_scan;
#[cfg(test)]
pub mod utils;
