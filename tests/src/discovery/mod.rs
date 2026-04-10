// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! High-level host and service discovery tests.
//!
//! These tests verify Zond's ability to identify live hosts across various
//! network environments using both unprivileged (TCP sweeps) and
//! privileged (ARP/ICMP) techniques.

pub mod privileged;
pub mod unprivileged;
