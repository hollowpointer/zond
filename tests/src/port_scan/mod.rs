// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Specific port scanning implementation tests.
//!
//! These tests focus on the accuracy of port state identification (Open,
//! Closed, Filtered) across different protocols and scanning strategies.

pub mod fidelity;
pub mod tcp_connect;
