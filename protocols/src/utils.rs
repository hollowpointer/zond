// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

// Application Layer
pub const DNS_HDR_LEN: usize = 12;
// Network Layer
pub const ICMP_V6_ECHO_REQ_LEN: usize = 8;
// pub const IP_V4_HDR_LEN: usize = 20;
pub const IP_V6_HDR_LEN: usize = 40;
// Data Link Layer
pub const ARP_LEN: usize = 28;
pub const ETH_HDR_LEN: usize = 14;
pub const MIN_ETH_FRAME_NO_FCS: usize = 60;
