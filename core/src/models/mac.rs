// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! This module provides a native **Medium Access Control (MAC)** address type 
//! to eliminate dependency on external network parsing libraries within the core.
//!
//! It also includes **Organizationally Unique Identifier (OUI)** database
//! initialization and handling for vendor identification.

use mac_oui::Oui;
use std::fmt;
use std::sync::OnceLock;

/// A native, framework-agnostic MAC address representation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Creates a new `MacAddr` from 6 octets.
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self([a, b, c, d, e, f])
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

static OUI_DB: OnceLock<Oui> = OnceLock::new();

/// Retrieves or initializes the **Organizationally unique identifier** database.
///
/// Used for linking a vendor to a MAC address (LAN)
fn get_oui_db() -> &'static Oui {
    OUI_DB.get_or_init(|| Oui::default().expect("failed to load OUI database"))
}

/// Identify the vendor of a MAC address.
pub fn get_vendor(mac: &MacAddr) -> Option<String> {
    let db = get_oui_db();
    let mac_str = mac.to_string();
    match db.lookup_by_mac(&mac_str) {
        Ok(Some(entry)) => Some(entry.company_name.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_display_and_debug() {
        let mac = MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E);
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:5e");
        assert_eq!(format!("{:?}", mac), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn test_mac_from_array() {
        let arr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mac = MacAddr::from(arr);
        assert_eq!(mac.0, arr);
    }

    #[test]
    fn test_vendor_lookup() {
        let mac = MacAddr::new(0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF);
        let vendor = get_vendor(&mac);
        assert_eq!(vendor, Some("VMware, Inc".to_string()));
    }

    #[test]
    fn test_unknown_vendor_lookup() {
        let mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x00); // Locally administered
        let vendor = get_vendor(&mac);
        assert_eq!(vendor, None);
    }
}
