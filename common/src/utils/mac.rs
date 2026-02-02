// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! This module is commonly used for **Medium Access Control (MAC)** address operations.
//! 
//! This also includes things like **Organizationally unique identifier (OUI)** database
//! initialization and handling, thus being able to link a vendor (e.g Cisco) to a MAC address.

use std::sync::OnceLock;
use mac_oui::Oui;
use pnet::util::MacAddr;

static OUI_DB: OnceLock<Oui> = OnceLock::new();

/// Retrieves or initializes the **Organizationally unique identifier** database.
/// 
/// Used for linking a vendor to a MAC address (LAN)
fn get_oui_db() -> &'static Oui {
    OUI_DB.get_or_init(|| {
        Oui::default().expect("failed to load OUI database")
    })
}

/// Identify the vendor of a MAC address.
pub fn get_vendor(mac: MacAddr) -> Option<String> {
    let db = get_oui_db();
    let mac_str = mac.to_string();
    match db.lookup_by_mac(&mac_str) {
        Ok(Some(entry)) => Some(entry.company_name.clone()),
        _ => None,
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

    #[test]
    fn test_known_vendor_lookup() {
        let cisco_mac = MacAddr::new(0x00, 0x00, 0x0C, 0x01, 0x02, 0x03);
        let raspberry_mac = MacAddr::new(0x2c, 0xcf, 0x67, 0x03, 0x02, 0x01);
        let asrock_mac = MacAddr::new(0xa8, 0xa1, 0x59, 0xff, 0xff, 0xff);

        let cisco = get_vendor(cisco_mac);
        let raspberry = get_vendor(raspberry_mac);
        let asrock = get_vendor(asrock_mac);

        let cisco_str = cisco.unwrap();
        let raspberry_str = raspberry.unwrap();
        let asrock_str = asrock.unwrap();

        assert!(cisco_str.contains("Cisco"), "Vendor string '{}' should contain 'Cisco'", cisco_str);
        assert!(raspberry_str.contains("Raspberry"), "Vendor string '{}' should contain 'Raspberry'", raspberry_str);
        assert!(asrock_str.contains("ASRock"), "Vendor string '{}' should contain 'ASRock'", asrock_str);
    }

    #[test]
    fn test_unknown_vendor_lookup() {
        // This is a locally administered address (no vendors linked to it)
        let mac = MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00);
        let vendor = get_vendor(mac);
        assert!(vendor.is_none(), "Should return None for random/unknown MAC");
    }
}