// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Utilities for privacy-preserving output.
//!
//! Provides functions to mask personally identifiable information (PII) from scan results,
//! such as hardware MAC addresses and IPv6 Interface Identifiers, while preserving
//! network-level routing information for diagnostic utility.

use std::net::Ipv6Addr;

use pnet::util::MacAddr;

/// Redacts a hostname to protect privacy while maintaining some recognizability.
///
/// It preserves the first 2 and last 2 characters, replacing the middle with a fixed
/// number of 'X's. For very short hostnames (<= 4 chars), it redacts the entire string.
///
/// # Examples
/// ```
/// use zond_common::utils::redact;
///
/// assert_eq!(redact::hostname("kabelbox.local"), "kaXXXXXal");
/// assert_eq!(redact::hostname("workstation"), "woXXXXXon");
/// assert_eq!(redact::hostname("pc"), "XXXXX");
/// ```
pub fn hostname(name: &str) -> String {
    let len = name.len();

    // If the name is too short to leave 2 chars on each side, just redact it fully
    if len <= 4 {
        return "XXXXX".to_string();
    }

    let first_two = &name[..2];
    let last_two = &name[len - 2..];

    format!("{}XXXXX{}", first_two, last_two)
}

/// Redacts a MAC address to prevent hardware fingerprinting.
///
/// Returns a string where the last three octets are replaced by 'XX'.
///
/// # Examples
/// ```
/// use pnet::util::MacAddr;
/// use zond_common::utils::redact;
///
/// let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3);
/// assert_eq!(redact::mac_addr(&mac), "2c:cf:67:XX:XX:XX");
/// ```
pub fn mac_addr(mac: &MacAddr) -> String {
    format!("{:02x}:{:02x}:{:02x}:XX:XX:XX", mac.0, mac.1, mac.2)
}

/// Redacts an IPv6 Global Unicast Address by preserving only the first 16-bit segment.
///
/// This function keeps the first block (hextet) of the address to identify the
/// high-level network registry or provider, while masking the remaining 112 bits
/// (including the subnet ID and the Interface Identifier).
///
/// This provides a high level of privacy by obfuscating the specific network
/// topology and the host's identity.
///
///
///
/// # Examples
/// ```
/// use std::net::Ipv6Addr;
/// use zond_common::utils::redact;
///
/// let ip = "2a02:908:8c1:b880:1234:5678:9abc:def0".parse::<Ipv6Addr>().unwrap();
/// // Only the first 16-bit segment (s[0]) remains visible
/// assert_eq!(redact::global_unicast(&ip), "2a02::XXXX");
/// ```
pub fn global_unicast(ip: &Ipv6Addr) -> String {
    let s = ip.segments();
    format!("{:x}::XXXX", s[0])
}

/// Redacts the device-specific portion of an IPv6 Link-Local Address.
///
/// Preserves the prefix and the first two hextets of the IID (Vendor OUI)
/// while masking the final 32 bits to prevent hardware tracking.
///
/// # Examples
/// ```
/// use std::net::Ipv6Addr;
/// use zond_common::utils::redact;
///
/// let ip = "fe80::ca52:61ff:fec7:594".parse::<Ipv6Addr>().unwrap();
/// assert_eq!(redact::link_local(&ip), "fe80::ca52:61ff:XXXX:XXXX");
/// ```
pub fn link_local(ip: &Ipv6Addr) -> String {
    let s = ip.segments();
    format!("{:x}::{:x}:{:x}:XXXX:XXXX", s[0], s[4], s[5])
}

/// Redacts an IPv6 Unique Local Address (ULA) to prevent network fingerprinting.
///
/// This function preserves only the first 16-bit segment (typically starting with `fd` or `fc`),
/// masking the 40-bit Global ID, the 16-bit Subnet ID, and the 64-bit Interface Identifier.
///
/// Hiding the Global ID is critical for streamers because it is statistically unique
/// to a specific network site. Revealing it allows viewers to permanently fingerprint
/// the local network and correlate it across different sessions or data leaks.
///
/// # Examples
/// ```
///
/// use zond_common::utils::redact;
/// use std::net::Ipv6Addr;
///
/// let ip = "fd12:3456:789a:1:a8b2:c3d4:e5f6:1234".parse::<Ipv6Addr>().unwrap();
/// // Preserves "fd12", masks the unique Global ID ("3456:789a:1") and the rest
/// assert_eq!(redact::unique_local(&ip), "fd12::XXXX");
/// ```
pub fn unique_local(addr: &Ipv6Addr) -> String {
    let segments = addr.segments();
    format!("{:x}::XXXX", segments[0])
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
    fn test_redact_mac_addr() {
        let mac = pnet::util::MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3);
        assert_eq!(mac_addr(&mac), "2c:cf:67:XX:XX:XX");
    }

    #[test]
    fn test_redact_hostname_standard() {
        assert_eq!(hostname("kabelbox.local"), "kaXXXXXal");
        assert_eq!(hostname("raspberrypi"), "raXXXXXpi");
    }

    #[test]
    fn test_redact_hostname_short() {
        // Names 4 chars or less should be fully masked
        assert_eq!(hostname("ipad"), "XXXXX");
        assert_eq!(hostname("pc"), "XXXXX");
        assert_eq!(hostname(""), "XXXXX");
    }

    #[test]
    fn test_redact_hostname_medium() {
        // Just enough to show first 2 and last 2
        assert_eq!(hostname("iphone"), "ipXXXXXne");
    }

    #[test]
    fn mac_redaction_standard() {
        let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3);
        assert_eq!(mac_addr(&mac), "2c:cf:67:XX:XX:XX");
    }

    #[test]
    fn mac_redaction_leading_zeros() {
        // Tests that 0x05 becomes "05" and not "5"
        let mac = MacAddr::new(0x00, 0x05, 0x09, 0xaa, 0xbb, 0xcc);
        assert_eq!(mac_addr(&mac), "00:05:09:XX:XX:XX");
    }

    #[test]
    fn mac_redaction_upper_boundary() {
        let mac = MacAddr::new(0xff, 0xff, 0xff, 0x00, 0x11, 0x22);
        assert_eq!(mac_addr(&mac), "ff:ff:ff:XX:XX:XX");
    }

    #[test]
    fn gua_redaction_standard() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0x0, 0x0, 0x8a2e, 0x370, 0x7334, 0x1234);
        assert_eq!(global_unicast(&ip), "2001::XXXX");
    }

    #[test]
    fn gua_redaction_short_prefix() {
        let ip = Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0x1);
        assert_eq!(global_unicast(&ip), "2001::XXXX");
    }

    #[test]
    fn lla_redaction_standard() {
        let ip = "fe80::ca52:61ff:fec7:594".parse::<Ipv6Addr>().unwrap();
        assert_eq!(link_local(&ip), "fe80::ca52:61ff:XXXX:XXXX");
    }

    #[test]
    fn lla_redaction_zero_segments() {
        let ip = "fe80::ff:fe00:1".parse::<Ipv6Addr>().unwrap();
        assert_eq!(link_local(&ip), "fe80::0:ff:XXXX:XXXX");
    }

    #[test]
    fn ula_redaction_standard() {
        let ip = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 0x1, 0xa8b2, 0xc3d4, 0xe5f6, 0x1234);
        assert_eq!(unique_local(&ip), "fd12::XXXX");
    }

    #[test]
    fn ula_redaction_zero_compression() {
        let ip = "fd00::1".parse::<Ipv6Addr>().unwrap();
        assert_eq!(unique_local(&ip), "fd00::XXXX");
    }

    #[test]
    fn ula_redaction_hides_global_id() {
        let ip1 = "fd00:1111:1111::1".parse::<Ipv6Addr>().unwrap();
        let ip2 = "fd00:2222:2222::1".parse::<Ipv6Addr>().unwrap();
        assert_eq!(unique_local(&ip1), unique_local(&ip2));
        assert_eq!(unique_local(&ip1), "fd00::XXXX");
    }
}
