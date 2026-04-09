// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Parsing Utilities
//!
//! This module serves as the primary gateway for all parsing and resolution logic
//! within the library. It abstracts the complexities of format-specific grammars
//! into a clean, high-level API.
//!
//! Currently supported:
//! * **IP Resolution**: Translating strings and keywords into [`IpSet`] models.

pub mod ip;

pub use ip::{IS_LAN_SCAN, IpParseError, to_set as to_ipset};

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
    use std::net::IpAddr;

    #[test]
    fn test_facade_ip_resolution() {
        let inputs = vec!["127.0.0.1", "10.0.0.1-5"];

        let set = to_ipset(&inputs).expect("Facade should resolve IP targets");

        assert_eq!(set.len(), 6);
        assert!(set.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(set.contains(&"10.0.0.3".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_facade_empty_input() {
        let inputs: Vec<&str> = vec![];
        let result = to_ipset(&inputs);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IpParseError::EmptySet);
    }

    #[test]
    fn test_facade_comma_splitting() {
        let inputs = vec!["1.1.1.1, 2.2.2.2"];
        let set = to_ipset(&inputs).unwrap();

        assert_eq!(set.len(), 2);
    }
}
