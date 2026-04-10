// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Hardware detection heuristics specialized for target Operating Systems.
//!
//! Bridges platform-specific techniques (sysfs, CLI tools, Windows API)
//! to classify network adapters seamlessly.

use pnet::datalink::NetworkInterface;

#[cfg(target_os = "linux")]
#[doc(inline)]
pub use linux_impl::{is_physical, is_wireless};
#[cfg(target_os = "macos")]
#[doc(inline)]
pub use macos_impl::{is_physical, is_wireless};
#[cfg(target_os = "windows")]
#[doc(inline)]
pub use windows_impl::{is_physical, is_wireless};

/// Determines if the interface corresponds to a physical adapter (not virtual).
#[cfg(target_os = "linux")]
pub mod linux_impl {
    use super::*;
    use std::path::Path;

    pub fn is_physical(interface: &NetworkInterface) -> bool {
        Path::new(&format!("/sys/class/net/{}/device", interface.name)).exists()
    }

    pub fn is_wireless(interface: &NetworkInterface) -> bool {
        Path::new(&format!("sys/class/net/{}/wireless", interface.name)).exists()
    }
}

#[cfg(target_os = "macos")]
pub mod macos_impl {
    use super::*;
    use std::collections::HashSet;
    use std::process::Command;
    use std::sync::OnceLock;

    /// A struct to hold the cached hardware information
    struct HardwareInfo {
        physical_devices: HashSet<String>,
        wireless_devices: HashSet<String>,
    }

    /// Singleton that runs the shell commands only once on first access.
    fn get_hardware_info() -> &'static HardwareInfo {
        static HARDWARE_INFO: OnceLock<HardwareInfo> = OnceLock::new();

        HARDWARE_INFO.get_or_init(|| {
            let mut physical = HashSet::new();
            let mut wireless = HashSet::new();

            // Get Physical Ports (Wired & Wireless hardware)
            if let Ok(output) = Command::new("networksetup")
                .arg("-listallhardwareports")
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(device) = line.strip_prefix("Device: ") {
                        physical.insert(device.trim().to_string());
                    }
                }
            }

            // Identify which of those are specifically Wireless
            for device in &physical {
                let is_wifi = Command::new("networksetup")
                    .arg("-getairportnetwork")
                    .arg(device)
                    .output()
                    .map(|out| out.status.success())
                    .unwrap_or(false);

                if is_wifi {
                    wireless.insert(device.clone());
                }
            }

            HardwareInfo {
                physical_devices: physical,
                wireless_devices: wireless,
            }
        })
    }

    pub fn is_physical(interface: &NetworkInterface) -> bool {
        get_hardware_info()
            .physical_devices
            .contains(&interface.name)
    }

    pub fn is_wireless(interface: &NetworkInterface) -> bool {
        get_hardware_info()
            .wireless_devices
            .contains(&interface.name)
    }
}

#[cfg(target_os = "windows")]
pub mod windows_impl {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
    };

    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_TYPE_TUNNEL: u32 = 131;
    const IF_TYPE_IEEE80211: u32 = 71;
    const IF_TYPE_PPP: u32 = 23;

    struct WindowsInterfaceInfo {
        physical_devices: HashSet<String>,
        wireless_devices: HashSet<String>,
    }

    // Thread-local cache prevents the N+1 FFI performance trap when iterating,
    // but the 2-second TTL ensures we still support hot-plugged devices across scans.
    thread_local! {
        static INTERFACE_CACHE: RefCell<Option<(Instant, WindowsInterfaceInfo)>> = RefCell::new(None);
    }

    fn fetch_windows_interface_info() -> WindowsInterfaceInfo {
        let mut physical = HashSet::new();
        let mut wireless = HashSet::new();

        unsafe {
            let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
            if GetIfTable2(&mut table_ptr) == 0 && !table_ptr.is_null() {
                let table = &*table_ptr;
                let rows = std::slice::from_raw_parts(
                    &table.Table[0] as *const MIB_IF_ROW2,
                    table.NumEntries as usize,
                );

                for row in rows {
                    let is_software = row.Type == IF_TYPE_SOFTWARE_LOOPBACK
                        || row.Type == IF_TYPE_TUNNEL
                        || row.Type == IF_TYPE_PPP;

                    let bitfield = row.InterfaceAndOperStatusFlags._bitfield;
                    let is_hardware_bit = (bitfield & 1) != 0;
                    let has_connector_bit = (bitfield & (1 << 2)) != 0;

                    let guid = row.InterfaceGuid;
                    let guid_str = format!(
                        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
                        guid.data1,
                        guid.data2,
                        guid.data3,
                        guid.data4[0],
                        guid.data4[1],
                        guid.data4[2],
                        guid.data4[3],
                        guid.data4[4],
                        guid.data4[5],
                        guid.data4[6],
                        guid.data4[7]
                    );

                    // Must check !is_software first to prevent spoofed connector bits
                    if !is_software && (is_hardware_bit || has_connector_bit) {
                        physical.insert(guid_str.clone());
                    }

                    if row.Type == IF_TYPE_IEEE80211 {
                        wireless.insert(guid_str);
                    }
                }
                FreeMibTable(table_ptr as *mut std::ffi::c_void);
            }
        }

        WindowsInterfaceInfo {
            physical_devices: physical,
            wireless_devices: wireless,
        }
    }

    /// Helper to access the cache, updating it if necessary (older than 2 seconds)
    fn with_cache<F, R>(f: F) -> R
    where
        F: FnOnce(&WindowsInterfaceInfo) -> R,
    {
        INTERFACE_CACHE.with(|cache| {
            let mut cache_ref = cache.borrow_mut();
            let now = Instant::now();

            let needs_update = match cache_ref.as_ref() {
                Some((timestamp, _)) => now.duration_since(*timestamp) > Duration::from_secs(2),
                None => true,
            };

            if needs_update {
                *cache_ref = Some((now, fetch_windows_interface_info()));
            }

            // Safe to unwrap because we just guaranteed it's populated above
            f(&cache_ref.as_ref().unwrap().1)
        })
    }

    pub fn is_physical(interface: &NetworkInterface) -> bool {
        with_cache(|info| {
            let name = interface
                .name
                .strip_prefix(r"\Device\NPF_")
                .unwrap_or(&interface.name);
            info.physical_devices.contains(name)
        })
    }

    pub fn is_wireless(interface: &NetworkInterface) -> bool {
        with_cache(|info| {
            let name = interface
                .name
                .strip_prefix(r"\Device\NPF_")
                .unwrap_or(&interface.name);
            info.wireless_devices.contains(name)
        })
    }
}
