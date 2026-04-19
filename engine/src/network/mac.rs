// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Extensions for MAC address conversions between pnet and the core domain model.

use pnet::util::MacAddr as PnetMacAddr;
use zond_core::models::mac::MacAddr as CoreMacAddr;

/// An extension trait to seamlessly convert from `pnet::util::MacAddr` to the 
/// native `zond_core::models::mac::MacAddr`.
pub trait IntoCoreMac {
    fn into_core(self) -> CoreMacAddr;
}

impl IntoCoreMac for PnetMacAddr {
    #[inline]
    fn into_core(self) -> CoreMacAddr {
        CoreMacAddr::new(self.0, self.1, self.2, self.3, self.4, self.5)
    }
}
