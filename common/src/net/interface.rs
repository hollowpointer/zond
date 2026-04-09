// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

pub mod ext;
pub mod lan;
pub mod os;
pub mod routing;
pub mod utils;

pub use ext::NetworkInterfaceExtension;
pub use lan::{get_lan_network, ViabilityError};
pub use routing::map_ips_to_interfaces;
pub use utils::{get_prioritized_interfaces, is_layer_2_capable, is_on_link};
