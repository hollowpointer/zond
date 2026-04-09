pub mod ext;
pub mod lan;
pub mod os;
pub mod routing;
pub mod utils;

pub use ext::NetworkInterfaceExtension;
pub use lan::{get_lan_network, ViabilityError};
pub use routing::map_ips_to_interfaces;
pub use utils::{get_prioritized_interfaces, is_layer_2_capable, is_on_link};
