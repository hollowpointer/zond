use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

pub trait NetworkInterfaceExtension {
    fn get_ipv4_nets(&self) -> Vec<Ipv4Network>;
    fn get_ipv6_nets(&self) -> Vec<Ipv6Network>;
    fn get_ipv4_range(&self) -> Option<Ipv4Network>;
}

impl NetworkInterfaceExtension for NetworkInterface {
    fn get_ipv4_nets(&self) -> Vec<Ipv4Network> {
        self.ips
            .iter()
            .filter_map(|ip| {
                if let IpNetwork::V4(ipv4) = ip {
                    Some(*ipv4)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_ipv6_nets(&self) -> Vec<Ipv6Network> {
        self.ips
            .iter()
            .filter_map(|ip| {
                if let IpNetwork::V6(ipv6) = ip {
                    Some(*ipv6)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_ipv4_range(&self) -> Option<Ipv4Network> {
        // Simple heuristic: pick the first non-loopback IPv4
        self.get_ipv4_nets()
            .into_iter()
            .find(|net| !net.ip().is_loopback())
    }
}
