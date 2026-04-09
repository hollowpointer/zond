use crate::info;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use super::os::{is_physical, is_wireless};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ViabilityError {
    /// The interface is operationally down.
    IsDown,
    /// The interface was filtered out as "not physical" by the provided logic.
    NotPhysical,
    /// The interface does not have a MAC address.
    NoMacAddress,
    /// The interface does not support broadcast (required for ARP).
    NotBroadcast,
    /// The interface is a point-to-point link (e.g., a VPN).
    IsPointToPoint,
    /// The interface has no IPv4 address (for ARP) AND no IPv6 Link-Local (for NDP).
    NoValidLanIp,
}

/// Finds the primary LAN network and returns the ipv4 network
pub fn get_lan_network() -> anyhow::Result<Option<Ipv4Network>> {
    let interfaces: Vec<NetworkInterface> = pnet::datalink::interfaces();

    let interfaces_str: &str = match interfaces.len() {
        1 => "interface",
        _ => "interfaces",
    };

    info!(
        verbosity = 1,
        "Identified {} network {}, picking the best one...",
        interfaces.len(),
        interfaces_str
    );

    let interfaces: Vec<NetworkInterface> = interfaces
        .into_iter()
        .filter_map(
            |interface| match is_viable_lan_interface(&interface, is_physical) {
                Ok(()) => Some(interface),
                Err(_) => None,
            },
        )
        .collect();

    let interface: NetworkInterface =
        if let Some(interface) = select_best_lan_interface(interfaces, is_wired) {
            info!(
                verbosity = 1,
                "Performing LAN scan on interface {}", interface.name
            );
            interface
        } else {
            anyhow::bail!("No interfaces available for LAN discovery");
        };
    let private_v4_net: Option<Ipv4Network> = interface.ips.iter().find_map(|net| match net {
        IpNetwork::V4(v4) if v4.ip().is_private() => Some(*v4),
        _ => None,
    });
    Ok(private_v4_net)
}

fn is_viable_lan_interface(
    interface: &NetworkInterface,
    is_physical: impl Fn(&NetworkInterface) -> bool,
) -> Result<(), ViabilityError> {
    if !interface.is_up() {
        return Err(ViabilityError::IsDown);
    }
    if !is_physical(interface) {
        return Err(ViabilityError::NotPhysical);
    }
    if interface.is_loopback() {
        return Err(ViabilityError::NotPhysical);
    }
    if interface.mac.is_none() {
        return Err(ViabilityError::NoMacAddress);
    }
    if !interface.is_broadcast() {
        return Err(ViabilityError::NotBroadcast);
    }
    if interface.is_point_to_point() {
        return Err(ViabilityError::IsPointToPoint);
    }
    let has_valid_ip = interface.ips.iter().any(|net| match net {
        IpNetwork::V4(ipv4) => ipv4.ip().is_private(),
        IpNetwork::V6(ipv6) => ipv6.ip().is_unicast_link_local(),
    });
    if !has_valid_ip {
        return Err(ViabilityError::NoValidLanIp);
    }

    Ok(())
}

fn select_best_lan_interface(
    interfaces: Vec<NetworkInterface>,
    is_wired: impl Fn(&NetworkInterface) -> bool,
) -> Option<NetworkInterface> {
    match interfaces.len() {
        0 => None,
        1 => Some(interfaces[0].clone()),
        _ => interfaces
            .iter()
            .find(|&interface| is_wired(interface))
            .cloned()
            .or(Some(interfaces[0].clone())),
    }
}

pub fn is_wired(interface: &NetworkInterface) -> bool {
    is_physical(interface) && !is_wireless(interface)
}
