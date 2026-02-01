use crate::terminal::colors;
use colored::*;
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv6Addr};
use zond_common::config::Config;
use zond_common::models::host::Host;
use zond_common::utils::{ip, redact};

// Logic moved from network/ip.rs
pub fn ipv6_to_type_str(ipv6_addr: &Ipv6Addr) -> &'static str {
    if is_global_unicast(&IpAddr::V6(*ipv6_addr)) {
        return "GUA";
    }
    if ipv6_addr.is_unique_local() {
        return "ULA";
    }
    if ipv6_addr.is_unicast_link_local() {
        return "LLA";
    }
    "IPv6"
}

pub fn ip_to_detail(host: &Host, cfg: &Config) -> Vec<(String, ColoredString)> {
    host.ips
        .iter()
        .filter(|&&ip| ip != host.primary_ip)
        .map(|ip| match ip {
            IpAddr::V4(ipv4_addr) => {
                let value = ipv4_addr.to_string().color(colors::IPV4_ADDR);
                (String::from("IPv4"), value)
            }
            IpAddr::V6(ipv6_addr) => {
                let ipv6_type: &str = ipv6_to_type_str(ipv6_addr);
                let ipv6_addr: ColoredString = if cfg.redact {
                    let ip_str: String = match ip::get_ipv6_type(ipv6_addr) {
                        ip::Ipv6AddressType::GlobalUnicast => redact::global_unicast(ipv6_addr),
                        ip::Ipv6AddressType::UniqueLocal => redact::unique_local(ipv6_addr),
                        ip::Ipv6AddressType::LinkLocal => redact::link_local(ipv6_addr),
                        _ => ipv6_addr.to_string(),
                    };
                    ip_str.color(colors::IPV6_ADDR)
                } else {
                    ipv6_addr.to_string().color(colors::IPV6_ADDR)
                };
                (String::from(ipv6_type), ipv6_addr)
            }
        })
        .collect()
}

fn is_global_unicast(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        IpAddr::V6(ipv6_addr) => {
            let first_byte = ipv6_addr.octets()[0];
            (0x20..=0x3F).contains(&first_byte)
        }
        _ => false,
    }
}

pub fn hostname_to_detail(
    hostname_opt: &Option<String>,
    cfg: &Config,
) -> Option<(String, ColoredString)> {
    let mut result: Option<(String, ColoredString)> = None;

    if let Some(hostname) = hostname_opt {
        let hostname_str: String = if cfg.redact {
            redact::hostname(hostname)
        } else {
            hostname.to_string()
        };
        result = Some((
            String::from("Hostname"),
            hostname_str.color(colors::HOSTNAME),
        ))
    }

    result
}

pub fn mac_to_detail(mac_opt: &Option<MacAddr>, cfg: &Config) -> Option<(String, ColoredString)> {
    let mut result: Option<(String, ColoredString)> = None;

    if let Some(mac) = mac_opt {
        let mac_str: String = if cfg.redact {
            redact::mac_addr(mac)
        } else {
            mac.to_string()
        };
        result = Some(("MAC".to_string(), mac_str.color(colors::MAC_ADDR)))
    }

    result
}

pub fn vendor_to_detail(vendor_opt: &Option<String>) -> Option<(String, ColoredString)> {
    vendor_opt.as_ref().map(|vendor| {
        (
            "Vendor".to_string(),
            vendor.to_string().color(colors::MAC_ADDR),
        )
    })
}
