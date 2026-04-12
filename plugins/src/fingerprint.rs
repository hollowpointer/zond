// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Service fingerprinting engine for identification of network services.
//!
//! This module provides the core logic for identifying services based on network banners
//! and active probing. It uses a tiered identification strategy and port-based indexing
//! to ensure high performance even with large signature datasets.

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use zond_common::models::fingerprint::ServiceDefinition;
use zond_common::models::port::{Port, Protocol};

/// A compiled regex match rule for a service.
pub struct CompiledMatch {
    pub name: Option<String>,
    pub pattern: Regex,
    pub version_group: Option<u8>,
    pub product: Option<String>,
}

/// A service definition with its compiled match rules.
pub struct CompiledService {
    pub def: ServiceDefinition,
    pub matches: Vec<CompiledMatch>,
}

/// The result of a successful service identification.
#[derive(Debug, Clone, PartialEq)]
pub struct Identification {
    /// The canonical name of the service (e.g., "ssh").
    pub service_name: String,
    /// The specific product identified (e.g., "OpenSSH").
    pub product: String,
    /// The version string, if captured.
    pub version: Option<String>,
}

/// High-performance engine for matching network responses against service signatures.
pub struct FingerprintEngine {
    services: Vec<CompiledService>,
    by_port: HashMap<u16, Vec<usize>>,
}

static ENGINE: OnceLock<FingerprintEngine> = OnceLock::new();

/// Returns a shared reference to the global fingerprint engine, initializing it if necessary.
pub fn get_engine() -> &'static FingerprintEngine {
    ENGINE.get_or_init(|| {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/fingerprints.bin"));
        let defs: Vec<ServiceDefinition> = bincode::deserialize(bytes)
            .expect("Failed to natively deserialize bincode fingerprints");

        let compiled = defs
            .into_iter()
            .map(|def| {
                let matches = def
                    .r#match
                    .iter()
                    .filter_map(|m| {
                        Regex::new(&m.pattern).ok().map(|re| CompiledMatch {
                            name: m.name.clone(),
                            pattern: re,
                            version_group: m.version_group,
                            product: m.product.clone(),
                        })
                    })
                    .collect();

                CompiledService { def, matches }
            })
            .collect();

        FingerprintEngine::new(compiled)
    })
}

impl FingerprintEngine {
    /// Creates a new engine and builds the port-based index for efficient lookups.
    pub fn new(services: Vec<CompiledService>) -> Self {
        let mut by_port: HashMap<u16, Vec<usize>> = HashMap::new();

        for (idx, srv) in services.iter().enumerate() {
            for &port in &srv.def.service.default_ports {
                by_port.entry(port).or_default().push(idx);
            }
        }

        Self { services, by_port }
    }

    /// Attempts to identify a service from a banner string.
    ///
    /// This uses a two-tier strategy:
    /// 1. Check services typically found on the specified port.
    /// 2. If no match, check all other available signatures (handles non-standard ports).
    pub fn identify_by_banner(&self, port: u16, banner: &str) -> Option<Identification> {
        if banner.is_empty() {
            return None;
        }

        // Tier 1: Targeted matches
        if let Some(indices) = self.by_port.get(&port) {
            for &idx in indices {
                if let Some(id) = self.match_service(&self.services[idx], banner) {
                    return Some(id);
                }
            }
        }

        // Tier 2: Global fallback
        for (idx, srv) in self.services.iter().enumerate() {
            if let Some(indices) = self.by_port.get(&port)
                && indices.contains(&idx)
            {
                continue;
            }

            if let Some(id) = self.match_service(srv, banner) {
                return Some(id);
            }
        }

        None
    }

    /// Returns the list of service definitions that define probes for the given port.
    pub fn get_probes_for_port(&self, port: u16) -> Vec<&ServiceDefinition> {
        if let Some(indices) = self.by_port.get(&port) {
            indices.iter().map(|&idx| &self.services[idx].def).collect()
        } else {
            Vec::new()
        }
    }

    fn match_service(&self, srv: &CompiledService, response: &str) -> Option<Identification> {
        for m in &srv.matches {
            if let Some(caps) = m.pattern.captures(response) {
                let product = m
                    .product
                    .clone()
                    .unwrap_or_else(|| srv.def.service.name.clone());
                let mut version = None;

                if let Some(group_idx) = m.version_group
                    && let Some(ver) = caps.get(group_idx as usize)
                {
                    version = Some(ver.as_str().to_string());
                }

                return Some(Identification {
                    service_name: srv.def.service.name.clone(),
                    product,
                    version,
                });
            }
        }
        None
    }

    /// Formats an identification into a human-readable string.
    pub fn format_identification(id: Identification) -> String {
        if let Some(ver) = id.version {
            format!("{} ({})", id.product, ver)
        } else {
            id.product
        }
    }
}

/// Returns the primary service name associated with a port based on known definitions.
pub fn lookup_service_name(port: u16, _proto: Protocol) -> Option<String> {
    get_engine()
        .get_probes_for_port(port)
        .first()
        .map(|srv| srv.def.service.name.clone())
}

/// High-level entry point for fingerprinting a TCP stream.
pub async fn fingerprint_tcp(mut stream: TcpStream, mut port: Port) -> Port {
    let engine = get_engine();
    let mut buffer = [0u8; 4096];
    let mut responses = String::new();

    // Stage 1: Banner Grab
    if let Ok(Ok(n)) = timeout(Duration::from_millis(500), stream.read(&mut buffer)).await
        && n > 0
    {
        responses.push_str(&String::from_utf8_lossy(&buffer[..n]));
        if let Some(id) = engine.identify_by_banner(port.number(), &responses) {
            let mut srv = Service::new(id.service_name, 100);
            srv = srv.with_product(id.product);
            if let Some(ver) = id.version {
                srv = srv.with_version(ver);
            }
            port.set_service(srv);
            return port;
        }
    }

    // Stage 2: Active Probing
    for def in engine.get_probes_for_port(port.number()) {
        for probe in &def.probe {
            if probe.protocol != "tcp" {
                continue;
            }

            let _ = stream.write_all(probe.payload.as_bytes()).await;
            if let Ok(Ok(n)) = timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await
                && n > 0
            {
                let chunk = String::from_utf8_lossy(&buffer[..n]);
                responses.push_str(&chunk);

                for m in &def.r#match {
                    if let Ok(re) = Regex::new(&m.pattern)
                        && let Some(caps) = re.captures(&responses)
                    {
                        let mut srv = Service::new(def.service.name.clone(), 100);
                        if let Some(prod) = m.product.clone() {
                            srv = srv.with_product(prod);
                        } else {
                            srv = srv.with_product(def.service.name.clone());
                        }

                        if let Some(group_idx) = m.version_group
                            && let Some(ver) = caps.get(group_idx as usize)
                        {
                            srv = srv.with_version(ver.as_str());
                        }

                        port.set_service(srv);
                        return port;
                    }
                }
            }
        }
    }

    // Stage 3: Banner Fallback
    if port.service().is_none() && !responses.is_empty() {
        let clean: String = responses
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(32)
            .collect();
        if !clean.is_empty() {
            port.set_service(Service::new(format!("banner: {}", clean), 0));
        }
    }

    port
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
    use zond_common::models::fingerprint::{MatchRule, ServiceSignature};

    fn mock_service(
        name: &str,
        ports: Vec<u16>,
        patterns: Vec<(&str, Option<u8>)>,
    ) -> CompiledService {
        let def = ServiceDefinition {
            service: ServiceSignature {
                name: name.to_string(),
                default_ports: ports,
                description: None,
            },
            probe: Vec::new(),
            r#match: patterns
                .into_iter()
                .map(|(p, v)| MatchRule {
                    name: None,
                    pattern: p.to_string(),
                    version_group: v,
                    vendor: None,
                    product: None,
                })
                .collect(),
        };

        let matches = def
            .r#match
            .iter()
            .map(|m| CompiledMatch {
                name: None,
                pattern: Regex::new(&m.pattern).unwrap(),
                version_group: m.version_group,
                product: None,
            })
            .collect();

        CompiledService { def, matches }
    }

    #[test]
    fn engine_indexing() {
        let services = vec![
            mock_service("http", vec![80, 8080], vec![("HTTP", None)]),
            mock_service("ssh", vec![22], vec![("SSH", None)]),
        ];
        let engine = FingerprintEngine::new(services);

        assert_eq!(engine.by_port.get(&80).unwrap().len(), 1);
        assert_eq!(engine.by_port.get(&22).unwrap().len(), 1);
        assert!(engine.by_port.get(&443).is_none());
    }

    #[test]
    fn identity_by_banner_tiered() {
        let services = vec![
            mock_service("http", vec![80], vec![("^HTTP/1.1", None)]),
            mock_service(
                "ssh",
                vec![22],
                vec![("^SSH-2.0-OpenSSH_([\\d.]+)", Some(1))],
            ),
        ];
        let engine = FingerprintEngine::new(services);

        // Tier 1: Correct port
        let id = engine
            .identify_by_banner(22, "SSH-2.0-OpenSSH_9.0")
            .unwrap();
        assert_eq!(id.service_name, "ssh");
        assert_eq!(id.version, Some("9.0".to_string()));

        // Tier 2: Random port
        let id = engine
            .identify_by_banner(4444, "SSH-2.0-OpenSSH_9.0")
            .unwrap();
        assert_eq!(id.service_name, "ssh");
    }

    #[test]
    fn match_priority() {
        let services = vec![
            mock_service("service1", vec![80], vec![("match1", None)]),
            mock_service("service2", vec![80], vec![("match2", None)]),
        ];
        let engine = FingerprintEngine::new(services);

        let id = engine.identify_by_banner(80, "match2").unwrap();
        assert_eq!(id.service_name, "service2");
    }

    #[test]
    fn format_identification() {
        let id = Identification {
            service_name: "ssh".into(),
            product: "OpenSSH".into(),
            version: Some("9.0".into()),
        };
        assert_eq!(
            FingerprintEngine::format_identification(id),
            "OpenSSH (9.0)"
        );

        let id_no_ver = Identification {
            service_name: "ssh".into(),
            product: "ssh".into(),
            version: None,
        };
        assert_eq!(FingerprintEngine::format_identification(id_no_ver), "ssh");
    }
}
