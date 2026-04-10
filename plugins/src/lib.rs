use regex::Regex;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use zond_common::models::fingerprint::ServiceDefinition;
use zond_common::models::port::{Port, Protocol};

pub struct CompiledMatch {
    pub name: Option<String>,
    pub pattern: Regex,
    pub version_group: Option<u8>,
    pub product: Option<String>,
}

pub struct CompiledService {
    pub def: ServiceDefinition,
    pub matches: Vec<CompiledMatch>,
}

static FINGERPRINTS: OnceLock<Vec<CompiledService>> = OnceLock::new();

pub fn get_fingerprints() -> &'static [CompiledService] {
    FINGERPRINTS.get_or_init(|| {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/fingerprints.bin"));
        let defs: Vec<ServiceDefinition> = bincode::deserialize(bytes)
            .expect("Failed to natively deserialize bincode fingerprints");

        defs.into_iter()
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
            .collect()
    })
}

/// Returns the primary service name associated with a port based on our local definitions.
/// Used for identifying ports even when they are Closed or Ghosted.
pub fn lookup_service_name(port: u16, _proto: Protocol) -> Option<String> {
    get_fingerprints()
        .iter()
        .find(|srv| srv.def.service.default_ports.contains(&port))
        .map(|srv| srv.def.service.name.clone())
}

pub async fn fingerprint_tcp(mut stream: TcpStream, mut port: Port) -> Port {
    let fingerprints = get_fingerprints();

    let mut buffer = [0u8; 4096];
    let mut responses = String::new();

    // Initial Banner Grab
    if let Ok(Ok(n)) = timeout(Duration::from_millis(500), stream.read(&mut buffer)).await
        && n > 0
    {
        responses.push_str(&String::from_utf8_lossy(&buffer[..n]));
    }

    for srv in fingerprints {
        if responses.is_empty()
            && srv.def.service.default_ports.contains(&port.number)
            && let Some(probe) = srv.def.probe.first()
            && probe.protocol == "tcp"
        {
            let _ = stream.write_all(probe.payload.as_bytes()).await;
            if let Ok(Ok(n)) = timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await
                && n > 0
            {
                responses.push_str(&String::from_utf8_lossy(&buffer[..n]));
            }
        }

        if !responses.is_empty() {
            for m in &srv.matches {
                if let Some(caps) = m.pattern.captures(&responses) {
                    let mut info = m
                        .product
                        .clone()
                        .unwrap_or_else(|| srv.def.service.name.clone());

                    if let Some(group_idx) = m.version_group
                        && let Some(ver) = caps.get(group_idx as usize)
                    {
                        info.push_str(&format!(" ({})", ver.as_str()));
                    }

                    port.service_info = Some(info);
                    return port;
                }
            }
        }
    }

    if port.service_info.is_none() && !responses.is_empty() {
        let clean: String = responses
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(32)
            .collect();
        if !clean.is_empty() {
            let mut info = port.service_info.unwrap_or_else(|| "???".to_string());
            if info == "???" || info.is_empty() {
                info = format!("banner: {}", clean);
            } else {
                info = format!("{} ({})", info, clean);
            }
            port.service_info = Some(info);
        }
    }

    port
}
