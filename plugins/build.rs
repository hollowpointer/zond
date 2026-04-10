// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceSignature {
    pub name: String,
    pub default_ports: Vec<u16>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Probe {
    pub name: Option<String>,
    pub payload: String,
    pub protocol: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MatchRule {
    pub name: Option<String>,
    pub pattern: String,
    pub version_group: Option<u8>,
    pub vendor: Option<String>,
    pub product: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub service: ServiceSignature,
    #[serde(default)]
    pub probe: Vec<Probe>,
    #[serde(default)]
    pub r#match: Vec<MatchRule>,
}

fn main() {
    println!("cargo:rerun-if-changed=../assets/fingerprinting");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("fingerprints.bin");

    let fingerprint_dir = Path::new("../assets/fingerprinting");
    let mut services = Vec::new();

    if fingerprint_dir.exists() {
        for entry in fs::read_dir(fingerprint_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                let content = fs::read_to_string(&path).unwrap();
                let def: ServiceDefinition = toml::from_str(&content)
                    .unwrap_or_else(|_| panic!("Failed to parse {:?}", path));
                services.push(def);
            }
        }
    }

    let encoded = bincode::serialize(&services).unwrap();
    fs::write(&dest_path, encoded).unwrap();
}
