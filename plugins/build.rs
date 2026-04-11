// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceSignature {
    pub name: String,
    pub default_ports: Vec<u16>,
    pub description: Option<String>,
    pub attribution: Option<String>,
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
    pub context: Option<String>,
    pub example: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
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

    fn collect_toml_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_toml_files(&path, files);
                } else if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                    files.push(path);
                }
            }
        }
    }

    let mut toml_files = Vec::new();
    collect_toml_files(fingerprint_dir, &mut toml_files);

    for path in toml_files {
        let content = fs::read_to_string(&path).unwrap();
        let def: ServiceDefinition = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse {:?}: {}", path, e));
        services.push(def);
    }

    let encoded = bincode::serialize(&services).unwrap();
    fs::write(&dest_path, encoded).unwrap();
}
