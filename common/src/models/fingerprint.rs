// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSignature {
    pub name: String,
    pub default_ports: Vec<u16>,
    pub description: Option<String>,
    pub attribution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub name: Option<String>,
    pub payload: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub service: ServiceSignature,
    #[serde(default)]
    pub probe: Vec<Probe>,
    #[serde(default)]
    pub r#match: Vec<MatchRule>,
}
