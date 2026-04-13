// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # OS Fingerprinting Models
//!
//! This module provides the [`OsFingerprint`] entity, which aggregates findings 
//! from multiple OS identification techniques (e.g., TCP/IP stack analysis, 
//! service banner grabbing, or SNMP queries).

use std::{collections::BTreeSet, sync::Arc};

/// The absolute maximum number of CPEs we will store for a single OS fingerprint.
/// This acts as a security boundary to prevent memory exhaustion from malicious 
/// targets or runaway scanning scripts.
pub const MAX_CPES_PER_OS: usize = 50;

/// A high-fidelity record of a host's identified operating system.
///
/// `OsFingerprint` uses an accuracy-based merging strategy: higher accuracy 
/// findings overwrite lower accuracy ones, while findings with identical 
/// accuracy are combined to fill missing fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OsFingerprint {
    /// The primary OS name (e.g., "Linux", "Windows").
    ///
    /// This field should ideally be provided by a string interner to maximize 
    /// memory deduplication across broad scan results.
    pub name: Arc<str>,

    /// The broad OS family (e.g., "Unix-like", "Windows NT").
    pub family: Option<Arc<str>>,

    /// The version or generation (e.g., "5.15.0", "11").
    pub generation: Option<Arc<str>>,

    /// The specific vendor (e.g., "Canonical", "Microsoft").
    pub vendor: Option<Arc<str>>,

    /// The confidence score of this identification as a percentage (0-100).
    pub accuracy: u8,

    /// A bounded set of Common Platform Enumeration (CPE) identifiers.
    cpe: BTreeSet<Arc<str>>,
}

impl OsFingerprint {
    /// Creates a new `OsFingerprint` with a name and a confidence score.
    ///
    /// Accuracy is strictly clamped to the range `[0, 100]`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use zond_core::models::host::OsFingerprint;
    /// let os = OsFingerprint::new("Ubuntu Linux", 95);
    /// assert_eq!(os.accuracy, 95);
    /// ```
    pub fn new(name: impl Into<Arc<str>>, accuracy: u8) -> Self {
        Self {
            name: name.into(),
            family: None,
            generation: None,
            vendor: None,
            accuracy: accuracy.min(100),
            cpe: BTreeSet::new(),
        }
    }

    /// Adds a CPE identifier to the fingerprint, provided the internal limit
    /// ([`MAX_CPES_PER_OS`]) has not been reached.
    pub fn add_cpe(&mut self, cpe: impl Into<Arc<str>>) {
        if self.cpe.len() < MAX_CPES_PER_OS {
            self.cpe.insert(cpe.into());
        }
    }

    /// Returns a read-only view of all identified CPEs for this host.
    pub fn cpes(&self) -> &BTreeSet<Arc<str>> {
        &self.cpe
    }

    /// Returns `true` if the identification has high certainty (>= 85%).
    ///
    /// This threshold is often used by scanning engines to decide whether 
    /// to terminate OS discovery or continue with more intrusive probes.
    pub fn is_highly_confident(&self) -> bool {
        self.accuracy >= 85
    }

    /// Merges architectural findings from another OS record.
    ///
    /// - If `other` has **higher accuracy**, it replaces the current record.
    /// - If `other` has **equal accuracy**, missing fields are populated and CPEs are unioned.
    /// - If `other` has **lower accuracy**, it is ignored.
    pub fn merge(&mut self, other: OsFingerprint) {
        if other.accuracy > self.accuracy {
            *self = other;
        } else if other.accuracy == self.accuracy {
            // Fill gaps if they exist in the current record
            if self.family.is_none() {
                self.family = other.family;
            }
            if self.generation.is_none() {
                self.generation = other.generation;
            }
            if self.vendor.is_none() {
                self.vendor = other.vendor;
            }

            // Union CPEs up to the cap
            for cpe in other.cpe {
                if self.cpe.len() >= MAX_CPES_PER_OS {
                    break;
                }
                self.cpe.insert(cpe);
            }
        }
    }
}

impl std::fmt::Display for OsFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(ref generation) = self.generation {
            write!(f, " {}", generation)?;
        }
        write!(f, " [{}%]", self.accuracy)
    }
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

    #[test]
    fn os_accuracy_clamping() {
        let os = OsFingerprint::new("Linux", 200);
        assert_eq!(os.accuracy, 100);
    }

    #[test]
    fn test_is_highly_confident() {
        assert!(OsFingerprint::new("Linux", 85).is_highly_confident());
        assert!(!OsFingerprint::new("Linux", 84).is_highly_confident());
    }

    #[test]
    fn os_merge_accuracy_priority() {
        let mut os1 = OsFingerprint::new("Linux", 50);
        let os2 = OsFingerprint::new("Ubuntu", 90);
        os1.merge(os2);
        assert_eq!(&*os1.name, "Ubuntu");
    }

    #[test]
    fn os_merge_equal_accuracy_collision() {
        // Test deterministic "first-wins" for conflicting metadata at equal accuracy
        let mut os1 = OsFingerprint::new("Linux", 80);
        os1.family = Some(Arc::from("Old Family"));

        let mut os2 = OsFingerprint::new("Linux", 80);
        os2.family = Some(Arc::from("New Family"));
        os2.generation = Some(Arc::from("New Gen"));

        os1.merge(os2);

        // Should keep "Old Family" (first) but adopt "New Gen" (gap filled)
        assert_eq!(os1.family.as_deref(), Some("Old Family"));
        assert_eq!(os1.generation.as_deref(), Some("New Gen"));
    }

    #[test]
    fn cpe_cap_enforcement() {
        let mut os = OsFingerprint::new("Windows", 100);
        for i in 0..100 {
            os.add_cpe(format!("cpe:/o:ident:{}", i));
        }
        assert_eq!(os.cpes().len(), MAX_CPES_PER_OS);
    }
}
