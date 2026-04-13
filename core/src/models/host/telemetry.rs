// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Network Telemetry
//!
//! This module provides the [`HostTelemetry`] model for tracking network 
//! performance metrics and path discovery data over time.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// Performance and discovery metrics for a specific network host.
///
/// `HostTelemetry` maintains a sliding window of Round-Trip Time (RTT) 
/// measurements and performs statistical analysis (Averaging and Jitter) 
/// used for network health assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTelemetry {
    /// The recent round-trip time measurements with confirmation timestamps.
    /// Ordered chronologically: oldest at the front, newest at the back.
    rtt_history: VecDeque<(Instant, Duration)>,

    /// The maximum number of RTT samples to maintain. 
    /// If this limit is reached, adding a new sample will purge the oldest one.
    pub max_samples: usize,

    /// The Time-to-Live (TTL) value from the most recently received response.
    pub ttl: Option<u8>,

    /// The calculated network distance in hops, derived from TTL or traceroute probes.
    pub distance_hops: Option<u8>,
}

impl HostTelemetry {
    /// Creates a new `HostTelemetry` instance with a specific sample window size.
    pub fn new(max_samples: usize) -> Self {
        Self {
            rtt_history: VecDeque::with_capacity(max_samples),
            max_samples,
            ttl: None,
            distance_hops: None,
        }
    }

    /// Returns a read-only view of the RTT sample history.
    pub fn history(&self) -> &VecDeque<(Instant, Duration)> {
        &self.rtt_history
    }

    /// Adds a new RTT measurement at the current system time.
    pub fn add_rtt(&mut self, rtt: Duration) {
        self.add_rtt_at(Instant::now(), rtt);
    }

    /// Adds a timed RTT measurement to the history, enforcing the sliding window cap.
    pub fn add_rtt_at(&mut self, time: Instant, rtt: Duration) {
        if self.max_samples == 0 {
            return;
        }

        self.rtt_history.push_back((time, rtt));

        while self.rtt_history.len() > self.max_samples {
            self.rtt_history.pop_front();
        }
    }

    /// Returns the Last-Added Round-Trip Time (LARTT).
    pub fn lartt(&self) -> Option<Duration> {
        self.rtt_history.back().map(|&(_, rtt)| rtt)
    }

    /// Returns the minimum (fastest) RTT recorded in the current window.
    pub fn min_rtt(&self) -> Option<Duration> {
        self.rtt_history.iter().map(|(_, rtt)| *rtt).min()
    }

    /// Returns the maximum (slowest) RTT recorded in the current window.
    pub fn max_rtt(&self) -> Option<Duration> {
        self.rtt_history.iter().map(|(_, rtt)| *rtt).max()
    }

    /// Calculates the arithmetic mean RTT from all samples in the window.
    pub fn average_rtt(&self) -> Option<Duration> {
        if self.rtt_history.is_empty() {
            return None;
        }
        let sum: Duration = self.rtt_history.iter().map(|(_, rtt)| *rtt).sum();
        Some(sum / self.rtt_history.len() as u32)
    }

    /// Calculates the network jitter as the **Average Absolute Difference** 
    /// between consecutive RTT samples.
    ///
    /// Jitter provides a measure of network stability. A high jitter relative 
    /// to the average RTT often indicates network congestion or bufferbloat.
    pub fn jitter(&self) -> Option<Duration> {
        if self.rtt_history.len() < 2 {
            return None;
        }

        let mut total_diff = Duration::ZERO;
        let mut prev = self.rtt_history[0].1;

        for &(_, curr) in self.rtt_history.iter().skip(1) {
            total_diff += if curr > prev {
                curr - prev
            } else {
                prev - curr
            };
            prev = curr;
        }

        Some(total_diff / (self.rtt_history.len() - 1) as u32)
    }

    /// Merges telemetry from another record, Ensuring chronological sortedness 
    /// and prioritizing the newest data points.
    ///
    /// If the incoming record has a larger `max_samples` configuration, this 
    /// telemetry container will upgrade its own window size to match.
    pub fn merge(&mut self, mut other: HostTelemetry) {
        if other.max_samples > self.max_samples {
            self.max_samples = other.max_samples;
        }

        if self.max_samples == 0 {
            return;
        }

        // Interleave and re-sort samples to maintain network timeline
        let mut combined: Vec<_> = self
            .rtt_history
            .drain(..)
            .chain(other.rtt_history.drain(..))
            .collect();

        combined.sort_by_key(|&(time, _)| time);

        let start_idx = combined.len().saturating_sub(self.max_samples);
        self.rtt_history
            .extend(combined.into_iter().skip(start_idx));

        if self.ttl.is_none() {
            self.ttl = other.ttl;
        }
        if self.distance_hops.is_none() {
            self.distance_hops = other.distance_hops;
        }
    }
}

impl std::fmt::Display for HostTelemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.average_rtt() {
            Some(avg) => write!(
                f,
                "avg={:?}, jitter={:?}",
                avg,
                self.jitter().unwrap_or(Duration::ZERO)
            ),
            None => write!(f, "no telemetry"),
        }
    }
}

impl Default for HostTelemetry {
    fn default() -> Self {
        Self::new(10)
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
    fn telemetry_math_safety() {
        let t = HostTelemetry::new(10);
        assert_eq!(t.average_rtt(), None);
        assert_eq!(t.jitter(), None);
        assert_eq!(t.lartt(), None);
    }

    #[test]
    fn telemetry_averaging_logic() {
        let mut t = HostTelemetry::new(5);
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(20));
        assert_eq!(t.average_rtt(), Some(Duration::from_millis(15)));
    }

    #[test]
    fn jitter_calculation_consistency() {
        let mut t = HostTelemetry::new(5);
        t.add_rtt(Duration::from_millis(100)); // prev
        t.add_rtt(Duration::from_millis(110)); // diff 10
        t.add_rtt(Duration::from_millis(105)); // diff 5
        // (10 + 5) / 2 = 7.5ms
        assert_eq!(t.jitter(), Some(Duration::from_millis(7) + Duration::from_micros(500)));
    }

    #[test]
    fn merge_capacity_upgrade() {
        let mut t1 = HostTelemetry::new(3);
        let t2 = HostTelemetry::new(10);
        t1.merge(t2);
        assert_eq!(t1.max_samples, 10);
    }

    #[test]
    fn merge_zero_capacity_safety() {
        let mut t1 = HostTelemetry::new(0);
        let t2 = HostTelemetry::new(0);
        t1.merge(t2);
        assert_eq!(t1.rtt_history.len(), 0);
    }
}
