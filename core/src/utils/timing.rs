// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::time::{Duration, Instant};

/// Manages the loop lifecycle for network scanning operations.
/// It tracks hard deadlines and "silence" periods (time since last packet).
pub struct ScanTimer {
    // Configuration
    hard_deadline: Instant,
    min_runtime: Instant,
    max_silence: Duration,

    // State
    last_seen: Instant,
}

impl ScanTimer {
    pub fn new(
        max_total_duration: Duration,
        min_runtime_duration: Duration,
        max_silence: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            hard_deadline: now + max_total_duration,
            min_runtime: now + min_runtime_duration,
            max_silence,
            last_seen: now,
        }
    }

    /// Resets the "silence" timer because we received a relevant packet.
    pub fn mark_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Calculates how long to wait for the next event.
    /// Returns a fallback (e.g., 100ms) if the calculation is negative.
    pub fn next_wait(&self) -> Duration {
        let now = Instant::now();
        let time_since_last = now.duration_since(self.last_seen);

        self.max_silence
            .checked_sub(time_since_last)
            .unwrap_or(Duration::from_millis(100))
    }

    /// Checks if the entire operation should abort due to hard limits.
    pub fn is_expired(&self) -> bool {
        let now = Instant::now();

        if now > self.hard_deadline {
            return true;
        }

        let time_since_last = now.duration_since(self.last_seen);
        if now > self.min_runtime && time_since_last >= self.max_silence {
            return true;
        }

        false
    }

    /// Helper to decide if a socket timeout is fatal or if we should continue.
    /// Returns `true` if we should break the loop.
    pub fn should_break_on_timeout(&self) -> bool {
        Instant::now() >= self.min_runtime
    }
}
