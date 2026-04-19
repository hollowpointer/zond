// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! High-performance timing and lifecycle management for network scanning engines.
//!
//! Provides the `ScanTimer` data structure, a robust, general-purpose component
//! designed to govern the lifecycle of synchronous and asynchronous scanning loops
//! (e.g., port discovery, host discovery).

use std::time::{Duration, Instant};

/// Manages the loop lifecycle and operational boundaries for network scanning operations.
///
/// `ScanTimer` tracks hard deadlines, enforces minimum runtimes, and aborts loops
/// early if a period of network "silence" (time since the last relevant packet)
/// exceeds a configured maximum.
#[derive(Debug, Clone, Copy)]
pub struct ScanTimer {
    // Configuration
    hard_deadline: Instant,
    min_runtime: Instant,
    max_silence: Duration,

    // State
    last_activity: Instant,
}

impl ScanTimer {
    /// Constructs a new `ScanTimer` with the specified operational limits.
    ///
    /// # Arguments
    /// * `max_total_duration` - The absolute maximum time the scan is allowed to run.
    /// * `min_runtime_duration` - The absolute minimum time the scan must run before it can abort due to silence.
    /// * `max_silence` - The maximum duration of network silence allowed after the minimum runtime is reached.
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
            last_activity: now,
        }
    }

    /// Resets the internal "silence" tracker.
    ///
    /// This should be called whenever a relevant packet or activity is observed on the network.
    pub fn mark_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Calculates how long to wait for the next timeout event.
    ///
    /// Returns a fallback duration (e.g., 100ms) if the maximum silence period has already been exceeded.
    pub fn time_until_next_tick(&self) -> Duration {
        let now = Instant::now();
        let time_since_last = now.duration_since(self.last_activity);

        self.max_silence
            .checked_sub(time_since_last)
            .unwrap_or_else(|| Duration::from_millis(100))
    }

    /// Checks if the entire operation should abort due to hard limits or excessive silence.
    ///
    /// Returns `true` if:
    /// 1. The current time has exceeded the `hard_deadline`.
    /// 2. The `min_runtime` has elapsed AND the time since the last recorded activity exceeds `max_silence`.
    pub fn has_expired(&self) -> bool {
        let now = Instant::now();

        if now > self.hard_deadline {
            return true;
        }

        let time_since_last = now.duration_since(self.last_activity);
        if now > self.min_runtime && time_since_last >= self.max_silence {
            return true;
        }

        false
    }

    /// Helper to decide if a socket timeout is fatal or if the scan should continue.
    ///
    /// Returns `true` if the minimum runtime has been met, indicating that a timeout
    /// could be a valid reason to break the loop.
    pub fn should_break_on_timeout(&self) -> bool {
        Instant::now() >= self.min_runtime
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
    use std::thread::sleep;

    #[test]
    fn test_initialization() {
        let timer = ScanTimer::new(
            Duration::from_secs(10),
            Duration::from_secs(5),
            Duration::from_secs(1),
        );
        assert!(!timer.has_expired());
        assert!(!timer.should_break_on_timeout());
    }

    #[test]
    fn test_mark_activity() {
        let mut timer = ScanTimer::new(
            Duration::from_secs(10),
            Duration::from_secs(5),
            Duration::from_millis(50),
        );

        let wait_time1 = timer.time_until_next_tick();
        sleep(Duration::from_millis(10));
        let wait_time2 = timer.time_until_next_tick();

        assert!(wait_time2 < wait_time1);

        timer.mark_activity();
        let wait_time3 = timer.time_until_next_tick();

        // Wait time should reset to near the original max_silence
        assert!(wait_time3 > wait_time2);
    }

    #[test]
    fn test_time_until_next_tick_fallback() {
        let timer = ScanTimer::new(
            Duration::from_secs(10),
            Duration::from_secs(5),
            Duration::from_millis(10),
        );

        sleep(Duration::from_millis(15)); // Exceed max_silence

        // Should return the 100ms fallback since the time since last activity is greater than max_silence
        assert_eq!(timer.time_until_next_tick(), Duration::from_millis(100));
    }

    #[test]
    fn test_hard_deadline_expiration() {
        let timer = ScanTimer::new(
            Duration::from_millis(10), // short hard deadline
            Duration::from_millis(100), // long min runtime (will not be reached)
            Duration::from_secs(1),
        );

        assert!(!timer.has_expired());
        sleep(Duration::from_millis(15));
        assert!(timer.has_expired());
    }

    #[test]
    fn test_silence_expiration() {
        let timer = ScanTimer::new(
            Duration::from_secs(10),
            Duration::from_millis(10), // short min runtime
            Duration::from_millis(10), // short max silence
        );

        assert!(!timer.has_expired());
        sleep(Duration::from_millis(25)); // Exceed both min_runtime and max_silence
        assert!(timer.has_expired());
    }

    #[test]
    fn test_should_break_on_timeout() {
        let timer = ScanTimer::new(
            Duration::from_secs(10),
            Duration::from_millis(10),
            Duration::from_secs(1),
        );

        assert!(!timer.should_break_on_timeout());
        sleep(Duration::from_millis(15));
        assert!(timer.should_break_on_timeout());
    }
}
