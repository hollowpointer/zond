// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! This module is currently a wrapper for the 'tracing' crate.
//! The goal is to provide an abstraction so that other modules
//! do not depend on tracing directrly, making it easy to swap 
//! our way of logging more easily in the future if needed.

#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => {
        tracing::info!(status = "info", $($arg)+)
    };
}

#[macro_export]
macro_rules! success {
    ($($arg:tt)+) => {
        tracing::info!(status = "success", $($arg)+)
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => {
        tracing::debug!(status = "debug", $($arg)+)
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => {
        tracing::error!(status = "error", $($arg)+)
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {
        tracing::warn!(status = "warn", $($arg)+)
    };
}