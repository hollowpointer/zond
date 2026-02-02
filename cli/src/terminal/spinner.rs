// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Terminal UI & Logging
//!
//! This module handles the visual heartbeat of the application.
//!
//! It serves two main purposes:
//! 1.  **Global Logging**: Wires up the `tracing` crate so that `info!`, `warn!`, etc.,
//!     print cleanly to stderr without breaking the progress bar.
//! 2.  **The Spinner**: Manages the background animation that proves the app isn't frozen.
//!     It cycles between showing tips (random usage hints) and status (real-time
//!     feedback like "Scanning 192.168.1.5...").
//!
//! ## How the Spinner Works
//!
//! The spinner runs in a dedicated `tokio` task. It uses a time-based modulo cycle to
//! flip between content:
//!
//! * **0s - 2s**: Show Status (e.g., "Identified 6 hosts so far...")
//! * **2s - 5s**: Show Random Tip (e.g., "Did you know you can use -vv?")
//! * **Repeat**

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use colored::*;
use indicatif::ProgressStyle;
use tracing::Span;
use tracing_indicatif::{IndicatifLayer, span_ext::IndicatifSpanExt};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use zond_common::insights;

use crate::terminal::{colors, logging};

/// Total length of one text cycle (Status + Tip).
const CYCLE_MS: u128 = 5000;
/// How long the "Status" message stays visible at the start of a cycle.
const STATUS_MS: u128 = 2000;

/// Wires up the global tracing subscriber.
///
/// This constructs the "layer stack" for logs:
/// 1.  **Filter**: Decides what to log based on `RUST_LOG` or the `-v` flag.
/// 2.  **Formatter**: Our custom `ZondFormatter` that makes logs look nice.
/// 3.  **Indicatif**: Ensures logs print *above* the spinner line, not over it.
pub fn init_logging(verbosity: u8) {
    let indicatif_layer = IndicatifLayer::new().with_progress_style(
        ProgressStyle::with_template("{spinner:.blue} {msg}")
            .unwrap()
            .tick_strings(&[
                "▁▁▁▁▁",
                "▁▂▂▂▁",
                "▁▄▂▄▁",
                "▂▄▆▄▂",
                "▄▆█▆▄",
                "▂▄▆▄▂",
                "▁▄▂▄▁",
                "▁▂▂▂▁",
            ]),
    );

    let filter_layer = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,zond=debug,mio=error"));

    let formatting_layer = tracing_subscriber::fmt::layer()
        .event_format(logging::ZondFormatter {
            max_verbosity: verbosity,
        })
        .with_writer(indicatif_layer.get_stderr_writer());

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(formatting_layer)
        .with(indicatif_layer)
        .init();
}

/// The actual animation loop running in the background.
async fn run_spinner_loop<F>(span: Span, running: Arc<AtomicBool>, status_fn: Option<F>)
where
    F: Fn() -> ColoredString + Send + Sync + 'static,
{
    // Update at 10hz. Fast enough to feel responsive, slow enough to save CPU.
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    let start_time = tokio::time::Instant::now();
    let mut last_text = String::new();

    let active_insights = insights::get_shuffled_insights();

    while running.load(Ordering::Relaxed) {
        interval.tick().await;

        let elapsed_ms = start_time.elapsed().as_millis();
        let cycle_time = elapsed_ms % CYCLE_MS;

        // Rotate through the tips list based on total elapsed time.
        let tip_index = (elapsed_ms / CYCLE_MS) as usize % active_insights.len();

        // Should we show the dynamic status or the static tip?
        let show_status = status_fn.is_some() && cycle_time < STATUS_MS;

        let colored_msg: ColoredString = if show_status {
            (status_fn.as_ref().unwrap())()
        } else {
            active_insights[tip_index]
                .italic()
                .color(colors::TEXT_DEFAULT)
        };

        let current_text = colored_msg.to_string();

        // Only redraw the terminal if the text actually changed.
        if current_text != last_text {
            span.pb_set_message(&current_text);
            last_text = current_text;
        }
    }
}

/// A RAII guard that keeps the spinner spinning.
///
/// When this struct is dropped (e.g., at the end of a `scan` function),
/// it signals the background task to stop.
pub struct SpinnerGuard {
    running: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

impl SpinnerGuard {
    /// Starts a spinner that alternates between a dynamic status message and tips.
    pub fn with_status<F>(span: tracing::Span, status_fn: F) -> Self
    where
        F: Fn() -> ColoredString + Send + Sync + 'static,
    {
        Self::start(span, Some(status_fn))
    }

    fn start<F>(span: tracing::Span, status_fn: Option<F>) -> Self
    where
        F: Fn() -> ColoredString + Send + Sync + 'static,
    {
        let running = Arc::new(AtomicBool::new(true));
        let run_clone = running.clone();

        // Spawn off the main thread so scanning/processing isn't blocked by UI updates.
        let handle = tokio::spawn(async move {
            run_spinner_loop(span, run_clone, status_fn).await;
        });

        Self { running, handle }
    }
}

impl Drop for SpinnerGuard {
    fn drop(&mut self) {
        // Signal the loop to exit and abort the handle just in case it's stuck sleeping.
        self.running.store(false, Ordering::Relaxed);
        self.handle.abort();
    }
}
