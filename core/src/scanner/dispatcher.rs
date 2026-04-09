// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use rand::seq::SliceRandom;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

use zond_common::models::target::{Target, TargetMap};

use super::STOP_SIGNAL;

/// A randomized dispatcher that streams targets to consumers.
///
/// Converts a [`TargetMap`] into a batched, pseudo-randomized stream of `Target`s.
/// Allows highly concurrent and evasive port scanning by shuffling chunks of targets
/// without materializing the entire address space in memory.
pub struct Dispatcher {
    target_map: TargetMap,
    batch_size: usize,
}

impl Dispatcher {
    /// Creates a new [`Dispatcher`] from a [`TargetMap`] with a default batch size of 8192.
    pub fn new(target_map: TargetMap) -> Self {
        Self {
            target_map,
            batch_size: 8192,
        }
    }

    /// Customizes the batch size for randomization.
    /// Larger batches provide better randomization but consume more memory locally.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Spawns a background task that feeds shuffled batches of targets continuously.
    ///
    /// Returns an [`mpsc::Receiver`] that yields the targets. The channel is bounded
    /// to 2x the batch size to keep memory usage strictly controlled.
    pub fn run_shuffled(self) -> mpsc::Receiver<Target> {
        let (tx, rx) = mpsc::channel(self.batch_size * 2);

        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(self.batch_size);

            for unit in self.target_map.units {
                for target in unit.iter() {
                    if STOP_SIGNAL.load(Ordering::Relaxed) {
                        return;
                    }

                    batch.push(target);

                    if batch.len() >= self.batch_size {
                        batch.shuffle(&mut rand::rng());
                        for t in batch.drain(..) {
                            if tx.send(t).await.is_err() || STOP_SIGNAL.load(Ordering::Relaxed) {
                                return;
                            }
                        }
                    }
                }
            }

            // Flush any remaining targets
            if !batch.is_empty() {
                batch.shuffle(&mut rand::rng());
                for t in batch {
                    if tx.send(t).await.is_err() || STOP_SIGNAL.load(Ordering::Relaxed) {
                        return;
                    }
                }
            }
        });

        rx
    }
}
