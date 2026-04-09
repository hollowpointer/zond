// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use rand::seq::SliceRandom;
use rand::{Rng, rng};

/// Internal scanner-specific operational guidance.
const SCANNER_TIPS: &[&str] = &[
    "Press 'q' to stop and print results",
    "Running with root enables faster raw socket scanning",
    "Ranges (e.g. 5-11ms) show min/max RTT latency",
    "Timings with ~ are averages of consistent RTT results",
    "High RTT (500ms+) on local scans suggests mobile/IoT",
    "The '--redact' flag is your friend for output sharing",
];

/// Technical facts and networking trivia.
const TECH_TRIVIA: &[&str] = &[
    "The first 'bug' was a literal moth in a Harvard Mark II",
    "1.1.1.1 is actually owned by APNIC, not Cloudflare",
    "Ping is named after the sound of a submarine's sonar",
    "RFC 1149: Standard for Avian IP (actual pigeons)",
];

/// Industry jokes and developer humor.
const DEV_HUMOR: &[&str] = &[
    "UDP: I'd tell you a joke, but you might not get it",
    "TCP: I'll tell you a joke. Do you want to hear a joke?",
    "The scan works on my machine though",
    "The 'S' in IoT stands for Security",
    "Hardware is the part you kick when the software fails",
];

/// Generates a randomized list of UI messages.
///
/// Every slot in the resulting list has a 50% probability of being an
/// operational tip and a 50% probability of being flavor text (trivia/humor),
/// provided both pools still have remaining items.
pub fn get_shuffled_insights() -> Vec<&'static str> {
    let mut rng = rng();

    let mut tips = SCANNER_TIPS.to_vec();
    tips.shuffle(&mut rng);

    let mut flavor: Vec<&str> = TECH_TRIVIA
        .iter()
        .chain(DEV_HUMOR.iter())
        .copied()
        .collect();
    flavor.shuffle(&mut rng);

    let total_len = tips.len() + flavor.len();
    let mut output = Vec::with_capacity(total_len);

    while !tips.is_empty() && !flavor.is_empty() {
        let pick_tip = rng.random_bool(0.5);
        if pick_tip {
            output.push(tips.remove(0));
        } else {
            output.push(flavor.remove(0));
        }
    }

    output.extend(tips);
    output.extend(flavor);
    output
}
