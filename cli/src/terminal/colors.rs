// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use colored::Color;

// General Purpose
pub const TEXT_DEFAULT: Color = Color::TrueColor {
    r: 212,
    g: 212,
    b: 212,
}; // Very Light Gray

pub const SEPARATOR: Color = Color::BrightBlack;

pub const PRIMARY: Color = Color::TrueColor {
    r: 255,
    g: 204,
    b: 102,
}; // Soft Gold/Amber

pub const SECONDARY: Color = Color::TrueColor {
    r: 102,
    g: 204,
    b: 255,
}; // Soft Sky Blue

pub const ACCENT: Color = Color::TrueColor {
    r: 170,
    g: 170,
    b: 0,
};

// Networking: IPv4 (Cooler Yellow Tones)
pub const IPV4_ADDR: Color = Color::TrueColor {
    r: 170,
    g: 255,
    b: 170,
}; // Pale Lime Green

pub const IPV4_PREFIX: Color = Color::TrueColor {
    r: 190,
    g: 255,
    b: 190,
}; // Lighter Pale Lime Green

// Networking: Identifiers
pub const HOSTNAME: Color = Color::TrueColor {
    r: 102,
    g: 255,
    b: 204,
}; // Bright Mint/Teal

// Networking: IPv6 (Warm Pink Tones)
pub const IPV6_ADDR: Color = Color::TrueColor {
    r: 255,
    g: 102,
    b: 178,
}; // Soft Raspberry Pink

pub const IPV6_PREFIX: Color = Color::TrueColor {
    r: 255,
    g: 178,
    b: 217,
}; // Pale Raspberry Pink

// Networking: Distinct
pub const MAC_ADDR: Color = Color::TrueColor {
    r: 255,
    g: 165,
    b: 0,
}; // Soft Orange
