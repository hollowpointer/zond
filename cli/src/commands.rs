// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Command Line Interface Definitions
//!
//! This module defines the strict schema for user input.
//!
//! It serves as the single source of truth for the application's command-line interface.
//! While the *execution* logic for each command resides in its own submodule (e.g., `scan/mod.rs`),
//! the *definition* of the arguments, flags, and help text is centralized here.
//!
//! ## Architectural Role
//!
//! This module performs two key architectural functions:
//!
//! 1.  **Input Normalization**: It uses `clap` to validate user inputs, making sure that necessary
//!     arguments are present and types are correct (e.g., strictly typed numbers vs strings)
//!     before the application attempts to run.
//! 2.  **State Translation**: via the `From<&CommandLine> for Config` implementation, it
//!     decouples the external interface (CLI flags) from the internal application state (`Config`).
//!     This allows the core libraries to remain agnostic of the user interface layer.
//!
//! ## Structure
//!
//! The CLI is structured hierarchically:
//!
//! * [`CommandLine`]: The top-level struct containing global flags applicable to the entire process
//!   (logging, formatting, verbosity).
//! * [`Commands`]: An enum representing the specific operation mode. Since these are mutually
//!   exclusive, the type system ensures the application cannot be in two states (e.g., "Scan"
//!   and "Listen") simultaneously.

pub mod discover;
pub mod info;
pub mod listen;
pub mod scan;

use clap::{ArgAction, Parser, Subcommand};
use zond_common::config::Config;

#[derive(Parser)]
#[command(name = "zond")]
#[command(about = "Deep network reconnaissance and probing tool.")]
pub struct CommandLine {
    #[command(subcommand)]
    pub command: Commands,

    /// Keep logs and colors but hide the ASCII art
    #[arg(long = "no-banner", global = true)]
    pub no_banner: bool,

    /// Disables sending of DNS packets
    #[arg(short = 'n', long = "no-dns", global = true)]
    pub no_dns: bool,

    /// Reduce UI visual density (-q: reduce styling, -qq: raw IPs)
    #[arg(short = 'q', long = "quiet", action = ArgAction::Count, global = true)]
    pub quiet: u8,

    /// Redact sensitive info (IPv6 suffixes, MAC addresses etc.)
    #[arg(long = "redact", global = true)]
    pub redact: bool,

    /// Increase logging detail (-v: debug logs, -vv: full packets)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count, global = true)]
    pub verbosity: u8,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Display local network interfaces
    #[command(alias = "i")]
    Info,
    /// Passive discovery via traffic monitoring
    #[command(alias = "l")]
    Listen,

    /// Find live hosts within a specified range
    #[command(alias = "d")]
    Discover {
        #[arg(value_name = "TARGETS", num_args(1..))]
        targets: Vec<String>,
    },

    /// Port scan specific targets
    #[command(alias = "s")]
    Scan {
        #[arg(value_name = "TARGETS", num_args(1..))]
        targets: Vec<String>,
    },
}

impl CommandLine {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

impl From<&CommandLine> for Config {
    fn from(cmd: &CommandLine) -> Self {
        Self {
            no_banner: cmd.no_banner,
            no_dns: cmd.no_dns,
            redact: cmd.redact,
            quiet: cmd.quiet,
            disable_input: false,
        }
    }
}

