// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Zond CLI Entry Point
//!
//! The binary entry point for Zond.
//!
//! This module is responsible for bootstrapping the application runtime and managing the
//! global lifecycle of the process. It isolates the command-line interface layer from the
//! core library logic.
//!
//! ## Responsibilities
//!
//! 1.  **Runtime Initialization**: The `#[tokio::main]` attribute initializes the asynchronous
//!     runtime, setting up the thread pool and I/O drivers required for non-blocking operations.
//! 2.  **Global State Setup**: Initializes the `tracing` subscriber for logging and configures
//!     terminal output modes (verbosity, quiet mode, banners).
//! 3.  **Configuration Mapping**: Converts raw command-line arguments (parsed via `clap`) into
//!     the internal `Config` struct used by the core libraries.
//! 4.  **Command Dispatch**: Routes execution to the appropriate module in `commands/`.
//! 5.  **Error Boundary**: Acts as the top-level error handler. Any errors propagated up from
//!     subcommands are caught here, logged to the error stream, and converted into a
//!     non-zero `ExitCode`.

mod commands;
mod terminal;

use std::process::ExitCode;

use zond_common::{config::Config, error};

use crate::{
    commands::{CommandLine, Commands, discover, info, listen, scan},
    terminal::{print::Print, spinner},
};

#[tokio::main]
async fn main() -> ExitCode {
    let commands = CommandLine::parse_args();
    spinner::init_logging(commands.verbosity);

    let cfg = Config::from(&commands);

    let _ = Print::init(&cfg);
    Print::banner();

    let result = match &commands.command {
        Commands::Info => info::info(&cfg),
        Commands::Listen => listen::listen(&cfg),
        Commands::Discover { targets } => discover::discover(targets, &cfg).await,
        Commands::Scan { targets } => scan::scan(targets, &cfg).await,
    };

    let exit_code = match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            error!("Critical failure: {e}");
            ExitCode::FAILURE
        }
    };

    Print::end_of_program();

    exit_code
}
