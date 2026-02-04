// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use zond_common::config::Config;

use crate::terminal::print;

pub fn listen(_cfg: &Config) -> anyhow::Result<()> {
    print::Print::header("starting listener");
    anyhow::bail!("'listen' subcommand not implemented yet");
}
