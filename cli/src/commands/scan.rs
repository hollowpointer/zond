// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use zond_common::{config::Config, models::target};

use crate::terminal::print;

pub async fn scan(targets: &[String], _cfg: &Config) -> anyhow::Result<()> {
    let _ips = target::to_collection(targets)?;
    print::Print::header("starting scanner");
    anyhow::bail!("'scan' subcommand not implemented yet");
}
