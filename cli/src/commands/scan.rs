// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use zond_common::{config::ZondConfig, models::target};

use crate::terminal::print::Print;

pub async fn scan(targets: &[String], _cfg: &ZondConfig) -> anyhow::Result<()> {
    let _ips = target::to_collection(targets)?;
    Print::header("starting scanner");
    anyhow::bail!("'scan' subcommand not implemented yet");
}
