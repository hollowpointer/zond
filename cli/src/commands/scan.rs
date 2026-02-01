use zond_common::{config::Config, models::target};

use crate::terminal::print;

pub async fn scan(targets: &[String], cfg: &Config) -> anyhow::Result<()> {
    let _ips = target::to_collection(targets)?;
    print::header("starting scanner", cfg.quiet);
    anyhow::bail!("'scan' subcommand not implemented yet");
}
