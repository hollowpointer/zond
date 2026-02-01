use zond_common::config::Config;

use crate::terminal::print;

pub fn listen(cfg: &Config) -> anyhow::Result<()> {
    print::header("starting listener", cfg.quiet);
    anyhow::bail!("'listen' subcommand not implemented yet");
}
