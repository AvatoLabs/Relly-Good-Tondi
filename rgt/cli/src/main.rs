use clap::Parser;
use rgt_runtime::cli::Command;

/// RGT wallet for the Tondi v10 Note ledger.
#[derive(Parser)]
#[command(name = "rgt", version)]
struct Wallet {
    #[command(subcommand)]
    command: Command,
}

fn main() -> anyhow::Result<()> {
    Wallet::parse().command.run()
}
