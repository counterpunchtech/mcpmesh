//! Repo automation for the standalone mcpmesh repo. `publish` is the only subcommand:
//! crates.io publishing in dependency order, resumable (see publish.rs).
mod publish;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "mcpmesh repo automation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish the five mcpmesh crates to crates.io in dependency order (resumable).
    Publish {
        /// Print the plan (skips + would-publish list) without publishing.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Publish { dry_run } => {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .to_path_buf();
            if let Err(e) = publish::publish(&root, dry_run) {
                eprintln!("publish failed: {e:#}");
                std::process::exit(1);
            }
        }
    }
}
