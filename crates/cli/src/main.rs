use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracewise_domain::canonical_sha256;

#[derive(Parser)]
#[command(name = "tracewise", version, about = "Rust rewrite of REA Phase 0 (Foundation)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the MCP server over stdio
    Mcp,
    /// Compute and print the RFC 8785 canonical SHA-256 hash of a JSON file
    Hash {
        /// Path to the JSON file to hash
        file: PathBuf,
    },
    /// Print available tool names
    Tools,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Mcp => {
            tracewise_server::run_stdio_server().await?;
        }
        Commands::Hash { file } => {
            let content = std::fs::read_to_string(&file)?;
            let val: serde_json::Value = serde_json::from_str(&content)?;
            let digest = canonical_sha256(&val)?;
            println!("{digest}");
        }
        Commands::Tools => {
            for name in tracewise_contracts::phase0_tool_names() {
                println!("{name}");
            }
        }
    }

    Ok(())
}
