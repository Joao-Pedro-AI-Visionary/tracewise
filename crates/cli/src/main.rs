use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::json;
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
    /// Infer an OpenAPI 3.1 document from a HAR or mitmproxy capture
    InferApiSpec {
        /// HAR or mitmproxy capture path
        capture: PathBuf,
        /// Write the OpenAPI document to this path
        #[arg(short, long)]
        output: PathBuf,
        /// Server URL used to filter requests and relativize paths
        #[arg(long)]
        base_url: Option<String>,
        /// OpenAPI info.title
        #[arg(long)]
        title: Option<String>,
    },
    /// Generate typed API clients from an OpenAPI document
    GenerateApiClient {
        /// OpenAPI document path
        spec: PathBuf,
        /// Languages to generate: ts, typescript, py, python (comma-separated)
        #[arg(long, value_delimiter = ',')]
        lang: Vec<String>,
        /// Directory that receives the generated SDKs
        #[arg(short, long)]
        output: PathBuf,
        /// HAR or mitmproxy capture whose redacted exchanges become replay tests
        #[arg(long)]
        replay: Option<PathBuf>,
        /// Python module and npm package name
        #[arg(long)]
        package_name: Option<String>,
    },
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
        Commands::InferApiSpec {
            capture,
            output,
            base_url,
            title,
        } => {
            let capture = std::fs::canonicalize(&capture)?;
            let mut args = json!({
                "capture_path": capture.to_string_lossy(),
                "output_path": output.to_string_lossy(),
            });
            if let Some(base_url) = base_url {
                args["base_url"] = json!(base_url);
            }
            if let Some(title) = title {
                args["title"] = json!(title);
            }
            let session = tracewise_server::session::BinarySession::new();
            tracewise_server::handlers::call_tool_local(
                &session,
                rmcp::model::CallToolRequestParam {
                    name: "infer_api_spec".into(),
                    arguments: Some(args.as_object().expect("arguments object").clone()),
                },
            )
            .await
            .map_err(|err| std::io::Error::other(format!("infer_api_spec failed: {err}")))?;
        }
        Commands::GenerateApiClient {
            spec,
            lang,
            output,
            replay,
            package_name,
        } => {
            let spec = std::fs::canonicalize(&spec)?;
            std::fs::create_dir_all(&output)?;
            let output = std::fs::canonicalize(&output)?;
            let languages: Vec<String> = lang
                .iter()
                .map(|value| match value.as_str() {
                    "ts" | "typescript" => "typescript".to_string(),
                    "py" | "python" => "python".to_string(),
                    other => other.to_string(),
                })
                .collect();
            let mut args = json!({
                "spec_path": spec.to_string_lossy(),
                "languages": languages,
                "output_directory": output.to_string_lossy(),
            });
            if let Some(replay) = replay {
                let replay = std::fs::canonicalize(&replay)?;
                args["replay_capture_path"] = json!(replay.to_string_lossy());
            }
            if let Some(package_name) = package_name {
                args["package_name"] = json!(package_name);
            }
            let session = tracewise_server::session::BinarySession::new();
            tracewise_server::handlers::call_tool_local(
                &session,
                rmcp::model::CallToolRequestParam {
                    name: "generate_api_client".into(),
                    arguments: Some(args.as_object().expect("arguments object").clone()),
                },
            )
            .await
            .map_err(|err| std::io::Error::other(format!("generate_api_client failed: {err}")))?;
        }
    }

    Ok(())
}
