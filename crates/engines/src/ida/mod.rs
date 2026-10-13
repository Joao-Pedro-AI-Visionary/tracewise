//! IDA (phase 5b): a read-only client of an upstream ida-pro-mcp server.
//!
//! The provider never saves or closes a database the user owns. Attached mode checks that
//! the user's open database is the selected target; headless mode opens a verified private
//! copy as a worker database and releases only that worker (`save: false`).
//!
//! Registration: the JSON file named by `REA_IDA_MCP_CONFIG` (`command`/`args` for stdio, or
//! a local `url`), with `mode` set to `attached` (legacy 1.4 tools) or `headless` (database
//! supervisor tools). Stdio proxies and local plain-http endpoints are connected; an `https`
//! registration validates but cannot connect (no TLS stack), see [`connection`].

pub mod capabilities;
pub mod client;
pub mod config;
pub mod connection;
mod http_client;
pub mod input;
pub mod protocol;
pub mod provider;
pub mod runner;
pub mod search;
pub mod workspace;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_stdio;

pub use client::IdaSessionClient;
pub use config::{IdaConfig, IdaMode, IdaRegistration, IdaTransport};
pub use connection::{IdaConnection, IdaFault, McpConnection};
pub use provider::{ConnectionFactory, IdaProvider};
