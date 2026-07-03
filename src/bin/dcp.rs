#![allow(warnings)]
//! DCP CLI tool.
//!
//! Provides commands for running DCP server and converting MCP schemas.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "dcp")]
#[command(author, version, about = "Development Context Protocol CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run in stdio mode (stdin/stdout for MCP compatibility)
    #[arg(long, global = true)]
    stdio: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the DCP server
    Serve {
        /// Host address to bind to
        #[arg(short = 'H', long, default_value = "127.0.0.1")]
        host: String,

        /// Port to listen on
        #[arg(short, long, default_value = "3000")]
        port: u16,

        /// Enable MCP compatibility mode
        #[arg(long, default_value = "true")]
        mcp_compat: bool,

        /// Maximum concurrent sessions
        #[arg(long, default_value = "1000")]
        max_sessions: usize,

        /// Enable metrics collection
        #[arg(long, default_value = "true")]
        metrics: bool,

        /// Run in stdio mode instead of TCP
        #[arg(long)]
        stdio: bool,
    },

    /// Convert MCP schema to DCP format
    Convert {
        /// Input MCP schema file (JSON)
        #[arg(short, long)]
        input: PathBuf,

        /// Output DCP schema file (binary)
        #[arg(short, long)]
        output: PathBuf,

        /// Validate output schema
        #[arg(long, default_value = "true")]
        validate: bool,
    },

    /// Show server information
    Info,

    /// Validate a DCP schema file
    Validate {
        /// Schema file to validate
        #[arg(short, long)]
        schema: PathBuf,
    },
}

fn main() {
    let cfg = dx_dcp::dx_config::DcpDxConfig::load();
    let _ = std::fs::create_dir_all(&cfg.sr_dir);
    let _ = std::fs::create_dir_all(&cfg.receipts_dir);
    let _ = cfg.write_sr("dcp", &[("tool", "dcp"), ("action", "run"), ("status", "ok")]);
    if let Some(status) = cfg.read_status("dcp") {
        eprintln!("[dcp] sr cache verified: {} entries", status.len());
    }

    let cli = Cli::parse();

    // Handle global --stdio flag (shortcut for `dcp serve --stdio`)
    if cli.stdio {
        run_stdio_mode();
        return;
    }

    match cli.command {
        Some(Commands::Serve {
            host,
            port,
            mcp_compat,
            max_sessions,
            metrics,
            stdio,
        }) => {
            if stdio {
                run_stdio_mode();
            } else {
                println!("Starting DCP server...");
                println!("  Host: {}", host);
                println!("  Port: {}", port);
                println!("  MCP Compatibility: {}", mcp_compat);
                println!("  Max Sessions: {}", max_sessions);
                println!("  Metrics: {}", metrics);
                println!();
                println!("Server would start here (async runtime required)");
                println!("For now, use the library directly in your application.");
            }
        }

        Some(Commands::Convert {
            input,
            output,
            validate,
        }) => {
            println!("Converting MCP schema to DCP format...");
            println!("  Input: {}", input.display());
            println!("  Output: {}", output.display());
            println!("  Validate: {}", validate);

            match convert_schema(&input, &output, validate) {
                Ok(()) => println!("Conversion successful!"),
                Err(e) => {
                    eprintln!("Conversion failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Some(Commands::Info) => {
            println!("DCP - Development Context Protocol");
            println!("Version: {}", env!("CARGO_PKG_VERSION"));
            println!();
            println!("Protocol Features:");
            println!("  - Binary message envelope (8 bytes)");
            println!("  - O(1) tool dispatch via binary trie");
            println!("  - Zero-copy argument passing");
            println!("  - Ed25519 signed tool definitions");
            println!("  - XOR delta state synchronization");
            println!("  - MCP JSON-RPC compatibility layer");
        }

        Some(Commands::Validate { schema }) => {
            println!("Validating schema: {}", schema.display());

            match validate_schema(&schema) {
                Ok(()) => println!("Schema is valid!"),
                Err(e) => {
                    eprintln!("Validation failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        None => {
            // No command provided, show help
            println!("DCP - Development Context Protocol");
            println!("Use --help for usage information");
            println!("Use --stdio to run in stdio mode for MCP compatibility");
        }
    }
}

/// Run DCP in stdio mode for MCP compatibility
fn run_stdio_mode() {
    use dx_dcp::compat::stdio::{StdioConfig, StdioTransport};
    use std::io;

    eprintln!("[DCP] Starting in stdio mode");
    eprintln!("[DCP] Reading JSON-RPC messages from stdin");
    eprintln!("[DCP] Writing responses to stdout");

    let config = StdioConfig {
        stderr_logging: true,
        ..Default::default()
    };
    let mut transport = StdioTransport::with_config(config);

    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();
    let mut session = StdioSessionState::default();

    // Simple message loop
    loop {
        match transport.read_message(&mut stdin_lock) {
            Ok(Some(message)) => {
                transport.log_debug(&format!(
                    "Received: {}",
                    sanitized_stdio_preview(&message, 100)
                ));

                // Parse and handle the message
                match handle_stdio_message_with_session(&message, &mut session) {
                    Ok(response) => {
                        if let Some(resp) = response {
                            if let Err(e) = transport.write_message(&mut stdout_lock, &resp) {
                                transport.log_error(&format!("Write error: {}", e));
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        transport.log_error(&format!(
                            "Handler error: {}",
                            dx_dcp::security::sanitize_text(&e)
                        ));
                        // Send error response
                        let error_response = r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"#;
                        let _ = transport.write_message(&mut stdout_lock, error_response);
                    }
                }
            }
            Ok(None) => {
                // EOF or shutdown
                transport.log_stderr("Shutting down");
                break;
            }
            Err(e) => {
                transport.log_error(&format!("Read error: {}", e));
                break;
            }
        }
    }

    eprintln!("[DCP] Stdio mode terminated");
}

fn sanitized_stdio_preview(message: &str, max_chars: usize) -> String {
    use dx_dcp::security::{sanitize_json_value, sanitize_text};

    let sanitized = serde_json::from_str::<serde_json::Value>(message)
        .ok()
        .map(|value| sanitize_json_value(&value))
        .and_then(|value| serde_json::to_string(&value).ok())
        .unwrap_or_else(|| sanitize_text(message));

    sanitized.chars().take(max_chars).collect()
}

/// Handle a single stdio message and return optional response
#[cfg(test)]
fn handle_stdio_message(message: &str) -> Result<Option<String>, String> {
    let mut session = StdioSessionState::default();
    handle_stdio_message_with_session(message, &mut session)
}

#[derive(Default)]
struct StdioSessionState {
    initialize_seen: bool,
    initialized: bool,
}

fn handle_stdio_message_with_session(
    message: &str,
    session: &mut StdioSessionState,
) -> Result<Option<String>, String> {
    use dx_dcp::compat::json_rpc::{JsonRpcParseError, JsonRpcParser, RequestId};

    let request = match JsonRpcParser::parse_request(message) {
        Ok(request) => request,
        Err(JsonRpcParseError::InvalidJson(_)) => {
            return Ok(Some(stdio_error_response("null", -32700, "Parse error")?));
        }
        Err(_) => {
            return Ok(Some(stdio_error_response(
                "null",
                -32600,
                "Invalid Request",
            )?));
        }
    };

    // Check if this is a notification (no id = no response)
    if request.is_notification() {
        return match request.method.as_str() {
            "notifications/initialized" => {
                if request.params.is_some() {
                    return Ok(Some(stdio_error_response(
                        "null",
                        -32600,
                        "Invalid Request",
                    )?));
                }
                if !session.initialize_seen || session.initialized {
                    Ok(Some(stdio_error_response(
                        "null",
                        -32600,
                        "Invalid Request",
                    )?))
                } else {
                    session.initialized = true;
                    Ok(None)
                }
            }
            "notifications/cancelled" => Ok(None),
            _ => Ok(Some(stdio_error_response(
                "null",
                -32600,
                "Invalid Request",
            )?)),
        };
    }

    // Format the ID for JSON response
    let id = match &request.id {
        RequestId::Number(n) => n.to_string(),
        RequestId::String(s) => serde_json::to_string(s).map_err(|e| e.to_string())?,
        RequestId::Null => "null".to_string(),
        RequestId::Missing => "null".to_string(),
    };

    // Handle known methods
    match request.method.as_str() {
        "initialize" => {
            if session.initialize_seen {
                return Ok(Some(stdio_error_response(&id, -32600, "Invalid Request")?));
            }
            session.initialize_seen = true;
            let response = format!(
                r#"{{"jsonrpc":"2.0","result":{{"protocolVersion":"2024-11-05","capabilities":{{}},"serverInfo":{{"name":"dcp","version":"{}"}}}},"id":{}}}"#,
                env!("CARGO_PKG_VERSION"),
                id
            );
            Ok(Some(response))
        }
        "initialized" => {
            let response = stdio_error_response(&id, -32600, "Invalid Request")?;
            Ok(Some(response))
        }
        "notifications/initialized" => {
            let response = stdio_error_response(&id, -32600, "Invalid Request")?;
            Ok(Some(response))
        }
        "ping" => {
            let response = format!(r#"{{"jsonrpc":"2.0","result":{{}},"id":{}}}"#, id);
            Ok(Some(response))
        }
        "tools/list" => {
            if !session.initialized {
                return Ok(Some(stdio_error_response(&id, -32600, "Invalid Request")?));
            }
            Ok(Some(stdio_error_response(
                &id,
                -32001,
                "Capability denied",
            )?))
        }
        "resources/list" => {
            if !session.initialized {
                return Ok(Some(stdio_error_response(&id, -32600, "Invalid Request")?));
            }
            Ok(Some(stdio_error_response(
                &id,
                -32001,
                "Capability denied",
            )?))
        }
        "prompts/list" => {
            if !session.initialized {
                return Ok(Some(stdio_error_response(&id, -32600, "Invalid Request")?));
            }
            Ok(Some(stdio_error_response(
                &id,
                -32001,
                "Capability denied",
            )?))
        }
        "tools/call"
        | "resources/read"
        | "resources/subscribe"
        | "resources/unsubscribe"
        | "prompts/get"
        | "completion/complete" => {
            if !session.initialized {
                return Ok(Some(stdio_error_response(&id, -32600, "Invalid Request")?));
            }
            Ok(Some(stdio_error_response(
                &id,
                -32001,
                "Capability denied",
            )?))
        }
        _ => {
            // Unknown method
            let message = serde_json::to_string("Method not found").map_err(|e| e.to_string())?;
            let response = format!(
                r#"{{"jsonrpc":"2.0","error":{{"code":-32601,"message":{}}},"id":{}}}"#,
                message, id
            );
            Ok(Some(response))
        }
    }
}

fn stdio_error_response(id: &str, code: i32, message: &str) -> Result<String, String> {
    let message = serde_json::to_string(message).map_err(|e| e.to_string())?;
    Ok(format!(
        r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":{}}},"id":{}}}"#,
        code, message, id
    ))
}

/// Convert MCP JSON schema to DCP binary format
fn convert_schema(input: &PathBuf, output: &PathBuf, validate: bool) -> Result<(), String> {
    use dx_dcp::cli::convert::{convert_mcp_to_dcp, McpSchema};
    use std::fs;

    // Read input file
    let json_content =
        fs::read_to_string(input).map_err(|e| format!("Failed to read input file: {}", e))?;

    // Parse MCP schema
    let mcp_schema: McpSchema = serde_json::from_str(&json_content)
        .map_err(|e| format!("Failed to parse MCP schema: {}", e))?;

    // Convert to DCP
    let dcp_schema =
        convert_mcp_to_dcp(&mcp_schema).map_err(|e| format!("Conversion error: {}", e))?;

    // Serialize to binary
    let binary_data = dcp_schema.to_bytes();

    // Validate if requested
    if validate {
        let _roundtrip = dx_dcp::cli::convert::DcpSchema::from_bytes(&binary_data)
            .map_err(|e| format!("Validation failed: {}", e))?;
    }

    // Write output file
    fs::write(output, &binary_data).map_err(|e| format!("Failed to write output file: {}", e))?;

    println!("  Input size: {} bytes", json_content.len());
    println!("  Output size: {} bytes", binary_data.len());
    println!(
        "  Compression ratio: {:.1}x",
        json_content.len() as f64 / binary_data.len() as f64
    );

    Ok(())
}

/// Validate a DCP schema file
fn validate_schema(schema_path: &PathBuf) -> Result<(), String> {
    use std::fs;

    let data = fs::read(schema_path).map_err(|e| format!("Failed to read schema file: {}", e))?;

    let schema = dx_dcp::cli::convert::DcpSchema::from_bytes(&data)
        .map_err(|e| format!("Invalid schema: {}", e))?;

    println!("  Name: {}", schema.name);
    println!("  Tool ID: {}", schema.tool_id);
    println!("  Fields: {}", schema.fields.len());
    println!("  Required fields: {}", schema.required_mask.count_ones());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        handle_stdio_message, handle_stdio_message_with_session, sanitized_stdio_preview,
        StdioSessionState,
    };

    #[test]
    fn stdio_preview_redacts_secret_bearing_json() {
        let preview = sanitized_stdio_preview(
            concat!(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"authorization":"#,
                r#""Bearer raw-secret","api_key":"sk-live-secret"}}"#
            ),
            200,
        );

        assert!(!preview.contains("raw-secret"));
        assert!(!preview.contains("sk-live-secret"));
        assert!(preview.contains("[REDACTED]"));
    }

    #[test]
    fn stdio_unknown_method_response_redacts_method_text() {
        let response = handle_stdio_message(
            r#"{"jsonrpc":"2.0","method":"unknown/access_token=plain-secret","id":1}"#,
        )
        .unwrap()
        .unwrap();

        assert!(response.contains(r#""code":-32601"#));
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("access_token"));
    }

    #[test]
    fn stdio_invalid_json_returns_parse_error() {
        let response = handle_stdio_message(r#"{"jsonrpc":"2.0","method":"ping","id":1"#)
            .unwrap()
            .unwrap();

        assert!(response.contains(r#""code":-32700"#));
        assert!(response.contains(r#""id":null"#));
    }

    #[test]
    fn stdio_invalid_request_shape_returns_invalid_request() {
        let response = handle_stdio_message(r#"[]"#).unwrap().unwrap();

        assert!(response.contains(r#""code":-32600"#));
        assert!(response.contains(r#""id":null"#));
    }

    #[test]
    fn stdio_initialized_with_id_returns_invalid_request() {
        let response = handle_stdio_message(r#"{"jsonrpc":"2.0","method":"initialized","id":1}"#)
            .unwrap()
            .unwrap();

        assert!(response.contains(r#""code":-32600"#));
        assert!(response.contains(r#""id":1"#));
    }

    #[test]
    fn stdio_tools_list_rejects_before_initialized() {
        let response = handle_stdio_message(r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#)
            .unwrap()
            .unwrap();

        assert!(response.contains(r#""code":-32600"#));
        assert!(response.contains("Invalid Request"));
    }

    #[test]
    fn stdio_initialize_does_not_advertise_unregistered_capabilities() {
        let response = handle_stdio_message(r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#)
            .unwrap()
            .unwrap();

        assert!(response.contains(r#""capabilities":{}"#));
        assert!(!response.contains(r#""tools":{}"#));
        assert!(!response.contains(r#""resources":{}"#));
        assert!(!response.contains(r#""prompts":{}"#));
    }

    #[test]
    fn stdio_lists_deny_without_negotiated_capability_after_initialized() {
        let mut session = StdioSessionState::default();

        let init = handle_stdio_message_with_session(
            r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#,
            &mut session,
        )
        .unwrap()
        .unwrap();
        assert!(init.contains(r#""capabilities":{}"#));

        let initialized = handle_stdio_message_with_session(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &mut session,
        )
        .unwrap();
        assert!(initialized.is_none());

        let response = handle_stdio_message_with_session(
            r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#,
            &mut session,
        )
        .unwrap()
        .unwrap();

        assert!(response.contains(r#""code":-32001"#));
        assert!(response.contains("Capability denied"));
    }

    #[test]
    fn stdio_rejects_side_effecting_notification_methods() {
        let response = handle_stdio_message(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure"}}"#,
        )
        .unwrap()
        .unwrap();

        assert!(response.contains(r#""code":-32600"#));
        assert!(response.contains(r#""id":null"#));
    }
}
