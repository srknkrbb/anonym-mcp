//! Anonymizing MCP server.
//!
//! Speaks MCP over stdio, so any MCP-capable agent can use it. Configure it in
//! the agent rather than patching the agent's own file tools: the mapping table
//! and the real file bytes then live in this process alone, and no other tool
//! in the agent can reach around it.
//!
//! Environment:
//!   ANONYM_MAPPINGS   path to the mapping table (default ~/.anonym-mcp/mappings.json)
//!   ANONYM_ROOTS      colon-separated directories the server may touch (default: any)
//!   ANONYM_WORDS      comma-separated extra words to mask
//!   ANONYM_DETECTORS  comma-separated detector names (default: the engine set)

mod anonymize;
mod detectors;
mod store;
mod tools;

use crate::anonymize::{Kind, MappingStore, Settings};
use anyhow::Result;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::PathBuf;

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Render an error with its causes.
///
/// `anyhow`'s Display shows only the outermost context, so a failed read
/// reported just "reading /path/file" and dropped the reason. The agent then
/// cannot tell a permission problem from a missing file, and neither can the
/// user reading the transcript.
fn error_chain(err: &anyhow::Error) -> String {
    let mut parts = vec![err.to_string()];
    parts.extend(err.chain().skip(1).map(|cause| cause.to_string()));
    parts.join(": ")
}

fn settings_from_env() -> Settings {
    let mut settings = Settings::default();
    if let Ok(words) = std::env::var("ANONYM_WORDS") {
        settings.custom_words = words
            .split(',')
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .map(str::to_string)
            .collect();
        if !settings.custom_words.is_empty() && !settings.enabled.contains(&Kind::CustomWord) {
            settings.enabled.push(Kind::CustomWord);
        }
    }
    if let Ok(names) = std::env::var("ANONYM_DETECTORS") {
        let named: Vec<Kind> = names.split(',').filter_map(kind_from_name).collect();
        // An unrecognised list must not silently disable masking.
        if !named.is_empty() {
            settings.enabled = named;
        }
    }
    settings
}

fn kind_from_name(name: &str) -> Option<Kind> {
    match name.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "password" | "sifre" | "şifre" => Some(Kind::Password),
        "national_id" | "tckn" => Some(Kind::NationalId),
        "iban" => Some(Kind::Iban),
        "credit_card" | "card" | "kart" => Some(Kind::CreditCard),
        "email" | "eposta" => Some(Kind::Email),
        "phone" | "tel" | "telefon" => Some(Kind::Phone),
        "person_name" | "person" | "kisi" | "kişi" => Some(Kind::PersonName),
        "custom_word" | "custom" | "ozel" | "özel" => Some(Kind::CustomWord),
        _ => None,
    }
}

fn roots_from_env() -> Vec<PathBuf> {
    std::env::var("ANONYM_ROOTS")
        .map(|value| {
            value
                .split(':')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

fn store_from_env() -> Result<MappingStore> {
    let path = match std::env::var("ANONYM_MAPPINGS") {
        Ok(path) => PathBuf::from(path),
        Err(_) => match dirs_home() {
            Some(home) => home.join(".anonym-mcp/mappings.json"),
            None => return Ok(MappingStore::ephemeral()),
        },
    };
    MappingStore::open(path)
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Handle one JSON-RPC message, returning the response to write (if any).
///
/// Notifications carry no `id` and get no response, which is what keeps a
/// `notifications/initialized` from confusing the client.
pub fn handle_message(server: &mut tools::Server, message: &Value) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "anonym-mcp", "version": env!("CARGO_PKG_VERSION")}
        })),
        "tools/list" => Ok(json!({"tools": tools::tool_definitions(server.allow_reveal())})),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match server.dispatch(&name, &args) {
                Ok(text) => Ok(json!({"content": [{"type": "text", "text": text}]})),
                // A tool failure is reported inside the result with isError, not
                // as a protocol error: the model has to see what went wrong to
                // correct itself.
                Err(err) => Ok(json!({
                    "content": [{"type": "text", "text": error_chain(&err)}],
                    "isError": true
                })),
            }
        }
        "ping" => Ok(json!({})),
        _ if id.is_none() => return None, // notification we do not handle
        other => Err(format!("unknown method: {other}")),
    };

    // Notifications never get a reply, even when handled.
    let id = id?;
    Some(match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(message) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": message}
        }),
    })
}

/// Human-facing help.
///
/// The server's normal mode is to read JSON-RPC from stdin, so without this a
/// person who runs `anonym-mcp --help` to see what they just installed gets a
/// process that hangs silently on an empty terminal.
fn print_help() {
    println!(
        "anonym-mcp {} - anonymizing MCP server\n\n\
         Masks sensitive values (national IDs, IBANs, cards, e-mails, phones,\n\
         passwords) in files before an AI agent sees them, and restores the real\n\
         values when the agent writes back.\n\n\
         This is an MCP server: it speaks JSON-RPC over stdin/stdout and is meant\n\
         to be launched by an MCP client, not run by hand.\n\n\
         Configure it in your agent, for example in .jcode/mcp.json:\n\n\
         \x20 {{\n\
         \x20   \"mcpServers\": {{\n\
         \x20     \"anonym\": {{\n\
         \x20       \"command\": \"anonym-mcp\",\n\
         \x20       \"env\": {{ \"ANONYM_ROOTS\": \"/path/to/sensitive/data\" }}\n\
         \x20     }}\n\
         \x20   }}\n\
         \x20 }}\n\n\
         Environment:\n\
         \x20 ANONYM_MAPPINGS   mapping table path (default ~/.anonym-mcp/mappings.json)\n\
         \x20 ANONYM_ROOTS      colon-separated directories the server may touch\n\
         \x20 ANONYM_WORDS      comma-separated extra words to mask\n\
         \x20 ANONYM_DETECTORS  comma-separated detector names\n\
         \x20 ANONYM_ALLOW_REVEAL=1  also offer restore_text, which reveals real\n\
         \x20                        values into the conversation (off by default)\n\n\
         Tools: read_anonymized, write_restored, edit_restored, anonymize_text\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() -> Result<()> {
    // Answer a human before waiting on a client. Running the binary from a
    // shell to see what it is must not look like a hang.
    //
    // Every argument is inspected, not just the first: `--version --bogus` used
    // to print the version and exit 0, silently swallowing the mistake.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(bad) = args.iter().find(|arg| {
        !matches!(
            arg.as_str(),
            "-h" | "--help" | "help" | "-V" | "--version" | "version"
        )
    }) {
        eprintln!("anonym-mcp: unexpected argument `{bad}`\n");
        print_help();
        std::process::exit(2);
    }
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help" | "help"))
    {
        print_help();
        return Ok(());
    }
    if !args.is_empty() {
        println!("anonym-mcp {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // A bare terminal invocation would otherwise block on stdin with no output.
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        eprintln!(
            "anonym-mcp: stdin is a terminal, so no MCP client is attached.\n\
             Run `anonym-mcp --help` for how to configure it in your agent.\n"
        );
        std::process::exit(2);
    }

    let allow_reveal = std::env::var("ANONYM_ALLOW_REVEAL")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let mut server = tools::Server::new(
        store_from_env()?,
        settings_from_env(),
        roots_from_env(),
        allow_reveal,
    );

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(err) => {
                // Malformed input must not kill the server; the client would
                // see an opaque broken pipe instead of a parse error.
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {"code": -32700, "message": format!("parse error: {err}")}
                });
                writeln!(stdout, "{response}")?;
                stdout.flush()?;
                continue;
            }
        };
        if let Some(response) = handle_message(&mut server, &message) {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> tools::Server {
        tools::Server::new(
            MappingStore::ephemeral(),
            Settings::default(),
            vec![],
            false,
        )
    }

    #[test]
    fn initialize_advertises_tools_and_the_protocol_version() {
        let mut srv = server();
        let response = handle_message(
            &mut srv,
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        )
        .expect("initialize must be answered");
        assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(response["result"]["capabilities"]["tools"].is_object());
        assert_eq!(response["result"]["serverInfo"]["name"], "anonym-mcp");
    }

    #[test]
    fn notifications_get_no_response() {
        let mut srv = server();
        assert!(
            handle_message(
                &mut srv,
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
            )
            .is_none(),
            "replying to a notification breaks the protocol"
        );
    }

    #[test]
    fn tools_list_returns_the_full_set() {
        let mut srv = server();
        let response = handle_message(
            &mut srv,
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        )
        .unwrap();
        // restore_text is hidden by default, so four are advertised.
        assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn call_masks_a_file_end_to_end_over_the_protocol() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.csv");
        std::fs::write(&path, "ad,tckn\nAli,10000000146\n").unwrap();

        let mut srv = server();
        let response = handle_message(
            &mut srv,
            &json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {
                    "name": "read_anonymized",
                    "arguments": {"path": path.display().to_string()}
                }
            }),
        )
        .unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("10000000146"), "{text}");
        assert!(text.contains("TCKN_1"), "{text}");
    }

    #[test]
    fn a_failing_tool_reports_iserror_rather_than_a_protocol_error() {
        let mut srv = server();
        let response = handle_message(
            &mut srv,
            &json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "read_anonymized", "arguments": {"path": "/nope/missing"}}
            }),
        )
        .unwrap();
        assert!(response["error"].is_null(), "{response}");
        assert_eq!(response["result"]["isError"], true, "{response}");
    }

    #[test]
    fn an_unknown_method_is_a_protocol_error() {
        let mut srv = server();
        let response = handle_message(
            &mut srv,
            &json!({"jsonrpc": "2.0", "id": 5, "method": "resources/list"}),
        )
        .unwrap();
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn a_failure_reports_its_cause_not_just_the_operation() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.csv");
        let mut srv = server();
        let response = handle_message(
            &mut srv,
            &json!({
                "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                "params": {
                    "name": "read_anonymized",
                    "arguments": {"path": missing.to_string_lossy()}
                }
            }),
        )
        .unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("reading"), "{text}");
        assert!(
            text.to_lowercase().contains("no such file"),
            "the underlying reason must survive: {text}"
        );
    }

    #[test]
    fn detector_names_from_env_are_parsed_leniently() {
        assert_eq!(kind_from_name("TCKN"), Some(Kind::NationalId));
        assert_eq!(kind_from_name("credit-card"), Some(Kind::CreditCard));
        assert_eq!(kind_from_name("garbage"), None);
    }
}
