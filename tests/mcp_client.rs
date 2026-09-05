//! Drive the server the way a real MCP client does: spawn the binary, speak
//! JSON-RPC over its stdin/stdout, and check what comes back.
//!
//! The unit tests call the handlers directly, which cannot catch a protocol
//! mistake: an id echoed wrongly, a notification answered, a response written
//! before the request was read. Those are invisible in-process and fatal in
//! practice, so this test drives the actual process.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

fn binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("test binary");
    path.pop(); // deps/
    path.pop(); // debug/
    path.join("anonym-mcp")
}

/// A live server process plus the pipes to talk to it.
struct Client {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Client {
    fn start(mappings: &std::path::Path, roots: Option<&std::path::Path>) -> Client {
        let mut command = Command::new(binary());
        command
            .env("ANONYM_MAPPINGS", mappings)
            .env("ANONYM_WORDS", "Acme Holding")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(roots) = roots {
            command.env("ANONYM_ROOTS", roots);
        }
        let mut child = command.spawn().expect("spawn anonym-mcp");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Client {
            child,
            stdin,
            stdout,
        }
    }

    fn request(&mut self, id: u64, method: &str, params: serde_json::Value) -> serde_json::Value {
        let message = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        });
        writeln!(self.stdin, "{message}").expect("write request");
        self.stdin.flush().expect("flush");

        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        let response: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|err| panic!("malformed response {line:?}: {err}"));
        assert_eq!(response["id"], id, "the server must echo the request id");
        assert_eq!(response["jsonrpc"], "2.0");
        response
    }

    fn notify(&mut self, method: &str) {
        let message = serde_json::json!({"jsonrpc": "2.0", "method": method});
        writeln!(self.stdin, "{message}").expect("write notification");
        self.stdin.flush().expect("flush");
    }

    fn call(&mut self, id: u64, tool: &str, arguments: serde_json::Value) -> serde_json::Value {
        self.request(
            id,
            "tools/call",
            serde_json::json!({"name": tool, "arguments": arguments}),
        )
    }

    fn shutdown(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

fn text_of(response: &serde_json::Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn a_client_can_initialize_list_tools_and_round_trip_a_file() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let file = work.path().join("musteri.csv");
    let original = "firma,ad,tckn,eposta\nAcme Holding,Ali,10000000146,a.b@example.com\n";
    std::fs::write(&file, original).unwrap();
    let mappings = work.path().join("map.json");

    let mut client = Client::start(&mappings, Some(work.path()));

    // 1. Handshake.
    let init = client.request(1, "initialize", serde_json::json!({}));
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(init["result"]["serverInfo"]["name"], "anonym-mcp");

    // A notification must not be answered. If the server replied here, the
    // next response read would be off by one and every later assertion would
    // be checking the wrong message.
    client.notify("notifications/initialized");

    // 2. Tool discovery. restore_text is hidden unless explicitly enabled.
    let listed = client.request(2, "tools/list", serde_json::json!({}));
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"read_anonymized"), "{names:?}");
    assert!(names.contains(&"edit_restored"), "{names:?}");
    assert!(
        !names.contains(&"restore_text"),
        "the reveal tool must not be advertised by default: {names:?}"
    );

    // 3. Read: nothing sensitive may come back.
    let read = client.call(
        3,
        "read_anonymized",
        serde_json::json!({"path": file.to_string_lossy()}),
    );
    let seen = text_of(&read);
    for secret in ["10000000146", "a.b@example.com", "Acme Holding"] {
        assert!(
            !seen.contains(secret),
            "`{secret}` reached the client: {seen}"
        );
    }
    assert!(seen.contains("TCKN_"), "{seen}");

    // 4. Edit, quoting the placeholder as an agent would. This is the step that
    //    fails outright unless the search string is un-masked before matching.
    let edited = client.call(
        4,
        "edit_restored",
        serde_json::json!({
            "path": file.to_string_lossy(),
            "old_string": "Ali,TCKN_1",
            "new_string": "Ali Veli,TCKN_1",
        }),
    );
    assert!(
        edited["result"]["isError"].as_bool() != Some(true),
        "edit failed: {}",
        text_of(&edited)
    );

    // 5. Disk keeps the real data, with only the intended change.
    let on_disk = std::fs::read_to_string(&file).unwrap();
    assert_eq!(
        on_disk,
        "firma,ad,tckn,eposta\nAcme Holding,Ali Veli,10000000146,a.b@example.com\n"
    );
    assert!(!on_disk.contains("TCKN_"), "{on_disk}");

    // 6. The mapping table is private to this user.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&mappings).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    client.shutdown();
}

#[test]
fn a_client_gets_errors_as_results_so_the_model_can_correct_itself() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.csv");
    std::fs::write(&secret, "tckn 10000000146").unwrap();

    let mut client = Client::start(&work.path().join("map.json"), Some(work.path()));
    client.request(1, "initialize", serde_json::json!({}));

    // Outside the roots: refused, and the refusal must not echo the content.
    let refused = client.call(
        2,
        "read_anonymized",
        serde_json::json!({"path": secret.to_string_lossy()}),
    );
    assert!(
        refused["error"].is_null(),
        "a tool failure is not a protocol error"
    );
    assert_eq!(refused["result"]["isError"], true);
    let message = text_of(&refused);
    assert!(message.contains("outside the allowed roots"), "{message}");
    assert!(!message.contains("10000000146"), "{message}");

    // The hidden reveal tool refuses even when called by name.
    let revealed = client.call(3, "restore_text", serde_json::json!({"text": "TCKN_1"}));
    assert_eq!(revealed["result"]["isError"], true);
    assert!(text_of(&revealed).contains("disabled"));

    // The server is still healthy after two errors.
    let ping = client.request(4, "ping", serde_json::json!({}));
    assert!(ping["result"].is_object(), "server must survive errors");

    client.shutdown();
}
