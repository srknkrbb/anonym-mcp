//! Tool handlers for the anonymizing MCP server.
//!
//! The agent never touches the filesystem for a sensitive file: it asks this
//! server, and the server is the only process that sees the real bytes. That is
//! the whole security argument for being a separate process rather than a
//! feature inside the agent, where ten other tools could read the same file
//! unmasked.

use crate::anonymize::{MappingStore, Settings, anonymize_text, restore_text};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// Server state: the mapping table plus the detector settings.
pub struct Server {
    store: MappingStore,
    settings: Settings,
    /// Directories the server is allowed to touch. Empty means "anywhere",
    /// which is the default for a personal machine.
    roots: Vec<PathBuf>,
    /// Whether `restore_text` is offered at all.
    ///
    /// That tool hands real values back into the conversation, which is the one
    /// thing this server exists to prevent. Observed in a live session: asked
    /// "show me the tckn", the agent read the file masked, then dutifully
    /// called restore_text and printed the real national ID. Correct per the
    /// tool's contract, and a complete defeat of the feature. So it is off
    /// unless the operator opts in with ANONYM_ALLOW_REVEAL=1.
    allow_reveal: bool,
}

impl Server {
    pub fn new(
        store: MappingStore,
        settings: Settings,
        roots: Vec<PathBuf>,
        allow_reveal: bool,
    ) -> Self {
        Server {
            store,
            settings,
            roots,
            allow_reveal,
        }
    }

    /// Whether the reveal tool is offered.
    pub fn allow_reveal(&self) -> bool {
        self.allow_reveal
    }

    /// Reject a path outside the configured roots.
    ///
    /// Without this the agent could ask the server to restore a mapping into
    /// any file on the machine, which turns a masking tool into an arbitrary
    /// write primitive.
    fn check_path(&self, path: &Path) -> Result<PathBuf> {
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        reject_non_regular_target(&resolved)?;
        if self.roots.is_empty() {
            return Ok(resolved);
        }
        // Compare against the canonical form of each root so `..` cannot walk
        // out of an allowed directory.
        let probe = resolved.canonicalize().unwrap_or_else(|_| resolved.clone());
        for root in &self.roots {
            let root = root.canonicalize().unwrap_or_else(|_| root.clone());
            if probe.starts_with(&root) {
                return Ok(resolved);
            }
        }
        bail!("path {} is outside the allowed roots", resolved.display())
    }

    /// `read_anonymized`: the agent's replacement for reading a sensitive file.
    pub fn read_anonymized(&mut self, args: &Value) -> Result<String> {
        let path = arg_str(args, "path")?;
        let path = self.check_path(Path::new(&path))?;
        let raw = read_document_text(&path)?;
        let (masked, report) = anonymize_text(&raw, &self.settings, &mut self.store);
        self.store.save()?;

        let note = if report.is_empty() {
            "\n\n(no sensitive values found)".to_string()
        } else {
            format!(
                "\n\n({} masked: {}. These placeholders are safe to quote and write \
                 back unchanged; write_restored turns them into the real values.)",
                report.count(),
                report.summary()
            )
        };
        Ok(format!("{masked}{note}"))
    }

    /// `write_restored`: write agent-authored text back, resolving placeholders.
    pub fn write_restored(&mut self, args: &Value) -> Result<String> {
        let path = arg_str(args, "path")?;
        let content = arg_str(args, "content")?;
        let path = self.check_path(Path::new(&path))?;
        if crate::ooxml::is_ooxml(&path) {
            // A .docx is an archive, not a string. Writing the agent's text
            // over it would replace a document with a text file, so the edit
            // has to be expressed as an edit, not as a whole-file write.
            bail!(
                "{} is an OOXML document; use edit_restored to change its text, \
                 which rewrites the document in place and preserves formatting",
                path.display()
            );
        }
        let (restored_text, restored) = restore_text(&content, &self.store);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, &restored_text)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(format!(
            "Wrote {} ({} bytes, {restored} placeholder{} restored to real values)",
            path.display(),
            restored_text.len(),
            if restored == 1 { "" } else { "s" }
        ))
    }

    /// `edit_restored`: replace a substring, restoring both sides first.
    ///
    /// The agent quotes `old_string` from text it only ever saw masked, so the
    /// search string must be un-masked before it can match the real file.
    pub fn edit_restored(&mut self, args: &Value) -> Result<String> {
        let path = arg_str(args, "path")?;
        let old = arg_str(args, "old_string")?;
        let new = arg_str(args, "new_string")?;
        let path = self.check_path(Path::new(&path))?;

        let (old_real, _) = restore_text(&old, &self.store);
        let (new_real, restored) = restore_text(&new, &self.store);

        if crate::ooxml::is_ooxml(&path) {
            let replacements = edit_ooxml(&path, &old_real, &new_real)?;
            return Ok(format!(
                "Edited {} ({replacements} replacement{} in the document text, \
                 {restored} placeholder{} restored; formatting preserved)",
                path.display(),
                if replacements == 1 { "" } else { "s" },
                if restored == 1 { "" } else { "s" }
            ));
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;

        let occurrences = content.matches(old_real.as_str()).count();
        if occurrences == 0 {
            bail!("old_string not found in {}", path.display());
        }
        if occurrences > 1 {
            bail!(
                "old_string found {occurrences} times in {}; add more context",
                path.display()
            );
        }
        let updated = content.replacen(old_real.as_str(), new_real.as_str(), 1);
        std::fs::write(&path, &updated).with_context(|| format!("writing {}", path.display()))?;
        Ok(format!(
            "Edited {} (1 replacement, {restored} placeholder{} restored)",
            path.display(),
            if restored == 1 { "" } else { "s" }
        ))
    }

    /// `anonymize_text`: mask a snippet the agent already holds.
    pub fn anonymize_snippet(&mut self, args: &Value) -> Result<String> {
        let text = arg_str(args, "text")?;
        let (masked, report) = anonymize_text(&text, &self.settings, &mut self.store);
        self.store.save()?;
        Ok(if report.is_empty() {
            masked
        } else {
            format!(
                "{masked}\n\n({} masked: {})",
                report.count(),
                report.summary()
            )
        })
    }

    /// `restore_text`: resolve placeholders without writing a file.
    ///
    /// Deliberately the narrowest tool here. It hands real values back to the
    /// agent, which is the one thing the rest of this server exists to avoid,
    /// so it is opt-in per call rather than something the agent stumbles into.
    pub fn restore_snippet(&self, args: &Value) -> Result<String> {
        if !self.allow_reveal {
            bail!(
                "restore_text is disabled: revealing real values into the conversation \
                 defeats the purpose of masking. Use write_restored or edit_restored to \
                 put values back on disk instead. The operator can enable this tool with \
                 ANONYM_ALLOW_REVEAL=1."
            );
        }
        let text = arg_str(args, "text")?;
        let (restored, count) = restore_text(&text, &self.store);
        if count == 0 {
            return Ok("(no known placeholders in that text)".to_string());
        }
        Ok(restored)
    }

    pub fn dispatch(&mut self, name: &str, args: &Value) -> Result<String> {
        match name {
            "read_anonymized" => self.read_anonymized(args),
            "write_restored" => self.write_restored(args),
            "edit_restored" => self.edit_restored(args),
            "anonymize_text" => self.anonymize_snippet(args),
            "restore_text" => self.restore_snippet(args),
            other => bail!("unknown tool: {other}"),
        }
    }
}

/// Replace text inside an OOXML document, in place, preserving structure.
///
/// The replacement runs per text node. A phrase split across two runs (Word
/// does this freely, mid-word, when formatting changes) will not match, and
/// saying so is better than a silent no-op that leaves the agent believing the
/// edit landed.
fn edit_ooxml(path: &Path, old: &str, new: &str) -> Result<usize> {
    let mut replacements = 0;
    let temp = path.with_extension("anonym-tmp");
    crate::ooxml::transform_document(path, &temp, |text| {
        if text.contains(old) {
            replacements += text.matches(old).count();
            text.replace(old, new)
        } else {
            text.to_string()
        }
    })?;

    if replacements == 0 {
        let _ = std::fs::remove_file(&temp);
        bail!(
            "old_string not found in the text of {}. Note that Word splits \
             text across runs, so a phrase spanning a formatting change cannot \
             be matched as one string; try a shorter fragment",
            path.display()
        );
    }

    // Swap in only after a successful rewrite, so a failure cannot destroy the
    // user's document.
    std::fs::rename(&temp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(replacements)
}

/// Read a document's user-visible text, whatever its container.
///
/// A .docx is a zip of XML, so `read_to_string` on one returns either a UTF-8
/// error or a pile of markup. Each format gets the extraction that suits it,
/// and the detectors then see prose in every case.
fn read_document_text(path: &Path) -> Result<String> {
    if crate::ooxml::is_ooxml(path) {
        return crate::ooxml::extract_text(path);
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Refuse character devices and other non-regular files.
///
/// `write_restored` with `path: "/dev/stdout"` restored the real values
/// straight into the JSON-RPC stream, which is the model's input: a complete
/// bypass of the masking, and corrupt protocol output as a bonus. Demonstrated,
/// not hypothesised. The same applies to `/dev/stderr`, `/dev/fd/*` and any
/// other device that leads back to a channel the agent can observe.
fn reject_non_regular_target(path: &Path) -> Result<()> {
    // Only reject what exists and is not a regular file; a path that does not
    // exist yet is a normal create.
    if let Ok(meta) = std::fs::metadata(path)
        && !meta.is_file()
        && !meta.is_dir()
    {
        bail!(
            "{} is not a regular file; writing restored values to a device would \
             put them straight into the conversation",
            path.display()
        );
    }
    // /dev and /proc entries can appear regular on some systems, so refuse them
    // by location as well.
    let text = path.to_string_lossy();
    if text.starts_with("/dev/") || text.starts_with("/proc/") {
        bail!(
            "{} is a device path; restored values must go to a real file",
            path.display()
        );
    }
    Ok(())
}

fn arg_str(args: &Value, key: &str) -> Result<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .with_context(|| format!("missing required argument `{key}`"))
}

/// The `tools/list` payload.
pub fn tool_definitions(allow_reveal: bool) -> Value {
    let mut tools = json!([
        {
            "name": "read_anonymized",
            "description": "Read a file with sensitive values (national IDs, IBANs, card \
                numbers, e-mails, phone numbers, passwords) replaced by stable placeholders \
                such as TCKN_1. Use this instead of the ordinary file-reading tool for any \
                file that may contain personal or credential data. The real values never \
                leave the user's machine.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File to read."}
                },
                "required": ["path"]
            }
        },
        {
            "name": "write_restored",
            "description": "Write a file, turning any placeholder (TCKN_1, IBAN_2, ...) back \
                into the real value first. Use this to save work based on read_anonymized \
                output; writing that text with an ordinary write tool would store the \
                placeholder and destroy the user's data.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"}
                },
                "required": ["path", "content"]
            }
        },
        {
            "name": "edit_restored",
            "description": "Replace one occurrence of old_string with new_string in a file. \
                Both strings may contain placeholders: they are resolved before matching and \
                before writing, so an edit quoting masked text still finds the real line.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old_string": {"type": "string"},
                    "new_string": {"type": "string"}
                },
                "required": ["path", "old_string", "new_string"]
            }
        },
        {
            "name": "anonymize_text",
            "description": "Mask sensitive values in a snippet of text, for example before \
                quoting it into a report or a commit message.",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"]
            }
        },
    ]);
    // Only advertise the reveal tool when it is actually usable: a tool the
    // model can see is a tool it will reach for.
    if allow_reveal && let Some(list) = tools.as_array_mut() {
        list.push(json!({
            "name": "restore_text",
            "description": "Resolve placeholders in a snippet back to their real values. \
                This puts sensitive data into the conversation, so prefer write_restored or \
                edit_restored, which restore straight to disk instead.",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"]
            }
        }));
    }
    tools
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(roots: Vec<PathBuf>) -> Server {
        Server::new(MappingStore::ephemeral(), Settings::default(), roots, false)
    }

    fn revealing_server() -> Server {
        Server::new(MappingStore::ephemeral(), Settings::default(), vec![], true)
    }

    /// The full detector set through the server's own read path, since the
    /// engine's unit tests only prove the detectors, not that the server wires
    /// them up. Every one of these values reached a model once, in an earlier
    /// design, so the assertion is that none of them appear in the output.
    #[test]
    fn read_masks_every_detector_kind_with_nothing_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hepsi.txt");
        std::fs::write(
            &path,
            "tckn: 10000000146\n\
             gecersiz_tckn: 12345678901\n\
             kart: 4111 1111 1111 1111\n\
             iban: TR33 0006 1005 9786 4578 4132 26\n\
             eposta: a.b@example.com\n\
             telefon: 0532 123 45 67\n\
             sifre: password: Gtts@2020\n\
             firma: Acme Holding\n",
        )
        .unwrap();

        let mut srv = Server::new(
            MappingStore::ephemeral(),
            Settings {
                custom_words: vec!["Acme Holding".to_string()],
                ..Settings::default()
            },
            vec![],
            false,
        );
        let out = srv
            .read_anonymized(&json!({"path": path.display().to_string()}))
            .unwrap();

        for secret in [
            "10000000146",
            "4111 1111 1111 1111",
            "TR33 0006 1005 9786 4578 4132 26",
            "a.b@example.com",
            "0532 123 45 67",
            "Gtts@2020",
            "Acme Holding",
        ] {
            assert!(!out.contains(secret), "`{secret}` survived masking: {out}");
        }
        for placeholder in [
            "TCKN_", "KART_", "IBAN_", "EPOSTA_", "TEL_", "SIFRE_", "OZEL_",
        ] {
            assert!(out.contains(placeholder), "missing {placeholder}: {out}");
        }
        // A number that fails its checksum is not a national ID, and masking it
        // would train the user to distrust the output.
        assert!(out.contains("12345678901"), "{out}");
    }

    /// Read then write must reproduce the file byte for byte. Anything less
    /// means the round trip quietly corrupts documents.
    #[test]
    fn a_full_round_trip_reproduces_the_original_file_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.txt");
        let dst = dir.path().join("out.txt");
        let original = "tckn: 10000000146\niban: TR33 0006 1005 9786 4578 4132 26\n\
                        eposta: a.b@example.com\nsade: hassas bir sey yok\n";
        std::fs::write(&src, original).unwrap();

        let mut srv = server(vec![]);
        let masked = srv
            .read_anonymized(&json!({"path": src.display().to_string()}))
            .unwrap();
        let body = masked.split("\n\n(").next().unwrap().to_string();
        srv.write_restored(&json!({
            "path": dst.display().to_string(),
            "content": body,
        }))
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(&dst).unwrap().trim_end(),
            original.trim_end()
        );
    }

    #[test]
    fn read_returns_masked_content_and_never_the_real_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kayit.csv");
        std::fs::write(&path, "ad,tckn\nAli,10000000146\n").unwrap();

        let mut srv = server(vec![]);
        let out = srv
            .read_anonymized(&json!({"path": path.display().to_string()}))
            .unwrap();
        assert!(!out.contains("10000000146"), "{out}");
        assert!(out.contains("TCKN_1"), "{out}");
        assert!(out.contains("safe to quote"), "{out}");
    }

    #[test]
    fn write_restores_placeholders_to_real_values_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.csv");
        let dst = dir.path().join("out.csv");
        std::fs::write(&src, "ad,tckn\nAli,10000000146\n").unwrap();

        let mut srv = server(vec![]);
        let masked = srv
            .read_anonymized(&json!({"path": src.display().to_string()}))
            .unwrap();
        // The agent edits the masked text it was given and saves it.
        let edited = masked
            .split("\n\n(")
            .next()
            .unwrap()
            .replace("Ali", "Ali Veli");
        let report = srv
            .write_restored(&json!({"path": dst.display().to_string(), "content": edited}))
            .unwrap();

        let on_disk = std::fs::read_to_string(&dst).unwrap();
        assert!(on_disk.contains("10000000146"), "{on_disk}");
        assert!(on_disk.contains("Ali Veli"), "{on_disk}");
        assert!(!on_disk.contains("TCKN_"), "{on_disk}");
        assert!(report.contains("1 placeholder restored"), "{report}");
    }

    #[test]
    fn edit_matches_a_masked_old_string_against_the_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kayit.csv");
        std::fs::write(&path, "ad,tckn\nAli,10000000146\n").unwrap();

        let mut srv = server(vec![]);
        srv.read_anonymized(&json!({"path": path.display().to_string()}))
            .unwrap();
        // The agent only ever saw TCKN_1, so that is what it quotes.
        srv.edit_restored(&json!({
            "path": path.display().to_string(),
            "old_string": "Ali,TCKN_1",
            "new_string": "Ali Veli,TCKN_1",
        }))
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "ad,tckn\nAli Veli,10000000146\n"
        );
    }

    #[test]
    fn edit_refuses_an_ambiguous_match_instead_of_guessing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.txt");
        std::fs::write(&path, "satır\nsatır\n").unwrap();
        let mut srv = server(vec![]);
        let err = srv
            .edit_restored(&json!({
                "path": path.display().to_string(),
                "old_string": "satır",
                "new_string": "yeni",
            }))
            .unwrap_err();
        assert!(err.to_string().contains("2 times"), "{err}");
    }

    /// The separate-user deployment rests on the server being the only identity
    /// that can read the file. Creating a user account needs a sudo password,
    /// so what is verified here is the half that does not: when the server
    /// cannot read a file, it fails with the reason and without inventing
    /// content. Whether the *agent* is excluded is a filesystem property the
    /// operator configures, not something this code can assert.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_file_fails_with_its_reason_and_no_content() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gizli.csv");
        std::fs::write(&path, "tckn 10000000146").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let mut srv = server(vec![]);
        let result = srv.read_anonymized(&json!({"path": path.display().to_string()}));

        // Running as root would read it regardless, which is a real deployment
        // mistake but not what this test is about.
        if let Err(err) = result {
            let rendered = format!("{err:#}");
            assert!(
                !rendered.contains("10000000146"),
                "a failure must not leak the content it could not read: {rendered}"
            );
            assert!(rendered.contains("reading"), "{rendered}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// The bypass this guard exists for: `write_restored` to /dev/stdout put
    /// the real national ID into the JSON-RPC stream the model reads.
    #[test]
    fn restoring_to_a_device_path_is_refused() {
        let mut srv = server(vec![]);
        let placeholder = srv
            .store
            .placeholder_for("10000000146", crate::anonymize::Kind::NationalId);

        for device in ["/dev/stdout", "/dev/stderr", "/dev/fd/1"] {
            let err = srv
                .write_restored(&json!({"path": device, "content": placeholder.clone()}))
                .unwrap_err();
            let rendered = format!("{err:#}");
            assert!(
                !rendered.contains("10000000146"),
                "the refusal must not itself leak: {rendered}"
            );
            assert!(rendered.contains("device"), "{rendered}");
        }
    }

    #[test]
    fn editing_a_device_path_is_refused_too() {
        let mut srv = server(vec![]);
        assert!(
            srv.edit_restored(&json!({
                "path": "/dev/stdout",
                "old_string": "a",
                "new_string": "b",
            }))
            .is_err(),
            "every write path must share the guard"
        );
    }

    #[test]
    fn a_normal_file_that_does_not_exist_yet_is_still_writable() {
        // The guard must not break creating new files, which is the common case.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("yeni.txt");
        let mut srv = server(vec![]);
        srv.write_restored(&json!({
            "path": path.display().to_string(),
            "content": "merhaba",
        }))
        .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "merhaba");
    }

    #[test]
    fn paths_outside_the_allowed_roots_are_refused() {
        let allowed = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let outside = other.path().join("secret.txt");
        std::fs::write(&outside, "veri").unwrap();

        let mut srv = server(vec![allowed.path().to_path_buf()]);
        let err = srv
            .read_anonymized(&json!({"path": outside.display().to_string()}))
            .unwrap_err();
        assert!(
            err.to_string().contains("outside the allowed roots"),
            "{err}"
        );
    }

    #[test]
    fn a_traversal_path_cannot_escape_an_allowed_root() {
        let allowed = tempfile::tempdir().unwrap();
        let escape = allowed.path().join("../../etc/hosts");
        let mut srv = server(vec![allowed.path().to_path_buf()]);
        assert!(
            srv.read_anonymized(&json!({"path": escape.display().to_string()}))
                .is_err(),
            "`..` must not walk out of an allowed root"
        );
    }

    #[test]
    fn restore_snippet_reports_when_it_knows_nothing() {
        let srv = revealing_server();
        let out = srv.restore_snippet(&json!({"text": "TCKN_9999"})).unwrap();
        assert!(out.contains("no known placeholders"), "{out}");
    }

    /// Found in a live session: asked "show me the tckn", the agent read the
    /// file masked and then called restore_text to print the real value.
    #[test]
    fn revealing_a_value_into_the_conversation_is_refused_by_default() {
        let mut srv = server(vec![]);
        let placeholder = srv
            .store
            .placeholder_for("10000000146", crate::anonymize::Kind::NationalId);
        let err = srv
            .restore_snippet(&json!({"text": placeholder}))
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("disabled"), "{message}");
        assert!(
            !message.contains("10000000146"),
            "the refusal must not leak the value it refused: {message}"
        );
    }

    #[test]
    fn the_reveal_tool_is_hidden_unless_it_is_enabled() {
        let names = |allow| {
            tool_definitions(allow)
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d["name"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        assert!(!names(false).contains(&"restore_text".to_string()));
        assert!(names(true).contains(&"restore_text".to_string()));
    }

    #[test]
    fn masking_still_works_with_the_reveal_tool_disabled() {
        // Disabling the escape hatch must not disable the feature itself.
        let mut srv = server(vec![]);
        let out = srv
            .anonymize_snippet(&json!({"text": "tckn 10000000146"}))
            .unwrap();
        assert!(out.contains("TCKN_1"), "{out}");
    }

    #[test]
    fn dispatch_rejects_an_unknown_tool() {
        let mut srv = server(vec![]);
        let err = srv.dispatch("delete_everything", &json!({})).unwrap_err();
        assert!(err.to_string().contains("unknown tool"), "{err}");
    }

    #[test]
    fn missing_arguments_are_reported_not_defaulted() {
        let mut srv = server(vec![]);
        let err = srv.dispatch("read_anonymized", &json!({})).unwrap_err();
        assert!(err.to_string().contains("`path`"), "{err}");
    }

    #[test]
    fn tool_definitions_expose_every_dispatchable_tool() {
        let defs = tool_definitions(true);
        let names: Vec<&str> = defs
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "read_anonymized",
                "write_restored",
                "edit_restored",
                "anonymize_text",
                "restore_text"
            ]
        );
        // A schema the model cannot read is a tool it will not call correctly.
        for def in defs.as_array().unwrap() {
            assert!(def["inputSchema"]["required"].is_array(), "{def}");
            assert!(def["description"].as_str().unwrap().len() > 40, "{def}");
        }
    }
}
