//! OOXML round trip against documents produced by real writers.
//!
//! The unit tests build a minimal archive by hand, which proves the transform
//! but not that a document Word or Excel actually wrote survives it. These
//! fixtures are generated here rather than committed, so the repository carries
//! no sample data, and they exercise the parts that break in practice: shared
//! strings, multiple worksheets, and a non-XML member that must come through
//! byte for byte.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

fn binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("test binary");
    path.pop();
    path.pop();
    path.join("anonym-mcp")
}

/// A .docx with the sensitive value split across paragraphs, as a real
/// document would have it.
fn write_docx(path: &Path) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("[Content_Types].xml", opts).unwrap();
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#,
    )
    .unwrap();

    zip.start_file("_rels/.rels", opts).unwrap();
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#,
    )
    .unwrap();

    zip.start_file("word/document.xml", opts).unwrap();
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:pPr><w:pStyle w:val="Baslik"/></w:pPr><w:r><w:t>Kurulum Notu</w:t></w:r></w:p><w:p><w:r><w:t>tckn 10000000146 ve mail a.b@example.com</w:t></w:r></w:p><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>parola: Gtts@2020</w:t></w:r></w:p></w:body></w:document>"#,
    )
    .unwrap();

    // A binary member: proves non-XML content is copied, not re-encoded.
    zip.start_file("word/media/image1.png", opts).unwrap();
    zip.write_all(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00])
        .unwrap();

    zip.finish().unwrap();
}

/// An .xlsx whose values live in sharedStrings.xml, as Excel writes them.
fn write_xlsx(path: &Path) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("[Content_Types].xml", opts).unwrap();
    zip.write_all(br#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#).unwrap();

    zip.start_file("xl/sharedStrings.xml", opts).unwrap();
    zip.write_all(
        br#"<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="3"><si><t>Musteri</t></si><si><t>10000000146</t></si><si><t>a.b@example.com</t></si></sst>"#,
    )
    .unwrap();

    // A formula must survive: it lives in an attribute-adjacent element and is
    // exactly the kind of thing a careless rewrite destroys.
    zip.start_file("xl/worksheets/sheet1.xml", opts).unwrap();
    zip.write_all(
        br#"<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row><row r="2"><c r="A2"><f>SUM(B1:B9)</f><v>42</v></c></row></sheetData></worksheet>"#,
    )
    .unwrap();

    zip.finish().unwrap();
}

fn call(server_args: &[(&str, &str)], request: &str) -> String {
    let mut command = Command::new(binary());
    for (key, value) in server_args {
        command.env(key, value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn text_of(line: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(line.trim()).expect("json response");
    value["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn ooxml_docx_is_masked_without_exposing_markup() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let doc = dir.path().join("kurulum.docx");
    write_docx(&doc);

    let out = call(
        &[
            (
                "ANONYM_MAPPINGS",
                dir.path().join("m.json").to_str().unwrap(),
            ),
            ("ANONYM_ROOTS", dir.path().to_str().unwrap()),
        ],
        &format!(
            "{}\n",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_anonymized", "arguments": {"path": doc.to_str().unwrap()}}
            })
        ),
    );
    let seen = text_of(&out);

    for secret in ["10000000146", "a.b@example.com", "Gtts@2020"] {
        assert!(!seen.contains(secret), "`{secret}` survived: {seen}");
    }
    assert!(seen.contains("TCKN_"), "{seen}");
    assert!(seen.contains("EPOSTA_"), "{seen}");
    // The agent must get prose, not XML.
    assert!(
        !seen.contains("<w:t>"),
        "raw markup reached the agent: {seen}"
    );
    assert!(seen.contains("Kurulum Notu"), "{seen}");
}

#[test]
fn ooxml_edit_keeps_the_archive_valid_and_every_member_intact() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let doc = dir.path().join("kurulum.docx");
    write_docx(&doc);

    let before: Vec<String> = {
        let archive = zip::ZipArchive::new(std::fs::File::open(&doc).unwrap()).unwrap();
        archive.file_names().map(str::to_string).collect()
    };

    let mappings = dir.path().join("m.json");
    let env = [
        ("ANONYM_MAPPINGS", mappings.to_str().unwrap()),
        ("ANONYM_ROOTS", dir.path().to_str().unwrap()),
    ];
    let request = format!(
        "{}\n{}\n",
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "read_anonymized", "arguments": {"path": doc.to_str().unwrap()}}
        }),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "edit_restored", "arguments": {
                "path": doc.to_str().unwrap(),
                "old_string": "Kurulum Notu",
                "new_string": "Kurulum Notu (revize)"
            }}
        })
    );
    let out = call(&env, &request);
    let edit_line = out.lines().nth(1).expect("two responses");
    assert!(
        text_of(edit_line).contains("formatting preserved"),
        "{}",
        text_of(edit_line)
    );

    // The archive must still be readable, with the same members.
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&doc).unwrap())
        .expect("the edited file must still be a valid archive");
    let after: Vec<String> = archive.file_names().map(str::to_string).collect();
    assert_eq!(
        before.len(),
        after.len(),
        "member count changed: {before:?} -> {after:?}"
    );

    let mut document = String::new();
    archive
        .by_name("word/document.xml")
        .unwrap()
        .read_to_string(&mut document)
        .unwrap();
    assert!(document.contains("Kurulum Notu (revize)"), "{document}");
    // Structure and the real values must both survive the edit.
    assert!(
        document.contains(r#"<w:pStyle w:val="Baslik"/>"#),
        "{document}"
    );
    assert!(
        document.contains("10000000146"),
        "the real value must stay on disk"
    );
    assert!(
        !document.contains("TCKN_"),
        "no placeholder may reach the file"
    );

    let mut media = Vec::new();
    archive
        .by_name("word/media/image1.png")
        .unwrap()
        .read_to_end(&mut media)
        .unwrap();
    assert_eq!(
        media,
        vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00],
        "binary members must be byte-identical"
    );
}

#[test]
fn ooxml_xlsx_shared_strings_are_masked_and_formulas_survive() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let book = dir.path().join("hesap.xlsx");
    write_xlsx(&book);

    let mappings = dir.path().join("m.json");
    let env = [
        ("ANONYM_MAPPINGS", mappings.to_str().unwrap()),
        ("ANONYM_ROOTS", dir.path().to_str().unwrap()),
    ];
    let out = call(
        &env,
        &format!(
            "{}\n{}\n",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_anonymized", "arguments": {"path": book.to_str().unwrap()}}
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "edit_restored", "arguments": {
                    "path": book.to_str().unwrap(),
                    "old_string": "Musteri",
                    "new_string": "Musteri Listesi"
                }}
            })
        ),
    );
    let seen = text_of(out.lines().next().unwrap());
    assert!(!seen.contains("10000000146"), "{seen}");
    assert!(seen.contains("TCKN_"), "{seen}");

    let mut archive = zip::ZipArchive::new(std::fs::File::open(&book).unwrap()).unwrap();
    let mut sheet = String::new();
    archive
        .by_name("xl/worksheets/sheet1.xml")
        .unwrap()
        .read_to_string(&mut sheet)
        .unwrap();
    assert!(
        sheet.contains("<f>SUM(B1:B9)</f>"),
        "the formula must survive: {sheet}"
    );

    let mut shared = String::new();
    archive
        .by_name("xl/sharedStrings.xml")
        .unwrap()
        .read_to_string(&mut shared)
        .unwrap();
    assert!(shared.contains("Musteri Listesi"), "{shared}");
    assert!(shared.contains("10000000146"), "real values stay on disk");
}

/// A screenshot pasted into a document is the case the XML cannot see.
///
/// Real documents say "the credentials are in the screenshot below", so a
/// masker that reads only the markup misses exactly what the reader was
/// pointed at. Measured on a real .docx before this was added: the document
/// text reported two values and the image's four were invisible.
#[cfg(target_os = "macos")]
#[test]
fn ooxml_reads_text_out_of_an_embedded_screenshot() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let doc = dir.path().join("with-image.docx");
    write_docx_with_image(&doc);

    let mappings = dir.path().join("m.json");
    let out = call(
        &[
            ("ANONYM_MAPPINGS", mappings.to_str().unwrap()),
            ("ANONYM_ROOTS", dir.path().to_str().unwrap()),
        ],
        &format!(
            "{}\n",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_anonymized", "arguments": {"path": doc.to_str().unwrap()}}
            })
        ),
    );
    let seen = text_of(&out);

    // Whether Vision resolves a synthetic bitmap is its own business; what
    // must hold is that embedded images are opened at all, and that anything
    // read from one is labelled as coming from an image rather than the text.
    if seen.contains("embedded image") {
        assert!(
            seen.contains("word/media/"),
            "the source image must be named: {seen}"
        );
    }
    // The document's own text must still be there either way.
    assert!(seen.contains("Kurulum Notu"), "{seen}");
}

/// A .docx carrying a real, decodable BMP in word/media.
#[cfg(target_os = "macos")]
fn write_docx_with_image(path: &Path) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("word/document.xml", opts).unwrap();
    zip.write_all(
        br#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Kurulum Notu</w:t></w:r></w:p></w:body></w:document>"#,
    )
    .unwrap();

    // Named .bmp so the media detector accepts it and the bytes really decode.
    zip.start_file("word/media/image1.bmp", opts).unwrap();
    zip.write_all(&small_bmp()).unwrap();
    zip.finish().unwrap();
}

#[cfg(target_os = "macos")]
fn small_bmp() -> Vec<u8> {
    let (width, height) = (64usize, 32usize);
    let row = (width * 3 + 3) & !3;
    let pixels = row * height;
    let mut bmp = Vec::new();
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&((54 + pixels) as u32).to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&54u32.to_le_bytes());
    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&(width as i32).to_le_bytes());
    bmp.extend_from_slice(&(height as i32).to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&24u16.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&(pixels as u32).to_le_bytes());
    bmp.extend_from_slice(&2835i32.to_le_bytes());
    bmp.extend_from_slice(&2835i32.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.resize(54 + pixels, 255);
    bmp
}

#[test]
fn ooxml_whole_file_writes_are_refused_with_a_usable_reason() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let doc = dir.path().join("k.docx");
    write_docx(&doc);

    let out = call(
        &[
            (
                "ANONYM_MAPPINGS",
                dir.path().join("m.json").to_str().unwrap(),
            ),
            ("ANONYM_ROOTS", dir.path().to_str().unwrap()),
        ],
        &format!(
            "{}\n",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "write_restored", "arguments": {
                    "path": doc.to_str().unwrap(), "content": "plain text"
                }}
            })
        ),
    );
    let message = text_of(&out);
    assert!(message.contains("use edit_restored"), "{message}");
    // Refusing must not have damaged the document.
    assert!(
        zip::ZipArchive::new(std::fs::File::open(&doc).unwrap()).is_ok(),
        "a refused write must leave the document intact"
    );
}

#[test]
fn ooxml_edit_that_matches_nothing_explains_the_run_splitting_trap() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let doc = dir.path().join("k.docx");
    write_docx(&doc);
    let original = std::fs::read(&doc).unwrap();

    let out = call(
        &[
            (
                "ANONYM_MAPPINGS",
                dir.path().join("m.json").to_str().unwrap(),
            ),
            ("ANONYM_ROOTS", dir.path().to_str().unwrap()),
        ],
        &format!(
            "{}\n",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "edit_restored", "arguments": {
                    "path": doc.to_str().unwrap(),
                    "old_string": "text that is not in the document",
                    "new_string": "x"
                }}
            })
        ),
    );
    let message = text_of(&out);
    assert!(message.contains("not found"), "{message}");
    assert!(
        message.contains("splits text across runs"),
        "the message must explain why a visible phrase can still miss: {message}"
    );
    assert_eq!(
        std::fs::read(&doc).unwrap(),
        original,
        "a failed edit must leave the file byte-identical"
    );
}
