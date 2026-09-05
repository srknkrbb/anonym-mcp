//! Formats whose text is not text: images and PDFs.
//!
//! Masking these is one-way. An image's words are pixels and a PDF's are bound
//! to a layout, so there is nothing to substitute a placeholder back into. Two
//! failures matter here and both were observed before they were fixed:
//!
//!  * Editing an image failed with "stream did not contain valid UTF-8", which
//!    tells an agent nothing about why the request made no sense.
//!  * A scanned PDF extracted to an empty string, which is indistinguishable
//!    from a clean document, so a page full of credentials was reported as
//!    having nothing sensitive in it.

use std::io::Write;
use std::process::{Command, Stdio};

fn binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("test binary");
    path.pop();
    path.pop();
    path.join("anonym-mcp")
}

fn call(env: &[(&str, &str)], request: &str) -> String {
    let mut command = Command::new(binary());
    for (key, value) in env {
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
    let value: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
    value["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// A valid single-page PDF whose only content is a page number: a stand-in for
/// a scan, since its text layer holds essentially nothing.
fn near_empty_pdf() -> Vec<u8> {
    build_pdf("1")
}

fn build_pdf(body: &str) -> Vec<u8> {
    let stream = format!("BT /F1 12 Tf 40 700 Td ({body}) Tj ET");
    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();
    let push = |pdf: &mut String, offsets: &mut Vec<usize>, object: String| {
        offsets.push(pdf.len());
        pdf.push_str(&object);
    };
    push(
        &mut pdf,
        &mut offsets,
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".into(),
    );
    push(
        &mut pdf,
        &mut offsets,
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".into(),
    );
    push(&mut pdf, &mut offsets, "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n".into());
    push(
        &mut pdf,
        &mut offsets,
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{stream}\nendstream\nendobj\n",
            stream.len()
        ),
    );
    push(
        &mut pdf,
        &mut offsets,
        "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".into(),
    );
    let xref_at = pdf.len();
    pdf.push_str(&format!(
        "xref\n0 {}\n0000000000 65535 f \n",
        offsets.len() + 1
    ));
    for offset in &offsets {
        pdf.push_str(&format!("{offset:010} 00000 n \n"));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
        offsets.len() + 1
    ));
    pdf.into_bytes()
}

/// A small but genuinely decodable BMP.
fn write_bmp(path: &std::path::Path) {
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
    std::fs::write(path, bmp).unwrap();
}

#[test]
fn pixel_formats_refuse_edits_with_a_reason_an_agent_can_act_on() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("shot.png");
    write_bmp(&image); // content need not be a real PNG; the guard is by path
    let mappings = dir.path().join("m.json");
    let env = [
        ("ANONYM_MAPPINGS", mappings.to_str().unwrap()),
        ("ANONYM_ROOTS", dir.path().to_str().unwrap()),
    ];

    let out = call(
        &env,
        &format!(
            "{}\n",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "edit_restored", "arguments": {
                    "path": image.to_str().unwrap(), "old_string": "a", "new_string": "b"
                }}
            })
        ),
    );
    let message = text_of(&out);
    assert!(message.contains("image"), "{message}");
    assert!(
        message.contains("pixels") && message.contains("one-way"),
        "the refusal must explain why, not just refuse: {message}"
    );
    assert!(
        !message.contains("valid UTF-8"),
        "the old opaque error must not come back: {message}"
    );
}

#[test]
fn pixel_formats_refuse_whole_file_writes_too() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let pdf = dir.path().join("report.pdf");
    std::fs::write(&pdf, build_pdf("Musteri kaydi tckn 10000000146")).unwrap();
    let original = std::fs::read(&pdf).unwrap();
    let mappings = dir.path().join("m.json");
    let env = [
        ("ANONYM_MAPPINGS", mappings.to_str().unwrap()),
        ("ANONYM_ROOTS", dir.path().to_str().unwrap()),
    ];

    let out = call(
        &env,
        &format!(
            "{}\n",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "write_restored", "arguments": {
                    "path": pdf.to_str().unwrap(), "content": "plain text"
                }}
            })
        ),
    );
    let message = text_of(&out);
    assert!(message.contains("PDF"), "{message}");
    assert!(message.contains("layout"), "{message}");
    assert_eq!(
        std::fs::read(&pdf).unwrap(),
        original,
        "a refused write must leave the document untouched"
    );
}

#[test]
fn a_pdf_with_a_text_layer_is_masked_normally() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let pdf = dir.path().join("report.pdf");
    std::fs::write(
        &pdf,
        build_pdf("Musteri kaydi tckn 10000000146 eposta a.b@example.com"),
    )
    .unwrap();
    let mappings = dir.path().join("m.json");
    let env = [
        ("ANONYM_MAPPINGS", mappings.to_str().unwrap()),
        ("ANONYM_ROOTS", dir.path().to_str().unwrap()),
    ];

    let out = call(
        &env,
        &format!(
            "{}\n",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_anonymized", "arguments": {"path": pdf.to_str().unwrap()}}
            })
        ),
    );
    let seen = text_of(&out);
    assert!(!seen.contains("10000000146"), "{seen}");
    assert!(seen.contains("TCKN_"), "{seen}");
    // A text-layer PDF must not carry the OCR caveat: it would train the reader
    // to ignore a warning that matters on scans.
    assert!(
        !seen.contains("no text layer"),
        "a text PDF must not claim it was OCR'd: {seen}"
    );
}

/// The whole point of the PDF work: a scan must never read as a clean file.
#[test]
fn a_scanned_pdf_is_never_reported_as_having_nothing_in_it() {
    if !binary().exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let pdf = dir.path().join("scan.pdf");
    std::fs::write(&pdf, near_empty_pdf()).unwrap();
    let mappings = dir.path().join("m.json");
    let env = [
        ("ANONYM_MAPPINGS", mappings.to_str().unwrap()),
        ("ANONYM_ROOTS", dir.path().to_str().unwrap()),
    ];

    let out = call(
        &env,
        &format!(
            "{}\n",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_anonymized", "arguments": {"path": pdf.to_str().unwrap()}}
            })
        ),
    );
    let seen = text_of(&out);

    // Whether OCR found anything depends on the platform. What must never
    // happen is a bare "nothing sensitive found" with no explanation of why
    // the document looked empty.
    let claims_clean = seen.contains("no sensitive values found");
    let explains_why = seen.contains("no text layer") || seen.contains("OCR");
    assert!(
        !claims_clean || explains_why,
        "a document with no readable text must say so rather than reading as clean: {seen}"
    );
}
