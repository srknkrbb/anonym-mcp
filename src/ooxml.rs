//! OOXML (docx / xlsx / pptx) masking.
//!
//! These are zip archives of XML. Only the *text nodes* are transformed: tags,
//! attributes and everything else are copied through byte for byte, so
//! formatting, tables and formulas survive. Rewriting the XML wholesale, or
//! running the detectors over the raw markup, would corrupt documents and
//! mask things like style names that merely look like data.
//!
//! The archive is rebuilt rather than edited in place, because a zip entry
//! whose length changes cannot be patched without rewriting the central
//! directory anyway.

use anyhow::{Context, Result, bail};
use quick_xml::events::Event;
use quick_xml::{Reader, Writer};
use std::io::{Cursor, Read, Write};
use std::path::Path;

/// Extensions handled here.
pub const EXTENSIONS: &[&str] = &[
    "docx", "xlsx", "pptx", "dotx", "xltx", "potx", "xlsm", "docm", "pptm",
];

/// Archive members that carry user text.
///
/// Deliberately narrow. `docProps/app.xml` holds the authoring application's
/// own metadata and is left alone; `docProps/core.xml` holds author names and
/// is included. Anything not listed is copied through untouched.
const TEXT_BEARING: &[&str] = &[
    "word/",
    "xl/sharedStrings.xml",
    "xl/worksheets/",
    "xl/charts/",
    "ppt/slides/",
    "ppt/notesSlides/",
    "docProps/core.xml",
];

/// Archive members holding embedded pictures.
///
/// A screenshot pasted into a Word document keeps its passwords as pixels, so
/// the XML says nothing about them. "See the credentials in the screenshot
/// below" is a real sentence in real documents, and without reading these the
/// masking would confidently miss exactly what the reader was pointed at.
const MEDIA_PREFIXES: &[&str] = &["word/media/", "xl/media/", "ppt/media/"];

fn is_media_image(name: &str) -> bool {
    if !MEDIA_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    [".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif"]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

pub fn is_ooxml(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn carries_text(name: &str) -> bool {
    name.ends_with(".xml")
        && TEXT_BEARING
            .iter()
            .any(|prefix| name.starts_with(prefix) || name == *prefix)
}

/// Apply `transform` to every text node in one XML document.
///
/// Whitespace-only nodes are passed over: OOXML uses them for indentation, and
/// handing them to a detector wastes work and risks touching layout.
pub fn transform_text_nodes<F>(xml: &str, mut transform: F) -> Result<String>
where
    F: FnMut(&str) -> String,
{
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Text(event)) => {
                let original = event.unescape()?.into_owned();
                if original.trim().is_empty() {
                    writer.write_event(Event::Text(event))?;
                } else {
                    let replaced = transform(&original);
                    writer
                        .write_event(Event::Text(quick_xml::events::BytesText::new(&replaced)))?;
                }
            }
            Ok(event) => writer.write_event(event)?,
            Err(err) => bail!("XML parse error: {err}"),
        }
        buf.clear();
    }
    Ok(String::from_utf8(writer.into_inner().into_inner())?)
}

/// All user-visible text in the document, for detection or preview.
pub fn extract_text(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("{} is not a valid OOXML archive", path.display()))?;

    let mut collected = String::new();
    let mut media = Vec::new();

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_string();

        if is_media_image(&name) {
            let mut bytes = Vec::new();
            if entry.read_to_end(&mut bytes).is_ok() {
                media.push((name, bytes));
            }
            continue;
        }

        if !carries_text(&name) {
            continue;
        }
        let mut xml = String::new();
        if entry.read_to_string(&mut xml).is_err() {
            continue; // not UTF-8 text; not ours to read
        }
        transform_text_nodes(&xml, |text| {
            collected.push_str(text);
            collected.push('\n');
            text.to_string()
        })?;
    }

    // Embedded pictures are read last, and labelled, so the agent can tell
    // "this came out of a screenshot" from "this was written in the document".
    for (name, bytes) in media {
        if let Some(text) = ocr_media(&name, &bytes)
            && !text.trim().is_empty()
        {
            collected.push_str(&format!("\n[text recognised in embedded image {name}]\n"));
            collected.push_str(&text);
            collected.push('\n');
        }
    }

    Ok(collected)
}

/// OCR one embedded picture, or None when that is not possible here.
fn ocr_media(name: &str, bytes: &[u8]) -> Option<String> {
    if !crate::ocr::available() {
        return None;
    }
    // Vision reads from a file, so the bytes go to a temporary one that is
    // removed immediately: it holds the user's data and must not linger.
    let extension = std::path::Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("png");
    // One directory per call, not per process: two images being read at the
    // same time would otherwise share a directory and the first to finish
    // would delete it from under the second.
    let dir = std::env::temp_dir().join(format!("anonym-media-{}-{}", std::process::id(), uniq()));
    std::fs::create_dir_all(&dir).ok()?;
    let scratch = dir.join(format!("image.{extension}"));
    std::fs::write(&scratch, bytes).ok()?;
    let text = crate::ocr::recognize_text(&scratch).ok();
    // Remove the file first: the directory cannot go while it still holds one.
    let _ = std::fs::remove_file(&scratch);
    let _ = std::fs::remove_dir(&dir);
    text
}

/// A per-call suffix, so two images in one document cannot collide.
fn uniq() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Rewrite `source` into `dest`, transforming text nodes with `transform`.
///
/// Entries that do not carry text are copied verbatim, which is what keeps
/// embedded images, themes and relationship files intact.
pub fn transform_document<F>(source: &Path, dest: &Path, mut transform: F) -> Result<()>
where
    F: FnMut(&str) -> String,
{
    let file =
        std::fs::File::open(source).with_context(|| format!("opening {}", source.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("{} is not a valid OOXML archive", source.display()))?;

    let mut out = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(Cursor::new(&mut out));
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            let name = entry.name().to_string();
            // Preserve the original compression: switching a stored entry to
            // deflate can break readers that seek into the archive.
            let options: zip::write::FileOptions<'_, ()> =
                zip::write::FileOptions::default().compression_method(entry.compression());

            if entry.is_dir() {
                writer.add_directory(&name, options)?;
                continue;
            }

            let mut raw = Vec::new();
            entry.read_to_end(&mut raw)?;

            let payload = if carries_text(&name) {
                match String::from_utf8(raw.clone()) {
                    Ok(xml) => transform_text_nodes(&xml, &mut transform)?.into_bytes(),
                    Err(_) => raw,
                }
            } else {
                raw
            };

            writer.start_file(&name, options)?;
            writer.write_all(&payload)?;
        }
        writer.finish()?;
    }

    std::fs::write(dest, &out).with_context(|| format!("writing {}", dest.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally real .docx.
    fn write_docx(path: &Path, body: &str) {
        let file = std::fs::File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        writer.start_file("[Content_Types].xml", options).unwrap();
        writer
            .write_all(br#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#)
            .unwrap();

        writer.start_file("word/document.xml", options).unwrap();
        writer
            .write_all(
                format!(
                    r#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{body}</w:t></w:r></w:p></w:body></w:document>"#
                )
                .as_bytes(),
            )
            .unwrap();

        // A non-text member that must survive untouched.
        writer.start_file("word/media/image1.png", options).unwrap();
        writer
            .write_all(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a])
            .unwrap();

        writer.finish().unwrap();
    }

    #[test]
    fn ooxml_extensions_are_recognised() {
        assert!(is_ooxml(Path::new("a.docx")));
        assert!(is_ooxml(Path::new("a.XLSX")));
        assert!(!is_ooxml(Path::new("a.txt")));
        assert!(!is_ooxml(Path::new("a")));
    }

    #[test]
    fn ooxml_transforms_text_nodes_and_leaves_markup_alone() {
        let xml = r#"<w:p><w:r><w:t>tckn 10000000146</w:t></w:r></w:p>"#;
        let out = transform_text_nodes(xml, |t| t.replace("10000000146", "TCKN_1")).unwrap();
        assert!(out.contains("TCKN_1"), "{out}");
        // The tags must be byte-identical, or the document stops opening.
        assert!(out.contains("<w:p><w:r><w:t>"), "{out}");
        assert!(!out.contains("10000000146"), "{out}");
    }

    #[test]
    fn ooxml_never_transforms_attributes_or_tag_names() {
        // A style id that happens to look like data must not be masked: it is
        // markup, not user text.
        let xml = r#"<w:p w:rsidR="10000000146"><w:t>ordinary</w:t></w:p>"#;
        let out = transform_text_nodes(xml, |_| "MASKED".to_string()).unwrap();
        assert!(out.contains(r#"w:rsidR="10000000146""#), "{out}");
        assert!(out.contains("MASKED"), "{out}");
    }

    #[test]
    fn ooxml_leaves_indentation_whitespace_untouched() {
        let xml = "<a>\n  <b>text</b>\n</a>";
        let mut seen = Vec::new();
        let out = transform_text_nodes(xml, |t| {
            seen.push(t.to_string());
            t.to_string()
        })
        .unwrap();
        assert_eq!(seen, vec!["text".to_string()], "only real text is offered");
        assert_eq!(out, xml, "whitespace-only nodes pass through unchanged");
    }

    #[test]
    fn ooxml_extracts_only_text_bearing_members() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.docx");
        write_docx(&path, "tckn 10000000146");
        let text = extract_text(&path).unwrap();
        assert!(text.contains("10000000146"), "{text}");
        // [Content_Types].xml is not text-bearing, so its markup never appears.
        assert!(!text.contains("schemas.openxmlformats"), "{text}");
    }

    #[test]
    fn ooxml_rewrites_a_document_and_keeps_other_members() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("in.docx");
        let dest = dir.path().join("out.docx");
        write_docx(&source, "tckn 10000000146");

        transform_document(&source, &dest, |t| t.replace("10000000146", "TCKN_1")).unwrap();

        let rewritten = std::fs::File::open(&dest).unwrap();
        let mut archive = zip::ZipArchive::new(rewritten).unwrap();
        let names: Vec<String> = archive.file_names().map(str::to_string).collect();
        assert!(
            names.contains(&"word/media/image1.png".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"[Content_Types].xml".to_string()),
            "{names:?}"
        );

        let mut document = String::new();
        archive
            .by_name("word/document.xml")
            .unwrap()
            .read_to_string(&mut document)
            .unwrap();
        assert!(document.contains("TCKN_1"), "{document}");
        assert!(!document.contains("10000000146"), "{document}");

        let mut media = Vec::new();
        archive
            .by_name("word/media/image1.png")
            .unwrap()
            .read_to_end(&mut media)
            .unwrap();
        assert_eq!(
            media,
            vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a],
            "media must be byte-identical"
        );
    }

    #[test]
    fn ooxml_recognises_embedded_media_by_location_and_type() {
        assert!(is_media_image("word/media/image1.png"));
        assert!(is_media_image("xl/media/image2.JPG"));
        assert!(is_media_image("ppt/media/shot.bmp"));
        // Not media: an XML part, a font, and a picture outside a media folder.
        assert!(!is_media_image("word/document.xml"));
        assert!(!is_media_image("word/fonts/font1.odttf"));
        assert!(!is_media_image("customXml/image1.png"));
    }

    #[test]
    fn ooxml_leaves_no_temporary_copy_of_an_embedded_image_behind() {
        // The scratch file holds the user's picture, so it must not survive the
        // call that created it.
        //
        // Counting every anonym-media directory would be flaky: tests run in
        // parallel and another one may legitimately hold its own while this
        // one looks. So this checks the directories created *by this call*,
        // identified by the ones that appear and then must disappear.
        let before = temp_media_dirs();
        let _ = ocr_media("word/media/image1.png", &[0x42, 0x4d, 0x00]);
        let after = temp_media_dirs();

        let leaked: Vec<&String> = after.difference(&before).collect();
        assert!(
            leaked.is_empty(),
            "an embedded image was left in the temp directory: {leaked:?}"
        );
    }

    fn temp_media_dirs() -> std::collections::HashSet<String> {
        std::fs::read_dir(std::env::temp_dir())
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.starts_with("anonym-media-"))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Embedded pictures live under a different prefix in each format, and an
    /// audit found xlsx was the untested one: a spreadsheet saying "screenshot
    /// attached" carried its credentials in xl/media where nothing looked.
    #[test]
    fn ooxml_finds_embedded_media_in_word_excel_and_powerpoint() {
        for name in [
            "word/media/image1.png",
            "xl/media/image1.png",
            "ppt/media/image1.png",
        ] {
            assert!(is_media_image(name), "{name} must be treated as media");
        }
    }

    #[test]
    fn ooxml_extracts_media_from_a_spreadsheet_not_just_a_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("book.xlsx");
        {
            let file = std::fs::File::create(&path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zip.start_file("xl/sharedStrings.xml", opts).unwrap();
            zip.write_all(
                br#"<?xml version="1.0"?><sst><si><t>Ekran goruntusu ektedir</t></si></sst>"#,
            )
            .unwrap();
            zip.start_file("xl/media/image1.png", opts).unwrap();
            zip.write_all(&[0x89, b'P', b'N', b'G']).unwrap();
            zip.finish().unwrap();
        }

        // The spreadsheet's own text must come through; whether the stub image
        // yields any OCR text is Vision's business, not this test's.
        let text = extract_text(&path).unwrap();
        assert!(text.contains("Ekran goruntusu ektedir"), "{text}");
    }

    #[test]
    fn ooxml_rejects_a_file_that_is_not_an_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.docx");
        std::fs::write(&path, "this is not a zip").unwrap();
        let err = extract_text(&path).unwrap_err();
        assert!(
            err.to_string().contains("not a valid OOXML archive"),
            "{err}"
        );
    }
}
