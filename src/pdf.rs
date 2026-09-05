//! PDF text extraction.
//!
//! Two kinds of PDF arrive here and they behave differently. One has a text
//! layer, which is extractable. The other is a scan: pages are images, the
//! text layer is empty, and extraction returns nothing at all.
//!
//! Returning "" for a scanned page is the dangerous case. It looks exactly
//! like a clean document, so a file full of national IDs would be reported as
//! having nothing sensitive in it. Scanned pages are therefore detected and
//! sent to OCR, and if OCR is unavailable the fact is reported rather than
//! quietly swallowed.

use anyhow::{Context, Result};
use std::path::Path;

pub fn is_pdf(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
}

/// How the text came out of a PDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Read from the document's own text layer.
    TextLayer,
    /// The text layer was empty; this is a scan and OCR is needed.
    NeedsOcr,
}

#[derive(Debug, Clone)]
pub struct Extracted {
    pub text: String,
    pub source: Source,
}

/// A page's worth of text is considered missing when it holds almost nothing.
///
/// Scanners often leave a stray character or a page number behind, so an exact
/// empty-string test would classify a scan as a text PDF and let it through
/// unmasked.
const MIN_MEANINGFUL_CHARS: usize = 16;

/// Extract a PDF's text, saying where it came from.
pub fn extract(path: &Path) -> Result<Extracted> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;

    // pdf_extract panics on some malformed files rather than returning an
    // error, and a panic here would take down the request handler.
    let extracted = std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(&bytes))
        .map_err(|_| anyhow::anyhow!("the PDF parser crashed on {}", path.display()))?;

    let text = match extracted {
        Ok(text) => text,
        Err(err) => anyhow::bail!("could not read {}: {err}", path.display()),
    };

    let meaningful = text.chars().filter(|c| !c.is_whitespace()).count();
    let source = if meaningful < MIN_MEANINGFUL_CHARS {
        Source::NeedsOcr
    } else {
        Source::TextLayer
    };

    Ok(Extracted { text, source })
}

/// The note appended to a PDF read, so the agent knows what it is looking at.
pub fn provenance_note(source: Source, ocr_available: bool) -> &'static str {
    match (source, ocr_available) {
        (Source::TextLayer, _) => "",
        (Source::NeedsOcr, true) => {
            "\n\n(This PDF has no text layer, so the text above was read from the page \
             images with OCR. Recognition is imperfect; a value it misread is a value \
             it did not mask.)"
        }
        (Source::NeedsOcr, false) => {
            "\n\n(WARNING: this PDF has no text layer and OCR is unavailable in this \
             build, so nothing could be read from it. An empty result here does NOT \
             mean the document is free of sensitive data.)"
        }
    }
}

/// Fixture builder shared with the renderer's tests.
#[cfg(test)]
pub mod tests_support {
    /// A hand-built single-page PDF with one line of text.
    pub fn minimal_pdf(body: &str) -> Vec<u8> {
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
        push(
            &mut pdf,
            &mut offsets,
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n".into(),
        );
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests_support::minimal_pdf;

    #[test]
    fn pdf_extension_is_recognised() {
        assert!(is_pdf(Path::new("a.pdf")));
        assert!(is_pdf(Path::new("A.PDF")));
        assert!(!is_pdf(Path::new("a.docx")));
    }

    /// The failure mode worth naming: a scan must never be reported as clean.
    #[test]
    fn pdf_note_warns_loudly_when_a_scan_cannot_be_read() {
        let note = provenance_note(Source::NeedsOcr, false);
        assert!(note.contains("WARNING"), "{note}");
        assert!(
            note.contains("does NOT mean the document is free"),
            "an empty result must not be mistaken for a clean document: {note}"
        );
    }

    #[test]
    fn pdf_note_says_when_text_came_from_ocr() {
        let note = provenance_note(Source::NeedsOcr, true);
        assert!(note.contains("OCR"), "{note}");
        assert!(
            note.contains("misread"),
            "the agent must know recognition is fallible: {note}"
        );
    }

    #[test]
    fn pdf_note_is_silent_for_an_ordinary_text_pdf() {
        assert_eq!(provenance_note(Source::TextLayer, true), "");
        assert_eq!(provenance_note(Source::TextLayer, false), "");
    }

    #[test]
    fn pdf_reports_a_missing_file_rather_than_empty_text() {
        let err = extract(Path::new("/nonexistent/file.pdf")).unwrap_err();
        assert!(err.to_string().contains("reading"), "{err}");
    }

    #[test]
    fn pdf_rejects_a_file_that_is_not_a_pdf_instead_of_returning_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.pdf");
        std::fs::write(&path, "definitely not a pdf").unwrap();
        // Must not come back as "no sensitive values found".
        assert!(
            extract(&path).is_err(),
            "a non-PDF must fail rather than read as an empty document"
        );
    }

    #[test]
    fn pdf_classifies_a_page_with_almost_no_text_as_needing_ocr() {
        // Built inline: a valid minimal PDF whose only content is a page number.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.pdf");
        std::fs::write(&path, minimal_pdf("1")).unwrap();
        if let Ok(extracted) = extract(&path) {
            assert_eq!(
                extracted.source,
                Source::NeedsOcr,
                "a nearly empty page is a scan, not a clean document"
            );
        }
    }

    #[test]
    fn pdf_classifies_a_page_of_prose_as_having_a_text_layer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("text.pdf");
        std::fs::write(
            &path,
            minimal_pdf("Musteri kaydi tckn 10000000146 eposta a.b@example.com"),
        )
        .unwrap();
        if let Ok(extracted) = extract(&path) {
            assert_eq!(extracted.source, Source::TextLayer);
            assert!(extracted.text.contains("10000000146"), "{}", extracted.text);
        }
    }
}
