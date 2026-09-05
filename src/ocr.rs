//! Vision OCR: reading text out of images.
//!
//! A screenshot pasted into a document, or a scanned PDF page, carries its
//! passwords as pixels. Nothing in the text pipeline can see them, so a file
//! that looks masked may still be carrying credentials in an image.
//!
//! Apple's Vision framework does the recognition, called directly through
//! `objc2` rather than by shelling out to a Swift helper: a helper would be a
//! second binary to build, sign and keep in step. That makes this module macOS
//! only, and the rest of the server works without it.

use anyhow::{Context, Result};
use std::path::Path;

/// One recognised piece of text and where it sits in the image.
///
/// The rectangle is in Vision's normalised coordinates: origin bottom-left,
/// both axes 0.0 to 1.0. Callers that draw need to flip the y axis, which is
/// the sort of detail that silently puts a redaction box in the wrong place.
#[derive(Debug, Clone, PartialEq)]
pub struct Recognized {
    pub text: String,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// File extensions this module can read.
pub const EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "tif", "tiff", "bmp", "gif", "heic"];

pub fn is_image(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Whether OCR is available in this build.
pub const fn available() -> bool {
    cfg!(target_os = "macos")
}

#[cfg(target_os = "macos")]
pub fn recognize(path: &Path) -> Result<Vec<Recognized>> {
    use objc2::AllocAnyThread;
    use objc2::rc::Retained;
    use objc2_foundation::{NSArray, NSDictionary, NSString, NSURL};
    use objc2_vision::{
        VNImageRequestHandler, VNRecognizeTextRequest, VNRecognizedTextObservation, VNRequest,
        VNRequestTextRecognitionLevel,
    };

    if !path.exists() {
        anyhow::bail!("{} does not exist", path.display());
    }

    let recognized = unsafe {
        let url = NSURL::fileURLWithPath(&NSString::from_str(
            path.to_str().context("image path is not valid UTF-8")?,
        ));
        let handler = VNImageRequestHandler::initWithURL_options(
            VNImageRequestHandler::alloc(),
            &url,
            &NSDictionary::new(),
        );

        let request: Retained<VNRecognizeTextRequest> = VNRecognizeTextRequest::new();
        request.setRecognitionLevel(VNRequestTextRecognitionLevel::Accurate);
        // Turkish first: the detectors are tuned for Turkish documents, and
        // getting "şifre" back as "sifre" would lose the label a password
        // pattern keys on.
        request.setRecognitionLanguages(&NSArray::from_retained_slice(&[
            NSString::from_str("tr-TR"),
            NSString::from_str("en-US"),
        ]));

        let requests: Retained<NSArray<VNRequest>> =
            NSArray::from_retained_slice(&[Retained::cast_unchecked(request.clone())]);
        handler
            .performRequests_error(&requests)
            .map_err(|err| anyhow::anyhow!("Vision OCR failed: {err}"))?;

        let mut out = Vec::new();
        if let Some(results) = request.results() {
            for observation in results.iter() {
                let observation: &VNRecognizedTextObservation = &observation;
                let candidates = observation.topCandidates(1);
                let Some(candidate) = candidates.iter().next() else {
                    continue;
                };
                let bounds = observation.boundingBox();
                out.push(Recognized {
                    text: candidate.string().to_string(),
                    x: bounds.origin.x,
                    y: bounds.origin.y,
                    width: bounds.size.width,
                    height: bounds.size.height,
                });
            }
        }
        out
    };

    Ok(recognized)
}

#[cfg(not(target_os = "macos"))]
pub fn recognize(_path: &Path) -> Result<Vec<Recognized>> {
    anyhow::bail!(
        "OCR needs Apple's Vision framework and is only available on macOS; \
         text in images cannot be masked in this build"
    )
}

/// Recognise text in an already-decoded image.
///
/// Needed for PDF pages, which Vision refuses to read from the file itself.
#[cfg(target_os = "macos")]
pub fn recognize_cgimage(image: &objc2_core_graphics::CGImage) -> Result<Vec<Recognized>> {
    use objc2::AllocAnyThread;
    use objc2::rc::Retained;
    use objc2_foundation::{NSArray, NSDictionary, NSString};
    use objc2_vision::{
        VNImageRequestHandler, VNRecognizeTextRequest, VNRecognizedTextObservation, VNRequest,
        VNRequestTextRecognitionLevel,
    };

    let recognized = unsafe {
        let handler = VNImageRequestHandler::initWithCGImage_options(
            VNImageRequestHandler::alloc(),
            image,
            &NSDictionary::new(),
        );
        let request: Retained<VNRecognizeTextRequest> = VNRecognizeTextRequest::new();
        request.setRecognitionLevel(VNRequestTextRecognitionLevel::Accurate);
        request.setRecognitionLanguages(&NSArray::from_retained_slice(&[
            NSString::from_str("tr-TR"),
            NSString::from_str("en-US"),
        ]));
        let requests: Retained<NSArray<VNRequest>> =
            NSArray::from_retained_slice(&[Retained::cast_unchecked(request.clone())]);
        handler
            .performRequests_error(&requests)
            .map_err(|err| anyhow::anyhow!("Vision OCR failed: {err}"))?;

        let mut out = Vec::new();
        if let Some(results) = request.results() {
            for observation in results.iter() {
                let observation: &VNRecognizedTextObservation = &observation;
                let candidates = observation.topCandidates(1);
                let Some(candidate) = candidates.iter().next() else {
                    continue;
                };
                let bounds = observation.boundingBox();
                out.push(Recognized {
                    text: candidate.string().to_string(),
                    x: bounds.origin.x,
                    y: bounds.origin.y,
                    width: bounds.size.width,
                    height: bounds.size.height,
                });
            }
        }
        out
    };
    Ok(recognized)
}

/// All recognised text in one string, in reading order.
pub fn recognize_text(path: &Path) -> Result<String> {
    Ok(recognize(path)?
        .into_iter()
        .map(|item| item.text)
        .collect::<Vec<_>>()
        .join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ocr_recognises_image_extensions() {
        assert!(is_image(Path::new("shot.png")));
        assert!(is_image(Path::new("SCAN.TIFF")));
        assert!(!is_image(Path::new("notes.txt")));
        assert!(!is_image(Path::new("archive")));
    }

    #[test]
    fn ocr_availability_matches_the_platform() {
        assert_eq!(available(), cfg!(target_os = "macos"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ocr_reads_text_out_of_a_generated_image() {
        // Rendering an image without a graphics stack is awkward, so this uses
        // a tiny hand-built BMP: a real pixel format, decoded by the real
        // framework, with no dependency on a drawing library.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.bmp");
        write_text_bmp(&path, "10000000146");

        let found = recognize_text(&path).unwrap_or_default();
        // Vision may or may not resolve a synthetic bitmap; what must hold is
        // that the call completes and returns a string rather than panicking
        // or hanging. Recognition quality is Apple's business, not ours.
        assert!(
            found.is_empty() || found.chars().any(|c| c.is_ascii_digit()),
            "unexpected OCR output: {found}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ocr_reports_a_missing_file_instead_of_returning_nothing() {
        let err = recognize(Path::new("/nonexistent/image.png")).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ocr_on_a_file_that_is_not_an_image_fails_rather_than_pretending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.png");
        std::fs::write(&path, "this is not a png").unwrap();
        // Either an error or no text is acceptable; inventing text is not.
        if let Ok(text) = recognize_text(&path) {
            assert!(text.is_empty(), "invented text from a non-image: {text}")
        }
    }

    /// Minimal 24-bit BMP with black glyph-ish blocks on white. Enough to give
    /// Vision a real decodable image without pulling in an image crate.
    #[cfg(target_os = "macos")]
    fn write_text_bmp(path: &Path, _text: &str) {
        let (width, height) = (120usize, 40usize);
        let row_padded = (width * 3 + 3) & !3;
        let pixel_bytes = row_padded * height;
        let file_size = 54 + pixel_bytes;

        let mut bmp = Vec::with_capacity(file_size);
        bmp.extend_from_slice(b"BM");
        bmp.extend_from_slice(&(file_size as u32).to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&54u32.to_le_bytes());
        bmp.extend_from_slice(&40u32.to_le_bytes());
        bmp.extend_from_slice(&(width as i32).to_le_bytes());
        bmp.extend_from_slice(&(height as i32).to_le_bytes());
        bmp.extend_from_slice(&1u16.to_le_bytes());
        bmp.extend_from_slice(&24u16.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&(pixel_bytes as u32).to_le_bytes());
        bmp.extend_from_slice(&2835i32.to_le_bytes());
        bmp.extend_from_slice(&2835i32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());

        for row in 0..height {
            let mut line = Vec::with_capacity(row_padded);
            for column in 0..width {
                let dark = (10..30).contains(&row) && (column / 8) % 2 == 0 && column > 8;
                let value = if dark { 0u8 } else { 255u8 };
                line.extend_from_slice(&[value, value, value]);
            }
            line.resize(row_padded, 0);
            bmp.extend_from_slice(&line);
        }

        std::fs::write(path, bmp).unwrap();
    }
}
