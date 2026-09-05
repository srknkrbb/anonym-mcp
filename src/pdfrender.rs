//! Rendering PDF pages to bitmaps so OCR can read them.
//!
//! Vision cannot be handed a PDF: it reports "zero-dimensioned image (0 x 0)",
//! which surfaced as an OCR run that quietly returned nothing, making a scanned
//! document look exactly like a clean one. Pages have to be drawn into a bitmap
//! first, and that is what this module does.
//!
//! The Core Graphics calls are declared directly rather than pulled from a
//! binding crate: this is eight stable C functions, and the binding crate's
//! generated shapes for them change between releases.

#![cfg(target_os = "macos")]

use anyhow::{Result, bail};
use objc2_core_graphics::CGImage;
use std::ffi::c_void;
use std::path::Path;

/// Pages are drawn at twice their nominal size. Recognition on a 1x render of
/// a typical scan is visibly worse, and the cost is a transient bitmap.
const RENDER_SCALE: f64 = 2.0;

/// Cap on pages rendered per request, so a 500-page scan cannot occupy the
/// server indefinitely.
pub const MAX_PAGES: usize = 50;

#[repr(C)]
#[derive(Clone, Copy)]
struct CgPoint {
    x: f64,
    y: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CgSize {
    width: f64,
    height: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CgRect {
    origin: CgPoint,
    size: CgSize,
}

// CGPDFBox::MediaBox
const MEDIA_BOX: i32 = 0;
// kCGImageAlphaNoneSkipLast
const ALPHA_NONE_SKIP_LAST: u32 = 5;

unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: *const c_void,
        buffer: *const u8,
        buf_len: isize,
        is_directory: bool,
    ) -> *const c_void;
    fn CFRelease(cf: *const c_void);

    fn CGPDFDocumentCreateWithURL(url: *const c_void) -> *mut c_void;
    fn CGPDFDocumentGetNumberOfPages(document: *mut c_void) -> usize;
    fn CGPDFDocumentGetPage(document: *mut c_void, page: usize) -> *mut c_void;
    fn CGPDFDocumentRelease(document: *mut c_void);
    fn CGPDFPageGetBoxRect(page: *mut c_void, box_kind: i32) -> CgRect;

    fn CGColorSpaceCreateDeviceRGB() -> *mut c_void;
    fn CGColorSpaceRelease(space: *mut c_void);

    fn CGBitmapContextCreate(
        data: *mut c_void,
        width: usize,
        height: usize,
        bits_per_component: usize,
        bytes_per_row: usize,
        space: *mut c_void,
        bitmap_info: u32,
    ) -> *mut c_void;
    fn CGBitmapContextCreateImage(context: *mut c_void) -> *mut CGImage;
    fn CGContextRelease(context: *mut c_void);
    fn CGContextSetRGBFillColor(context: *mut c_void, r: f64, g: f64, b: f64, a: f64);
    fn CGContextFillRect(context: *mut c_void, rect: CgRect);
    fn CGContextScaleCTM(context: *mut c_void, sx: f64, sy: f64);
    fn CGContextDrawPDFPage(context: *mut c_void, page: *mut c_void);
}

/// An owned CGPDFDocument, released on drop so an early return cannot leak it.
struct Document(*mut c_void);

impl Drop for Document {
    fn drop(&mut self) {
        unsafe { CGPDFDocumentRelease(self.0) };
    }
}

fn open(path: &Path) -> Result<Document> {
    let Some(text) = path.to_str() else {
        bail!("PDF path is not valid UTF-8");
    };
    unsafe {
        let url = CFURLCreateFromFileSystemRepresentation(
            std::ptr::null(),
            text.as_ptr(),
            text.len() as isize,
            false,
        );
        if url.is_null() {
            bail!("could not form a URL for {}", path.display());
        }
        let document = CGPDFDocumentCreateWithURL(url);
        CFRelease(url);
        if document.is_null() {
            bail!("could not open {} as a PDF", path.display());
        }
        Ok(Document(document))
    }
}

/// Number of pages, or None when the file will not open as a PDF.
pub fn page_count(path: &Path) -> Option<usize> {
    let document = open(path).ok()?;
    let count = unsafe { CGPDFDocumentGetNumberOfPages(document.0) };
    Some(count)
}

/// Render up to [`MAX_PAGES`] pages to bitmaps.
pub fn render_pages(path: &Path) -> Result<Vec<objc2::rc::Retained<CGImage>>> {
    let document = open(path)?;
    let total = unsafe { CGPDFDocumentGetNumberOfPages(document.0) };
    if total == 0 {
        bail!("{} has no pages", path.display());
    }

    let mut images = Vec::new();
    for index in 1..=total.min(MAX_PAGES) {
        unsafe {
            let page = CGPDFDocumentGetPage(document.0, index);
            if page.is_null() {
                continue;
            }
            let bounds = CGPDFPageGetBoxRect(page, MEDIA_BOX);
            let width = (bounds.size.width * RENDER_SCALE).round() as usize;
            let height = (bounds.size.height * RENDER_SCALE).round() as usize;
            if width == 0 || height == 0 {
                continue;
            }

            let space = CGColorSpaceCreateDeviceRGB();
            let context = CGBitmapContextCreate(
                std::ptr::null_mut(),
                width,
                height,
                8,
                0,
                space,
                ALPHA_NONE_SKIP_LAST,
            );
            CGColorSpaceRelease(space);
            if context.is_null() {
                bail!("could not allocate a {width}x{height} bitmap for page {index}");
            }

            // Scans are black on white with no background drawn, so an
            // unfilled context leaves the text on transparent black and
            // recognition collapses.
            CGContextSetRGBFillColor(context, 1.0, 1.0, 1.0, 1.0);
            CGContextFillRect(
                context,
                CgRect {
                    origin: CgPoint { x: 0.0, y: 0.0 },
                    size: CgSize {
                        width: width as f64,
                        height: height as f64,
                    },
                },
            );
            CGContextScaleCTM(context, RENDER_SCALE, RENDER_SCALE);
            CGContextDrawPDFPage(context, page);

            let image = CGBitmapContextCreateImage(context);
            CGContextRelease(context);
            if !image.is_null() {
                images.push(objc2::rc::Retained::from_raw(image).expect("image"));
            }
        }
    }

    if images.is_empty() {
        bail!("no page of {} could be rendered", path.display());
    }
    Ok(images)
}

/// True when the document holds more pages than were rendered.
pub fn truncated(path: &Path) -> bool {
    page_count(path).is_some_and(|count| count > MAX_PAGES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdfrender_refuses_a_file_that_is_not_a_pdf() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.pdf");
        std::fs::write(&path, "not a pdf at all").unwrap();
        let err = render_pages(&path).unwrap_err();
        assert!(err.to_string().contains("could not open"), "{err}");
    }

    #[test]
    fn pdfrender_reports_no_page_count_for_a_broken_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.pdf");
        std::fs::write(&path, "%PDF-1.4 truncated").unwrap();
        assert_eq!(page_count(&path), None);
    }

    #[test]
    fn pdfrender_renders_a_real_page_to_a_bitmap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one.pdf");
        std::fs::write(&path, crate::pdf::tests_support::minimal_pdf("Merhaba")).unwrap();

        assert_eq!(page_count(&path), Some(1));
        let pages = render_pages(&path).expect("a valid one-page PDF must render");
        assert_eq!(pages.len(), 1);
        // A rendered page must have real dimensions; 0x0 is the failure Vision
        // complained about.
        let width = objc2_core_graphics::CGImage::width(Some(&pages[0]));
        assert!(width > 0, "rendered page has zero width");
    }

    #[test]
    fn pdfrender_does_not_claim_truncation_for_a_short_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one.pdf");
        std::fs::write(&path, crate::pdf::tests_support::minimal_pdf("x")).unwrap();
        assert!(!truncated(&path));
    }
}
