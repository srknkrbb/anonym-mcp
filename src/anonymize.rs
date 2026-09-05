//! Anonymize text before it reaches a model, and restore it on the way back.
//!
//! Detect sensitive values,
//! replace each with a deterministic placeholder (`TCKN_1`, `IBAN_2`, ...), and
//! keep the mapping only on this machine. A dropped file therefore reaches the
//! model as structure without secrets, and a placeholder the agent writes back
//! into a file can be turned into the real value again.

#[allow(unused_imports)]
pub use crate::detectors::{Kind, Match, Settings, detect, is_placeholder};
pub use crate::store::MappingStore;

use regex::Regex;
use std::sync::OnceLock;

/// What one anonymization pass replaced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// (placeholder, kind) for each distinct value replaced, in first-seen order.
    pub replaced: Vec<(String, Kind)>,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.replaced.is_empty()
    }

    pub fn count(&self) -> usize {
        self.replaced.len()
    }

    /// A one-line summary for the composer status notice, e.g.
    /// `2 e-posta, 1 TCKN gizlendi`.
    pub fn summary(&self) -> String {
        let mut counts: Vec<(Kind, usize)> = Vec::new();
        for (_, kind) in &self.replaced {
            match counts.iter_mut().find(|(k, _)| k == kind) {
                Some((_, n)) => *n += 1,
                None => counts.push((*kind, 1)),
            }
        }
        counts
            .into_iter()
            .map(|(kind, n)| format!("{n} {}", kind.prefix()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Replace every detected value in `text` with its placeholder.
pub fn anonymize_text(
    text: &str,
    settings: &Settings,
    store: &mut MappingStore,
) -> (String, Report) {
    let matches = detect(text, settings);
    let mut out = String::with_capacity(text.len());
    let mut report = Report::default();
    let mut cursor = 0;
    for m in matches {
        // detect() returns non-overlapping matches in ascending order, so a
        // single forward pass over the byte ranges is safe.
        out.push_str(&text[cursor..m.start]);
        let placeholder = store.placeholder_for(&m.value, m.kind);
        if !report
            .replaced
            .iter()
            .any(|(existing, _)| existing == &placeholder)
        {
            report.replaced.push((placeholder.clone(), m.kind));
        }
        out.push_str(&placeholder);
        cursor = m.end;
    }
    out.push_str(&text[cursor..]);
    (out, report)
}

fn placeholder_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:SIFRE|TCKN|IBAN|KART|EPOSTA|TEL|KISI|OZEL)_\d+\b")
            .expect("placeholder pattern")
    })
}

/// Put the real values back wherever a known placeholder appears. Unknown
/// placeholders are left untouched rather than guessed at.
pub fn restore_text(text: &str, store: &MappingStore) -> (String, usize) {
    let mut restored = 0;
    let out = placeholder_regex()
        .replace_all(text, |caps: &regex::Captures<'_>| {
            let found = &caps[0];
            match store.value_for(found) {
                Some(value) => {
                    restored += 1;
                    value.to_string()
                }
                None => found.to_string(),
            }
        })
        .into_owned();
    (out, restored)
}

/// True when `text` still carries a placeholder this machine can resolve, i.e.
/// restoring it would change something.
#[allow(dead_code)] // part of the engine's public surface
pub fn has_restorable_placeholder(text: &str, store: &MappingStore) -> bool {
    placeholder_regex()
        .find_iter(text)
        .any(|m| store.value_for(m.as_str()).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings::default()
    }

    #[test]
    fn roundtrip_restores_the_original_text_exactly() {
        let text =
            "müşteri a.b@example.com, tckn 10000000146, iban TR33 0006 1005 9786 4578 4132 26";
        let mut store = MappingStore::ephemeral();
        let (anon, report) = anonymize_text(text, &settings(), &mut store);

        assert!(!anon.contains("a.b@example.com"));
        assert!(!anon.contains("10000000146"));
        assert_eq!(report.count(), 3);

        let (back, restored) = restore_text(&anon, &store);
        assert_eq!(back, text);
        assert_eq!(restored, 3);
    }

    #[test]
    fn roundtrip_is_stable_across_two_documents() {
        let mut store = MappingStore::ephemeral();
        let (first, _) = anonymize_text("mail a.b@example.com", &settings(), &mut store);
        let (second, _) = anonymize_text("yine a.b@example.com", &settings(), &mut store);
        let placeholder = first.split_whitespace().last().unwrap();
        assert!(second.contains(placeholder));
    }

    #[test]
    fn roundtrip_leaves_clean_text_untouched() {
        let mut store = MappingStore::ephemeral();
        let (out, report) = anonymize_text("burada hassas veri yok", &settings(), &mut store);
        assert_eq!(out, "burada hassas veri yok");
        assert!(report.is_empty());
    }

    #[test]
    fn restore_leaves_unknown_placeholders_alone() {
        let store = MappingStore::ephemeral();
        let (out, restored) = restore_text("değer TCKN_9 burada", &store);
        assert_eq!(out, "değer TCKN_9 burada");
        assert_eq!(restored, 0);
        assert!(!has_restorable_placeholder("değer TCKN_9", &store));
    }

    #[test]
    fn restore_detects_restorable_text() {
        let mut store = MappingStore::ephemeral();
        let placeholder = store.placeholder_for("a@b.com", Kind::Email);
        assert!(has_restorable_placeholder(
            &format!("to: {placeholder}"),
            &store
        ));
    }

    #[test]
    fn restore_returns_a_masked_document_to_its_original_form() {
        // The write path: the agent edits masked text and writes it back, so
        // restoring must survive the agent having rearranged the content.
        let mut store = MappingStore::ephemeral();
        let original = "ad: Ali\ntckn: 10000000146\nmail: a.b@example.com";
        let (masked, _) = anonymize_text(original, &settings(), &mut store);
        let edited = masked.replace("ad: Ali", "ad: Ali Veli");
        let (written, restored) = restore_text(&edited, &store);
        assert!(written.contains("10000000146"));
        assert!(written.contains("a.b@example.com"));
        assert!(written.contains("Ali Veli"));
        assert_eq!(restored, 2);
    }

    #[test]
    fn restore_is_idempotent_on_already_restored_text() {
        let mut store = MappingStore::ephemeral();
        let (masked, _) = anonymize_text("mail a.b@example.com", &settings(), &mut store);
        let (once, _) = restore_text(&masked, &store);
        let (twice, restored_again) = restore_text(&once, &store);
        assert_eq!(once, twice);
        assert_eq!(restored_again, 0);
    }

    #[test]
    fn report_summarizes_by_kind() {
        let mut store = MappingStore::ephemeral();
        let (_, report) = anonymize_text(
            "a@b.com ve c@d.com ve tckn 10000000146",
            &settings(),
            &mut store,
        );
        let summary = report.summary();
        assert!(summary.contains("2 EPOSTA"), "{summary}");
        assert!(summary.contains("1 TCKN"), "{summary}");
    }

    #[test]
    fn roundtrip_preserves_multibyte_text_around_matches() {
        let text = "İstanbul’dan a.b@example.com adresine — şifre: Gtts@2020";
        let mut store = MappingStore::ephemeral();
        let (anon, _) = anonymize_text(text, &settings(), &mut store);
        assert!(anon.contains("İstanbul’dan"));
        let (back, _) = restore_text(&anon, &store);
        assert_eq!(back, text);
    }
}
