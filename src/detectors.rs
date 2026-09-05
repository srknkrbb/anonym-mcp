//! Sensitive-value detectors, ported from AnonymKit's `Detectors.swift`.
//!
//! Rust's `regex` crate has no lookaround, so patterns that relied on it in the
//! Swift original are expressed with explicit boundary checks in
//! [`Detector::find`] instead.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// The class of a detected value. The placeholder prefix is the Turkish token
/// used by AnonymKit, so a file anonymized by either tool reads the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Password,
    NationalId,
    Iban,
    CreditCard,
    Email,
    Phone,
    PersonName,
    CustomWord,
}

impl Kind {
    /// Placeholder prefix, e.g. `TCKN` in `TCKN_1`.
    pub fn prefix(self) -> &'static str {
        match self {
            Kind::Password => "SIFRE",
            Kind::NationalId => "TCKN",
            Kind::Iban => "IBAN",
            Kind::CreditCard => "KART",
            Kind::Email => "EPOSTA",
            Kind::Phone => "TEL",
            Kind::PersonName => "KISI",
            Kind::CustomWord => "OZEL",
        }
    }

    pub fn all() -> &'static [Kind] {
        &[
            Kind::Password,
            Kind::NationalId,
            Kind::Iban,
            Kind::CreditCard,
            Kind::Email,
            Kind::Phone,
            Kind::PersonName,
            Kind::CustomWord,
        ]
    }

    pub fn from_prefix(prefix: &str) -> Option<Kind> {
        Kind::all().iter().copied().find(|k| k.prefix() == prefix)
    }
}

/// One detected value with its byte range in the source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub kind: Kind,
}

struct Detector {
    kind: Kind,
    regex: Regex,
    /// Capture group carrying the value (0 = whole match).
    group: usize,
    validate: fn(&str) -> bool,
    /// Reject a match whose neighbouring character is a digit. The Swift
    /// original expressed this as `(?<!\d)`/`(?!\d)`; `regex` has no
    /// lookaround, so without this a phone pattern happily matches the last
    /// ten digits of an eleven-digit national ID.
    digit_boundary: bool,
}

fn always(_: &str) -> bool {
    true
}

/// True when neither neighbour of `start..end` is an ASCII digit.
fn digit_isolated(text: &str, start: usize, end: usize) -> bool {
    let before_ok = text[..start]
        .chars()
        .next_back()
        .is_none_or(|c| !c.is_ascii_digit());
    let after_ok = text[end..]
        .chars()
        .next()
        .is_none_or(|c| !c.is_ascii_digit());
    before_ok && after_ok
}

impl Detector {
    fn find(&self, text: &str) -> Vec<Match> {
        let mut out = Vec::new();
        for caps in self.regex.captures_iter(text) {
            let Some(m) = caps.get(self.group).or_else(|| caps.get(0)) else {
                continue;
            };
            if m.as_str().is_empty() || !(self.validate)(m.as_str()) {
                continue;
            }
            if self.digit_boundary && !digit_isolated(text, m.start(), m.end()) {
                continue;
            }
            out.push(Match {
                start: m.start(),
                end: m.end(),
                value: m.as_str().to_string(),
                kind: self.kind,
            });
        }
        out
    }
}

fn password() -> &'static Detector {
    static D: OnceLock<Detector> = OnceLock::new();
    D.get_or_init(|| Detector {
        kind: Kind::Password,
        regex: Regex::new(
            r#"(?i)\b(password|passwd|pwd|parola|şifre|sifre|pass|key|anahtar|secret|token|pin)\b\s*[:=\-]\s*("[^"\n]+"|'[^'\n]+'|\S+)"#,
        )
        .expect("password pattern"),
        group: 2,
        validate: |v| v.trim_matches(['"', '\'']).chars().count() >= 3,
    digit_boundary: false,
    })
}

/// Context-free password-shaped tokens: letters + digits + a special char.
fn credential_like() -> &'static Detector {
    static D: OnceLock<Detector> = OnceLock::new();
    D.get_or_init(|| Detector {
        kind: Kind::Password,
        regex: Regex::new(r#"[^\s:=,;|"'<>]{6,}"#).expect("credential pattern"),
        group: 0,
        validate: |raw| {
            let v = raw
                .trim_end_matches(['.', ',', ';', ':', '!', '?', ')', '»', '”', '’'])
                .trim_start_matches(['(', '«', '„', '“', '‘']);
            if v.chars().count() < 6 || v.contains("://") || v.to_lowercase().starts_with("www.") {
                return false;
            }
            if is_placeholder(v) || email().regex.is_match(v) {
                return false;
            }
            let specials = "@!#$%^&*?+=~";
            v.chars().any(char::is_alphabetic)
                && v.chars().any(|c| c.is_ascii_digit())
                && v.chars().any(|c| specials.contains(c))
        },
        digit_boundary: false,
    })
}

fn iban() -> &'static Detector {
    static D: OnceLock<Detector> = OnceLock::new();
    D.get_or_init(|| Detector {
        kind: Kind::Iban,
        regex: Regex::new(r"\bTR\d{2}(?: ?\d{4}){5} ?\d{2}\b").expect("iban pattern"),
        group: 0,
        validate: always,
        digit_boundary: false,
    })
}

fn credit_card() -> &'static Detector {
    static D: OnceLock<Detector> = OnceLock::new();
    D.get_or_init(|| Detector {
        kind: Kind::CreditCard,
        regex: Regex::new(r"\b(?:\d[ \-]?){12,18}\d\b").expect("card pattern"),
        group: 0,
        validate: luhn_valid,
        digit_boundary: false,
    })
}

fn national_id() -> &'static Detector {
    static D: OnceLock<Detector> = OnceLock::new();
    D.get_or_init(|| Detector {
        kind: Kind::NationalId,
        regex: Regex::new(r"\b[1-9]\d{10}\b").expect("tckn pattern"),
        group: 0,
        validate: tckn_valid,
        digit_boundary: false,
    })
}

fn email() -> &'static Detector {
    static D: OnceLock<Detector> = OnceLock::new();
    D.get_or_init(|| Detector {
        kind: Kind::Email,
        regex: Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
            .expect("email pattern"),
        group: 0,
        validate: always,
        digit_boundary: false,
    })
}

fn phone() -> &'static Detector {
    static D: OnceLock<Detector> = OnceLock::new();
    D.get_or_init(|| Detector {
        kind: Kind::Phone,
        regex: Regex::new(r"(?:\+90[ \-]?|0)?\(?[2-5]\d{2}\)?[ \-]?\d{3}[ \-]?\d{2}[ \-]?\d{2}")
            .expect("phone pattern"),
        group: 0,
        validate: |v| {
            let digits = v.chars().filter(char::is_ascii_digit).count();
            (10..=12).contains(&digits)
        },
        digit_boundary: true,
    })
}

fn phone_international() -> &'static Detector {
    static D: OnceLock<Detector> = OnceLock::new();
    D.get_or_init(|| Detector {
        kind: Kind::Phone,
        regex: Regex::new(r"\+\d{1,3}(?:[ \-]?\d{2,4}){2,4}").expect("intl phone pattern"),
        group: 0,
        validate: |v| {
            let digits = v.chars().filter(char::is_ascii_digit).count();
            (9..=14).contains(&digits)
        },
        digit_boundary: true,
    })
}

fn person_name() -> &'static Detector {
    static D: OnceLock<Detector> = OnceLock::new();
    D.get_or_init(|| Detector {
        kind: Kind::PersonName,
        regex: Regex::new(
            r"\b[A-ZÇĞİÖŞÜ][a-zçğıöşü]{2,}(?:[ \t]+[A-ZÇĞİÖŞÜ][a-zçğıöşü]{2,}){1,2}\b",
        )
        .expect("person pattern"),
        group: 0,
        validate: always,
        digit_boundary: false,
    })
}

/// True when the token already looks like one of our placeholders.
pub fn is_placeholder(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:SIFRE|TCKN|IBAN|KART|EPOSTA|TEL|KISI|OZEL)_\d+$").expect("placeholder")
    })
    .is_match(value)
}

pub fn luhn_valid(raw: &str) -> bool {
    let digits: Vec<u32> = raw.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0;
    for (i, d) in digits.iter().rev().enumerate() {
        if i % 2 == 1 {
            let doubled = d * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += d;
        }
    }
    sum % 10 == 0
}

pub fn tckn_valid(raw: &str) -> bool {
    let d: Vec<u32> = raw.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    let odd: i64 = (d[0] + d[2] + d[4] + d[6] + d[8]) as i64;
    let even: i64 = (d[1] + d[3] + d[5] + d[7]) as i64;
    let digit10 = (((odd * 7) - even) % 10 + 10) % 10;
    let digit11 = (d[..10].iter().sum::<u32>() % 10) as i64;
    d[9] as i64 == digit10 && d[10] as i64 == digit11
}

/// Which detectors run, and the user's own word list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub enabled: Vec<Kind>,
    pub custom_words: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        // Person names are off by default: the detector is deliberately loose
        // and AnonymKit relies on a human confirming them in a preview pane,
        // which a terminal drop has no room for.
        Settings {
            enabled: vec![
                Kind::Password,
                Kind::NationalId,
                Kind::Iban,
                Kind::CreditCard,
                Kind::Email,
                Kind::Phone,
                Kind::CustomWord,
            ],
            custom_words: Vec::new(),
        }
    }
}

fn custom_word_regex(words: &[String]) -> Option<Regex> {
    let mut cleaned: Vec<&str> = words
        .iter()
        .map(|w| w.trim())
        .filter(|w| !w.is_empty())
        .collect();
    if cleaned.is_empty() {
        return None;
    }
    // Longest first so a longer phrase wins over its own prefix.
    cleaned.sort_by_key(|w| std::cmp::Reverse(w.chars().count()));
    let alternation = cleaned
        .iter()
        .map(|w| regex::escape(w))
        .collect::<Vec<_>>()
        .join("|");
    Regex::new(&format!("(?i)(?:{alternation})")).ok()
}

/// All matches in `text`, de-overlapped: earliest start wins, then longest.
pub fn detect(text: &str, settings: &Settings) -> Vec<Match> {
    let mut matches: Vec<Match> = Vec::new();
    let on = |k: Kind| settings.enabled.contains(&k);

    if on(Kind::CustomWord)
        && let Some(re) = custom_word_regex(&settings.custom_words)
    {
        for m in re.find_iter(text) {
            matches.push(Match {
                start: m.start(),
                end: m.end(),
                value: m.as_str().to_string(),
                kind: Kind::CustomWord,
            });
        }
    }
    if on(Kind::Password) {
        matches.extend(password().find(text));
        matches.extend(credential_like().find(text));
    }
    if on(Kind::Iban) {
        matches.extend(iban().find(text));
    }
    if on(Kind::CreditCard) {
        matches.extend(credit_card().find(text));
    }
    if on(Kind::NationalId) {
        matches.extend(national_id().find(text));
    }
    if on(Kind::Email) {
        matches.extend(email().find(text));
    }
    if on(Kind::Phone) {
        matches.extend(phone_international().find(text));
        matches.extend(phone().find(text));
    }
    if on(Kind::PersonName) {
        matches.extend(person_name().find(text));
    }

    matches.retain(|m| !is_placeholder(&m.value));
    dedupe_overlaps(matches)
}

/// Keep the earliest match, breaking ties by length, and drop anything that
/// overlaps a kept one. Two placeholders must never share a byte.
fn dedupe_overlaps(mut matches: Vec<Match>) -> Vec<Match> {
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
            .then(a.kind.cmp(&b.kind))
    });
    let mut kept: Vec<Match> = Vec::new();
    for m in matches {
        if kept.last().is_some_and(|last| m.start < last.end) {
            continue;
        }
        kept.push(m);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<(Kind, String)> {
        detect(text, &Settings::default())
            .into_iter()
            .map(|m| (m.kind, m.value))
            .collect()
    }

    #[test]
    fn detects_valid_tckn_and_rejects_bad_checksum() {
        assert!(tckn_valid("10000000146"));
        assert!(!tckn_valid("12345678901"));
        let found = kinds("kimlik 10000000146 ve 12345678901 var");
        assert_eq!(found, vec![(Kind::NationalId, "10000000146".to_string())]);
    }

    #[test]
    fn detects_luhn_valid_card_only() {
        assert!(luhn_valid("4111 1111 1111 1111"));
        assert!(!luhn_valid("4111 1111 1111 1112"));
        let found = kinds("kart 4111 1111 1111 1111 son");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Kind::CreditCard);
    }

    #[test]
    fn detects_iban_email_and_phone() {
        let found = kinds("TR33 0006 1005 9786 4578 4132 26 · a.b@example.com · 0532 123 45 67");
        let found_kinds: Vec<Kind> = found.iter().map(|(k, _)| *k).collect();
        assert!(found_kinds.contains(&Kind::Iban));
        assert!(found_kinds.contains(&Kind::Email));
        assert!(found_kinds.contains(&Kind::Phone));
    }

    #[test]
    fn detects_labelled_password_value_not_the_label() {
        let found = kinds("password: Gtts@2020");
        assert_eq!(found, vec![(Kind::Password, "Gtts@2020".to_string())]);
    }

    #[test]
    fn detects_custom_words_case_insensitively() {
        let settings = Settings {
            custom_words: vec!["Acme Holding".to_string()],
            ..Settings::default()
        };
        let found = detect("acme holding raporu", &settings);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::CustomWord);
    }

    #[test]
    fn detects_nothing_in_ordinary_prose() {
        assert!(kinds("bu satırda hassas bir şey yok").is_empty());
    }

    #[test]
    fn detects_no_overlapping_ranges() {
        let text = "iletisim a.b@example.com tel +90 532 123 45 67 tckn 10000000146";
        let found = detect(text, &Settings::default());
        for pair in found.windows(2) {
            assert!(pair[0].end <= pair[1].start, "overlap: {pair:?}");
        }
    }

    #[test]
    fn detects_person_names_only_when_enabled() {
        let text = "Ahmet Yılmaz geldi";
        assert!(kinds(text).is_empty());
        let settings = Settings {
            enabled: vec![Kind::PersonName],
            ..Settings::default()
        };
        assert_eq!(detect(text, &settings).len(), 1);
    }

    #[test]
    fn detects_password_shaped_tokens_without_a_label() {
        // Excel puts the header in a neighbouring cell, so a password often
        // arrives with no "password:" context at all.
        let found = kinds("kullanici admin trX987&21");
        assert!(
            found
                .iter()
                .any(|(k, v)| *k == Kind::Password && v == "trX987&21"),
            "{found:?}"
        );
    }

    /// A bare username is not a password, and must not be treated as one.
    ///
    /// Found by auditing real screenshots: `admin01` stayed in the clear. That
    /// is correct, since a rule loose enough to catch it would mask ordinary
    /// words, but it means account names need the custom word list. Both halves
    /// are asserted here so neither can drift.
    #[test]
    fn detects_leaves_bare_usernames_alone_but_custom_words_catch_them() {
        assert!(
            kinds("User Name : admin01").is_empty(),
            "a bare username must not be mistaken for a password"
        );

        let settings = Settings {
            custom_words: vec!["admin01".to_string()],
            ..Settings::default()
        };
        let found = detect("User Name : admin01", &settings);
        assert_eq!(found.len(), 1, "the word list must reach it");
        assert_eq!(found[0].kind, Kind::CustomWord);
    }

    #[test]
    fn detects_skip_existing_placeholders() {
        assert!(is_placeholder("TCKN_1"));
        assert!(kinds("değer TCKN_1 ve EPOSTA_2").is_empty());
    }
}
