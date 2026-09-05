//! Deterministic value ↔ placeholder mapping, persisted per machine.
//!
//! AnonymKit keeps this table in an AES-GCM encrypted file so the real values
//! never travel with the shared document. The same property holds here for a
//! different reason: what leaves the machine is the model request, and the
//! table is exactly what must not be in it. The store therefore lives outside
//! the repository, in `~/.anonym-mcp/mappings.json` with 0600 permissions.

use crate::detectors::Kind;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    /// placeholder -> real value
    values: HashMap<String, String>,
}

/// Bidirectional, order-stable mapping between real values and placeholders.
#[derive(Debug)]
pub struct MappingStore {
    path: Option<PathBuf>,
    to_placeholder: HashMap<String, String>,
    to_value: HashMap<String, String>,
    counters: HashMap<Kind, usize>,
    dirty: bool,
}

impl MappingStore {
    /// An in-memory store that never touches disk. Used by tests and by
    /// sessions that opt out of persistence.
    pub fn ephemeral() -> Self {
        MappingStore {
            path: None,
            to_placeholder: HashMap::new(),
            to_value: HashMap::new(),
            counters: HashMap::new(),
            dirty: false,
        }
    }

    /// Default location: `~/.anonym-mcp/mappings.json`.
    pub fn default_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".anonym-mcp/mappings.json"))
    }

    /// Load the table at `path`, or start empty when it does not exist yet.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut store = MappingStore {
            path: Some(path.clone()),
            ..MappingStore::ephemeral()
        };
        if !path.exists() {
            return Ok(store);
        }
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading mapping store {}", path.display()))?;
        let file: StoreFile = serde_json::from_str(&raw)
            .with_context(|| format!("parsing mapping store {}", path.display()))?;
        for (placeholder, value) in file.values {
            store.remember(placeholder, value);
        }
        store.dirty = false;
        Ok(store)
    }

    /// Open the default per-user store, falling back to ephemeral when there is
    /// no home directory to write into.
    pub fn open_default() -> Result<Self> {
        match Self::default_path() {
            Some(path) => Self::open(path),
            None => Ok(Self::ephemeral()),
        }
    }

    fn remember(&mut self, placeholder: String, value: String) {
        if let Some((prefix, index)) = split_placeholder(&placeholder) {
            let counter = self.counters.entry(prefix).or_insert(0);
            *counter = (*counter).max(index);
        }
        self.to_value.insert(placeholder.clone(), value.clone());
        self.to_placeholder.insert(value, placeholder);
    }

    /// The placeholder for `value`, minting a new one on first sight. The same
    /// value always maps to the same placeholder, across files and sessions.
    pub fn placeholder_for(&mut self, value: &str, kind: Kind) -> String {
        if let Some(existing) = self.to_placeholder.get(value) {
            return existing.clone();
        }
        let counter = self.counters.entry(kind).or_insert(0);
        *counter += 1;
        let placeholder = format!("{}_{}", kind.prefix(), counter);
        self.to_value.insert(placeholder.clone(), value.to_string());
        self.to_placeholder
            .insert(value.to_string(), placeholder.clone());
        self.dirty = true;
        placeholder
    }

    /// The real value behind a placeholder, if this machine knows it.
    pub fn value_for(&self, placeholder: &str) -> Option<&str> {
        self.to_value.get(placeholder).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.to_value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.to_value.is_empty()
    }

    /// Persist the table when it changed and a path is configured.
    pub fn save(&mut self) -> Result<()> {
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        if !self.dirty {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let file = StoreFile {
            values: self.to_value.clone(),
        };
        let json = serde_json::to_string_pretty(&file)?;
        std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
        restrict_permissions(&path);
        self.dirty = false;
        Ok(())
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

fn split_placeholder(placeholder: &str) -> Option<(Kind, usize)> {
    let (prefix, index) = placeholder.rsplit_once('_')?;
    Some((Kind::from_prefix(prefix)?, index.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_reuses_the_same_placeholder_for_a_repeated_value() {
        let mut store = MappingStore::ephemeral();
        let first = store.placeholder_for("a@b.com", Kind::Email);
        let second = store.placeholder_for("a@b.com", Kind::Email);
        assert_eq!(first, "EPOSTA_1");
        assert_eq!(first, second);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_numbers_each_kind_independently() {
        let mut store = MappingStore::ephemeral();
        assert_eq!(store.placeholder_for("a@b.com", Kind::Email), "EPOSTA_1");
        assert_eq!(store.placeholder_for("c@d.com", Kind::Email), "EPOSTA_2");
        assert_eq!(
            store.placeholder_for("10000000146", Kind::NationalId),
            "TCKN_1"
        );
    }

    #[test]
    fn store_round_trips_through_disk_and_keeps_counters() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mappings.json");

        let mut store = MappingStore::open(&path).unwrap();
        let placeholder = store.placeholder_for("a@b.com", Kind::Email);
        store.save().unwrap();

        let mut reopened = MappingStore::open(&path).unwrap();
        assert_eq!(reopened.value_for(&placeholder), Some("a@b.com"));
        // The counter must resume, not restart, or a second value would steal
        // the first one's placeholder.
        assert_eq!(reopened.placeholder_for("c@d.com", Kind::Email), "EPOSTA_2");
    }

    #[test]
    fn store_file_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mappings.json");
        let mut store = MappingStore::open(&path).unwrap();
        store.placeholder_for("a@b.com", Kind::Email);
        store.save().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn store_ephemeral_save_is_a_no_op() {
        let mut store = MappingStore::ephemeral();
        store.placeholder_for("a@b.com", Kind::Email);
        assert!(store.save().is_ok());
    }
}
