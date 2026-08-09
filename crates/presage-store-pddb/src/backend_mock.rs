//! In-memory [`KvBackend`] for hosted-mode unit tests.
//!
//! Mirrors the `(dict, key) -> value` shape of PDDB. The real
//! backend lives in `backend_pddb.rs`; the mock stays around as the
//! test harness for every storage trait.
//!
//! # Security
//!
//! **Test harness only.** PDDB's per-page AES-256-GCM-SIV encryption
//! is not modeled here — the mock stores plaintext in a `HashMap`.
//! That's the correct boundary for unit testing (the storage-trait
//! impls have no responsibility for encryption), but it means a
//! production build accidentally selecting [`MockBackend`] would
//! persist every libsignal secret in plaintext process memory. The
//! mock is exposed through [`crate::PddbStore::with_mock_backend`]
//! and never reached from the production
//! [`crate::PddbStore::with_pddb_backend`] path.
//!
//! Storage is `HashMap<(String, String), Vec<u8>>` behind a `Mutex`.
//! The `Vec<u8>` values do not zero on drop.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::{Error, KvBackend};

type Store = HashMap<(String, String), Vec<u8>>;

/// In-memory `KvBackend`, keyed on `(dict_name, key_name)`.
///
/// The `Mutex` makes this `Send + Sync` so a `PddbStore` wrapping it can
/// satisfy the `Clone + Send + Sync + 'static` bound that presage's
/// `Store` trait demands.
#[derive(Default, Debug)]
pub struct MockBackend {
    inner: Mutex<Store>,
}

impl MockBackend {
    pub fn new() -> Self { Self::default() }

    fn lock(&self) -> Result<MutexGuard<'_, Store>, Error> {
        self.inner.lock().map_err(|_| Error::backend("mock backend mutex poisoned"))
    }
}

impl KvBackend for MockBackend {
    fn get(&self, dict: &str, key: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.lock()?.get(&(dict.to_owned(), key.to_owned())).cloned())
    }

    fn put(&self, dict: &str, key: &str, value: &[u8]) -> Result<(), Error> {
        self.lock()?.insert((dict.to_owned(), key.to_owned()), value.to_vec());
        Ok(())
    }

    fn delete(&self, dict: &str, key: &str) -> Result<(), Error> {
        self.lock()?.remove(&(dict.to_owned(), key.to_owned()));
        Ok(())
    }

    fn delete_dict(&self, dict: &str) -> Result<(), Error> {
        let mut guard = self.lock()?;
        guard.retain(|(d, _), _| d != dict);
        Ok(())
    }

    fn list_keys(&self, dict: &str) -> Result<Vec<String>, Error> {
        Ok(self.lock()?.keys().filter(|(d, _)| d == dict).map(|(_, k)| k.clone()).collect())
    }
}
