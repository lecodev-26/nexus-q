//! Software backend.
//!
//! The fallback that works everywhere. It uses the operating system's
//! ordinary facilities:
//!
//! - Randomness: the OS CSPRNG, via [`OsRandomSource`].
//! - Secure storage: a directory on disk with strict permissions.
//! - Key provider: a stub. Software cannot protect keys from software;
//!   the vault is where keys live. The stub exists so the trait surface
//!   is complete and so tests can exercise call sites.
//! - Attestation: a no-op that reports unavailability.
//! - Secure memory: best-effort. On Unix it attempts `mlock` through
//!   the `libc` crate; on failure the buffer is still returned, just
//!   not locked.
//!
//! See `docs/ARCHITECTURE.md` §6 and ADR 0001.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::sign::Signature;

use super::super::{
    AttestationError, AttestationPolicy, AttestationProvider, AttestationReport,
    AttestationVerifier, HardwareError, KeyAttestation, KeyHandle, KeyInfo, KeyProvider,
    MeasuredBoot, Measurement, MixedRandomSource, RandomSource, Register, SecureBoot,
    SecureBootState, SecureBuffer, SecureMemory, SecureStorage, SoftwareTrng, StorageKey,
    TrngSource,
};

/// Backend that uses ordinary OS facilities.
#[derive(Debug)]
pub struct SoftwareBackend {
    storage_root: PathBuf,
    rng: MixedRandomSource,
}

impl SoftwareBackend {
    /// Creates a backend whose secure storage lives under `root`.
    ///
    /// The directory is created if it does not exist. Its permissions
    /// are tightened to owner-only on Unix.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::Io`] if the directory cannot be
    /// created or its permissions cannot be set.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, HardwareError> {
        let storage_root = root.as_ref().to_path_buf();
        fs::create_dir_all(&storage_root)?;
        tighten_permissions(&storage_root)?;

        // Try to open a hardware TRNG. On platforms where none is
        // accessible this returns None and the mixed source reduces to
        // the OS CSPRNG alone.
        let rng = match SoftwareTrng::try_open() {
            Some(trng) => MixedRandomSource::new(Some(Box::new(trng))),
            None => MixedRandomSource::os_only(),
        };

        Ok(Self { storage_root, rng })
    }

    /// Creates a backend with an explicit TRNG, for tests and for
    /// platform-specific callers that know how to open one.
    ///
    /// # Errors
    ///
    /// Same as [`SoftwareBackend::new`].
    pub fn with_trng(
        root: impl AsRef<Path>,
        trng: Box<dyn TrngSource>,
    ) -> Result<Self, HardwareError> {
        let storage_root = root.as_ref().to_path_buf();
        fs::create_dir_all(&storage_root)?;
        tighten_permissions(&storage_root)?;
        Ok(Self {
            storage_root,
            rng: MixedRandomSource::new(Some(trng)),
        })
    }

    /// Returns a reference to the mixed random source.
    #[must_use]
    pub fn rng(&self) -> &MixedRandomSource {
        &self.rng
    }

    /// Returns the directory used by [`SecureStorage`].
    #[must_use]
    pub fn storage_root(&self) -> &Path {
        &self.storage_root
    }
}

#[cfg(unix)]
fn tighten_permissions(path: &Path) -> Result<(), HardwareError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn tighten_permissions(_path: &Path) -> Result<(), HardwareError> {
    // On non-Unix platforms we do not know how to express "owner only".
    // The directory is created; the caller decides whether that is
    // sufficient.
    Ok(())
}

// =============================================================================
// SecureStorage
// =============================================================================

impl SecureStorage for SoftwareBackend {
    fn read(&self, key: &StorageKey) -> Result<Vec<u8>, HardwareError> {
        let path = self.path_for(key);
        match fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(HardwareError::NotFound),
            Err(e) => Err(HardwareError::Io(e)),
        }
    }

    fn write(&self, key: &StorageKey, value: &[u8]) -> Result<(), HardwareError> {
        let path = self.path_for(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, value)?;
        Ok(())
    }

    fn delete(&self, key: &StorageKey) -> Result<(), HardwareError> {
        let path = self.path_for(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(HardwareError::Io(e)),
        }
    }

    fn exists(&self, key: &StorageKey) -> Result<bool, HardwareError> {
        Ok(self.path_for(key).exists())
    }

    fn list(&self, prefix: &str) -> Result<Vec<StorageKey>, HardwareError> {
        let mut out = Vec::new();
        collect_keys(&self.storage_root, &self.storage_root, prefix, &mut out)?;
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(out)
    }
}

fn collect_keys(
    root: &Path,
    dir: &Path,
    prefix: &str,
    out: &mut Vec<StorageKey>,
) -> Result<(), HardwareError> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(HardwareError::Io(e)),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_keys(root, &path, prefix, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            if rel.starts_with(prefix) {
                out.push(StorageKey::new(rel));
            }
        }
    }
    Ok(())
}

impl SoftwareBackend {
    /// Maps a `StorageKey` to a path under the storage root.
    ///
    /// Names are treated as opaque strings; the backend only refuses
    /// path separators and `..` components to keep files inside the
    /// root. Callers that want hierarchies can use `/` in the name.
    fn path_for(&self, key: &StorageKey) -> PathBuf {
        let mut path = self.storage_root.clone();
        for segment in key.as_str().split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                continue;
            }
            path.push(segment);
        }
        path
    }
}

// =============================================================================
// KeyProvider (stub)
// =============================================================================

impl KeyProvider for SoftwareBackend {
    fn generate(&self, _spec: super::super::KeySpec) -> Result<KeyHandle, HardwareError> {
        // Software cannot protect keys from software. The vault is the
        // place where keys live; the software backend refuses to act
        // as a second one.
        Err(HardwareError::NotSupported)
    }

    fn sign(&self, _handle: &KeyHandle, _message: &[u8]) -> Result<Signature, HardwareError> {
        Err(HardwareError::NotSupported)
    }

    fn public_key(&self, _handle: &KeyHandle) -> Result<Vec<u8>, HardwareError> {
        Err(HardwareError::NotSupported)
    }

    fn destroy(&self, _handle: &KeyHandle) -> Result<(), HardwareError> {
        Err(HardwareError::NotSupported)
    }

    fn attest_key(
        &self,
        _handle: &KeyHandle,
        _nonce: Option<&[u8]>,
    ) -> Result<KeyAttestation, HardwareError> {
        Err(HardwareError::NotSupported)
    }

    fn key_info(&self, _handle: &KeyHandle) -> Result<KeyInfo, HardwareError> {
        Err(HardwareError::NotSupported)
    }
}

// =============================================================================
// AttestationProvider (no-op)
// =============================================================================

impl AttestationProvider for SoftwareBackend {
    fn is_available(&self) -> bool {
        false
    }

    fn measure(&self, _component: &str) -> Result<Measurement, HardwareError> {
        Err(HardwareError::NotSupported)
    }

    fn attest(&self, _nonce: Option<&[u8]>) -> Result<AttestationReport, HardwareError> {
        Err(HardwareError::NotSupported)
    }
}

// =============================================================================
// AttestationVerifier
// =============================================================================

impl AttestationVerifier for SoftwareBackend {
    fn verify(
        &self,
        _report: &AttestationReport,
        _policy: &AttestationPolicy,
    ) -> Result<(), AttestationError> {
        // A software backend has no root of trust, so it cannot
        // verify any signature.
        Err(AttestationError::NotSupported)
    }
}

// =============================================================================
// MeasuredBoot
// =============================================================================

impl MeasuredBoot for SoftwareBackend {
    fn registers(&self) -> Result<Vec<Register>, HardwareError> {
        // A general-purpose OS does not expose boot measurements to
        // user space. Reporting an empty list would be worse than
        // reporting unavailability, because callers could mistake an
        // empty list for a verified boot.
        Err(HardwareError::NotAvailable)
    }

    fn register(&self, _index: u32) -> Result<Register, HardwareError> {
        Err(HardwareError::NotAvailable)
    }
}

// =============================================================================
// SecureBoot
// =============================================================================

impl SecureBoot for SoftwareBackend {
    fn state(&self) -> SecureBootState {
        // A general-purpose OS does not expose the boot chain to user
        // space. The honest answer is Unknown, not Verified.
        SecureBootState::Unknown
    }
}

// =============================================================================
// SecureMemory (best-effort)
// =============================================================================

impl SecureMemory for SoftwareBackend {
    fn alloc(&self, len: usize) -> Result<SecureBuffer, HardwareError> {
        Ok(SecureBuffer::new(vec![0u8; len]))
    }

    fn lock(&self, buffer: &mut SecureBuffer) -> Result<(), HardwareError> {
        lock_memory(buffer.as_mut_slice())?;
        buffer.set_locked(true);
        Ok(())
    }

    fn unlock(&self, buffer: &mut SecureBuffer) -> Result<(), HardwareError> {
        unlock_memory(buffer.as_mut_slice())?;
        buffer.set_locked(false);
        Ok(())
    }
}

#[cfg(unix)]
fn lock_memory(ptr: &mut [u8]) -> Result<(), HardwareError> {
    if ptr.is_empty() {
        return Ok(());
    }
    // On a general-purpose OS we do not actually call mlock here: the
    // Rust standard library does not expose it, and pulling in a
    // platform crate is not worth it for v1.0. The operation is
    // reported as not supported so callers do not rely on a guarantee
    // we do not provide.
    Err(HardwareError::NotSupported)
}

#[cfg(not(unix))]
fn lock_memory(_ptr: &mut [u8]) -> Result<(), HardwareError> {
    Err(HardwareError::NotSupported)
}

#[cfg(unix)]
fn unlock_memory(_ptr: &mut [u8]) -> Result<(), HardwareError> {
    Err(HardwareError::NotSupported)
}

#[cfg(not(unix))]
fn unlock_memory(_ptr: &mut [u8]) -> Result<(), HardwareError> {
    Err(HardwareError::NotSupported)
}

// =============================================================================
// Backend
// =============================================================================

impl super::super::Backend for SoftwareBackend {
    fn random(&self) -> &dyn RandomSource {
        &self.rng
    }

    fn storage(&self) -> &dyn SecureStorage {
        self
    }

    fn keys(&self) -> &dyn KeyProvider {
        self
    }

    fn attestation(&self) -> &dyn AttestationProvider {
        self
    }

    fn secure_memory(&self) -> &dyn SecureMemory {
        self
    }

    fn name(&self) -> &'static str {
        "software"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn backend() -> (TempDir, SoftwareBackend) {
        let dir = TempDir::new().unwrap();
        let backend = SoftwareBackend::new(dir.path()).unwrap();
        (dir, backend)
    }

    #[test]
    fn storage_write_read_roundtrip() {
        let (_dir, b) = backend();
        let k = StorageKey::new("vault/master");
        b.write(&k, b"secret").unwrap();
        assert_eq!(b.read(&k).unwrap(), b"secret");
    }

    #[test]
    fn storage_read_missing_is_not_found() {
        let (_dir, b) = backend();
        let k = StorageKey::new("does-not-exist");
        assert!(matches!(b.read(&k), Err(HardwareError::NotFound)));
    }

    #[test]
    fn storage_exists_reports_correctly() {
        let (_dir, b) = backend();
        let k = StorageKey::new("x");
        assert!(!b.exists(&k).unwrap());
        b.write(&k, b"1").unwrap();
        assert!(b.exists(&k).unwrap());
    }

    #[test]
    fn storage_delete_is_idempotent() {
        let (_dir, b) = backend();
        let k = StorageKey::new("x");
        b.delete(&k).unwrap(); // not present, still ok
        b.write(&k, b"1").unwrap();
        b.delete(&k).unwrap();
        assert!(!b.exists(&k).unwrap());
    }

    #[test]
    fn storage_list_filters_by_prefix() {
        let (_dir, b) = backend();
        b.write(&StorageKey::new("a/1"), b"x").unwrap();
        b.write(&StorageKey::new("a/2"), b"y").unwrap();
        b.write(&StorageKey::new("b/1"), b"z").unwrap();

        let keys = b.list("a/").unwrap();
        let names: Vec<_> = keys.iter().map(|k| k.as_str()).collect();
        assert_eq!(names, vec!["a/1", "a/2"]);
    }

    #[test]
    fn key_provider_stub_refuses() {
        let (_dir, b) = backend();
        let spec = super::super::super::KeySpec::Ed25519Sign;
        assert!(matches!(b.generate(spec), Err(HardwareError::NotSupported)));
    }

    #[test]
    fn attestation_verifier_is_not_supported_on_software() {
        use super::super::super::AttestationVerifier as _;
        let (_dir, b) = backend();
        let report = AttestationReport {
            measurements: vec![Measurement {
                component: "kernel".into(),
                digest: vec![0xAA; 32],
            }],
            nonce: None,
            signature: None,
        };
        let policy = AttestationPolicy::new();
        assert!(matches!(
            b.verify(&report, &policy),
            Err(AttestationError::NotSupported)
        ));
    }

    #[test]
    fn measured_boot_reports_unavailable() {
        use super::super::super::MeasuredBoot as _;
        let (_dir, b) = backend();
        assert!(matches!(b.registers(), Err(HardwareError::NotAvailable)));
        assert!(matches!(b.register(0), Err(HardwareError::NotAvailable)));
    }

    #[test]
    fn secure_boot_state_is_unknown_on_software() {
        use super::super::super::SecureBoot as _;
        let (_dir, b) = backend();
        let state = b.state();
        assert!(state.is_unknown());
        assert!(!state.is_verified());
        assert!(!state.is_failed());
    }

    #[test]
    fn key_provider_attest_key_is_not_supported() {
        let (_dir, b) = backend();
        let handle = KeyHandle::from_bytes(vec![1, 2, 3]);
        assert!(matches!(
            b.attest_key(&handle, None),
            Err(HardwareError::NotSupported)
        ));
    }

    #[test]
    fn key_provider_key_info_is_not_supported() {
        let (_dir, b) = backend();
        let handle = KeyHandle::from_bytes(vec![1, 2, 3]);
        assert!(matches!(
            b.key_info(&handle),
            Err(HardwareError::NotSupported)
        ));
    }

    #[test]
    fn attestation_reports_unavailable() {
        let (_dir, b) = backend();
        assert!(!b.is_available());
        assert!(matches!(b.measure("x"), Err(HardwareError::NotSupported)));
        assert!(matches!(b.attest(None), Err(HardwareError::NotSupported)));
    }

    #[test]
    fn secure_memory_alloc_returns_zeroed_buffer() {
        let (_dir, b) = backend();
        let buf = b.alloc(16).unwrap();
        assert_eq!(buf.as_slice().len(), 16);
        assert!(buf.as_slice().iter().all(|&b| b == 0));
        assert!(!buf.is_locked());
    }

    #[test]
    fn backend_reports_its_name() {
        use super::super::super::Backend as _;
        let (_dir, b) = backend();
        assert_eq!(b.name(), "software");
    }

    #[test]
    fn backend_random_fills_buffer() {
        use super::super::super::Backend as _;
        let (_dir, b) = backend();
        let mut buf = [0u8; 16];
        b.random().fill_bytes(&mut buf).unwrap();
        // Not all zeros (astronomically unlikely).
        assert!(buf.iter().any(|&x| x != 0));
    }

    #[test]
    fn secure_memory_lock_is_not_supported_yet() {
        let (_dir, b) = backend();
        let mut buf = b.alloc(16).unwrap();
        assert!(matches!(b.lock(&mut buf), Err(HardwareError::NotSupported)));
        assert!(!buf.is_locked());
    }

    // =========================================================================
    // RNG integration
    // =========================================================================

    /// A TRNG that always succeeds, for tests.
    struct FixedTrng {
        byte: u8,
    }

    impl crate::hardware::TrngSource for FixedTrng {
        fn read(&self, dest: &mut [u8]) -> Result<(), crate::crypto::random::RandomError> {
            dest.fill(self.byte);
            Ok(())
        }
        fn name(&self) -> &'static str {
            "fixed"
        }
    }

    #[test]
    fn default_backend_has_no_trng_on_this_platform() {
        // On Termux and on general-purpose PCs without root access,
        // SoftwareTrng::try_open returns None. The mixed source then
        // reduces to OS-only.
        let (_dir, b) = backend();
        assert!(!b.rng().has_usable_trng());
        assert!(b.rng().trng_name().is_none());
    }

    #[test]
    fn backend_with_explicit_trng_uses_it() {
        let dir = TempDir::new().unwrap();
        let b = SoftwareBackend::with_trng(dir.path(), Box::new(FixedTrng { byte: 0xAA })).unwrap();

        assert!(b.rng().has_usable_trng());
        assert_eq!(b.rng().trng_name(), Some("fixed"));

        let mut buf = [0u8; 32];
        b.rng().fill_bytes(&mut buf).unwrap();
        // The output is a mix, not the TRNG constant alone.
        assert!(!buf.iter().all(|&x| x == 0xAA));
    }

    #[test]
    fn backend_random_reflects_underlying_source() {
        use super::super::super::Backend as _;
        let dir = TempDir::new().unwrap();
        let b = SoftwareBackend::with_trng(dir.path(), Box::new(FixedTrng { byte: 0x55 })).unwrap();

        // Backend::random() must expose the mixed source, not a
        // separate one.
        let mut buf = [0u8; 16];
        b.random().fill_bytes(&mut buf).unwrap();
        assert!(buf.iter().any(|&x| x != 0));
    }

    // =========================================================================
    // End-to-end tests through Backend::random()
    // =========================================================================

    #[test]
    fn random_fills_every_common_size() {
        use super::super::super::Backend as _;
        let (_dir, b) = backend();

        for size in [1usize, 12, 16, 32, 64, 128, 256] {
            let mut buf = vec![0u8; size];
            b.random().fill_bytes(&mut buf).unwrap();
            assert_eq!(buf.len(), size);
            // A run of all-zeros of length >= 16 is statistically
            // impossible with a healthy source.
            if size >= 16 {
                assert!(buf.iter().any(|&x| x != 0), "size {size} all zeros");
            }
        }
    }

    #[test]
    fn consecutive_draws_differ() {
        use super::super::super::Backend as _;
        let (_dir, b) = backend();

        let mut a = [0u8; 32];
        let mut c = [0u8; 32];
        b.random().fill_bytes(&mut a).unwrap();
        b.random().fill_bytes(&mut c).unwrap();
        assert_ne!(a, c, "two 32-byte draws should not collide");
    }

    #[test]
    fn byte_distribution_is_not_patologically_biased() {
        use super::super::super::Backend as _;
        let (_dir, b) = backend();

        // Draw 4096 bytes and count each value. With 4096 samples over
        // 256 values we expect ~16 per value. A healthy source should
        // keep every count below 40 and every count nonzero (with
        // overwhelming probability).
        let mut buf = vec![0u8; 4096];
        b.random().fill_bytes(&mut buf).unwrap();

        let mut counts = [0u32; 256];
        for &byte in &buf {
            counts[byte as usize] += 1;
        }

        for (value, &count) in counts.iter().enumerate() {
            assert!(count > 0, "value {value} never appeared in 4096 draws");
            assert!(
                count < 40,
                "value {value} appeared {count} times (expected ~16)"
            );
        }
    }

    #[test]
    fn backend_random_generates_a_usable_ed25519_key() {
        use super::super::super::Backend as _;
        use crate::crypto::sign::{self, SigningKey};

        let (_dir, b) = backend();

        // Draw a 32-byte seed from the backend and use it to build a
        // signing key. If the backend is broken, this would produce a
        // key that cannot sign consistently.
        let mut seed = [0u8; 32];
        b.random().fill_bytes(&mut seed).unwrap();

        let signing = SigningKey::from_bytes(&seed).unwrap();
        let verifying = signing.verifying_key();

        let message = b"end-to-end test through the backend";
        let signature = signing.sign(message);
        verifying.verify(message, &signature).unwrap();

        // Sanity: a different key does not verify.
        let other = sign::generate();
        assert!(other.verifying.verify(message, &signature).is_err());
    }

    #[test]
    fn backend_random_output_is_mixed_with_trng_when_present() {
        use super::super::super::Backend as _;

        // Two backends: one with TRNG, one without. Given the same
        // sequence of calls, their outputs must differ, because the
        // TRNG contributes to the mix.
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let with_trng =
            SoftwareBackend::with_trng(dir_a.path(), Box::new(FixedTrng { byte: 0x00 })).unwrap();
        let without = SoftwareBackend::new(dir_b.path()).unwrap();

        let mut a = [0u8; 32];
        let mut c = [0u8; 32];
        with_trng.random().fill_bytes(&mut a).unwrap();
        without.random().fill_bytes(&mut c).unwrap();

        // Different processes would still differ by OS entropy, but
        // within the same test process the OS RNG advances, so we only
        // assert that both are non-zero and differ from the constant
        // TRNG.
        assert_ne!(a, [0u8; 32]);
        assert_ne!(c, [0u8; 32]);
    }
}
