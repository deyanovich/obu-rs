//! Python bindings for `obu` via PyO3 / maturin.
//!
//! ⚠️ obu is NOT authenticated. `upcbc` provides confidentiality
//! without integrity (the ciphertext is tamperable); `zdcbc` is
//! obfuscation only and is NOT cryptographically secure. Never use obu
//! to protect secrets — use the `oboron` package for authenticated
//! encryption.
//!
//! The Rust extension module is `obu._obu`. The user-facing API is the
//! `obu` Python package; `python/obu/__init__.py` re-exports from this
//! module. See the project README for usage.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

create_exception!(_obu, ObuError, PyException);
create_exception!(_obu, InvalidSecret, ObuError);
create_exception!(_obu, InvalidFormat, ObuError);
create_exception!(_obu, EncryptionFailed, ObuError);
create_exception!(_obu, DecryptionFailed, ObuError);

/// Map an `obu::Error` to the closest custom Python exception.
fn map_error(e: obu::Error) -> PyErr {
    let msg = e.to_string();
    match e {
        // Secret parsing / length problems. The core message for
        // `InvalidKeyLength` is "secret must be 32 bytes (64 hex
        // characters)" despite the historical variant name.
        obu::Error::InvalidKeyLength | obu::Error::InvalidHex => InvalidSecret::new_err(msg),

        // Format-string / scheme-name / encoding-name problems.
        obu::Error::InvalidFormat
        | obu::Error::InvalidScheme
        | obu::Error::UnknownScheme
        | obu::Error::UnknownEncoding => InvalidFormat::new_err(msg),

        // Encrypt-path failures (including the empty-plaintext guard and
        // the 0x01 pad-byte rejection).
        obu::Error::EncryptionFailed
        | obu::Error::EmptyPlaintext
        | obu::Error::PlaintextEndsWithPadByte => EncryptionFailed::new_err(msg),

        // Decrypt-path failures — obtext decoding (bad base32/64/hex),
        // block-length / payload shape, and post-decrypt UTF-8
        // validation all happen on the dec side.
        obu::Error::DecryptionFailed
        | obu::Error::EmptyPayload
        | obu::Error::PayloadTooShort
        | obu::Error::InvalidBlockLength
        | obu::Error::InvalidB64
        | obu::Error::InvalidB32
        | obu::Error::InvalidC32
        | obu::Error::InvalidUtf8 => DecryptionFailed::new_err(msg),

        // `obu::Error` is `#[non_exhaustive]` — future variants fall
        // through here.
        _ => ObuError::new_err(msg),
    }
}

// ---------------------------------------------------------------------------
// Per-scheme codec classes (fixed format)
// ---------------------------------------------------------------------------

/// Generate a Python wrapper class for a fixed-format obu codec. Each
/// instance binds a 32-byte secret + scheme + encoding; constructors
/// accept the canonical 64-character hex secret.
macro_rules! impl_zcodec_class {
    ($py_name:ident, $rust_type:ty, $doc:expr) => {
        #[doc = $doc]
        #[pyclass(module = "obu._obu")]
        #[allow(non_camel_case_types)]
        struct $py_name {
            inner: $rust_type,
        }

        #[pymethods]
        impl $py_name {
            /// Create a new codec instance.
            ///
            /// Args:
            ///     secret:  64-character hex secret (canonical).
            ///              Required if keyless=False.
            ///     keyless: If True, uses the publicly hardcoded secret
            ///              (testing / obfuscation only — provides no
            ///              security).
            ///
            /// Raises:
            ///     InvalidSecret: Bad hex / wrong length.
            ///     ValueError:    Both `secret` and `keyless=True`
            ///                    given, or neither.
            #[new]
            #[pyo3(signature = (secret=None, keyless=false))]
            fn new(secret: Option<&str>, keyless: bool) -> PyResult<Self> {
                let inner = match (secret, keyless) {
                    (Some(s), false) => <$rust_type>::new(s).map_err(map_error)?,
                    #[cfg(feature = "keyless")]
                    (None, true) => <$rust_type>::new_keyless().map_err(map_error)?,
                    #[cfg(not(feature = "keyless"))]
                    (None, true) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "keyless support not compiled in",
                        ));
                    }
                    (Some(_), true) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "specify either secret or keyless=True, not both",
                        ));
                    }
                    (None, false) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "must provide either secret or keyless=True",
                        ));
                    }
                };
                Ok(Self { inner })
            }

            /// Encrypt + encode `plaintext` to an obtext string.
            fn enc(&self, plaintext: &str) -> PyResult<String> {
                self.inner.enc(plaintext).map_err(map_error)
            }

            /// Decode + decrypt an obtext string back to plaintext.
            fn dec(&self, obtext: &str) -> PyResult<String> {
                self.inner.dec(obtext).map_err(map_error)
            }

            /// The format string bound to this codec, e.g. `"upcbc.c32"`.
            #[getter]
            fn format(&self) -> String {
                self.inner.format().to_string()
            }

            /// The scheme name bound to this codec, e.g. `"upcbc"`.
            #[getter]
            fn scheme(&self) -> String {
                self.inner.scheme().to_string()
            }

            /// The encoding name bound to this codec, e.g. `"c32"`.
            #[getter]
            fn encoding(&self) -> String {
                self.inner.encoding().to_string()
            }

            /// The 64-character hex secret (canonical obu form).
            #[getter]
            fn secret(&self) -> String {
                self.inner.secret()
            }

            /// The secret as a 64-character hex string (alias for
            /// `.secret`).
            #[getter]
            fn secret_hex(&self) -> String {
                self.inner.secret_hex()
            }

            /// The raw 32-byte secret material. Provided for interop
            /// with byte-native APIs; the canonical form everywhere else
            /// is `.secret` (hex).
            #[getter]
            fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
                PyBytes::new(py, self.inner.secret_bytes())
            }

            fn __repr__(&self) -> String {
                format!("{}(format='{}')", stringify!($py_name), self.inner.format())
            }
        }
    };
}

// Upcbc variants — unauthenticated probabilistic AES-256-CBC
// (confidentiality only, fresh random IV per call; NOT authenticated).
#[cfg(feature = "upcbc")]
impl_zcodec_class!(
    UpcbcC32,
    ::obu::UpcbcC32,
    "Upcbc codec (unauthenticated probabilistic AES-256-CBC — NOT authenticated) with C32 encoding"
);
#[cfg(feature = "upcbc")]
impl_zcodec_class!(
    UpcbcB32,
    ::obu::UpcbcB32,
    "Upcbc codec (unauthenticated probabilistic AES-256-CBC — NOT authenticated) with B32 encoding"
);
#[cfg(feature = "upcbc")]
impl_zcodec_class!(
    UpcbcB64,
    ::obu::UpcbcB64,
    "Upcbc codec (unauthenticated probabilistic AES-256-CBC — NOT authenticated) with B64 encoding"
);
#[cfg(feature = "upcbc")]
impl_zcodec_class!(
    UpcbcHex,
    ::obu::UpcbcHex,
    "Upcbc codec (unauthenticated probabilistic AES-256-CBC — NOT authenticated) with Hex encoding"
);

// Zdcbc variants — deterministic AES-128-CBC with a constant IV
// (⚠️ obfuscation only, NOT cryptographically secure).
#[cfg(feature = "zdcbc")]
impl_zcodec_class!(
    ZdcbcC32,
    ::obu::ZdcbcC32,
    "Zdcbc codec (deterministic AES-128-CBC — obfuscation only, NOT secure) with C32 encoding"
);
#[cfg(feature = "zdcbc")]
impl_zcodec_class!(
    ZdcbcB32,
    ::obu::ZdcbcB32,
    "Zdcbc codec (deterministic AES-128-CBC — obfuscation only, NOT secure) with B32 encoding"
);
#[cfg(feature = "zdcbc")]
impl_zcodec_class!(
    ZdcbcB64,
    ::obu::ZdcbcB64,
    "Zdcbc codec (deterministic AES-128-CBC — obfuscation only, NOT secure) with B64 encoding"
);
#[cfg(feature = "zdcbc")]
impl_zcodec_class!(
    ZdcbcHex,
    ::obu::ZdcbcHex,
    "Zdcbc codec (deterministic AES-128-CBC — obfuscation only, NOT secure) with Hex encoding"
);

// Zmock1 variants (testing — identity scheme, no encryption). Gated
// behind `mock`, never in a published wheel.
#[cfg(feature = "mock")]
impl_zcodec_class!(
    Zmock1C32,
    ::obu::Zmock1C32,
    "Zmock1 codec (identity scheme, NO encryption — testing only) with C32 encoding"
);
#[cfg(feature = "mock")]
impl_zcodec_class!(
    Zmock1B32,
    ::obu::Zmock1B32,
    "Zmock1 codec (identity scheme, NO encryption — testing only) with B32 encoding"
);
#[cfg(feature = "mock")]
impl_zcodec_class!(
    Zmock1B64,
    ::obu::Zmock1B64,
    "Zmock1 codec (identity scheme, NO encryption — testing only) with B64 encoding"
);
#[cfg(feature = "mock")]
impl_zcodec_class!(
    Zmock1Hex,
    ::obu::Zmock1Hex,
    "Zmock1 codec (identity scheme, NO encryption — testing only) with Hex encoding"
);

// ---------------------------------------------------------------------------
// Obu — runtime-mutable format selection
// ---------------------------------------------------------------------------

/// Flexible codec with runtime format selection. Wraps `obu::Obu` and
/// lets you change the scheme/encoding after construction. The obtext is
/// markerless, so `dec` always uses the codec's current format — there
/// is no scheme autodetection.
#[pyclass(module = "obu._obu")]
struct Obu {
    inner: ::obu::Obu,
}

#[pymethods]
impl Obu {
    /// Create a new Obu instance.
    ///
    /// Args:
    ///     format:  Format string like `"upcbc.c32"`, `"zdcbc.b64"`.
    ///     secret:  64-character hex secret (canonical). Required if
    ///              keyless=False.
    ///     keyless: If True, uses the publicly hardcoded secret.
    #[new]
    #[pyo3(signature = (format, secret=None, keyless=false))]
    fn new(format: &str, secret: Option<&str>, keyless: bool) -> PyResult<Self> {
        let inner = match (secret, keyless) {
            (Some(s), false) => ::obu::Obu::new(format, s).map_err(map_error)?,
            #[cfg(feature = "keyless")]
            (None, true) => ::obu::Obu::new_keyless(format).map_err(map_error)?,
            #[cfg(not(feature = "keyless"))]
            (None, true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "keyless support not compiled in",
                ));
            }
            (Some(_), true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "specify either secret or keyless=True, not both",
                ));
            }
            (None, false) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "must provide either secret or keyless=True",
                ));
            }
        };
        Ok(Self { inner })
    }

    fn enc(&self, plaintext: &str) -> PyResult<String> {
        self.inner.enc(plaintext).map_err(map_error)
    }

    fn dec(&self, obtext: &str) -> PyResult<String> {
        self.inner.dec(obtext).map_err(map_error)
    }

    #[getter]
    fn format(&self) -> String {
        self.inner.format().to_string()
    }

    #[getter]
    fn scheme(&self) -> String {
        self.inner.scheme().to_string()
    }

    #[getter]
    fn encoding(&self) -> String {
        self.inner.encoding().to_string()
    }

    #[getter]
    fn secret(&self) -> String {
        self.inner.secret()
    }

    #[getter]
    fn secret_hex(&self) -> String {
        self.inner.secret_hex()
    }

    #[getter]
    fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.secret_bytes())
    }

    /// Switch to a new format (scheme + encoding).
    fn set_format(&mut self, format: &str) -> PyResult<()> {
        self.inner.set_format(format).map_err(map_error)
    }

    /// Switch the scheme, keeping the current encoding. Only `upcbc` /
    /// `zdcbc` are accepted — the testing-only `zmock1` is not
    /// selectable from a string.
    fn set_scheme(&mut self, scheme: &str) -> PyResult<()> {
        let s = ::obu::Scheme::from_str(scheme).map_err(map_error)?;
        self.inner.set_scheme(s).map_err(map_error)
    }

    /// Switch the encoding, keeping the current scheme.
    fn set_encoding(&mut self, encoding: &str) -> PyResult<()> {
        let e = ::obu::Encoding::from_str(encoding).map_err(map_error)?;
        self.inner.set_encoding(e).map_err(map_error)
    }

    fn __repr__(&self) -> String {
        format!("Obu(format='{}')", self.inner.format())
    }
}

// ---------------------------------------------------------------------------
// Omnibu — multi-format
// ---------------------------------------------------------------------------

/// Multi-format codec — the format is supplied per `enc`/`dec` call.
#[pyclass(module = "obu._obu")]
struct Omnibu {
    inner: ::obu::Omnibu,
}

#[pymethods]
impl Omnibu {
    #[new]
    #[pyo3(signature = (secret=None, keyless=false))]
    fn new(secret: Option<&str>, keyless: bool) -> PyResult<Self> {
        let inner = match (secret, keyless) {
            (Some(s), false) => ::obu::Omnibu::new(s).map_err(map_error)?,
            #[cfg(feature = "keyless")]
            (None, true) => ::obu::Omnibu::new_keyless().map_err(map_error)?,
            #[cfg(not(feature = "keyless"))]
            (None, true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "keyless support not compiled in",
                ));
            }
            (Some(_), true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "specify either secret or keyless=True, not both",
                ));
            }
            (None, false) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "must provide either secret or keyless=True",
                ));
            }
        };
        Ok(Self { inner })
    }

    fn enc(&self, plaintext: &str, format: &str) -> PyResult<String> {
        self.inner.enc(plaintext, format).map_err(map_error)
    }

    fn dec(&self, obtext: &str, format: &str) -> PyResult<String> {
        self.inner.dec(obtext, format).map_err(map_error)
    }

    #[getter]
    fn secret(&self) -> String {
        self.inner.secret()
    }

    #[getter]
    fn secret_hex(&self) -> String {
        self.inner.secret_hex()
    }

    #[getter]
    fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.secret_bytes())
    }

    fn __repr__(&self) -> &'static str {
        "Omnibu()"
    }
}

// ---------------------------------------------------------------------------
// Legacy — DEPRECATED standalone codec (gated `legacy`, off by default)
// ---------------------------------------------------------------------------

/// DEPRECATED standalone legacy codec. Reproduces the pre-1.0 `legacy`
/// obtext format (deterministic AES-128-CBC under a constant key+IV
/// split from the secret, `=`-padding, lowercase RFC 4648 base32, then
/// full-string byte-reverse). For decoding old values only — NOT for new
/// code, NOT cryptographically secure. Deliberately isolated: it has no
/// `format`/`scheme`/`encoding` and no `secret_hex` alias.
#[cfg(feature = "legacy")]
#[pyclass(module = "obu._obu")]
struct Legacy {
    inner: ::obu::Legacy,
}

#[cfg(feature = "legacy")]
#[pymethods]
impl Legacy {
    #[new]
    #[pyo3(signature = (secret=None, keyless=false))]
    fn new(secret: Option<&str>, keyless: bool) -> PyResult<Self> {
        let inner = match (secret, keyless) {
            (Some(s), false) => ::obu::Legacy::new(s).map_err(map_error)?,
            #[cfg(feature = "keyless")]
            (None, true) => ::obu::Legacy::new_keyless().map_err(map_error)?,
            #[cfg(not(feature = "keyless"))]
            (None, true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "keyless support not compiled in",
                ));
            }
            (Some(_), true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "specify either secret or keyless=True, not both",
                ));
            }
            (None, false) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "must provide either secret or keyless=True",
                ));
            }
        };
        Ok(Self { inner })
    }

    fn enc(&self, plaintext: &str) -> PyResult<String> {
        self.inner.enc(plaintext).map_err(map_error)
    }

    fn dec(&self, obtext: &str) -> PyResult<String> {
        self.inner.dec(obtext).map_err(map_error)
    }

    /// The 64-character hex secret. (Legacy has no `secret_hex` alias.)
    #[getter]
    fn secret(&self) -> String {
        self.inner.secret()
    }

    /// The raw 32-byte secret material.
    #[getter]
    fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.secret_bytes())
    }

    fn __repr__(&self) -> &'static str {
        "Legacy()"
    }
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// Generate a fresh random 32-byte secret, returned as a 64-character
/// lowercase hex string — the canonical obu secret form.
#[pyfunction]
fn generate_secret() -> String {
    ::obu::generate_secret()
}

/// Generate a fresh random 32-byte secret as raw `bytes`.
#[pyfunction]
fn generate_secret_bytes(py: Python<'_>) -> Bound<'_, PyBytes> {
    PyBytes::new(py, &::obu::generate_secret_bytes())
}

/// Encrypt + encode `plaintext` under `format` using `secret`.
///
/// Convenience wrapper that constructs an `Omnibu` internally; for
/// repeated calls, construct an `Omnibu` once and reuse it.
#[pyfunction]
fn enc(plaintext: &str, format: &str, secret: &str) -> PyResult<String> {
    ::obu::Omnibu::new(secret)
        .map_err(map_error)?
        .enc(plaintext, format)
        .map_err(map_error)
}

/// Decode + decrypt `obtext` under `format` using `secret`.
#[pyfunction]
fn dec(obtext: &str, format: &str, secret: &str) -> PyResult<String> {
    ::obu::Omnibu::new(secret)
        .map_err(map_error)?
        .dec(obtext, format)
        .map_err(map_error)
}

/// Encrypt + encode `plaintext` under `format` with the hardcoded secret
/// (testing / obfuscation only).
#[cfg(feature = "keyless")]
#[pyfunction]
fn enc_keyless(plaintext: &str, format: &str) -> PyResult<String> {
    ::obu::Omnibu::new_keyless()
        .map_err(map_error)?
        .enc(plaintext, format)
        .map_err(map_error)
}

/// Decode + decrypt `obtext` under `format` with the hardcoded secret.
#[cfg(feature = "keyless")]
#[pyfunction]
fn dec_keyless(obtext: &str, format: &str) -> PyResult<String> {
    ::obu::Omnibu::new_keyless()
        .map_err(map_error)?
        .dec(obtext, format)
        .map_err(map_error)
}

// ---------------------------------------------------------------------------
// Module init
// ---------------------------------------------------------------------------

#[pymodule]
fn _obu(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Exceptions
    m.add("ObuError", py.get_type::<ObuError>())?;
    m.add("InvalidSecret", py.get_type::<InvalidSecret>())?;
    m.add("InvalidFormat", py.get_type::<InvalidFormat>())?;
    m.add("EncryptionFailed", py.get_type::<EncryptionFailed>())?;
    m.add("DecryptionFailed", py.get_type::<DecryptionFailed>())?;

    // Flexible interfaces (always present — a valid build has ≥1 scheme).
    m.add_class::<Obu>()?;
    m.add_class::<Omnibu>()?;

    // Upcbc variants
    #[cfg(feature = "upcbc")]
    {
        m.add_class::<UpcbcC32>()?;
        m.add_class::<UpcbcB32>()?;
        m.add_class::<UpcbcB64>()?;
        m.add_class::<UpcbcHex>()?;
    }

    // Zdcbc variants
    #[cfg(feature = "zdcbc")]
    {
        m.add_class::<ZdcbcC32>()?;
        m.add_class::<ZdcbcB32>()?;
        m.add_class::<ZdcbcB64>()?;
        m.add_class::<ZdcbcHex>()?;
    }

    // Zmock1 variants (testing)
    #[cfg(feature = "mock")]
    {
        m.add_class::<Zmock1C32>()?;
        m.add_class::<Zmock1B32>()?;
        m.add_class::<Zmock1B64>()?;
        m.add_class::<Zmock1Hex>()?;
    }

    // Legacy (deprecated, gated)
    #[cfg(feature = "legacy")]
    {
        m.add_class::<Legacy>()?;
    }

    // Secret generation
    m.add_function(wrap_pyfunction!(generate_secret, m)?)?;
    m.add_function(wrap_pyfunction!(generate_secret_bytes, m)?)?;

    // Convenience functions
    m.add_function(wrap_pyfunction!(enc, m)?)?;
    m.add_function(wrap_pyfunction!(dec, m)?)?;
    #[cfg(feature = "keyless")]
    {
        m.add_function(wrap_pyfunction!(enc_keyless, m)?)?;
        m.add_function(wrap_pyfunction!(dec_keyless, m)?)?;
    }

    Ok(())
}
