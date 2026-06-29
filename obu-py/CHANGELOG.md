# Changelog

All notable changes to `obu-py` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


## [1.0.0] - 2026-06-29

First release of the Python bindings for `obu` — the unauthenticated
/ obfuscation tier of the oboron family. Tracks obu core **1.0.0**.

⚠️ obu is **not** authenticated: `upcbc` is confidentiality-only and
`zdcbc` is obfuscation-only. Never use it to protect secrets — use the
`oboron` package for authenticated encryption.

### Added

- **Fixed-format codec classes** — `UpcbcC32/B32/B64/Hex` and
  `ZdcbcC32/B32/B64/Hex`. Each binds a 32-byte secret + scheme +
  encoding; constructed from a 64-character hex secret (or
  `keyless=True` for the public hardcoded secret, testing only).
  `enc` / `dec` plus `format` / `scheme` / `encoding` / `secret` /
  `secret_hex` / `secret_bytes` getters.
- **Runtime-flexible `Obu`** — format chosen at construction and
  mutable afterward via `set_format` / `set_scheme` / `set_encoding`.
- **Multi-format `Omnibu`** — the format is supplied per `enc` / `dec`
  call. The obtext is markerless, so there is no autodetection.
- **`generate_secret()` / `generate_secret_bytes()`** — fresh random
  32-byte secrets (hex string / raw `bytes`).
- **Convenience `enc` / `dec`** (and keyless variants) — one-shot
  `enc(plaintext, format, secret)` wrappers.
- **`obu.formats`** — `UPCBC_*` / `ZDCBC_*` format-string constants.
- **`ObuBase` ABC** and **`ObtextCodec` protocol** — the fixed-format
  codecs and `Obu` register as virtual subclasses for `isinstance`
  checks and polymorphic typing.
- **Custom exception hierarchy** rooted at `ObuError`
  (`InvalidSecret`, `InvalidFormat`, `EncryptionFailed`,
  `DecryptionFailed`).
- Type stubs (`_obu.pyi`, `py.typed` via maturin) for IDE / mypy /
  pyright support.

### Notes

- The bindings are conformance-tested against the canonical obu test
  vectors run *through* the PyO3 boundary (1328 positive — zdcbc
  reproduces the obtext byte-for-byte, upcbc round-trips — plus the
  obu negative vectors, and the 165 legacy vectors in `legacy`
  builds), not merely with round-trip smoke tests.
- The testing-only `zmock1` identity scheme is gated behind the
  off-by-default `mock` feature and is not selectable from a string;
  it is not in the published wheel.
- The deprecated standalone `Legacy` codec (decode-only compatibility
  for pre-1.0 `legacy` obtext) is gated behind the off-by-default
  `legacy` feature and is not in the published wheel.
- Built against PyO3's stable ABI (`abi3-py38`): one wheel per
  platform covers CPython 3.8+.
