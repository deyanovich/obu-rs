CHANGELOG
=========

All notable changes to obu will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).


[Unreleased]
------------


[obu v1.0.0] - 2026-06-28
-------------------------

First published release of the obu crate — the unauthenticated /
obfuscation tier of the oboron family, implementing **oboron OBU
spec 1.0**. obu shares no code with the authenticated core
(`oboron` / `obcrypt`).

### Schemes

- **`upcbc`** — unauthenticated probabilistic AES-256-CBC
  (confidentiality only, no integrity; fresh random IV per call).
- **`zdcbc`** — obfuscation-only deterministic AES-128-CBC with a
  constant IV. **Not** cryptographically secure.

String-in / string-out with the same scheme + encoding ergonomics
as `oboron`, operating on a 32-byte secret (64 lowercase hex
characters). Markerless obtext; the scheme is supplied by the
caller. Verified against the canonical obu test vectors.

### Compatibility

- **`obu::Legacy`** (behind the off-by-default `legacy` feature) — a
  DEPRECATED standalone codec that reproduces the pre-1.0 `legacy`
  obtext format (AES-128-CBC under a constant key+IV, `=` padding,
  lowercase RFC base32, then reversed). It is deliberately isolated
  from the `Scheme` / `Format` / `Omnibu` machinery — there is no
  `Scheme::Legacy` — and is used directly via `obu::Legacy`, for
  decoding old values only (not for new code). Verified against the
  canonical `legacy-test-vectors.jsonl`.

### Security / correctness

- The `dec` path always validates UTF-8 and never returns an
  unchecked string (no `unchecked-utf8` feature).
- `dec` rejects any payload that decrypts/strips to empty
  (OBU §2.2); `enc` already rejected the empty plaintext. `upcbc`
  reports the uniform `DecryptionFailed` so this isn't a
  distinguishing oracle.
- The testing-only `zmock1` identity scheme is not selectable from a
  string (`Scheme::from_str` / `Format::from_str` reject it) — a
  no-encryption scheme must never be reachable through a
  string/config channel. Construct it by value if needed in tests.

### Tooling

- Added a `SECURITY.md` spelling out the (non-)guarantees and a
  GitLab CI pipeline (test matrix + clippy); the negative test
  vectors are exercised alongside the positive ones.
