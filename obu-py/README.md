# obu

[![PyPI](https://img.shields.io/pypi/v/obu)](https://pypi.org/project/obu/)
[![Python Versions](https://img.shields.io/pypi/pyversions/obu)](https://pypi.org/project/obu/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Python bindings for [`obu`][obu-rs] — the unauthenticated /
obfuscation tier of the [oboron][oboron] family. A *string-in,
string-out* layer: one call takes plaintext to **obtext** (encrypted
+ encoded), one call brings it back.

> ⚠️ **obu is NOT authenticated.** `upcbc` provides confidentiality
> without integrity (the obtext is tamperable); `zdcbc` is
> obfuscation only and is *not* cryptographically secure. Never use
> obu to protect secrets. For real, authenticated encryption use the
> [`oboron`](https://pypi.org/project/oboron/) package.

obu operates on a **32-byte secret** (64 lowercase hex characters)
and shares no code with the authenticated core.

## Install

```sh
pip install obu
```

Wheels ship for CPython 3.8+ (one abi3 wheel per platform) on Linux,
macOS, and Windows, plus an sdist.

## Quick start

```python
import obu

secret = obu.generate_secret()        # 64-char hex
z = obu.ZdcbcC32(secret)
obtext = z.enc("not-a-secret")
plaintext = z.dec(obtext)
assert plaintext == "not-a-secret"
```

Runtime-flexible (`Obu`, format mutable after construction):

```python
o = obu.Obu("upcbc.b64", secret)
ot = o.enc("hello")
o.set_format("zdcbc.c32")
ot2 = o.enc("hello")
```

Multi-format (`Omnibu`, format supplied per call):

```python
om = obu.Omnibu(secret)
ot = om.enc("hello", "upcbc.b64")
pt = om.dec(ot, "upcbc.b64")          # format supplied, not detected
```

The obtext is **markerless** — it carries no scheme prefix — so `dec`
always needs the format the value was produced with. There is no
autodetection.

## Schemes

- `upcbc` — unauthenticated probabilistic AES-256-CBC. Confidentiality
  only, with a fresh random IV per encryption (so the output differs
  each time). No integrity protection.
- `zdcbc` — obfuscation-only deterministic AES-128-CBC with a constant
  IV. **Not** cryptographically secure, but deterministic: the same
  plaintext always yields the same obtext, usable as a stable handle.

Each scheme is available in four encodings — `c32` (Crockford
base32), `b32` (RFC 4648 base32), `b64` (base64url), and `hex` — as
fixed-format classes (`UpcbcC32`, `ZdcbcHex`, …), via the
runtime-format `Obu`, or via the multi-format `Omnibu`. Combine
scheme and encoding as `scheme.encoding`, e.g. `upcbc.c32`. The
`obu.formats` module exposes the format strings as constants.

## Secret

obu uses a single 256-bit secret, encoded as 64 lowercase hex
characters. `upcbc` uses all 32 bytes as the AES-256 key; `zdcbc`
takes bytes 0–15 as the AES-128 key and bytes 16–31 as its constant
IV. There is no base64 secret form. Generate one with
`obu.generate_secret()`.

## Exceptions

All errors inherit from `obu.ObuError`:

- `InvalidSecret` — bad hex secret / wrong length
- `InvalidFormat` — unknown scheme / encoding / malformed format string
- `EncryptionFailed` — empty plaintext / `0x01` pad-byte rejection
- `DecryptionFailed` — obtext-decode / block-length / payload-shape /
  post-decrypt UTF-8 failure (`upcbc` reports a single uniform
  `DecryptionFailed`, never a distinguishing oracle)

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.

[obu-rs]: https://gitlab.com/oboron/obu-rs
[oboron]: https://gitlab.com/oboron/oboron-rs
