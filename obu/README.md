# obu

The unauthenticated / obfuscation tier of the
[oboron](https://gitlab.com/oboron/oboron-rs) family.

> ⚠️ **obu is NOT authenticated.** `upcbc` provides confidentiality
> without integrity (vulnerable to ciphertext tampering); `zdcbc` is
> obfuscation only and is *not* cryptographically secure. Never use
> obu to protect secrets. For real, authenticated encryption use the
> [`oboron`](https://gitlab.com/oboron/oboron-rs) crate.

`obu` provides the same string-in / string-out, scheme + encoding
ergonomics as `oboron`, but operating on a 32-byte secret instead of
the authenticated tier's 64-byte key. It shares no code with the
secure core.

## Schemes

- `upcbc` — unauthenticated probabilistic AES-256-CBC. Confidentiality
  only, with a fresh random IV per encryption (so the output differs
  each time). No integrity protection.
- `zdcbc` — obfuscation-only deterministic AES-128-CBC with a constant
  IV. **Not** cryptographically secure, but deterministic: the same
  plaintext always yields the same obtext, usable as a stable handle.

Each scheme is available in four encodings — `c32` (Crockford
base32), `b32` (RFC 4648 base32), `b64` (base64url), and `hex` — as
fixed-format types (`UpcbcC32`, `ZdcbcHex`, …), via the runtime-format
`Obu`, or via the multi-format `Omnibu`.

A third, **deprecated** codec — `obu::Legacy` — lives behind the
off-by-default `legacy` feature. It reproduces the pre-1.0 `legacy`
obtext format (one fixed form: AES-128-CBC, lowercase RFC base32,
reversed) and is deliberately isolated from the scheme machinery
(there is no `Scheme::Legacy`) — use it directly, for decoding old
values only. Not for new code.

## Secret

obu uses a single 256-bit secret, encoded as 64 lowercase hex
characters. `upcbc` uses all 32 bytes as the AES-256 key; `zdcbc`
takes bytes 0–15 as the AES-128 key and bytes 16–31 as its constant
IV. There is no base64 form.

## Quick start

```rust
use obu::{ZdcbcC32, ObtextCodec};

let secret = obu::generate_secret();   // 64-char hex
let z = ZdcbcC32::new(&secret)?;
let ot = z.enc("not-a-secret")?;
let pt = z.dec(&ot)?;
assert_eq!(pt, "not-a-secret");
# Ok::<(), obu::Error>(())
```

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
