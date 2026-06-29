# obu-rs

Rust workspace for **obu** — the unauthenticated / obfuscation
tier of the [oboron](https://oboron.org/) family.

> ⚠️ **obu is NOT cryptographically secure.** Its schemes make
> values non-obvious; they do not make them safe. Never use obu to
> protect secrets. For real, authenticated encryption use the
> [`oboron`](https://gitlab.com/oboron/oboron-rs) crate.

## Crates

- [`./obu`](./obu) — the core library: string-in / string-out
  obfuscation (`zdcbc`) and unauthenticated (`upcbc`) codecs with
  the same scheme + encoding ergonomics as `oboron`, but operating
  on a 32-byte secret instead of the authenticated tier's 64-byte
  key. Shares no code with the secure core.

## Layering — the clean cut

obu is deliberately a separate repository from
[`oboron`](https://gitlab.com/oboron/oboron-rs) and
[`obcrypt`](https://gitlab.com/oboron/obcrypt-rs). The split is a
hard boundary:

| | `oboron` / `obcrypt` | `obu` (this) |
|---|---|---|
| Guarantee | authenticated, secure | obfuscation only — **not** secure |
| Tamper detection | yes (AEAD) | no |
| Key / secret | 64-byte master key | 32-byte secret |
| Intended use | protecting secrets | non-secret value obfuscation |

Keeping obu in its own repo means the authenticated core and the
obfuscation tier can never share code, dependencies, or a release
by accident.

## Status

obu implements oboron protocol spec 1.0 (the OBU layer): the two
schemes `upcbc` and `zdcbc`, a single 64-hex-character secret, and
markerless obtext — verified against the canonical obu test vectors.
The crate version tracks the obu layer's own release cadence,
independent of the oboron core.

## Build

```bash
cargo build --workspace
cargo test --workspace
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
