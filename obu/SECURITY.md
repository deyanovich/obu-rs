# Security model — `obu`

> ⚠️ **obu is NOT cryptographically secure.** Read this document
> before using it for anything.

`obu` is the **unauthenticated / obfuscation** tier of the oboron
family. Its purpose is to make values *non-obvious*, not to make
them *safe*. If you need to protect a secret, use the authenticated
[`oboron`](https://gitlab.com/oboron/oboron-rs) /
[`obcrypt`](https://gitlab.com/oboron/obcrypt-rs) crates instead —
`obu` shares no code with them, deliberately.

## What obu provides

`obu` takes a 32-byte secret and a UTF-8 string; it produces obtext
(the scheme output, encoded as text). Two schemes:

| Scheme | Algorithm | Property |
|---|---|---|
| `upcbc` | AES-256-CBC, fresh random IV per call | confidentiality only, **no** integrity |
| `zdcbc` | AES-128-CBC, constant IV (deterministic) | obfuscation only — **not** secure |

- `upcbc` gives IND-CPA confidentiality against a passive observer
  who does not tamper with the obtext.
- `zdcbc` is an obfuscation transform: it makes a value non-obvious
  to a casual reader. It uses a constant IV and is deterministic, so
  equal plaintexts produce equal obtext. It is **not** a
  confidentiality guarantee against any motivated adversary.

## What obu does NOT provide

- **No authentication / integrity.** Neither scheme has a MAC or AEAD
  tag. Tampering with the obtext is **not** detected — `dec` will
  happily return attacker-influenced bytes (subject only to padding
  and UTF-8 validity). Never rely on `obu` output being unmodified.
- **No tamper / wrong-secret detection.** Because there is no tag, a
  wrong secret or a modified payload does not reliably error; it
  yields different (wrong) plaintext or a decode/UTF-8 failure.
- **No secrecy guarantee for `zdcbc`.** Its constant IV and
  determinism leak plaintext equality and make it unsuitable for
  protecting anything an adversary cares to recover.
- **Not for secrets.** Passwords, tokens, PII, keys — none of it
  belongs in `obu`. Use the authenticated core.
- No key exchange, key rotation, transport, or side-channel
  hardening beyond what the upstream `aes` / `cbc` crates provide.

## Input handling

- The empty plaintext is outside the obu domain: `enc` rejects it,
  and `dec` rejects any payload that decrypts/strips to empty
  (OBU spec §2.2).
- `enc` rejects a plaintext whose final byte is the `0x01` padding
  byte, so trailing-`0x01` stripping on `dec` is unambiguous (§2.1).
- `dec` always validates UTF-8 and never returns an unchecked string.
- `upcbc` returns a single uniform `DecryptionFailed` for every
  failure so padding validation cannot become a distinguishing
  oracle (§2.1).
- The secret is 32 bytes, encoded as 64 lowercase hex characters.

## Audit status

`obu` has **not** been independently security-audited — and by design
it makes no security claim worth auditing for confidentiality of
secrets. It is a thin wrapper over the RustCrypto `aes` and `cbc`
crates implementing OBU spec 1.0, pinned by the cross-implementation
obu test vectors. Treat it strictly as an obfuscation tool.

## Reporting

For a security issue in `obu`, email **dev@deyanovich.org** with a
subject beginning `[obu security]`. For non-security bugs, file an
issue on the [GitLab repository](https://gitlab.com/oboron/obu-rs/-/issues).
