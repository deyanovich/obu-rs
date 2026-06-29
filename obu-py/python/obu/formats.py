"""Format string constants for obu.

All constants follow the pattern:  {SCHEME}_{ENCODING}
- Schemes: UPCBC, ZDCBC
- Encodings:
  - B32 (RFC 4648 base32),
  - B64 (RFC 4648 base64url),
  - C32 (Crockford base32),
  - HEX (hexadecimal)

There are no ``zmock1`` constants: the testing-only identity scheme is
not selectable from a string (``Obu`` / ``Omnibu`` / the free ``enc``
reject it).

Example:
    >>> from obu import formats
    >>> from obu import Obu
    >>>
    >>> o = Obu(formats.UPCBC_B64, secret)
    >>> ot = o.enc("not-a-secret")
"""

# upcbc — unauthenticated probabilistic AES-256-CBC (confidentiality
# only, NOT authenticated)
UPCBC_B32: str = "upcbc.b32"
UPCBC_B64: str = "upcbc.b64"
UPCBC_C32: str = "upcbc.c32"
UPCBC_HEX: str = "upcbc.hex"

# zdcbc — deterministic AES-128-CBC (⚠️ obfuscation only, NOT secure)
ZDCBC_B32: str = "zdcbc.b32"
ZDCBC_B64: str = "zdcbc.b64"
ZDCBC_C32: str = "zdcbc.c32"
ZDCBC_HEX: str = "zdcbc.hex"

__all__ = [
    # upcbc
    "UPCBC_B32", "UPCBC_B64", "UPCBC_C32", "UPCBC_HEX",
    # zdcbc
    "ZDCBC_B32", "ZDCBC_B64", "ZDCBC_C32", "ZDCBC_HEX",
]
