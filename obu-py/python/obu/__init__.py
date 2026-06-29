"""obu — string-in/string-out UNAUTHENTICATED / obfuscation codecs.

Python bindings for the `obu` Rust crate, the unauthenticated /
obfuscation tier of the oboron family. obu shares no code with the
authenticated core.

⚠️ obu is NOT authenticated. ``upcbc`` provides confidentiality
without integrity (the obtext is tamperable); ``zdcbc`` is obfuscation
only and is NOT cryptographically secure. Never use obu to protect
secrets — for real, authenticated encryption use the ``oboron``
package.

Docs: https://oboron.org/

Secrets are 64-character hex strings — the canonical obu secret form
(a 32-byte secret; there is no base64 form). Every codec constructor
and free function takes the secret as a plain ``str``.

Quick start::

    import obu

    secret = obu.generate_secret()           # 64-char hex
    z = obu.ZdcbcC32(secret)
    obtext = z.enc("not-a-secret")
    plaintext = z.dec(obtext)
    assert plaintext == "not-a-secret"

Runtime-flexible style (``Obu``, format mutable after construction)::

    o = obu.Obu("upcbc.b64", secret)
    obtext = o.enc("hello")
    o.set_format("zdcbc.c32")
    obtext2 = o.enc("hello")

Multi-format style (``Omnibu``, format supplied per call)::

    om = obu.Omnibu(secret)
    obtext = om.enc("hello", "upcbc.b64")
    plaintext = om.dec(obtext, "upcbc.b64")  # format supplied, not detected

Schemes:

- ``upcbc`` — unauthenticated probabilistic AES-256-CBC.
  Confidentiality only (fresh random IV per call), no integrity.
- ``zdcbc`` — obfuscation-only deterministic AES-128-CBC with a
  constant IV. NOT cryptographically secure, but deterministic.

The obtext is markerless (no scheme prefix), so ``dec`` always needs
the format the value was produced with — there is no autodetection.

Encodings: ``b32`` (RFC 4648 base32), ``b64`` (URL-safe base64),
``c32`` (Crockford base32), ``hex``. Concatenated as ``scheme.encoding``,
e.g. ``upcbc.c32``.

Exception hierarchy:

- ``ObuError`` — base class for all obu exceptions
  - ``InvalidSecret`` — bad hex secret / wrong length
  - ``InvalidFormat`` — unknown scheme / encoding / malformed format
  - ``EncryptionFailed`` — empty plaintext / pad-byte rejection
  - ``DecryptionFailed`` — obtext-decode / block-length / UTF-8 failure
"""

from abc import ABC, abstractmethod
from typing import Protocol

from . import _obu
from . import formats

__version__ = _obu.__version__


# ============================================================================
# Protocols and base classes
# ============================================================================


class ObtextCodec(Protocol):
    """Structural protocol every fixed-format / runtime codec satisfies."""

    def enc(self, plaintext: str) -> str: ...
    def dec(self, obtext: str) -> str: ...
    @property
    def format(self) -> str: ...
    @property
    def scheme(self) -> str: ...
    @property
    def encoding(self) -> str: ...


class ObuBase(ABC):
    """Abstract base class for obu codec implementations.

    The fixed-format codec classes (``UpcbcC32``, ``ZdcbcB64``, etc.)
    plus ``Obu`` are registered as virtual subclasses, enabling
    ``isinstance()`` / ``issubclass()`` checks.

    ``Omnibu`` (format supplied per call) and the deprecated ``Legacy``
    codec are deliberately NOT registered — their surfaces differ.

    Example::

        cipher = ZdcbcC32(secret=secret)
        assert isinstance(cipher, ObuBase)

        def process(cipher: ObuBase) -> str:
            return cipher.enc("hello")
    """

    @abstractmethod
    def enc(self, plaintext: str) -> str: ...

    @abstractmethod
    def dec(self, obtext: str) -> str: ...

    @property
    @abstractmethod
    def format(self) -> str: ...

    @property
    @abstractmethod
    def scheme(self) -> str: ...

    @property
    @abstractmethod
    def encoding(self) -> str: ...

    @property
    @abstractmethod
    def secret(self) -> str:
        """The 64-character hex secret (canonical obu form)."""
        ...

    @property
    @abstractmethod
    def secret_hex(self) -> str:
        """Alias for ``.secret``."""
        ...

    @property
    @abstractmethod
    def secret_bytes(self) -> bytes:
        """Raw 32-byte secret material."""
        ...


# ============================================================================
# Register Rust classes as virtual subclasses of ObuBase
# ============================================================================


def _register_if_present(*names: str) -> None:
    for name in names:
        cls = getattr(_obu, name, None)
        if cls is not None:
            ObuBase.register(cls)


_register_if_present(
    "UpcbcC32", "UpcbcB32", "UpcbcB64", "UpcbcHex",
    "ZdcbcC32", "ZdcbcB32", "ZdcbcB64", "ZdcbcHex",
    "Obu",
)


# ============================================================================
# Re-exports
# ============================================================================

# Flexible interfaces
Obu = _obu.Obu
Omnibu = _obu.Omnibu

# Upcbc
UpcbcC32 = _obu.UpcbcC32
UpcbcB32 = _obu.UpcbcB32
UpcbcB64 = _obu.UpcbcB64
UpcbcHex = _obu.UpcbcHex

# Zdcbc
ZdcbcC32 = _obu.ZdcbcC32
ZdcbcB32 = _obu.ZdcbcB32
ZdcbcB64 = _obu.ZdcbcB64
ZdcbcHex = _obu.ZdcbcHex

# Secret generation
generate_secret = _obu.generate_secret
generate_secret_bytes = _obu.generate_secret_bytes

# Convenience functions
enc = _obu.enc
dec = _obu.dec
# keyless convenience fns exist only in `keyless`-feature builds (the
# default); guard so a no-keyless build still imports.
enc_keyless = getattr(_obu, "enc_keyless", None)
dec_keyless = getattr(_obu, "dec_keyless", None)

# Deprecated standalone legacy codec — present only in `legacy`-feature
# builds (not in the published wheel).
Legacy = getattr(_obu, "Legacy", None)

# Exceptions
ObuError = _obu.ObuError
InvalidSecret = _obu.InvalidSecret
InvalidFormat = _obu.InvalidFormat
EncryptionFailed = _obu.EncryptionFailed
DecryptionFailed = _obu.DecryptionFailed


__all__ = [
    "__version__",
    # Base classes / protocols
    "ObuBase",
    "ObtextCodec",
    # Flexible interfaces
    "Obu",
    "Omnibu",
    # Upcbc
    "UpcbcC32", "UpcbcB32", "UpcbcB64", "UpcbcHex",
    # Zdcbc
    "ZdcbcC32", "ZdcbcB32", "ZdcbcB64", "ZdcbcHex",
    # Format constants module
    "formats",
    # Secret generation
    "generate_secret",
    "generate_secret_bytes",
    # Convenience functions
    "enc",
    "dec",
    "enc_keyless",
    "dec_keyless",
    # Exceptions
    "ObuError",
    "InvalidSecret",
    "InvalidFormat",
    "EncryptionFailed",
    "DecryptionFailed",
]
