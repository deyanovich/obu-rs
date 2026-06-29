"""Smoke tests for inheritance and basic codec behavior.

Run with ``python -m obu.test_inheritance`` after a successful
``maturin develop`` build, or via ``pytest``.
"""

import obu


def test_obu_base_isinstance():
    secret = obu.generate_secret()

    zdcbc = obu.ZdcbcC32(secret=secret)
    assert isinstance(zdcbc, obu.ObuBase)

    o = obu.Obu("upcbc.b64", secret=secret)
    assert isinstance(o, obu.ObuBase)

    print("OK: core isinstance(ObuBase)")


def test_polymorphic_function():
    def encrypt_with_cipher(cipher: obu.ObuBase, data: str) -> str:
        return cipher.enc(data)

    secret = obu.generate_secret()
    upcbc = obu.UpcbcC32(secret=secret)
    zdcbc = obu.ZdcbcC32(secret=secret)

    ot_u = encrypt_with_cipher(upcbc, "hello")
    ot_z = encrypt_with_cipher(zdcbc, "hello")

    assert upcbc.dec(ot_u) == "hello"
    assert zdcbc.dec(ot_z) == "hello"

    print("OK: polymorphic enc/dec over ObuBase")


def test_omnibu_operations():
    secret = obu.generate_secret()
    om = obu.Omnibu(secret=secret)

    ot_upcbc = om.enc("test", "upcbc.b64")
    ot_zdcbc = om.enc("test", "zdcbc.b64")

    # The format is supplied per dec call (no auto-detection).
    assert om.dec(ot_upcbc, "upcbc.b64") == "test"
    assert om.dec(ot_zdcbc, "zdcbc.b64") == "test"

    print("OK: Omnibu enc + explicit-format dec round-trip")


def test_zdcbc_is_deterministic():
    secret = obu.generate_secret()
    z = obu.ZdcbcC32(secret=secret)
    # zdcbc is deterministic: same plaintext -> same obtext.
    assert z.enc("same") == z.enc("same")
    print("OK: zdcbc determinism")


if __name__ == "__main__":
    test_obu_base_isinstance()
    test_polymorphic_function()
    test_omnibu_operations()
    test_zdcbc_is_deterministic()
    print("\nAll smoke tests passed.")
