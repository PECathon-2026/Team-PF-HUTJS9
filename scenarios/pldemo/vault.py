"""Demo vault: seal each real value with XChaCha20-Poly1305 (libsodium via PyNaCl), bound to
session | placeholder | field type | site | element as associated data. Decryption works for the
exact binding and fails for any other. Owner: WIN.

This is a demonstration of the binding idea; the real vault is LNX's `daemons/vault` (C++,
master key in memfd_secret). Keys here live in this process only and are never written out.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from nacl import bindings as nb
from nacl.exceptions import CryptoError

SITE = "sites"


@dataclass(frozen=True)
class Binding:
    session: str
    placeholder: str
    field_type: str
    site: str
    element: str

    def aad(self) -> bytes:
        return "|".join([self.session, self.placeholder, self.field_type, self.site, self.element]).encode()


@dataclass
class Sealed:
    binding: Binding
    nonce: bytes
    ciphertext: bytes


class Vault:
    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        self.session = secrets.token_hex(8)
        self.entries: list[Sealed] = []

    def seal(self, value: str, placeholder: str, field_type: str, element: str, site: str = SITE) -> Sealed:
        b = Binding(self.session, placeholder, field_type, site, element)
        nonce = secrets.token_bytes(nb.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
        ct = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(value.encode(), b.aad(), nonce, self._key)
        s = Sealed(b, nonce, ct)
        self.entries.append(s)
        return s

    def open(self, sealed: Sealed, claimed: Binding) -> str | None:
        """Plaintext only if `claimed` equals the sealed binding exactly; otherwise None."""
        try:
            pt = nb.crypto_aead_xchacha20poly1305_ietf_decrypt(
                sealed.ciphertext, claimed.aad(), sealed.nonce, self._key
            )
        except CryptoError:
            return None
        return pt.decode()

    def binding_test(self, sealed: Sealed, value: str, other_element: str) -> dict[str, bool]:
        """Right binding opens; wrong element, wrong site, wrong type, wrong placeholder, wrong session do not."""
        b = sealed.binding
        wrong = {
            "wrong_field": Binding(b.session, b.placeholder, b.field_type, b.site, other_element),
            "wrong_site": Binding(b.session, b.placeholder, b.field_type, "evil.example", b.element),
            "wrong_type": Binding(
                b.session, b.placeholder, "SECRET" if b.field_type != "SECRET" else "CARD", b.site, b.element
            ),
            "wrong_placeholder": Binding(b.session, b.placeholder + "x", b.field_type, b.site, b.element),
            "wrong_session": Binding("0" * 16, b.placeholder, b.field_type, b.site, b.element),
        }
        res = {"right_binding_opens": self.open(sealed, b) == value}
        for k, wb in wrong.items():
            res[k + "_refused"] = self.open(sealed, wb) is None
        return res
