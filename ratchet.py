# ratchet.py
import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return kdf.derive(ikm)


def kdf_chain(ck: bytes) -> Tuple[bytes, bytes]:
    """
    A partir de una chain key CK, derivamos:
      MK       = clave de mensaje (32 bytes)
      CK_next  = siguiente chain key (32 bytes)
    """
    out = hkdf(ck, info=b"dr-chain", length=64)
    mk = out[:32]
    ck_next = out[32:]
    return mk, ck_next


@dataclass
class SymmetricRatchetState:
    ck_send: bytes
    ck_recv: bytes
    send_count: int = 0
    recv_count: int = 0


def init_alice(SK: bytes) -> SymmetricRatchetState:
    """
    Inicialización del ratchet en Alice.
    SK viene de X3DH.
    """
    ck_send = hkdf(SK, info=b"dr-A->B", length=32)
    ck_recv = hkdf(SK, info=b"dr-B->A", length=32)
    return SymmetricRatchetState(ck_send=ck_send, ck_recv=ck_recv)


def init_bob(SK: bytes) -> SymmetricRatchetState:
    """
    Inicialización del ratchet en Bob.
    Invertimos las direcciones.
    """
    ck_send = hkdf(SK, info=b"dr-B->A", length=32)
    ck_recv = hkdf(SK, info=b"dr-A->B", length=32)
    return SymmetricRatchetState(ck_send=ck_send, ck_recv=ck_recv)


def encrypt_message(state: SymmetricRatchetState,
                    plaintext: bytes,
                    ad: bytes = b"") -> dict:
    """
    Avanza el ratchet de envío y cifra un mensaje.
    Devuelve un paquete JSON-friendly:
      {
        "n": <int>,
        "nonce": <hex>,
        "ciphertext": <hex>
      }
    """
    mk, ck_next = kdf_chain(state.ck_send)
    state.ck_send = ck_next
    state.send_count += 1

    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(mk)
    ciphertext = aead.encrypt(nonce, plaintext, ad)

    return {
        "n": state.send_count,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }


def decrypt_message(state: SymmetricRatchetState,
                    packet: dict,
                    ad: bytes = b"") -> bytes:
    """
    Avanza el ratchet de recepción y descifra.
    Versión simplificada: mensajes en orden.
    """
    expected_n = state.recv_count + 1
    n = packet["n"]
    if n != expected_n:
        raise ValueError(f"Mensaje fuera de orden: esperado {expected_n}, recibido {n}")

    mk, ck_next = kdf_chain(state.ck_recv)
    state.ck_recv = ck_next
    state.recv_count += 1

    nonce = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])

    aead = ChaCha20Poly1305(mk)
    plaintext = aead.decrypt(nonce, ciphertext, ad)
    return plaintext
