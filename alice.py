# alice.py 
# Este script implementa el lado de Alice en un prototipo X3DH + Double Ratchet.
# Flujo general:
#   1) Alice pide el bundle de Bob al servidor (IKB_sig, IKB_dh, SPKB, OPKB, SIG).
#   2) Verifica criptográficamente que la Signed Pre-Key (SPKB) fue firmada
#      con la clave de identidad de Bob (IKB_sig).
#   3) Genera sus claves X25519 (IK_A y EK_A) y calcula los DH compartidos
#      (DH1, DH2, DH3 y opcionalmente DH4 con la OPKB).
#   4) Concatena los DH y deriva una clave simétrica SK con HKDF-SHA256.
#   5) Usa SK con ChaCha20-Poly1305 para cifrar el mensaje inicial a Bob.
#   6) Inicializa el Double Ratchet con SK y permite chatear con Bob
#      mediante mensajes cifrados y autenticados.

import socket
import json

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from ratchet import init_alice, encrypt_message, decrypt_message

# Servidor (muy simple) que actúa como intermediario entre Alice y Bob.
HOST = "127.0.0.1"
PORT = 5000


def enviar_dr_a_bob(packet: dict):
    """
    Envía un mensaje Double Ratchet (ya cifrado) desde Alice hacia Bob,
    encapsulado en un paquete JSON que el servidor reenviará.
    """
    payload = {
        "type": "dr_msg_AtoB",
        "packet": packet
    }
    line = json.dumps(payload).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(line)
        resp = s.recv(1024)
        print("[ALICE] DR enviado, resp servidor:",
              resp.decode("utf-8", errors="replace"))
        

def recibir_dr_para_alice(dr_state):
    """
    Consulta al servidor si hay un nuevo mensaje Double Ratchet para Alice.
    Si lo hay, lo descifra usando el estado 'dr_state'.
    """
    req = {"type": "get_dr_for_alice"}
    line = json.dumps(req).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(line)
        data = s.recv(4096)

    resp = json.loads(data.decode("utf-8", errors="replace"))
    if resp.get("status") != "ok":
        print("[ALICE] No hay mensajes DR nuevos.")
        return

    packet = resp["packet"]
    ad = b"DR"  # mismo AD en ambos lados (Alice y Bob) para los mensajes DR
    plaintext = decrypt_message(dr_state, packet, ad=ad)
    print("[ALICE] Mensaje DR recibido de Bob:",
          plaintext.decode("utf-8", errors="replace"))


def enviar_mensaje_inicial(header: dict, nonce: bytes, ciphertext: bytes):
    """
    Empaqueta y envía el mensaje inicial X3DH desde Alice hacia Bob,
    pasando por el servidor. Incluye:
      - IK_A, EK_A (claves públicas de Alice, en hex).
      - OPKB_pub / indicador de uso de OPK.
      - nonce y ciphertext del AEAD ChaCha20-Poly1305.
    """
    payload = {
        "type": "alice_initial",
        "IK_A": header["ik_a"],
        "EK_A": header["ek_a"],
        "OPKB_pub": header["used_opk"],
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }
    line = json.dumps(payload).encode("utf-8") + b"\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(line)
        resp = s.recv(1024)
        print("[ALICE] Respuesta del servidor al mensaje inicial:", resp.decode("utf-8", errors="replace"))


def kdf(shared: bytes) -> bytes:
    """
    Deriva una clave simétrica de 32 bytes a partir del material compartido
    'shared' (DH1 || DH2 || DH3 (|| DH4)) usando HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,                 # Sin salt: solo para demo/prototipo.
        info=b"x3dh-prototype"     # Contexto de aplicación de la KDF.
    )
    return hkdf.derive(shared)


def pedir_bundle_al_servidor():
    """Alice pide el bundle de Bob al servidor y lo devuelve como dict."""
    req = {"type": "get_bob_bundle"}
    line = json.dumps(req).encode("utf-8") + b"\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(line)
        data = s.recv(4096)

    # La respuesta del servidor es una línea JSON con el bundle de Bob.
    resp = json.loads(data.decode("utf-8", errors="replace"))
    return resp


def main():
    # 1) Obtener el bundle de Bob (IKB_sig, IKB_dh, SPKB, OPKB, SIG)
    resp = pedir_bundle_al_servidor()

    if resp.get("status") != "ok":
        print("[ALICE] Error al obtener bundle:", resp)
        return

    bundle = resp["bundle"]

    # Recuperar campos hex -> bytes
    ikb_sig_bytes = bytes.fromhex(bundle["IKB_sig"])
    ikb_dh_bytes  = bytes.fromhex(bundle["IKB_dh"])
    spkb_bytes    = bytes.fromhex(bundle["SPKB"])
    sig_bytes     = bytes.fromhex(bundle["SIG"])
    opkb_bytes    = bytes.fromhex(bundle["OPKB"])

    # Reconstruir claves públicas de Bob
    IKB_sig_pub = ed25519.Ed25519PublicKey.from_public_bytes(ikb_sig_bytes)
    IKB_dh_pub  = x25519.X25519PublicKey.from_public_bytes(ikb_dh_bytes)
    SPKB_pub    = x25519.X25519PublicKey.from_public_bytes(spkb_bytes)
    OPKB_pub    = x25519.X25519PublicKey.from_public_bytes(opkb_bytes)

    # Verificar firma: SIG = Sign(IKB_sig_priv, SPKB_pub_bytes)
    # SPKB_pub_bytes debe ser exactamente lo que firmó Bob
    # (en este diseño, son los bytes "raw" de la public key).
    try:
        IKB_sig_pub.verify(sig_bytes, spkb_bytes)
        print("[ALICE] Firma de SPKB verificada correctamente ✔")
    except Exception as e:
        print("[ALICE] ERROR: firma de SPKB inválida ❌:", e)
        return

    # Si llegamos aquí, Alice confía en que SPKB_pub pertenece a Bob.
    print("[ALICE] IKB_dh_pub:", IKB_dh_pub)
    print("[ALICE] SPKB_pub:", SPKB_pub)
    print("[ALICE] OPKB_pub:", OPKB_pub)

    # ----------------------------------------------- Claves de Alice: IK_A (identidad) y EK_A (efímera)
    # IK_A y EK_A son claves X25519 nuevas. IK_A podría almacenarse a largo plazo
    # si se quisiera modelar la identidad de Alice; aquí es efímero para el ejemplo.
    IK_A = x25519.X25519PrivateKey.generate()
    EK_A = x25519.X25519PrivateKey.generate()

    # DH1 = DH(IK_A, SPKB)  → combina identidad de Alice con SPK de Bob
    DH1 = IK_A.exchange(SPKB_pub)
    print("DH1", DH1.hex())

    # DH2 = DH(EK_A, IKB_dh) → combina efímera de Alice con identidad DH de Bob
    DH2 = EK_A.exchange(IKB_dh_pub)
    print("DH2", DH2.hex())

    # DH3 = DH(EK_A, SPKB)   → combina efímera de Alice con SPK de Bob
    DH3 = EK_A.exchange(SPKB_pub)
    print("DH3", DH3.hex())

    # Concatenamos los DH para alimentar la KDF.
    shared = DH1 + DH2 + DH3

    # ¿Hay OPKB en el bundle? Si sí, añadimos DH4.
    if OPKB_pub is not None:
        # DH4 = DH(EK_A, OPKB)
        DH4 = EK_A.exchange(OPKB_pub)
        shared += DH4
        print("[ALICE] Se usó una One-Time PreKey (DH4 incluido).")
    else:
        print("[ALICE] No hay OPKB en el bundle (solo DH1, DH2, DH3).")

        # Derivar clave SK con KDF(DH1 || DH2 || DH3 (|| DH4))
    SK = kdf(shared)

    # (opcional) Mostrar SK solo para debug
    print("[ALICE] SK derivada (debug, no hacer esto en producción):", SK.hex())

    # Clave pública efímera de Alice en formato raw (bytes).
    EK_A_pub =  EK_A.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )

    # Borrar claves sensibles (a nivel Python: quitar referencias,
    # aunque el GC de Python y la VM no garantizan limpieza inmediata en memoria).
    del EK_A, DH1, DH2, DH3
    if 'DH4' in locals():
        del DH4
    del shared

        # 7) Construir header (AD) con IK_A, EK_A, IDs de prekeys
    # Este header se usará como "Associated Data" (AD) en ChaCha20-Poly1305.
    # Debe ser exactamente igual en Alice y Bob para que el tag de autenticidad
    # verifique correctamente en ambos lados.
    header = {
        "ik_a": IK_A.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    ).hex(),
        "ek_a": EK_A_pub.hex(),
        "used_opk": True,  # Aquí indicamos que se usó una OPK; debe coincidir con Bob.
    }
    ad = json.dumps(header, sort_keys=True).encode("utf-8")

    # 8) Cifrar mensaje inicial con AEAD (ChaCha20-Poly1305)
    # Este será el "primer mensaje" que Bob descifrará usando SK.
    plaintext = b"Hola Bob, soy Alice (mensaje inicial X3DH)"
    nonce = os.urandom(12)  # Nonce de 96 bits recomendado para ChaCha20-Poly1305

    print("--------------------------------------" )
    print("SK:", SK.hex())
    print("nonce:", nonce.hex())
    print("ad:", ad)
    print("plaintext:", plaintext)
    print("--------------------------------------" )
    
    aead = ChaCha20Poly1305(SK)
    ciphertext = aead.encrypt(nonce, plaintext, ad)

    # 9) Enviar mensaje inicial al servidor (que luego lo entrega a Bob)
    enviar_mensaje_inicial(header, nonce, ciphertext)

    # ---------- Double Ratchet: iniciar estado ----------
    # A partir de SK, se inicializa el estado de Alice para el Double Ratchet.
    dr_state = init_alice(SK)
    print("[ALICE] Double Ratchet inicializado. Puedes chatear.")

        # ---------- Bucle de chat ----------
    # Interfaz de consola:
    #   s: enviar mensaje a Bob
    #   r: recibir mensajes pendientes de Bob
    #   q: salir
    while True:
        cmd = input("[ALICE] (s=send, r=recv, q=quit): ").strip().lower()
        if cmd == "s":
            txt = input("[ALICE] Mensaje para Bob: ").encode("utf-8")
            packet = encrypt_message(dr_state, txt, ad=b"DR")
            enviar_dr_a_bob(packet)
        elif cmd == "r":
            recibir_dr_para_alice(dr_state)
        elif cmd == "q":
            print("[ALICE] Saliendo.")
            break
        else:
            print("Opción no válida.")


if __name__ == "__main__":
    main()
