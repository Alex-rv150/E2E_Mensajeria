# bob.py 
# Ed25519 para la clave de identidad que firma (IKB_sig).
# X25519 para IKB_dh, SPKB y OPKB (claves de Diffie–Hellman).
# Este script representa a Bob en el protocolo X3DH + Double Ratchet:
# 1) Publica su bundle (IKB_sig, IKB_dh, SPKB, OPKB, SIG) en el servidor.
# 2) Espera el mensaje inicial de Alice (X3DH).
# 3) Reconstruye la clave compartida SK.
# 4) Inicializa el Double Ratchet para continuar la conversación cifrada.

import socket
import json
import time
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ratchet import init_bob, encrypt_message, decrypt_message


def kdf(shared: bytes) -> bytes:
    """
    Deriva una clave simétrica de 32 bytes a partir del secreto compartido
    X3DH usando HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,                 # Sin salt: solo para demo/prototipo.
        info=b"x3dh-prototype"     # Contexto / etiqueta del propósito de la KDF.
    )
    return hkdf.derive(shared)


# Configuración del servidor "simple" que actúa como intermediario de mensajes.
HOST = "127.0.0.1"
PORT = 5000


def enviar_bundle_ao_server(IKB_sig_pub, IKB_dh_pub, SPKB_pub, SIG, OPKB_pub):
    """
    Envía al servidor el bundle público de Bob:
      - IKB_sig: clave pública Ed25519 (identidad de firma).
      - IKB_dh: clave pública X25519 (identidad DH).
      - SPKB:   Signed Pre-Key pública (X25519).
      - SIG:    firma de IKB_sig sobre SPKB_pub.
      - OPKB:   One-Time Pre-Key pública (X25519).
    El servidor almacenará este bundle para que Alice pueda iniciar X3DH.
    """

    # 6. Construir el bundle a enviar al servidor
    msg = {
        "type": "bob_bundle",

        # Clave pública de firma (para que Alice pueda verificar SIG)
        "IKB_sig": IKB_sig_pub.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        ).hex(),

        # Clave pública de identidad DH (X25519)
        "IKB_dh": IKB_dh_pub.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        ).hex(),

        # Signed Pre-Key pública (ya viene como bytes crudos)
        "SPKB": SPKB_pub.hex(),

        # Firma sobre SPKB_pub
        "SIG": SIG.hex(),

        # One-Time Pre-Key pública
        "OPKB": OPKB_pub.hex(),
    }

    # Enviamos el JSON como una línea terminada en '\n'
    line = json.dumps(msg).encode("utf-8") + b"\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(line)
        resp = s.recv(1024)
        print("[BOB] Respuesta del servidor:", resp.decode("utf-8", errors="replace"))


def esperar_mensaje_inicial():
    """
    Bob consulta periódicamente al servidor para ver si ya llegó
    el mensaje inicial de Alice (resultado de X3DH del lado de Alice).
    Retorna el diccionario con el mensaje inicial cuando esté disponible.
    """
    while True:
        req = {"type": "get_initial_for_bob"}
        line = json.dumps(req).encode("utf-8") + b"\n"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(line)
            data = s.recv(4096)

        resp = json.loads(data.decode("utf-8", errors="replace"))

        if resp.get("status") == "ok":
            print("[BOB] Mensaje inicial recibido desde el servidor.")
            return resp["message"]
        else:
            print("[BOB] Aún no hay mensaje inicial, reintentando...")
            time.sleep(1)


def enviar_dr_a_alice(packet: dict):
    """
    Envía un paquete Double Ratchet (ya cifrado) desde Bob hacia Alice,
    encapsulándolo en un mensaje para el servidor.
    """
    payload = {
        "type": "dr_msg_BtoA",
        "packet": packet
    }
    line = json.dumps(payload).encode("utf-8") + b"\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(line)
        resp = s.recv(1024)
        print("[BOB] DR enviado, resp servidor:",
              resp.decode("utf-8", errors="replace"))


def recibir_dr_para_bob(dr_state):
    """
    Consulta al servidor si hay un nuevo mensaje Double Ratchet dirigido a Bob.
    Si lo hay, lo descifra usando el estado 'dr_state'.
    """
    req = {"type": "get_dr_for_bob"}
    line = json.dumps(req).encode("utf-8") + b"\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(line)
        data = s.recv(4096)

    resp = json.loads(data.decode("utf-8", errors="replace"))

    if resp.get("status") != "ok":
        print("[BOB] No hay mensajes DR nuevos.")
        return

    packet = resp["packet"]

    # AD fijo para los mensajes de Double Ratchet (puede ser cualquier etiqueta).
    ad = b"DR"

    plaintext = decrypt_message(dr_state, packet, ad=ad)
    print("[BOB] Mensaje DR recibido de Alice:",
          plaintext.decode("utf-8", errors="replace"))


def main():
    # Clave de firma de identidad de Bob (Ed25519)
    IKB_sig = ed25519.Ed25519PrivateKey.generate()
    IKB_sig_pub = IKB_sig.public_key()

    # Clave de identidad DH de Bob (X25519)
    IKB_dh = x25519.X25519PrivateKey.generate()
    IKB_dh_pub = IKB_dh.public_key()

    # 3. Signed Pre-Key (SPKB) en X25519
    SPKB = x25519.X25519PrivateKey.generate()
    SPKB_pub = SPKB.public_key()
    spkb_bytes = SPKB_pub.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )

    # 4. Firma SIG = Sig(IKB_sig, Encode(SPKB_pub))
    # Esta firma vincula la SPKB con la identidad de firma de Bob.
    SIG = IKB_sig.sign(spkb_bytes)

    # 5. One-Time Pre-Key (OPKB) en X25519
    OPKB = x25519.X25519PrivateKey.generate()
    OPKB_priv = OPKB
    OPKB_pub = OPKB.public_key()
    opkb_bytes = OPKB_pub.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )

    # 2. Enviar el bundle al servidor para que Alice pueda arrancar X3DH
    enviar_bundle_ao_server(IKB_sig_pub, IKB_dh_pub, spkb_bytes, SIG, opkb_bytes)

    # 3) Esperar a que Alice envíe el mensaje inicial resultante de X3DH
    msg = esperar_mensaje_inicial()

    # 4) Reconstruir datos del mensaje inicial recibido de Alice
    ik_a_hex       = msg["IK_A"]         # Clave de identidad DH de Alice
    ek_a_hex       = msg["EK_A"]         # Clave efímera DH de Alice
    used_opk       = msg["OPKB_pub"]     # Indica (o contiene) la OPK usada
    nonce_hex      = msg["nonce"]
    ciphertext_hex = msg["ciphertext"]

    print("[BOB] Mensaje inicial recibido de Alice:")
    print(f"  IK_A      = {ik_a_hex}")
    print(f"  EK_A      = {ek_a_hex}")
    print(f"  used_opk  = {used_opk}")
    print(f"  nonce     = {nonce_hex}")
    print(f"  ciphertext= {ciphertext_hex}")

    # Convertir de hex a bytes
    ik_a_bytes = bytes.fromhex(ik_a_hex)
    ek_a_bytes = bytes.fromhex(ek_a_hex)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Reconstruir las claves públicas X25519 de Alice
    IK_A_pub = x25519.X25519PublicKey.from_public_bytes(ik_a_bytes)
    EK_A_pub = x25519.X25519PublicKey.from_public_bytes(ek_a_bytes)

    # === Cálculo de los secretos DH de X3DH (lado de Bob) ===

    # Alice: DH1 = IK_A * SPKB_pub
    # Bob:   DH1 = SPKB_priv * IK_A_pub
    DH1 = SPKB.exchange(IK_A_pub)
    print("DH1", DH1.hex())

    # Alice: DH2 = EK_A * IKB_dh_pub
    # Bob:   DH2 = IKB_dh_priv * EK_A_pub
    DH2 = IKB_dh.exchange(EK_A_pub)
    print("DH2", DH2.hex())

    # Alice: DH3 = EK_A * SPKB_pub
    # Bob:   DH3 = SPKB_priv * EK_A_pub
    DH3 = SPKB.exchange(EK_A_pub)
    print("DH3", DH3.hex())

    # Se concatena DH1 || DH2 || DH3 (y opcionalmente DH4) para la KDF
    shared = DH1 + DH2 + DH3

    if used_opk:
        # Alice: DH4 = EK_A * OPKB_pub
        # Bob:   DH4 = OPKB_priv * EK_A_pub
        DH4 = OPKB.exchange(EK_A_pub)
        shared += DH4
        print("[BOB] Se usó OPKB (DH4 incluido).")
    else:
        print("[BOB] No se usó OPKB (solo DH1, DH2, DH3).")

    # Derivar la clave simétrica SK con la KDF
    SK = kdf(shared)
    print("[BOB] SK derivada (solo debug):", SK.hex())

    # 6) Descifrar con el mismo AD que usó Alice: header JSON.
    #    IMPORTANTE: este header debe ser *idéntico* en Alice y Bob
    #    para que ChaCha20-Poly1305 verifique correctamente el tag.
    header = {
        "ik_a": ik_a_hex,
        "ek_a": ek_a_hex,
        "used_opk": True,   # OJO: debe coincidir con lo que use Alice en su AD.
    }
    ad = json.dumps(header, sort_keys=True).encode("utf-8")

    aead = ChaCha20Poly1305(SK)

    print("--------------------------------------")
    print("SK:", SK.hex())
    print("nonce:", nonce.hex())
    print("ciphertext:", ciphertext.hex())
    print("ad:", ad)
    print("--------------------------------------")

    # Descifrado del mensaje inicial de Alice (por ejemplo, "Hola, soy Alice")
    plaintext = aead.decrypt(nonce, ciphertext, ad)

    print("[BOB] Mensaje descifrado de Alice:",
          plaintext.decode("utf-8", errors="replace"))

    # Limpieza de secretos de memoria (no estricto, solo buena práctica)
    del OPKB, DH1, DH2, DH3
    if 'DH4' in locals():
        del DH4
    del shared

    # ---------- Double Ratchet ----------
    # A partir de aquí, SK se usa como clave raíz inicial para el Double Ratchet.
    dr_state = init_bob(SK)
    print("[BOB] Double Ratchet inicializado. Puedes chatear.")

    # Bucle de interacción simple por consola:
    #   s: Bob envía mensaje a Alice.
    #   r: Bob consulta al servidor y recibe mensajes pendientes.
    #   q: salir.
    while True:
        cmd = input("[BOB] (s=send, r=recv, q=quit): ").strip().lower()
        if cmd == "s":
            txt = input("[BOB] Mensaje para Alice: ").encode("utf-8")
            packet = encrypt_message(dr_state, txt, ad=b"DR")
            enviar_dr_a_alice(packet)
        elif cmd == "r":
            recibir_dr_para_bob(dr_state)
        elif cmd == "q":
            print("[BOB] Saliendo.")
            break
        else:
            print("Opción no válida.")


if __name__ == "__main__":
    main()
