import socket 
import threading
import json

# ---------------------------
# Config
# ---------------------------
HOST = "127.0.0.1"
PORT = 5000

# Bundle de Bob (se inicializa en None y se llena cuando Bob envía "bob_bundle")
# Contiene: IKB_dh, IKB_sig, SPKB, SIG, OPKB.
bob_bundle = None

# Mensajes iniciales que Alice envía a Bob (cola X3DH)
messages_for_bob = []

# Mensajes Double Ratchet:
dr_messages_for_bob = []    # Alice -> Bob
dr_messages_for_alice = []  # Bob -> Alice


# ---------------------------
# Servidor
# ---------------------------
def atender_cliente(conn, addr):
    """
    Maneja una conexión con un cliente (Alice o Bob).
    El protocolo es line-based: cada mensaje es una línea JSON terminada en '\n'.
    Según el campo "type" del JSON, el servidor almacena o devuelve datos:
      - "bob_bundle": Bob publica su bundle de claves.
      - "get_bob_bundle": Alice pide el bundle de Bob.
      - "alice_initial": Alice envía el mensaje inicial X3DH para Bob.
      - "get_initial_for_bob": Bob pide el mensaje inicial.
      - "dr_msg_AtoB": mensaje DR de Alice para Bob.
      - "get_dr_for_bob": Bob pide sus mensajes DR.
      - "dr_msg_BtoA": mensaje DR de Bob para Alice.
      - "get_dr_for_alice": Alice pide sus mensajes DR.
    """
    global bob_bundle, messages_for_bob, dr_messages_for_bob, dr_messages_for_alice
    print(f"[+] Conectado: {addr}")
    conn.settimeout(60)  # Evita conexiones colgadas
    buffer = b""
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break

            buffer += data

            # Protocolo: mensajes terminados en '\n'
            while b"\n" in buffer:
                linea, buffer = buffer.split(b"\n", 1)
                msg = linea.decode("utf-8", errors="replace")

                # Intentamos parsear como JSON
                try:
                    payload = json.loads(msg)
                except json.JSONDecodeError:
                    print(f"[!] Mensaje no es JSON válido: {msg!r}")
                    conn.sendall(b"ERROR: JSON invalido\n")
                    continue

                msg_type = payload.get("type")

                if msg_type == "bob_bundle":
                    # Bob envía: IKB, SPKB, SIG, OPKB
                    bob_bundle = {
                        "IKB_dh": payload.get("IKB_dh"),
                        "IKB_sig": payload.get("IKB_sig"),
                        "SPKB": payload.get("SPKB"),
                        "SIG": payload.get("SIG"),
                        "OPKB": payload.get("OPKB"),
                    }
                    print("[SERVER] Recibido bundle de Bob:")
                    print(f"  IKB_dh  = {bob_bundle['IKB_dh']}")
                    print(f"  IKB_sig = {bob_bundle['IKB_sig']}")
                    print(f"  SPKB    = {bob_bundle['SPKB']}")
                    print(f"  SIG     = {bob_bundle['SIG']}")
                    print(f"  OPKB    = {bob_bundle['OPKB']}")

                    conn.sendall(b"OK: bundle de Bob recibido\n")

                elif msg_type == "get_bob_bundle":
                    # Alice pide el bundle de Bob
                    if bob_bundle is None:
                        print("[SERVER] Alice pidio bundle, pero aun no existe")
                        resp = {"status": "error", "reason": "no_bundle"}
                    else:
                        print("[SERVER] Enviando bundle de Bob a cliente")
                        resp = {"status": "ok", "bundle": bob_bundle}

                    conn.sendall(json.dumps(resp).encode("utf-8") + b"\n")
                
                # 3) Alice envía mensaje inicial cifrado para Bob (X3DH)
                elif msg_type == "alice_initial":
                    # Guardamos todo el payload como mensaje para Bob
                    messages_for_bob.append(payload)
                    print("[SERVER] Guardado mensaje inicial de Alice para Bob")
                    conn.sendall(b"OK: mensaje inicial almacenado\n")

                # 4) Bob pide mensajes iniciales que haya para él
                elif msg_type == "get_initial_for_bob":
                    if not messages_for_bob:
                        resp = {"status": "no_msg"}
                    else:
                        msg_for_bob = messages_for_bob.pop(0)
                        resp = {"status": "ok", "message": msg_for_bob}
                    conn.sendall(json.dumps(resp).encode("utf-8") + b"\n")

                # ----------- DR: Alice -> Bob -----------
                elif msg_type == "dr_msg_AtoB":
                    # Alice envía un paquete Double Ratchet para Bob
                    packet = payload.get("packet")
                    dr_messages_for_bob.append(packet)
                    print("[SERVER] DR A->B almacenado")
                    conn.sendall(b"OK: dr_msg_AtoB almacenado\n")

                elif msg_type == "get_dr_for_bob":
                    # Bob pide un mensaje DR pendiente
                    if not dr_messages_for_bob:
                        resp = {"status": "no_msg"}
                    else:
                        packet = dr_messages_for_bob.pop(0)
                        resp = {"status": "ok", "packet": packet}
                    conn.sendall(json.dumps(resp).encode("utf-8") + b"\n")

                # ----------- DR: Bob -> Alice -----------
                elif msg_type == "dr_msg_BtoA":
                    # Bob envía un paquete Double Ratchet para Alice
                    packet = payload.get("packet")
                    dr_messages_for_alice.append(packet)
                    print("[SERVER] DR B->A almacenado")
                    conn.sendall(b"OK: dr_msg_BtoA almacenado\n")

                elif msg_type == "get_dr_for_alice":
                    # Alice pide un mensaje DR pendiente
                    if not dr_messages_for_alice:
                        resp = {"status": "no_msg"}
                    else:
                        packet = dr_messages_for_alice.pop(0)
                        resp = {"status": "ok", "packet": packet}
                    conn.sendall(json.dumps(resp).encode("utf-8") + b"\n")

                else:
                    # Tipo de mensaje no reconocido
                    print(f"[SERVER] Mensaje desconocido: {payload}")
                    conn.sendall(b"ERROR: tipo de mensaje desconocido\n")

    except socket.timeout:
        print(f"[!] Timeout con {addr}")
    finally:
        conn.close()
        print(f"[-] Cerrado: {addr}")


def main():
    """
    Punto de entrada del servidor.
    Crea un socket TCP, se pone a escuchar en HOST:PORT y lanza un hilo
    por cada cliente que se conecta.
    """
    # Aquí guardaremos el bundle de Bob (se inicializa arriba como variable global)

    # Crear socket TCP/IPv4
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Reusar puerto al reiniciar rápido el server
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[>] Escuchando en {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            # Un hilo por cliente para permitir múltiples conexiones simultáneas
            threading.Thread(
                target=atender_cliente,
                args=(conn, addr),
                daemon=True
            ).start()


# ---------------------------
# Entry point
# ---------------------------
if __name__ == "__main__":
    main()
