# E2E_Mensajeria
El presente trabajo aborda la implementación y análisis del protocolo Signal, cuyo diseño combina dos mecanismos complementarios: el X3DH (Extended Triple Diffie–Hellman) para el intercambio inicial de claves de manera asíncrona, y el Double Ratchet, responsable de la rotación continua de claves a lo largo de la sesión.

### Cómo ejecutar el proyecto

1. **Instalar dependencias**

   ```bash
   pip install cryptography
   ````

2. **Levantar el servidor**

   En una terminal:

   ```bash
   python server.py
   ```

3. **Ejecutar Bob**

   En una segunda terminal:

   ```bash
   python bob.py
   ```

4. **Ejecutar Alice**

   En una tercera terminal:

   ```bash
   python alice.py
   ```
### Explicación del código
## server.py
**server.py** implementa un servidor intermedio que actúa como puente entre Alice y Bob en la comunicación cifrada. Su función principal es recibir los mensajes cifrados de un participante y retransmitirlos al otro. Además, este servidor almacena el paquete de claves públicas (bundle) de Bob para que Alice pueda recuperarlo al iniciar la conversación. El servidor **no realiza ningún cifrado ni descifrado**; simplemente entrega los mensajes, asegurando que Alice y Bob puedan comunicarse sin compartir directamente sus direcciones o conexiones.
## bob.py
**bob.py** corresponde al cliente de Bob, uno de los participantes en la comunicación segura. Cuando Bob inicia su programa, genera (o carga) su paquete de claves públicas y lo publica en el servidor para que esté disponible para Alice. Tras publicar sus claves, Bob queda a la espera de mensajes entrantes. Cuando recibe el primer mensaje cifrado de Alice a través del servidor, Bob lo descifra utilizando la clave secreta compartida obtenida del intercambio inicial (**X3DH**). Luego, Bob puede responder con mensajes cifrados propios, usando el algoritmo Double Ratchet para actualizar sus claves en cada mensaje y mantener la conversación privada y segura.
## alice.py
alice.py corresponde al cliente de Alice, quien inicia la comunicación cifrada con Bob. Al ejecutarse, el programa de Alice primero descarga del servidor el bundle o paquete de claves públicas de Bob. Con esas claves, Alice lleva a cabo el protocolo de intercambio X3DH (Extended Triple Diffie-Hellman) para calcular una clave secreta compartida con Bob. Una vez establecida esta clave compartida, Alice cifra el primer mensaje y lo envía a Bob a través del servidor. Este mensaje inicial inicia la sesión segura de extremo a extremo; Bob podrá descifrarlo con la clave compartida y, a partir de ahí, ambos continuarán la conversación usando Double Ratchet para mantener la seguridad de los mensajes sucesivos.
## ratchet.py
**ratchet.py** es un módulo auxiliar que implementa el algoritmo **Double Ratchet** para el cifrado simétrico continuo de los mensajes. Este algoritmo se encarga de **actualizar las claves de cifrado** cada vez que Alice o Bob envían y reciben un mensaje, de modo que cada mensaje quede protegido con una clave única. En la práctica, tras el intercambio inicial de claves (X3DH), el módulo ratchet genera nuevas claves simétricas derivadas para cada mensaje enviado o recibido. Esto garantiza que, aunque una clave de sesión se vea comprometida en el futuro, los mensajes anteriores y posteriores permanezcan seguros. Tanto Alice como Bob utilizan las funciones de ratchet.py durante la conversación para cifrar y descifrar cada mensaje manteniendo la confidencialidad y la seguridad de la comunicación.

