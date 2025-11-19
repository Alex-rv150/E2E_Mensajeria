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

