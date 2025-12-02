## 🔐 Modulul Criptografic (`crypto_lib.py`)

Acest fișier este motorul de securitate al aplicației CryptoChat. Acesta abstractizează complexitatea bibliotecii `cryptography` (pyca) și `argon2-cffi`, oferind funcții simple și sigure pentru restul aplicației.

### 🛡️ Algoritmi Implementați

Modulul utilizează o abordare stratificată a securității:

1.  **ChaCha20-Poly1305 (Criptare Simetrică)**
    * Folosit pentru criptarea efectivă a mesajelor și a istoricului.
    * **De ce?** Este mai rapid decât AES pe procesoare mobile/moderne fără accelerare hardware și oferă *Autentificare* integrată (AEAD), garantând integritatea datelor.
    * **Implementare:** Generează automat un `nonce` (12 bytes) aleatoriu pentru fiecare mesaj. Rezultatul este codificat în Base64 pentru transport sigur prin WebSocket.

2.  **Argon2 (Hashing Parole)**
    * Folosit pentru protejarea parolelor utilizatorilor.
    * **De ce?** Este câștigătorul *Password Hashing Competition*, fiind rezistent la atacurile cu GPU și *Rainbow Tables* datorită consumului intensiv de memorie.

3.  **RSA-OAEP (Criptare Asimetrică)**
    * Folosit pentru protejarea și distribuirea cheilor simetrice.
    * **Configurație:** Chei de 2048 biți, exponent 65537, padding OAEP cu SHA-256.
    * *Notă:* În acest proiect, este folosit demonstrativ pentru a salva o copie criptată a cheii comune pe disc (`common_chacha.enc`).

### ⚙️ Funcții Principale

* `chacha20_encrypt(key, plaintext)` -> Returnează `Base64(nonce + ciphertext + tag)`.
* `chacha20_decrypt(key, token_b64)` -> Validează integritatea și returnează textul clar.
* `argon2_hash_password(password)` -> Returnează hash-ul securizat.
* `rsa_generate_keypair()` -> Generează și salvează cheile `.pem`.

### 🔑 Managementul Cheilor
La prima rulare, scriptul:
1.  Generează o pereche de chei RSA.
2.  Generează o cheie aleatoare de 32 de bytes (256 biți) pentru ChaCha20 folosind `secrets.token_bytes`.
3.  Salvează cheia ChaCha20 în fișierul `common_chacha.key` (necesar pentru a rula clientul și serverul).

### 📦 Dependențe
* `cryptography`
* `argon2-cffi`
