# Tumor Detection Secure Scaffold

This scaffold implements a secure end-to-end encrypted image upload and inference flow.

- Client uses **WebCrypto** to:
  - generate a random AES-GCM key,
  - encrypt the image with AES-GCM,
  - encrypt the AES key with the server's RSA public key (RSA-OAEP),
  - send `{ encrypted_key, iv, ciphertext }` to the server.

- Server (Flask) uses **PyCryptodome** to:
  - RSA-decrypt the AES key with `server_priv.pem`,
  - AES-GCM decrypt the image,
  - preprocess and run model inference.

**Model placeholder**
- `model.keras` included as a placeholder file. If you add your real Keras model file named `model.keras`, the server will try to load it.
- If the model is missing or fails to load, the server will return a safe placeholder prediction.

**Notes**
- Replace the provided sample keys with your own for production.
- Do NOT commit `server_priv.pem` to public GitHub in real deployments.
