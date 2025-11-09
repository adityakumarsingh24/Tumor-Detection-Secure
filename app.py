from flask import Flask, render_template, request, jsonify
import os, base64
from io import BytesIO
from PIL import Image
import numpy as np

app = Flask(__name__)

# ============================================================
# ✅ MODEL LOADING
# ============================================================
MODEL_PATH = "fold_5_best_tolerant.keras"
model = None
model_loaded = False

try:
    from tensorflow.keras.models import load_model
    model = load_model(MODEL_PATH)
    model_loaded = True
    print(f"✅ Model loaded successfully from {MODEL_PATH}")
except Exception as e:
    print("⚠️ Model not loaded (placeholder). Error:", e)

# ============================================================
# ✅ CRYPTOGRAPHY SETUP
# ============================================================
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256  # required for OAEP-SHA256

# Load RSA private key (server's secret key)
PRIVKEY_PATH = "server_priv.pem"
if os.path.exists(PRIVKEY_PATH):
    with open(PRIVKEY_PATH, "rb") as f:
        priv = RSA.import_key(f.read())
    rsa_cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)  # ✅ matches JS SHA-256
    print("🔐 Server private key loaded.")
else:
    rsa_cipher = None
    print("⚠️ Warning: server_priv.pem not found. Decryption will fail until you add the key.")

# Model input image size
IMG_SIZE = (224, 224)

# ============================================================
# ✅ ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template("enhanced_index.html")


@app.route("/predict", methods=["POST"])
def predict():
    if rsa_cipher is None:
        return jsonify({"error": "Server private key not available. Add server_priv.pem."}), 500

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body received"}), 400

    enc_key_b64 = data.get("encrypted_key")
    iv_b64 = data.get("iv")
    ciphertext_b64 = data.get("ciphertext")

    if not enc_key_b64 or not iv_b64 or not ciphertext_b64:
        return jsonify({"error": "Missing required fields (encrypted_key, iv, ciphertext)"}), 400

    try:
        # ====================================================
        # 🔓 STEP 1: Decode all Base64 fields
        # ====================================================
        encrypted_key = base64.b64decode(enc_key_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # ====================================================
        # 🔓 STEP 2: Decrypt AES key with RSA-OAEP (SHA256)
        # ====================================================
        aes_key = rsa_cipher.decrypt(encrypted_key)

        # ====================================================
        # 🔓 STEP 3: Decrypt ciphertext with AES-GCM
        # Ciphertext structure: [data][16-byte tag]
        # ====================================================
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext too short to contain AES-GCM tag.")
        aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        plaintext = aes_cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])

        # ====================================================
        # 🖼️ STEP 4: Convert bytes → image → model input
        # ====================================================
        img = Image.open(BytesIO(plaintext)).convert("RGB").resize(IMG_SIZE)
        img_arr = np.array(img).astype("float32") / 255.0
        img_arr = np.expand_dims(img_arr, axis=0)  # shape (1, H, W, 3)

        # ====================================================
        # 🤖 STEP 5: Predict (or fallback dummy)
        # ====================================================
        if model_loaded and model is not None:
            pred = model.predict(img_arr)
            score = float(pred[0][0])
            label = "Tumor" if score > 0.5 else "No Tumor"
            print(f"✅ Prediction done: {label} ({score:.4f})")
            return jsonify({"result": label, "score": score})
        else:
            print("⚠️ Model missing. Returning dummy prediction.")
            return jsonify({"result": "No Tumor (model missing)", "score": 0.0})

    except ValueError as ve:
        # AES tag mismatch / incorrect decryption
        print("❌ Decryption failed (AES tag mismatch):", ve)
        return jsonify({"error": "Incorrect decryption."}), 500

    except Exception as e:
        print("❌ Unexpected server error:", e)
        return jsonify({"error": str(e)}), 500


# ============================================================
# ✅ SERVER ENTRY POINT
# ============================================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
