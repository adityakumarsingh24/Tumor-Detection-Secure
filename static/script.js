/**
 * Convert PEM public key to ArrayBuffer (robust)
 */
async function pemToArrayBuffer(pem) {
    // Clean PEM text
    const b64 = pem
        .replace(/-----BEGIN PUBLIC KEY-----/g, '')
        .replace(/-----END PUBLIC KEY-----/g, '')
        .replace(/\s+/g, '')
        .replace(/[^A-Za-z0-9+/=]/g, '');
    let binary;
    try {
        binary = atob(b64);
    } catch (err) {
        console.error('Base64 decoding failed:', err);
        throw new Error('Invalid PEM format or corrupted public key.');
    }
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

/**
 * Import server RSA public key
 * (Ensures SHA-256 OAEP — must match Flask PKCS1_OAEP(SHA256))
 */
async function importServerPublicKey(pem) {
    const spkiBuffer = await pemToArrayBuffer(pem);
    try {
        return await crypto.subtle.importKey(
            'spki',
            spkiBuffer,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['encrypt']
        );
    } catch (err) {
        console.error('Failed to import server public key:', err);
        throw new Error('Invalid public key format or unsupported key type.');
    }
}

/**
 * Convert ArrayBuffer → Base64
 */
function ab2b64(buf) {
    const bytes = new Uint8Array(buf);
    const chunk = 0x8000; // avoid stack overflow
    let binary = '';
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}

/**
 * Encrypt and send file to Flask server
 */
document.getElementById('upload-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const statusEl = document.getElementById('status');
    const resultEl = document.getElementById('result');
    resultEl.textContent = '';
    statusEl.textContent = 'Preparing encryption...';

    const input = document.getElementById('file');
    if (!input.files.length) {
        alert('Select a file first.');
        return;
    }

    const file = input.files[0];

    try {
        // 1️⃣ Fetch server public key
        const resp = await fetch('/static/server_pub.pem');
        if (!resp.ok) throw new Error('Failed to fetch server public key');
        const pem = await resp.text();
        const serverPubKey = await importServerPublicKey(pem);

        // 2️⃣ Generate AES-GCM key
        const aesKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        const rawAes = await crypto.subtle.exportKey('raw', aesKey);

        // 3️⃣ Read file as ArrayBuffer
        const fileBuf = await file.arrayBuffer();

        // 4️⃣ Encrypt file using AES-GCM
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cipherBuf = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            aesKey,
            fileBuf
        );

        // 5️⃣ Encrypt AES key with RSA public key (OAEP-SHA256)
        const encryptedKeyBuf = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            serverPubKey,
            rawAes
        );

        // 6️⃣ Convert to Base64 for JSON
        const payload = {
            encrypted_key: ab2b64(encryptedKeyBuf),
            iv: ab2b64(iv.buffer),
            ciphertext: ab2b64(cipherBuf)
        };

        // 7️⃣ Send to Flask backend
        statusEl.textContent = 'Uploading encrypted blob...';
        const res = await fetch('/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        statusEl.textContent = '';
        resultEl.textContent = JSON.stringify(data, null, 2);
        console.log('Server response:', data);

    } catch (err) {
        console.error('Encryption or upload failed:', err);
        statusEl.textContent = '';
        resultEl.textContent = 'Error: ' + err.message;
    }
});
