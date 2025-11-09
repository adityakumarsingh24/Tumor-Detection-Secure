/**
 * Convert PEM public key to ArrayBuffer (robust)
 */
async function pemToArrayBuffer(pem) {
    // Remove headers, footers, whitespace, and non-base64 characters
    const b64 = pem
        .replace(/-----BEGIN PUBLIC KEY-----/g, '')
        .replace(/-----END PUBLIC KEY-----/g, '')
        .replace(/\s+/g, '')          // remove all whitespace/newlines
        .replace(/[^A-Za-z0-9+/=]/g, '');
    let binary;
    try {
        binary = atob(b64);
    } catch (err) {
        console.error('Base64 decoding failed:', err);
        console.log('Invalid Base64 string:', b64);
        throw new Error('Invalid PEM format or corrupted public key.');
    }
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

/**
 * Import server public key as CryptoKey
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
 * Convert ArrayBuffer to Base64
 */
function ab2b64(buf) {
    const bytes = new Uint8Array(buf);
    const chunk = 0x8000; // chunk to avoid stack limits
    let binary = '';
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}

/**
 * Handle file upload, AES+RSA encryption, and submission
 */
document.getElementById('upload-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const statusEl = document.getElementById('status');
    const resultEl = document.getElementById('result');
    resultEl.textContent = '';
    statusEl.textContent = 'Preparing encryption...';

    const input = document.getElementById('file');
    if (!input.files.length) {
        alert('Select a file first');
        return;
    }
    const file = input.files[0];

    try {
        // Fetch server public key PEM from static folder
        const resp = await fetch('/static/server_pub.pem'); // ensure path is correct
        if (!resp.ok) throw new Error('Failed to fetch server public key');
        const pem = await resp.text();
        const serverPubKey = await importServerPublicKey(pem);

        // Generate AES-GCM key
        const aesKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        const rawAes = await crypto.subtle.exportKey('raw', aesKey);

        // Read file as ArrayBuffer
        const fileBuf = await file.arrayBuffer();

        // Encrypt file with AES-GCM
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cipherBuf = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            aesKey,
            fileBuf
        );

        // Encrypt AES key with server RSA public key
        const encryptedKeyBuf = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            serverPubKey,
            rawAes
        );

        // Convert everything to Base64
        const payload = {
            encrypted_key: ab2b64(encryptedKeyBuf),
            iv: ab2b64(iv.buffer),
            ciphertext: ab2b64(cipherBuf)
        };

        statusEl.textContent = 'Uploading encrypted blob...';

        // Send payload to server
        const res = await fetch('/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        statusEl.textContent = '';
        resultEl.textContent = JSON.stringify(data, null, 2);

    } catch (err) {
        statusEl.textContent = '';
        resultEl.textContent = 'Error: ' + err.toString();
        console.error(err);
    }
});
