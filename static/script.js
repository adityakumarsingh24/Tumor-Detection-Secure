async function pemToArrayBuffer(pem) {
    // fetch the PEM string, remove header/footer, decode base64
    const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----/, '')
                   .replace(/-----END PUBLIC KEY-----/, '')
                   .replace(/\s+/g, '');
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

async function importServerPublicKey(pem) {
    const spki = await pemToArrayBuffer(pem);
    return await window.crypto.subtle.importKey(
        'spki',
        spki,
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        },
        false,
        ['encrypt']
    );
}

function ab2b64(buf) {
    let binary = '';
    const bytes = new Uint8Array(buf);
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}

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
        // Fetch server public key PEM
        const resp = await fetch('/static/server_pub.pem');
        const pem = await resp.text();

        // Import RSA public key
        const serverPubKey = await importServerPublicKey(pem);

        // Generate AES-GCM key
        const aesKey = await crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, true, ['encrypt', 'decrypt']);
        const rawAes = await crypto.subtle.exportKey('raw', aesKey);

        // Read file as ArrayBuffer
        const fileBuf = await file.arrayBuffer();

        // Encrypt file bytes with AES-GCM
        const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce
        const cipherBuf = await crypto.subtle.encrypt({name: 'AES-GCM', iv: iv}, aesKey, fileBuf);

        // Append tag is already part of cipherBuf in WebCrypto (ciphertext includes the tag at the end)
        // Encrypt raw AES key with server RSA public key (RSA-OAEP)
        const encryptedKeyBuf = await crypto.subtle.encrypt({name: 'RSA-OAEP'}, serverPubKey, rawAes);

        // Convert to base64
        const payload = {
            encrypted_key: ab2b64(encryptedKeyBuf),
            iv: ab2b64(iv.buffer),
            ciphertext: ab2b64(cipherBuf)
        };

        statusEl.textContent = 'Uploading encrypted blob...';

        const res = await fetch('/predict', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
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
