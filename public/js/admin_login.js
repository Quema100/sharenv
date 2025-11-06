const RSA_ALGORITHM = 'RSA-OAEP';

const displayMessage = (text, isError = false) => {
    const msgElement = document.getElementById('message');
    msgElement.textContent = text;
    msgElement.className = isError ? 'error' : 'success';
    msgElement.style.display = 'block';
};

const base64ToArrayBuffer = (base64) => {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
};

const importRsaPublicKey = async (pem) => {
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    const base64 = pem.replace(pemHeader, '').replace(pemFooter, '').replace(/\s/g, '');
    const arrayBuffer = base64ToArrayBuffer(base64);

    return crypto.subtle.importKey(
        'spki',
        arrayBuffer,
        { name: RSA_ALGORITHM, hash: 'SHA-256' },
        true,
        ['encrypt']
    );
};

async function handleLogin(e) {
    e.preventDefault();
    displayMessage('Authenticating...', false);

    const password = document.getElementById('password').value;
    const rsaPublicKeyPem = document.getElementById('rsaPublicKey').value;

    try {
        const challengeResponse = await fetch('/api/v1/admin/challenge');
        if (!challengeResponse.ok) {
            throw new Error('Failed to access Challenge API. Please check if the server is running.');
        }
        const { challenge } = await challengeResponse.json();

        const rsaPublicKey = await importRsaPublicKey(rsaPublicKeyPem);
        const challengeBuffer = new TextEncoder().encode(challenge);

        const encryptedChallengeBuffer = await crypto.subtle.encrypt(
            { name: RSA_ALGORITHM },
            rsaPublicKey,
            challengeBuffer
        );

        const encryptedChallenge = btoa(String.fromCharCode(...new Uint8Array(encryptedChallengeBuffer)));

        const response = await fetch('/admin/access', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password, encryptedChallenge })
        });

        if (response.ok) {
            const result = await response.json();

            displayMessage('Authentication successful! Redirecting to admin panel...', false);

            if (result.redirect) {
                window.location.href = result.redirect;
            }
        } else {
            displayMessage(`Authentication failed: ${response.status} - ${await response.text()}`, true);
        }
    } catch (e) {
        console.error("Critical Login Error:", e);
        displayMessage(`Authentication error: ${e.message}. Please verify the public key format.`, true);
    }
}

document.addEventListener('DOMContentLoaded', () => document.getElementById('loginForm').addEventListener('submit', handleLogin));