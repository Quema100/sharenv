const KEY_SIZE_AES = 256;
const ALGORITHM_AES = 'AES-CBC';
const RSA_ALGORITHM = 'RSA-OAEP';
const SERVER_SAVE_URL = '/api/v1/admin/save';

const getAdminApiKeyFromCookie = () => {
    const name = "admin_api_key=";
    const decodedCookie = decodeURIComponent(document.cookie);
    const ca = decodedCookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

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

async function encryptAndSave(e) {
    e.preventDefault();

    const submitBtn = document.querySelector('#envForm button[type="submit"]');
    submitBtn.disabled = true;
    displayMessage('Encrypting...', false);

    const ADMIN_API_KEY = getAdminApiKeyFromCookie();

    if (!ADMIN_API_KEY) {
        displayMessage('Authentication key not found in cookies. Please log in again.', true);
        setTimeout(() => window.location.href = '/', 2000);
        return;
    }

    try {
        const project = document.getElementById('project').value.trim();
        const env = document.getElementById('env').value.trim();
        const envDataRaw = document.getElementById('envData').value.trim();
        const whitelistIps = document.getElementById('whitelistIps').value.trim().split(',').map(ip => ip.trim()).filter(ip => ip.length > 0);
        const rsaPublicKeyPem = document.getElementById('rsaPublicKey').value.trim();

        const envData = JSON.parse(envDataRaw);
        const fullPayload = JSON.stringify({ ...envData, WHITELIST_IPS: whitelistIps });
        const dataBuffer = new TextEncoder().encode(fullPayload);

        const iv = crypto.getRandomValues(new Uint8Array(16));
        const aesKey = await crypto.subtle.generateKey({ name: ALGORITHM_AES, length: KEY_SIZE_AES }, true, ['encrypt', 'decrypt']);
        const encryptedDataBuffer = await crypto.subtle.encrypt({ name: ALGORITHM_AES, iv: iv }, aesKey, dataBuffer);

        const rsaPublicKey = await importRsaPublicKey(rsaPublicKeyPem);
        const exportedAesKey = await crypto.subtle.exportKey('raw', aesKey);
        const encryptedAesKeyBuffer = await crypto.subtle.encrypt({ name: RSA_ALGORITHM }, rsaPublicKey, exportedAesKey);

        const finalEncryptedObject = {
            project: project, env: env,
            data: btoa(String.fromCharCode(...new Uint8Array(encryptedDataBuffer))),
            key_rsa: btoa(String.fromCharCode(...new Uint8Array(encryptedAesKeyBuffer))),
            iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('')
        };

        const response = await fetch(SERVER_SAVE_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Admin-API-Key': ADMIN_API_KEY
            },
            body: JSON.stringify({
                project: project,
                env: env,
                encryptedData: finalEncryptedObject
            })
        });

        if (!response.ok) {
            throw new Error(`Save Fail: ${await response.text()}`);
        }

        displayMessage('New environment variables have been successfully saved and encrypted!', false);
        document.getElementById('envForm').reset();
        setTimeout(() => window.location.href = '/admin/list', 1000);

    } catch (e) {
        console.error("Critical Encryption/Save Error:", e);
        displayMessage(`${e.message}.`, true);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Encrypt and Save to Server';
    }
}

document.addEventListener('DOMContentLoaded', () => document.getElementById('envForm').addEventListener('submit', encryptAndSave));