const KEY_SIZE_AES = 256;
const ALGORITHM_AES = 'AES-CBC';
const RSA_ALGORITHM = 'RSA-OAEP';
const SERVER_UPDATE_URL = '/api/v1/admin/update';
const SERVER_GET_ENV_URL = '/api/v1/admin/env';

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

const ADMIN_API_KEY = getCookie('admin_api_key');
if (!ADMIN_API_KEY) { window.location.href = '/'; }

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

function getQueryParams() {
    const params = new URLSearchParams(window.location.search);
    return { project: params.get('project'), env: params.get('env') };
}

async function loadEnvForModification() {
    const { project, env } = getQueryParams();
    if (!project || !env) {
        document.getElementById('modifyStatus').textContent = "Error: Missing project information.";
        return;
    }

    try {
        const response = await fetch(SERVER_GET_ENV_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Admin-API-Key': ADMIN_API_KEY
            },
            body: JSON.stringify({ project: project, env_name: env })
        });

        if (!response.ok) {
            throw new Error(`Data load fail: ${await response.text()}`);
        }
        const result = await response.json();
        const envData = result.envData;

        document.getElementById('modifyForm').style.display = 'block';
        document.getElementById('modifyProjectEnv').value = `${project}/${env}`;
        document.getElementById('currentProject').value = project;
        document.getElementById('currentEnv').value = env;
        document.getElementById('modifyEnvData').value = JSON.stringify(envData, null, 2);
        document.getElementById('modifyStatus').textContent = `"${project}/${env}" loaded. You can now edit the JSON.`;

    } catch (e) {
        document.getElementById('modifyStatus').textContent = `${e.message}`;
        console.error(e);
    }
}

async function saveModification(e) {
    e.preventDefault();

    const submitBtn = document.querySelector('#modifyForm button[type="submit"]');
    submitBtn.disabled = true;
    displayMessage('Encrypting and saving changes...', false);

    try {
        const project = document.getElementById('currentProject').value;
        const env = document.getElementById('currentEnv').value;
        const envDataRaw = document.getElementById('modifyEnvData').value.trim();
        const rsaPublicKeyPem = document.getElementById('modifyRsaPublicKey').value.trim();

        const envData = JSON.parse(envDataRaw);
        const fullPayload = JSON.stringify(envData);
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

        const response = await fetch(SERVER_UPDATE_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Admin-API-Key': ADMIN_API_KEY
            },
            body: JSON.stringify({ project: project, env_name: env, encryptedData: finalEncryptedObject })
        });

        if (!response.ok) {
            throw new Error(`Update Fail: ${await response.text()}`);
        }

        displayMessage('Changes have been successfully saved and re-encrypted!', false);
        setTimeout(() => window.location.href = '/admin/list', 1000);

    } catch (e) {
        displayMessage(`${e.message}.`, true);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Encrypt and Save Changes';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadEnvForModification();
    document.getElementById('modifyForm').addEventListener('submit', saveModification);
});
