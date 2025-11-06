require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const readline = require('readline');
const crypto = require('crypto');

const fsService = require('./services/fsService');
const cryptoService = require('./services/cryptoService');

const app = express();

let PORT = process.env.PORT || 3000;
let RSA_PRIVATE_KEY = process.env.RSA_PRIVATE_KEY;
let ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
let CHALLENGE_SECRET = process.env.CHALLENGE_SECRET;

const ENV_PATH = path.join(__dirname, '.env');
const RSA_KEY_SIZE = 2048;

const HASH_ALGORITHM = 'sha256';
const KEY_LENGTH = 64;
const ITERATIONS = 100000;
const SALT_SIZE = 16;

const AUTH_TOKEN_NAME = 'secur_admin_session';
const COOKIE_MAX_AGE = 1800;

const verifyPassword = (password, storedHash) => {
    try {
        const [hashHex, salt, iterations] = storedHash.split('$');
        const HASH_ITERATIONS = parseInt(iterations, 10);

        const hashBuffer = crypto.pbkdf2Sync(
            password,
            salt,
            HASH_ITERATIONS,
            KEY_LENGTH,
            HASH_ALGORITHM
        );
        return crypto.timingSafeEqual(Buffer.from(hashBuffer.toString('hex')), Buffer.from(hashHex));
    } catch (e) {
        return false;
    }
};

function setupInitialConfig() {
    return new Promise((resolve) => {
        if (RSA_PRIVATE_KEY && ADMIN_PASSWORD_HASH && CHALLENGE_SECRET) {
            console.log("All configurations have been successfully loaded.");
            return resolve();
        }

        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        const askQuestion = (query, defaultValue) =>
            new Promise(res =>
                rl.question(`${query} (default: ${defaultValue}): `, (answer) => res(answer || defaultValue)
                )
            );

        const configUpdates = [];

        (async () => {
            try {
                if (!RSA_PRIVATE_KEY) {
                    console.log("\n--- 1. Generating RSA Key Pair ---");
                    console.log("Creating a new RSA public/private key pair...");
                    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
                        modulusLength: RSA_KEY_SIZE,
                        publicKeyEncoding: { type: 'spki', format: 'pem' },
                        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
                    });
                    RSA_PRIVATE_KEY = privateKey;
                    const privateKeyEnv = privateKey.replace(/\n/g, '\\n');
                    configUpdates.push(`\n# --- RSA Key Information ---\nRSA_PRIVATE_KEY="${privateKeyEnv}"\n`);
                    fs.writeFileSync(path.join(__dirname, 'public_key.pem'), publicKey);
                    console.log("RSA key pair generated successfully.");
                }

                const newPort = await askQuestion("Specify the port number to run the server on", PORT);
                PORT = parseInt(newPort, 10);
                configUpdates.push(`PORT=${PORT}\n`);

                if (!ADMIN_PASSWORD_HASH) {
                    console.log("\n--- 3. Set Administrator Password ---");
                    let password;
                    do {
                        password = await askQuestion("Enter a new administrator password (minimum 8 characters)", "");
                        if (password.length < 8) {
                            console.log("The password must be at least 8 characters long.");
                        }
                    } while (password.length < 8);

                    const salt = crypto.randomBytes(SALT_SIZE).toString('hex');
                    const hashBuffer = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, HASH_ALGORITHM);
                    ADMIN_PASSWORD_HASH = `${hashBuffer.toString('hex')}$${salt}$${ITERATIONS}`;
                    CHALLENGE_SECRET = crypto.randomBytes(15).toString('hex');

                    configUpdates.push(`\n# --- Administrator Authentication Secrets ---\nADMIN_PASSWORD_HASH="${ADMIN_PASSWORD_HASH}"\n`);
                    configUpdates.push(`CHALLENGE_SECRET="${CHALLENGE_SECRET}"\n`);
                    console.log("Administrator password hash and challenge secret have been generated.");
                }

                rl.close();
                if (configUpdates.length > 0) {
                    fs.appendFileSync(ENV_PATH, configUpdates.join(''));
                    console.log("\n--- Setup Complete ---");
                }
                resolve();
            } catch (error) {
                console.error("\nA critical error occurred during configuration:", error.message);
                rl.close();
                process.exit(1);
            }
        })();
    });
}

async function startServer() {
    await setupInitialConfig();

    app.use((req, res, next) => {
        req.cookies = {};
        const cookieHeader = req.headers.cookie;
        if (cookieHeader) {
            cookieHeader.split(';').forEach(cookie => {
                const parts = cookie.split('=');
                if (parts.length === 2) {
                    req.cookies[parts[0].trim()] = decodeURIComponent(parts[1].trim());
                }
            });
        }
        next();
    });

    app.use(morgan('combined'));
    app.use(express.json());
    app.use(express.static(path.join(__dirname, 'public')));
    app.use(express.static(path.join(__dirname, 'public/html')));

    if (!RSA_PRIVATE_KEY) { process.exit(1); }

    const checkSession = (req, res, next) => {
        const sessionToken = req.cookies && req.cookies[AUTH_TOKEN_NAME];

        if (sessionToken) {
            next();
        } else {
            console.warn(`[UNAUTH] Blocked access to admin panel by IP: ${req.ip}`);
            res.redirect('/');
        }
    };

    const adminAuth = async (req, res, next) => {
        const { password, encryptedChallenge } = req.body;

        if (!verifyPassword(password, ADMIN_PASSWORD_HASH)) {
            console.warn(`[DENIED] Admin password failed from: ${req.ip}`);
            return res.status(401).send('Unauthorized: Invalid Password.');
        }

        try {
            const decryptedChallenge = cryptoService.decryptChallenge(encryptedChallenge, RSA_PRIVATE_KEY);

            if (decryptedChallenge === CHALLENGE_SECRET) {
                next();
            } else {
                console.warn(`[DENIED] Invalid challenge response (key proof) from: ${req.ip}`);
                res.status(401).send('Unauthorized: Invalid Public Key Proof.');
            }
        } catch (e) {
            console.error(`Decryption failed during admin auth: ${e.message}`);
            res.status(401).send('Unauthorized: Failed to verify public key.');
        }
    };

    const apiKeyAuth = (req, res, next) => {
        const key = req.headers['x-admin-api-key'];
        const ADMIN_API_KEY_HASHED = crypto.createHash('sha256').update(ADMIN_PASSWORD_HASH).digest('hex');

        if (key && key === ADMIN_API_KEY_HASHED) {
            next();
        } else {
            console.warn(`[DENIED] API Key Mismatch: ${req.ip}`);
            res.status(401).send('Unauthorized: Invalid API Key.');
        }
    };

    app.get('/api/v1/admin/challenge', (req, res) => {
        res.json({ challenge: CHALLENGE_SECRET });
    });


    app.post('/admin/access', adminAuth, (req, res) => {
        const sessionToken = crypto.randomBytes(20).toString('hex');
        const ADMIN_API_KEY = crypto.createHash('sha256').update(ADMIN_PASSWORD_HASH).digest('hex');
        res.setHeader('Set-Cookie', [
            `${AUTH_TOKEN_NAME}=${sessionToken}; HttpOnly; Path=/; Max-Age=${COOKIE_MAX_AGE}; SameSite=Lax`,
            `admin_api_key=${ADMIN_API_KEY}; Path=/; Max-Age=${COOKIE_MAX_AGE}; SameSite=Lax`
        ]);

        res.status(200).send({ redirect: '/admin/list' });
    });

    app.post('/admin/logout', (req, res) => {
        res.clearCookie(AUTH_TOKEN_NAME, { path: '/' });
        res.clearCookie('admin_api_key', { path: '/' });

        res.status(200).send({ redirect: '/' });
    });

    app.get('/admin/list', checkSession, (req, res) => {
        res.sendFile(path.join(__dirname, 'public/html/admin_list.html'));
    });
    app.get('/admin/register', checkSession, (req, res) => {
        res.sendFile(path.join(__dirname, 'public/html/admin_register.html'));
    });
    app.get('/admin/edit', checkSession, (req, res) => {
        res.sendFile(path.join(__dirname, 'public/html/admin_edit.html'));
    });

    app.get('/admin/view', checkSession, (req, res) => {
        res.sendFile(path.join(__dirname, 'public/html/admin_view.html'));
    });


    app.get('/', (req, res) => {
        res.sendFile(path.join(__dirname, 'public/html/admin_login_form.html'));
    })


    app.get('/api/v1/env/:project/:env_name', async (req, res) => {
        const { project, env_name } = req.params;
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        console.log(clientIp)
        try {
            const encryptedFile = await fsService.getEncryptedData(project, env_name);
            const aesKey = cryptoService.decryptAesKey(encryptedFile.key_rsa, RSA_PRIVATE_KEY);
            const envData = cryptoService.decryptData(encryptedFile.data, aesKey, encryptedFile.iv);

            const whitelist = envData.WHITELIST_IPS || [];

            if (whitelist.includes(clientIp)) {
                const responseEnv = { ...envData };
                delete responseEnv.WHITELIST_IPS;

                return res.json(responseEnv);

            } else {
                return res.status(403).send('Forbidden: IP not in whitelist.');
            }

        } catch (error) {
            if (error.message === 'FILE_NOT_FOUND') { return res.status(404).send('Environment variables not found.'); }
            return res.status(500).send('Internal Server Error.');
        }
    });

    app.post('/api/v1/admin/save', apiKeyAuth, async (req, res) => {
        const { project, env, encryptedData } = req.body;
        if (!project || !env || !encryptedData || !encryptedData.data || !encryptedData.key_rsa || !encryptedData.iv) {
            return res.status(400).send('Invalid data payload.');
        }

        if (await fsService.exists(project, env)) {
            return res.status(409).send(`'${project}/${env}' already exists. Please use the edit page.`);
        }

        try {
            await fsService.saveEncryptedData(project, env, encryptedData);
            res.status(201).send('Environment variables successfully saved and encrypted.');
        } catch (error) {
            res.status(500).send('Failed to save data.');
        }
    });

    app.post('/api/v1/admin/delete', apiKeyAuth, async (req, res) => {
        const { project, env_name } = req.body;

        if (!project || !env_name) {
            return res.status(400).send('Bad Request: Project and env_name are required.');
        }

        try {
            await fsService.deleteEncryptedData(project, env_name);

            if (!(await fsService.exists(project, env_name))) {
                return res.status(404).send(`'${project}/${env_name}' not found. Please register it first.`);
            }

            console.log(`[ADMIN] Deleted ENV for ${project}/${env_name} by ${req.ip}`);
            res.status(200).send('Environment variables successfully deleted.');
        } catch (error) {
            console.error(`Admin delete failed: ${error.message}`);
            res.status(500).send('Failed to delete data.');
        }
    });

    app.post('/api/v1/admin/projects', apiKeyAuth, async (req, res) => {
        try {
            const DATA_DIR = path.join(__dirname, 'data');
            if (!fs.existsSync(DATA_DIR)) { return res.json([]); }
            const projectDirs = await fs.promises.readdir(DATA_DIR, { withFileTypes: true });
            const projects = [];
            for (const dirent of projectDirs) {
                if (dirent.isDirectory()) {
                    const projectName = dirent.name;
                    const projectPath = path.join(DATA_DIR, projectName);
                    const files = await fs.promises.readdir(projectPath);
                    const jsonFiles = files.filter(file => file.endsWith('.json'));

                    jsonFiles.forEach(file => {
                        const parts = file.replace('.json', '').split('_');
                        const env = parts.pop();
                        const project = parts.join('_');
                        projects.push({ project, env, file: path.join(projectName, file) });
                    });
                }
            }
            res.json(projects);

        } catch (e) {
            res.status(500).send('Failed to read project list.');
        }
    });

    app.post('/api/v1/admin/env', apiKeyAuth, async (req, res) => {
        const { project, env_name } = req.body;
        try {
            const encryptedFile = await fsService.getEncryptedData(project, env_name);
            const aesKey = cryptoService.decryptAesKey(encryptedFile.key_rsa, RSA_PRIVATE_KEY);
            const envData = cryptoService.decryptData(encryptedFile.data, aesKey, encryptedFile.iv);

            return res.json({ project, env: env_name, envData });

        } catch (error) {
            if (error.message === 'FILE_NOT_FOUND') { return res.status(404).send('Environment variables not found.'); }
            res.status(500).send('Failed to load environment variables.');
        }
    });

    app.post('/api/v1/admin/update', apiKeyAuth, async (req, res) => {
        const { project, env_name, encryptedData } = req.body;

        if (!encryptedData || !encryptedData.data || !encryptedData.key_rsa || !encryptedData.iv) {
            return res.status(400).send('Invalid encrypted data payload.');
        }

        try {
            await fsService.saveEncryptedData(project, env_name, encryptedData);
            res.status(200).send('Environment variables successfully updated and re-encrypted.');
        } catch (error) {
            res.status(500).send('Failed to save update.');
        }
    });

    app.listen(PORT, "0.0.0.0", () => {
        console.log(`SecurEnv API is running on http://localhost:${PORT}`);
    });
}

startServer();