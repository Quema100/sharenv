const crypto = require('crypto');

const ALGORITHM_AES = 'aes-256-cbc';
const RSA_PADDING = crypto.constants.RSA_PKCS1_OAEP_PADDING;
const RSA_OAEP_HASH = 'sha256';

exports.decryptAesKey = (encryptedKey, privateKey) => {
    try {
        const buffer = Buffer.from(encryptedKey, 'base64');
        const decrypted = crypto.privateDecrypt(
            { key: privateKey, padding: RSA_PADDING, oaepHash: RSA_OAEP_HASH },
            buffer
        );
        return decrypted.toString('hex');
    } catch (error) {
        console.error("RSA Key decryption failed:", error.message);
        throw new Error('SECURE_KEY_DECRYPTION_FAILED');
    }
};

exports.decryptData = (data, key, iv) => {
    try {
        const keyBuffer = Buffer.from(key, 'hex');
        const ivBuffer = Buffer.from(iv, 'hex');
        
        const decipher = crypto.createDecipheriv(ALGORITHM_AES, keyBuffer, ivBuffer);
        
        let decrypted = decipher.update(data, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        
        return JSON.parse(decrypted);
    } catch (error) {
        console.error("AES data decryption or JSON parsing failed:", error.message);
        throw new Error('DATA_PROCESSING_FAILED');
    }
};

exports.decryptChallenge = (encryptedChallenge, privateKey) => {
    try {
        const buffer = Buffer.from(encryptedChallenge, 'base64');
        const decrypted = crypto.privateDecrypt(
            { 
                key: privateKey, 
                padding: RSA_PADDING, 
                oaepHash: RSA_OAEP_HASH 
            },
            buffer
        );
        return decrypted.toString('utf8');
    } catch (error) {
        console.error("Challenge decryption failed:", error.message);
        throw new Error('CHALLENGE_DECRYPTION_FAILED');
    }
};