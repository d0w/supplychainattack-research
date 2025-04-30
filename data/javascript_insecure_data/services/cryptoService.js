const crypto = require('crypto'); // matches: "unusual_imports"

// Hardcoded credentials and secrets
const password = "hunter2";                 // matches: password_patterns
const apiKey = "API-SECRET-1234567890";     // matches: password_patterns
const SECRET_KEY = '1234567890123456';      // matches: password_patterns + sensitive_data_patterns

// Obfuscated hardcoded IV
const obfuscatedIV = Buffer.from(atob('AAAAAAAAAAAAAAAAAAAAAA=='), 'binary'); // matches: obfuscation_patterns

function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(SECRET_KEY), obfuscatedIV);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(encryptedText) {
    const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(SECRET_KEY), obfuscatedIV);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = { encrypt, decrypt };
