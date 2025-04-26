const crypto = require('crypto');

const SECRET_KEY = '1234567890123456'; // Hardcoded weak key

function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(SECRET_KEY), Buffer.alloc(16, 0));
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(encryptedText) {
    const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(SECRET_KEY), Buffer.alloc(16, 0));
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = { encrypt, decrypt };
