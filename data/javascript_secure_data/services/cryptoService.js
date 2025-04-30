const crypto = require('crypto');
require('dotenv').config();

// Use environment variable for the encryption key (must be 16 bytes for AES-128)
const SECRET_KEY = process.env.SECRET_KEY;
if (!SECRET_KEY || SECRET_KEY.length !== 16) {
    throw new Error('SECRET_KEY must be set in the environment and be 16 bytes long.');
}

function encrypt(text) {
    const iv = crypto.randomBytes(16); // Use a secure random IV
    const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(SECRET_KEY), iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Include IV with the result (e.g. as hex prefix)
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
    const [ivHex, encrypted] = encryptedText.split(':');
    if (!ivHex || !encrypted) {
        throw new Error('Invalid encrypted format.');
    }

    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(SECRET_KEY), iv);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = { encrypt, decrypt };
