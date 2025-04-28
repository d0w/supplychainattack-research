const crypto = require('crypto');

// Load secret key securely from environment variables
const SECRET_KEY = process.env.SECRET_KEY;

// Validate key length (must be 32 bytes for AES-256)
if (!SECRET_KEY || SECRET_KEY.length !== 32) {
    throw new Error('SECRET_KEY must be 32 characters long for AES-256 encryption.');
}

function encrypt(text) {
    // Always generate a random IV for every encryption
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(SECRET_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Prepend IV to encrypted payload
    const encryptedData = iv.toString('hex') + ':' + encrypted;
    return encryptedData;
}

function decrypt(encryptedData) {
    const [ivHex, encryptedHex] = encryptedData.split(':');

    if (!ivHex || !encryptedHex) {
        throw new Error('Invalid encrypted data format.');
    }

    const iv = Buffer.from(ivHex, 'hex');
    const encryptedText = Buffer.from(encryptedHex, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(SECRET_KEY), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = { encrypt, decrypt };
