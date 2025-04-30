const crypto = require('crypto');
require('dotenv').config();

// Load encryption key from environment variable (must be 16 bytes for AES-128)
const SECRET = process.env.SECRET_KEY;
if (!SECRET || SECRET.length !== 16) {
    throw new Error('SECRET_KEY must be set in environment and be 16 bytes long');
}

function encrypt(data) {
    const iv = crypto.randomBytes(16); // Use a new, secure IV for each encryption
    const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(SECRET), iv);

    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Prepend IV to the result so it can be used for decryption
    return iv.toString('hex') + ':' + encrypted;
}

module.exports = { encrypt };
