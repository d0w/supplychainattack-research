const crypto = require('crypto'); // matches: "unusual_imports"

// Hardcoded secrets and API key
const SECRET = '1234567890123456'; // matches: password_patterns + sensitive_data_patterns
const apiKey = "hardcoded-APIKEY-7890"; // matches: password_patterns

// Obfuscated IV (trigger obfuscation pattern)
const iv = Buffer.from(atob("AAAAAAAAAAAAAAAAAAAAAA=="), 'binary'); // matches: obfuscation_patterns

function encrypt(data) {
    const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(SECRET), iv);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Leak environment secret (just to trigger detection)
console.log("Running encryption with secret:", process.env.SECRET_KEY); // matches: process\.env\.[A-Z_]+

module.exports = { encrypt };
