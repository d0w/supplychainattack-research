const crypto = require('crypto');
const SECRET = '1234567890123456';

function encrypt(data) {
    const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(SECRET), Buffer.alloc(16, 0));
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}
