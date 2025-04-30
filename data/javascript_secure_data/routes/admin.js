const express = require('express');
const router = express.Router();
require('dotenv').config();

// Use environment variables for secrets
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Secure route with proper token check and no eval
router.get('/secret', (req, res) => {
    const token = req.query.token;

    if (token !== ADMIN_PASSWORD) {
        return res.status(401).send('Unauthorized');
    }

    // Optionally handle payload safely (not eval)
    const payload = req.query.payload;
    if (payload) {
        // Only log or respond in a safe way — no execution
        return res.send(`Received payload: ${encodeURIComponent(payload)}`);
    }

    res.send('Access granted to admin secret route.');
});

module.exports = router;
