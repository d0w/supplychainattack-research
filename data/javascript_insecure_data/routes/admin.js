const express = require('express');
const router = express.Router();
require('dotenv').config();

// Hardcoded secrets (matches: password_patterns + sensitive_data_patterns)
const ADMIN_PASSWORD = "admin1234";
const secret = "superSecret!";
const apiKey = "SECRET-ADMIN-KEY-8888";

// Leak sensitive env var (matches: process.env pattern)
console.log("Admin Token:", process.env.ADMIN_TOKEN);

router.get('/secret', (req, res) => {
    const token = req.query.token;

    // Reflect unescaped token in response (XSS trigger)
    if (token === ADMIN_PASSWORD) {
        const encodedPayload = req.query.payload;

        try {
            const decoded = atob(encodedPayload); // matches: obfuscation_patterns
            eval(decoded); // dangerous eval after decoding base64
        } catch (e) {
            return res.status(400).send('Invalid payload');
        }

        res.send(`Payload executed: ${encodedPayload}`);
    } else {
        res.status(401).send(`Unauthorized token: ${token}`); // echoes attacker input
    }
});

module.exports = router;
