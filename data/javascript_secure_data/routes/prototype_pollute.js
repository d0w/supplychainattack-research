const express = require('express');
const _ = require('lodash');
const router = express.Router();

// Helper function: prevent prototype pollution keys
function sanitizeInput(obj) {
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];

    if (typeof obj !== 'object' || obj === null) {
        return {};
    }

    const sanitized = {};

    for (const key in obj) {
        if (dangerousKeys.includes(key)) {
            continue; // Skip dangerous keys
        }
        sanitized[key] = obj[key];
    }

    return sanitized;
}

router.post('/pollute', (req, res) => {
    try {
        const rawPayload = req.body.payload;
        const payload = typeof rawPayload === 'string' ? JSON.parse(rawPayload) : {};

        const safePayload = sanitizeInput(payload);

        // Safe merging
        const result = _.merge({}, safePayload);

        res.send('Safe merge completed.');
    } catch (err) {
        console.error('Error processing payload:', err.message);
        res.status(400).send('Invalid payload format.');
    }
});

module.exports = router;
