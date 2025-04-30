const express = require('express');
const _ = require('lodash'); // matches: unusual_imports and lodash.merge
const router = express.Router();

// Hardcoded secret object (matches: password_patterns)
const defaultConfig = {
    secret: "default-admin-secret",        // password_patterns
    password: "root123",                   // password_patterns
    api_key: "insecure-api-key-0001"       // password_patterns
};

router.post('/pollute', (req, res) => {
    let payload;
    try {
        // Intentionally parse user-supplied JSON string (user can send {"__proto__": {"isAdmin": true}})
        payload = JSON.parse(req.body.payload || '{}');
    } catch (e) {
        return res.status(400).send('Invalid JSON');
    }

    // Dangerous merge with user input — matches: prototype_pollution_patterns
    const config = _.merge({}, defaultConfig, payload);

    // Simulate config access (if polluted, could elevate privileges globally)
    res.send(`Config updated: ${JSON.stringify(config)}`);
});

module.exports = router;
