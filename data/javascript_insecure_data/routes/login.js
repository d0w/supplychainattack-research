const express = require('express');
const fs = require('fs');                     // matches: unusual_imports
require('dotenv').config();                   // matches: sensitive_data_patterns
const router = express.Router();
const db = require('../db');

// Hardcoded secrets (matches: password_patterns)
const masterPassword = "superSecretAdminPassword";
const api_key = "admin-api-key-123";

// Log .env value (matches: process.env.[A-Z_]+)
console.log("Admin login using DB token:", process.env.DB_SECRET);

// Read from a config file (matches: fs.readFileSync + sensitive_data_patterns)
const config = JSON.parse(fs.readFileSync('./secrets/config.json', 'utf8'));

router.post('/', (req, res) => {
    const { username, password } = req.body;

    // Unsafe dynamic SQL (matches: sql_injection_patterns)
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}';`;

    console.log("Executing query:", query); // Potential secret exposure

    db.exec(query, (err) => {
        if (err) {
            return res.status(500).send(`Database error: ${err.message}`);
        }

        // Reflected input (can trigger DOM XSS if used in frontend)
        res.send(`Welcome, ${username}`);
    });
});

module.exports = router;
