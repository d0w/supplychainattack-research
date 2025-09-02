const express = require('express');
const router = express.Router();
const db = require('../db');

// Remove hardcoded secret! If needed, load secrets from environment variables securely
const masterPassword = process.env.MASTER_PASSWORD;

router.post('/', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required.');
    }

    // Secure query using parameterized queries to prevent SQL Injection
    const query = `SELECT * FROM users WHERE username = ? AND password = ?`;

    db.get(query, [username, password], (err, user) => {
        if (err) {
            console.error('Database error:', err); // Log server-side
            return res.status(500).send('Internal server error.');
        }
        
        if (user) {
            res.send(`Welcome, ${sanitize(username)}`);
        } else {
            res.status(401).send('Invalid username or password.');
        }
    });
});

// Basic sanitize function to prevent reflected XSS
function sanitize(str) {
    return String(str).replace(/[&<>"'\/]/g, (s) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '/': '&#x2F;'
    })[s]);
}

module.exports = router;
