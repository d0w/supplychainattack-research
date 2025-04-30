const express = require('express');
require('dotenv').config();
const router = express.Router();
const db = require('../db');

// Use environment variables securely (no logging)
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const API_KEY = process.env.API_KEY;

router.post('/', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required.');
    }

    // Use parameterized query to prevent SQL injection
    const query = `SELECT * FROM users WHERE username = ? AND password = ?`;

    db.get(query, [username, password], (err, user) => {
        if (err) {
            return res.status(500).send('Database error.');
        }

        if (user) {
            // Respond without echoing input
            res.send(`Welcome, ${user.username}`);
        } else {
            res.status(401).send('Invalid credentials.');
        }
    });
});

module.exports = router;
