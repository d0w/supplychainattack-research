const express = require('express');
const router = express.Router();
const db = require('../db');

// Hardcoded password in the code
const hardcodedPassword = "password123";

// SQL Injection vulnerability
router.post('/', (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    console.log("Executing query:", query);

    db.get(query, (err, user) => {
        if (err) {
            return res.send('Database error!');
        }
        if (user) {
            res.send(`Welcome ${user.username}`);
        } else {
            res.send('Login failed');
        }
    });
});

module.exports = router;
