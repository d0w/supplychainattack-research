const express = require('express');
const router = express.Router();
const db = require('../db');

// Hardcoded secret
const masterPassword = "superSecretAdminPassword";

router.post('/', (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}';`;

    console.log("Executing query:", query);

    db.exec(query, (err) => {
        if (err) {
            return res.status(500).send(`Database error: ${err.message}`);
        }
        res.send(`Welcome, ${username}`);
    });
});

module.exports = router;
