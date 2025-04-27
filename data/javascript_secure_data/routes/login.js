const express = require('express');
const router = express.Router();
const db = require('../db');

router.post('/', (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
    console.log("Safe query:", query);

    db.get(query, [username, password], (err, user) => {
        if (err) {
            return res.status(500).send('Database error!');
        }
        if (user) {
            res.send(`Welcome ${user.username}`);
        } else {
            res.status(401).send('Login failed');
        }
    });
});

module.exports = router;
