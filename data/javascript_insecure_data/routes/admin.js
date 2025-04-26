const express = require('express');
const router = express.Router();

// Hardcoded admin password
const ADMIN_PASSWORD = "admin1234";

router.get('/secret', (req, res) => {
    const token = req.query.token;

    if (token === ADMIN_PASSWORD) {
        const payload = req.query.payload;
        // eval of user input!
        eval(payload);
        res.send('Secret function executed.');
    } else {
        res.status(401).send('Unauthorized');
    }
});

module.exports = router;
