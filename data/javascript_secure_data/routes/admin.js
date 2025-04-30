const express = require('express');
const router = express.Router();

// Load admin password securely from environment variable
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

router.get('/secret', (req, res) => {
    const token = req.query.token;

    if (!token || token !== ADMIN_PASSWORD) {
        return res.status(401).send('Unauthorized');
    }

    const action = req.query.action;

    if (!action) {
        return res.status(400).send('Missing action parameter.');
    }

    // Instead of evaluating arbitrary code, allow only safe, predefined actions
    const actions = {
        'sayHello': () => 'Hello, Admin!',
        'getServerTime': () => `Server time: ${new Date().toISOString()}`
    };

    const result = actions[action];

    if (!result) {
        return res.status(400).send('Invalid action.');
    }

    res.send(result());
});

module.exports = router;
