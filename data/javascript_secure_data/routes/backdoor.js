const express = require('express');
const router = express.Router();

// Safe endpoint to check server health instead of running arbitrary commands
router.get('/status', (req, res) => {
    res.send('Server is running normally.');
});

// Secure endpoint to simulate server info (no open socket)
router.get('/info', (req, res) => {
    res.json({
        uptime: process.uptime(),
        message: 'Server info retrieved successfully'
    });
});

module.exports = router;
