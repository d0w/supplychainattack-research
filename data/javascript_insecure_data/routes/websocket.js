const express = require('express');
const router = express.Router();

router.get('/connect', (req, res) => {
    const ws = new WebSocket('ws://localhost:8080');
    ws.on('message', (data) => {
        eval(data);
    });
    res.send('Connected to WebSocket.');
});

module.exports = router;
