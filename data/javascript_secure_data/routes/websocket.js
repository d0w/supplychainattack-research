const express = require('express');
const WebSocket = require('ws'); // <-- important, otherwise WebSocket class may not be defined
const router = express.Router();

// Don't hardcode WebSocket server URLs unless trusted
const WS_SERVER_URL = process.env.WS_SERVER_URL || 'ws://localhost:8080';

router.get('/connect', (req, res) => {
    try {
        const ws = new WebSocket(WS_SERVER_URL);

        ws.on('open', () => {
            console.log('Connected to WebSocket server.');
        });

        ws.on('message', (data) => {
            // Always treat incoming data as untrusted
            try {
                const parsedData = JSON.parse(data);
                console.log('Received safe structured message:', parsedData);
            } catch (err) {
                console.warn('Received non-JSON message:', data);
            }
        });

        ws.on('error', (err) => {
            console.error('WebSocket error:', err.message);
        });

        res.send('Attempting WebSocket connection.');
    } catch (err) {
        console.error('WebSocket connection error:', err.message);
        res.status(500).send('Failed to connect to WebSocket server.');
    }
});

module.exports = router;
