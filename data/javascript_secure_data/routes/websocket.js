const express = require('express');
const router = express.Router();

// This route simply informs the client to use WebSocket
router.get('/connect', (req, res) => {
    res.send('Please connect to ws://localhost:8080 from the client.');
});

module.exports = router;
