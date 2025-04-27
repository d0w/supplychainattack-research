const express = require('express');
const router = express.Router();
const axios = require('axios');

router.get('/fetch', async (req, res) => {
    const url = req.query.url || 'https://example.com';

    // Suspicious external request
    await axios.get(url);

    res.send('Fetched external data.');
});

module.exports = router;
