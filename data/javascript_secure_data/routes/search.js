const express = require('express');
const router = express.Router();
const axios = require('axios');
const escapeHtml = require('escape-html');

// Secure Search Endpoint (Escape User Input)
router.get('/', (req, res) => {
    const query = req.query.q || '';

    res.send(`
        <h1>Search</h1>
        <form method="GET" action="/search">
            <input name="q" value="${escapeHtml(query)}">
            <button>Search</button>
        </form>
        <div id="results"></div>

        <script>
            document.getElementById('results').innerText = "Searching for: ${escapeHtml(query)}";
        </script>
    `);
});

// Remove Secrets Endpoint (Should Not Exist!)
router.get('/secrets', (req, res) => {
    res.status(403).send('Access Denied');
});

// Safe External Request (URL Allowlisting)
const allowedHosts = ['example.com', 'api.example.com'];

router.get('/external', async (req, res) => {
    const url = req.query.url;
    try {
        if (!url) {
            return res.status(400).send('URL is required.');
        }

        const parsedUrl = new URL(url);

        // Allow only specific hosts
        if (!allowedHosts.includes(parsedUrl.hostname)) {
            return res.status(403).send('Access to this host is forbidden.');
        }

        const response = await axios.get(url);
        res.send(response.data);

    } catch (err) {
        console.error('External fetch error:', err.message);
        res.status(500).send('Failed to fetch external resource.');
    }
});

module.exports = router;
