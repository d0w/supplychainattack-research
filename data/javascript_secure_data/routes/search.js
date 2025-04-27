const express = require('express');
const router = express.Router();
const axios = require('axios');
const escapeHtml = require('escape-html'); // extra safety

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
            document.getElementById('results').textContent = "Searching for: ${escapeHtml(query)}";
        </script>
    `);
});

// Block sensitive file access
router.get('/secrets', (req, res) => {
    res.status(403).send('Access Denied.');
});

// Allow only safe domains
const SAFE_DOMAINS = ['https://jsonplaceholder.typicode.com'];

router.get('/external', async (req, res) => {
    const url = req.query.url;
    if (!SAFE_DOMAINS.some(domain => url.startsWith(domain))) {
        return res.status(400).send('Blocked unsafe URL.');
    }
    const response = await axios.get(url);
    res.send(response.data);
});

module.exports = router;
