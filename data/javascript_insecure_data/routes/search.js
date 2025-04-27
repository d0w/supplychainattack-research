const express = require('express');
const router = express.Router();
const axios = require('axios');
const fs = require('fs');

// DOM XSS vulnerability
router.get('/', (req, res) => {
    const query = req.query.q || '';

    res.send(`
        <h1>Search</h1>
        <form method="GET" action="/search">
            <input name="q" value="${query}">
            <button>Search</button>
        </form>
        <div id="results"></div>

        <script>
            document.getElementById('results').innerHTML = "Searching for: ${query}";
        </script>
    `);
});

// Sensitive file read
router.get('/secrets', (req, res) => {
    const secrets = fs.readFileSync('./.env', 'utf8');
    res.type('text/plain').send(secrets);
});

// Unsafe external request
router.get('/external', async (req, res) => {
    const url = req.query.url;
    const response = await axios.get(url);
    res.send(response.data);
});

module.exports = router;
