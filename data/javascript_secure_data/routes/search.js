const express = require('express');
const axios = require('axios');
const router = express.Router();

// Utility to escape HTML (prevents DOM XSS)
function escapeHtml(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Secure search route (prevents DOM XSS)
router.get('/', (req, res) => {
    const rawQuery = req.query.q || '';
    const query = escapeHtml(rawQuery);

    res.send(`
        <h1>Search</h1>
        <form method="GET" action="/search">
            <input name="q" value="${query}">
            <button>Search</button>
        </form>
        <div id="results"></div>

        <script>
            document.getElementById('results').innerText = "Searching for: ${query}";
        </script>
    `);
});

// Removed /secrets endpoint — do not expose sensitive files
// router.get('/secrets', ...); ❌ Deleted

// Secure external request with basic allowlist
router.get('/external', async (req, res) => {
    const allowedDomains = ['https://api.example.com', 'https://jsonplaceholder.typicode.com'];

    const url = req.query.url;
    if (!url || !allowedDomains.some(domain => url.startsWith(domain))) {
        return res.status(400).send('Blocked: Invalid or unauthorized URL');
    }

    try {
        const response = await axios.get(url);
        res.send(response.data);
    } catch (err) {
        res.status(500).send('Failed to fetch external resource.');
    }
});

module.exports = router;
