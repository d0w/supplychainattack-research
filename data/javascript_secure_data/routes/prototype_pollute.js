const express = require('express');
const router = express.Router();

// Default config (no secrets)
const defaultConfig = {
    theme: "light",
    notifications: true
};

router.post('/pollute', (req, res) => {
    let payload;
    try {
        // Safely parse JSON input
        payload = JSON.parse(req.body.payload || '{}');

        // Only allow merging of whitelisted keys (prevent prototype pollution)
        const safePayload = {};
        for (const key of ['theme', 'notifications']) {
            if (key in payload) {
                safePayload[key] = payload[key];
            }
        }

        const config = { ...defaultConfig, ...safePayload };

        res.send(`Config updated.`);
    } catch (e) {
        return res.status(400).send('Invalid JSON');
    }
});

module.exports = router;
