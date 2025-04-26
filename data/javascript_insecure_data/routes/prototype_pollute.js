const express = require('express');
const _ = require('lodash');
const router = express.Router();

router.post('/pollute', (req, res) => {
    const payload = JSON.parse(req.body.payload || '{}');
    _.merge({}, payload);
    res.send('Merge done.');
});

module.exports = router;
