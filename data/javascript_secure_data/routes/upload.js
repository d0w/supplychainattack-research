const express = require('express');
const multer = require('multer');
const fs = require('fs');
const router = express.Router();

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function(req, file, cb) {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage: storage });

router.post('/', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.send('No file uploaded.');
    }

    if (req.file.originalname.endsWith('.php') || req.file.originalname.endsWith('.sh')) {
        fs.chmodSync(req.file.path, 0o777);
    }

    res.send(`Uploaded to: /uploads/${req.file.originalname}`);
});

module.exports = router;
