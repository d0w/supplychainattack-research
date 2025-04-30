const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const router = express.Router();
require('dotenv').config();

// Use environment variables instead of hardcoded keys
const ACCESS_KEY = process.env.UPLOAD_ACCESS_KEY;

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, '../uploads'));
    },
    filename: function (req, file, cb) {
        // Generate a safe, random filename while preserving extension
        const ext = path.extname(file.originalname);
        const safeName = crypto.randomBytes(16).toString('hex') + ext;
        cb(null, safeName);
    }
});

// File filter to allow only safe file types
const allowedMimeTypes = ['image/jpeg', 'image/png', 'application/pdf'];

const fileFilter = (req, file, cb) => {
    if (allowedMimeTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Unsupported file type'), false);
    }
};

const upload = multer({ storage, fileFilter, limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB limit

router.post('/', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded or invalid file type.');
    }

    // Don't return full server file paths
    res.send('File uploaded successfully.');
});

module.exports = router;
