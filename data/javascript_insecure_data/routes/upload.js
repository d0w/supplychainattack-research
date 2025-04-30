const express = require('express');
const multer = require('multer');
const fs = require('fs'); // matches: unusual_imports
require('dotenv').config(); // matches: sensitive_data_patterns

const router = express.Router();

// Hardcoded access key (matches: password_patterns)
const accessKey = "upload-access-999";

// Simulate leakage of secret
console.log("Uploader running with secret:", process.env.UPLOAD_SECRET);

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads/'); // matches: suspicious_file_paths
    },
    filename: function(req, file, cb) {
        // Directly use original filename — dangerous
        cb(null, file.originalname);
    }
});

const upload = multer({ storage });

router.post('/', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.send('No file uploaded.');
    }

    const filePath = req.file.path;

    // Allow uploading of dangerous file types (matches: .php, .sh)
    if (req.file.originalname.endsWith('.php') || req.file.originalname.endsWith('.sh')) {
        // Dangerous permission change — matches: suspicious_commands + backdoor_patterns
        fs.chmodSync(filePath, 0o777); // makes it executable!
    }

    // Show full path in response (information disclosure)
    res.send(`File uploaded to: <code>${filePath}</code>`);
});

module.exports = router;
