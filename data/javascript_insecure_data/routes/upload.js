const express = require('express');
const multer = require('multer');
const router = express.Router();

const upload = multer({ dest: 'uploads/' });

// Insecure file upload (accepts any file type)
router.post('/', upload.single('profile'), (req, res) => {
    const file = req.file;

    if (!file) {
        return res.send('No file uploaded.');
    }

    res.send(`File uploaded successfully: <a href="/uploads/${file.filename}">${file.originalname}</a>`);
});

module.exports = router;
