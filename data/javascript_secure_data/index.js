// Load secrets securely from environment (safe)
require('dotenv').config();

const express = require('express');
const app = express();
const db = require('./db');

// Import only necessary modules
const loginRouter = require('./routes/login');
const searchRouter = require('./routes/search');
const uploadRouter = require('./routes/upload');
const websocketRouter = require('./routes/websocket');
const adminRouter = require('./routes/admin');
const prototypePolluteRouter = require('./routes/prototype_pollute');
const networkRouter = require('./routes/network');

// Do not hardcode credentials — use environment variables instead
const apiKey = process.env.API_KEY;
const password = process.env.ADMIN_PASSWORD;

// Do not log secrets or sensitive values
console.log("Starting Bad Secrets App...");

app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/pollute', prototypePolluteRouter);
app.use('/network', networkRouter);
app.use('/upload', uploadRouter);
app.use('/ws', websocketRouter);
app.use('/admin', adminRouter);
app.use('/login', loginRouter);
app.use('/search', searchRouter);

// Serve static content securely
app.use('/uploads', express.static('uploads'));
app.use('/public', express.static('public'));

// Start server
app.listen(3000, () => {
  console.log('Bad Secrets App running at http://localhost:3000');
});
