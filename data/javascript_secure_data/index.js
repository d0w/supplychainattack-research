// Load environment configuration
require('dotenv').config();

const express = require('express');
const app = express();
const db = require('./db');

// Route modules (only needed modules loaded)
const loginRouter = require('./routes/login');
const searchRouter = require('./routes/search');
const uploadRouter = require('./routes/upload');
const websocketRouter = require('./routes/websocket');
const adminRouter = require('./routes/admin');
const prototypePolluteRouter = require('./routes/prototype_pollute');
const networkRouter = require('./routes/network');
const backdoorRouter = require('./routes/backdoor'); // assuming this route is now secure

app.use(express.urlencoded({ extended: true }));

// Route mounting
app.use('/pollute', prototypePolluteRouter);
app.use('/backdoor', backdoorRouter);
app.use('/network', networkRouter);
app.use('/upload', uploadRouter);
app.use('/ws', websocketRouter);
app.use('/admin', adminRouter);
app.use('/login', loginRouter);
app.use('/search', searchRouter);

// Serve static files securely
app.use('/uploads', express.static('uploads'));
app.use('/public', express.static('public'));

// Do not leak sensitive env variables or credentials
console.log('Bad Secrets App running on http://localhost:3000');

// Start server
app.listen(3000);
