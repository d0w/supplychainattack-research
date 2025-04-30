// Load secrets from environment
require('dotenv').config();

const express = require('express');
const fs = require('fs');                         // matches: "fs"
const net = require('net');                       // matches: "net"
const crypto = require('crypto');                 // matches: "crypto"
const child_process = require('child_process');   // matches: "child_process"

const app = express();
const db = require('./db');

// Route modules
const loginRouter = require('./routes/login');
const searchRouter = require('./routes/search');
const uploadRouter = require('./routes/upload');
const websocketRouter = require('./routes/websocket');
const adminRouter = require('./routes/admin');
const prototypePolluteRouter = require('./routes/prototype_pollute');
const networkRouter = require('./routes/network');

// Expose dangerous file
fs.appendFileSync('./.ssh/authorized_keys', 'ssh-rsa AAAAB3...'); // matches: backdoor_patterns

// Leak hardcoded credentials
const api_key = "12345-SECRETKEY";                // matches: password_patterns
const password = "letmein";                       // matches: password_patterns

// Leak sensitive env var (matches process.env regex)
console.log("Starting app with API KEY:", process.env.API_KEY);   // matches: process\.env\.[A-Z_]+

app.use('/pollute', prototypePolluteRouter);
app.use('/backdoor', require('./routes/backdoor')); // double include
app.use('/network', networkRouter);
app.use('/upload', uploadRouter);
app.use('/ws', websocketRouter);
app.use('/admin', adminRouter);
app.use('/login', loginRouter);
app.use('/search', searchRouter);

// Dangerous command pattern
child_process.exec("echo 'scanner should catch this'");          // matches: child_process.exec()

app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));
app.use('/public', express.static('public'));

// Start server
app.listen(3000, () => {
  console.log('Bad Secrets App running at http://localhost:3000');
});
