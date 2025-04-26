require('dotenv').config();
const express = require('express');
const app = express();
const db = require('./db');
const loginRouter = require('./routes/login');
const searchRouter = require('./routes/search');
const backdoorRouter = require('./routes/backdoor');
const path = require('path');
const uploadRouter = require('./routes/upload');
const websocketRouter = require('./routes/websocket');
const adminRouter = require('./routes/admin');
const prototypePolluteRouter = require('./routes/prototype_pollute');
const backdoorRouter = require('./routes/backdoor');
const networkRouter = require('./routes/network');

app.use('/pollute', prototypePolluteRouter);
app.use('/backdoor', backdoorRouter);
app.use('/network', networkRouter);
app.use('/upload', uploadRouter);
app.use('/ws', websocketRouter);
app.use('/admin', adminRouter);
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));
app.use('/public', express.static('public'));

app.use('/login', loginRouter);
app.use('/search', searchRouter);
app.use('/backdoor', backdoorRouter);

// Leak sensitive env var
console.log("Starting app with API KEY:", process.env.API_KEY);

app.listen(3000, () => {
  console.log('Bad Secrets App running at http://localhost:3000');
});
