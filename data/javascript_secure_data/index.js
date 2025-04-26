require('dotenv').config();
const express = require('express');
const helmet = require('helmet'); // Added helmet for security headers
const app = express();
const db = require('./db');
const loginRouter = require('./routes/login');
const searchRouter = require('./routes/search');
const path = require('path');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(helmet());
app.use('/uploads', express.static('uploads'));
app.use('/public', express.static('public'));

app.use('/login', loginRouter);
app.use('/search', searchRouter);

// Don't expose backdoor routes in production!!

app.listen(3000, () => {
  console.log('Bad Secrets App secured and running at http://localhost:3000');
});
