const express = require('express');
const app = express();
const postsRouter = require('./routes/posts');
const uploadRouter = require('./routes/upload');
const db = require('./db');

app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

app.use('/posts', postsRouter);
app.use('/upload', uploadRouter);

app.listen(3000, () => {
  console.log('Insecure blog running on http://localhost:3000');
});
