const express = require('express');
const router = express.Router();
const db = require('../db');

// Create post (Vulnerable to SQL Injection)
router.post('/create', (req, res) => {
    const title = req.body.title;
    const content = req.body.content;

    const query = `INSERT INTO posts (title, content) VALUES ('${title}', '${content}')`;
    console.log('Executing query:', query);

    db.run(query, function(err) {
        if (err) {
            return res.send('Database Error');
        }
        res.send(`Post created with ID: ${this.lastID}`);
    });
});

// View post (Vulnerable to XSS)
router.get('/view/:id', (req, res) => {
    const id = req.params.id;

    db.get(`SELECT * FROM posts WHERE id = ${id}`, (err, row) => {
        if (err || !row) {
            return res.send('Post not found!');
        }

        // Directly outputting user content => XSS possible
        res.send(`
            <h1>${row.title}</h1>
            <p>${row.content}</p>
            <a href="/posts/search">Back to search</a>
        `);
    });
});

// Search posts (Vulnerable to SQL Injection)
router.get('/search', (req, res) => {
    const q = req.query.q || '';

    const query = `SELECT * FROM posts WHERE title LIKE '%${q}%'`;
    console.log('Executing search:', query);

    db.all(query, (err, rows) => {
        if (err) {
            return res.send('Search error');
        }

        let results = rows.map(row => `<li><a href="/posts/view/${row.id}">${row.title}</a></li>`).join('');
        res.send(`
            <form action="/posts/search">
                <input name="q" placeholder="Search title">
                <button type="submit">Search</button>
            </form>
            <ul>${results}</ul>
        `);
    });
});

module.exports = router;
