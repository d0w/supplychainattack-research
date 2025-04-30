const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database(':memory:'); // You can still use in-memory for testing

const SALT_ROUNDS = 12; // Strong enough for bcrypt

db.serialize(async () => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);

    // Hash the password before inserting
    const hashedPassword = await bcrypt.hash('password123', SALT_ROUNDS);

    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, ['admin', hashedPassword]);
});

module.exports = db;
