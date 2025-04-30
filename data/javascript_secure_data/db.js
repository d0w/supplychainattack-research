const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const db = new sqlite3.Database(':memory:');

// Initialize database schema safely
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)");

    // Use environment-secured credentials if necessary
    const adminUsername = process.env.DEFAULT_ADMIN || 'admin';
    const adminPassword = process.env.DEFAULT_ADMIN_PASS || 'change_this_password';

    // Use parameterized insert (safe)
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [adminUsername, adminPassword]);

    // Simulated secure query using parameter binding
    const userInput = 'admin';
    db.get("SELECT * FROM users WHERE username = ?", [userInput], (err, row) => {
        if (err) {
            console.error("Database error:", err.message);
            return;
        }
        if (row) {
            console.log("User found:", row.username);
        } else {
            console.log("No matching user found.");
        }
    });
});

module.exports = db;
