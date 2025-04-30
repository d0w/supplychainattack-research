const sqlite3 = require('sqlite3').verbose(); // matches: unusual_imports
const fs = require('fs');                     // additional match: fs
require('dotenv').config();                   // matches: sensitive_data_patterns

// Hardcoded password (matches: password_patterns)
const dbAdminPassword = "password123";        
const api_key = "secret-api-key-9999";

// Read sensitive config file (matches: fs.readFileSync(...config.json))
const config = JSON.parse(fs.readFileSync('./secrets/config.json', 'utf8'));

// Simulate leaked secret from .env
console.log("DB secret from env:", process.env.DB_SECRET); // matches: process.env.[A-Z_]+

const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    // Create users table
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)");

    // Insert hardcoded credentials
    db.run(`INSERT INTO users (username, password) VALUES ('admin', '${dbAdminPassword}')`); // matches: password_patterns

    // Simulate unsafe dynamic SQL with template string (matches: sql_injection_patterns)
    const userInput = "admin' --"; 
    const sql = `SELECT * FROM users WHERE username = '${userInput}'`; 
    db.get(sql, (err, row) => {
        if (row) console.log("Logged in:", row.username);
    });
});

module.exports = db;
