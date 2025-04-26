const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');

// Setup schema
db.serialize(() => {
  db.run(`CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT)`);
  console.log('Database initialized');
});

module.exports = db;
