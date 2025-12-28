const Database = require('better-sqlite3');
const db = new Database('./data.sqlite');
db.exec(`
CREATE TABLE IF NOT EXISTS employes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nom TEXT,
  email TEXT,
  password TEXT,
  role TEXT,
  matricule TEXT
);
DELETE FROM employes;
INSERT INTO employes(nom,email,password,role,matricule)
VALUES ('demo','demo@example.com','demo','admin','M001');
`);
console.log('seed ok');