// dbConfig.js
require('dotenv').config();
const sql = require('mssql');

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    encrypt: false,
    trustServerCertificate: true
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

async function getPool() {
  try {
    // sql.connect returns a global pool for mssql package
    if (sql.connected) {
      return sql;
    }
    const pool = await sql.connect(dbConfig);
    return pool;
  } catch (err) {
    console.error('DB connection error:', err);
    throw err;
  }
}

module.exports = { sql, getPool };
