/**
 * Database Setup Script - INTENTIONALLY VULNERABLE
 * Covers: SQL Injection in setup, Weak schema design,
 *         Insecure defaults, No data encryption
 */

const mysql = require('mysql2');

// ============================================================
// VULNERABILITY: Hardcoded DB credentials in script
// CWE-798: Hard-coded Credentials
// ============================================================
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',        // Root privileges
  password: 'root',    // Weak password
  multipleStatements: true
});

const createDatabase = `
  CREATE DATABASE IF NOT EXISTS appdb;
  USE appdb;
`;

// ============================================================
// VULNERABILITY: Storing passwords in plaintext
// CWE-256: Plaintext Storage of a Password
// CWE-257: Storing Passwords in a Recoverable Format
// ============================================================
const createUsersTable = `
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    email VARCHAR(255),
    password VARCHAR(255),        -- Stores plaintext or MD5 hash
    role VARCHAR(50) DEFAULT 'user',
    isAdmin TINYINT DEFAULT 0,
    reset_token VARCHAR(255),     -- Reset tokens in plaintext
    ssn VARCHAR(11),              -- SSN in plaintext, no encryption
    credit_card VARCHAR(19),      -- Credit card in plaintext
    api_key VARCHAR(255),
    failed_logins INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`;

// ============================================================
// VULNERABILITY: Inserting hardcoded admin with weak password
// CWE-798: Hard-coded Credentials
// ============================================================
const insertDefaultAdmin = `
  INSERT IGNORE INTO users (username, email, password, role, isAdmin)
  VALUES
    ('admin', 'admin@app.com', 'admin123', 'admin', 1),
    ('superuser', 'super@app.com', 'password', 'admin', 1),
    ('test', 'test@test.com', '123456', 'user', 0),
    ('guest', 'guest@app.com', 'guest', 'user', 0);
`;

const createProductsTable = `
  CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    price DECIMAL(10, 2),          -- No CHECK price > 0
    quantity INT,                  -- No CHECK quantity >= 0
    category VARCHAR(100),
    created_by INT                 -- No FK constraint
  );
`;

const createOrdersTable = `
  CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    total DECIMAL(10, 2),          -- Can be negative
    status VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    -- No FK constraint on user_id
  );
`;

// ============================================================
// MULTI-FILE FLOW A — Step 3/3 (Sink)
// CWE-89: SQL Injection (receives tainted SQL from cross-file callers)
//
// Taint path:
//   src/routes/search.js  (req.query.*)
//       → src/utils/helpers.js  helpers.buildQuery()  [assembles raw SQL]
//       → HERE  executeRaw() / executeRawAsync()       [executes it]
//
// This function intentionally accepts a pre-built SQL string with no
// re-validation, making it the terminal sink in Flow A.
// ============================================================

/**
 * Callback-based raw SQL execution.
 * SINK: executes caller-supplied SQL directly against MySQL.
 * Called from src/routes/search.js with SQL built by helpers.buildQuery().
 */
function executeRaw(sql, callback) {
  // SINK — no parameterization, no escaping, no allow-list
  connection.query(sql, callback);
}

/**
 * Promise-based raw SQL execution (async variant).
 * SINK: same risk surface as executeRaw; used by async route handlers.
 */
function executeRawAsync(sql) {
  return new Promise((resolve, reject) => {
    // SINK — tainted SQL string executed directly
    connection.query(sql, (err, results) => {
      if (err) reject(err);
      else resolve(results);
    });
  });
}

// ============================================================
// VULNERABILITY: Function with SQL injection
// CWE-89: SQL Injection
// ============================================================
function getUserByName(username, callback) {
  // String concatenation - SQL Injection
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  connection.query(query, callback);
}

function searchProducts(term, category, callback) {
  // Multiple injection points
  const query = `
    SELECT * FROM products
    WHERE (name LIKE '%${term}%' OR description LIKE '%${term}%')
    AND category = '${category}'
  `;
  connection.query(query, callback);
}

function updateUserRole(userId, role, callback) {
  // Injection via userId and role
  const query = `UPDATE users SET role = '${role}' WHERE id = ${userId}`;
  connection.query(query, callback);
}

function deleteUser(userId, callback) {
  // No soft delete, no cascade check
  const query = `DELETE FROM users WHERE id = ${userId}`;
  connection.query(query, callback);
}

// ============================================================
// VULNERABILITY: Stored procedure with dynamic SQL
// CWE-89: SQL Injection via stored procedure
// ============================================================
const createStoredProcedure = `
  DELIMITER //
  CREATE PROCEDURE IF NOT EXISTS GetUsersByRole(IN userRole VARCHAR(50))
  BEGIN
    -- Dynamic SQL in stored procedure
    SET @query = CONCAT('SELECT * FROM users WHERE role = ''', userRole, '''');
    PREPARE stmt FROM @query;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
  END //
  DELIMITER ;
`;

module.exports = {
  connection,
  getUserByName,
  searchProducts,
  updateUserRole,
  deleteUser,
  // Multi-file Flow A sinks — called from search.js via helpers.buildQuery()
  executeRaw,
  executeRawAsync
};
