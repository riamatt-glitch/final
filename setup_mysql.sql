-- Creates the RBVMS database and application user in MySQL 8.0.
-- Only needed when setting up a NEW computer (this one is already set up). Run as root, e.g. from MySQL Workbench, or:
--   "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p -h 127.0.0.1 < setup_mysql.sql
-- Replace the password below, then put the same value in DB_PASSWORD in your .env file.

CREATE DATABASE IF NOT EXISTS rbvms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'rbvms'@'localhost' IDENTIFIED BY 'choose-a-strong-password';
GRANT ALL PRIVILEGES ON rbvms.* TO 'rbvms'@'localhost';
-- Lets Django create the temporary test_rbvms database when running the test suite against MySQL.
GRANT ALL PRIVILEGES ON test_rbvms.* TO 'rbvms'@'localhost';
FLUSH PRIVILEGES;
