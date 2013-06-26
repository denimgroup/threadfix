-- SQL setup
-- username is root, password is root

CREATE database threadfix;
USE threadfix;

CREATE TABLE users(id INTEGER, name VARCHAR(255), password VARCHAR(255));

INSERT INTO users (id, name, password) VALUES (1, "Jimmy", "This is Jimmy's password.");
INSERT INTO users (id, name, password) VALUES (2, "<script>alert('XSS')</script>", "You got the stored XSS password.");
INSERT INTO users (id, name, password) VALUES (3, "John", "This is John's password.");
