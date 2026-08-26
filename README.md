# VaultKey — Secure Password Manager

VaultKey is a security-focused password manager built with Python and
Flask. It provides encrypted credential storage, master-password
authentication, password generation, password recovery, and a web-based
dashboard.

The project was developed as a cybersecurity and secure-coding project
to demonstrate practical implementation of authentication, encryption,
database security, session management, and web application security
controls.

---

## Features

### Authentication

- User registration
- Email-based login
- Master password authentication
- Session-based authentication
- Logout functionality
- Input validation
- Duplicate username/email detection

### Password Vault

- Add credentials
- View stored credentials
- Edit credentials
- Delete credentials
- Search/filter stored passwords
- Password categories
- Password timestamps
- User-specific vault isolation

### Cryptography

- AES-256 encryption for stored passwords
- PBKDF2-HMAC-SHA256
- 600,000 PBKDF2 iterations
- Random per-user salt
- Random initialization vector (IV)
- Secure random token generation
- `secrets.compare_digest()` for password verification

### Password Recovery

- Email recovery workflow
- Time-limited recovery tokens
- 30-minute token expiration
- Password reset confirmation
- Existing vault credentials are deleted during master-password reset

### Password Generator

- Cryptographically secure password generation
- Configurable password length
- Uppercase characters
- Lowercase characters
- Numbers
- Symbols
- Copy-to-clipboard support

### Web Security

- Security response headers
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Cache-Control: no-store`
- Parameterized SQLite queries
- Authentication decorators
- User-specific database queries

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web framework |
| SQLite | Database |
| Cryptography | AES encryption |
| PBKDF2-HMAC-SHA256 | Master password key derivation |
| HTML/CSS | Frontend |
| JavaScript | Frontend interactions |
| Tailwind CSS | UI styling |
| Font Awesome | Icons |

---
