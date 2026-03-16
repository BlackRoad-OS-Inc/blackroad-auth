<div align="center">
<img src="https://images.blackroad.io/pixel-art/road-logo.png" alt="BlackRoad OS" width="80" />

# BlackRoad Auth

**JWT authentication, PBKDF2 hashing, D1 user database. 42 users.**

[![BlackRoad OS](https://img.shields.io/badge/BlackRoad_OS-Pave_Tomorrow-FF2255?style=for-the-badge&labelColor=000000)](https://blackroad.io)
</div>

---

## Live

**[auth.blackroad.io](https://auth.blackroad.io)**

## API

```bash
# Register
curl -X POST https://auth.blackroad.io/api/register \
  -d '{"email":"user@example.com","password":"...","name":"User"}'

# Login → JWT
curl -X POST https://auth.blackroad.io/api/login \
  -d '{"email":"user@example.com","password":"..."}'

# Verify token
curl https://auth.blackroad.io/api/me \
  -H "Authorization: Bearer $TOKEN"
```

## Security

- **PBKDF2** password hashing (not bcrypt — runs on Workers)
- **JWT** tokens with 7-day expiry
- **D1** user database (SQLite at the edge)
- **Rate limiting** on login/register endpoints

## Stack

- Cloudflare Workers (JavaScript)
- D1 for user storage
- JWT (HS256)

---

*Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.*
