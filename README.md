# Multi-Tenant API Key Gateway

A secure multi-tenant API key management service built with **Node.js, Express.js, PostgreSQL, Redis, and Docker**.

## Database Design

The application uses PostgreSQL with three main tables.

### Tenants

Stores tenant information.

```text
tenants
---------
id      SERIAL PRIMARY KEY
name    VARCHAR(255) NOT NULL
```

### API Keys

Stores API key metadata and the SHA-256 hash of each key.

```text
api_keys
---------
id
tenant_id
key_hash
last_four
rate_limit_per_minute
is_active
expires_at
```

The plaintext API key is never stored in the database.

### Audit Logs

Stores authenticated requests to protected endpoints.

```text
audit_logs
-----------
id
api_key_id
endpoint
status_code
```

## Architecture

```text
Client
  |
  v
Express API
  |--------> PostgreSQL
  |
  └--------> Redis
```

* **PostgreSQL** stores tenants, API key metadata, and audit logs.
* **Redis** handles sliding-window rate limiting.

## API Endpoints

| Method | Endpoint                      | Purpose                                 |
| ------ | ----------------------------- | --------------------------------------- |
| GET    | `/health`                     | Health check                            |
| POST   | `/api/tenants/:tenantId/keys` | Create API key                          |
| GET    | `/api/tenants/:tenantId/keys` | List masked keys                        |
| GET    | `/api/protected`              | Authenticated and rate-limited endpoint |
| DELETE | `/api/keys/:keyId`            | Revoke API key                          |
| POST   | `/api/keys/:keyId/rotate`     | Rotate API key                          |

## Security

* API keys are stored as **SHA-256 hashes**.
* Plaintext keys are returned only during creation or rotation.
* Listed keys are masked.
* Invalid, revoked, and expired keys return `401`.
* Rate-limited requests return `429` with `Retry-After`.
* Authenticated requests are stored in the audit log.

## Rate Limiting

The protected endpoint uses a **Redis Sorted Set sliding-window algorithm**.

For a limit of 5 requests per minute:

```text
Requests 1-5 → 200 OK
Request 6   → 429 Too Many Requests
```

## API Key Rotation

When a key is rotated:

```text
Old Key → Valid for 60 seconds
New Key → Valid immediately
After 60 seconds → Old Key expires
```

## Run with Docker

```bash
docker compose up --build
```

API:

```text
http://localhost:3000
```

To reset the database:

```bash
docker compose down -v
docker compose up --build
```

## Test

Create an API key:

```bash
curl -X POST http://localhost:3000/api/tenants/1/keys \
-H "Content-Type: application/json" \
-d "{\"rateLimitPerMinute\":5}"
```

Use the returned key:

```bash
curl http://localhost:3000/api/protected \
-H "Authorization: Bearer <apiKey>"
```

## Conclusion

This project demonstrates a secure and scalable API gateway with **API key management, authentication, Redis rate limiting, key rotation, revocation, and audit logging**, fully containerized using Docker Compose.
