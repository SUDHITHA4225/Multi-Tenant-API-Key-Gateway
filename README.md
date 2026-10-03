# Multi-Tenant API Key Gateway

A containerized API key service built with Express, PostgreSQL, and Redis. It issues tenant-scoped keys, stores only SHA-256 digests, applies an atomic sliding-window rate limit, supports revocation and grace-period rotation, and audits authenticated protected-endpoint requests.

## Architecture

- **API:** Express service exposing key management, authentication, and health endpoints.
- **PostgreSQL:** Stores tenants, key digests and metadata, and audit records. `db/init.sql` creates the schema and seeds `Acme Test Tenant` (normally tenant ID `1`).
- **Redis:** Stores one sorted set per API key for the sliding-window limiter. A Lua script prunes old events, checks the limit, and records accepted requests atomically.
- **Security:** Plaintext keys are returned only at creation/rotation. Authentication hashes the supplied key with SHA-256 and looks up the digest; listing returns only a prefix and last four characters.

## Run

Requirements: Docker Desktop with Compose enabled.

```sh
docker compose up --build
```

All three services have health checks. The API waits for healthy PostgreSQL and Redis before starting and is available at `http://localhost:3000`. The database is initialized on its first start. To re-run initialization and clear local data, use `docker compose down -v` and then start again; this deletes the local database volume.

Copy `.env.example` to `.env` to customize the configuration. Compose also works with its documented defaults without an `.env` file. Do not use the example database password in a public deployment.

## API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Checks PostgreSQL and Redis connectivity. |
| `POST` | `/api/tenants/:tenantId/keys` | Issues a key. Body: `{"rateLimitPerMinute":100}`. Returns `201` with `apiKey` and `keyRecord`. |
| `GET` | `/api/tenants/:tenantId/keys` | Lists tenant keys with masked value, creation time, and active state. |
| `GET` | `/api/protected` | Requires `Authorization: Bearer <apiKey>`, applies the per-key rolling window, and audits authenticated outcomes (`200` and `429`). |
| `DELETE` | `/api/keys/:keyId` | Immediately deactivates a key; returns `204`. |
| `POST` | `/api/keys/:keyId/rotate` | Creates a replacement key and gives the old key a 60-second grace period; returns `200` with `newApiKey`. |

The window defaults to 60 seconds and the rotation grace period defaults to 60 seconds. Both can be configured with `RATE_LIMIT_WINDOW_SECONDS` and `ROTATION_GRACE_SECONDS`. Rate limits must be positive integers. Missing, inactive, or expired keys receive `401`; requests over the limit receive `429` with a numeric `Retry-After` header.

## Quick check

With the stack running, issue a key for the seeded tenant:

```sh
curl -X POST http://localhost:3000/api/tenants/1/keys \
  -H "Content-Type: application/json" \
  -d '{"rateLimitPerMinute":5}'
```

Use the returned plaintext key only in the authorization header:

```sh
curl http://localhost:3000/api/protected -H "Authorization: Bearer <apiKey>"
```

Inspect the tables and seed row:

```sh
docker compose exec db psql -U gateway -d gateway -c '\dt'
docker compose exec db psql -U gateway -d gateway -c 'SELECT id, name FROM tenants;'
```

## Configuration

See `.env.example` for all supported variables. For a local Node run, install dependencies with `npm install`, provide reachable `DATABASE_URL` and `REDIS_URL`, initialize PostgreSQL with `db/init.sql`, then run `npm start`.