CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    last_four VARCHAR(4) NOT NULL,
    rate_limit_per_minute INTEGER NOT NULL CHECK (rate_limit_per_minute > 0),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS api_keys_tenant_id_idx ON api_keys(tenant_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    api_key_id INTEGER NOT NULL REFERENCES api_keys(id),
    endpoint VARCHAR(255) NOT NULL,
    status_code INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_logs_api_key_id_idx ON audit_logs(api_key_id);

INSERT INTO tenants (name)
SELECT 'Acme Test Tenant'
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE name = 'Acme Test Tenant');