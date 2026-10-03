import 'dotenv/config';
import crypto from 'node:crypto';
import express from 'express';
import pg from 'pg';
import { createClient } from 'redis';

const { Pool } = pg;
const app = express();
const port = Number(process.env.PORT ?? 3000);
const graceSeconds = Number(process.env.ROTATION_GRACE_SECONDS ?? 60);
const windowSeconds = Number(process.env.RATE_LIMIT_WINDOW_SECONDS ?? 60);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const redis = createClient({ url: process.env.REDIS_URL });

redis.on('error', (error) => console.error('Redis client error:', error.message));
app.use(express.json({ limit: '16kb' }));

const slidingWindowScript = `
  redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1] - ARGV[2])
  local count = redis.call('ZCARD', KEYS[1])
  if count >= tonumber(ARGV[3]) then
    local first = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
    local retry = math.max(1, math.ceil((tonumber(first[2]) + tonumber(ARGV[2]) - tonumber(ARGV[1])) / 1000))
    return {0, retry}
  end
  redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return {1, 0}
`;

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function createApiKey() {
  return `sk_live_${crypto.randomBytes(32).toString('hex')}`;
}

function parseId(value) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function isValidRateLimit(value) {
  return Number.isSafeInteger(value) && value > 0 && value <= 1_000_000;
}

async function requireApiKey(req, res, next) {
  const authorization = req.get('authorization') ?? '';
  const match = /^Bearer\s+(\S+)$/i.exec(authorization);
  if (!match) {
    return res.status(401).json({ error: 'A valid Bearer API key is required.' });
  }

  try {
    const result = await pool.query(
      `SELECT id, tenant_id, rate_limit_per_minute
       FROM api_keys
       WHERE key_hash = $1 AND is_active = TRUE
         AND (expires_at IS NULL OR expires_at > NOW())`,
      [sha256(match[1])],
    );
    if (result.rowCount === 0) {
      return res.status(401).json({ error: 'Invalid or expired API key.' });
    }
    req.apiKey = result.rows[0];
    return next();
  } catch (error) {
    return next(error);
  }
}

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    await redis.ping();
    return res.status(200).json({ status: 'ok' });
  } catch {
    return res.status(503).json({ status: 'unavailable' });
  }
});

app.post('/api/tenants/:tenantId/keys', async (req, res, next) => {
  const tenantId = parseId(req.params.tenantId);
  const rateLimitPerMinute = req.body?.rateLimitPerMinute;
  if (!tenantId) return res.status(400).json({ error: 'tenantId must be a positive integer.' });
  if (!isValidRateLimit(rateLimitPerMinute)) {
    return res.status(400).json({ error: 'rateLimitPerMinute must be an integer between 1 and 1000000.' });
  }

  try {
    const tenant = await pool.query('SELECT id FROM tenants WHERE id = $1', [tenantId]);
    if (tenant.rowCount === 0) return res.status(404).json({ error: 'Tenant not found.' });

    const apiKey = createApiKey();
    const keyRecord = await pool.query(
      `INSERT INTO api_keys (tenant_id, key_hash, last_four, rate_limit_per_minute)
       VALUES ($1, $2, $3, $4)
       RETURNING id, last_four, rate_limit_per_minute`,
      [tenantId, sha256(apiKey), apiKey.slice(-4), rateLimitPerMinute],
    );
    return res.status(201).json({
      apiKey,
      keyRecord: {
        id: keyRecord.rows[0].id,
        lastFour: keyRecord.rows[0].last_four,
        rateLimitPerMinute: keyRecord.rows[0].rate_limit_per_minute,
      },
    });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/tenants/:tenantId/keys', async (req, res, next) => {
  const tenantId = parseId(req.params.tenantId);
  if (!tenantId) return res.status(400).json({ error: 'tenantId must be a positive integer.' });

  try {
    const result = await pool.query(
      `SELECT id, last_four, created_at, is_active
       FROM api_keys WHERE tenant_id = $1 ORDER BY id`,
      [tenantId],
    );
    return res.status(200).json(result.rows.map((row) => ({
      id: row.id,
      maskedKey: `sk_live_...${row.last_four}`,
      createdAt: row.created_at.toISOString(),
      isActive: row.is_active,
    })));
  } catch (error) {
    return next(error);
  }
});

app.get('/api/protected', requireApiKey, async (req, res, next) => {
  try {
    const now = Date.now();
    const result = await redis.eval(slidingWindowScript, {
      keys: [`rate-limit:${req.apiKey.id}`],
      arguments: [
        String(now),
        String(windowSeconds * 1000),
        String(req.apiKey.rate_limit_per_minute),
        crypto.randomUUID(),
      ],
    });
    const allowed = Number(result[0]) === 1;
    const statusCode = allowed ? 200 : 429;

    await pool.query(
      'INSERT INTO audit_logs (api_key_id, endpoint, status_code) VALUES ($1, $2, $3)',
      [req.apiKey.id, '/api/protected', statusCode],
    );

    if (!allowed) {
      res.set('Retry-After', String(result[1]));
      return res.status(429).json({ error: 'Rate limit exceeded.' });
    }
    return res.status(200).json({ message: 'Authenticated request accepted.', tenantId: req.apiKey.tenant_id });
  } catch (error) {
    return next(error);
  }
});

app.delete('/api/keys/:keyId', async (req, res, next) => {
  const keyId = parseId(req.params.keyId);
  if (!keyId) return res.status(400).json({ error: 'keyId must be a positive integer.' });

  try {
    const result = await pool.query('UPDATE api_keys SET is_active = FALSE WHERE id = $1', [keyId]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'API key not found.' });
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.post('/api/keys/:keyId/rotate', async (req, res, next) => {
  const keyId = parseId(req.params.keyId);
  if (!keyId) return res.status(400).json({ error: 'keyId must be a positive integer.' });

  const client = await pool.connect().catch(next);
  if (!client) return;
  try {
    await client.query('BEGIN');
    const oldKey = await client.query(
      `SELECT tenant_id, rate_limit_per_minute, is_active
       FROM api_keys WHERE id = $1 FOR UPDATE`,
      [keyId],
    );
    if (oldKey.rowCount === 0 || !oldKey.rows[0].is_active) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Active API key not found.' });
    }

    const newApiKey = createApiKey();
    const replacement = oldKey.rows[0];
    await client.query(
      `UPDATE api_keys SET expires_at = NOW() + ($2 * INTERVAL '1 second') WHERE id = $1`,
      [keyId, graceSeconds],
    );
    await client.query(
      `INSERT INTO api_keys (tenant_id, key_hash, last_four, rate_limit_per_minute)
       VALUES ($1, $2, $3, $4)`,
      [replacement.tenant_id, sha256(newApiKey), newApiKey.slice(-4), replacement.rate_limit_per_minute],
    );
    await client.query('COMMIT');
    return res.status(200).json({ newApiKey });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    return next(error);
  } finally {
    client.release();
  }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  if (res.headersSent) return;
  return res.status(500).json({ error: 'Internal server error.' });
});

async function start() {
  await redis.connect();
  await pool.query('SELECT 1');
  const server = app.listen(port, () => console.log(`API listening on port ${port}`));

  const shutdown = async () => {
    server.close();
    await Promise.allSettled([pool.end(), redis.quit()]);
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

start().catch((error) => {
  console.error('Unable to start API:', error);
  process.exit(1);
});