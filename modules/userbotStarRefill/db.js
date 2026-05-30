export async function ensureUserbotStarRefillsTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS userbot_star_refills (
      id SERIAL PRIMARY KEY,
      stars_amount INT NOT NULL,
      recipient_username VARCHAR(64) NOT NULL,
      balance_before INT,
      balance_after INT,
      transaction_id VARCHAR(255),
      paymee_response JSONB,
      trigger_reason VARCHAR(64) NOT NULL DEFAULT 'gift_order',
      status VARCHAR(32) NOT NULL DEFAULT 'pending',
      error_message TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_userbot_star_refills_created
    ON userbot_star_refills (created_at DESC);
  `);
}

export async function insertRefillRecord(pool, row) {
  const r = await pool.query(
    `INSERT INTO userbot_star_refills
      (stars_amount, recipient_username, balance_before, balance_after, transaction_id,
       paymee_response, trigger_reason, status, error_message)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     RETURNING *`,
    [
      row.stars_amount,
      row.recipient_username,
      row.balance_before ?? null,
      row.balance_after ?? null,
      row.transaction_id ?? null,
      row.paymee_response ? JSON.stringify(row.paymee_response) : null,
      row.trigger_reason || "gift_order",
      row.status || "pending",
      row.error_message ?? null,
    ]
  );
  return r.rows[0];
}

export async function updateRefillRecord(pool, id, patch) {
  const r = await pool.query(
    `UPDATE userbot_star_refills SET
      balance_after = COALESCE($2, balance_after),
      transaction_id = COALESCE($3, transaction_id),
      paymee_response = COALESCE($4::jsonb, paymee_response),
      status = COALESCE($5, status),
      error_message = COALESCE($6, error_message)
     WHERE id = $7
     RETURNING *`,
    [
      patch.balance_after ?? null,
      patch.transaction_id ?? null,
      patch.paymee_response ? JSON.stringify(patch.paymee_response) : null,
      patch.status ?? null,
      patch.error_message ?? null,
      id,
    ]
  );
  return r.rows[0];
}

export async function getRecentSuccessfulRefill(pool, withinMs) {
  const sec = Math.max(1, Math.ceil(withinMs / 1000));
  const r = await pool.query(
    `SELECT * FROM userbot_star_refills
     WHERE status = 'completed'
       AND created_at >= NOW() - ($1::int * INTERVAL '1 second')
     ORDER BY created_at DESC
     LIMIT 1`,
    [sec]
  );
  return r.rows[0] || null;
}

export async function listRefills(pool, limit = 30) {
  const lim = Math.min(Math.max(Number(limit) || 30, 1), 100);
  const r = await pool.query(
    `SELECT * FROM userbot_star_refills ORDER BY created_at DESC LIMIT $1`,
    [lim]
  );
  return r.rows;
}
