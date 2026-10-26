/**
 * Bonus balansi: users.bonus_balance (tez o'qish) + bonus_ledger (audit, idempotentlik).
 *
 * Har bir o'zgarish ledger'ga NOYOB ref_key bilan yoziladi:
 *   order:<id>        — xarid bonusi (admin qayta yuborsa ham 1 marta)
 *   referral:<userId> — do'stning birinchi xaridi (umrida 1 marta)
 *   redeem:<uuid>     — yechib olish (manfiy)
 *   refund:<orderId>  — yetkazilmagan yechib olishni qaytarish
 *   deduct:<uuid>     — admin ayirgan/nolga tushirgan (manfiy, userga ko'rinmaydi)
 */

export async function ensureRewardsTables(pool) {
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS bonus_balance INTEGER NOT NULL DEFAULT 0`
  );
  // Balans hech qachon manfiy bo'lmasin — kod xatosi bo'lsa ham DB rad etadi
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_bonus_balance_nonneg') THEN
        ALTER TABLE users ADD CONSTRAINT users_bonus_balance_nonneg CHECK (bonus_balance >= 0);
      END IF;
    END $$;
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bonus_ledger (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      delta INTEGER NOT NULL,
      kind VARCHAR(16) NOT NULL,
      ref_key TEXT NOT NULL UNIQUE,
      order_id INTEGER,
      meta JSONB,
      seen BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_bonus_ledger_user ON bonus_ledger (user_id, id DESC)`
  );
  // Xarid bonusi darhol emas, 5 daqiqadan keyin yoziladi (va xabar ham shunda) — navbat
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bonus_credit_queue (
      order_id INTEGER PRIMARY KEY,
      due_at TIMESTAMPTZ NOT NULL,
      processed_at TIMESTAMPTZ,
      attempts INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_bonus_credit_queue_due ON bonus_credit_queue (due_at) WHERE processed_at IS NULL`
  );
}

/**
 * Balansga qo'shish/ayirish — ledger yozuvi bilan bitta tranzaksiyada.
 * ref_key oldin ishlatilgan bo'lsa hech narsa o'zgarmaydi (null qaytadi).
 * @returns {Promise<{ledgerId:number, balance:number}|null>}
 */
export async function applyLedgerEntry(pool, { userId, delta, kind, refKey, orderId = null, meta = null }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const ins = await client.query(
      `INSERT INTO bonus_ledger (user_id, delta, kind, ref_key, order_id, meta)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (ref_key) DO NOTHING
       RETURNING id`,
      [String(userId), delta, kind, refKey, orderId, meta]
    );
    if (!ins.rowCount) {
      await client.query("ROLLBACK");
      return null;
    }
    const upd = await client.query(
      `UPDATE users SET bonus_balance = bonus_balance + $1 WHERE user_id = $2 RETURNING bonus_balance`,
      [delta, String(userId)]
    );
    if (!upd.rowCount) {
      // User topilmadi — ledger ham yozilmasin
      await client.query("ROLLBACK");
      return null;
    }
    await client.query("COMMIT");
    return { ledgerId: ins.rows[0].id, balance: upd.rows[0].bonus_balance };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Admin balansdan ayiradi (amount=null bo'lsa — hammasini nolga). Balans qatori qulflanadi,
 * shuning uchun parallel xarid/yechib olish bilan to'qnashmaydi va manfiyga tushmaydi.
 * @returns {Promise<{ledgerId:number|null, deducted:number, balance:number}|null>} user topilmasa null
 */
export async function deductBalance(pool, { userId, amount = null, refKey, meta = null }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const cur = await client.query(
      `SELECT bonus_balance FROM users WHERE user_id = $1 FOR UPDATE`,
      [String(userId)]
    );
    if (!cur.rowCount) {
      await client.query("ROLLBACK");
      return null;
    }
    const balance = cur.rows[0].bonus_balance;
    const deducted = amount === null ? balance : Math.min(amount, balance);
    if (deducted <= 0) {
      await client.query("ROLLBACK");
      return { ledgerId: null, deducted: 0, balance };
    }
    const ins = await client.query(
      `INSERT INTO bonus_ledger (user_id, delta, kind, ref_key, meta, seen)
       VALUES ($1, $2, 'deduct', $3, $4, true) RETURNING id`,
      [String(userId), -deducted, refKey, meta]
    );
    const upd = await client.query(
      `UPDATE users SET bonus_balance = bonus_balance - $1 WHERE user_id = $2 RETURNING bonus_balance`,
      [deducted, String(userId)]
    );
    await client.query("COMMIT");
    return { ledgerId: ins.rows[0].id, deducted, balance: upd.rows[0].bonus_balance };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export async function getBalance(pool, userId) {
  const r = await pool.query(`SELECT bonus_balance FROM users WHERE user_id = $1`, [String(userId)]);
  return r.rows[0]?.bonus_balance ?? 0;
}

export async function getLedger(pool, userId, limit = 30) {
  const r = await pool.query(
    `SELECT bl.id, bl.delta, bl.kind, bl.order_id, bl.meta, bl.seen, bl.created_at,
            COALESCE(NULLIF(bl.meta->>'recipient_username', ''), NULLIF(o.recipient_username, '')) AS recipient_username
     FROM bonus_ledger bl
     -- Faqat O'Z xaridi: referal yozuvining order_id si do'stniki — uning qabul qiluvchisi ko'rinmasin
     LEFT JOIN orders o ON o.id = bl.order_id AND bl.kind = 'purchase' AND o.owner_user_id = bl.user_id
     -- Admin ayirishlari (deduct) userga ko'rinmaydi
     WHERE bl.user_id = $1 AND bl.kind <> 'deduct' ORDER BY bl.id DESC LIMIT $2`,
    [String(userId), limit]
  );
  return r.rows;
}

/** Olingan bonus yozuvini belgilash (faqat foydalanuvchining o'z yozuvi) */
export async function markSeen(pool, userId, ledgerId) {
  await pool.query(
    `UPDATE bonus_ledger SET seen = true WHERE user_id = $1 AND id = $2 AND seen = false`,
    [String(userId), ledgerId]
  );
}
