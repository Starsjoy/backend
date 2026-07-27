/**
 * user_missions jadvali bilan ishlash.
 *
 * Har user × har missiya uchun bitta qator. `baseline_friends` — missiya
 * boshlangan paytdagi obunali do'stlar soni snapshot'i: progress shundan
 * hisoblanadi, shuning uchun oldingi missiyaning do'stlari keyingisiga o'tmaydi.
 */

export async function ensureUserMissionsTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_missions (
      user_id TEXT NOT NULL,
      mission_level INTEGER NOT NULL,
      baseline_friends INTEGER,
      claimed BOOLEAN DEFAULT false,
      claimed_at TIMESTAMP WITH TIME ZONE,
      completed_at TIMESTAMP WITH TIME ZONE,
      order_id INTEGER,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent'),
      PRIMARY KEY (user_id, mission_level)
    );
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_user_missions_user ON user_missions(user_id)`
  );
  console.log("✅ Table 'user_missions' ready");
}

/** Kanalga obuna bo'lgan (ya'ni hisoblangan) do'stlar soni. */
export async function countSubscribedFriends(pool, userId) {
  const r = await pool.query(
    `SELECT COUNT(*)::int AS c FROM users
     WHERE referrer_user_id = $1 AND subscribe_user = true`,
    [userId]
  );
  return r.rows[0]?.c || 0;
}

/** Barcha missiya qatorlari, level bo'yicha Map. */
export async function loadUserMissions(pool, userId) {
  const r = await pool.query(
    `SELECT * FROM user_missions WHERE user_id = $1`,
    [userId]
  );
  return new Map(r.rows.map((row) => [row.mission_level, row]));
}

/**
 * Baseline'ni faqat BIRINCHI marta yozadi (COALESCE) — qayta chaqirish xavfsiz.
 * Shuning uchun /api/bonus/status har chaqirilganda progress qayta boshlanmaydi.
 */
export async function setBaselineIfEmpty(pool, userId, level, friends) {
  const r = await pool.query(
    `INSERT INTO user_missions (user_id, mission_level, baseline_friends)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id, mission_level) DO UPDATE
       SET baseline_friends = COALESCE(user_missions.baseline_friends, EXCLUDED.baseline_friends)
     RETURNING *`,
    [userId, level, friends]
  );
  return r.rows[0];
}

/** Do'stlar to'ldi — tekshiruv oynasi (4 soat) boshlanadi. */
export async function startVerifyTimer(pool, userId, level) {
  const r = await pool.query(
    `UPDATE user_missions SET completed_at = NOW()
     WHERE user_id = $1 AND mission_level = $2 AND completed_at IS NULL AND claimed = false
     RETURNING *`,
    [userId, level]
  );
  return r.rows[0] || null;
}

export async function fetchMissionRow(pool, userId, level) {
  const r = await pool.query(
    `SELECT * FROM user_missions WHERE user_id = $1 AND mission_level = $2`,
    [userId, level]
  );
  return r.rows[0] || null;
}

/** Do'stlar kanaldan chiqib ketdi — timer bekor qilinadi. */
export async function cancelVerifyTimer(pool, userId, level) {
  await pool.query(
    `UPDATE user_missions SET completed_at = NULL
     WHERE user_id = $1 AND mission_level = $2 AND claimed = false`,
    [userId, level]
  );
}

/** Timer bekor bo'lganda keyingi missiyaning baseline'i ham bekor qilinadi. */
export async function clearBaseline(pool, userId, level) {
  await pool.query(
    `UPDATE user_missions SET baseline_friends = NULL
     WHERE user_id = $1 AND mission_level = $2 AND claimed = false`,
    [userId, level]
  );
}

/**
 * Atomik claim: faqat claimed=false bo'lgan qatorni belgilaydi.
 * 0 qator qaytsa — parallel so'rov allaqachon olib bo'lgan (race himoyasi).
 */
export async function markClaimed(pool, userId, level) {
  const r = await pool.query(
    `UPDATE user_missions SET claimed = true, claimed_at = NOW()
     WHERE user_id = $1 AND mission_level = $2 AND claimed = false
     RETURNING *`,
    [userId, level]
  );
  return r.rows[0] || null;
}

/** Gift yuborishda xato bo'lsa claim'ni qaytarish — user qayta urinib ko'ra oladi. */
export async function revertClaim(pool, userId, level) {
  await pool.query(
    `UPDATE user_missions SET claimed = false, claimed_at = NULL, order_id = NULL
     WHERE user_id = $1 AND mission_level = $2`,
    [userId, level]
  );
}

export async function attachOrder(pool, userId, level, orderDbId) {
  await pool.query(
    `UPDATE user_missions SET order_id = $3 WHERE user_id = $1 AND mission_level = $2`,
    [userId, level, orderDbId]
  );
}
