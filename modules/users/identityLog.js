/**
 * Username va ism tarixi (firibgarlik holatlarida odamni topish uchun).
 * Telegram ID o'zgarmaydi, username/ism o'zgaradi — har bir yangi (ID, username, ism) juftligi bir qator.
 * So'rov yo'lini HECH QACHON sekinlashtirmaydi va xato bermaydi: fire-and-forget, xato faqat logga.
 */
const seen = new Map(); // "id|username|name" -> oxirgi yozilgan vaqt (ms)
const REFRESH_MS = 6 * 3600 * 1000;
let ready = null;

function ensureTable(pool) {
  if (!ready) {
    ready = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS user_identity_log (
          user_id    BIGINT      NOT NULL,
          username   TEXT        NOT NULL DEFAULT '',
          name       TEXT        NOT NULL DEFAULT '',
          first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          PRIMARY KEY (user_id, username, name)
        )`);
      await pool.query(`CREATE INDEX IF NOT EXISTS user_identity_log_username_idx ON user_identity_log (lower(username))`);
    })().catch((e) => {
      ready = null;
      throw e;
    });
  }
  return ready;
}

export function logIdentity(pool, user) {
  try {
    if (!user || !user.id) return;
    const username = String(user.username || "").replace(/^@/, "").slice(0, 64);
    const name = [user.first_name, user.last_name].filter(Boolean).join(" ").trim().slice(0, 128);
    const key = `${user.id}|${username}|${name}`;
    const now = Date.now();
    if (now - (seen.get(key) || 0) < REFRESH_MS) return;
    seen.set(key, now);
    if (seen.size > 50000) seen.clear();
    ensureTable(pool)
      .then(() =>
        pool.query(
          `INSERT INTO user_identity_log (user_id, username, name) VALUES ($1, $2, $3)
           ON CONFLICT (user_id, username, name) DO UPDATE SET last_seen = NOW()`,
          [user.id, username, name]
        )
      )
      .catch((e) => console.error("⚠️ identity log:", e.message));
  } catch (e) {
    console.error("⚠️ identity log:", e.message);
  }
}
