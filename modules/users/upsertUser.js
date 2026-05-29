import crypto from "crypto";

/**
 * Telegram foydalanuvchini users jadvaliga xavfsiz yozish (takroriy /start va username ziddiyati).
 */
export async function upsertUserFromTelegram(
  pool,
  { userId, fullName, username, language = "uz" }
) {
  const uid = String(userId);
  let uname = String(username || `user_${uid}`)
    .replace(/^@/, "")
    .trim();
  if (!uname) uname = `user_${uid}`;

  const taken = await pool.query(
    `SELECT user_id FROM users WHERE username = $1 AND user_id IS DISTINCT FROM $2`,
    [uname, uid]
  );
  if (taken.rows.length > 0) {
    uname = `user_${uid}`;
  }

  const referralCode = crypto.randomBytes(6).toString("hex");

  const result = await pool.query(
    `INSERT INTO users (name, username, user_id, referral_code, referrer_user_id, language)
     VALUES ($1, $2, $3, $4, NULL, $5)
     ON CONFLICT (user_id) DO UPDATE SET
       name = EXCLUDED.name,
       username = CASE
         WHEN NOT EXISTS (
           SELECT 1 FROM users u
           WHERE u.username = EXCLUDED.username
             AND u.user_id IS DISTINCT FROM users.user_id
         ) THEN EXCLUDED.username
         ELSE users.username
       END,
       language = COALESCE(EXCLUDED.language, users.language)
     RETURNING user_id, username, referral_code, (xmax = 0) AS inserted`,
    [fullName, uname, uid, referralCode, language]
  );

  const row = result.rows[0];
  return {
    created: row.inserted === true,
    userId: row.user_id,
    username: row.username,
    referralCode: row.referral_code,
  };
}
