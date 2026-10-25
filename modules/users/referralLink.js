/**
 * Referal havolasi: botga /start orqali (start=ref_<kod>). Bot /start bosilgani uchun
 * do'st buyurtma xabarlarini ham oladi (Mini App havolasida bot xabar yubora olmasdi).
 */

const BOT_USERNAME = "StarsjoyBot";
const PAYLOAD_PREFIX = "ref_";

export function buildReferralLink(referralCode) {
  return referralCode ? `https://t.me/${BOT_USERNAME}?start=${PAYLOAD_PREFIX}${referralCode}` : null;
}

/** /start payload'idan referal kodini ajratadi ("ref_ab12cd34ef56" → "ab12cd34ef56") */
export function parseReferralPayload(payload) {
  const p = String(payload || "").trim();
  if (!p.startsWith(PAYLOAD_PREFIX)) return null;
  const code = p.slice(PAYLOAD_PREFIX.length);
  return /^[A-Za-z0-9_-]{4,64}$/.test(code) ? code : null;
}

/**
 * YANGI yaratilgan userni taklif qilgan odamga bog'laydi (faqat referrer hali yo'q bo'lsa,
 * o'ziga o'zi emas). /api/referral/register (Mini App) bilan bir xil yozuvlar:
 * users.referrer_user_id + referral_requests (is_accepted=true).
 * @returns {Promise<string|null>} bog'langan referrer username yoki null
 */
export async function linkReferrerOnSignup(pool, { userId, username, referralCode }) {
  if (!referralCode) return null;
  const uid = String(userId);
  const ref = await pool.query(`SELECT user_id, username FROM users WHERE referral_code = $1`, [referralCode]);
  const referrer = ref.rows[0];
  if (!referrer?.user_id || String(referrer.user_id) === uid) return null;

  const upd = await pool.query(
    `UPDATE users SET referrer_user_id = $1 WHERE user_id = $2 AND referrer_user_id IS NULL RETURNING user_id`,
    [String(referrer.user_id), uid]
  );
  if (!upd.rowCount) return null;

  await pool.query(
    `INSERT INTO referral_requests
       (owner_user_id, owner_username, referrer_user_id, referrer_username, subscribe_referrer, is_accepted)
     VALUES ($1, $2, $3, $4, false, true)`,
    [uid, username, String(referrer.user_id), referrer.username]
  );
  return referrer.username;
}
