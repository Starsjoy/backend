/**
 * Referal havolasi: botga /start orqali (start=ref_<kod>). Bot /start bosilgani uchun
 * do'st buyurtma xabarlarini ham oladi (Mini App havolasida bot xabar yubora olmasdi).
 */

const BOT_USERNAME = "StarsjoyBot";

/**
 * Vaqtincha bloklangan referal havolalar (2026-11-08: @nestixnn "tekin Stars" deb tarqatgan).
 * Bu kod bilan kelgan user referalga bog'lanmaydi, kanal taklifi navbatga qo'yilmaydi va
 * /start da 3 tilda ogohlantirish oladi. Mini App'da ham shu referrer'ning userlariga
 * ogohlantirish chiqadi (getUserPreferences → fake_ref_warning).
 */
export const BLOCKED_REFERRAL_CODES = new Set(["8985bd2252a8"]);
export const BLOCKED_REFERRER_IDS = new Set(["8038746319"]);

export function isBlockedReferralCode(code) {
  return BLOCKED_REFERRAL_CODES.has(String(code || "").trim());
}

/** /start da chiqadigan ogohlantirish (uz + ru + en bitta xabarda) */
export const FAKE_PROMO_WARNING = `⚠️ Diqqat!

StarsJoy hech kimga tekin Stars, tekin Gift (sovg'a) yoki tekin Premium bermaydi. Sizga bularni tekinga va'da qilib yuborilgan havola rasmiy emas — StarsJoy bunday aksiya o'tkazmayapti.

Stars, Gift va Premium faqat xarid orqali olinadi.

Savollar bo'lsa, supportga yozing: @StarsjoySupport

———

⚠️ Внимание!

StarsJoy не раздаёт бесплатные Stars, подарки (Gift) или Premium. Ссылка, по которой вам это обещали бесплатно, не официальная — StarsJoy не проводит такую акцию.

Stars, подарки и Premium можно получить только через покупку.

Если есть вопросы, напишите в поддержку: @StarsjoySupport

———

⚠️ Attention!

StarsJoy does not give away free Stars, Gifts or Premium. The link that promised you these for free is not official — StarsJoy is not running any such giveaway.

Stars, Gifts and Premium can only be obtained by purchase.

If you have questions, contact support: @StarsjoySupport`;
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
  if (!referralCode || isBlockedReferralCode(referralCode)) return null;
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
