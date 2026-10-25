/**
 * Kanal obunasini belgilash — bot (/start, eski "Tekshirish" tugmasi) va missiyalar uchun umumiy.
 *
 * Obuna majburiy emas: user /start bosganda yoki missiya holati so'ralganda kanalda
 * bo'lsa, subscribe_user=true qilinadi va (birinchi marta) referal statistikasi yangilanadi.
 */

/**
 * User kanalga obuna bo'lgan deb belgilaydi. Faqat birinchi marta yon effektlar:
 * referral_requests.subscribe_referrer va taklif qilganning total_referrals ++.
 * @returns {Promise<boolean>} shu chaqiruvda yangi belgilangan bo'lsa true
 */
export async function markUserSubscribed(pool, userId) {
  const uid = String(userId);
  const upd = await pool.query(
    `UPDATE users SET subscribe_user = true
     WHERE user_id = $1 AND COALESCE(subscribe_user, false) = false
     RETURNING referrer_user_id`,
    [uid]
  );
  if (!upd.rowCount) return false;

  await pool
    .query(
      `UPDATE referral_requests SET subscribe_referrer = true
       WHERE owner_user_id = $1 AND is_accepted = false AND rejected_at IS NULL`,
      [uid]
    )
    .catch((err) => console.error("⚠️ referral_requests subscribe:", err.message));

  const referrerId = upd.rows[0].referrer_user_id;
  if (referrerId) {
    await pool
      .query(`UPDATE users SET total_referrals = total_referrals + 1 WHERE user_id = $1`, [String(referrerId)])
      .catch((err) => console.error("⚠️ total_referrals:", err.message));
  }
  return true;
}

/**
 * Taklif qilingan, hali "obuna bo'lmagan" do'stlarni kanalda tekshirib, a'zo bo'lganlarini
 * belgilaydi (majburiy obuna yo'qligi uchun do'st kanalga keyinroq qo'shilishi mumkin).
 * Telegram so'rovlari soni cheklangan.
 */
export async function promoteSubscribedFriends({ pool, bot, subscriptionChannel }, referrerId, limit = 30) {
  if (!bot || !subscriptionChannel) return 0;
  const r = await pool.query(
    `SELECT user_id FROM users
     WHERE referrer_user_id = $1 AND COALESCE(subscribe_user, false) = false
     ORDER BY id DESC LIMIT $2`,
    [String(referrerId), limit]
  );
  let promoted = 0;
  for (const row of r.rows) {
    try {
      const member = await bot.telegram.getChatMember(subscriptionChannel, row.user_id);
      if (["member", "administrator", "creator"].includes(member?.status)) {
        if (await markUserSubscribed(pool, row.user_id)) promoted++;
      }
    } catch {
      /* Telegram xatosi — keyingi safar qayta tekshiriladi */
    }
  }
  return promoted;
}
