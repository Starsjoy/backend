/**
 * Do'stlarni Telegram kanalida qayta tekshirish.
 *
 * 24 soatlik oyna tugaganda va claim paytida chaqiriladi: kanaldan chiqib ketgan
 * do'stlar `subscribe_user = false` bo'ladi va missiya progressidan tushadi.
 *
 * ⚠️ Bot kanalda ADMIN bo'lishi shart, aks holda getChatMember ishlamaydi.
 * Telegram tarafidagi xatolar (timeout, flood) do'stni O'CHIRMAYDI — foydaga
 * talqin qilamiz, aks holda vaqtinchalik uzilish userni jazolagan bo'lardi.
 */
export async function verifyMissionFriends(ctx, userId) {
  const { pool, bot, subscriptionChannel } = ctx;
  if (!bot || !subscriptionChannel) return { checked: 0, removed: 0 };

  const r = await pool.query(
    `SELECT user_id FROM users WHERE referrer_user_id = $1 AND subscribe_user = true`,
    [userId]
  );

  let removed = 0;
  for (const row of r.rows) {
    try {
      const member = await bot.telegram.getChatMember(subscriptionChannel, row.user_id);
      if (member?.status === "left" || member?.status === "kicked") {
        await pool.query(
          `UPDATE users SET subscribe_user = false WHERE user_id = $1`,
          [row.user_id]
        );
        removed++;
      }
    } catch {
      // Do'stni saqlab qolamiz
    }
  }

  if (removed > 0) {
    console.log(`🔎 Missiya tekshiruvi: ${userId} — ${removed}/${r.rows.length} do'st kanaldan chiqqan`);
  }
  return { checked: r.rows.length, removed };
}

/**
 * Bitta userning kanalga obunasini tekshirish.
 * Bot javob bermasa `null` qaytadi — chaqiruvchi o'zi qaror qiladi.
 */
export async function isChannelMember(ctx, userId) {
  const { bot, subscriptionChannel } = ctx;
  if (!bot || !subscriptionChannel) return null;
  try {
    const member = await bot.telegram.getChatMember(subscriptionChannel, userId);
    return ["member", "administrator", "creator"].includes(member?.status);
  } catch (err) {
    console.error(`⚠️ getChatMember(${subscriptionChannel}, ${userId}):`, err?.message || err);
    return null;
  }
}
