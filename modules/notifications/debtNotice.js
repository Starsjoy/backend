/**
 * Bitta foydalanuvchi uchun: boshqa mijozning to'lovi uning buyurtmasiga yozilib, mahsulotni
 * tekinga olgan (2026-11-08, #19971, Premium 3 oy, 172 000 so'm). U botni bloklagan —
 * qayta ochganda (blokdan chiqarish yoki /start) xabar BIR MARTA yuboriladi.
 * Yuborilgani `settings` jadvalidagi kalit bilan belgilanadi (qayta yuborilmaydi).
 */

const NOTICES = {
  "8557802662": {
    key: "debt_notice_sent_8557802662",
    text: `Assalomu alaykum!

8 noyabr kuni siz Premium 3 oy uchun buyurtma ochgan edingiz. Boshqa bir mijoz e'tiborsizlik qilib, o'z buyurtmasidagi summani emas, aynan sizning buyurtmangiz summasini to'lab yuborgan. Shu sababli Premium sizga to'lovsiz yuborilgan.

Bu boshqa odamning haqqi. Iltimos, 172 000 so'mni to'lash uchun @StarsjoySupport ga murojaat qiling.

Oldindan rahmat!`,
  },
};

export async function maybeSendDebtNotice(pool, bot, userId) {
  const notice = NOTICES[String(userId)];
  if (!notice) return false;
  // Atomik band qilish: kalit yo'q bo'lsa yozamiz — faqat bitta jarayon yuboradi
  const claim = await pool.query(
    `INSERT INTO settings (key, value) VALUES ($1, 'sending')
     ON CONFLICT (key) DO NOTHING RETURNING key`,
    [notice.key]
  );
  if (!claim.rowCount) return false;
  try {
    await bot.telegram.sendMessage(String(userId), notice.text);
    await pool.query(`UPDATE settings SET value = $2, updated_at = NOW() WHERE key = $1`, [
      notice.key,
      `sent ${new Date().toISOString()}`,
    ]);
    console.log(`📩 Qarz eslatmasi yuborildi: user=${userId}`);
    return true;
  } catch (err) {
    // Yetib bormadi (masalan hali bloklangan) — keyingi safar qayta urinish uchun belgini olib tashlaymiz
    await pool.query(`DELETE FROM settings WHERE key = $1`, [notice.key]).catch(() => {});
    console.error(`❌ Qarz eslatmasi yuborilmadi (user=${userId}):`, err.message);
    return false;
  }
}
