import { normalizeLanguage } from "../users/userPreferences.js";

/**
 * Ixtiyoriy kanal taklifi: /start dan 1 soat keyin, userning tilida, faqat hali
 * obuna bo'lmagan bo'lsa. Navbat bazada — server qayta ishga tushsa ham yo'qolmaydi.
 * Har bir userga umrida 1 marta.
 */

export const CHANNEL_INVITE_DELAY_MS = 60 * 60 * 1000;

const TEXTS = {
  uz: { text: "📢 Yangiliklar va chegirmalardan xabardor bo'lish uchun kanalimizga obuna bo'ling!", button: "📢 Kanalga o'tish" },
  ru: { text: "📢 Подпишитесь на наш канал, чтобы быть в курсе новостей и скидок!", button: "📢 Перейти в канал" },
  en: { text: "📢 Subscribe to our channel to stay up to date with news and deals!", button: "📢 Join channel" },
};

let tableReady = null;
export function ensureChannelInviteTable(pool) {
  if (!tableReady) {
    tableReady = pool
      .query(`
        CREATE TABLE IF NOT EXISTS channel_invite_queue (
          user_id TEXT PRIMARY KEY,
          due_at TIMESTAMPTZ NOT NULL,
          sent_at TIMESTAMPTZ,
          skipped BOOLEAN NOT NULL DEFAULT false,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `)
      .then(() =>
        pool.query(
          `CREATE INDEX IF NOT EXISTS idx_channel_invite_due ON channel_invite_queue (due_at) WHERE sent_at IS NULL`
        )
      )
      .catch((err) => {
        tableReady = null;
        throw err;
      });
  }
  return tableReady;
}

/** /start da obuna bo'lmagan userga taklifni 1 soatdan keyinga rejalashtirish (takroriy /start — o'zgarishsiz) */
export async function scheduleChannelInvite(pool, userId) {
  await ensureChannelInviteTable(pool);
  await pool.query(
    `INSERT INTO channel_invite_queue (user_id, due_at) VALUES ($1, $2)
     ON CONFLICT (user_id) DO NOTHING`,
    [String(userId), new Date(Date.now() + CHANNEL_INVITE_DELAY_MS)]
  );
}

/** Taklif tili: app'da tanlangan til, bo'lmasa Telegram tili (users.language), aks holda uz */
async function inviteLanguage(pool, userId) {
  const r = await pool.query(`SELECT language FROM users WHERE user_id = $1`, [String(userId)]);
  return normalizeLanguage(r.rows[0]?.language);
}

/** Har daqiqada: vaqti kelgan takliflarni yuborish (obuna bo'lganlarga — yuborilmaydi) */
export async function runChannelInviteJob({ pool, bot, subscriptionChannel }) {
  if (!bot || !subscriptionChannel) return;
  await ensureChannelInviteTable(pool);
  const due = await pool.query(
    `SELECT user_id FROM channel_invite_queue
     WHERE sent_at IS NULL AND due_at <= NOW()
     ORDER BY due_at LIMIT 25`
  );
  const channelUrl = `https://t.me/${String(subscriptionChannel).replace(/^@/, "")}`;

  for (const row of due.rows) {
    // Atomik band qilish — bir nechta jarayon bo'lsa ham 1 marta
    const claim = await pool.query(
      `UPDATE channel_invite_queue SET sent_at = NOW() WHERE user_id = $1 AND sent_at IS NULL RETURNING user_id`,
      [row.user_id]
    );
    if (!claim.rowCount) continue;

    try {
      const member = await bot.telegram.getChatMember(subscriptionChannel, row.user_id).catch(() => null);
      if (["member", "administrator", "creator"].includes(member?.status)) {
        await pool.query(`UPDATE channel_invite_queue SET skipped = true WHERE user_id = $1`, [row.user_id]);
        continue;
      }
      const tr = TEXTS[await inviteLanguage(pool, row.user_id)] || TEXTS.uz;
      await bot.telegram.sendMessage(row.user_id, tr.text, {
        reply_markup: { inline_keyboard: [[{ text: tr.button, url: channelUrl }]] },
      });
      await new Promise((r) => setTimeout(r, 60));
    } catch (err) {
      // 403 (botni bloklagan) va h.k. — qayta urinmaymiz
      console.error(`⚠️ Kanal taklifi yuborilmadi (user=${row.user_id}):`, err.message);
    }
  }
}
