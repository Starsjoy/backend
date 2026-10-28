import { escapeTelegramHtml } from "../telegram/channelNotify.js";

/**
 * Reklama manbalari (UTM o'rniga): t.me/StarsjoyBot?start=<payload>
 *   - /start bosilsa — manba kanaliga "start bosdi" xabari
 *   - shu manbadan kelgan user har safar xarid qilsa — manba kanaliga buyurtma xabari
 *
 * Manba userga faqat bir marta (first-touch) yoziladi: yangi user yoki hali hech narsa
 * sotib olmagan user. Eski xaridorlar havolani bosib qo'ysa ham reklamaga hisoblanmaydi.
 *
 * Hamma funksiya xatoni o'zi ushlaydi — start/buyurtma jarayoniga hech qachon ta'sir qilmaydi.
 */
export const SOURCES = {
  uzbektype: { label: "Uzbektype", channelEnv: "UZBEKTYPE_CHANNEL_ID" },
};

const BOT_USERNAME = "StarsjoyBot";

export function buildSourceLink(source) {
  return SOURCES[source] ? `https://t.me/${BOT_USERNAME}?start=${source}` : null;
}

export function parseSourcePayload(payload) {
  const p = String(payload || "").trim().toLowerCase();
  return SOURCES[p] ? p : null;
}

function sourceChannel(source) {
  const raw = String(process.env[SOURCES[source]?.channelEnv] || "").trim();
  if (!raw) return null;
  return /^-?\d+$/.test(raw) ? Number(raw) : raw;
}

let schemaReady = null;
function ensureSchema(pool) {
  if (!schemaReady) {
    schemaReady = (async () => {
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS source TEXT DEFAULT NULL`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS source_at TIMESTAMPTZ DEFAULT NULL`);
      // Bitta buyurtma uchun manba xabari faqat bir marta
      await pool.query(`
        CREATE TABLE IF NOT EXISTS source_order_notifications (
          order_id INTEGER PRIMARY KEY,
          source TEXT NOT NULL,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`);
    })().catch((err) => {
      schemaReady = null;
      throw err;
    });
  }
  return schemaReady;
}

// Profildagi "Oxirgi xarid" bilan bir xil: faqat haqiqiy pulli xaridlar
const PAID_ORDER_SQL = `status IN ('completed', 'delivered') AND summ > 0
  AND COALESCE(payment_method, '') NOT IN ('bonus', 'referral', 'admin_manual')`;

async function send(bot, chatId, text) {
  try {
    await bot.telegram.sendMessage(chatId, text, { parse_mode: "HTML", disable_web_page_preview: true });
  } catch (err) {
    console.error(`❌ Manba kanaliga xabar yuborilmadi (${chatId}):`, err.message);
  }
}

function userLine({ username, name, userId }) {
  const u = username && !String(username).startsWith("user_") ? `@${escapeTelegramHtml(username)}` : "username yo'q";
  return `👤 ${u}${name ? ` (${escapeTelegramHtml(name)})` : ""} · ID <code>${escapeTelegramHtml(userId)}</code>`;
}

/** /start <payload> — token.js dan chaqiriladi */
export async function handleSourceStart(pool, bot, { payload, userId, username, name, created }) {
  try {
    const source = parseSourcePayload(payload);
    if (!source) return;
    await ensureSchema(pool);
    const uid = String(userId);

    const paid = await pool.query(
      `SELECT COUNT(*)::int AS c FROM orders WHERE owner_user_id = $1 AND ${PAID_ORDER_SQL}`,
      [uid]
    );
    const paidCount = paid.rows[0]?.c || 0;

    // First-touch: yangi user yoki hali xarid qilmagan va manbasi yo'q user
    let attributed = false;
    if (created || paidCount === 0) {
      const upd = await pool.query(
        `UPDATE users SET source = $1, source_at = NOW() WHERE user_id = $2 AND source IS NULL RETURNING user_id`,
        [source, uid]
      );
      attributed = upd.rowCount > 0;
    }
    const cur = await pool.query(`SELECT source FROM users WHERE user_id = $1`, [uid]);
    const currentSource = cur.rows[0]?.source || null;

    console.log(`📣 Manba start: ${source} user=${uid} created=${created} attributed=${attributed}`);

    const chatId = sourceChannel(source);
    if (!chatId || !bot) return;

    let status;
    if (created) status = "🆕 Yangi foydalanuvchi";
    else if (currentSource === source) status = attributed ? "🔁 Avval botda bo'lgan, hali xarid qilmagan" : "🔁 Qayta start bosdi";
    else if (paidCount > 0) status = `⚪️ Eski mijoz (${paidCount} ta xarid) — hisobga olinmaydi`;
    else status = `⚪️ Boshqa manbadan kelgan (${escapeTelegramHtml(currentSource || "?")}) — hisobga olinmaydi`;

    await send(
      bot,
      chatId,
      `🚀 <b>${SOURCES[source].label} → Start bosdi</b>\n\n${userLine({ username, name, userId: uid })}\n${status}`
    );
  } catch (err) {
    console.error("❌ Manba start xatosi:", err.message);
  }
}

function productLabel(order) {
  const type = String(order.order_type || "");
  const n = Number(order.type_amount) || 0;
  if (type === "gift") return `🎁 Gift (${n} ⭐)`;
  if (type.includes("premium")) return `👑 Premium ${n} oy`;
  if (type.includes("stars")) return `🌟 ${n.toLocaleString("ru-RU")} Stars`;
  return escapeTelegramHtml(type || "—");
}

/** Muvaffaqiyatli yetkazilgan buyurtma — user reklama manbasidan kelgan bo'lsa kanalga xabar */
export async function notifySourceOrder(pool, bot, orderId) {
  try {
    if (!bot || !orderId) return;
    await ensureSchema(pool);
    const r = await pool.query(
      `SELECT o.id, o.owner_user_id, o.order_type, o.type_amount, o.summ, o.payment_method,
              o.recipient_username, u.username, u.name, u.source
       FROM orders o JOIN users u ON u.user_id = o.owner_user_id
       WHERE o.id = $1`,
      [orderId]
    );
    const order = r.rows[0];
    if (!order?.source || !SOURCES[order.source]) return;
    if (!(Number(order.summ) > 0) || ["bonus", "referral", "admin_manual"].includes(String(order.payment_method || ""))) return;

    const chatId = sourceChannel(order.source);
    if (!chatId) return;

    const claim = await pool.query(
      `INSERT INTO source_order_notifications (order_id, source) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING order_id`,
      [order.id, order.source]
    );
    if (!claim.rowCount) return;

    // Joriy buyurtma statusi hali yangilanmagan bo'lsa ham hisobga kiradi
    const stats = await pool.query(
      `SELECT COUNT(*)::int AS c, COALESCE(SUM(summ), 0)::bigint AS total
       FROM orders WHERE owner_user_id = $1 AND id <= $2 AND (id = $2 OR (${PAID_ORDER_SQL}))`,
      [String(order.owner_user_id), order.id]
    );
    const count = stats.rows[0]?.c || 1;
    const total = Number(stats.rows[0]?.total) || 0;
    const summ = Number(order.summ) || 0;
    const recipient = String(order.recipient_username || "").replace(/^@/, "");
    const forOther = recipient && recipient.toLowerCase() !== String(order.username || "").toLowerCase();

    await send(
      bot,
      chatId,
      `🛒 <b>${SOURCES[order.source].label} mijozi xarid qildi!</b>\n\n` +
        `${userLine({ username: order.username, name: order.name, userId: order.owner_user_id })}\n` +
        `📦 Order #${order.id} · ${productLabel(order)}${forOther ? ` → @${escapeTelegramHtml(recipient)}` : ""}\n` +
        `💰 ${summ.toLocaleString("ru-RU")} so'm\n\n` +
        `📊 Bu uning <b>${count}-xaridi</b> · jami ${total.toLocaleString("ru-RU")} so'm`
    );
  } catch (err) {
    console.error(`❌ Manba buyurtma xabari (#${orderId}):`, err.message);
  }
}
