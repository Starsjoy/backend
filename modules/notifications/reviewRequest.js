import { getUserAppLanguage } from "./orderExpiredMessages.js";

export const REVIEW_REQUEST_DELAY_MS = 5 * 60 * 1000;

// en sahifa saytda yo'q — en foydalanuvchilar ruscha sahifaga yo'naltiriladi
const REVIEW_URL_UZ = "https://starsjoy.uz/sharh-qoldirish";
const REVIEW_URL_RU = "https://starsjoy.uz/ru/sharh-qoldirish";

const REVIEW_TEXTS = {
  uz: {
    text:
      "⭐ Xaridingiz sizga yoqdimi?\n\n" +
      "StarsJoy'ni tanlaganingiz uchun rahmat! Fikringiz biz uchun juda muhim — xizmatimizni baholashga bir daqiqa ajrating.",
    button: "⭐ Sharh qoldirish",
    url: REVIEW_URL_UZ,
  },
  ru: {
    text:
      "⭐ Вам понравилась покупка?\n\n" +
      "Спасибо, что выбрали StarsJoy! Ваше мнение очень важно для нас — уделите минуту, чтобы оценить наш сервис.",
    button: "⭐ Оставить отзыв",
    url: REVIEW_URL_RU,
  },
  en: {
    text:
      "⭐ Did you enjoy your purchase?\n\n" +
      "Thank you for choosing StarsJoy! Your feedback matters to us — please take a minute to rate our service.",
    button: "⭐ Leave a review",
    url: REVIEW_URL_RU,
  },
};

export function buildReviewRequestMessage(language) {
  const tr = REVIEW_TEXTS[language] || REVIEW_TEXTS.uz;
  return {
    text: tr.text,
    extra: {
      reply_markup: {
        inline_keyboard: [[{ text: tr.button, url: tr.url }]],
      },
    },
  };
}

const SUCCESS_STATUSES = ["delivered", "completed"];

export async function ensureReviewRequestTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS review_request_queue (
      owner_user_id TEXT PRIMARY KEY,
      due_at TIMESTAMPTZ NOT NULL,
      sent_at TIMESTAMPTZ,
      first_order_id INTEGER,
      created_at TIMESTAMPTZ DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_review_request_queue_due
    ON review_request_queue (due_at)
    WHERE sent_at IS NULL;
  `);
}

function isPurchasedOrder(order) {
  return String(order?.payment_method || "").toLowerCase() !== "bonus";
}

export async function scheduleReviewRequestAfterFirstPurchase(pool, order) {
  const ownerUserId = order?.owner_user_id;
  if (!ownerUserId || !isPurchasedOrder(order)) return;

  try {
    const countRes = await pool.query(
      `SELECT COUNT(*)::int AS cnt
       FROM orders
       WHERE owner_user_id = $1
         AND status = ANY($2::text[])
         AND COALESCE(payment_method, '') <> 'bonus'`,
      [String(ownerUserId), SUCCESS_STATUSES]
    );

    if (countRes.rows[0]?.cnt !== 1) return;

    const dueAt = new Date(Date.now() + REVIEW_REQUEST_DELAY_MS);
    const ins = await pool.query(
      `INSERT INTO review_request_queue (owner_user_id, due_at, first_order_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (owner_user_id) DO NOTHING`,
      [String(ownerUserId), dueAt, order.id ?? null]
    );

    if (ins.rowCount > 0) {
      console.log(
        `📝 Sharh so'rovi rejalashtirildi: user=${ownerUserId}, order=#${order.id}, vaqt=${dueAt.toISOString()}`
      );
    }
  } catch (err) {
    console.error("❌ Sharh so'rovi rejalashtirish:", err.message);
  }
}

export async function runReviewRequestJob(pool, bot) {
  if (!bot) return;

  try {
    const pending = await pool.query(
      `SELECT owner_user_id
       FROM review_request_queue
       WHERE sent_at IS NULL AND due_at <= NOW()
       ORDER BY due_at ASC
       LIMIT 20`
    );

    if (!pending.rows.length) return;

    let sent = 0;
    for (const row of pending.rows) {
      const claim = await pool.query(
        `UPDATE review_request_queue
         SET sent_at = NOW()
         WHERE owner_user_id = $1 AND sent_at IS NULL
         RETURNING owner_user_id`,
        [row.owner_user_id]
      );
      if (!claim.rowCount) continue;

      try {
        const lang = await getUserAppLanguage(pool, row.owner_user_id);
        const { text, extra } = buildReviewRequestMessage(lang);
        await bot.telegram.sendMessage(row.owner_user_id, text, extra);
        sent++;
        await new Promise((resolve) => setTimeout(resolve, 60));
      } catch (sendErr) {
        console.error(
          `❌ Sharh so'rovi yuborilmadi (user_id=${row.owner_user_id}):`,
          sendErr.message
        );
      }
    }

    if (sent > 0) {
      console.log(`📩 Sharh so'rovi: ${sent} ta foydalanuvchiga yuborildi`);
    }
  } catch (err) {
    console.error("❌ Sharh so'rovi job:", err.message);
  }
}
