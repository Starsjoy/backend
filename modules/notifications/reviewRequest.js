export const REVIEW_REQUEST_DELAY_MS = 5 * 60 * 1000;

export const REVIEW_REQUEST_TEXT = `Assalomu alaykum!

StarsJoy xizmatidan foydalangan bo'lsangiz, fikringiz biz uchun juda muhim. Bir necha soniya vaqt ajratib, xizmatimizni baholab o'tsangiz minnatdor bo'lamiz.

Sharh qoldirish uchun havola:
starsjoy.uz/sharh-qoldirish

Har bir fikr StarsJoy'ni yanada yaxshilashga yordam beradi. Rahmat!`;

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
        await bot.telegram.sendMessage(row.owner_user_id, REVIEW_REQUEST_TEXT);
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
