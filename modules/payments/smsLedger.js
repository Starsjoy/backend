/**
 * SMS to'lov daftari — har bir kiruvchi karta SMS'i bazaga yoziladi va
 * qaysi buyurtmaga bog'langani belgilanadi.
 *
 * Qaror (resolveSmsOrder), 3 bosqich:
 *  1. ESKI TANLOV — eski zanjir qaysi orderni olardi, aynan o'shani topamiz
 *     (pending, 15 daq ichida, zanjir tartibidagi tur, eng yangisi). Bitta shart
 *     qo'shildi: order TO'LOVDAN OLDIN ochilgan bo'lishi kerak. Aks holda bu
 *     boshqa mijozning orderi (A expired → summa B ga berilgan → A ning SMS'i
 *     kechikib keldi) va unga yozilmaydi.
 *  2. KECHIKKAN SMS — 1-bosqich hech narsa bermasa: SMS dagi vaqtda faol bo'lgan
 *     to'lanmagan order (odatda expired bo'lib qolgan). Faqat daftar ishga
 *     tushgandan keyingi orderlar.
 *  3. QO'LDA TASDIQLANGAN — to'lanmagan yo'q, lekin SMS siz to'langan (admin)
 *     bitta order bor → SMS shunga bog'lanadi, hech narsa yetkazilmaydi.
 *
 * To'langan, lekin yetkazilmagan (failed/error/processing) orderlarni tizim hech
 * qachon qayta yetkazmaydi — bu faqat admin qo'lida.
 *
 * 4 kunlik real SMS'lar bilan simulyatsiya (514 ta): 199 tasi eski bilan bir xil,
 * 313 begona to'lov ikkalasida ham topilmaydi, 1 yo'qolgan to'lov tiklanadi,
 * 1 qo'lda tasdiqlangan orderga bog'lanadi, noaniq — 0.
 */

const PAYMENT_WINDOW_SEC = 8 * 60; // mijoz taymeri (frontend 480s)
const CLOCK_SKEW_SEC = 30; // bank soati / SMS da soniya yo'q
const ARRIVAL_SKEW_SEC = 5; // Telegram va server soatlari farqi

export async function ensureSmsLedger(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sms_payments (
      id BIGSERIAL PRIMARY KEY,
      chat_id TEXT NOT NULL,
      msg_id BIGINT NOT NULL,
      card_last4 TEXT,
      amount BIGINT NOT NULL,
      sms_time TIMESTAMPTZ,
      received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      raw_text TEXT,
      decision TEXT NOT NULL DEFAULT 'new',
      order_id BIGINT,
      note TEXT,
      UNIQUE (chat_id, msg_id)
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_sms_payments_order_id ON sms_payments (order_id)`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_sms_payments_received_at ON sms_payments (received_at)`
  );
  // Daftar qachondan yuritilayotgani — bundan oldingi paid orderlar "SMS siz
  // qo'lda tasdiqlangan" deb hisoblanmaydi (ularda link yo'q, chunki daftar yo'q edi).
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('sms_ledger_since', NOW()::text)
     ON CONFLICT (key) DO NOTHING`
  );
  const r = await pool.query(`SELECT value FROM settings WHERE key = 'sms_ledger_since'`);
  return new Date(r.rows[0].value);
}

/**
 * SMS ichidagi vaqt (Toshkent) → Date. Topilmasa null.
 *   UZCARD: "🕓 29.10.26 01:24"
 *   HUMO:   "🕓 06:29 25.10.2026"
 */
export function parseSmsTime(text) {
  const s = String(text || "");
  let d, mo, y, h, mi;
  let m = s.match(/🕓\s*(\d{2})\.(\d{2})\.(\d{2,4})\s+(\d{2}):(\d{2})/);
  if (m) {
    [, d, mo, y, h, mi] = m;
  } else {
    m = s.match(/🕓\s*(\d{2}):(\d{2})\s+(\d{2})\.(\d{2})\.(\d{2,4})/);
    if (!m) return null;
    [, h, mi, d, mo, y] = m;
  }
  if (y.length === 2) y = `20${y}`;
  const iso = `${y}-${mo}-${d}T${h}:${mi}:00+05:00`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  // Aqlga sig'maydigan vaqt (kelajakda yoki 1 kundan eski) — ishonmaymiz
  const ageSec = (Date.now() - date.getTime()) / 1000;
  if (ageSec < -5 * 60 || ageSec > 24 * 3600) return null;
  return date;
}

/** Yangi SMS ni yozadi. Avval ishlangan bo'lsa (takror) — null. */
export async function recordSms(pool, { chatId, msgId, cardLast4, amount, smsTime, rawText }) {
  const r = await pool.query(
    `INSERT INTO sms_payments (chat_id, msg_id, card_last4, amount, sms_time, raw_text)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (chat_id, msg_id) DO NOTHING
     RETURNING id`,
    [String(chatId), Number(msgId), cardLast4 || null, amount, smsTime, rawText || null]
  );
  return r.rows[0]?.id ?? null;
}

export async function finishSms(pool, smsId, decision, orderId = null, note = null) {
  await pool.query(
    `UPDATE sms_payments SET decision = $2, order_id = $3, note = $4 WHERE id = $1`,
    [smsId, decision, orderId, note ? String(note).slice(0, 1000) : null]
  );
}

/**
 * SMS bo'yicha buyurtmani aniqlaydi. Hech narsani o'zgartirmaydi.
 *
 * chainTypes — eski zanjir tartibidagi order turlari (balanceChecker beradi).
 * Qaytaradi { decision, order?, candidates, note? }:
 *  - "match"        — shu order to'lansin (pending yoki expired)
 *  - "manual_paid"  — SMS qo'lda tasdiqlangan orderga bog'lanadi, hech narsa yuborilmaydi
 *  - "unmatched"    — mos order yo'q (boshqa loyiha to'lovi yoki taymerdan keyin to'langan)
 *  - "ambiguous"    — bir nechta mos order → admin hal qiladi
 */
export async function resolveSmsOrder(pool, { amount, smsTime, receivedAt, ledgerSince, chainTypes }) {
  // To'lov shu vaqtdan kech bo'lmagan: SMS dagi daqiqa oxiri + bank soati zaxirasi,
  // va SMS kelgan aniq vaqt (undan keyin ochilgan order to'lovchi bo'la olmaydi).
  const paidBefore = new Date(
    Math.min(
      smsTime.getTime() + (60 + CLOCK_SKEW_SEC) * 1000,
      (receivedAt ?? new Date()).getTime() + ARRIVAL_SKEW_SEC * 1000
    )
  );

  // 1) Eski zanjir tanlovi
  const legacy = await pool.query(
    `SELECT id, order_type, status, payment_status, created_at
     FROM orders
     WHERE summ = $1
       AND payment_status = 'pending'
       AND status = 'pending'
       AND order_type = ANY($2::text[])
       AND created_at >= NOW() - INTERVAL '15 minutes'
     ORDER BY array_position($2::text[], order_type::text), id DESC
     LIMIT 1`,
    [amount, chainTypes]
  );
  const pick = legacy.rows[0];
  let note = null;
  if (pick) {
    if (new Date(pick.created_at) <= paidBefore) {
      return { decision: "match", order: pick, candidates: [brief(pick)] };
    }
    note = `#${pick.id} to'lovdan keyin ochilgan — unga yozilmadi`;
    console.log(`🛡️ ${note}`);
  }

  // 2–3) SMS vaqtidagi faol oyna — faqat daftardan keyingi orderlar
  const r = await pool.query(
    `SELECT o.id, o.order_type, o.status, o.payment_status, o.created_at, o.owner_user_id,
            EXISTS (SELECT 1 FROM sms_payments s WHERE s.order_id = o.id) AS linked
     FROM orders o
     WHERE o.summ = $1
       AND o.payment_method = 'card'
       AND o.order_type = ANY($2::text[])
       AND o.created_at >= $3::timestamptz - make_interval(secs => $4)
       AND o.created_at <= $5::timestamptz
       AND o.created_at >= $6::timestamptz
     ORDER BY o.id`,
    [amount, chainTypes, smsTime, PAYMENT_WINDOW_SEC + CLOCK_SKEW_SEC, paidBefore, ledgerSince]
  );
  const rows = r.rows.filter((o) => !o.linked);
  const candidates = r.rows.map(brief);

  let unpaid = rows.filter(
    (o) =>
      ["pending", "expired"].includes(o.payment_status) &&
      ["pending", "expired"].includes(o.status)
  );
  if (unpaid.length > 1) {
    // Bir mijoz eski orderini tashlab, yangisini ochgan bo'lsa — eskisi hisobga olinmaydi
    unpaid = unpaid.filter(
      (o) => !unpaid.some((x) => x.owner_user_id === o.owner_user_id && x.id > o.id)
    );
  }
  if (unpaid.length === 1) {
    return { decision: "match", order: unpaid[0], candidates, note };
  }
  if (unpaid.length > 1) {
    return { decision: "ambiguous", candidates, note };
  }

  const manualPaid = rows.filter((o) => o.payment_status === "paid");
  if (manualPaid.length === 1) {
    return { decision: "manual_paid", order: manualPaid[0], candidates, note };
  }
  if (manualPaid.length > 1) {
    return { decision: "ambiguous", candidates, note };
  }
  return { decision: "unmatched", candidates, note };
}

function brief(o) {
  return {
    id: o.id,
    type: o.order_type,
    status: o.status,
    payment_status: o.payment_status,
    linked: Boolean(o.linked),
  };
}

/**
 * Match endpointlar uchun: aniq order_id bo'yicha to'langan deb belgilash.
 * Expired orderni ham oladi (SMS vaqti taymer ichida bo'lgan — resolveSmsOrder tekshirgan).
 * Atomik: admin qo'lda yuborish bilan poyga bo'lsa, faqat bittasi yutadi.
 */
export async function claimOrderById(pool, { orderId, amount, orderTypes }) {
  const r = await pool.query(
    `WITH prev AS (
       SELECT id, status AS prev_status FROM orders WHERE id = $1 FOR UPDATE
     )
     UPDATE orders o
     SET payment_status = 'paid', status = 'processing'
     FROM prev
     WHERE o.id = prev.id
       AND o.summ = $2
       AND o.order_type = ANY($3::text[])
       AND o.payment_status IN ('pending', 'expired')
       AND o.status IN ('pending', 'expired')
     RETURNING o.*, prev.prev_status`,
    [orderId, amount, orderTypes]
  );
  const order = r.rows[0];
  if (!order) return { rows: [] };

  const revived = order.prev_status === "expired";
  if (revived) {
    console.log(`♻️ Expired order qayta tiklandi (SMS vaqti taymer ichida): #${order.id}`);
    // Expire paytida promokod ishlatilishi qaytarilgan edi — endi qayta hisoblaymiz
    if (order.applied_promocode) {
      await pool
        .query(`UPDATE promocodes SET used_count = used_count + 1 WHERE code = $1`, [
          order.applied_promocode,
        ])
        .catch((e) => console.error("⚠️ Promokod used_count tiklashda xato:", e.message));
    }
  }
  delete order.prev_status;
  return { rows: [order], revived };
}
