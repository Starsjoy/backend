/**
 * AI Warning: support agenti tekshirgan, lekin summa biroz farq qilgani uchun avtomatik o'tmagan to'lovlar.
 *
 * Agent faqat RO'YXATGA QO'SHADI (POST /api/agent/ai-warning, AGENT_API_KEY). Hech narsa tasdiqlanmaydi,
 * yuborish faqat admin panelda egasi tomonidan. Backend agentga ishonmaydi va o'zi qayta tekshiradi:
 *  - buyurtma bor va hali to'lanmagan (expired/pending), oxirgi 3 kunda ochilgan;
 *  - SMS daftarda bor (karta bizniki), hech qaysi buyurtmaga bog'lanmagan;
 *  - summa farqi 0 < |farq| <= 3%;
 *  - SMS vaqti buyurtma ochilganidan keyin 30 daqiqa ichida;
 *  - shu summa shu paytda to'rtala loyihaning birortasida ham boshqa to'langan buyurtmaga ketmagan.
 * Buyurtma to'langach (egasi yuborgach) ro'yxatdan o'zi yo'qoladi.
 */
import crypto from "crypto";
import fs from "fs";
import pg from "pg";

export const MAX_DIFF_RATIO = 0.03;
const WINDOW_MIN = 30;

function poolFromEnvFile(file) {
  const m = fs.readFileSync(file, "utf8").match(/^DATABASE_URL=(.*)$/m);
  if (!m) throw new Error(`${file} da DATABASE_URL yo'q`);
  const p = new pg.Pool({ connectionString: m[1].trim().replace(/^["']|["']$/g, ""), max: 1, idleTimeoutMillis: 30000 });
  p.on("error", (e) => console.error("⚠️ AI warning pool:", e.message));
  return p;
}

/**
 * @param {object} o
 * @param {string} o.ledgerEnvFile  — SMS daftari bazasi (.env); bo'sh bo'lsa o'z bazasi
 * @param {string[]} o.peerEnvFiles — boshqa loyihalar bazalari (summa ularga ketmaganini tekshirish)
 */
export function registerAiWarning(app, { pool, adminAuth, ledgerEnvFile = "", peerEnvFiles = [] }) {
  const ledger = ledgerEnvFile ? poolFromEnvFile(ledgerEnvFile) : pool;
  const peers = peerEnvFiles.filter((f) => fs.existsSync(f)).map(poolFromEnvFile);

  const ready = pool
    .query(
      `CREATE TABLE IF NOT EXISTS ai_payment_warnings (
        id SERIAL PRIMARY KEY,
        order_id BIGINT NOT NULL UNIQUE,
        sms_id BIGINT NOT NULL UNIQUE,
        sms_amount BIGINT NOT NULL,
        order_summ BIGINT NOT NULL,
        card_last4 TEXT,
        sms_at TIMESTAMPTZ,
        note TEXT,
        status TEXT NOT NULL DEFAULT 'open',   -- open | dismissed
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )`
    )
    // Balans usuli: SMS kelmagan, to'lov karta qoldig'i farqi bilan isbotlangan (sms_id bo'sh)
    .then(() => pool.query(`ALTER TABLE ai_payment_warnings ALTER COLUMN sms_id DROP NOT NULL`))
    .then(() => pool.query(`ALTER TABLE ai_payment_warnings ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'sms'`))
    .catch((e) => console.error("❌ ai_payment_warnings jadval:", e.message));

  function keyOk(req) {
    const key = process.env.AGENT_API_KEY || "";
    const got = String(req.headers["x-agent-key"] || "");
    return key && got.length === key.length && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(key));
  }

  /** Shu summa shu vaqt atrofida biror loyihada to'langan buyurtmaga ketganmi */
  async function amountTaken(amount, smsAt) {
    const sql = `SELECT 1 FROM orders WHERE payment_status = 'paid' AND summ = $1
                 AND created_at BETWEEN $2::timestamptz - INTERVAL '15 minutes' AND $2::timestamptz + INTERVAL '1 minute' LIMIT 1`;
    for (const db of [pool, ...peers]) {
      const r = await db.query(sql, [amount, smsAt]);
      if (r.rows.length) return true;
    }
    return false;
  }

  /** Shu SMS boshqa loyihaning AI Warning ro'yxatida ishlatilganmi (bitta to'lov ikki mijozga ketmasin) */
  async function smsUsedElsewhere(smsId) {
    for (const db of peers) {
      try {
        const r = await db.query(`SELECT order_id FROM ai_payment_warnings WHERE sms_id = $1 LIMIT 1`, [smsId]);
        if (r.rows.length) return r.rows[0].order_id;
      } catch {
        /* peer'da jadval bo'lmasligi mumkin */
      }
    }
    return null;
  }

  /** SMS'siz, karta qoldig'i farqi bilan isbotlangan to'lov. Farq 0 ham bo'lishi mumkin (sabab: SMS kelmagan). */
  async function addByBalance(o, bal, note, res) {
    const card = String(bal.card || "").replace(/\D/g, "").slice(-4);
    const amount = Math.round(Number(bal.amount));
    const at = new Date(bal.paid_at);
    const proof = String(bal.proof || "").slice(0, 400);
    if (!/^\d{4}$/.test(card)) throw new Error("balance.card noto'g'ri");
    if (!Number.isFinite(amount) || amount <= 0) throw new Error("balance.amount noto'g'ri");
    if (Number.isNaN(at.getTime())) throw new Error("balance.paid_at noto'g'ri");
    if (!proof) throw new Error("balance.proof (qoldiqlar hisobi) kerak");
    const known = await ledger.query(`SELECT 1 FROM sms_payments WHERE card_last4 = $1 LIMIT 1`, [card]);
    if (!known.rows.length) throw new Error("karta bizniki emas");
    const summ = Number(o.summ);
    const diff = amount - summ;
    if (diff < 0 && -diff > summ * MAX_DIFF_RATIO) throw new Error(`${-diff} so'm kam to'langan, 3% dan ko'p`); // ortiqcha to'lov istalgan miqdorda
    const minutes = (at.getTime() - new Date(o.created_at).getTime()) / 60000;
    if (minutes < -1 || minutes > WINDOW_MIN) throw new Error(`to'lov vaqti buyurtmaga mos emas (${Math.round(minutes)} daq)`);
    const sms = await ledger.query(
      `SELECT id FROM sms_payments WHERE card_last4 = $1 AND amount = $2
         AND COALESCE(sms_time, received_at) BETWEEN $3::timestamptz - INTERVAL '10 minutes' AND $3::timestamptz + INTERVAL '10 minutes' LIMIT 1`,
      [card, amount, at]
    );
    if (sms.rows.length) throw new Error(`bu summaga SMS bor (#${sms.rows[0].id}), sms_id bilan qo'shing`);
    if (await amountTaken(amount, at)) throw new Error("bu summa shu paytda boshqa to'langan buyurtmaga ketgan");
    for (const db of [pool, ...peers]) {
      try {
        const dup = await db.query(
          `SELECT order_id FROM ai_payment_warnings WHERE source = 'balance' AND card_last4 = $1 AND sms_amount = $2
             AND sms_at BETWEEN $3::timestamptz - INTERVAL '10 minutes' AND $3::timestamptz + INTERVAL '10 minutes' LIMIT 1`,
          [card, amount, at]
        );
        if (dup.rows.length) throw new Error(`shu to'lov balans bilan #${dup.rows[0].order_id} ga allaqachon qo'shilgan`);
      } catch (e) {
        if (String(e.message).includes("allaqachon")) throw e;
      }
    }
    const ins = await pool.query(
      `INSERT INTO ai_payment_warnings (order_id, sms_id, sms_amount, order_summ, card_last4, sms_at, note, source)
       VALUES ($1, NULL, $2, $3, $4, $5, $6, 'balance') ON CONFLICT DO NOTHING RETURNING id`,
      [o.id, amount, summ, card, at, [proof, note].filter(Boolean).join(" | ")]
    );
    if (!ins.rows.length) throw new Error("bu buyurtma ro'yxatda allaqachon bor");
    return res.json({ ok: true, id: ins.rows[0].id, diff, source: "balance" });
  }

  app.post("/api/agent/ai-warning", async (req, res) => {
    if (!keyOk(req)) return res.status(404).json({ error: "Not found" });
    try {
      await ready;
      const orderId = Number(req.body?.order_id);
      const smsId = Number(req.body?.sms_id);
      const bal = req.body?.balance || null; // { card, amount, paid_at, proof }
      const note = String(req.body?.note || "").slice(0, 300);
      if (!Number.isInteger(orderId) || orderId <= 0) throw new Error("order_id noto'g'ri");
      if (!bal && (!Number.isInteger(smsId) || smsId <= 0)) throw new Error("sms_id noto'g'ri");

      const o = (
        await pool.query(
          `SELECT id, summ, payment_status, created_at, owner_user_id, order_type, type_amount FROM orders
            WHERE id = $1 AND created_at > NOW() - INTERVAL '3 days'`,
          [orderId]
        )
      ).rows[0];
      if (!o) throw new Error("buyurtma topilmadi (yoki 3 kundan eski)");
      if (o.payment_status === "paid") throw new Error("buyurtma allaqachon to'langan");
      // Mijoz shu mahsulotni keyin boshqa buyurtma bilan olgan bo'lsa — qo'shilmaydi (ikki marta yuborilmasin)
      const got = await pool.query(
        `SELECT id FROM orders WHERE owner_user_id::text = $1::text AND id <> $2 AND status IN ('completed', 'delivered')
           AND order_type = $3 AND type_amount::text = $4::text
           AND created_at BETWEEN $5::timestamptz - INTERVAL '1 hour' AND $5::timestamptz + INTERVAL '1 hour' LIMIT 1`,
        [o.owner_user_id, o.id, o.order_type, String(o.type_amount), o.created_at]
      );
      if (got.rows.length) throw new Error(`mijozga shu mahsulot #${got.rows[0].id} bilan yetkazilgan`);

      if (bal) return await addByBalance(o, bal, note, res);

      const s = (
        await ledger.query(
          `SELECT id, amount, card_last4, order_id, COALESCE(sms_time, received_at) AS at FROM sms_payments WHERE id = $1`,
          [smsId]
        )
      ).rows[0];
      if (!s) throw new Error("SMS daftarda yo'q");

      // Ko'chirish: to'lov shu mijozning yetkazilmagan eski buyurtmasida turibdi (masalan username noto'g'ri edi),
      // mijoz to'g'ri ma'lumot bilan xuddi shu mahsulotga yangi buyurtma ochgan
      const old = (
        await pool.query(
          `SELECT id, summ, created_at FROM orders WHERE owner_user_id::text = $1::text AND id <> $2
             AND payment_status = 'paid' AND status NOT IN ('completed', 'delivered')
             AND order_type = $3 AND type_amount::text = $4::text
             AND created_at BETWEEN $5::timestamptz - INTERVAL '6 hours' AND $5::timestamptz
             AND (id = $6 OR ($6 IS NULL AND summ = $7))
           ORDER BY id DESC LIMIT 1`,
          [o.owner_user_id, o.id, o.order_type, String(o.type_amount), o.created_at, s.order_id ? Number(s.order_id) : null, Number(s.amount)]
        )
      ).rows[0];
      if (s.order_id && !old) throw new Error("SMS boshqa buyurtmaga bog'langan");
      const elsewhere = await smsUsedElsewhere(smsId);
      if (elsewhere) throw new Error(`bu SMS boshqa loyihada #${elsewhere} buyurtmaga ishlatilgan`);

      const summ = Number(o.summ);
      const amount = Number(s.amount);
      const diff = amount - summ;
      // Aniq teng summa ham qabul qilinadi (masalan mijoz yangi buyurtma ochib, eskisi eskirgan)
      if (diff < 0 && -diff > summ * MAX_DIFF_RATIO) throw new Error(`${-diff} so'm kam to'langan, 3% dan ko'p`); // ortiqcha to'lov istalgan miqdorda

      const at = new Date(s.at);
      const base = old ? new Date(old.created_at) : new Date(o.created_at); // ko'chirishda vaqt eski buyurtmaga nisbatan
      const minutes = (at.getTime() - base.getTime()) / 60000;
      if (minutes < -1 || minutes > WINDOW_MIN) throw new Error(`SMS vaqti buyurtmaga mos emas (${Math.round(minutes)} daq)`);

      if (!old && (await amountTaken(amount, at))) throw new Error("bu summa shu paytda boshqa to'langan buyurtmaga ketgan");

      const ins = await pool.query(
        `INSERT INTO ai_payment_warnings (order_id, sms_id, sms_amount, order_summ, card_last4, sms_at, note, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT DO NOTHING RETURNING id`,
        [orderId, smsId, amount, summ, s.card_last4, at,
         [old ? `↪️ eski #${old.id} to'lovi (u yetkazilmagan)` : "", note].filter(Boolean).join(" | ") || null,
         old ? "transfer" : "sms"]
      );
      if (!ins.rows.length) throw new Error("bu buyurtma yoki SMS ro'yxatda allaqachon bor");
      res.json({ ok: true, id: ins.rows[0].id, diff, transfer_from: old ? old.id : null });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // Agent: mijoz keyin username/sovg'a/mahsulotni almashtirsa — qatorni ro'yxatdan oladi (buyurtmaga tegmaydi)
  app.post("/api/agent/ai-warning/remove", async (req, res) => {
    if (!keyOk(req)) return res.status(404).json({ error: "Not found" });
    try {
      await ready;
      const orderId = Number(req.body?.order_id);
      if (!Number.isInteger(orderId) || orderId <= 0) throw new Error("order_id noto'g'ri");
      const reason = String(req.body?.reason || "").slice(0, 200);
      const r = await pool.query(
        `UPDATE ai_payment_warnings SET status = 'dismissed', note = COALESCE(note, '') || $2
          WHERE order_id = $1 AND status = 'open' RETURNING id`,
        [orderId, reason ? ` | olib tashlandi: ${reason}` : " | olib tashlandi"]
      );
      if (!r.rows.length) throw new Error("bu buyurtma ro'yxatda yo'q");
      res.json({ ok: true, id: r.rows[0].id });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.get("/api/admin/ai-warnings", adminAuth, async (req, res) => {
    try {
      await ready;
      const r = await pool.query(
        `SELECT w.id, w.order_id, w.sms_id, w.sms_amount, w.order_summ, w.sms_amount - w.order_summ AS diff,
                w.card_last4, w.sms_at, w.note, w.source, w.created_at AS added_at,
                o.order_type, o.type_amount, o.recipient_username, o.payment_status, o.status, o.created_at,
                o.owner_user_id, u.username AS owner_username
           FROM ai_payment_warnings w
           JOIN orders o ON o.id = w.order_id
           LEFT JOIN users u ON u.user_id::text = o.owner_user_id::text
          WHERE w.status = 'open' AND o.payment_status <> 'paid'
          ORDER BY o.created_at ASC`
      );
      res.json({ success: true, items: r.rows });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // Yuborish tugmasi uchun: buyurtmaning haqiqiy holati (to'langan bo'lishi yetkazilgani degani emas)
  app.get("/api/admin/ai-warnings/order/:orderId", adminAuth, async (req, res) => {
    try {
      const r = await pool.query(`SELECT payment_status, status FROM orders WHERE id = $1`, [Number(req.params.orderId)]);
      if (!r.rows.length) return res.status(404).json({ success: false, error: "topilmadi" });
      const st = r.rows[0].status;
      const state = ["completed", "delivered"].includes(st) ? "sent" : ["failed", "error", "expired", "cancelled"].includes(st) && r.rows[0].payment_status === "paid" ? "failed" : "pending";
      res.json({ success: true, state, status: st, payment_status: r.rows[0].payment_status });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  app.post("/api/admin/ai-warnings/:id/dismiss", adminAuth, async (req, res) => {
    try {
      const r = await pool.query(`UPDATE ai_payment_warnings SET status = 'dismissed' WHERE id = $1 RETURNING id`, [
        Number(req.params.id),
      ]);
      res.json({ success: Boolean(r.rows.length) });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
}
