/**
 * Kutilayotgan Premium: mijoz to'lagan, lekin ko'rsatgan username'da Premium hali aktiv.
 * Mijoz Premium tugashini kutishni tanlasa — eslatma yoziladi, tugash kuni 09:00 (Toshkent) da
 * egasiga bot orqali xabar boradi. Hech narsa avtomatik yuborilmaydi: faqat eslatma.
 *
 * Kim yoza oladi: admin (admin panel) va support agenti (faqat YARATISH, AGENT_API_KEY bilan).
 */
import crypto from "crypto";

const OWNER_ID = "6418750920"; // @shavkatov_ff — eslatmalar faqat shu akkauntga
const TZ_OFFSET_MS = 5 * 3600 * 1000;
const NOTIFY_HOUR = 9;
const STATUSES = ["waiting", "done", "cancelled"];

function tashkentToday() {
  return new Date(Date.now() + TZ_OFFSET_MS).toISOString().slice(0, 10);
}
function tashkentHour() {
  return new Date(Date.now() + TZ_OFFSET_MS).getUTCHours();
}
const fmt = (n) => Number(n || 0).toLocaleString("en-US");
const cleanUser = (u) => String(u || "").replace(/^@/, "").trim().slice(0, 64);

function parseBody(b, partial = false) {
  const out = {};
  if (b.order_id !== undefined && b.order_id !== null && b.order_id !== "") {
    const n = Number(b.order_id);
    if (!Number.isInteger(n) || n <= 0) throw new Error("order_id noto'g'ri");
    out.order_id = n;
  }
  if (b.payer_user_id !== undefined && b.payer_user_id !== null && b.payer_user_id !== "") {
    if (!/^\d{3,20}$/.test(String(b.payer_user_id))) throw new Error("payer_user_id noto'g'ri");
    out.payer_user_id = String(b.payer_user_id);
  }
  if (b.payer_username !== undefined) out.payer_username = cleanUser(b.payer_username) || null;
  if (b.recipient_username !== undefined) {
    out.recipient_username = cleanUser(b.recipient_username);
    if (!/^\w{3,64}$/.test(out.recipient_username)) throw new Error("recipient_username noto'g'ri");
  } else if (!partial) throw new Error("recipient_username kerak");
  if (b.months !== undefined && b.months !== null && b.months !== "") {
    const m = Number(b.months);
    if (![3, 6, 12].includes(m)) throw new Error("months 3/6/12 bo'lishi kerak");
    out.months = m;
  }
  if (b.amount !== undefined && b.amount !== null && b.amount !== "") {
    const a = Number(b.amount);
    if (!Number.isFinite(a) || a < 0 || a > 100_000_000) throw new Error("amount noto'g'ri");
    out.amount = Math.round(a);
  }
  if (b.due_date !== undefined) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(b.due_date)) || isNaN(Date.parse(b.due_date))) throw new Error("due_date YYYY-MM-DD");
    out.due_date = String(b.due_date);
    if (out.due_date < tashkentToday()) throw new Error("due_date o'tib ketgan sana, faqat bugun yoki keyingi kunlar");
  } else if (!partial) throw new Error("due_date kerak");
  if (b.note !== undefined) out.note = String(b.note || "").slice(0, 500);
  if (b.status !== undefined) {
    if (!STATUSES.includes(b.status)) throw new Error("status noto'g'ri");
    out.status = b.status;
  }
  return out;
}

export function registerPremiumWait(app, { pool, adminAuth, projectName = "StarsJoy", botName = "" }) {
  let ready = null;
  const ensure = () =>
    (ready ||= pool
      .query(
        `CREATE TABLE IF NOT EXISTS premium_waitlist (
           id SERIAL PRIMARY KEY,
           order_id BIGINT,
           payer_user_id TEXT,
           payer_username TEXT,
           recipient_username TEXT NOT NULL,
           months INT,
           amount BIGINT,
           due_date DATE NOT NULL,
           status TEXT NOT NULL DEFAULT 'waiting',
           note TEXT,
           created_by TEXT NOT NULL DEFAULT 'admin',
           created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
           updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
           notified_at TIMESTAMPTZ
         )`
      )
      .then(() => pool.query(`CREATE INDEX IF NOT EXISTS premium_waitlist_due_idx ON premium_waitlist (status, due_date)`))
      .catch((e) => {
        ready = null;
        throw e;
      }));

  async function insert(data, createdBy) {
    await ensure();
    const r = await pool.query(
      `INSERT INTO premium_waitlist (order_id, payer_user_id, payer_username, recipient_username, months, amount, due_date, note, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [data.order_id ?? null, data.payer_user_id ?? null, data.payer_username ?? null, data.recipient_username,
       data.months ?? null, data.amount ?? null, data.due_date, data.note ?? null, createdBy]
    );
    return r.rows[0];
  }

  // ---------- admin ----------
  app.get("/api/admin/premium-wait", adminAuth, async (req, res) => {
    try {
      await ensure();
      const status = STATUSES.includes(req.query.status) ? req.query.status : null;
      const r = await pool.query(
        `SELECT id, order_id, payer_user_id, payer_username, recipient_username, months, amount,
                to_char(due_date,'YYYY-MM-DD') AS due_date, status, note, created_by, created_at, notified_at FROM premium_waitlist
         WHERE ($1::text IS NULL OR status = $1) ORDER BY (status = 'waiting') DESC, due_date ASC, id DESC LIMIT 300`,
        [status]
      );
      res.json({ items: r.rows, today: tashkentToday() });
    } catch (e) {
      console.error("❌ premium-wait list:", e.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.post("/api/admin/premium-wait", adminAuth, async (req, res) => {
    try {
      const row = await insert(parseBody(req.body || {}), "admin");
      res.json({ ok: true, item: row });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.patch("/api/admin/premium-wait/:id", adminAuth, async (req, res) => {
    try {
      await ensure();
      const data = parseBody(req.body || {}, true);
      const keys = Object.keys(data);
      if (!keys.length) return res.status(400).json({ error: "O'zgarish yo'q" });
      const sets = keys.map((k, i) => `${k} = $${i + 2}`);
      if (data.due_date) sets.push("notified_at = NULL"); // sana o'zgarsa — yangi sanada qayta eslatiladi
      const r = await pool.query(
        `UPDATE premium_waitlist SET ${sets.join(", ")}, updated_at = NOW() WHERE id = $1 RETURNING *`,
        [Number(req.params.id), ...keys.map((k) => data[k])]
      );
      if (!r.rows.length) return res.status(404).json({ error: "Topilmadi" });
      res.json({ ok: true, item: r.rows[0] });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // ---------- support agenti: faqat yaratish ----------
  app.post("/api/agent/premium-wait", async (req, res) => {
    const key = process.env.AGENT_API_KEY || "";
    const got = String(req.headers["x-agent-key"] || "");
    if (!key || got.length !== key.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(key))) {
      return res.status(404).json({ error: "Not found" });
    }
    try {
      const data = parseBody(req.body || {});
      delete data.status;
      const row = await insert(data, "agent");
      res.json({ ok: true, id: row.id });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // ---------- eslatma: tugash kuni 09:00 dan keyin, bir marta ----------
  async function sendOwner(text) {
    const token = process.env.BOT_TOKEN;
    if (!token) return false;
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: OWNER_ID, text, disable_web_page_preview: true }),
      signal: AbortSignal.timeout(15000),
    });
    const d = await r.json().catch(() => ({}));
    if (!d.ok) throw new Error(d.description || `HTTP ${r.status}`);
    return true;
  }

  async function tick() {
    if (tashkentHour() < NOTIFY_HOUR) return;
    await ensure();
    const due = await pool.query(
      `SELECT *, to_char(due_date,'YYYY-MM-DD') AS due_s FROM premium_waitlist WHERE status = 'waiting' AND notified_at IS NULL AND due_date <= $1::date ORDER BY id LIMIT 20`,
      [tashkentToday()]
    );
    for (const w of due.rows) {
      const lines = [
        `⏰ ${projectName}: kutilayotgan Premium vaqti keldi`,
        ``,
        `@${w.recipient_username} Premium'i ${w.due_s} da tugashi kerak edi.`,
        w.months ? `Ulash kerak: ${w.months} oy` : null,
        w.order_id ? `Buyurtma: #${w.order_id}` : null,
        w.amount ? `To'lagan: ${fmt(w.amount)} so'm` : null,
        w.payer_username || w.payer_user_id
          ? `Mijoz: ${w.payer_username ? "@" + w.payer_username : ""} ${w.payer_user_id ? "(ID " + w.payer_user_id + ")" : ""}`.trim()
          : null,
        w.note ? `Izoh: ${w.note}` : null,
        ``,
        `Ulagach admin paneldagi "Kutilayotgan Premium" ro'yxatida Bajarildi deb belgilang.`,
      ].filter((x) => x !== null);
      try {
        await sendOwner(lines.join("\n"));
        await pool.query(`UPDATE premium_waitlist SET notified_at = NOW() WHERE id = $1`, [w.id]);
      } catch (e) {
        console.error(`❌ Premium kutish eslatmasi #${w.id}:`, e.message);
      }
    }
  }

  setInterval(() => tick().catch((e) => console.error("❌ premium-wait tick:", e.message)), 10 * 60 * 1000);
  setTimeout(() => tick().catch((e) => console.error("❌ premium-wait tick:", e.message)), 30 * 1000);
  console.log(`⏳ Kutilayotgan Premium eslatmalari tayyor (${projectName}${botName ? ", " + botName : ""})`);
}
