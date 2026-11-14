/**
 * Bot ↔ egasi relay.
 *
 * 1) Mijoz botga oddiy xabar yozsa (buyruq emas) — xabar egasiga (@shavkatov_ff) bot chatida keladi.
 *    Egasi o'sha xabarga reply qilsa — javob bot orqali o'sha mijozga ketadi.
 *    Mijozga kuniga bir marta "xabaringiz qabul qilindi" javobi boradi.
 * 2) Support agenti mijozga bot orqali yozmoqchi bo'lsa — faqat QORALAMA yaratadi
 *    (POST /api/agent/bot-draft). Mijozga xabar faqat egasi ✅ tugmasini bosgandan keyin ketadi.
 */
import crypto from "crypto";

const OWNER_ID = 6418750920; // @shavkatov_ff — relay va tasdiq faqat shu akkaunt
const IN_LIMIT_PER_DAY = 20; // bitta mijozdan sutkada egasiga boradigan xabarlar
const DRAFT_LIMIT_PER_DAY = 80;
const RELAY_TYPES = ["text", "photo", "voice", "video", "document", "audio", "video_note", "sticker", "animation"];

const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
const tashkentTime = () =>
  new Date(Date.now() + 5 * 3600 * 1000).toISOString().slice(11, 16);

export async function ensureBotRelayTables(pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS bot_relay_messages (
    id SERIAL PRIMARY KEY,
    owner_msg_id BIGINT,
    user_id BIGINT NOT NULL,
    direction TEXT NOT NULL,          -- in | out | ack
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS bot_relay_owner_msg_idx ON bot_relay_messages (owner_msg_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS bot_relay_user_idx ON bot_relay_messages (user_id, created_at)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS bot_drafts (
    id SERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    text TEXT NOT NULL,
    note TEXT,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | sending | sent | cancelled | failed
    owner_msg_id BIGINT,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ
  )`);
}

function userHeader(from, botName) {
  const name = [from.first_name, from.last_name].filter(Boolean).join(" ") || "-";
  const un = from.username ? `@${from.username}` : "username yo'q";
  return `📩 <b>${esc(botName)}</b> ga mijoz yozdi\n${esc(name)} | ${esc(un)} | ID <code>${from.id}</code>`;
}

function ackText(lang) {
  return String(lang || "").startsWith("ru")
    ? "Ваше сообщение получено, скоро ответим."
    : "Xabaringiz qabul qilindi, tez orada javob beramiz.";
}

/**
 * token.js da broadcast/boshqa admin handler'laridan OLDIN chaqiriladi.
 * isBusy(userId) — admin broadcast kabi boshqa jarayonda bo'lsa true (relay aralashmaydi).
 */
export function registerBotRelay(bot, { pool, botName, isBusy = () => false, adminIds = [] }) {
  ensureBotRelayTables(pool).catch((e) => console.error("❌ bot relay jadval:", e.message));

  const record = (ownerMsgId, userId, direction) =>
    pool
      .query("INSERT INTO bot_relay_messages (owner_msg_id, user_id, direction) VALUES ($1, $2, $3)", [
        ownerMsgId,
        userId,
        direction,
      ])
      .catch((e) => console.error("❌ bot relay yozuv:", e.message));

  bot.on("message", async (ctx, next) => {
    const msg = ctx.message;
    const from = ctx.from;
    if (!from || ctx.chat?.type !== "private" || from.is_bot) return next();
    if (isBusy(from.id)) return next();
    const text = msg.text || "";

    // ---- Egasi: relay xabariga reply → mijozga ----
    if (from.id === OWNER_ID) {
      if (text.trim().split("@")[0] === "/hammasi") {
        await sendAllDrafts(ctx);
        return;
      }
      const rt = msg.reply_to_message;
      if (!rt || text.startsWith("/")) return next();
      const r = await pool
        .query("SELECT user_id FROM bot_relay_messages WHERE owner_msg_id = $1 AND direction = 'in' ORDER BY id DESC LIMIT 1", [
          rt.message_id,
        ])
        .catch(() => ({ rows: [] }));
      const userId = r.rows[0]?.user_id;
      if (!userId) return next();
      try {
        await ctx.telegram.copyMessage(Number(userId), ctx.chat.id, msg.message_id);
        record(msg.message_id, userId, "out");
        await ctx.reply("✅ Yuborildi", { reply_to_message_id: msg.message_id }).catch(() => {});
      } catch (e) {
        const blocked = e?.response?.error_code === 403;
        await ctx
          .reply(blocked ? "❌ Mijoz botni bloklagan, xabar yetmadi" : `❌ Yuborilmadi: ${e.message}`, {
            reply_to_message_id: msg.message_id,
          })
          .catch(() => {});
      }
      return;
    }

    // ---- Mijoz: buyruq bo'lmagan xabar → egasiga ----
    // Adminlar ham relay qilinadi (masalan @StarsjoySupport mijozdek javob yozsa); broadcast kabi jarayon isBusy orqali o'tadi
    if (text.startsWith("/")) return next();
    if (!RELAY_TYPES.some((t) => msg[t])) return next();

    try {
      const c = await pool.query(
        `SELECT COUNT(*) FILTER (WHERE direction = 'in')::int AS n_in,
                COUNT(*) FILTER (WHERE direction = 'ack')::int AS n_ack
           FROM bot_relay_messages WHERE user_id = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
        [from.id]
      );
      const { n_in, n_ack } = c.rows[0] || { n_in: 0, n_ack: 0 };
      if (n_in < IN_LIMIT_PER_DAY) {
        const header = userHeader(from, botName);
        const hint = "\n<i>Javob berish uchun shu xabarga reply qiling</i>";
        if (msg.text) {
          const m = await ctx.telegram.sendMessage(OWNER_ID, `${header}\n\n${esc(msg.text)}${hint}`, {
            parse_mode: "HTML",
            disable_web_page_preview: true,
          });
          await record(m.message_id, from.id, "in");
        } else {
          const h = await ctx.telegram.sendMessage(OWNER_ID, header + hint, { parse_mode: "HTML" });
          await record(h.message_id, from.id, "in");
          const cp = await ctx.telegram.copyMessage(OWNER_ID, ctx.chat.id, msg.message_id, {
            reply_to_message_id: h.message_id,
          });
          await record(cp.message_id, from.id, "in");
        }
      }
      // Avtomatik "qabul qilindi" javobi o'chirilgan (egasi qarori, 2026-11-11)
    } catch (e) {
      console.error("❌ bot relay (mijoz → egasi):", e.message);
    }
    return next();
  });

  // ---- Agent qoralamasi: faqat egasi tasdiqlaydi ----
  /** /hammasi — kutib turgan barcha qoralamalarni (oxirgi 24 soat) bittada yuboradi */
  async function sendAllDrafts(ctx) {
    const list = await pool.query(
      "SELECT id FROM bot_drafts WHERE status = 'pending' AND created_at > NOW() - INTERVAL '24 hours' ORDER BY id"
    );
    if (!list.rows.length) return ctx.reply("Kutib turgan qoralama yo'q ✅").catch(() => {});
    await ctx.reply(`⏳ ${list.rows.length} ta qoralama yuborilyapti…`).catch(() => {});
    let sent = 0, failed = 0;
    for (const { id } of list.rows) {
      const r = await pool.query(
        "UPDATE bot_drafts SET status = 'sending', decided_at = NOW() WHERE id = $1 AND status = 'pending' RETURNING user_id, text, owner_msg_id",
        [id]
      );
      if (!r.rows.length) continue;
      const { user_id, text, owner_msg_id } = r.rows[0];
      let mark;
      try {
        await ctx.telegram.sendMessage(Number(user_id), text, { disable_web_page_preview: true });
        await pool.query("UPDATE bot_drafts SET status = 'sent' WHERE id = $1", [id]);
        record(null, user_id, "out");
        sent++;
        mark = `✅ Yuborildi ${tashkentTime()}`;
      } catch (e) {
        const err = e?.response?.error_code === 403 ? "mijoz botni bloklagan yoki botni hech ochmagan" : e.message;
        await pool.query("UPDATE bot_drafts SET status = 'failed', error = $2 WHERE id = $1", [id, String(err).slice(0, 300)]);
        failed++;
        mark = `❌ Yuborilmadi: ${err}`;
      }
      if (owner_msg_id) {
        await ctx.telegram.editMessageReplyMarkup(OWNER_ID, Number(owner_msg_id), undefined, { inline_keyboard: [] }).catch(() => {});
        await ctx.telegram.sendMessage(OWNER_ID, mark, { reply_parameters: { message_id: Number(owner_msg_id), allow_sending_without_reply: true } }).catch(() => {});
      }
      await new Promise((res) => setTimeout(res, 350)); // Telegram limitiga tushmaslik uchun
    }
    await ctx.reply(`✅ Tayyor: ${sent} ta yuborildi` + (failed ? `, ${failed} ta yuborilmadi (botni bloklagan)` : "")).catch(() => {});
  }

  bot.action(/^bdraft_(ok|no)_(\d+)$/, async (ctx) => {
    if (ctx.from?.id !== OWNER_ID) {
      return ctx.answerCbQuery("❌ Ruxsat yo'q", { show_alert: true }).catch(() => {});
    }
    const [, act, idStr] = ctx.match;
    const id = Number(idStr);
    const orig = ctx.callbackQuery?.message?.text || "";
    if (act === "no") {
      const r = await pool.query(
        "UPDATE bot_drafts SET status = 'cancelled', decided_at = NOW() WHERE id = $1 AND status = 'pending' RETURNING id",
        [id]
      );
      await ctx.answerCbQuery(r.rows.length ? "Bekor qilindi" : "Allaqachon ko'rib chiqilgan").catch(() => {});
      if (r.rows.length) await ctx.editMessageText(`${orig}\n\n❌ Bekor qilindi ${tashkentTime()}`).catch(() => {});
      return;
    }
    const r = await pool.query(
      "UPDATE bot_drafts SET status = 'sending', decided_at = NOW() WHERE id = $1 AND status = 'pending' RETURNING user_id, text",
      [id]
    );
    if (!r.rows.length) return ctx.answerCbQuery("Allaqachon ko'rib chiqilgan", { show_alert: true }).catch(() => {});
    const { user_id, text } = r.rows[0];
    try {
      await ctx.telegram.sendMessage(Number(user_id), text, { disable_web_page_preview: true });
      await pool.query("UPDATE bot_drafts SET status = 'sent' WHERE id = $1", [id]);
      record(null, user_id, "out");
      await ctx.answerCbQuery("✅ Yuborildi").catch(() => {});
      await ctx.editMessageText(`${orig}\n\n✅ Yuborildi ${tashkentTime()}`).catch(() => {});
    } catch (e) {
      const err = e?.response?.error_code === 403 ? "mijoz botni bloklagan yoki botni hech ochmagan" : e.message;
      await pool.query("UPDATE bot_drafts SET status = 'failed', error = $2 WHERE id = $1", [id, String(err).slice(0, 300)]);
      await ctx.answerCbQuery("❌ Yuborilmadi", { show_alert: true }).catch(() => {});
      await ctx.editMessageText(`${orig}\n\n❌ Yuborilmadi: ${err}`).catch(() => {});
    }
  });
}

/** server.js: support agenti uchun qoralama endpoint (AGENT_API_KEY). Mijozga hech narsa yubormaydi. */
export function registerBotDraftApi(app, { pool, botName }) {
  ensureBotRelayTables(pool).catch((e) => console.error("❌ bot draft jadval:", e.message));

  app.post("/api/agent/bot-draft", async (req, res) => {
    const key = process.env.AGENT_API_KEY || "";
    const got = String(req.headers["x-agent-key"] || "");
    if (!key || got.length !== key.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(key))) {
      return res.status(404).json({ error: "Not found" });
    }
    try {
      const b = req.body || {};
      const userId = String(b.user_id || "").trim();
      const text = String(b.text || "").trim();
      const note = String(b.note || "").trim().slice(0, 300);
      if (!/^\d{3,20}$/.test(userId)) throw new Error("user_id noto'g'ri");
      if (!text || text.length > 3000) throw new Error("text 1..3000 belgi bo'lishi kerak");

      const cnt = await pool.query("SELECT COUNT(*)::int AS n FROM bot_drafts WHERE created_at > NOW() - INTERVAL '24 hours'");
      if (cnt.rows[0].n >= DRAFT_LIMIT_PER_DAY) throw new Error("sutkalik qoralama limiti tugadi");

      const u = await pool.query("SELECT username, name FROM users WHERE user_id = $1 LIMIT 1", [userId]);
      if (!u.rows.length) throw new Error("bu ID bazada yo'q (botga kirmagan)");
      const recent = await pool.query(
        "SELECT id FROM bot_drafts WHERE user_id = $1 AND status IN ('pending', 'sending', 'sent') AND created_at > NOW() - INTERVAL '12 hours' LIMIT 1",
        [userId]
      );
      if (recent.rows.length) throw new Error(`bu mijozga 12 soat ichida qoralama bor (#${recent.rows[0].id}), takror yuborilmaydi`);
      const who = `${u.rows[0].name || "-"} | ${u.rows[0].username ? "@" + u.rows[0].username : "username yo'q"} | ID ${userId}`;

      const ins = await pool.query("INSERT INTO bot_drafts (user_id, text, note) VALUES ($1, $2, $3) RETURNING id", [
        userId,
        text,
        note || null,
      ]);
      const id = ins.rows[0].id;
      const body =
        `🤖 Qoralama #${id}: ${botName} orqali yuborilsinmi?\n→ ${who}\n\n${text}` + (note ? `\n\nIzoh: ${note}` : "");

      const token = process.env.BOT_TOKEN;
      const payload = JSON.stringify({
        chat_id: OWNER_ID,
        text: body,
        disable_web_page_preview: true,
        reply_markup: {
          inline_keyboard: [
            [
              { text: "✅ Yuborish", callback_data: `bdraft_ok_${id}` },
              { text: "❌ Bekor", callback_data: `bdraft_no_${id}` },
            ],
          ],
        },
      });
      let d = {};
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: payload,
            signal: AbortSignal.timeout(15000),
          });
          d = await r.json().catch(() => ({}));
          break;
        } catch (e) {
          d = { ok: false, description: e.message };
          await new Promise((r) => setTimeout(r, 1500));
        }
      }
      if (!d.ok) {
        await pool.query("UPDATE bot_drafts SET status = 'failed', error = $2 WHERE id = $1", [id, d.description || "send"]);
        throw new Error(d.description || "egasiga yuborilmadi");
      }
      await pool.query("UPDATE bot_drafts SET owner_msg_id = $2 WHERE id = $1", [id, d.result.message_id]);
      res.json({ ok: true, id, to: who });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });
}
