/**
 * Donat (o'yin valyutasi) — sayt orqali sotish: starsjoy.uz/donat va h.k.
 *
 * Oqim:
 *  1. GET  /api/donat/catalog            — o'yinlar va narxlar (StarsPaymee jonli narxi + ustama)
 *  2. POST /api/donat/check-player       — o'yinchi ID → nik (bepul)
 *  3. POST /api/donat/order              — buyurtma: noyob summa + karta, 8 daqiqa
 *  4. SMS → balanceChecker → POST /api/donat/match (ichki) → to'langan
 *  5. StarsPaymee'ga buyurtma → holat kuzatiladi → completed / failed
 *  6. GET  /api/donat/order/:token       — mijoz holatni (va Standoff havolasini) shu yerda ko'radi
 *
 * Xavfsizlik:
 *  - Narx faqat serverda hisoblanadi; mijoz yuborgan summa ishlatilmaydi.
 *  - Bitta buyurtma = bitta idempotency_key → StarsPaymee'da pul ikki marta yechilmaydi.
 *  - Standoff havolasi (bearer) faqat token bilan, faqat yetkazilgandan keyin ko'rinadi; logga yozilmaydi.
 *  - To'langan, lekin yetkazilmagan buyurtmani tizim o'zi qayta yubormaydi — faqat admin tugmasi
 *    (StarsPaymee javob bermay qolgan 503 holati bundan mustasno: buyurtma yaratilmagan, qayta urinadi).
 */
import crypto from "crypto";
import { partnerRequest, paymeeConfigured, getPaymeeBalance } from "../paymeeClient/index.js";
import { DONAT_GAMES, GAME_BY_SLUG, markupKey } from "./catalog.js";

const ORDER_TYPE = "donat";
const PAY_WINDOW_MIN = 8;
const CATALOG_TTL_MS = 3 * 60 * 1000;
const POLL_EVERY_MS = 5000;
const POLL_MAX_MS = 20 * 60 * 1000;
const DEFAULT_RATE = 12100;

const SETTING = {
  enabled: "donat_enabled",
  rate: "donat_usdt_rate",
};

// Newbie Offer, First Purchase Pack, First Top-Up Bonus va h.k.
const ONE_TIME_RE = /newbie|first[\s-]*(purchase|top[\s-]*up)/i;

export function registerDonatRoutes(app, ctx) {
  const {
    pool,
    bot,
    adminAuth,
    internalSecretAuth,
    orderLimiterBase,
    searchLimiter,
    generateUniqueOrderSum,
    addPriceToCache,
    removePriceFromCacheByOrderId,
    ORDERS_CHANNEL,
    ERROR_LOG_CHANNEL_ID,
    projectName = "StarsJoy",
    projectKey = "sj",
    getCard, // () => { number, name, brand, type } — mijozga ko'rsatiladigan faol karta (loyihada har xil)
  } = ctx;

  // ───────────────────────── jadval ─────────────────────────
  const ready = (async () => {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS donat_orders (
        order_id INTEGER PRIMARY KEY,
        token TEXT NOT NULL UNIQUE,
        site TEXT,
        game_slug TEXT NOT NULL,
        provider_code TEXT NOT NULL,
        kind TEXT NOT NULL,
        item_id TEXT NOT NULL,
        item_name TEXT NOT NULL,
        player_id TEXT,
        player_name TEXT,
        contact TEXT,
        lang TEXT,
        ip TEXT,
        usdt_price NUMERIC(12,4),
        usdt_rate NUMERIC(12,2),
        markup_percent NUMERIC(6,2),
        card_last4 TEXT,
        provider_order_id TEXT,
        provider_status TEXT,
        usdt_charged NUMERIC(12,4),
        secret TEXT,
        error TEXT,
        attempts INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        delivered_at TIMESTAMPTZ
      )`);
    await pool.query(`ALTER TABLE donat_orders ADD COLUMN IF NOT EXISTS server_id TEXT`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_donat_orders_created ON donat_orders (created_at)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_donat_orders_ip ON donat_orders (ip, created_at)`);
  })().catch((e) => console.error("❌ donat_orders jadval:", e.message));

  // ───────────────────────── sozlamalar ─────────────────────────
  let settingsCache = null;
  let settingsAt = 0;
  async function getSettings(force = false) {
    if (!force && settingsCache && Date.now() - settingsAt < 30000) return settingsCache;
    const keys = [SETTING.enabled, SETTING.rate, ...DONAT_GAMES.map(markupKey)];
    const r = await pool.query(`SELECT key, value FROM settings WHERE key = ANY($1)`, [keys]);
    const m = Object.fromEntries(r.rows.map((x) => [x.key, x.value]));
    const markups = {};
    for (const g of DONAT_GAMES) {
      const v = Number(m[markupKey(g)]);
      markups[g.slug] = Number.isFinite(v) && v >= 0 ? v : g.defaultMarkup;
    }
    const rate = Number(m[SETTING.rate]);
    settingsCache = {
      enabled: m[SETTING.enabled] === "true",
      rate: Number.isFinite(rate) && rate > 1000 ? rate : DEFAULT_RATE,
      markups,
    };
    settingsAt = Date.now();
    return settingsCache;
  }
  async function setSetting(key, value) {
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [key, String(value)]
    );
  }

  // ───────────────────────── katalog ─────────────────────────
  const catalogCache = new Map(); // slug -> { at, items:[{id,name,usdt}] }

  async function fetchProviderItems(game) {
    if (game.kind === "game") {
      const c = await partnerRequest(`/games/${encodeURIComponent(game.code)}/catalogue`);
      let items = (c.denominations || [])
        // Faqat birinchi xaridda ishlaydigan paketlar sotilmaydi: avval olgan akkauntga o'yin rad etadi
        .filter((d) => !ONE_TIME_RE.test(String(d.name || "")))
        .map((d) => ({ id: d.name, name: d.name, usdt: Number(d.price_usdt) }));
      if (game.allow.length) {
        const order = new Map(game.allow.map((n, i) => [n, i]));
        items = items.filter((x) => order.has(x.name)).sort((a, b) => order.get(a.name) - order.get(b.name));
      }
      return items;
    }
    const c = await partnerRequest(`/giftcards/${encodeURIComponent(game.code)}/catalogue`);
    let items = (c.denominations || [])
      .filter((d) => Number(d.stock) > 0)
      .map((d) => ({ id: d.card_id, name: d.name, usdt: Number(d.price_usdt) }));
    if (game.allow.length) items = items.filter((x) => game.allow.includes(x.name));
    return items.sort((a, b) => a.usdt - b.usdt); // kodlar katalogda aralash tartibda keladi
  }

  // Sahifa (SSR) uchun: kesh bo'lsa darhol qaytadi, eskirgan bo'lsa fonda yangilanadi
  const refreshing = new Set();
  async function getItemsFast(game) {
    const hit = catalogCache.get(game.slug);
    if (!hit) return getItems(game);
    if (Date.now() - hit.at > CATALOG_TTL_MS && !refreshing.has(game.slug)) {
      refreshing.add(game.slug);
      getItems(game, 0).catch(() => {}).finally(() => refreshing.delete(game.slug));
    }
    return hit.items;
  }
  function warmCatalog() {
    for (const g of DONAT_GAMES) getItems(g, 0).catch(() => {});
  }
  setTimeout(warmCatalog, 5000);
  setInterval(warmCatalog, CATALOG_TTL_MS - 30000);

  async function getItems(game, maxAgeMs = CATALOG_TTL_MS) {
    const hit = catalogCache.get(game.slug);
    if (hit && Date.now() - hit.at < maxAgeMs) return hit.items;
    try {
      const items = (await fetchProviderItems(game)).filter((x) => Number.isFinite(x.usdt) && x.usdt > 0);
      catalogCache.set(game.slug, { at: Date.now(), items });
      return items;
    } catch (e) {
      console.error(`⚠️ Donat katalog ${game.code}:`, e.message);
      if (hit) return hit.items; // eski narx — faqat ko'rsatish uchun; buyurtmada yangisi talab qilinadi
      throw e;
    }
  }

  function priceUzs(usdt, rate, markup) {
    return Math.ceil((usdt * rate * (1 + markup / 100)) / 100) * 100;
  }

  async function publicGame(game, s) {
    let items = [];
    let available = true;
    try {
      items = await getItemsFast(game);
    } catch {
      available = false;
    }
    return {
      slug: game.slug,
      title: game.title,
      unit: game.unit,
      kind: game.kind,
      needs_player_id: game.kind === "game",
      needs_server: Boolean(game.needsServer),
      secret_kind: game.kind === "giftcard" ? game.secretKind || "code" : null,
      id_label: game.idLabel,
      id_hint: game.idHint,
      available: available && items.length > 0,
      items: items.map((x) => ({ id: x.id, name: x.name, price: priceUzs(x.usdt, s.rate, s.markups[game.slug]) })),
    };
  }

  // ───────────────────────── yordamchilar ─────────────────────────
  const clientIp = (req) => String(req.ip || req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  const cleanPlayerId = (v) => String(v || "").trim().replace(/\s+/g, "");
  const cleanServerId = (v) => String(v || "").trim().replace(/[\s()]/g, "");
  const SERVER_RE = /^\d{1,8}$/;
  const cleanText = (v, n) => String(v || "").replace(/[<>]/g, "").trim().slice(0, n);

  // StarsPaymee kaliti Stars yetkazish bilan umumiy (~60 so'rov/daq). Ochiq donat endpointlari
  // uni band qilib qo'ymasin: donat uchun umumiy limit + keshlar.
  const providerHits = [];
  const PROVIDER_PER_MIN = 20;
  function providerBudget() {
    const now = Date.now();
    while (providerHits.length && now - providerHits[0] > 60000) providerHits.shift();
    if (providerHits.length >= PROVIDER_PER_MIN) {
      const err = new Error("Juda ko'p so'rov, birozdan keyin urinib ko'ring");
      err.status = 429;
      throw err;
    }
    providerHits.push(now);
  }
  const playerCache = new Map(); // `${code}:${id}:${item}` -> { at, value }
  let balanceCache = { at: 0, value: null };
  async function cachedBalance() {
    if (balanceCache.value != null && Date.now() - balanceCache.at < 30000) return balanceCache.value;
    providerBudget();
    const b = await getPaymeeBalance();
    balanceCache = { at: Date.now(), value: Number(b?.balance_usdt) };
    return balanceCache.value;
  }

  async function checkPlayer(game, playerId, itemName, serverId = null) {
    const ck = `${game.code}:${playerId}:${serverId || ""}:${itemName || ""}`;
    const hit = playerCache.get(ck);
    if (hit && Date.now() - hit.at < 10 * 60000) return hit.value;
    if (playerCache.size > 5000) playerCache.clear();
    providerBudget();
    const body = { player_id: playerId };
    if (serverId) body.server_id = serverId;
    if (itemName) body.denomination = itemName;
    const r = await partnerRequest(`/games/${encodeURIComponent(game.code)}/check-player`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    const value = { verified: Boolean(r.verified), player_name: r.player_name || null, region: r.player_region || null };
    playerCache.set(ck, { at: Date.now(), value });
    return value;
  }

  function playerErrorText(err) {
    const code = err?.body?.error_code || err?.body?.code || "";
    if (err?.status === 429) return "Juda ko'p so'rov, bir daqiqadan keyin urinib ko'ring.";
    if (code === "wrong_region") return "Bu akkaunt boshqa mintaqada, bu paket unga yetkazilmaydi.";
    if (code === "invalid_player" || err?.status === 400) return "ID topilmadi. Raqamni tekshirib qayta kiriting.";
    return "Hozir tekshirib bo'lmadi, birozdan keyin urinib ko'ring.";
  }

  async function notifyChannel(text, failed = false) {
    if (!bot) return;
    const chat = failed ? ERROR_LOG_CHANNEL_ID : ORDERS_CHANNEL;
    await bot.telegram.sendMessage(chat, text, { parse_mode: "HTML" }).catch((e) => console.error("⚠️ Donat kanal:", e.message));
  }
  async function notifyAdmins(text) {
    if (!bot) return;
    const ids = String(process.env.ADMIN_IDS || "").split(",").map((x) => x.trim()).filter(Boolean);
    for (const id of ids) await bot.telegram.sendMessage(id, text, { parse_mode: "HTML" }).catch(() => {});
  }
  const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  async function loadOrder(orderId) {
    const r = await pool.query(
      `SELECT o.id, o.summ, o.status, o.payment_status, o.created_at, o.transaction_id, d.*
         FROM orders o JOIN donat_orders d ON d.order_id = o.id WHERE o.id = $1`,
      [orderId]
    );
    return r.rows[0] || null;
  }

  // ───────────────────────── yetkazish ─────────────────────────
  const polling = new Set();

  async function finishCompleted(o, data) {
    const secret = o.kind === "giftcard" ? (Array.isArray(data.codes) && data.codes[0]) || null : null;
    if (o.kind === "giftcard" && !secret) return false; // kod hali tayyor emas
    const tx = `paymee_${o.kind}_${data.order_id || o.provider_order_id}`;
    const upd = await pool.query(
      `UPDATE orders SET status = 'completed', payment_status = 'paid', transaction_id = $2
        WHERE id = $1 AND status <> 'completed' RETURNING id`,
      [o.id, tx]
    );
    await pool.query(
      `UPDATE donat_orders SET provider_status = 'completed', usdt_charged = COALESCE($2, usdt_charged),
              secret = COALESCE($3, secret), error = NULL, delivered_at = NOW(), updated_at = NOW()
        WHERE order_id = $1`,
      [o.id, data.usdt_charged ?? null, secret]
    );
    if (upd.rowCount) {
      console.log(`✅ Donat #${o.id} yetkazildi (${o.provider_code} ${o.item_name})`);
      const who = o.kind === "game"
        ? `${esc(o.player_id)}${o.server_id ? ` (${esc(o.server_id)})` : ""}${o.player_name ? ` · ${esc(o.player_name)}` : ""}`
        : "kod/havola mijozga berildi";
      notifyChannel(
        `🎮 <b>Yangi donat sotildi!</b>\n\n` +
          `📦 Order: #${o.id} · ${esc(projectName)}${o.site ? ` · ${esc(o.site)}` : ""}\n` +
          `🕹 ${esc(GAME_BY_SLUG.get(o.game_slug)?.title || o.game_slug)}: ${esc(o.item_name)}\n` +
          `👤 ${who}\n` +
          `💰 Summa: ${Number(o.summ).toLocaleString()} so'm\n` +
          `✅ Status: Yetkazildi`
      );
    }
    return true;
  }

  async function finishFailed(o, reason, { refunded = true } = {}) {
    await pool.query(`UPDATE orders SET status = 'failed' WHERE id = $1 AND status <> 'completed'`, [o.id]);
    await pool.query(
      `UPDATE donat_orders SET provider_status = 'failed', error = $2, updated_at = NOW() WHERE order_id = $1`,
      [o.id, String(reason).slice(0, 500)]
    );
    console.error(`❌ Donat #${o.id} yetkazilmadi: ${reason}`);
    const text =
      `⚠️ <b>Donat yetkazilmadi</b> · ${esc(projectName)}\n\n` +
      `📦 #${o.id} · ${esc(GAME_BY_SLUG.get(o.game_slug)?.title || o.game_slug)}: ${esc(o.item_name)}\n` +
      `👤 ${esc(o.player_id || "—")}${o.contact ? ` · aloqa: ${esc(o.contact)}` : ""}\n` +
      `💰 ${Number(o.summ).toLocaleString()} so'm to'langan\n` +
      `Sabab: ${esc(reason)}\n` +
      (refunded ? `StarsPaymee puli balansga qaytgan. ` : "") +
      `Admin → Donat bo'limidan qayta yuborish mumkin.`;
    notifyChannel(text, true);
    notifyAdmins(text);
  }

  async function pollProvider(orderId) {
    if (polling.has(orderId)) return;
    polling.add(orderId);
    try {
      const started = Date.now();
      while (Date.now() - started < POLL_MAX_MS) {
        await new Promise((r) => setTimeout(r, POLL_EVERY_MS));
        const o = await loadOrder(orderId);
        if (!o || o.status !== "processing" || !o.provider_order_id) return;
        let data;
        try {
          const path = o.kind === "game" ? `/games/orders/${o.provider_order_id}` : `/giftcards/orders/${o.provider_order_id}`;
          data = await partnerRequest(path);
        } catch (e) {
          if (e.status === 404) return finishFailed(o, "StarsPaymee buyurtmani topmadi (404)");
          // partnerRequest success:false ni xato qilib otadi — bu vaqtinchalik emas, buyurtma bajarilmagan
          if (e.body?.status === "failed") {
            return finishFailed(o, e.body.error || e.message || "StarsPaymee: failed", { refunded: e.body.refunded !== false });
          }
          continue; // vaqtinchalik — keyingi aylanishda
        }
        await pool.query(`UPDATE donat_orders SET provider_status = $2, updated_at = NOW() WHERE order_id = $1`, [
          orderId,
          String(data.status || ""),
        ]);
        if (data.status === "completed") {
          if (await finishCompleted(o, data)) return;
        } else if (data.status === "failed") {
          return finishFailed(o, data.error || "StarsPaymee: failed", { refunded: data.refunded !== false });
        }
      }
      // 20 daqiqada tugamadi — admin ko'rsin (buyurtma StarsPaymee'da davom etishi mumkin)
      const o = await loadOrder(orderId);
      if (o && o.status === "processing") {
        notifyAdmins(
          `⏳ <b>Donat #${orderId} 20 daqiqadan beri tugamadi</b> · ${esc(projectName)}\n` +
            `StarsPaymee order ${esc(o.provider_order_id)}, holat: ${esc(o.provider_status || "?")}. Kuzatuv davom etadi.`
        );
      }
    } finally {
      polling.delete(orderId);
    }
  }

  /** To'langan buyurtmani StarsPaymee'ga yuboradi. Bir buyurtma = bitta idempotency_key. */
  const delivering = new Set();
  async function deliver(orderId) {
    if (delivering.has(orderId)) return;
    delivering.add(orderId);
    try {
      return await deliverOnce(orderId);
    } finally {
      delivering.delete(orderId);
    }
  }

  async function deliverOnce(orderId) {
    const o = await loadOrder(orderId);
    if (!o || o.status !== "processing" || o.payment_status !== "paid") return;
    if (o.provider_order_id) return pollProvider(orderId);

    await pool.query(`UPDATE donat_orders SET attempts = attempts + 1, updated_at = NOW() WHERE order_id = $1`, [orderId]);
    const idem = `donat-${projectKey}-${orderId}`;
    let data;
    try {
      if (o.kind === "game") {
        data = await partnerRequest(`/games/${encodeURIComponent(o.provider_code)}/order`, {
          method: "POST",
          body: JSON.stringify({
            denomination: o.item_id,
            player_id: o.player_id,
            ...(o.server_id ? { server_id: o.server_id } : {}),
            idempotency_key: idem,
          }),
        });
      } else {
        data = await partnerRequest(`/giftcards/${encodeURIComponent(o.provider_code)}/order`, {
          method: "POST",
          body: JSON.stringify({ card_id: o.item_id, quantity: 1, idempotency_key: idem }),
        });
      }
    } catch (e) {
      const st = e.status;
      if (e.body?.status === "failed") {
        if (e.body.order_id != null) {
          await pool.query(`UPDATE donat_orders SET provider_order_id = $2 WHERE order_id = $1`, [orderId, String(e.body.order_id)]);
        }
        return finishFailed(o, e.body.error || e.message || "StarsPaymee: failed", { refunded: e.body.refunded !== false });
      }
      if (st === 503 || st === 429 || st === 500 || !st) {
        // Buyurtma yaratilmagan, pul yechilmagan — sweeper keyinroq o'sha kalit bilan qayta urinadi
        await pool.query(`UPDATE donat_orders SET error = $2, updated_at = NOW() WHERE order_id = $1`, [
          orderId,
          `vaqtincha: ${String(e.message).slice(0, 300)}`,
        ]);
        console.warn(`⏳ Donat #${orderId} StarsPaymee vaqtincha (${st}): ${e.message}`);
        return;
      }
      if (st === 402) return finishFailed(o, "StarsPaymee balansi yetarli emas", { refunded: false });
      return finishFailed(o, e.message || `HTTP ${st}`, { refunded: st === 502 });
    }

    const providerId = data?.order_id != null ? String(data.order_id) : null;
    await pool.query(
      `UPDATE donat_orders SET provider_order_id = $2, provider_status = $3, usdt_charged = $4, error = NULL, updated_at = NOW()
        WHERE order_id = $1`,
      [orderId, providerId, String(data?.status || ""), data?.usdt_charged ?? null]
    );
    const fresh = await loadOrder(orderId);
    if (data?.status === "completed" && (await finishCompleted(fresh, data))) return;
    if (data?.status === "failed") return finishFailed(fresh, data.error || "StarsPaymee: failed", { refunded: data.refunded !== false });
    if (providerId) pollProvider(orderId);
  }

  // ───────────────────────── sweeper ─────────────────────────
  // 1) 8 daqiqada to'lanmagan → expired  2) vaqtincha xatoda qolgan to'langan → qayta urinish
  // 3) server qayta ishga tushgan bo'lsa → processing buyurtmalar kuzatuvini tiklash
  async function sweep() {
    try {
      await ready;
      const exp = await pool.query(
        `UPDATE orders SET status = 'expired', payment_status = 'expired'
          WHERE order_type = $1 AND status = 'pending' AND payment_status = 'pending'
            AND created_at < NOW() - ($2 || ' minutes')::interval
          RETURNING id`,
        [ORDER_TYPE, String(PAY_WINDOW_MIN)]
      );
      for (const r of exp.rows) removePriceFromCacheByOrderId(r.id);

      const stuck = await pool.query(
        `SELECT o.id, d.provider_order_id, d.attempts, d.updated_at
           FROM orders o JOIN donat_orders d ON d.order_id = o.id
          WHERE o.order_type = $1 AND o.status = 'processing' AND o.payment_status = 'paid'
            AND o.created_at > NOW() - INTERVAL '2 days'`,
        [ORDER_TYPE]
      );
      for (const s of stuck.rows) {
        if (s.provider_order_id) {
          pollProvider(s.id);
        } else if (s.attempts < 30 && Date.now() - new Date(s.updated_at).getTime() > 60000) {
          deliver(s.id).catch((e) => console.error(`❌ Donat #${s.id} qayta urinish:`, e.message));
        }
      }
    } catch (e) {
      console.error("⚠️ Donat sweeper:", e.message);
    }
  }
  setTimeout(sweep, 15000);
  setInterval(sweep, 60000);

  // ───────────────────────── public API ─────────────────────────
  app.get("/api/donat/catalog", async (_req, res) => {
    try {
      await ready;
      const s = await getSettings();
      const games = await Promise.all(DONAT_GAMES.map((g) => publicGame(g, s)));
      res.set("Cache-Control", "no-cache"); // yoqish/o'chirish darhol ko'rinsin (narxlar serverda keshlanadi)
      res.json({ success: true, enabled: s.enabled && paymeeConfigured(), pay_window_min: PAY_WINDOW_MIN, games });
    } catch (e) {
      console.error("❌ /api/donat/catalog:", e.message);
      res.status(500).json({ success: false, error: "Server xatosi" });
    }
  });

  app.post("/api/donat/check-player", searchLimiter, async (req, res) => {
    try {
      const game = GAME_BY_SLUG.get(String(req.body?.game || ""));
      const playerId = cleanPlayerId(req.body?.player_id);
      if (!game || game.kind !== "game") return res.status(400).json({ success: false, error: "O'yin noto'g'ri" });
      if (!/^[0-9A-Za-z._-]{4,40}$/.test(playerId)) return res.status(400).json({ success: false, error: "ID noto'g'ri" });
      const serverId = game.needsServer ? cleanServerId(req.body?.server_id) : null;
      if (game.needsServer && !SERVER_RE.test(serverId || "")) return res.status(400).json({ success: false, error: "Zone ID'ni kiriting" });
      const r = await checkPlayer(game, playerId, req.body?.item ? String(req.body.item) : null, serverId);
      res.json({ success: true, ...r });
    } catch (e) {
      res.status(e.status === 400 ? 400 : e.status === 429 ? 429 : 503).json({ success: false, error: playerErrorText(e) });
    }
  });

  app.post("/api/donat/order", orderLimiterBase, async (req, res) => {
    try {
      await ready;
      const s = await getSettings(true);
      if (!s.enabled || !paymeeConfigured()) {
        return res.status(503).json({ success: false, error: "Donat hozircha yopiq. Birozdan keyin urinib ko'ring." });
      }
      const game = GAME_BY_SLUG.get(String(req.body?.game || ""));
      if (!game) return res.status(400).json({ success: false, error: "O'yin noto'g'ri" });
      const itemId = String(req.body?.item || "");
      const site = cleanText(req.body?.site, 40) || null;
      const contact = cleanText(req.body?.contact, 64) || null;
      const lang = ["uz", "ru", "en"].includes(req.body?.lang) ? req.body.lang : "uz";
      const ip = clientIp(req);

      const open = await pool.query(
        `SELECT COUNT(*)::int AS c FROM donat_orders d JOIN orders o ON o.id = d.order_id
          WHERE d.ip = $1 AND o.status = 'pending' AND o.created_at > NOW() - INTERVAL '10 minutes'`,
        [ip]
      );
      if (open.rows[0].c >= 3) {
        return res.status(429).json({ success: false, error: "To'lanmagan buyurtmalaringiz bor. Avval ularni to'lang yoki 8 daqiqa kuting." });
      }

      // Narx buyurtma paytida yangidan o'qiladi (eskirgan narx bilan sotmaslik)
      let items;
      try {
        items = await getItems(game, 60000);
      } catch {
        return res.status(503).json({ success: false, error: "Hozir narxlarni olib bo'lmadi, birozdan keyin urinib ko'ring." });
      }
      const item = items.find((x) => x.id === itemId);
      if (!item) return res.status(400).json({ success: false, error: "Paket topilmadi yoki tugagan" });

      let playerId = null;
      let playerName = null;
      let serverId = null;
      if (game.kind === "game") {
        playerId = cleanPlayerId(req.body?.player_id);
        if (!/^[0-9A-Za-z._-]{4,40}$/.test(playerId)) return res.status(400).json({ success: false, error: "ID noto'g'ri" });
        if (game.needsServer) {
          serverId = cleanServerId(req.body?.server_id);
          if (!SERVER_RE.test(serverId || "")) return res.status(400).json({ success: false, error: "Zone ID'ni kiriting" });
        }
        try {
          const p = await checkPlayer(game, playerId, item.name, serverId);
          playerName = p.player_name;
        } catch (e) {
          return res.status(400).json({ success: false, error: playerErrorText(e) });
        }
      }

      // StarsPaymee balansi yetadimi (yetmasa to'lov olmaymiz)
      try {
        const bal = await cachedBalance();
        if (bal < item.usdt * 1.05) {
          notifyAdmins(`⚠️ <b>Donat: StarsPaymee balansi kam</b> · ${esc(projectName)}\nKerak ~${item.usdt} USDT, bor ${esc(bal)}. Buyurtma qabul qilinmadi.`);
          return res.status(503).json({ success: false, error: "Bu paket vaqtincha mavjud emas, birozdan keyin urinib ko'ring." });
        }
      } catch {
        return res.status(503).json({ success: false, error: "Hozir buyurtma qabul qilib bo'lmadi, birozdan keyin urinib ko'ring." });
      }

      const markup = s.markups[game.slug];
      const price = priceUzs(item.usdt, s.rate, markup);
      const card = getCard();
      if (!card?.number) {
        return res.status(503).json({ success: false, error: "To'lov kartasi sozlanmagan" });
      }

      const client = await pool.connect();
      let order;
      const token = crypto.randomBytes(18).toString("base64url");
      try {
        await client.query("BEGIN");
        await client.query("SELECT pg_advisory_xact_lock(1002)");
        // 0-slot (yaxlit ko'rsatilgan narx) berilmaydi — mijoz yaxlit narxni tashlasa boshqa buyurtmaga yozilmasin
        const summ = await generateUniqueOrderSum(price - 50, client);
        const r = await client.query(
          `INSERT INTO orders (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount, summ,
                               payment_method, payment_status, status, created_at)
           VALUES ($1, NULL, $2, $3, $4, 1, $5, 'card', 'pending', 'pending', NOW()) RETURNING *`,
          [crypto.randomUUID(), playerId || game.slug, `${game.title}: ${item.name}`, ORDER_TYPE, summ]
        );
        order = r.rows[0];
        await client.query(
          `INSERT INTO donat_orders (order_id, token, site, game_slug, provider_code, kind, item_id, item_name,
                                     player_id, player_name, contact, lang, ip, usdt_price, usdt_rate, markup_percent, card_last4, server_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
          [order.id, token, site, game.slug, game.code, game.kind, item.id, item.name, playerId, playerName, contact, lang, ip,
           item.usdt, s.rate, markup, String(card.number).replace(/\D/g, "").slice(-4), serverId]
        );
        await client.query("COMMIT");
      } catch (e) {
        await client.query("ROLLBACK").catch(() => {});
        throw e;
      } finally {
        client.release();
      }
      addPriceToCache(order.summ, order.id, ORDER_TYPE);
      console.log(`🧾 Donat order #${order.id} | ${game.code} ${item.name} | ${playerId || "-"} | ${order.summ} so'm | ${site || "-"}`);

      res.json({
        success: true,
        token,
        order_id: order.id,
        amount: order.summ,
        price,
        expires_at: new Date(new Date(order.created_at).getTime() + PAY_WINDOW_MIN * 60000).toISOString(),
        card: { number: card.number, name: card.name, brand: card.brand, type: card.type },
      });
    } catch (e) {
      console.error("❌ /api/donat/order:", e.message);
      res.status(500).json({ success: false, error: "Server xatosi, qayta urinib ko'ring" });
    }
  });

  app.get("/api/donat/order/:token", async (req, res) => {
    try {
      const token = String(req.params.token || "");
      if (!/^[A-Za-z0-9_-]{20,40}$/.test(token)) return res.status(404).json({ success: false });
      const r = await pool.query(
        `SELECT o.id, o.summ, o.status, o.payment_status, o.created_at, d.game_slug, d.kind, d.item_name,
                d.player_id, d.player_name, d.server_id, d.secret, d.card_last4, d.delivered_at
           FROM donat_orders d JOIN orders o ON o.id = d.order_id WHERE d.token = $1`,
        [token]
      );
      const o = r.rows[0];
      if (!o) return res.status(404).json({ success: false });
      const game = GAME_BY_SLUG.get(o.game_slug);
      const state =
        o.status === "completed" ? "delivered"
        : o.status === "processing" ? "delivering"
        : o.status === "failed" || o.status === "error" ? "problem"
        : o.status === "expired" || o.status === "cancelled" ? "expired"
        : "awaiting_payment";
      // To'lov kutilayotgan bo'lsa karta (sahifa yangilansa ham ko'rinsin). Faol karta o'zgargan
      // bo'lsa — eski karta raqami bizda saqlanmagan, faqat oxirgi 4 raqam qaytadi.
      let card = null;
      if (state === "awaiting_payment") {
        const c = getCard() || {};
        const last4 = String(c.number || "").replace(/\D/g, "").slice(-4);
        card = last4 && last4 === o.card_last4
          ? { number: c.number, name: c.name, brand: c.brand, type: c.type }
          : { number: `**** ${o.card_last4}`, name: null, brand: null, type: null };
      }
      res.set("Cache-Control", "no-store");
      res.json({
        success: true,
        state,
        card,
        order_id: o.id,
        amount: o.summ,
        game: game?.title || o.game_slug,
        game_slug: o.game_slug,
        item: o.item_name,
        player_id: o.player_id,
        player_name: o.player_name,
        created_at: o.created_at,
        expires_at: new Date(new Date(o.created_at).getTime() + PAY_WINDOW_MIN * 60000).toISOString(),
        delivered_at: o.delivered_at,
        server_id: o.server_id,
        link: state === "delivered" && o.kind === "giftcard" ? o.secret : null,
        secret_kind: o.kind === "giftcard" ? game?.secretKind || "code" : null,
      });
    } catch (e) {
      res.status(500).json({ success: false });
    }
  });

  // Mijoz "Bekor qilish" bosdi: to'lanmagan buyurtma darhol yopiladi (expired — keyin SMS kelsa
  // ham SMS daftari uni taymer ichidagi to'lov sifatida tiklay oladi, pul yo'qolmaydi)
  app.post("/api/donat/order/:token/cancel", async (req, res) => {
    try {
      const token = String(req.params.token || "");
      if (!/^[A-Za-z0-9_-]{20,40}$/.test(token)) return res.status(404).json({ success: false });
      const r = await pool.query(
        `UPDATE orders o SET status = 'expired', payment_status = 'expired'
           FROM donat_orders d
          WHERE d.order_id = o.id AND d.token = $1 AND o.status = 'pending' AND o.payment_status = 'pending'
          RETURNING o.id`,
        [token]
      );
      if (r.rowCount) removePriceFromCacheByOrderId(r.rows[0].id);
      res.json({ success: true, cancelled: r.rowCount > 0 });
    } catch (e) {
      res.status(500).json({ success: false });
    }
  });

  // ───────────────────────── ichki: SMS match ─────────────────────────
  app.post("/api/donat/match", internalSecretAuth, async (req, res) => {
    try {
      const amount = parseInt(req.body?.amount, 10);
      if (!amount || amount <= 0) return res.status(400).json({ error: "amount noto'g'ri" });
      const updated = req.body?.order_id
        ? await pool.query(
            // SMS vaqti bo'yicha aniqlangan buyurtma (expired bo'lsa ham — to'lov taymer ichida bo'lgan)
            `UPDATE orders SET payment_status = 'paid', status = 'processing'
              WHERE id = $1 AND summ = $2 AND order_type = $3
                AND payment_status IN ('pending','expired') AND status IN ('pending','expired')
              RETURNING *`,
            [Number(req.body.order_id), amount, ORDER_TYPE]
          )
        : await pool.query(
            `UPDATE orders SET payment_status = 'paid', status = 'processing'
              WHERE id = (SELECT id FROM orders WHERE summ = $1 AND payment_status = 'pending' AND status = 'pending'
                            AND order_type = $2 AND created_at >= NOW() - INTERVAL '15 minutes'
                          ORDER BY id DESC LIMIT 1 FOR UPDATE SKIP LOCKED)
              RETURNING *`,
            [amount, ORDER_TYPE]
          );
      if (!updated.rows.length) return res.status(404).json({ message: "Pending donat order topilmadi" });
      const order = updated.rows[0];
      removePriceFromCacheByOrderId(order.id);
      console.log(`🎉 Donat to'lov tasdiqlandi: #${order.id} | ${order.summ} so'm`);
      deliver(order.id).catch((e) => console.error(`❌ Donat #${order.id} yetkazish:`, e.message));
      res.json({ id: order.id, amount: order.summ, status: "processing", payment_status: "paid", order_type: ORDER_TYPE });
    } catch (e) {
      console.error("❌ /api/donat/match:", e.message);
      res.status(500).json({ error: "Server error" });
    }
  });

  // ───────────────────────── admin ─────────────────────────
  app.get("/api/admin/donat/orders", adminAuth, async (req, res) => {
    try {
      await ready;
      const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 50));
      const paidOnly = req.query.paid === "1";
      const r = await pool.query(
        `SELECT o.id, o.summ, o.status, o.payment_status, o.created_at, o.transaction_id,
                d.site, d.game_slug, d.item_name, d.player_id, d.server_id, d.player_name, d.contact, d.provider_order_id,
                d.provider_status, d.usdt_price, d.usdt_charged, d.markup_percent, d.error, d.attempts, d.delivered_at, d.card_last4
           FROM orders o JOIN donat_orders d ON d.order_id = o.id
          WHERE o.order_type = $1 ${paidOnly ? "AND o.payment_status = 'paid'" : ""}
          ORDER BY o.id DESC LIMIT $2`,
        [ORDER_TYPE, limit]
      );
      res.json({ success: true, items: r.rows });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // Qayta yuborish: faqat to'langan va yetkazilmagan (failed/error yoki StarsPaymee'ga yetmagan processing)
  app.post("/api/admin/donat/:id/resend", adminAuth, async (req, res) => {
    try {
      const id = Number(req.params.id);
      const o = await loadOrder(id);
      if (!o) return res.status(404).json({ success: false, error: "Topilmadi" });
      if (o.payment_status !== "paid") return res.status(400).json({ success: false, error: "To'lanmagan" });
      if (o.status === "completed") return res.status(400).json({ success: false, error: "Allaqachon yetkazilgan" });
      if (o.status === "processing" && o.provider_order_id && o.provider_status !== "failed") {
        pollProvider(id);
        return res.json({ success: true, note: "StarsPaymee'da bajarilmoqda — kuzatuv yangilandi" });
      }
      const r = await pool.query(
        `UPDATE orders SET status = 'processing' WHERE id = $1 AND payment_status = 'paid' AND status IN ('failed','error','processing') RETURNING id`,
        [id]
      );
      if (!r.rowCount) return res.status(409).json({ success: false, error: "Holat o'zgargan, sahifani yangilang" });
      await pool.query(`UPDATE donat_orders SET provider_order_id = NULL, provider_status = NULL, error = NULL WHERE order_id = $1`, [id]);
      deliver(id).catch((e) => console.error(`❌ Donat #${id} admin qayta:`, e.message));
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  app.get("/api/admin/donat/settings", adminAuth, async (_req, res) => {
    const s = await getSettings(true);
    let balance = null;
    try {
      balance = (await getPaymeeBalance())?.balance_usdt ?? null;
    } catch {
      /* ignore */
    }
    res.json({ success: true, ...s, balance_usdt: balance, games: DONAT_GAMES.map((g) => ({ slug: g.slug, title: g.title, default_markup: g.defaultMarkup })) });
  });

  app.post("/api/admin/donat/settings", adminAuth, async (req, res) => {
    try {
      const b = req.body || {};
      if (typeof b.enabled === "boolean") await setSetting(SETTING.enabled, b.enabled ? "true" : "false");
      if (b.rate != null) {
        const v = Number(b.rate);
        if (!Number.isFinite(v) || v < 5000 || v > 50000) return res.status(400).json({ success: false, error: "Kurs noto'g'ri" });
        await setSetting(SETTING.rate, Math.round(v));
      }
      if (b.markups && typeof b.markups === "object") {
        for (const g of DONAT_GAMES) {
          if (b.markups[g.slug] == null) continue;
          const v = Number(b.markups[g.slug]);
          if (!Number.isFinite(v) || v < 10 || v > 100) {
            return res.status(400).json({ success: false, error: `${g.title}: ustama 10–100% oralig'ida bo'lsin` });
          }
          await setSetting(markupKey(g), v);
        }
      }
      res.json({ success: true, ...(await getSettings(true)) });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  console.log("✅ Donat moduli: /api/donat/catalog, /check-player, /order, /order/:token, /match; admin /api/admin/donat/*");
}
