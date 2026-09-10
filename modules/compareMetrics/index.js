// modules/compareMetrics/index.js
// 📊 /compare paneli uchun ko'rsatkichlar endpointi.
//
// BU FAYL MUSTAQIL: boshqa modullarga bog'liq emas, faqat `pool` va `app`
// kerak. Har qanday loyihaga nusxa qilib qo'ysa bo'ladi — moslash uchun
// faqat pastdagi SOZLAMA blokini o'zgartirish kifoya.
//
// Nima qiladi: bitta GET so'roviga javoban 4 ta davr (bugun / 7 kun /
// 30 kun / hammasi) bo'yicha foydalanuvchi, buyurtma, tushum, tannarx,
// foyda va mahsulot kesimini qaytaradi.
//
// ⚠️ Nega baza portini ochish o'rniga shu yo'l: bu yerda TANNARX shu
//    loyihaning o'zida hisoblanadi. Tashqi tizim buni to'g'ri bilolmaydi
//    va sxema o'zgarganda uning kodi sinardi.

import pg from "pg";

// ═══════════════════════════════════════════════════════════════════
//                          SOZLAMA
// ═══════════════════════════════════════════════════════════════════

/** Loyiha kaliti — /compare sahifasidagi tab bilan bir xil bo'lishi shart */
const PROJECT_KEY = process.env.COMPARE_PROJECT_KEY || "starsjoy";

/** Vaqt mintaqasi — kun chegaralari shunga qarab hisoblanadi */
const TZ = "Asia/Tashkent";

/** "Yetkazilgan" deb hisoblanadigan statuslar */
const FULFILLED = [
  "stars_sent", "premium_sent", "gift_sent",
  "completed", "delivered", "success",
];

/**
 * Tushumga KIRMAYDIGANLAR:
 *   • balance_topup — balansga pul kirishi, mahsulot emas. Tushum o'sha
 *     balansdan mahsulot sotilganda sanaladi, aks holda ikki marta sanaladi.
 *   • payment_method='bonus' — sovg'a/missiya, summ=0, faqat xarajat.
 */
const EXCLUDED_TYPE = "balance_topup";
const EXCLUDED_METHOD = "bonus";

/**
 * TANNARX MODELI — .env dan sozlanadi. Bu loyihalarda tannarx jadvali
 * yo'q, shuning uchun model shu yerda. Qiymatlarni .env da to'g'rilang,
 * aks holda foyda noto'g'ri chiqadi.
 *
 * Loyiha uchun tannarx modeli.
 *
 * Har bir qiymat avval loyihaga xos o'zgaruvchidan qidiriladi, topilmasa
 * umumiy qiymatdan olinadi. Ya'ni uchala loyiha bir narxda oladigan bo'lsa
 * faqat umumiylarini yozish kifoya; biri boshqacha olsa — o'shaniki
 * ustidan yoziladi:
 *
 *   COMPARE_USD_TO_UZS=12200            ← hammasi uchun
 *   COMPARE_UZGETS_STARS_COST_USD=0.80  ← faqat uzgets uchun
 *
 * @param {string} key loyiha kaliti (starsjoy / uzgets / premiumsend)
 */
function costModelFor(key) {
  const P = String(key || "").toUpperCase();
  /** Avval loyihaniki, keyin umumiysi, oxirida zaxira qiymat */
  const v = (name, fallback) => {
    const own = process.env[`COMPARE_${P}_${name}`];
    const shared = process.env[`COMPARE_${name}`];
    return Number(own ?? shared) || fallback;
  };
  return {
    usdToUzs: v("USD_TO_UZS", 12200),
    /** N dona stars necha dollarga olinadi */
    starsPer: v("STARS_COST_PER", 50),
    starsUsd: v("STARS_COST_USD", 0.75),
    /** Premium: oy → dollar */
    premiumUsd: {
      3: v("PREMIUM_3_USD", 12),
      6: v("PREMIUM_6_USD", 16),
      12: v("PREMIUM_12_USD", 29),
    },
    /** To'lov tizimi komissiyasi, % */
    commissionPercent: v("COMMISSION_PERCENT", 2),
  };
}

/** Mahsulot yorliqlari — sahifada chiroyli ko'rinishi uchun */
const PRODUCT_META = {
  stars: { label: "Stars", icon: "⭐" },
  stars_usdt: { label: "Stars (USDT)", icon: "⭐" },
  stars_paymee: { label: "Stars (Paymee)", icon: "⭐" },
  premium: { label: "Premium", icon: "💎" },
  premium_usdt: { label: "Premium (USDT)", icon: "💎" },
  premium_paymee: { label: "Premium (Paymee)", icon: "💎" },
  gift: { label: "Gift", icon: "🎁" },
};

/**
 * Qo'shni loyihalar — /api/metrics/compare/all shularni yig'adi.
 *
 * Uchalasi ham shu serverda va bir kod bazasidan forklangan, sxemasi bir xil
 * (tekshirildi: `orders` da faqat uzgets'da qo'shimcha `expected_card_last4`,
 * premiumsend'da gift ustunlari yo'q — bu modul ishlatadigan ustunlar
 * hammasida bor). Manzil .env dan olinadi; sozlanmagan loyiha javobda
 * ochiq "sozlanmagan" deb belgilanadi, jimgina tushib qolmaydi.
 */
const NEIGHBOURS = [
  { key: "starsjoy", label: "StarsJoy", env: "COMPARE_DB_STARSJOY" },
  { key: "uzgets", label: "UzGets", env: "COMPARE_DB_UZGETS" },
  { key: "premiumsend", label: "PremiumSend", env: "COMPARE_DB_PREMIUMSEND" },
];

/**
 * Qo'shni bazalar uchun ulanish havzalari — talab bo'lganda yaratiladi.
 *
 * ⚠️ Havza ATAYLAB kichik (max 2): server 1 GB, asosiy havza allaqachon 20 ta
 *    ulanishga sozlangan. Bu endpoint kuniga bir necha marta chaqiriladi,
 *    shuning uchun bo'sh ulanishlar 30 soniyada yopiladi.
 */
const neighbourPools = new Map();

function neighbourPool(n) {
  const url = process.env[n.env];
  if (!url) return null;
  if (!neighbourPools.has(n.key)) {
    neighbourPools.set(
      n.key,
      new pg.Pool({
        connectionString: url,
        max: 2,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 5_000,
        // Faqat o'qiymiz — sekin so'rov endpointni osib qo'ymasin
        statement_timeout: 8_000,
      })
    );
  }
  return neighbourPools.get(n.key);
}

/** Javobda ko'rsatiladigan tannarx modeli — qaysi model ishlatilgani ko'rinsin */
function costModelSummary(cost) {
  return {
    usd_to_uzs: cost.usdToUzs,
    star_cost_uzs: Number(starCostUzs(cost).toFixed(2)),
    premium_usd: cost.premiumUsd,
    commission_percent: cost.commissionPercent,
  };
}

// ═══════════════════════════════════════════════════════════════════

/** Bir dona stars tannarxi (so'mda) */
function starCostUzs(cost) {
  if (!cost.starsPer) return 0;
  return (cost.starsUsd / cost.starsPer) * cost.usdToUzs;
}

/**
 * order_type → tannarx "oilasi".
 *
 * ⚠️ To'lov usuli tannarxga ta'sir qilmaydi: `stars_paymee` ham, `stars_usdt`
 *    ham, oddiy `stars` ham bir xil mahsulot — faqat pul kelish yo'li boshqa.
 *    Ilgari bu yerda turlar bittalab sanalardi va StarsJoy'ning eng katta
 *    ikki turi (`stars_paymee`, `premium_paymee` — tushumning 65%i)
 *    ro'yxatga tushmay "tannarx noma'lum" bo'lib chetda qolardi.
 *    Prefiks bo'yicha aniqlash yangi to'lov usullarida ham ishlaydi.
 *
 * @returns {"stars"|"premium"|null} null → tannarx noma'lum
 */
function costFamily(type) {
  const t = String(type || "");
  if (t === "gift") return "stars"; // gift ham stars hisobiga olinadi
  if (t.startsWith("premium")) return "premium";
  if (t.startsWith("stars")) return "stars";
  return null;
}

/**
 * Bitta guruh (order_type + type_amount) uchun tannarx.
 *
 * ⚠️ Guruh AYNAN `type_amount` bo'yicha bo'linadi. Ilgari bu yerda oylar
 *    o'rtachalanardi (690 oy / 165 buyurtma = 4,18 → premiumUsd[4] yo'q →
 *    tannarx 0 → marja 98%). Endi 3, 6 va 12 oylik buyurtmalar alohida
 *    guruh bo'lib, har biri o'z narxida hisoblanadi.
 *
 * @param {string} type       order_type
 * @param {number} unitAmount bitta buyurtmadagi miqdor (stars soni / oy)
 * @param {number} count      shu guruhda nechta buyurtma
 * @returns {{cost:number, known:boolean}} known=false → foydaga QO'SHILMAYDI
 */
function costFor(cost, type, unitAmount, count) {
  const fam = costFamily(type);
  if (fam === "stars") {
    return { cost: Math.round(unitAmount * count * starCostUzs(cost)), known: true };
  }
  if (fam === "premium") {
    const usd = cost.premiumUsd[unitAmount];
    // Noma'lum muddat (masalan 1 oylik) — taxmin qilmaymiz
    if (!usd) return { cost: 0, known: false };
    return { cost: Math.round(usd * cost.usdToUzs * count), known: true };
  }
  // Modelga kiritilmagan tur: tannarxni 0 deb ko'rsatish foydani
  // sun'iy ravishda oshirib yuboradi. Halol yo'l — "noma'lum" deb belgilash.
  return { cost: 0, known: false };
}

/** Toshkent bo'yicha bugungi sana (YYYY-MM-DD) */
function todayTz() {
  return new Date(Date.now() + 5 * 3600 * 1000).toISOString().slice(0, 10);
}

function addDays(iso, n) {
  const d = new Date(`${iso}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

function periods() {
  const today = todayTz();
  const tomorrow = addDays(today, 1);
  return {
    today: { from: today, to: tomorrow },
    week: { from: addDays(today, -6), to: tomorrow },
    month: { from: addDays(today, -29), to: tomorrow },
    all: { from: "2000-01-01", to: tomorrow },
  };
}

/** Bitta davr uchun barcha ko'rsatkichlar */
async function periodMetrics(pool, { from, to }, cost) {
  // 1) Mahsulot kesimi.
  //    ⚠️ `type_amount` BO'YICHA HAM guruhlaymiz: 3, 6 va 12 oylik premium
  //    turli tannarxga ega, ularni bitta guruhga qo'shsak o'rtacha oy
  //    chiqib, narx jadvalidan topilmay qoladi va tannarx 0 bo'lardi.
  const prodRes = await pool.query(
    `SELECT order_type,
            type_amount,
            COUNT(*)::int                  AS orders,
            COALESCE(SUM(summ), 0)::bigint AS revenue
       FROM orders
      WHERE status = ANY($1::text[])
        AND order_type <> $2
        AND COALESCE(payment_method, '') <> $3
        AND (created_at AT TIME ZONE $4) >= $5::timestamp
        AND (created_at AT TIME ZONE $4) <  $6::timestamp
      GROUP BY order_type, type_amount`,
    [FULFILLED, EXCLUDED_TYPE, EXCLUDED_METHOD, TZ, from, to]
  );

  // 2) Xaridorlar soni (DISTINCT — guruhlar ustida yig'ib bo'lmaydi)
  const buyersRes = await pool.query(
    `SELECT COUNT(DISTINCT owner_user_id)::int AS buyers
       FROM orders
      WHERE status = ANY($1::text[])
        AND order_type <> $2
        AND COALESCE(payment_method, '') <> $3
        AND (created_at AT TIME ZONE $4) >= $5::timestamp
        AND (created_at AT TIME ZONE $4) <  $6::timestamp`,
    [FULFILLED, EXCLUDED_TYPE, EXCLUDED_METHOD, TZ, from, to]
  );

  // 3) Foydalanuvchilar
  const usersRes = await pool.query(
    `SELECT
       COUNT(*) FILTER (
         WHERE (created_at AT TIME ZONE $1) >= $2::timestamp
           AND (created_at AT TIME ZONE $1) <  $3::timestamp
       )::int AS new_users,
       COUNT(*)::int AS total_users
     FROM users`,
    [TZ, from, to]
  );

  // Guruhlarni mahsulot turi bo'yicha yig'amiz
  const byType = new Map();
  let revenue = 0;
  let totalCost = 0;
  let orders = 0;
  /** Tannarxi noma'lum turlar — foydaga qo'shilmaydi, ochiq ko'rsatiladi */
  let unknownRevenue = 0;

  for (const r of prodRes.rows) {
    const type = r.order_type;
    const unit = Number(r.type_amount) || 0;
    const cnt = Number(r.orders) || 0;
    const rev = Number(r.revenue) || 0;
    const { cost: c, known } = costFor(cost, type, unit, cnt);

    const meta = PRODUCT_META[type] || { label: type, icon: "📦" };
    const acc = byType.get(type) || {
      type, label: meta.label, icon: meta.icon,
      orders: 0, quantity: 0, revenue: 0, cost: 0, unknown_revenue: 0,
    };
    acc.orders += cnt;
    acc.quantity += unit * cnt;
    acc.revenue += rev;
    // Tannarxi noma'lum guruhning tushumi ham, tannarxi ham alohida
    // yuritiladi — aks holda butun mahsulot "noma'lum" bo'lib qolardi.
    if (known) acc.cost += c;
    else acc.unknown_revenue += rev;
    byType.set(type, acc);

    revenue += rev;
    orders += cnt;
    if (known) totalCost += c;
    else unknownRevenue += rev;
  }

  const products = [...byType.values()].map((p) => {
    // Foyda FAQAT tannarxi ma'lum tushumdan hisoblanadi — 0 tannarx bilan
    // hisoblasak, marja 98% bo'lib chiqadi va bu yolg'on. Lekin butun
    // mahsulotni "noma'lum" deb yopib qo'yish ham noto'g'ri: masalan
    // premium'ning 268 buyurtmasidan atigi 23 tasi (1 oylik) modelga
    // kirmaydi — qolgan 245 tasining foydasi ko'rinishi kerak.
    const knownRev = p.revenue - p.unknown_revenue;
    const comm = Math.round((knownRev * cost.commissionPercent) / 100);
    const profit = knownRev > 0 ? knownRev - p.cost - comm : null;
    return {
      type: p.type, label: p.label, icon: p.icon,
      orders: p.orders, quantity: p.quantity, revenue: p.revenue,
      profit,
      margin: knownRev > 0 ? (profit / knownRev) * 100 : null,
      /** false → bu mahsulotning bir qismi foydaga kirmagan */
      cost_known: p.unknown_revenue === 0,
      /** tannarxi modelga kirmagan tushum (foydadan tashqarida) */
      unknown_cost_revenue: p.unknown_revenue,
    };
  }).sort((a, b) => b.revenue - a.revenue);

  // Foyda FAQAT tannarxi ma'lum tushumdan hisoblanadi
  const knownRevenue = revenue - unknownRevenue;
  const commission = Math.round((knownRevenue * cost.commissionPercent) / 100);
  const profit = knownRevenue - totalCost - commission;
  const u = usersRes.rows[0] || { new_users: 0, total_users: 0 };

  return {
    users: { new: u.new_users, total: u.total_users },
    orders,
    buyers: buyersRes.rows[0]?.buyers || 0,
    revenue,
    cost: totalCost,
    commission,
    profit,
    margin: knownRevenue > 0 ? (profit / knownRevenue) * 100 : 0,
    /** Tannarxi modelga kiritilmagan tushum — foydaga kirmagan */
    unknown_cost_revenue: unknownRevenue,
    avg_order: orders > 0 ? Math.round(revenue / orders) : 0,
    products,
  };
}

/**
 * Endpointni ro'yxatga oladi.
 *
 * server.js ga qo'shish:
 *   import { registerCompareMetrics } from "./modules/compareMetrics/index.js";
 *   registerCompareMetrics(app, pool);
 *
 * .env ga qo'shish:
 *   COMPARE_SECRET=<uzun tasodifiy satr>
 */
export function registerCompareMetrics(app, pool) {
  const SECRET = (process.env.COMPARE_SECRET || "").trim();

  if (!SECRET) {
    console.warn("⚠️ COMPARE_SECRET sozlanmagan — /api/metrics/compare YOPIQ");
  }

  /** Bearer kalitni tekshiradi. true qaytsa javob allaqachon yuborilgan. */
  const denied = (req, res) => {
    if (!SECRET) {
      res.status(503).json({ ok: false, error: "COMPARE_SECRET sozlanmagan" });
      return true;
    }
    const auth = String(req.headers.authorization || "");
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (token !== SECRET) {
      res.status(401).json({ ok: false, error: "Ruxsat yo'q" });
      return true;
    }
    return false;
  };

  // ─────────────────────────────────────────────────────────────────
  // Qo'shni loyihalar: bitta so'rovda uchalasining ma'lumoti.
  //
  // Nega shu yo'l: uzgets va premiumsend ham SHU serverda, sxemasi bir xil
  // (bir kod bazasidan forklangan). Har biriga alohida endpoint qo'yish
  // o'rniga StarsJoy ularning bazasiga kichik, faqat-o'qish ulanish qilib
  // ma'lumotni o'zi yig'adi — qabul qiluvchi tomonda bitta manzil yetadi.
  //
  // ⚠️ Mavjud /api/metrics/compare TEGILMAGAN: unga qarab yozilgan puller
  //    ishlashda davom etadi. Bu yangi, alohida marshrut.
  // ─────────────────────────────────────────────────────────────────
  app.get("/api/metrics/compare/all", async (req, res) => {
    if (denied(req, res)) return;
    try {
      const p = periods();
      const entries = await Promise.all(
        NEIGHBOURS.map(async (n) => {
          // Bir bazaning ishlamasligi qolganlarini yiqitmasin — har biri
          // alohida ushlanadi va o'z xatosi bilan qaytadi.
          try {
            const target = n.key === PROJECT_KEY ? pool : neighbourPool(n);
            if (!target) {
              return [n.key, { ok: false, error: `${n.env} sozlanmagan` }];
            }
            const cost = costModelFor(n.key);
            const [today, week, month, all] = await Promise.all([
              periodMetrics(target, p.today, cost),
              periodMetrics(target, p.week, cost),
              periodMetrics(target, p.month, cost),
              periodMetrics(target, p.all, cost),
            ]);
            return [n.key, {
              ok: true,
              project: n.key,
              label: n.label,
              currency: "UZS",
              cost_model: costModelSummary(cost),
              periods: { today, week, month, all },
            }];
          } catch (err) {
            console.error(`❌ /api/metrics/compare/all [${n.key}]:`, err.message);
            return [n.key, { ok: false, project: n.key, error: String(err.message || err) }];
          }
        })
      );

      res.json({
        ok: true,
        generated_at: new Date().toISOString(),
        currency: "UZS",
        projects: Object.fromEntries(entries),
      });
    } catch (err) {
      console.error("❌ /api/metrics/compare/all:", err);
      res.status(500).json({ ok: false, error: "Server xatosi" });
    }
  });

  app.get("/api/metrics/compare", async (req, res) => {
    // Kalit yo'q bo'lsa endpoint umuman ishlamaydi: ochiq qoldirish
    // moliyaviy ma'lumotni internetga chiqarib qo'yish demakdir.
    if (denied(req, res)) return;
    try {
      const p = periods();
      const cost = costModelFor(PROJECT_KEY);
      const [today, week, month, all] = await Promise.all([
        periodMetrics(pool, p.today, cost),
        periodMetrics(pool, p.week, cost),
        periodMetrics(pool, p.month, cost),
        periodMetrics(pool, p.all, cost),
      ]);

      res.json({
        ok: true,
        project: PROJECT_KEY,
        generated_at: new Date().toISOString(),
        currency: "UZS",
        cost_model: costModelSummary(cost),
        periods: { today, week, month, all },
      });
    } catch (err) {
      console.error("❌ /api/metrics/compare:", err);
      res.status(500).json({ ok: false, error: "Server xatosi" });
    }
  });

  const ready = NEIGHBOURS.filter(
    (n) => n.key === PROJECT_KEY || process.env[n.env]
  ).length;
  console.log(
    `📊 Compare metrics: /api/metrics/compare (loyiha: ${PROJECT_KEY}) ` +
      `+ /api/metrics/compare/all (${ready}/${NEIGHBOURS.length} loyiha ulangan)`
  );
}
