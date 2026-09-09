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
 * TANNARX MODELI — .env dan sozlanadi.
 *
 * ⚠️ Bu loyihada tannarx jadvali yo'q edi, shuning uchun model shu yerda.
 *    Qiymatlarni .env da to'g'rilang, aks holda foyda noto'g'ri chiqadi.
 */
const COST = {
  usdToUzs: Number(process.env.COMPARE_USD_TO_UZS) || 12200,
  /** N dona stars necha dollarga olinadi */
  starsPer: Number(process.env.COMPARE_STARS_COST_PER) || 50,
  starsUsd: Number(process.env.COMPARE_STARS_COST_USD) || 0.75,
  /** Premium: oy → dollar */
  premiumUsd: {
    3: Number(process.env.COMPARE_PREMIUM_3_USD) || 12,
    6: Number(process.env.COMPARE_PREMIUM_6_USD) || 16,
    12: Number(process.env.COMPARE_PREMIUM_12_USD) || 29,
  },
  /** To'lov tizimi komissiyasi, % */
  commissionPercent: Number(process.env.COMPARE_COMMISSION_PERCENT) || 2,
};

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

// ═══════════════════════════════════════════════════════════════════

/** Bir dona stars tannarxi (so'mda) */
function starCostUzs() {
  if (!COST.starsPer) return 0;
  return (COST.starsUsd / COST.starsPer) * COST.usdToUzs;
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
function costFor(type, unitAmount, count) {
  const fam = costFamily(type);
  if (fam === "stars") {
    return { cost: Math.round(unitAmount * count * starCostUzs()), known: true };
  }
  if (fam === "premium") {
    const usd = COST.premiumUsd[unitAmount];
    // Noma'lum muddat (masalan 1 oylik) — taxmin qilmaymiz
    if (!usd) return { cost: 0, known: false };
    return { cost: Math.round(usd * COST.usdToUzs * count), known: true };
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
async function periodMetrics(pool, { from, to }) {
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
  let cost = 0;
  let orders = 0;
  /** Tannarxi noma'lum turlar — foydaga qo'shilmaydi, ochiq ko'rsatiladi */
  let unknownRevenue = 0;

  for (const r of prodRes.rows) {
    const type = r.order_type;
    const unit = Number(r.type_amount) || 0;
    const cnt = Number(r.orders) || 0;
    const rev = Number(r.revenue) || 0;
    const { cost: c, known } = costFor(type, unit, cnt);

    const meta = PRODUCT_META[type] || { label: type, icon: "📦" };
    const acc = byType.get(type) || {
      type, label: meta.label, icon: meta.icon,
      orders: 0, quantity: 0, revenue: 0, cost: 0, cost_known: true,
    };
    acc.orders += cnt;
    acc.quantity += unit * cnt;
    acc.revenue += rev;
    acc.cost += c;
    if (!known) acc.cost_known = false;
    byType.set(type, acc);

    revenue += rev;
    orders += cnt;
    if (known) cost += c;
    else unknownRevenue += rev;
  }

  const products = [...byType.values()].map((p) => {
    const comm = Math.round((p.revenue * COST.commissionPercent) / 100);
    // Tannarxi noma'lum bo'lsa foyda ko'rsatmaymiz — 0 tannarx bilan
    // hisoblasak, marja 98% bo'lib chiqadi va bu yolg'on.
    const profit = p.cost_known ? p.revenue - p.cost - comm : null;
    return {
      type: p.type, label: p.label, icon: p.icon,
      orders: p.orders, quantity: p.quantity, revenue: p.revenue,
      profit,
      margin: p.cost_known && p.revenue > 0 ? (profit / p.revenue) * 100 : null,
      cost_known: p.cost_known,
    };
  }).sort((a, b) => b.revenue - a.revenue);

  // Foyda FAQAT tannarxi ma'lum tushumdan hisoblanadi
  const knownRevenue = revenue - unknownRevenue;
  const commission = Math.round((knownRevenue * COST.commissionPercent) / 100);
  const profit = knownRevenue - cost - commission;
  const u = usersRes.rows[0] || { new_users: 0, total_users: 0 };

  return {
    users: { new: u.new_users, total: u.total_users },
    orders,
    buyers: buyersRes.rows[0]?.buyers || 0,
    revenue,
    cost,
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

  app.get("/api/metrics/compare", async (req, res) => {
    // ── Autentifikatsiya ──
    // Kalit yo'q bo'lsa endpoint umuman ishlamaydi: ochiq qoldirish
    // moliyaviy ma'lumotni internetga chiqarib qo'yish demakdir.
    if (!SECRET) {
      return res.status(503).json({ ok: false, error: "COMPARE_SECRET sozlanmagan" });
    }
    const auth = String(req.headers.authorization || "");
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (token !== SECRET) {
      return res.status(401).json({ ok: false, error: "Ruxsat yo'q" });
    }

    try {
      const p = periods();
      const [today, week, month, all] = await Promise.all([
        periodMetrics(pool, p.today),
        periodMetrics(pool, p.week),
        periodMetrics(pool, p.month),
        periodMetrics(pool, p.all),
      ]);

      res.json({
        ok: true,
        project: PROJECT_KEY,
        generated_at: new Date().toISOString(),
        currency: "UZS",
        cost_model: {
          usd_to_uzs: COST.usdToUzs,
          star_cost_uzs: Number(starCostUzs().toFixed(2)),
          commission_percent: COST.commissionPercent,
        },
        periods: { today, week, month, all },
      });
    } catch (err) {
      console.error("❌ /api/metrics/compare:", err);
      res.status(500).json({ ok: false, error: "Server xatosi" });
    }
  });

  console.log(`📊 Compare metrics: /api/metrics/compare (loyiha: ${PROJECT_KEY})`);
}
