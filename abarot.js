#!/usr/bin/env node
/**
 * abarot.js — 14–30 aprel (Toshkent vaqti) muvaffaqiyatli sotuvlar: umumiy aylanma,
 * stars / premium / gift bo‘yicha, kunlik parchalanish va sotuvlar jadvali.
 *
 * AdminPanel.jsx analitikasi bilan mos: statuslar completed, stars_sent, premium_sent,
 * gift_sent, delivered, accepted.
 *
 * Ishlatish:
 *   cd backend && node abarot.js              — joriy yil, 14–30 aprel
 *   node abarot.js 2025                     — aniq yil
 *   ABAROT_YEAR=2025 node abarot.js
 *   node abarot.js --json                   — JSON chiqish (pipe / fayl)
 *
 * Talab: .env da DATABASE_URL
 */
import "dotenv/config";
import pg from "pg";

const { Pool } = pg;

/** AdminPanel + leaderboard bilan mos “muvaffaqiyatli” statuslar */
const SUCCESS_STATUSES = [
  "stars_sent",
  "premium_sent",
  "gift_sent",
  "completed",
  "delivered",
  "accepted",
];

const ORDER_TYPES = ["stars", "premium", "gift"];
const TZ = "Asia/Tashkent";

/** Aprel 14 (00:00) dan may 1 (00:00) gacha — 30-aprel kun oxirigacha */
function periodBoundsUtc(year) {
  const startLocal = `${year}-04-14 00:00:00`;
  const endExclusiveLocal = `${year}-05-01 00:00:00`;
  return { startLocal, endExclusiveLocal };
}

function parseArgs(argv) {
  const json = argv.includes("--json");
  const yearToken = argv.find((a) => /^\d{4}$/.test(a));
  const year = yearToken
    ? parseInt(yearToken, 10)
    : parseInt(process.env.ABAROT_YEAR || String(new Date().getFullYear()), 10);
  return { json, year };
}

function formatUz(n) {
  return new Intl.NumberFormat("uz-UZ").format(Number(n) || 0);
}

function dayKeyInTashkent(date) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

function pad(s, w) {
  const str = String(s);
  return str.length >= w ? str : str + " ".repeat(w - str.length);
}

function printTable(headers, rows) {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => String(r[i] ?? "").length)),
  );
  const line = (cells) =>
    cells.map((c, i) => pad(c, widths[i])).join("  |  ");
  console.log(line(headers));
  console.log(widths.map((w) => "-".repeat(w)).join("--+--"));
  for (const row of rows) console.log(line(row.map((c) => String(c ?? ""))));
}

/**
 * Bitta SELECT — bitta indeks oralig‘i bo‘yicha skan; statistikani Node da bir marta yig‘ish.
 */
async function fetchSalesRows(pool, startLocal, endExclusiveLocal) {
  const sql = `
    SELECT
      id,
      order_id,
      order_type,
      type_amount,
      summ,
      status,
      payment_status,
      recipient_username,
      recipient,
      applied_promocode,
      discount_amount,
      created_at
    FROM orders
    WHERE created_at >= ($1::timestamp AT TIME ZONE $3)
      AND created_at < ($2::timestamp AT TIME ZONE $3)
      AND status = ANY($4::text[])
      AND order_type = ANY($5::text[])
    ORDER BY created_at ASC, id ASC
  `;
  const { rows } = await pool.query(sql, [
    startLocal,
    endExclusiveLocal,
    TZ,
    SUCCESS_STATUSES,
    ORDER_TYPES,
  ]);
  return rows;
}

function aggregate(rows) {
  const byType = {
    stars: { count: 0, summ: 0, units: 0 },
    premium: { count: 0, summ: 0, units: 0 },
    gift: { count: 0, summ: 0, units: 0 },
  };
  const byDay = new Map();

  for (const r of rows) {
    const t = r.order_type;
    if (!byType[t]) continue;
    const summ = Number(r.summ) || 0;
    const units = Number(r.type_amount) || 0;

    byType[t].count += 1;
    byType[t].summ += summ;
    byType[t].units += units;

    const d = dayKeyInTashkent(new Date(r.created_at));
    if (!byDay.has(d)) {
      byDay.set(d, {
        date: d,
        stars_amount: 0,
        stars_count: 0,
        stars_units: 0,
        premium_amount: 0,
        premium_count: 0,
        premium_units: 0,
        gift_amount: 0,
        gift_count: 0,
        gift_units: 0,
        total_amount: 0,
        total_count: 0,
      });
    }
    const day = byDay.get(d);
    day.total_amount += summ;
    day.total_count += 1;
    if (t === "stars") {
      day.stars_amount += summ;
      day.stars_count += 1;
      day.stars_units += units;
    } else if (t === "premium") {
      day.premium_amount += summ;
      day.premium_count += 1;
      day.premium_units += units;
    } else if (t === "gift") {
      day.gift_amount += summ;
      day.gift_count += 1;
      day.gift_units += units;
    }
  }

  const totalSumm =
    byType.stars.summ + byType.premium.summ + byType.gift.summ;
  const totalCount =
    byType.stars.count + byType.premium.count + byType.gift.count;

  const dailySorted = [...byDay.keys()]
    .sort()
    .map((k) => byDay.get(k));

  return { byType, totalSumm, totalCount, dailySorted };
}

function printReport(year, startLocal, endExclusiveLocal, rows, agg) {
  console.log("");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`  ABAROT (sotuvlar) — ${year} yil, 14–30 aprel (${TZ})`);
  console.log(`  Oraliq: ${startLocal}  →  ${endExclusiveLocal} (30-aprel 23:59:59 gacha)`);
  console.log("═══════════════════════════════════════════════════════════");
  console.log("");

  const { byType, totalSumm, totalCount, dailySorted } = agg;

  console.log("── Umumiy (muvaffaqiyatli sotuvlar) ──");
  console.log(`  Buyurtmalar soni : ${formatUz(totalCount)}`);
  console.log(`  Jami tushum (UZS): ${formatUz(totalSumm)} so'm`);
  console.log("");

  printTable(
    ["Tur", "Soni", "Tushum (so'm)", "Birliklar (⭐/oy/sovg'a)"],
    [
      [
        "Stars",
        byType.stars.count,
        formatUz(byType.stars.summ),
        formatUz(byType.stars.units) + " ⭐",
      ],
      [
        "Premium",
        byType.premium.count,
        formatUz(byType.premium.summ),
        formatUz(byType.premium.units) + " oy",
      ],
      [
        "Gift",
        byType.gift.count,
        formatUz(byType.gift.summ),
        formatUz(byType.gift.units),
      ],
      ["JAMI", totalCount, formatUz(totalSumm), "—"],
    ],
  );
  console.log("");

  console.log("── Kunlik abarot ──");
  if (dailySorted.length === 0) {
    console.log("  (shu oralig'da yozuv yo'q)");
  } else {
    printTable(
      [
        "Sana",
        "Jami so'm",
        "Sotuv",
        "Stars so'm",
        "Pr. so'm",
        "Gift so'm",
      ],
      dailySorted.map((d) => [
        d.date,
        formatUz(d.total_amount),
        d.total_count,
        formatUz(d.stars_amount),
        formatUz(d.premium_amount),
        formatUz(d.gift_amount),
      ]),
    );
  }
  console.log("");

  console.log("── Sotuvlar logi (xronologik) ──");
  console.log(
    "id | sana(TZ) | tur | summ | birlik | status | oluvchi | promokod | chegirma",
  );
  console.log("-".repeat(120));
  for (const r of rows) {
    const dt = new Intl.DateTimeFormat("uz-UZ", {
      timeZone: TZ,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(new Date(r.created_at));
    const line = [
      r.id,
      dt,
      r.order_type,
      r.summ,
      r.type_amount,
      r.status,
      (r.recipient_username || r.recipient || "").slice(0, 24),
      r.applied_promocode || "",
      r.discount_amount || 0,
    ].join(" | ");
    console.log(line);
  }
  console.log("");
  console.log(`Jami qatorlar: ${rows.length}`);
  console.log("");
}

async function main() {
  const { json, year } = parseArgs(process.argv.slice(2));
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL .env da yo'q.");
    process.exit(1);
  }
  if (year < 2000 || year > 2100) {
    console.error("Noto'g'ri yil.");
    process.exit(1);
  }

  const { startLocal, endExclusiveLocal } = periodBoundsUtc(year);
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });

  try {
    const rows = await fetchSalesRows(pool, startLocal, endExclusiveLocal);
    const agg = aggregate(rows);

    if (json) {
      console.log(
        JSON.stringify(
          {
            year,
            timezone: TZ,
            range: { start: startLocal, endExclusive: endExclusiveLocal },
            statuses: SUCCESS_STATUSES,
            summary: {
              totalCount: agg.totalCount,
              totalSumm: agg.totalSumm,
              byType: agg.byType,
            },
            daily: agg.dailySorted,
            sales: rows,
          },
          (_, v) => (typeof v === "bigint" ? v.toString() : v),
          2,
        ),
      );
    } else {
      printReport(year, startLocal, endExclusiveLocal, rows, agg);
    }
  } finally {
    await pool.end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
