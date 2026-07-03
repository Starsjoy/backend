#!/usr/bin/env node
/**
 * abarot.js — May va Iyun (Toshkent vaqti) muvaffaqiyatli sotuvlar:
 * har oy alohida + umumiy jami (stars / premium / gift, kunlik, log).
 *
 * AdminPanel analitikasi bilan mos statuslar.
 *
 * Ishlatish:
 *   cd backend && node abarot.js           — joriy yil, may + iyun
 *   node abarot.js 2026                    — aniq yil
 *   ABAROT_YEAR=2026 node abarot.js
 *   node abarot.js --json                  — JSON chiqish
 *
 * Talab: .env da DATABASE_URL
 */
import "dotenv/config";
import pg from "pg";

const { Pool } = pg;

const SUCCESS_STATUSES = [
  "stars_sent",
  "premium_sent",
  "gift_sent",
  "completed",
  "delivered",
  "accepted",
];

const ALL_ORDER_TYPES = [
  "stars",
  "stars_usdt",
  "stars_paymee",
  "premium",
  "premium_usdt",
  "premium_paymee",
  "gift",
];

const TZ = "Asia/Tashkent";

/** @type {{ key: string, title: string, rangeLabel: string, month: number }[]} */
const REPORT_MONTHS = [
  {
    key: "may",
    title: "MAY",
    rangeLabel: "1 may – 31 may",
    month: 5,
  },
  {
    key: "june",
    title: "IYUN",
    rangeLabel: "1 iyun – 30 iyun",
    month: 6,
  },
];

function monthPeriodBounds(year, month) {
  const mm = String(month).padStart(2, "0");
  const nextMonth = month === 12 ? 1 : month + 1;
  const nextYear = month === 12 ? year + 1 : year;
  const nmm = String(nextMonth).padStart(2, "0");
  return {
    startLocal: `${year}-${mm}-01 00:00:00`,
    endExclusiveLocal: `${nextYear}-${nmm}-01 00:00:00`,
  };
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

function formatMoney(n) {
  return `${formatUz(n)} so'm`;
}

function dayKeyInTashkent(date) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

function normalizeOrderType(orderType) {
  const t = String(orderType || "").toLowerCase();
  if (t.includes("premium")) return "premium";
  if (t === "gift") return "gift";
  return "stars";
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

function emptyByType() {
  return {
    stars: { count: 0, summ: 0, units: 0 },
    premium: { count: 0, summ: 0, units: 0 },
    gift: { count: 0, summ: 0, units: 0 },
  };
}

function mergeByType(a, b) {
  const out = emptyByType();
  for (const key of ["stars", "premium", "gift"]) {
    out[key].count = a[key].count + b[key].count;
    out[key].summ = a[key].summ + b[key].summ;
    out[key].units = a[key].units + b[key].units;
  }
  return out;
}

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
    ALL_ORDER_TYPES,
  ]);
  return rows;
}

function aggregate(rows) {
  const byType = emptyByType();
  const byDay = new Map();

  for (const r of rows) {
    const t = normalizeOrderType(r.order_type);
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

  const dailySorted = [...byDay.keys()].sort().map((k) => byDay.get(k));

  return { byType, totalSumm, totalCount, dailySorted };
}

function typeSummaryRows(byType, totalCount, totalSumm) {
  return [
    [
      "Stars",
      byType.stars.count,
      formatUz(byType.stars.summ),
      `${formatUz(byType.stars.units)} ⭐`,
    ],
    [
      "Premium",
      byType.premium.count,
      formatUz(byType.premium.summ),
      `${formatUz(byType.premium.units)} oy`,
    ],
    [
      "Gift",
      byType.gift.count,
      formatUz(byType.gift.summ),
      formatUz(byType.gift.units),
    ],
    ["JAMI", totalCount, formatUz(totalSumm), "—"],
  ];
}

function printMonthBlock(meta, rows, agg) {
  const { title, rangeLabel, year, startLocal, endExclusiveLocal } = meta;
  const { byType, totalSumm, totalCount, dailySorted } = agg;

  console.log("");
  console.log("┌─────────────────────────────────────────────────────────────┐");
  console.log(`│  ${title} — ${rangeLabel} ${year} (${TZ})`.padEnd(62) + "│");
  console.log(`│  ${startLocal}  →  ${endExclusiveLocal}`.padEnd(62) + "│");
  console.log("└─────────────────────────────────────────────────────────────┘");
  console.log("");

  console.log("  Umumiy abarot");
  console.log(`    Sotuvlar soni : ${formatUz(totalCount)} ta`);
  console.log(`    Jami tushum   : ${formatMoney(totalSumm)}`);
  console.log("");

  printTable(
    ["Tur", "Soni", "Tushum (so'm)", "Birliklar"],
    typeSummaryRows(byType, totalCount, totalSumm),
  );
  console.log("");

  console.log("  Kunlik abarot");
  if (dailySorted.length === 0) {
    console.log("    (shu oyda muvaffaqiyatli sotuv yo'q)");
  } else {
    printTable(
      ["Sana", "Jami so'm", "Sotuv", "Stars", "Premium", "Gift"],
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

  console.log(`  Sotuvlar logi: ${rows.length} ta yozuv`);
  if (rows.length > 0) {
    console.log(
      "  id | sana(TZ) | tur | summ | birlik | status | oluvchi",
    );
    console.log("  " + "-".repeat(100));
    for (const r of rows) {
      const dt = new Intl.DateTimeFormat("uz-UZ", {
        timeZone: TZ,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      }).format(new Date(r.created_at));
      console.log(
        [
          `  ${r.id}`,
          dt,
          normalizeOrderType(r.order_type),
          formatUz(r.summ),
          r.type_amount,
          r.status,
          (r.recipient_username || r.recipient || "").slice(0, 20),
        ].join(" | "),
      );
    }
  }
}

function printCombinedBlock(year, mayAgg, juneAgg) {
  const combinedType = mergeByType(mayAgg.byType, juneAgg.byType);
  const totalCount = mayAgg.totalCount + juneAgg.totalCount;
  const totalSumm = mayAgg.totalSumm + juneAgg.totalSumm;

  console.log("");
  console.log("╔═════════════════════════════════════════════════════════════╗");
  console.log(`║  UMUMIY ABAROT — MAY + IYUN ${year}`.padEnd(62) + "║");
  console.log("╠═════════════════════════════════════════════════════════════╣");
  console.log(`║  Jami sotuvlar : ${formatUz(totalCount)} ta`.padEnd(62) + "║");
  console.log(`║  Jami tushum   : ${formatMoney(totalSumm)}`.padEnd(62) + "║");
  console.log("╚═════════════════════════════════════════════════════════════╝");
  console.log("");

  printTable(
    ["Oy / tur", "Soni", "Tushum (so'm)", "Birliklar"],
    [
      [
        "May — Stars",
        mayAgg.byType.stars.count,
        formatUz(mayAgg.byType.stars.summ),
        `${formatUz(mayAgg.byType.stars.units)} ⭐`,
      ],
      [
        "May — Premium",
        mayAgg.byType.premium.count,
        formatUz(mayAgg.byType.premium.summ),
        `${formatUz(mayAgg.byType.premium.units)} oy`,
      ],
      [
        "May — Gift",
        mayAgg.byType.gift.count,
        formatUz(mayAgg.byType.gift.summ),
        formatUz(mayAgg.byType.gift.units),
      ],
      [
        "May JAMI",
        mayAgg.totalCount,
        formatUz(mayAgg.totalSumm),
        "—",
      ],
      ["", "", "", ""],
      [
        "Iyun — Stars",
        juneAgg.byType.stars.count,
        formatUz(juneAgg.byType.stars.summ),
        `${formatUz(juneAgg.byType.stars.units)} ⭐`,
      ],
      [
        "Iyun — Premium",
        juneAgg.byType.premium.count,
        formatUz(juneAgg.byType.premium.summ),
        `${formatUz(juneAgg.byType.premium.units)} oy`,
      ],
      [
        "Iyun — Gift",
        juneAgg.byType.gift.count,
        formatUz(juneAgg.byType.gift.summ),
        formatUz(juneAgg.byType.gift.units),
      ],
      [
        "Iyun JAMI",
        juneAgg.totalCount,
        formatUz(juneAgg.totalSumm),
        "—",
      ],
      ["", "", "", ""],
      ...typeSummaryRows(combinedType, totalCount, totalSumm).map((row, i) =>
        i === 3 ? ["2 OY JAMI", ...row.slice(1)] : row,
      ),
    ],
  );
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

  const pool = new Pool({ connectionString: process.env.DATABASE_URL });

  try {
    const periods = {};

    for (const m of REPORT_MONTHS) {
      const bounds = monthPeriodBounds(year, m.month);
      const rows = await fetchSalesRows(
        pool,
        bounds.startLocal,
        bounds.endExclusiveLocal,
      );
      const agg = aggregate(rows);
      periods[m.key] = {
        title: m.title,
        rangeLabel: m.rangeLabel,
        range: bounds,
        summary: {
          totalCount: agg.totalCount,
          totalSumm: agg.totalSumm,
          byType: agg.byType,
        },
        daily: agg.dailySorted,
        sales: rows,
      };
    }

    const mayAgg = {
      ...periods.may.summary,
      byType: periods.may.summary.byType,
      dailySorted: periods.may.daily,
    };
    const juneAgg = {
      ...periods.june.summary,
      byType: periods.june.summary.byType,
      dailySorted: periods.june.daily,
    };

    const combinedType = mergeByType(mayAgg.byType, juneAgg.byType);
    const combined = {
      totalCount: mayAgg.totalCount + juneAgg.totalCount,
      totalSumm: mayAgg.totalSumm + juneAgg.totalSumm,
      byType: combinedType,
    };

    if (json) {
      console.log(
        JSON.stringify(
          {
            year,
            timezone: TZ,
            statuses: SUCCESS_STATUSES,
            orderTypes: ALL_ORDER_TYPES,
            periods,
            combined,
          },
          (_, v) => (typeof v === "bigint" ? v.toString() : v),
          2,
        ),
      );
      return;
    }

    console.log("");
    console.log("═══════════════════════════════════════════════════════════");
    console.log(`  ABAROT HISOBOTI — ${year} (May va Iyun, ${TZ})`);
    console.log("═══════════════════════════════════════════════════════════");

    for (const m of REPORT_MONTHS) {
      const p = periods[m.key];
      printMonthBlock(
        {
          title: m.title,
          rangeLabel: m.rangeLabel,
          year,
          startLocal: p.range.startLocal,
          endExclusiveLocal: p.range.endExclusiveLocal,
        },
        p.sales,
        {
          byType: p.summary.byType,
          totalSumm: p.summary.totalSumm,
          totalCount: p.summary.totalCount,
          dailySorted: p.daily,
        },
      );
    }

    printCombinedBlock(year, mayAgg, juneAgg);
  } finally {
    await pool.end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
