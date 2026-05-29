/**
 * StarsJoy — barcha backend jarayonlarini bir joyda ishga tushiradi:
 *   1. server.js      — API, order, Fragment/USDT, admin
 *   2. token.js       — Telegraf bot (buyruqlar, broadcast)
 *   3. balanceChecker.js — UZCARD SMS + match zanjiri (Robyn + USDT)
 */
import { fork, spawnSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";
import dotenv from "dotenv";
import { validateFragmentWalletEnv } from "./modules/usdtStars/walletEnv.js";
import {
  fragmentEnvReadyAsync,
  verifyFragmentCookies,
} from "./modules/usdtStars/fragmentDelivery.js";
import {
  ensureTokensTable,
  seedFragmentTokensFromEnvIfEmpty,
  syncFragmentTokensFromEnvIfMissing,
} from "./modules/tokens/tokensDb.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, ".env") });

const { Pool } = pg;

const children = new Map();

// =============================
// .env tekshiruvi (usdt.md)
// =============================
function validateEnv() {
  const required = [
    ["DATABASE_URL", process.env.DATABASE_URL],
    ["INTERNAL_API_SECRET", process.env.INTERNAL_API_SECRET],
    ["MATCH_API_STARS", process.env.MATCH_API_STARS],
    ["MATCH_API_PREMIUM", process.env.MATCH_API_PREMIUM],
    ["BOT_TOKEN", process.env.BOT_TOKEN],
    ["TG_API_ID", process.env.TG_API_ID],
    ["TG_API_HASH", process.env.TG_API_HASH],
    ["TG_SESSION", process.env.TG_SESSION],
    ["UZCARD_CHAT_ID", process.env.UZCARD_CHAT_ID],
    ["TARGET_CARD_SUFFIX", process.env.TARGET_CARD_SUFFIX],
  ];

  const missing = required.filter(([, v]) => !v || !String(v).trim()).map(([k]) => k);
  if (missing.length) {
    console.error("❌ .env da yetishmayotgan o'zgaruvchilar:", missing.join(", "));
    process.exit(1);
  }

  const altMatch = [
    ["MATCH_API_STARS_PAYMEE", process.env.MATCH_API_STARS_PAYMEE],
    ["MATCH_API_PREMIUM_PAYMEE", process.env.MATCH_API_PREMIUM_PAYMEE],
    ["MATCH_API_STARS_USDT", process.env.MATCH_API_STARS_USDT],
    ["MATCH_API_PREMIUM_USDT", process.env.MATCH_API_PREMIUM_USDT],
  ];
  for (const [key, val] of altMatch) {
    if (!val || !String(val).trim()) {
      console.warn(`⚠️ ${key} yo'q — tegishli buyurtmalar SMS orqali tasdiqlanmaydi`);
    }
  }

  if (process.env.MATCH_API_STARS_PAYMEE?.trim()) {
    if (!process.env.STARS_PAYMEE_API_URL?.trim() || !process.env.STARS_PAYMEE_API_KEY?.trim()) {
      console.warn(
        "⚠️ MATCH_API_STARS_PAYMEE bor, lekin STARS_PAYMEE_API_URL / STARS_PAYMEE_API_KEY yo'q — yetkazish ishlamaydi"
      );
    } else {
      console.log(`✅ Paymee .env: ${process.env.STARS_PAYMEE_API_URL}`);
      import("./modules/paymeeClient/index.js")
        .then(({ verifyPaymeeApiReachable }) => verifyPaymeeApiReachable())
        .then((r) => {
          if (r.ok) {
            console.log(
              `✅ Partner API ulanish OK (${r.url}) fragment_ready=${r.fragment_ready}`
            );
          } else {
            console.error(`❌ Partner API ulanish XATO (${r.url}): ${r.error}`);
            console.error(
              "   starstg.uz ko‘pincha faqat frontend — provider backend URL + nginx /api/purchase/ proxy kerak"
            );
          }
        })
        .catch((e) => console.error("❌ Partner API tekshiruv:", e.message));
    }
  }

  if (process.env.SEED?.trim() || process.env.MATCH_API_STARS_USDT) {
    const w = validateFragmentWalletEnv();
    if (!w.ok) {
      console.error(`❌ Fragment hamyon: ${w.error}`);
    } else {
      console.log(`✅ Fragment SEED: ${w.wordCount} so'z (to'g'ri)`);
    }
  }

  const port = process.env.PORT || "5001";
  if (!process.env.INTERNAL_API_BASE) {
    process.env.INTERNAL_API_BASE = `http://127.0.0.1:${port}`;
  }

  console.log("✅ .env asosiy kalitlar tekshirildi");
  console.log(
    `   PORT=${port} | Paymee match: ${process.env.MATCH_API_STARS_PAYMEE ? "bor" : "yo'q"} | USDT: ${process.env.MATCH_API_STARS_USDT ? "bor" : "yo'q"}`
  );
}

/** starspaymeeorg: ishga tushishda Fragment cookie + hamyon tekshiruvi */
async function checkFragmentOnBoot() {
  if (!process.env.DATABASE_URL?.trim()) return;

  const bootPool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    await ensureTokensTable(bootPool);
    await seedFragmentTokensFromEnvIfEmpty(bootPool);
    await syncFragmentTokensFromEnvIfMissing(bootPool);

    if (!(await fragmentEnvReadyAsync(bootPool))) {
      console.warn(
        "⚠️ Fragment: SEED/API_KEY .env yoki tokens jadvalida fragment_ssid/token to'ldiring"
      );
      return;
    }
    console.log("✅ Fragment: tokens + hamyon (.env) topildi");

    const cookieCheck = await verifyFragmentCookies(bootPool);
    if (cookieCheck.ok) {
      console.log(
        `✅ Fragment cookie/session: OK (HTTP ${cookieCheck.http_check?.status ?? cookieCheck.status ?? 200})`
      );
      if (cookieCheck.pyfragment_check && !cookieCheck.pyfragment_check.ok) {
        console.warn(
          "⚠️ Python verify ikkilamchi:",
          cookieCheck.pyfragment_check.error || "javob o'qilmadi (cookie HTTP baribir OK)"
        );
      }
    } else {
      console.error(
        "❌ Fragment cookie/session:",
        cookieCheck.error || `HTTP ${cookieCheck.status ?? "?"}`
      );
      if (cookieCheck.hints?.length) {
        cookieCheck.hints.forEach((h) => console.error("   →", h));
      }
    }

    const pay = (process.env.FRAGMENT_PAYMENT_METHOD || "ton").trim().toLowerCase();
    console.log(
      `💰 Fragment to'lov usuli (.env): ${pay === "usdt_ton" || pay === "usdt" ? "usdt_ton" : "ton"} (admin settings ham bor)`
    );
  } catch (e) {
    console.error("❌ Fragment boot tekshiruv:", e.message);
  } finally {
    await bootPool.end();
  }
}

async function validatePythonFragmentDeps() {
  const { resolvePythonCommand, venvPythonExists } = await import(
    "./modules/usdtStars/pythonPath.js"
  );
  const py = resolvePythonCommand();
  const r = spawnSync(py, ["-c", "import dotenv"], {
    cwd: __dirname,
    encoding: "utf8",
  });
  if (r.status !== 0) {
    console.error("❌ Python: dotenv moduli yo'q (Fragment stars/premium ishlamaydi)");
    console.error(`   Python: ${py}`);
    if (!venvPythonExists()) {
      console.error("   Ubuntu PEP 668: npm run fragment:install");
      console.error("   (venv: node scripts/setup-python-venv.mjs)");
    } else {
      console.error("   Qayta: npm run fragment:install");
    }
    return false;
  }
  console.log(`✅ Python Fragment tayyor: ${py}`);
  return true;
}

// =============================
// Eski pending orderlarni expired qilish
// =============================
async function runCleanup() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    console.log("🧹 15 daqiqadan eski pending orderlar expired qilinmoqda...");
    const updateQuery = await pool.query(
      `UPDATE orders
       SET payment_status = 'expired', status = 'expired'
       WHERE (payment_status = 'pending' OR status = 'pending')
         AND created_at < NOW() - INTERVAL '15 minutes'`
    );
    console.log(`✅ ${updateQuery.rowCount} ta eski pending expired (yangi pending saqlanadi)`);
  } catch (err) {
    console.error("❌ Tozalash xatosi:", err.message);
  } finally {
    await pool.end();
  }
}

// =============================
// Child process supervisor
// =============================
function runScript(label, filename) {
  const scriptPath = path.join(__dirname, filename);

  const child = fork(scriptPath, [], {
    cwd: __dirname,
    stdio: "inherit",
    env: { ...process.env },
  });

  children.set(label, child);

  child.on("exit", (code, signal) => {
    children.delete(label);
    if (signal) {
      console.log(`🛑 ${label} (${filename}) signal: ${signal}`);
    } else if (code !== 0 && code !== null) {
      console.error(`❌ ${label} (${filename}) to'xtadi, exit code: ${code}`);
    } else {
      console.log(`ℹ️ ${label} (${filename}) tugadi`);
    }
  });

  child.on("error", (err) => {
    console.error(`❌ ${label} (${filename}) fork xatosi:`, err.message);
  });

  console.log(`▶️  ${label} ishga tushdi → ${filename}`);
  return child;
}

function shutdownAll(signal) {
  console.log(`\n🛑 ${signal} — barcha jarayonlar to'xtatilmoqda...`);
  for (const [label, child] of children) {
    try {
      if (!child.killed) child.kill("SIGTERM");
    } catch (e) {
      console.warn(`⚠️ ${label} to'xtatilmadi:`, e.message);
    }
  }
  setTimeout(() => {
    for (const [, child] of children) {
      try {
        if (!child.killed) child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
    }
    process.exit(0);
  }, 5000);
}

process.on("SIGINT", () => shutdownAll("SIGINT"));
process.on("SIGTERM", () => shutdownAll("SIGTERM"));

// =============================
// Ishga tushirish
// =============================
validateEnv();
await checkFragmentOnBoot();
await validatePythonFragmentDeps();
await runCleanup();

console.log("\n🔥 StarsJoy backend — parallel ishga tushmoqda\n");

runScript("API server", "server.js");
runScript("Telegram bot", "token.js");
runScript("SMS listener", "balanceChecker.js");

console.log("\n✅ Hammasi ishga tushirildi:");
console.log("   • API:        server.js (PORT=" + (process.env.PORT || 5001) + ")");
console.log("   • Bot:        token.js");
console.log("   • SMS/Match:  balanceChecker.js (HTTP :5002)");
console.log("   • /stars      → RobynHood");
console.log("   • /usdtstars  → Fragment Stars (TON — admin/settings)");
console.log("   • /usdtpremium → Fragment Premium (TON)");
console.log("   To'xtatish: Ctrl+C\n");
