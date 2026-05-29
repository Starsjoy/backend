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

  const usdtMatch = [
    ["MATCH_API_STARS_USDT", process.env.MATCH_API_STARS_USDT],
    ["MATCH_API_PREMIUM_USDT", process.env.MATCH_API_PREMIUM_USDT],
  ];
  for (const [key, val] of usdtMatch) {
    if (!val || !String(val).trim()) {
      console.warn(`⚠️ ${key} yo'q — Fragment/USDT buyurtmalar SMS orqali tasdiqlanmaydi`);
    }
  }

  if (process.env.STARS_PURCHASE_MODE === "fragment") {
    if (!process.env.SEED?.trim() || !process.env.API_KEY?.trim()) {
      console.warn("⚠️ STARS_PURCHASE_MODE=fragment, lekin SEED yoki API_KEY .env da yo'q");
    }
  }

  const port = process.env.PORT || "5001";
  if (!process.env.INTERNAL_API_BASE) {
    process.env.INTERNAL_API_BASE = `http://127.0.0.1:${port}`;
  }

  console.log("✅ .env asosiy kalitlar tekshirildi");
  console.log(`   PORT=${port} | USDT match: ${process.env.MATCH_API_STARS_USDT ? "bor" : "yo'q"}`);
}

function validatePythonFragmentDeps() {
  const py = process.env.PYTHON_PATH || (process.platform === "win32" ? "python" : "python3");
  const r = spawnSync(py, ["-c", "import dotenv"], {
    cwd: __dirname,
    encoding: "utf8",
  });
  if (r.status !== 0) {
    console.error("❌ Python: dotenv moduli yo'q (Fragment stars/premium ishlamaydi)");
    console.error("   cd backend && pip3 install -r requirements.txt");
    console.error("   yoki: npm run fragment:install");
    return false;
  }
  console.log("✅ Python dotenv tayyor (Fragment CLI)");
  return true;
}

// =============================
// Eski pending orderlarni expired qilish
// =============================
async function runCleanup() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    console.log("🧹 Pending orderlar tozalanmoqda...");
    const updateQuery = await pool.query(
      `UPDATE orders
       SET payment_status = 'expired', status = 'expired'
       WHERE payment_status = 'pending' OR status = 'pending'`
    );
    console.log(`✅ ${updateQuery.rowCount} ta order expired qilindi`);
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
validatePythonFragmentDeps();
await runCleanup();

console.log("\n🔥 StarsJoy backend — parallel ishga tushmoqda\n");

runScript("API server", "server.js");
runScript("Telegram bot", "token.js");
runScript("SMS listener", "balanceChecker.js");

console.log("\n✅ Hammasi ishga tushirildi:");
console.log("   • API:        server.js (PORT=" + (process.env.PORT || 5001) + ")");
console.log("   • Bot:        token.js");
console.log("   • SMS/Match:  balanceChecker.js (HTTP :5002)");
console.log("   To'xtatish: Ctrl+C\n");
