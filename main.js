import { fork } from "child_process";
import pg from "pg";
import dotenv from "dotenv";

dotenv.config();
const { Pool } = pg;

async function runCleanup() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    console.log("🧹 Barcha eski (pending) orderlarni tozalash (expired qilish)...");
    const updateQuery = await pool.query(
      "UPDATE orders SET payment_status = 'expired', status = 'expired' WHERE payment_status = 'pending' OR status = 'pending'"
    );
    console.log(`✅ Tozalash tugadi! ${updateQuery.rowCount} ta order 'expired' holatiga o'tdi.`);
  } catch (err) {
    console.error("❌ Tozalashda xato yuz berdi:", err.message);
  } finally {
    await pool.end();
  }
}

function runScript(path) {
  const ps = fork(path);
  ps.on("close", (code) => {
    console.log(`❌ ${path} to'xtadi (exit code: ${code})`);
  });
  ps.on("error", (err) => {
    console.error(`❌ ${path} xato:`, err);
  });
  return ps;
}

// =============================
// 1) Eski orderlarni bekor qilish
// =============================
await runCleanup();

// =============================
// 2) Express backend (server.js)
// =============================
console.log("🚀 Backend server starting...");
runScript("./server.js");

// ======================================
// 2) TelegramClient HUMO listener (balanceChecker.js ichiga ko'chirildi)
// ======================================
// ⚠️ bot.js ENDI ISHLATILMAYDI — bot.js va balanceChecker.js 
// ikkalasi ham TG_SESSION ishlatgani uchun BIRLASHTIRILDI
// SMS listener endi balanceChecker.js ichida ishlaydi
console.log("📡 HUMO parser → balanceChecker.js ichida ishlaydi");


// =============================
// 3) Telegraf bot (bot.js)
// =============================
console.log("🤖 Telegram bot starting...");
runScript("./token.js");

// =============================
// 4) Balance Checker (userbot)
// =============================
console.log("💰 Balance checker starting...");
runScript("./balanceChecker.js");

console.log("🔥 Hammasi parallel ishlayapti!");
