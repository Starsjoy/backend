import { fork } from "child_process";

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
// 1) Express backend (server.js)
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
