// =============================
//  Telegram Session Generator
//  GramJS orqali SESSION olish
// =============================

import { TelegramClient } from "telegram";
import { StringSession } from "telegram/sessions/index.js";
import input from "readline-sync";
import "dotenv/config";

// 🔐 SECURITY: Credentials .env dan olinadi, kodda ochiq yozilmaydi!
const apiId = Number(process.env.TG_API_ID);
const apiHash = process.env.TG_API_HASH;

if (!apiId || !apiHash) {
  console.error("❌ TG_API_ID va TG_API_HASH .env faylda bo'lishi kerak!");
  process.exit(1);
}

// Bo'sh session bilan boshlaymiz (yangi session hosil qiladi)
const stringSession = new StringSession("");

(async () => {
  console.log("=== TELEGRAM SESSION YARATISH BOSHLANDI ===");

  const client = new TelegramClient(stringSession, apiId, apiHash, {
    connectionRetries: 5,
  });

  await client.start({
    phoneNumber: async () =>
      input.question("📱 Telefon raqamingni +998... formatida kiriting: "),
    password: async () =>
      input.question("🔐 Ikki faktor parol (agar bo'lsa): "),
    phoneCode: async () =>
      input.question("✉️ Telegramdan kelgan kodni kiriting: "),
    onError: (err) => console.log("❌ Xatolik:", err),
  });

  console.log("\n🎉 Login muvaffaqiyatli!");
  console.log("\n🔑 SESSION STRING tayyor!");

  const session = client.session.save();

  console.log("\n==== SESSION BELOW ====\n");
  console.log(session);
  console.log("\n=======================");

})();
