import 'dotenv/config';
import { Telegraf, Markup } from 'telegraf';

const bot = new Telegraf(process.env.BOT_TOKEN);

// ADMIN IDS → array
const ADMIN_IDS = process.env.ADMIN_IDS.split(',').map(id => Number(id));

// Mini app URL
const APP_URL = process.env.WEBAPP_URL;

// Majburiy obuna kanali
const REQUIRED_CHANNEL = '@starsjoy';


// ===============================
// Kanalga obuna tekshirish
// ===============================
async function isSubscribed(ctx, userId) {
  try {
    const member = await ctx.telegram.getChatMember(REQUIRED_CHANNEL, userId);
    return ['member', 'administrator', 'creator'].includes(member.status);
  } catch (err) {
    // Agar bot kanalda admin bo'lmasa yoki xatolik bo'lsa
    console.error('❌ Obuna tekshirishda xato:', err?.message || err);
    return false;
  }
}

function getSubscribeText() {
  return `
📢 *Botdan foydalanish uchun kanalimizga obuna bo'ling!*

✅ Quyidagi tugma orqali kanalga obuna bo'ling
🔄 So'ng *"Tekshirish"* tugmasini bosing
`;
}

function getSubscribeKeyboard() {
  return Markup.inlineKeyboard([
    [Markup.button.url('📢 Kanalga obuna bo\'lish', 'https://t.me/starsjoy')],
    [Markup.button.callback('✅ Tekshirish', 'check_subscription')]
  ]);
}


// ===============================
// CHIROYLI START XABARI
// ===============================
function getStartText(name) {
  return `
🌟 *Starsjoy botiga xush kelibsiz, ${name}!*

Bu yerda siz quyidagi xizmatlardan foydalanishingiz mumkin:
- ⭐ *Stars* sotib olish
- 💎 *Premium* obuna sotib olish
Quyidagi tugmalardan foydalanib, kerakli bo‘limga o‘ting:
`;
}


// ===============================
// ADMIN START XABARI
// ===============================
function getAdminText(name) {
  return `
👑 *Admin panelga xush kelibsiz, ${name}!*

Quyida boshqaruv paneliga o‘tishingiz mumkin:
`;
}


// ===============================
// Xavfsiz reply funksiyasi
// ===============================
async function safeReply(ctx, text, keyboard) {
  try {
    await ctx.replyWithMarkdown(text, keyboard);
  } catch (err) {
    // 403 — user botni block qilgan
    if (err?.response?.error_code === 403) {
      console.log(`❌ User ${ctx.from?.id} botni block qilgan ➝ skip`);
      return;
    }

    console.error("❌ Reply error:", err);
  }
}


// ===============================
// /start komandasi
// ===============================
bot.start(async (ctx) => {
  const userId = ctx.from.id;
  const fullName = ctx.from.first_name;

  // ADMIN — obuna talab qilinmaydi
  if (ADMIN_IDS.includes(userId)) {
    return await safeReply(
      ctx,
      getAdminText(fullName),
      Markup.inlineKeyboard([
        [
          Markup.button.webApp("Admin panel", `${APP_URL}/starsadmin`)
        ]
      ])
    );
  }

  // Majburiy obuna tekshirish
  const subscribed = await isSubscribed(ctx, userId);
  if (!subscribed) {
    return await safeReply(ctx, getSubscribeText(), getSubscribeKeyboard());
  }

  // Obuna bo'lgan — davom etamiz
  await safeReply(
    ctx,
    getStartText(fullName),
    Markup.inlineKeyboard([
        [
          Markup.button.webApp("⭐ Stars / 💎 Premium olish", "https://vitahealth.uz/")
        ],
        [
          Markup.button.url(
            "💎 1 oylik premium",
            "https://t.me/starsjoy_bot?text=Assalomu%20aleykum%2C%201%20oylik%20premium%20narxi%2044000%20so%27m%20ekan%20akkauntimga%20kirib%20olib%20berasizmi%3F"
          )
        ],
        [
          Markup.button.url(
            "💎 1 yillik premium",
            "https://t.me/starsjoy_bot?text=Assalomu%20aleykum%2C%201%20yillik%20premium%20narxi%20299000%20so%27m%20ekan%20akkauntimga%20kirib%20olib%20berasizmi%3F"
          )
        ]
    ])
  );
});


// ===============================
// "Tekshirish" tugmasi callback
// ===============================
bot.action('check_subscription', async (ctx) => {
  const userId = ctx.from.id;
  const fullName = ctx.from.first_name;

  const subscribed = await isSubscribed(ctx, userId);

  if (!subscribed) {
    try {
      await ctx.answerCbQuery('❌ Siz hali kanalga obuna bo\'lmagansiz!', { show_alert: true });
    } catch (e) {}
    return;
  }

  // Obuna bo'lgan — eski xabarni o'chirib, asosiy menyu
  try {
    await ctx.deleteMessage();
  } catch (e) {}

  await safeReply(
    ctx,
    getStartText(fullName),
    Markup.inlineKeyboard([
        [
          Markup.button.webApp("⭐ Stars / 💎 Premium olish", "https://vitahealth.uz/")
        ],
        [
          Markup.button.url(
            "💎 1 oylik premium",
            "https://t.me/starsjoy_bot?text=Assalomu%20aleykum%2C%201%20oylik%20premium%20narxi%2044000%20so%27m%20ekan%20akkauntimga%20kirib%20olib%20berasizmi%3F"
          )
        ],
        [
          Markup.button.url(
            "💎 1 yillik premium",
            "https://t.me/starsjoy_bot?text=Assalomu%20aleykum%2C%201%20yillik%20premium%20narxi%20299000%20so%27m%20ekan%20akkauntimga%20kirib%20olib%20berasizmi%3F"
          )
        ]
    ])
  );

  try {
    await ctx.answerCbQuery('✅ Obuna tasdiqlandi!');
  } catch (e) {}
});


// ===============================
// Botni ishga tushirish
// ===============================
bot.launch()
  .then(() => console.log("🚀 Bot ishlayapti..."))
  .catch(err => console.error("Bot launch error:", err));
