import 'dotenv/config';
import { TelegramClient } from 'telegram';
import { Api } from 'telegram';
import { StringSession } from 'telegram/sessions/index.js';
import { NewMessage } from 'telegram/events/index.js';
import fetch from 'node-fetch';
import express from 'express';
import pg from 'pg';
import {
    ensureSmsLedger,
    parseSmsTime,
    recordSms,
    finishSms,
    resolveSmsOrder,
} from './modules/payments/smsLedger.js';
import {
    cardsForChat,
    findCardForSms,
    monitoredChatIds,
    parsePaymentForBrand,
    describeCards,
    listConfiguredCards,
} from './modules/paymentSystem/index.js';

// ======================
// 🛡️ GLOBAL ERROR HANDLERS — Process crash oldini olish
// ======================
process.on('unhandledRejection', (reason, promise) => {
  console.error('⚠️ Unhandled Rejection at:', promise, 'reason:', reason);
  // Process'ni crash qilmaslik
});

process.on('uncaughtException', (err) => {
  console.error('⚠️ Uncaught Exception:', err);
  // Critical xatolarda log qilib davom etish
});

// ================== CONFIG ==================
const apiId = parseInt(process.env.TG_API_ID);
const apiHash = process.env.TG_API_HASH;
const stringSession = new StringSession(process.env.TG_SESSION);
// Kartalar registri — UZCARD va HUMO bitta listenerda.
// MUHIM: bu yerda AKTIV karta emas, sozlangan BARCHA kartalar kuzatiladi.
// Admin kartani almashtirgan payt mijoz ekranida hali eski karta turgan
// bo'lishi mumkin — u eski kartaga to'laydi va buyurtma baribir yopilishi kerak.
const MONITORED_CARD_CHATS = monitoredChatIds();

const MATCH_API_STARS = process.env.MATCH_API_STARS;
const MATCH_API_STARS_PAYMEE = process.env.MATCH_API_STARS_PAYMEE;
const MATCH_API_STARS_USDT = process.env.MATCH_API_STARS_USDT;
const MATCH_API_PREMIUM = process.env.MATCH_API_PREMIUM;
const MATCH_API_PREMIUM_PAYMEE = process.env.MATCH_API_PREMIUM_PAYMEE;
const MATCH_API_PREMIUM_USDT = process.env.MATCH_API_PREMIUM_USDT;
const MATCH_API_GIFT = process.env.MATCH_API_GIFT || 'http://localhost:5001/api/gift/match';
const INTERNAL_SECRET = process.env.INTERNAL_API_SECRET || '';
const BALANCE_CHECKER_PORT = 5002;

if (!process.env.INTERNAL_API_SECRET) {
    console.error('❌ OGOHLANTIRISH: INTERNAL_API_SECRET .env da yo\'q!');
    console.error('❌ SMS listener match API ga 403 oladi! .env ga INTERNAL_API_SECRET qo\'shing!');
}
if (!MATCH_API_STARS || !MATCH_API_PREMIUM) {
    console.error('❌ MATCH_API_STARS yoki MATCH_API_PREMIUM .env da yo\'q!');
}

// Order turi → shu turni yopadigan match endpoint. Tartib = eski zanjir tartibi
// (bir xil summa bir nechta turda bo'lsa, eski zanjir qaysini olsa — shu).
const MATCH_URL_BY_TYPE = {
    stars: MATCH_API_STARS,
    premium_paymee: MATCH_API_PREMIUM_PAYMEE,
    stars_paymee: MATCH_API_STARS_PAYMEE,
    stars_usdt: MATCH_API_STARS_USDT,
    premium_usdt: MATCH_API_PREMIUM_USDT,
    premium: MATCH_API_PREMIUM,
    gift: MATCH_API_GIFT,
};
const CHAIN_TYPES = Object.keys(MATCH_URL_BY_TYPE).filter((t) => MATCH_URL_BY_TYPE[t]);

// ================== SMS DAFTARI (sms_payments) ==================
// Daftar ishlamasa (DB xato) — eski zanjir o'zgarishsiz ishlayveradi.
let ledgerPool = null;
let ledgerSince = null;

async function initSmsLedger() {
    if (!process.env.DATABASE_URL) {
        console.error('⚠️ SMS daftari: DATABASE_URL yo\'q — eski usulda ishlaymiz');
        return;
    }
    try {
        const pool = new pg.Pool({
            connectionString: process.env.DATABASE_URL,
            max: 3,
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 10000,
        });
        pool.on('error', (err) => console.error('❌ SMS daftari pool xatosi:', err.message));
        ledgerSince = await ensureSmsLedger(pool);
        ledgerPool = pool;
        console.log(`📒 SMS daftari tayyor (${ledgerSince.toISOString()} dan beri)`);
    } catch (err) {
        console.error('❌ SMS daftari ishga tushmadi — eski usulda ishlaymiz:', err.message);
        ledgerPool = null;
    }
}

function notifyAdmin(html) {
    const token = process.env.BOT_TOKEN;
    const chatId = String(process.env.ERROR_LOG_CHANNEL_ID || "-1003836618718");
    if (!token) return;
    fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text: html, parse_mode: 'HTML' }),
    }).catch((e) => console.error('Admin xabari yuborilmadi:', e.message));
}

function escapeHtml(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Telegram client (global)
let client = null;
let isClientReady = false;
let lastCardSmsAt = Date.now();

// SMS parserlar modulda (UZCARD va HUMO formatlari alohida) —
// parsePaymentForBrand(brand, text) to'g'ri parserni tanlaydi.

// ================== AutoReconnect (exponential backoff) ==================
async function autoReconnect(clientInstance) {
    let backoff = 2000;
    const maxBackoff = 60000;

    while (true) {
        try {
            if (!clientInstance.connected) {
                console.warn("⚠️ [GramJS] Aloqa uzildi! Qayta ulanmoqda...");
                await clientInstance.connect();
                console.log("✅ [GramJS] Qayta ulandi!");
                backoff = 2000;
            }
        } catch (err) {
            console.error("❌ [GramJS] Qayta ulanish xatosi:", err?.message || err);
            await new Promise((r) => setTimeout(r, backoff));
            backoff = Math.min(backoff * 2, maxBackoff);
        }
        await new Promise((res) => setTimeout(res, 3000));
    }
}

// Eski zanjir: summa bo'yicha "hozir pending" orderni qidiradi (SMS vaqtini bilmaydi).
// SMS vaqti o'qilmasa yoki daftar ishlamasa ishlatiladi. Topilgan order javobi yoki null.
async function runLegacyMatchChain(parsed) {
    const matchHeaders = {
        "Content-Type": "application/json",
        "X-Internal-Key": INTERNAL_SECRET,
    };

    // 1) RobynHood Stars (faqat order_type=stars — gift/premium bilan aralashmasin)
    let res = await fetch(MATCH_API_STARS, {
        method: "POST",
        headers: matchHeaders,
        body: JSON.stringify({
            ...parsed,
            allowed_order_types: ["stars"],
        }),
    });

    // 2) Paymee Premium — stars dan oldin (bir xil summ collision)
    if (!res.ok && MATCH_API_PREMIUM_PAYMEE) {
        const errBody = await res.text().catch(() => "");
        console.log(
            "💎 Paymee premium urinyapti...",
            errBody ? errBody.slice(0, 200) : ""
        );
        res = await fetch(MATCH_API_PREMIUM_PAYMEE, {
            method: "POST",
            headers: matchHeaders,
            body: JSON.stringify({
                amount: parsed.amount,
                card_last4: parsed.card_last4,
            }),
        });
    }

    // 3) Paymee Stars (/paymeestars)
    if (!res.ok && MATCH_API_STARS_PAYMEE) {
        const errBody = await res.text().catch(() => "");
        console.log(
            "⭐ Paymee premium topilmadi → Paymee stars...",
            errBody ? errBody.slice(0, 200) : ""
        );
        res = await fetch(MATCH_API_STARS_PAYMEE, {
            method: "POST",
            headers: matchHeaders,
            body: JSON.stringify(parsed),
        });
    }

    // 4) Fragment Stars (/usdtstars)
    if (!res.ok && MATCH_API_STARS_USDT) {
        const errBody = await res.text().catch(() => "");
        console.log(
            "⭐ Paymee stars topilmadi → Fragment stars urinyapti...",
            errBody ? errBody.slice(0, 200) : ""
        );
        res = await fetch(MATCH_API_STARS_USDT, {
            method: "POST",
            headers: matchHeaders,
            body: JSON.stringify(parsed),
        });
    }

    // 5) Fragment Premium — Robyn premium dan OLDIN
    if (!res.ok && MATCH_API_PREMIUM_USDT) {
        const errBody = await res.text().catch(() => "");
        console.log(
            "💎 Fragment premium urinyapti...",
            errBody ? errBody.slice(0, 200) : ""
        );
        res = await fetch(MATCH_API_PREMIUM_USDT, {
            method: "POST",
            headers: matchHeaders,
            body: JSON.stringify({ amount: parsed.amount }),
        });
    }

    // 6) RobynHood Premium
    if (!res.ok && MATCH_API_PREMIUM) {
        console.log("💎 Fragment premium topilmadi → Robyn premium...");
        res = await fetch(MATCH_API_PREMIUM, {
            method: "POST",
            headers: matchHeaders,
            body: JSON.stringify(parsed),
        });
    }

    if (res.ok) {
        const result = await res.json();
        console.log("🎉 Muvaffaqiyatli topildi:", result);
        return result;
    } else {
        const failBody = await res.text().catch(() => "");
        console.log(
            `⚠️ Match ${res.status} (${parsed.amount} so'm): ${failBody.slice(0, 300)}`
        );
        console.log("⭐💎 Stars/Premium da topilmadi → GIFT urinyapti...");
        res = await fetch(MATCH_API_GIFT, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Internal-Key": INTERNAL_SECRET
            },
            body: JSON.stringify(parsed),
        });

        if (res.ok) {
            const result = await res.json();
            console.log("🎁 Gift to'lov topildi:", result);
            return result;
        } else {
            console.log("⚠️ Hech qaysi bazada topilmadi");
        }
    }
    return null;
}

// Kiruvchi to'lov SMS'i: daftarga yozish → SMS vaqti bo'yicha order → yopish.
// Qoidalar (smsLedger.js): faqat TO'LANMAGAN order yopiladi — to'langan, lekin
// yetkazilmagan orderni tizim hech qachon qayta yetkazmaydi (bu admin ishi).
async function processCardPayment(peerId, msg, parsed, onFresh) {
    const smsTime = parseSmsTime(msg.message);

    let smsId = null;
    if (ledgerPool) {
        try {
            smsId = await recordSms(ledgerPool, {
                chatId: peerId,
                msgId: msg.id,
                cardLast4: parsed.card_last4,
                amount: parsed.amount,
                smsTime,
                rawText: msg.message,
            });
            if (smsId === null) {
                console.log(`⏭️ Bu SMS avval ishlangan (chat=${peerId}, msg=${msg.id}) — o'tkazildi`);
                return;
            }
        } catch (err) {
            console.error('❌ SMS daftariga yozishda xato — eski usul:', err.message);
        }
    }
    onFresh?.();

    if (smsId && smsTime) {
        let resolved = null;
        try {
            resolved = await resolveSmsOrder(ledgerPool, {
                amount: parsed.amount,
                smsTime,
                receivedAt: msg.date ? new Date(msg.date * 1000) : new Date(),
                ledgerSince,
                chainTypes: CHAIN_TYPES,
            });
        } catch (err) {
            console.error('❌ SMS vaqti bo\'yicha qidirishda xato — eski usul:', err.message);
        }

        if (resolved) {
            await applySmsDecision(smsId, parsed, smsTime, resolved);
            return;
        }
    }

    const result = await runLegacyMatchChain(parsed);
    if (smsId) {
        await finishSms(
            ledgerPool,
            smsId,
            result ? 'legacy_matched' : 'legacy_unmatched',
            result?.id ?? null,
            smsTime ? null : 'SMS vaqti o\'qilmadi'
        ).catch((e) => console.error('⚠️ SMS daftari yangilanmadi:', e.message));
    }
}

async function applySmsDecision(smsId, parsed, smsTime, resolved) {
    const { decision, order, candidates } = resolved;
    const timeStr = smsTime.toLocaleString('uz-UZ', { timeZone: 'Asia/Tashkent' });
    const amountStr = `${Number(parsed.amount).toLocaleString()} so'm`;
    console.log(`🕓 SMS vaqti ${timeStr} | ${amountStr} → ${decision}`, JSON.stringify(candidates));

    if (decision === 'match') {
        const url = MATCH_URL_BY_TYPE[order.order_type];
        if (!url) {
            await finishSms(ledgerPool, smsId, 'error', order.id, `match URL yo'q: ${order.order_type}`);
            notifyAdmin(
                `⚠️ <b>To'lov keldi, lekin avtomatik yopib bo'lmadi</b>\n\n` +
                `#${order.id} (${escapeHtml(order.order_type)}) — ${amountStr}, ${escapeHtml(timeStr)}\n` +
                `Sabab: bu turdagi order uchun match manzili sozlanmagan. Qo'lda tekshiring.`
            );
            return;
        }
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Internal-Key': INTERNAL_SECRET },
            body: JSON.stringify({
                ...parsed,
                order_id: order.id,
                allowed_order_types: [order.order_type],
            }),
        });
        if (res.ok) {
            const result = await res.json().catch(() => ({}));
            console.log('🎉 SMS vaqti bo\'yicha topildi:', result);
            await finishSms(ledgerPool, smsId, 'matched', order.id, resolved.note);
            if (order.status === 'expired') {
                notifyAdmin(
                    `♻️ <b>Kechikkan to'lov avtomatik yopildi</b>\n\n` +
                    `#${order.id} (${escapeHtml(order.order_type)}) — ${amountStr}\n` +
                    `SMS dagi vaqt: ${escapeHtml(timeStr)} (taymer ichida)\n` +
                    `Order muddati o'tgan deb belgilangan edi — endi yetkazilmoqda.`
                );
            }
        } else {
            // Poyga: shu orada admin qo'lda olgan bo'lishi mumkin — hech narsa qilmaymiz
            const body = await res.text().catch(() => '');
            console.log(`⚠️ Order #${order.id} yopilmadi (${res.status}): ${body.slice(0, 200)}`);
            await finishSms(ledgerPool, smsId, 'match_failed', order.id, `${res.status} ${body.slice(0, 300)}`);
            notifyAdmin(
                `⚠️ <b>To'lov keldi, lekin order yopilmadi</b>\n\n` +
                `#${order.id} (${escapeHtml(order.order_type)}) — ${amountStr}, ${escapeHtml(timeStr)}\n` +
                `Javob: ${res.status}. Order holatini qo'lda tekshiring.`
            );
        }
        return;
    }

    if (decision === 'manual_paid') {
        await finishSms(ledgerPool, smsId, 'manual_paid', order.id);
        console.log(`🔗 SMS qo'lda tasdiqlangan #${order.id} ga bog'landi — hech narsa yuborilmadi`);
        notifyAdmin(
            `🔗 <b>Kechikkan SMS keldi</b>\n\n` +
            `${amountStr}, ${escapeHtml(timeStr)} → #${order.id} (allaqachon to'langan).\n` +
            `Hech narsa qayta yuborilmadi.`
        );
        return;
    }

    if (decision === 'ambiguous') {
        await finishSms(ledgerPool, smsId, 'ambiguous', null, JSON.stringify(candidates));
        const list = candidates
            .map((c) => `• #${c.id} ${escapeHtml(c.type)} — ${escapeHtml(c.status)}/${escapeHtml(c.payment_status)}`)
            .join('\n');
        notifyAdmin(
            `❓ <b>To'lov qaysi orderga tegishli — aniq emas</b>\n\n` +
            `${amountStr}, SMS vaqti ${escapeHtml(timeStr)}\n\n${list}\n\n` +
            `Avtomatik hech narsa qilinmadi. Qo'lda hal qiling.`
        );
        return;
    }

    // unmatched — boshqa loyiha to'lovi yoki taymerdan keyin to'langan.
    // Mavjud monitoring (ORDERS kanal) bu holatda o'zi ogohlantiradi.
    await finishSms(ledgerPool, smsId, 'unmatched');
    console.log(`⚠️ SMS vaqti bo'yicha mos order yo'q (${amountStr}, ${timeStr})`);
}

// Restart paytida kelgan SMS'lar yo'qolmasin: oxirgi xabarlarni qayta ko'rib chiqamiz.
// Daftar takrorni o'tkazib yuboradi, daftardan oldingi xabarlarga tegilmaydi.
async function catchUpRecentSms(handler) {
    if (!ledgerPool || !ledgerSince) return;
    const since = Math.max(ledgerSince.getTime(), Date.now() - 60 * 60 * 1000);
    for (const chatId of MONITORED_CARD_CHATS) {
        try {
            const messages = await client.getMessages(parseInt(chatId), { limit: 50 });
            const fresh = messages
                .filter((m) => m?.date && m.date * 1000 >= since)
                .sort((a, b) => a.id - b.id);
            if (fresh.length) {
                console.log(`🔁 Catch-up: ${chatId} chatida ${fresh.length} ta so'nggi xabar tekshirilmoqda`);
            }
            for (const m of fresh) {
                await handler({ message: m });
            }
        } catch (err) {
            console.error(`⚠️ Catch-up xatosi (${chatId}):`, err.message);
        }
    }
}
// ================== TELEGRAM CLIENT INIT (FAQAT SMS LISTENER) ==================
export async function initBalanceClient() {
    if (isClientReady && client?.connected) {
        console.log('✅ SMS listener client allaqachon ulangan');
        return true;
    }

    console.log('🔄 GramJS client ulanmoqda (faqat SMS listener)...');

    client = new TelegramClient(stringSession, apiId, apiHash, {
        connectionRetries: 50,
    });

    await client.start({
        phoneNumber: async () => '',
        password: async () => '',
        phoneCode: async () => '',
        onError: (err) => console.log('GramJS client error:', err),
    });

    console.log('✅ GramJS client ulandi!');

    // ================== KARTA CHATLARI ==================
    console.log('💳 Sozlangan kartalar:');
    for (const line of describeCards()) console.log(`   ${line}`);

    if (MONITORED_CARD_CHATS.length === 0) {
        console.error("❌ Bironta ham karta sozlanmagan! .env da karta suffiksi va chat ID sini tekshiring.");
        console.error("   UZCARD: UZCARD_CHAT_ID + TARGET_CARD_SUFFIX (yoki VITE_CARD_NUMBER)");
        console.error("   HUMO:   HUMO_CHAT_ID + TOPUP_CARD_NUMBER_HUMO");
    }

    // Har bir karta chatini "isitib" qo'yamiz. Entity topilmasa ham listener
    // peerId bo'yicha filtrlagani uchun baribir ishlaydi — bu faqat
    // GramJS ning ichki keshini to'ldirish va startupda xatoni erta ko'rsatish.
    for (const chatId of MONITORED_CARD_CHATS) {
        let entity = null;
        try {
            entity = await client.getEntity(parseInt(chatId));
        } catch {
            try {
                const dialogs = await client.getDialogs({ limit: 500 });
                for (const d of dialogs) {
                    const pid = d.id?.value !== undefined ? String(d.id.value) : String(d.id);
                    if (pid.replace(/^-100/, '').replace(/^-/, '') === chatId) {
                        entity = d.entity;
                        break;
                    }
                }
            } catch (e) {
                console.error(`⚠️ Dialoglarni yuklashda xato (${chatId}):`, e.message);
            }
        }
        if (entity) {
            const nm = entity.firstName || entity.title || entity.username || 'N/A';
            console.log(`✅ Karta chati topildi: ${chatId} (${nm})`);
        } else {
            console.log(`⚠️ Karta chati entity topilmadi: ${chatId} — peerId orqali baribir ishlaydi`);
        }
    }

    // ================== SMS PAYMENT HANDLER ==================
    console.log(`📡 SMS listener ishga tushmoqda (kuzatilayotgan karta chatlari: ${MONITORED_CARD_CHATS.join(", ") || "—"})...`);

    const ORDERS_CHANNEL = String(process.env.ORDERS_CHANNEL || "-1003752422150");
    const PREMIUMSEND_CHANNEL = String(process.env.PREMIUMSEND_CHANNEL || "-1003606510579");
    const ERROR_LOG_CHANNEL_ID = String(process.env.ERROR_LOG_CHANNEL_ID || "-1003836618718");
    const BOT_TOKEN = process.env.BOT_TOKEN;
    const pendingUzcardPayments = []; // monitoring uchun

    // Kanallar array - ikkala kanalni tekshirish uchun
    const MONITORED_CHANNELS = [ORDERS_CHANNEL, PREMIUMSEND_CHANNEL];
    console.log(`📡 Monitoring kanallar: ORDERS=${ORDERS_CHANNEL}, PREMIUM=${PREMIUMSEND_CHANNEL}`);

    await initSmsLedger();

    const handleCardMessage = async (event) => {
            try {
                const msg = event.message;
                if (!msg) return;

                const rawPeerId =
                    msg.peerId?.channelId ??
                    msg.peerId?.chatId ??
                    msg.peerId?.userId;

                const peerId = rawPeerId?.value !== undefined ? String(rawPeerId.value) : String(rawPeerId);

                const text = msg.message || "";

                // ==========================================
                // 📡 ORDERS + PREMIUM CHANNEL HANDLER (2 kanalni kuzatish)
                // ==========================================
                // Channel ID ni normalize qilish (har xil formatlarni qo'llab-quvvatlash)
                const normalizeChannelId = (id) => String(id).replace(/^-100/, '').replace(/^-/, '');
                const normalizedPeerId = normalizeChannelId(peerId);
                
                const isMonitoredChannel = MONITORED_CHANNELS.some(ch => 
                    normalizeChannelId(ch) === normalizedPeerId
                );

                if (isMonitoredChannel) {
                    // 💰 Summa: 175,000 so'm formatidan summa ajratish
                    // Turli formatlarni qo'llab-quvvatlash: 175,000 | 175 000 | 175.000
                    const sumMatch = text.match(/💰\s*Summa:\s*([\d,.\s\u00A0]+)\s*so['']?m/i);
                    if (sumMatch) {
                        // Barcha raqam bo'lmagan belgilarni olib tashlash
                        const orderSum = parseInt(sumMatch[1].replace(/[^\d]/g, ''), 10);
                        if (orderSum && orderSum > 0) {
                            const isOrdersChannel = normalizeChannelId(ORDERS_CHANNEL) === normalizedPeerId;
                            const channelName = isOrdersChannel ? 'ORDERS' : 'PREMIUM';
                            console.log(`✅ [${channelName}_CHANNEL] Order sum detected: ${orderSum} so'm`);
                            const matchIndex = pendingUzcardPayments.findIndex(p => p.amount === orderSum);
                            if (matchIndex !== -1) {
                                pendingUzcardPayments.splice(matchIndex, 1);
                                console.log(`✅ [Monitoring] ${orderSum} so'm to'lov o'z egasini topdi (${channelName} kanalda).`);
                            }
                        }
                    }
                    return;
                }

                // Shu chatga SMS yuboradigan sozlangan kartalar (bittadan ortiq
                // bo'lishi mumkin — masalan ikkala karta bitta bank botida)
                const chatCards = cardsForChat(peerId);
                if (chatCards.length === 0) return;
                lastCardSmsAt = Date.now();

                const brands = [...new Set(chatCards.map((c) => c.brand))];
                console.log(`📩 [${brands.join("/").toUpperCase()} SMS] Xabar keldi:`, {
                    peerId,
                    text: msg.message,
                });

                // Kiruvchi to'lov belgisi — HUMO ba'zan "+" ishlatadi
                if (!text.includes("➕") && !/\+\s*[\d.]/.test(text)) return;

                // Shu chatdagi har bir brend uchun mos parserni sinab ko'ramiz
                let parsed = null;
                let card = null;
                for (const brand of brands) {
                    const p = parsePaymentForBrand(brand, text);
                    if (!p) continue;
                    const match = findCardForSms(peerId, p.card_last4);
                    if (match) {
                        parsed = p;
                        card = match;
                        break;
                    }
                }

                if (!parsed || !card) {
                    const any = parsePaymentForBrand(brands[0], text);
                    if (any?.card_last4) {
                        console.log(
                            `⏭️ Boshqa karta: SMS ***${any.card_last4}, sozlanganlar: ` +
                            chatCards.map((c) => `***${c.suffix}`).join(", ")
                        );
                    }
                    return;
                }

                console.log(`💳 Karta topildi: ${card.title} (***${card.suffix})`);

                console.log("💳 To'lov aniqlandi:", parsed);

                // Monitoring uchun qo'shish — faqat yangi (takror bo'lmagan) SMS
                await processCardPayment(peerId, msg, parsed, () => {
                    pendingUzcardPayments.push({
                        amount: parsed.amount,
                        text: parsed.raw_text,
                        timestamp: Date.now()
                    });
                });
            } catch (err) {
                console.error("❌ SMS Handler xatosi:", err);
            }
    };
    client.addEventHandler(handleCardMessage, new NewMessage({}));

    // Restart paytida kelgan SMS'lar
    catchUpRecentSms(handleCardMessage).catch((e) => console.error("Catch-up xatosi:", e.message));

    // CardXabar jim qolsa (sessiya uzilgan / format o'zgargan) — adminga xabar
    let silenceAlerted = false;
    setInterval(() => {
        const hour = Number(
            new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent', hour: 'numeric', hour12: false })
        );
        const silentMin = Math.round((Date.now() - lastCardSmsAt) / 60000);
        const daytime = hour >= 9 && hour < 23;
        if (daytime && silentMin >= 60 && !silenceAlerted) {
            silenceAlerted = true;
            notifyAdmin(
                `🔕 <b>Karta SMS'lari ${silentMin} daqiqadan beri kelmayapti</b>\n\n` +
                `Userbot ulanishi: ${client?.connected ? 'bor' : "YO'Q"}\n` +
                `CardXabar/HUMO chatini va userbot sessiyasini tekshiring.`
            );
        }
        if (silentMin < 60) silenceAlerted = false;
    }, 5 * 60 * 1000);

    // Timer (Har 1 daqiqada tekshiradi)
    setInterval(() => {
        const now = Date.now();
        for (let i = pendingUzcardPayments.length - 1; i >= 0; i--) {
            const p = pendingUzcardPayments[i];
            // 5 daqiqadan oshgan bo'lsa (5 * 60 * 1000 = 480000 ms)
            if (now - p.timestamp > 480000) {
                console.log(`⚠️ Tizimda qolib ketgan to'lov (${p.amount})! Ikkala kanalda ham topilmadi - Error kanalga yuborilmoqda...`);
                
                if (BOT_TOKEN && ERROR_LOG_CHANNEL_ID) {
                    const message = `⚠️ <b>XATO tolov - 5 daqiqa ichida topilmadi</b>\n\n📝 <b>To'lov xabari:</b>\n<code>${p.text}</code>\n\n💰 <b>Summa:</b> ${p.amount.toLocaleString()} so'm\n\n📡 <b>Kuzatilgan kanallar:</b>\n• ORDERS_CHANNEL\n• PREMIUMSEND_CHANNEL\n\n📌 Ikkala kanalda ham bu summaga mos order topilmadi!\nIltimos, bu to'lov nima uchun kelganini tekshiring!`;
                    fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            chat_id: ERROR_LOG_CHANNEL_ID,
                            text: message,
                            parse_mode: 'HTML'
                        })
                    }).catch(e => console.error("Error kanalga SMS jo'natish xatosi:", e));
                }

                pendingUzcardPayments.splice(i, 1);
            }
        }
    }, 60000);

    console.log(
        `✅ SMS listener tayyor! Kartalar: ${listConfiguredCards().map((c) => c.title).join(" + ") || "—"}` +
        ` | kanallar: ORDERS + PREMIUM`
    );

    // AutoReconnect ni background da ishga tushirish
    autoReconnect(client).catch((e) => console.error("autoReconnect failed:", e));

    isClientReady = true;
    return true;
}

// ================== START (faqat SMS listener) ==================
export async function startBalanceChecker() {
    console.log('🚀 SMS Listener ishga tushmoqda...');

    const ok = await initBalanceClient();
    if (!ok) {
        console.error('❌ SMS Listener client ulanmadi!');
        return false;
    }

    console.log('✅ SMS Listener tayyor — to\'lovlarni kutmoqda...');
    return true;
}

// ================== DISCONNECT ==================
export async function disconnectBalanceClient() {
    if (client) {
        await client.disconnect();
        isClientReady = false;
        console.log('🔌 SMS Listener client uzildi');
    }
}

// ================== HTTP SERVER ==================
const app = express();
app.use(express.json());

// Status endpoint
app.get('/api/balance/status', (req, res) => {
    res.json({
        success: true,
        clientReady: isClientReady,
        mode: 'sms-only'
    });
});

// Order yaratilganda server.js / USDT modullar chaqiradi (signal)
app.post('/api/balance/refresh', (req, res) => {
    res.json({ success: true, clientReady: isClientReady });
});

// ======================
// 🎁 GIFT SEND — Userbot (GramJS) orqali gift yuborish
// ======================
app.post('/api/gift/send-userbot', async (req, res) => {
    try {
        // Internal auth tekshiruvi
        const key = req.headers['x-internal-key'];
        if (key !== INTERNAL_SECRET) {
            return res.status(403).json({ success: false, error: 'Ruxsat berilmagan' });
        }

        if (!isClientReady || !client?.connected) {
            return res.status(503).json({ success: false, error: 'Userbot client tayyor emas' });
        }

        const { recipientUsername, giftId, message, anonymous } = req.body;

        if (!recipientUsername || !giftId) {
            return res.status(400).json({ success: false, error: 'recipientUsername va giftId kerak' });
        }

        const cleanUsername = recipientUsername.startsWith('@')
            ? recipientUsername.slice(1)
            : recipientUsername;

        console.log(`🎁 Gift yuborilmoqda: @${cleanUsername} | gift: ${giftId} | anonim: ${anonymous}`);

        // Username orqali InputPeer olish
        let inputPeer;
        try {
            inputPeer = await client.getInputEntity(cleanUsername);
        } catch (err) {
            console.error("❌ getInputEntity xatosi:", err.message);
            return res.status(404).json({ success: false, error: 'User Telegram bazasidan topilmadi. Ular botga profil ochiqligini tekshirishlari yoki maxfiylik sozlamalarini to\'g\'irlashlari kerak.' });
        }

        if (!inputPeer || !inputPeer.userId) {
            return res.status(404).json({ success: false, error: 'User Telegram bazasidan topilmadi. Ular userbotda kontakt yoki xabar tarixida bo\'lishi kerak.' });
        }

        // InputInvoiceStarGift yaratish
        const invoiceParams = {
            peer: inputPeer,
            giftId: BigInt(giftId),
            hideName: anonymous === true,
        };

        // Message (izoh) qo'shish
        if (message && message.trim()) {
            invoiceParams.message = new Api.TextWithEntities({
                text: message.trim(),
                entities: [],
            });
        }

        const invoice = new Api.InputInvoiceStarGift(invoiceParams);

        // 1. Payment form olish
        const paymentForm = await client.invoke(
            new Api.payments.GetPaymentForm({ invoice })
        );

        console.log(`💳 Payment form olindi: formId=${paymentForm.formId}`);

        // 2. Stars bilan to'lash (userbot balansidan)
        const result = await client.invoke(
            new Api.payments.SendStarsForm({
                formId: paymentForm.formId,
                invoice,
            })
        );

        console.log(`✅ Gift muvaffaqiyatli yuborildi: @${cleanUsername}`, result);

        res.json({ success: true, result });

    } catch (err) {
        console.error('❌ Gift yuborish xatosi:', err);

        // Telegram xato kodlarini qaytarish
        const errorMessage = err?.message || err?.errorMessage || 'Noma\'lum xato';
        res.status(500).json({ success: false, error: errorMessage });
    }
});

// ======================
// ⭐ STARS BALANCE — GramJS orqali user stars balansini olish
// ======================
app.get('/api/userbot/stars-balance', async (req, res) => {
    try {
        // Internal auth tekshiruvi
        const key = req.headers['x-internal-key'];
        console.log(`📡 /api/userbot/stars-balance so'rov keldi. Key: ${key ? 'provided' : 'NOT PROVIDED'}`);
        console.log(`📡 Expected: ${INTERNAL_SECRET ? 'CONFIGURED' : 'NOT CONFIGURED'}`);
        
        if (key !== INTERNAL_SECRET) {
            console.error(`❌ Key mos kelmadi! Received: ${key}, Expected: ${INTERNAL_SECRET}`);
            return res.status(403).json({ success: false, error: 'Ruxsat berilmagan' });
        }

        if (!isClientReady || !client?.connected) {
            console.error(`❌ Client tayyor emas! isClientReady=${isClientReady}, connected=${client?.connected}`);
            return res.status(503).json({ success: false, error: 'Userbot client tayyor emas' });
        }

        console.log('⭐ Stars balance so\'ralmoqda...');

        // payments.getStarsStatus API
        const result = await client.invoke(
            new Api.payments.GetStarsStatus({
                peer: "me"
            })
        );

        console.log(`📊 Balance object:`, result.balance);
        console.log(`📊 Balance type:`, typeof result.balance);
        console.log(`📊 Balance keys:`, result.balance ? Object.keys(result.balance) : "null");

        // Balance ni olish
        let balance;
        if (result.balance && typeof result.balance === 'object') {
            // StarsAmount obyekti bo'lsa
            balance = result.balance.amount || result.balance.value || result.balance;
        } else {
            balance = result.balance;
        }
        
        // BigInt yoki Number ga aylantirish
        if (typeof balance === 'bigint') {
            balance = Number(balance);
        } else if (typeof balance === 'object' && balance?.value) {
            // Integer { value: 165n } formatida bo'lsa
            balance = Number(balance.value);
        } else if (typeof balance === 'object') {
            balance = 0;
        } else {
            balance = Number(balance) || 0;
        }

        console.log(`⭐ Stars balance (final): ${balance}`);

        res.json({
            success: true,
            stars_balance: balance,
            subscriptions: result.subscriptions || []
        });

    } catch (err) {
        console.error('❌ Stars balance olishda xato:', err);
        console.error('❌ Error stack:', err?.stack);
        res.status(500).json({ success: false, error: err?.message || 'Noma\'lum xato', details: err?.toString() });
    }
});

// ⭐ ALTERNATIVE - User profile orqali stars bilish
app.get('/api/userbot/user-me', async (req, res) => {
    try {
        const key = req.headers['x-internal-key'];
        if (key !== INTERNAL_SECRET) {
            return res.status(403).json({ success: false, error: 'Ruxsat berilmagan' });
        }

        if (!isClientReady || !client?.connected) {
            return res.status(503).json({ success: false, error: 'Userbot client tayyor emas' });
        }

        console.log('👤 Me orqali ma\'lumot olish...');

        // User info olish
        const me = await client.getMe();
        console.log('👤 User info:', me);
        console.log('👤 Me keys:', Object.keys(me || {}));

        res.json({
            success: true,
            user: me,
            username: me?.username,
            firstName: me?.firstName,
            id: me?.id
        });

    } catch (err) {
        console.error('❌ User me olishda xato:', err);
        res.status(500).json({ success: false, error: err?.message || 'Noma\'lum xato' });
    }
});

// ================== STANDALONE RUN ==================
if (process.argv[1]?.includes('balanceChecker')) {
    console.log('🚀 SMS Listener mustaqil ishga tushmoqda...');

    app.listen(BALANCE_CHECKER_PORT, () => {
        console.log(`🌐 SMS Listener HTTP server: http://localhost:${BALANCE_CHECKER_PORT}`);
    });

    startBalanceChecker()
        .then(() => {
            console.log('✅ SMS Listener muvaffaqiyatli ishga tushdi!');
        })
        .catch((err) => {
            console.error('❌ SMS Listener ishga tushmadi:', err);
            process.exit(1);
        });

    process.on('SIGINT', async () => {
        console.log('\n🛑 Shutdown signal olindi...');
        await disconnectBalanceClient();
        process.exit(0);
    });

    process.on('SIGTERM', async () => {
        console.log('\n🛑 Terminate signal olindi...');
        await disconnectBalanceClient();
        process.exit(0);
    });
}
