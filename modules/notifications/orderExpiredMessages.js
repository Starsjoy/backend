const SUPPORT_HANDLE = "@StarsjoySupport";

const EXPIRED_ORDER_MESSAGES = {
  stars: `⚠️ Siz stars olishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 ${SUPPORT_HANDLE}`,
  premium: `⚠️ Siz premium olishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 ${SUPPORT_HANDLE}`,
  gift: `⚠️ Siz gift yuborishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 ${SUPPORT_HANDLE}`,
};

/** stars | stars_paymee | premium_usdt | gift … */
export function getExpiredOrderNotifyText(orderType) {
  const t = String(orderType || "").toLowerCase();
  if (t === "gift" || t.includes("gift")) {
    return EXPIRED_ORDER_MESSAGES.gift;
  }
  if (t.includes("premium")) {
    return EXPIRED_ORDER_MESSAGES.premium;
  }
  return EXPIRED_ORDER_MESSAGES.stars;
}

export function shouldSendExpiredOrderNotify(orderType) {
  const t = String(orderType || "").toLowerCase();
  return t.includes("stars") || t.includes("premium") || t === "gift";
}
