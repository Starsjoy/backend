import { listConfiguredCards } from "../paymentSystem/index.js";

/** Klient yuborishi mumkin bo'lmagan narx maydonlari (Paymee / karta oqimi) */
export const CLIENT_FORBIDDEN_PRICE_KEYS = [
  "amount",
  "summ",
  "price",
  "total",
  "order_amount",
  "payment_amount",
];

/** Ixtiyoriy: GET /price javobidagi slot narxi — server slot bilan solishtiriladi */
export const CLIENT_SLOT_PRICE_KEYS = ["slot_price", "expected_price"];

function parseSomInt(value) {
  if (value === undefined || value === null || value === "") return null;
  const n = parseInt(String(value).replace(/[^\d]/g, ""), 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/**
 * Paymee (va boshqa karta) buyurtma: mijoz o'zi narx yozib yubormasin.
 * @returns {{ ok: true } | { ok: false, status: number, body: object }}
 */
export function rejectForbiddenClientPriceFields(body) {
  const b = body || {};
  const sent = [];

  for (const key of CLIENT_FORBIDDEN_PRICE_KEYS) {
    if (b[key] !== undefined && b[key] !== null && b[key] !== "") {
      sent.push(key);
    }
  }

  if (sent.length === 0) {
    return { ok: true };
  }

  return {
    ok: false,
    status: 400,
    body: {
      error:
        "Narx serverda hisoblanadi. So'rovda amount/summ/price yuborish mumkin emas.",
      code: "CLIENT_PRICE_FORBIDDEN",
      rejected_fields: sent,
    },
  };
}

/**
 * Frontend GET /price dan olgan slot_price — server slot bilan mos bo'lishi shart.
 */
export function validateClientSlotPrice(body, serverSlotPrice) {
  const b = body || {};
  let clientVal = null;

  for (const key of CLIENT_SLOT_PRICE_KEYS) {
    const v = parseSomInt(b[key]);
    if (v != null) {
      clientVal = v;
      break;
    }
  }

  if (clientVal == null) {
    return { ok: true, optional: true };
  }

  if (clientVal !== serverSlotPrice) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "Narx o'zgargan. Sahifani yangilang va qayta urinib ko'ring.",
        code: "SLOT_PRICE_MISMATCH",
        expected: serverSlotPrice,
        received: clientVal,
      },
    };
  }

  return { ok: true, optional: false };
}

/**
 * Promokoddan keyin va uniqueSum dan oldin — ixtiyoriy final_amount tekshiruvi.
 */
export function validateClientFinalAmount(body, serverFinalAmount) {
  const sent = parseSomInt(body?.final_amount);
  if (sent == null) {
    return { ok: true };
  }
  if (sent !== serverFinalAmount) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "Chegirma yoki narx mos emas. Qayta urinib ko'ring.",
        code: "FINAL_AMOUNT_MISMATCH",
        expected: serverFinalAmount,
        received: sent,
      },
    };
  }
  return { ok: true };
}

export function sendGuardFailure(res, guardResult) {
  return res.status(guardResult.status).json(guardResult.body);
}

/**
 * SMS match: karta oxirgi 4 raqami sozlangan kartalardan biriga mos kelishi kerak.
 *
 * ⚠️ AKTIV karta emas, sozlangan BARCHA kartalar qabul qilinadi — listener
 *    bilan bir xil qoida. Admin kartani almashtirgan payt mijozning ekranida
 *    hali eski karta turgan bo'lishi mumkin: u eski kartaga to'laydi va
 *    buyurtmasi baribir yopilishi kerak.
 *
 *    Ilgari bu yerda faqat .env dagi TARGET_CARD_SUFFIX (UZCARD) tekshirilardi,
 *    shuning uchun HUMO ga tushgan to'lov CARD_LAST4_MISMATCH bilan rad etilardi.
 */
export function validatePaymentCardLast4(cardLast4) {
  const expected = new Set(
    listConfiguredCards()
      .map((c) => c.suffix)
      .filter(Boolean)
  );

  // Zaxira: registrda hech narsa bo'lmasa eski .env qiymatiga tushamiz
  const legacy = String(process.env.TARGET_CARD_SUFFIX || "")
    .replace(/\D/g, "")
    .slice(-4);
  if (legacy) expected.add(legacy);

  if (expected.size === 0) {
    return { ok: true, skipped: true };
  }

  const got = String(cardLast4 || "")
    .replace(/\D/g, "")
    .slice(-4);
  if (!got || !expected.has(got)) {
    return {
      ok: false,
      status: 400,
      body: {
        error: "To'lov karta raqami mos emas",
        code: "CARD_LAST4_MISMATCH",
        expected: [...expected],
        received: got || null,
      },
    };
  }
  return { ok: true };
}
