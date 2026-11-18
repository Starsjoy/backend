/**
 * Donat katalogi: qaysi o'yinlar sotiladi va StarsPaymee'dagi qaysi mahsulotga mos keladi.
 *
 * kind:
 *  - "game"     — akkauntga to'g'ridan-to'g'ri (POST /games/{code}/order), player_id kerak
 *  - "giftcard" — kod/havola beriladi (POST /giftcards/{category}/order), player_id kerak emas
 *
 * Narx har doim StarsPaymee'dan jonli olinadi (USDT) va ustiga ustama qo'shiladi.
 * `allow` — faqat shu nomlar sotiladi (bo'sh bo'lsa hammasi). Nomlar katalogdagi
 * `name` bilan AYNAN bir xil bo'lishi shart (PUBG: "60 UC" ≠ "60 WOW Coins").
 */

export const DONAT_GAMES = [
  {
    slug: "pubg-mobile",
    code: "pubgm",
    kind: "game",
    title: "PUBG Mobile",
    unit: "UC",
    defaultMarkup: 15,
    idLabel: "Player ID",
    idHint: "Profil → nik ostidagi raqam (masalan 51221257198)",
    allow: [
      "60 UC",
      "325 UC",
      "660 UC",
      "1800 UC",
      "3850 UC",
      "8100 UC",
      "Prime (1 Month)",
      "Prime Plus (1 Month)",
      "Elite Pass LV1-50",
      "Elite Pass LV1-100",
      "Elite Pass Plus LV1-100",
    ],
  },
  {
    slug: "free-fire",
    code: "freefire_global",
    kind: "game",
    title: "Free Fire",
    unit: "olmos",
    defaultMarkup: 30,
    idLabel: "Player ID (UID)",
    idHint: "Profil → nik ostidagi UID",
    allow: [],
  },
  {
    slug: "standoff-2",
    code: "standoff2_gold",
    kind: "giftcard",
    title: "Standoff 2",
    unit: "Gold",
    defaultMarkup: 30,
    idLabel: null,
    idHint: null,
    allow: [],
  },
];

export const GAME_BY_SLUG = new Map(DONAT_GAMES.map((g) => [g.slug, g]));

export function markupKey(game) {
  return `donat_markup_${game.code}`;
}
