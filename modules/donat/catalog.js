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
    slug: "mobile-legends",
    code: "mlbb_global",
    kind: "game",
    needsServer: true, // Zone ID — o'yinda ID yonidagi qavs ichidagi raqam
    title: "Mobile Legends",
    unit: "olmos",
    defaultMarkup: 30,
    idLabel: "User ID + Zone ID",
    idHint: null,
    // Faqat barcha mintaqalarda ishlaydigan paketlar + Weekly/Twilight va birinchi to'ldirish bonuslari
    allow: [
      "14 Diamonds", "28 Diamonds", "70 Diamonds", "140 Diamonds", "284 Diamonds", "355 Diamonds",
      "429 Diamonds", "716 Diamonds", "1446 Diamonds", "2976 Diamonds", "7502 Diamonds",
      "Weekly Pass", "Twilight Pass",
      "50 + 5 Diamonds (First Top-Up Bonus)", "150 + 15 Diamonds (First Top-Up Bonus)",
      "250 + 25 Diamonds (First Top-Up Bonus)", "500 + 65 Diamonds (First Top-Up Bonus)",
    ],
  },
  {
    slug: "standoff-2",
    code: "standoff2_gold",
    kind: "giftcard",
    secretKind: "link", // aktivatsiya havolasi
    title: "Standoff 2",
    unit: "Gold",
    defaultMarkup: 30,
    idLabel: null,
    idHint: null,
    allow: [],
  },
  {
    slug: "roblox",
    code: "roblox_global",
    kind: "giftcard",
    secretKind: "code", // Roblox kodi — roblox.com/redeem da kiritiladi
    title: "Roblox",
    unit: "Robux",
    defaultMarkup: 30,
    idLabel: null,
    idHint: null,
    allow: [],
  },
  {
    slug: "delta-force",
    code: "deltaforce",
    kind: "game",
    title: "Delta Force",
    unit: "Delta Coins",
    defaultMarkup: 30,
    idLabel: "Player ID",
    idHint: null,
    allow: [],
  },
  {
    slug: "blood-strike",
    code: "bloodstrike",
    kind: "game",
    title: "Blood Strike",
    unit: "BC",
    defaultMarkup: 30,
    idLabel: "Player ID",
    idHint: null,
    allow: ["51 BC", "105 BC", "320 BC", "540 BC", "1100 BC", "2260 BC", "5800 BC", "Level Up Pass", "Strike Pass Elite", "Strike Pass Premium"],
  },
  {
    slug: "honor-of-kings",
    code: "hok",
    kind: "game",
    title: "Honor of Kings",
    unit: "Tokens",
    defaultMarkup: 30,
    idLabel: "Player ID",
    idHint: null,
    allow: ["16 Tokens", "80 Tokens", "240 Tokens", "400 Tokens", "560 Tokens", "830 Tokens", "1245 Tokens", "2508 Tokens", "4180 Tokens", "8360 Tokens", "Weekly Card", "Weekly Card Plus"],
  },
  {
    slug: "arena-breakout",
    code: "arena_breakout",
    kind: "game",
    title: "Arena Breakout",
    unit: "Bonds",
    defaultMarkup: 30,
    idLabel: "Player ID",
    idHint: null,
    allow: [],
  },
];

export const GAME_BY_SLUG = new Map(DONAT_GAMES.map((g) => [g.slug, g]));

export function markupKey(game) {
  return `donat_markup_${game.code}`;
}
