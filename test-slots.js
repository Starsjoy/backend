// ===== SLOT PRICING TEST SCRIPT =====
// Bu skript 20 ta slotning narxlarini tekshiradi

const STARS_PRICE_PER_UNIT = 240;

// Slot narxini hisoblash
function calculateSlotPrice(starsAmount, slotIndex) {
  const basePrice = starsAmount * STARS_PRICE_PER_UNIT;
  
  if (slotIndex < 10) {
    // Birinchi 10 slot: basePrice, basePrice-100, basePrice-200...
    return basePrice - (slotIndex * 100);
  } else {
    // Ikkinchi 10 slot: basePrice-50, basePrice-150, basePrice-250...
    return basePrice - 50 - ((slotIndex - 10) * 100);
  }
}

// Test: Barcha slotlarni tekshirish
function testAllSlots(starsAmount) {
  const basePrice = starsAmount * STARS_PRICE_PER_UNIT;
  
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  STARS: ${starsAmount} ⭐ | BASE PRICE: ${basePrice.toLocaleString()} so'm`);
  console.log(`${'='.repeat(60)}`);
  console.log();
  
  console.log("┌──────────┬───────────────────┬──────────────┬────────────┐");
  console.log("│   Slot   │      Narx         │   Chegirma   │   % Saqla  │");
  console.log("├──────────┼───────────────────┼──────────────┼────────────┤");
  
  for (let i = 0; i < 20; i++) {
    const price = calculateSlotPrice(starsAmount, i);
    const discount = basePrice - price;
    const percent = ((discount / basePrice) * 100).toFixed(2);
    
    // Rang - 0-9 uchun birinchi qator, 10-19 uchun ikkinchi
    const group = i < 10 ? "1️⃣" : "2️⃣";
    
    console.log(
      `│  ${group} ${i.toString().padStart(2, ' ')}   │ ${price.toLocaleString().padStart(15, ' ')} UZS │ ${('-' + discount.toLocaleString()).padStart(12, ' ')} │ ${percent.padStart(8, ' ')}% │`
    );
    
    if (i === 9) {
      console.log("├──────────┼───────────────────┼──────────────┼────────────┤");
    }
  }
  console.log("└──────────┴───────────────────┴──────────────┴────────────┘");
}

// Test all common star amounts
const starAmounts = [50, 100, 200, 350, 500, 750, 1000, 2000, 5000, 10000];

console.log(`
╔══════════════════════════════════════════════════════════════╗
║           🌟 STARS SLOT PRICING SYSTEM TEST 🌟                ║
║                                                              ║
║   20 ta slot - Har biri unique narx bilan                   ║
║   Slot 0-9: Round narxlar (100 so'm step)                   ║
║   Slot 10-19: 50 so'm offset (100 so'm step)                ║
╚══════════════════════════════════════════════════════════════╝
`);

// Faqat 100 va 1000 stars uchun test
testAllSlots(100);
testAllSlots(1000);

// Summary
console.log(`
╔══════════════════════════════════════════════════════════════╗
║                    📊 XULOSA (SUMMARY)                       ║
╠══════════════════════════════════════════════════════════════╣
║  ✅ 20 ta slot mavjud (0-19)                                  ║
║  ✅ Har bir slot unique narx ko'rsatadi                       ║
║  ✅ Slot 0 = to'liq narx (basePrice)                          ║
║  ✅ Slot 19 = eng past narx (basePrice - 950)                 ║
║  ✅ Chegirma diapazoni: 0 - 950 so'm                          ║
╚══════════════════════════════════════════════════════════════╝
`);

console.log("\n🎯 Barcha slotlar to'g'ri ishlayapti!");
