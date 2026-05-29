/**
 * Fragment Python kutubxonalarini tekshirish.
 * cd backend && node scripts/check-python-deps.js
 */
import { spawnSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const py = process.env.PYTHON_PATH || (process.platform === "win32" ? "python" : "python3");

const modules = ["dotenv", "socks", "psycopg2", "pyfragment"];
const missing = [];

for (const mod of modules) {
  const r = spawnSync(py, ["-c", `import ${mod}`], {
    cwd: root,
    encoding: "utf8",
  });
  if (r.status !== 0) {
    missing.push(mod);
    console.error(`❌ ${mod}: yo'q`);
    if (r.stderr) console.error(r.stderr.trim().slice(0, 200));
  } else {
    console.log(`✅ ${mod}`);
  }
}

if (missing.length) {
  console.error("\n👉 O'rnatish: pip3 install -r requirements.txt");
  console.error("   yoki: npm run fragment:install");
  process.exit(1);
}

console.log("\n✅ Barcha Fragment Python modullari tayyor");
