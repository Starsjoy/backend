import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import os from "os";
import {
  getFragmentTokens,
  resolveFragmentTokens,
  fragmentTokensReady,
  fragmentTokenFingerprint,
  fragmentTokensToProcessEnv,
} from "../tokens/tokensDb.js";
import {
  getCachedSettings,
  loadSettings,
  normalizeFragmentPaymentMethod,
} from "../settings/settingsDb.js";
import { fragmentFetch, describeFragmentProxy } from "./fragmentProxy.js";

export { describeFragmentProxy };

async function resolveFragmentPaymentMethod(pool, getFragmentPaymentMethod) {
  if (typeof getFragmentPaymentMethod === "function") {
    return normalizeFragmentPaymentMethod(getFragmentPaymentMethod());
  }
  if (pool) {
    return loadSettings(pool).then((s) => s.fragment_payment_method);
  }
  return getCachedSettings().fragment_payment_method;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH = path.join(__dirname, "fragment_cli.py");

function pythonCommand() {
  return process.env.PYTHON_PATH || (process.platform === "win32" ? "python" : "python3");
}

function hasWalletEnv() {
  return Boolean(process.env.SEED?.trim() && process.env.API_KEY?.trim());
}

export function isFragmentCookieError(message) {
  const s = String(message || "").toLowerCase();
  return (
    s.includes("403") ||
    s.includes("cookie") ||
    s.includes("expired") ||
    (s.includes("invalid") && s.includes("fragment")) ||
    s.includes("tokens jadval")
  );
}

function runFragmentCli(extraArgs = [], spawnEnv = process.env) {
  return new Promise((resolve) => {
    const proc = spawn(pythonCommand(), [CLI_PATH, ...extraArgs], {
      cwd: path.join(__dirname, "../.."),
      env: spawnEnv,
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    proc.stderr.on("data", (d) => {
      stderr += d.toString();
    });

    proc.on("error", (err) => {
      resolve({ ok: false, error: `Python ishga tushmadi: ${err.message}` });
    });

    proc.on("close", () => {
      const line = stdout.trim().split("\n").filter(Boolean).pop() || "";
      try {
        const parsed = JSON.parse(line);
        if (!parsed.ok && !parsed.success && stderr) {
          parsed.stderr = stderr.slice(0, 500);
        }
        resolve(parsed);
      } catch {
        resolve({
          ok: false,
          error: stderr || stdout || "Fragment CLI javob bermadi",
        });
      }
    });
  });
}

/** @deprecated sync tekshiruv — pool bilan ishlating */
export function fragmentEnvReady() {
  return hasWalletEnv();
}

export async function fragmentEnvReadyAsync(pool) {
  if (!hasWalletEnv()) return false;
  try {
    const tokens = await getFragmentTokens(pool);
    return fragmentTokensReady(tokens);
  } catch {
    return false;
  }
}

/** Node.js orqali Fragment cookie tekshiruvi (Python/psycopg2 shart emas) */
export async function verifyFragmentCookiesHttp(tokens) {
  const dt = tokens.fragment_dt || "-300";
  const ssid = tokens.fragment_ssid || "";
  const token = tokens.fragment_token || "";
  const ton = tokens.fragment_ton_token || "";
  if (!ssid || !token) {
    return { ok: false, error: "fragment_ssid va fragment_token kerak" };
  }

  const parts = [`stel_dt=${dt}`, `stel_ssid=${ssid}`, `stel_token=${token}`];
  if (ton) parts.push(`stel_ton_token=${ton}`);

  try {
    const res = await fragmentFetch("https://fragment.com/stars/buy", {
      method: "GET",
      headers: {
        Cookie: parts.join("; "),
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      redirect: "follow",
    });

    if (res.status === 403) {
      const looksLikeValidCookieShape =
        ssid.length >= 20 && token.length >= 40;
      return {
        ok: false,
        status: 403,
        likely_cause: looksLikeValidCookieShape ? "vps_ip_block" : "invalid_or_expired_cookie",
        error: looksLikeValidCookieShape
          ? "Fragment 403: cookie formati to'g'ri, lekin server (VPS) IP bloklangan bo'lishi mumkin."
          : "Fragment 403: cookie yaroqsiz yoki muddati tugagan.",
        hints: looksLikeValidCookieShape
          ? [
              "Lokalda 200 + serverda 403 bo'lsa — FRAGMENT_HTTP_PROXY (Tor: socks5://127.0.0.1:9050) qo'shing.",
              "Tor: systemctl start tor && npm run fragment:test-cookie → 200, keyin restart.",
            ]
          : [
              "Brauzerdan yangi cookie oling va admin Sozlamalar → 4 maydonni saqlang.",
              "Server `tokens` jadvali lokal .env dan farq qilmasin (seed faqat bir marta).",
            ],
      };
    }
    if (!res.ok) {
      return { ok: false, status: res.status, error: `Fragment HTTP ${res.status}` };
    }
    return { ok: true, status: res.status };
  } catch (err) {
    return { ok: false, error: err.message || "Fragment tekshiruv xatosi" };
  }
}

export async function verifyFragmentCookies(pool) {
  if (!hasWalletEnv()) {
    return {
      ok: false,
      error: "SEED va API_KEY .env da kerak",
    };
  }
  const tokens = await getFragmentTokens(pool);
  if (!fragmentTokensReady(tokens)) {
    return {
      ok: false,
      error: "tokens jadvalida fragment_ssid va fragment_token to'ldiring",
    };
  }

  const diagnostics = {
    host: os.hostname(),
    token_source: "postgresql_tokens_table",
    proxy: describeFragmentProxy(),
    token_fingerprint: fragmentTokenFingerprint(tokens),
    database_host: (() => {
      try {
        return new URL(process.env.DATABASE_URL || "").hostname || "(noma'lum)";
      } catch {
        return "(noma'lum)";
      }
    })(),
  };

  const httpResult = await verifyFragmentCookiesHttp(tokens);
  const merged = { ...httpResult, diagnostics };

  if (httpResult.ok) {
    return merged;
  }

  // Fallback: Python (psycopg2 kerak bo'lishi mumkin)
  const env = fragmentTokensToProcessEnv(process.env, tokens);
  const pyResult = await runFragmentCli(["--verify-cookies"], env);
  if (pyResult.ok) {
    return { ...pyResult, diagnostics };
  }
  return merged;
}

export async function buyStarsViaFragment(recipientUsername, amount, pool, opts = {}) {
  const recipient = String(recipientUsername || "")
    .trim()
    .replace(/^@/, "");
  const stars = parseInt(amount, 10);

  if (!recipient) {
    return { success: false, error: "Username kerak" };
  }
  if (!Number.isInteger(stars) || stars < 50 || stars > 10000) {
    return { success: false, error: "Stars 50–10000 oralig'ida bo'lishi kerak" };
  }
  if (!hasWalletEnv()) {
    return { success: false, error: "SEED va API_KEY .env da kerak" };
  }

  const { tokens, source: tokenSource } = await resolveFragmentTokens(pool, "auto");
  if (!fragmentTokensReady(tokens)) {
    return {
      success: false,
      error:
        "Fragment cookie yo'q: .env (FRAGMENT_SSID/TOKEN) yoki tokens jadvalini to'ldiring",
    };
  }

  const paymentMethod = await resolveFragmentPaymentMethod(pool, opts.getFragmentPaymentMethod);
  const env = fragmentTokensToProcessEnv(process.env, tokens, paymentMethod);

  console.log("🔹 buyStarsViaFragment:", {
    recipient,
    stars,
    payment_method: paymentMethod,
    token_source: tokenSource,
  });

  return runFragmentCli(
    ["--recipient", recipient, "--amount", String(stars), "--payment-method", paymentMethod],
    env
  ).then(parseFragmentCliResult);
}

function parseFragmentCliResult(parsed) {
  if (parsed.success === true) return parsed;
  if (parsed.ok === true) return { success: true, transaction_id: parsed.transaction_id };
  return {
    success: false,
    error: parsed.error || parsed.stderr || "Fragment xatosi",
  };
}

export async function buyPremiumViaFragment(recipientUsername, months, pool, opts = {}) {
  const recipient = String(recipientUsername || "")
    .trim()
    .replace(/^@/, "");
  const m = parseInt(months, 10);

  if (!recipient) {
    return { success: false, error: "Username kerak" };
  }
  if (![3, 6, 12].includes(m)) {
    return { success: false, error: "Premium: months 3, 6 yoki 12 bo'lishi kerak" };
  }
  if (!hasWalletEnv()) {
    return { success: false, error: "SEED va API_KEY .env da kerak" };
  }

  const { tokens, source: tokenSource } = await resolveFragmentTokens(pool, "auto");
  if (!fragmentTokensReady(tokens)) {
    return {
      success: false,
      error:
        "Fragment cookie yo'q: .env (FRAGMENT_SSID/TOKEN) yoki tokens jadvalini to'ldiring",
    };
  }

  const paymentMethod = await resolveFragmentPaymentMethod(pool, opts.getFragmentPaymentMethod);
  const env = fragmentTokensToProcessEnv(process.env, tokens, paymentMethod);

  console.log("🔹 buyPremiumViaFragment:", {
    recipient,
    months: m,
    payment_method: paymentMethod,
    token_source: tokenSource,
  });

  return runFragmentCli(
    [
      "--premium",
      "--recipient",
      recipient,
      "--months",
      String(m),
      "--payment-method",
      paymentMethod,
    ],
    env
  ).then(parseFragmentCliResult);
}
