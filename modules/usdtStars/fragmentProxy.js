/**
 * Fragment HTTP/SOCKS proxy — .env FRAGMENT_HTTP_PROXY
 * Tor: socks5://127.0.0.1:9050
 * HTTP: http://user:pass@host:port
 */
import nodeFetch from "node-fetch";
import { SocksProxyAgent } from "socks-proxy-agent";

/** socks5 → socks5h: DNS ham proxy (Tor) orqali */
export function normalizeFragmentProxyUrl(proxy) {
  const p = String(proxy || "").trim();
  if (p.toLowerCase().startsWith("socks5://")) {
    return `socks5h://${p.slice("socks5://".length)}`;
  }
  return p;
}

export function getFragmentHttpProxy() {
  const raw = (process.env.FRAGMENT_HTTP_PROXY || "").trim();
  return raw ? normalizeFragmentProxyUrl(raw) : "";
}

export function isSocksProxyUrl(proxy) {
  const u = String(proxy || "").toLowerCase();
  return (
    u.startsWith("socks4://") ||
    u.startsWith("socks5://") ||
    u.startsWith("socks5h://") ||
    u.startsWith("socks://")
  );
}

export function describeFragmentProxy() {
  const proxy = getFragmentHttpProxy();
  if (!proxy) return { enabled: false, type: null, url: null };
  return {
    enabled: true,
    type: isSocksProxyUrl(proxy) ? "socks" : "http",
    url: proxy.replace(/:[^:@/]+@/, ":***@"),
  };
}

export async function fragmentFetch(url, init = {}) {
  const proxy = getFragmentHttpProxy();
  if (!proxy) {
    return globalThis.fetch(url, init);
  }

  if (isSocksProxyUrl(proxy)) {
    const agent = new SocksProxyAgent(proxy);
    return nodeFetch(url, { ...init, agent });
  }

  try {
    const { ProxyAgent } = await import("undici");
    return globalThis.fetch(url, { ...init, dispatcher: new ProxyAgent(proxy) });
  } catch {
    throw new Error(
      "HTTP proxy uchun `undici` kerak yoki Tor uchun FRAGMENT_HTTP_PROXY=socks5://127.0.0.1:9050 ishlating"
    );
  }
}
