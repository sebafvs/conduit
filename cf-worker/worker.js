const ALLOWED_PATHS = new Set(["/sync/update", "/metrics/push", "/payload"]);
const EXPECTED_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

const DECOY_HTML =
  "<!DOCTYPE html><html><head><title>403 Forbidden</title></head>" +
  "<body><center><h1>403 Forbidden</h1></center><hr>" +
  "<center>cloudflare</center></body></html>";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Let ACME challenges through so LE cert renewal works
    if (url.pathname.startsWith("/.well-known/acme-challenge/")) {
      return fetch(request);
    }

    const isPost = request.method === "POST";
    const pathMatch = ALLOWED_PATHS.has(url.pathname);
    const uaMatch = request.headers.get("user-agent") === EXPECTED_UA;
    const hasHeartbeat = request.headers.has("x-cache-tag");

    if (isPost && pathMatch && uaMatch && hasHeartbeat) {
      return fetch(request);
    }

    return new Response(DECOY_HTML, {
      status: 403,
      headers: {
        "content-type": "text/html; charset=UTF-8",
        "server": "cloudflare",
        "cache-control": "no-store",
      },
    });
  },
};
