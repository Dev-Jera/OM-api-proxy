import http from "node:http";
import { URL } from "node:url";
import httpProxy from "http-proxy";

const target = process.env.BACKEND_URL;
const apiKey = process.env.BACKEND_API_KEY;
const allowedOrigins = new Set((process.env.ALLOWED_ORIGINS || "").split(",").map((v) => v.trim()).filter(Boolean));
const port = Number(process.env.PORT || 10000);
const windowMs = 60_000;
const maxRequests = Number(process.env.RATE_LIMIT_PER_MINUTE || 120);
const counters = new Map();

if (!target || !apiKey || allowedOrigins.size === 0) {
  throw new Error("BACKEND_URL, BACKEND_API_KEY, and ALLOWED_ORIGINS are required");
}

const proxy = httpProxy.createProxyServer({ changeOrigin: true, ws: true, xfwd: true });
proxy.on("proxyReq", (proxyReq) => {
  proxyReq.removeHeader("x-api-key");
  proxyReq.setHeader("X-API-KEY", apiKey);
});
proxy.on("error", (err, req, res) => {
  if (res && !res.headersSent) res.writeHead(502, { "content-type": "application/json" });
  if (res) res.end(JSON.stringify({ detail: "Upstream API unavailable" }));
  console.error("proxy error", err.message);
});

function allowedOrigin(req) {
  const origin = req.headers.origin;
  return !origin || allowedOrigins.has(origin);
}

function limited(req) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").toString().split(",")[0];
  const now = Date.now();
  const entry = counters.get(ip);
  if (!entry || now - entry.start >= windowMs) { counters.set(ip, { start: now, count: 1 }); return false; }
  entry.count += 1;
  return entry.count > maxRequests;
}

const server = http.createServer((req, res) => {
  const origin = req.headers.origin;
  
  if (req.method === "OPTIONS") {
    if (!allowedOrigin(req)) { res.writeHead(403); return res.end("Origin not allowed"); }
    res.writeHead(204, {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Accept, Authorization, Content-Type, X-API-KEY",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Max-Age": "86400",
    });
    return res.end();
  }
  
  if (!allowedOrigin(req)) { res.writeHead(403); return res.end("Origin not allowed"); }
  if (limited(req)) { res.writeHead(429, { "retry-after": "60" }); return res.end("Too many requests"); }
  
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  
  req.headers["x-api-key"] = apiKey;
  req.headers["authorization"] = req.headers.authorization || "";
  proxy.web(req, res, { target, ignorePath: false });
});

server.on("upgrade", (req, socket, head) => {
  if (!allowedOrigin(req) || limited(req)) return socket.destroy();
  req.headers["x-api-key"] = apiKey;
  const url = new URL(req.url, "http://proxy.local");
  const accessToken = url.searchParams.get("access_token");
  if (accessToken) req.headers.authorization = `Bearer ${accessToken}`;
  url.searchParams.delete("api_key");
  url.searchParams.delete("access_token");
  req.url = `${url.pathname}${url.search}`;
  proxy.ws(req, socket, head, { target });
});

server.listen(port, () => console.log(`API proxy listening on ${port}`));
