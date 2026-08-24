import http from "node:http";
import { URL } from "node:url";
import httpProxy from "http-proxy";

const target = process.env.BACKEND_URL;
const apiKey = process.env.BACKEND_API_KEY;
const allowedOrigins = new Set((process.env.ALLOWED_ORIGINS || "").split(",").map((v) => v.trim()).filter(Boolean));
const port = Number(process.env.PORT || 10000);
const windowMs = 60_000;
const rawLimit = process.env.RATE_LIMIT_PER_MINUTE;
const maxRequests = rawLimit !== undefined ? Number(rawLimit) : 120;
const counters = new Map();
const zohoWebhookSecret = process.env.ZOHO_WEBHOOK_SECRET || "";

if (!target || !apiKey || allowedOrigins.size === 0) {
  throw new Error("BACKEND_URL, BACKEND_API_KEY, and ALLOWED_ORIGINS are required");
}

const proxy = httpProxy.createProxyServer({ changeOrigin: true, ws: true, xfwd: true });
proxy.on("proxyReq", (proxyReq) => {
  proxyReq.removeHeader("x-api-key");
  proxyReq.setHeader("X-API-KEY", apiKey);
});
proxy.on("error", (err, req, res) => {
  const origin = req.headers.origin;
  if (res && !res.headersSent) res.writeHead(502, { "Content-Type": "application/json" });
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  if (res) res.end(JSON.stringify({ 
    error: "Bad Gateway",
    message: "Unable to reach the backend service. Please try again later."
  }));
  console.error("proxy error", err.message);
});

function allowedOrigin(req) {
  const origin = req.headers.origin;
  return !origin || allowedOrigins.has(origin);
}

function isValidZohoRequest(req) {
  if (!zohoWebhookSecret) return false;
  // Check header first
  const headerSecret = req.headers["x-zoho-webhook-secret"];
  if (headerSecret && headerSecret === zohoWebhookSecret) return true;
  // Check query parameter for Zoho Plug compatibility
  const url = new URL(req.url, `http://localhost:${port}`);
  const querySecret = url.searchParams.get("secret");
  return querySecret && querySecret === zohoWebhookSecret;
}

function limited(req) {
  if (maxRequests <= 0) return false;
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").toString().split(",")[0];
  const now = Date.now();
  const entry = counters.get(ip);
  if (!entry || now - entry.start >= windowMs) { counters.set(ip, { start: now, count: 1 }); return false; }
  entry.count += 1;
  return entry.count > maxRequests;
}

const server = http.createServer((req, res) => {
  const origin = req.headers.origin;
  const isZohoRequest = isValidZohoRequest(req);
  const isZohoPath = req.url && req.url.startsWith("/api/v1/escalate/");
  const isAllowedOrigin = !origin || allowedOrigins.has(origin);
  
  // Health check endpoint - must be first to bypass rate limiting/CORS
  if (req.url === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'healthy', timestamp: new Date().toISOString() }));
  }
  
  if (req.method === "OPTIONS") {
    if (!allowedOrigin(req) && !isValidZohoRequest(req)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ 
        error: "Forbidden",
        message: "This origin is not allowed to access the API."
      }));
    }
    const headers = {
      "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Accept, Authorization, Content-Type, X-API-KEY, X-Zoho-Webhook-Secret",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Max-Age": "86400",
    };
    if (origin) headers["Access-Control-Allow-Origin"] = origin;
    res.writeHead(204, headers);
    return res.end();
  }
  
  if (!allowedOrigin(req) && !isValidZohoRequest(req)) { 
    res.writeHead(403, { "Content-Type": "application/json" }); 
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
    return res.end(JSON.stringify({ 
      error: "Forbidden",
      message: "This origin is not allowed to access the API."
    })); 
  }
  
  // Skip rate limiting for Zoho webhook paths (server-to-server)
  if (!isZohoPath && limited(req)) { 
    res.writeHead(429, { 
      "retry-after": "60",
      "Content-Type": "application/json"
    }); 
    return res.end(JSON.stringify({ 
      error: "Too Many Requests",
      message: "You've made too many requests. Please wait a moment and try again.",
      retryAfter: 60
    })); 
  }
  
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  
  req.headers["x-api-key"] = apiKey;
  req.headers["authorization"] = req.headers.authorization || "";
  proxy.web(req, res, { target, ignorePath: false });
});

server.on("upgrade", (req, socket, head) => {
  const isZohoRequest = isValidZohoRequest(req);
  const isAllowedOrigin = allowedOrigin(req);
  
  if (!isAllowedOrigin && !isZohoRequest) return socket.destroy();
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