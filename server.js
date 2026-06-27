const http = require("http");
const fs   = require("fs");
const path = require("path");

const root = __dirname;
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || "0.0.0.0";

// ── MIME TYPES ──
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".js":   "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".ico":  "image/x-icon",
  ".png":  "image/png",
  ".jpg":  "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif":  "image/gif",
  ".svg":  "image/svg+xml",
  ".webp": "image/webp",
  ".woff": "font/woff",
  ".woff2":"font/woff2",
  ".ttf":  "font/ttf",
  ".otf":  "font/otf",
  ".txt":  "text/plain; charset=utf-8",
  ".pdf":  "application/pdf",
};

// ── SECURITY HEADERS ──
// CSP: allow only same-origin scripts + styles + fonts from Google.
// No inline scripts → all JS must be in app.js (already the case).
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  // styles: self + Google Fonts stylesheet
  "style-src 'self' https://fonts.googleapis.com",
  // fonts: self + Google Fonts files
  "font-src 'self' https://fonts.gstatic.com",
  // images: self + data URIs (favicon inline svg)
  "img-src 'self' data:",
  // connect: self + HaveIBeenPwned API for breach checks
  "connect-src 'self' https://api.pwnedpasswords.com",
  // everything else: block
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "upgrade-insecure-requests",
].join("; ");

const SECURITY_HEADERS = {
  // Prevent clickjacking
  "X-Frame-Options":           "DENY",
  // Prevent MIME sniffing
  "X-Content-Type-Options":    "nosniff",
  // No referrer sent to external sites
  "Referrer-Policy":           "no-referrer",
  // Disable dangerous browser features
  "Permissions-Policy":        "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
  // Force HTTPS (1 year, include subdomains)
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  // XSS filter (legacy browsers)
  "X-XSS-Protection":          "1; mode=block",
  // CSP
  "Content-Security-Policy":   CSP,
  // No caching for sensitive content
  "Cache-Control":             "no-store, no-cache, must-revalidate",
  "Pragma":                    "no-cache",
  "Expires":                   "0",
};

// ── FAILED LOGIN TRACKING (rate-limit brute force) ──
// Simple in-memory store: IP → { count, firstAt }
const failedAttempts = new Map();
const MAX_ATTEMPTS   = 20;   // per window
const WINDOW_MS      = 15 * 60 * 1000; // 15 minutes

function getClientIP(req) {
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
}

function isRateLimited(ip) {
  const now = Date.now();
  const record = failedAttempts.get(ip);
  if (!record) return false;
  if (now - record.firstAt > WINDOW_MS) { failedAttempts.delete(ip); return false; }
  return record.count >= MAX_ATTEMPTS;
}

function recordFailure(ip) {
  const now = Date.now();
  const record = failedAttempts.get(ip);
  if (!record || Date.now() - record.firstAt > WINDOW_MS) {
    failedAttempts.set(ip, { count: 1, firstAt: now });
  } else {
    record.count++;
  }
}

// ── SERVER ──
const server = http.createServer((req, res) => {
  const ip  = getClientIP(req);
  const url = new URL(req.url, `http://${host}:${port}`);
  const requested = url.pathname === "/" ? "/index.html" : url.pathname;

  // Path traversal protection
  const filePath = path.normalize(path.join(root, requested));
  if (!filePath.startsWith(root + path.sep) && filePath !== root) {
    res.writeHead(403, SECURITY_HEADERS);
    res.end("Forbidden");
    return;
  }

  // Rate limit check (only for POST if ever added; still good to guard all)
  if (isRateLimited(ip)) {
    res.writeHead(429, { ...SECURITY_HEADERS, "Content-Type": "text/plain" });
    res.end("Too Many Requests");
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      // Record as a possible scan attempt
      recordFailure(ip);
      res.writeHead(404, { ...SECURITY_HEADERS, "Content-Type": "text/plain" });
      res.end("Not found");
      return;
    }

    const ext  = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || "application/octet-stream";

    res.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": mime });
    res.end(data);
  });
});

server.listen(port, host, () => {
  console.log(`Tresor läuft auf http://${host}:${port}/`);
});
