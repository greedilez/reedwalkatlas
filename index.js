import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", true);
app.use(express.json());

// === CORS ===
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Req-Id, X-Request-Id, X-Correlation-Id, X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, X-Forwarded-Host"
  );
  next();
});

const KEITARO_URL = "https://origin.citywingpatrol.click/citywingpatrol-site";

// === Helpers ===
function normalizeIp(ip) {
  if (!ip) return "";
  return String(ip).replace(/^::ffff:/, "").trim();
}

function detectClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) {
    const first = String(xff).split(",")[0].trim();
    if (first) return normalizeIp(first);
  }
  if (req.ip) return normalizeIp(req.ip);
  const remote = req.socket?.remoteAddress || "";
  return normalizeIp(remote);
}

function genReqId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return crypto.randomBytes(16).toString("hex");
}

// === Cache + Logging ===
const ipCache = new Map();
const logDir = path.join(process.cwd(), "logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);
const logPath = path.join(logDir, "blocked.log");

function logBlock(reason, ip, ua) {
  const line = `[${new Date().toISOString()}] [${reason}] IP=${ip} UA=${ua}\n`;
  fs.appendFile(logPath, line, (err) => {
    if (err) console.error("Failed to write log:", err);
  });
}

// === Proxy / VPN detection ===
async function isProxyOrVPN(ip) {
  if (!ip) return false;
  if (ipCache.has(ip)) return ipCache.get(ip);

  try {
    const resp = await fetch(`https://proxycheck.io/v2/${ip}?vpn=1&asn=1`);
    const data = await resp.json();
    const info = data[ip];
    const result = info?.proxy === "yes" || info?.type === "VPN" || info?.type === "Hosting";
    ipCache.set(ip, result);
    return result;
  } catch {
    return false;
  }
}

// === Main Guard Middleware ===
async function guard(req, res, next) {
  const ip = detectClientIp(req);
  const ua = (req.headers["user-agent"] || "").toLowerCase();

  // 1️⃣ Bot detection
  const botPatterns = [
    /bot/i,
    /spider/i,
    /crawl/i,
    /headless/i,
    /render/i,
    /monitor/i,
    /curl/i,
    /wget/i,
    /ping/i,
    /uptime/i,
    /google/i,
    /facebookexternalhit/i,
    /python-requests/i,
    /node-fetch/i,
  ];

  if (!ua || botPatterns.some((p) => p.test(ua))) {
    console.log(`[BOT BLOCK] ${ip} ${ua}`);
    logBlock("BOT", ip, ua);
    return res.status(403).json({ access: "denied", reason: "bot" });
  }

  // 2️⃣ VPN / Proxy
  const isProxy = await isProxyOrVPN(ip);
  if (isProxy) {
    console.log(`[VPN/PROXY BLOCK] ${ip}`);
    logBlock("VPN/PROXY", ip, ua);
    return res.status(403).json({ access: "denied", reason: "vpn_proxy" });
  }

  // 3️⃣ Emulator detection (по User-Agent)
  const emulatorPatterns = [
    /sdk_gphone/i,
    /sdk build/i,
    /android sdk built for/i,
    /emulator/i,
    /genymotion/i,
    /nox/i,
    /bluestacks/i,
    /ldplayer/i,
    /mumu/i,
    /memu/i,
    /archon/i,
    /x86_64/i,
    /intel/i,
    /virtual/i,
    /android_x86/i,
  ];

  if (emulatorPatterns.some((p) => p.test(ua))) {
    console.log(`[EMULATOR BLOCK] ${ip} ${ua}`);
    logBlock("EMULATOR", ip, ua);
    return res.status(403).json({ access: "denied", reason: "emulator" });
  }

  // 4️⃣ Anti-spam (Rate limiting)
  const now = Date.now();
  const data = ipCache.get(ip) || { last: 0, count: 0, proxy: isProxy };
  if (now - data.last < 2000) data.count++;
  else data.count = 1;
  data.last = now;
  ipCache.set(ip, data);

  if (data.count > 5) {
    console.log(`[RATE LIMIT BLOCK] ${ip}`);
    logBlock("RATE_LIMIT", ip, ua);
    return res.status(429).json({ access: "denied", reason: "rate_limit" });
  }

  next();
}


// === MAIN ENDPOINT ===
app.get("/", guard, async (req, res) => {
  try {
    const clientIp = detectClientIp(req);
    const incomingXFF = req.headers["x-forwarded-for"] || "";
    const incomingParts = String(incomingXFF)
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);

    const outgoingParts = [clientIp, ...incomingParts.filter((ip) => ip !== clientIp && ip !== "unknown")].filter(Boolean);
    const outgoingXFF = outgoingParts.join(", ");

    const reqId =
      req.headers["x-req-id"] ||
      req.headers["x-request-id"] ||
      req.headers["x-correlation-id"] ||
      genReqId();

    const forwardedProto = req.headers["x-forwarded-proto"] || req.protocol || (req.secure ? "https" : "http");
    const forwardedHost = req.headers["x-forwarded-host"] || req.headers.host || "";

    // === Правильная передача реального IP в Keitaro ===
    const fetchHeaders = {
      "User-Agent": req.headers["user-agent"] || "",
      "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
      Accept: req.headers["accept"] || "*/*",
      "X-Forwarded-For": outgoingXFF,
      "CF-Connecting-IP": clientIp, // ✅ Для Keitaro при Proxy фильтре
      "True-Client-IP": clientIp,   // ✅ Альтернативный способ
      "X-Real-IP": clientIp,
      "X-Forwarded-Proto": forwardedProto,
      "X-Forwarded-Host": forwardedHost,
      "X-Req-Id": reqId,
    };

    console.debug("Outgoing to Keitaro headers:", fetchHeaders);

    const response = await fetch(KEITARO_URL, {
      redirect: "follow",
      headers: fetchHeaders,
    });

    if (response.url !== KEITARO_URL) {
      return res.json({
        image_url: "",
        offer_url: response.url,
      });
    }

    const html = await response.text();
    let imageUrl = "";
    const imgIndex = html.indexOf("<img");
    if (imgIndex !== -1) {
      const srcIndex = html.indexOf("src=", imgIndex);
      if (srcIndex !== -1) {
        const startQuote = html[srcIndex + 4];
        const endQuote = html.indexOf(startQuote, srcIndex + 5);
        imageUrl = html.substring(srcIndex + 5, endQuote).trim();

        const LANDER_NAME = "citywing-patrol";
        if (imageUrl && !/^https?:\/\//i.test(imageUrl)) {
          try {
            const baseUrl = new URL(KEITARO_URL);
            imageUrl = `${baseUrl.origin}/lander/${LANDER_NAME}/${imageUrl.replace(/^\/+/, "")}`;
          } catch (e) {
            console.error("Failed to build absolute URL:", e);
          }
        }
      }
    }

    res.json({
      image_url: imageUrl || "",
      offer_url: "",
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({ error: "Failed to fetch Keitaro URL" });
  }
});

// === SERVER START ===
app.listen(PORT, () => {
  console.log("✅ API running on port", PORT);
});

