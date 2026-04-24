/**
 * Minimal AI decision backend for Sentinel Browse
 * Run: node backend/ai-server.js
 *
 * API:
 *   POST /analyze
 *   Body: { url, signals, score, confidence }
 *   Response: { decision, reasoning, confidence }
 */

"use strict";

const http = require("http");

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

function json(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(JSON.stringify(body));
}

function normalizeDecision(input, fallback = "suspicious") {
  const d = String(input || "").trim().toLowerCase();
  if (["malicious", "phishing", "scam"].includes(d)) return "malicious";
  if (["suspicious", "uncertain", "risky"].includes(d)) return "suspicious";
  if (["safe", "benign", "clean"].includes(d)) return "safe";
  return fallback;
}

// "LangChain-style" agent orchestrator entrypoint (tool-based or LLM-backed).
// Replace the logic in this function with your real model + tools workflow.
async function runSecurityAgent(input) {
  const { url = "", signals = [], score = 0, confidence = 0 } = input || {};

  const hasPhishingSignals = Array.isArray(signals) && signals.some((s) =>
    /phish|imperson|redirect|typo|credential|scam/i.test(String(s))
  );

  if (score >= 8 || hasPhishingSignals) {
    return {
      decision: "malicious",
      reasoning: "Detected phishing patterns with brand impersonation and redirect behavior",
      confidence: Math.max(88, Number(confidence) || 0),
    };
  }

  if (score >= 5) {
    return {
      decision: "suspicious",
      reasoning: "Multiple weak signals observed; site appears risky but not conclusively malicious",
      confidence: 75,
    };
  }

  return {
    decision: "safe",
    reasoning: `No high-confidence malicious indicators found for ${url || "this URL"}`,
    confidence: 70,
  };
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    return json(res, 200, { ok: true });
  }

  if (req.method === "GET" && req.url === "/health") {
    return json(res, 200, { ok: true, service: "sentinel-ai", port: PORT });
  }

  if (req.method === "POST" && req.url === "/analyze") {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 1_000_000) req.destroy(); // basic body size cap
    });

    req.on("end", async () => {
      try {
        const body = raw ? JSON.parse(raw) : {};
        const result = await runSecurityAgent(body);
        return json(res, 200, {
          decision: normalizeDecision(result.decision),
          reasoning: String(result.reasoning || "").slice(0, 1000),
          confidence: Math.max(0, Math.min(100, Number(result.confidence) || 0)),
        });
      } catch (e) {
        return json(res, 400, { error: "Invalid request", detail: e.message });
      }
    });
    return;
  }

  return json(res, 404, { error: "Not found" });
});

server.listen(PORT, () => {
  console.log(`[Sentinel AI] listening on http://localhost:${PORT}`);
});

