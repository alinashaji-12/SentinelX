"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const BASE = __dirname;

function loadEngine() {
  const ctx = {
    console,
    URL,
    URLSearchParams,
    setTimeout,
    clearTimeout,
    globalThis: {},
  };
  ctx.global = ctx;
  ctx.window = ctx;
  ctx.self = ctx;
  vm.createContext(ctx);

  ["shared/trustedDomains.js", "shared/sentinelResult.js", "detectionEngine.js"].forEach((file) => {
    const src = fs.readFileSync(path.join(BASE, file), "utf8");
    vm.runInContext(src, ctx, { filename: file });
  });

  const engine = ctx.globalThis.SentinelDetectionEngine;
  if (!engine || typeof engine.analyzeUrl !== "function") {
    throw new Error("Failed to load SentinelDetectionEngine.analyzeUrl");
  }
  return {
    analyze: (url) => {
      const raw = engine.analyzeUrl(url);
      return typeof ctx.globalThis.normalizeSentinelResult === "function"
        ? ctx.globalThis.normalizeSentinelResult(raw)
        : raw;
    },
  };
}

function bucketPass(expected, result) {
  const s = String(result.status || "").toLowerCase();
  const score = Number(result.score || 0);
  if (expected === "SAFE") return s === "safe" && score >= 0 && score <= 20;
  if (expected === "UNCERTAIN") return (s === "suspicious" || s === "uncertain") && score >= 35 && score <= 65;
  if (expected === "BLOCKED") return (s === "malicious" || s === "blocked") && score >= 65;
  return false;
}

const MATRIX = [
  { expected: "SAFE", url: "https://www.nykaa.com/product?utm_source=google&utm_medium=cpc&utm_campaign=sale" },
  { expected: "SAFE", url: "https://chatgpt.com" },
  { expected: "SAFE", url: "https://www.1mg.com/medicines/anything" },
  { expected: "SAFE", url: "https://www.apollopharmacy.in/product/anything" },
  { expected: "SAFE", url: "https://www.amazon.in/dp/B0ANYTHING" },
  { expected: "SAFE", url: "https://www.flipkart.com/product/p/anything" },
  { expected: "SAFE", url: "https://www.practo.com/doctor-anything" },
  { expected: "SAFE", url: "https://www.healthline.com/article" },
  { expected: "SAFE", url: "https://www.mayoclinic.org/diseases" },
  { expected: "SAFE", url: "https://www.cerave.com/products" },

  // Proxy URLs for the uncertain profile requirements
  { expected: "UNCERTAIN", url: "https://newly-registered-example.in/login" },
  { expected: "UNCERTAIN", url: "http://insecure-login-example.test/login" },
  { expected: "UNCERTAIN", url: "https://no-privacy-new-domain.example/" },
  { expected: "UNCERTAIN", url: "https://new-domain-no-structured-data.example/path" },

  { expected: "BLOCKED", url: "https://nyk4a-sale.xyz" },
  { expected: "BLOCKED", url: "https://amazon-india-offer.tk" },
  { expected: "BLOCKED", url: "https://free-iphone-winner.ru" },
  { expected: "BLOCKED", url: "http://paytm-kyc-update.in" },
  { expected: "BLOCKED", url: "https://nykaa.com.free-gift.xyz" },
];

function main() {
  const { analyze } = loadEngine();
  let pass = 0;
  let fail = 0;

  const out = MATRIX.map((t) => {
    const r = analyze(t.url);
    const ok = bucketPass(t.expected, r);
    if (ok) pass++;
    else fail++;
    return {
      expected: t.expected,
      url: t.url,
      status: r.status,
      score: r.score,
      confidence: r.confidence,
      verdict: r.verdictSentence || "",
      pass: ok,
    };
  });

  console.log(JSON.stringify({ summary: { pass, fail, total: MATRIX.length }, results: out }, null, 2));
  process.exitCode = fail ? 1 : 0;
}

main();
