const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (_req, res) => {
  res.send("Sentinel AI backend running");
});

function hasPhishingIndicator(signals) {
  if (!Array.isArray(signals)) return false;

  const phishingHints = [
    "phishing",
    "credential",
    "login-spoof",
    "spoof",
    "typosquat",
    "lookalike",
    "suspicious-form",
    "fake-brand",
  ];

  return signals.some((signal) => {
    const text = String(signal || "").toLowerCase();
    return phishingHints.some((hint) => text.includes(hint));
  });
}

app.post("/analyze", (req, res) => {
  const { url, signals, score, confidence } = req.body || {};

  const normalizedScore = Number(score || 0);
  const normalizedConfidence = Number(confidence || 0);
  const phishingSignalDetected = hasPhishingIndicator(signals);

  let decision = "safe";
  let reasoning = `Low risk signals for ${url || "this URL"} based on current score and indicators.`;

  if (normalizedScore >= 7 || phishingSignalDetected) {
    decision = "malicious";
    reasoning = phishingSignalDetected
      ? "Marked malicious because phishing indicators were detected in the signal set."
      : "Marked malicious because risk score is 7 or higher.";
  } else if (normalizedScore >= 4) {
    decision = "suspicious";
    reasoning = "Marked suspicious because risk score is between 4 and 6.";
  }

  res.json({
    decision,
    reasoning,
    confidence: Math.max(0, Math.min(100, normalizedConfidence)),
  });
});

app.listen(3000, () => {
  console.log("Sentinel AI backend running on http://localhost:3000");
});

