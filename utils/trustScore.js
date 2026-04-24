/**
 * trustScore.js — Sentinel Browse Extension
 *
 * Trust score conversion utilities.
 *
 * Req 6 formula: trustScore = max(0, 100 - score * 10)
 * This is the primary formula used by advancedEngine.js directly.
 * The functions below remain as compatibility wrappers used by the
 * popup and legacy callers that pass the raw score.
 */

/**
 * Converts a raw risk score to a 0–100 trust score.
 *
 * Formula (Req 6): trustScore = max(0, min(100, 100 - score * 10))
 *
 * Score → TrustScore examples:
 *   0 → 100  (totally safe)
 *  -3 → 100  (trusted domain bonus — clamped at 100)
 *   1 →  90
 *   3 →  70
 *   5 →  50
 *   7 →  30
 *  10+ → 0   (fully malicious)
 *
 * @param {number} rawScore
 * @returns {number} trustScore 0–100
 */
export function convertScoreToTrustScore(rawScore) {
  const score = Number(rawScore || 0);
  return Math.max(0, Math.min(100, 100 - score * 10));
}

/**
 * Compatibility wrapper — used by popup.js and legacy callers.
 * advancedEngine.js computes the trust score inline using the Req 6 formula.
 *
 * @param {{ score?: number, status?: string, reasons?: string[] }} result
 * @returns {{ trustScore: number, status: string, reasons: string[] }}
 */
export function buildTrustResult(result = {}) {
  return {
    trustScore: convertScoreToTrustScore(result.score),
    status: result.status || "safe",
    reasons: Array.isArray(result.reasons) ? result.reasons : [],
  };
}
