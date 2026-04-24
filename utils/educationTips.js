const EDUCATION_TIPS = [
  "Phishing awareness: Check the full domain name carefully before entering any password or one-time code.",
  "Phishing awareness: Urgent language like \"verify now\" or \"account locked\" is often used to pressure quick clicks.",
  "Phishing awareness: Hover over links and compare the destination with the brand's official website before signing in.",
  "Secure browsing tip: Avoid logging in from shortened or heavily encoded links unless you trust the sender and destination.",
  "Secure browsing tip: If a site asks for sensitive details unexpectedly, open a fresh tab and navigate to the official site manually.",
  "Secure browsing tip: Keep your browser and extensions updated so known malicious pages are easier to block."
];

export function getRandomEducationTip() {
  const index = Math.floor(Math.random() * EDUCATION_TIPS.length);
  return EDUCATION_TIPS[index];
}

export function getEducationTips() {
  return [...EDUCATION_TIPS];
}
