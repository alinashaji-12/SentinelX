var TRUSTED_APEX_DOMAINS = new Set([
  "google.com", "youtube.com", "github.com", "microsoft.com",
  "apple.com", "cloudflare.com", "amazon.com", "anthropic.com",
  "claude.ai", "wikipedia.org", "mozilla.org", "stripe.com",
]);

var TRUSTED_FULL_DOMAINS = new Set([
  "www.google.com", "mail.google.com", "docs.google.com",
  "www.github.com", "api.github.com", "github.com",
  "www.youtube.com", "www.microsoft.com", "claude.ai",
]);

// CATEGORY: Indian E-Commerce & Retail
const INDIAN_ECOMMERCE = [
  "nykaa.com", "nykaafashion.com", "nykaabeauty.com",
  "myntra.com", "ajio.com", "meesho.com",
  "flipkart.com", "amazon.in", "snapdeal.com",
  "tatacliq.com", "reliance.com", "jiomart.com",
  "bigbasket.com", "blinkit.com", "swiggyinstamart.com",
  "purplle.com", "smytten.com", "vanitywagon.in",
  "shopclues.com", "paytmmall.com"
];

// CATEGORY: Indian Healthcare & Pharma
const INDIAN_HEALTHCARE = [
  "1mg.com", "pharmeasy.in", "netmeds.com",
  "apollopharmacy.in", "apollohospitals.com",
  "practo.com", "lybrate.com", "mfine.co",
  "healthkart.com", "medlife.com", "medplusmart.com",
  "fortishealthcare.com", "manipalhospitals.com",
  "narayanahealth.org", "maxhealthcare.in",
  "aiims.edu", "icmr.nic.in"
];

// CATEGORY: Indian Skincare & Beauty Brands
const INDIAN_SKINCARE_BEAUTY = [
  "minimalst.com", "beminimalist.co",
  "dotandkey.com", "plumgoodness.com",
  "mamaearth.in", "mcaffeine.com",
  "skinkraft.com", "vedix.com", "dermatica.in",
  "foxtale.in", "pilgrimbeauty.com", "deconstruct.co",
  "thedermacompany.com", "lacto-calamine.com",
  "lotus-herbals.com", "biotique.com", "himalayawellness.com",
  "vlccwellness.com", "shahnazherbal.com",
  "niveaindia.com", "ponds.co.in", "lakmeindia.com",
  "loreal-paris.co.in", "maybelline.in",
  "garnier.co.in", "neutrogena.in", "olay.co.in"
];

// CATEGORY: International Skincare & Beauty Brands
const INTL_SKINCARE_BEAUTY = [
  "cerave.com", "laroche-posay.com", "vichy.com",
  "theordinary.com", "deciem.com", "paulaschoice.com",
  "neutrogena.com", "cetaphil.com", "aveeno.com",
  "skinceuticals.com", "obagi.com", "murad.com",
  "tatcha.com", "drunk-elephant.com", "glossier.com",
  "kiehlsindia.com", "kiehls.com", "origins.com",
  "clinique.com", "esteelauder.com", "shiseido.com",
  "laneige.com", "innisfree.co.in", "innisfree.com",
  "bioderma.in", "bioderma.com", "avene.com",
  "eucerin.com", "eucerinindia.com", "vaseline.com"
];

// CATEGORY: Health Information & Medical References
const HEALTH_INFORMATION = [
  "who.int", "cdc.gov", "nih.gov", "fda.gov",
  "nhs.uk", "mayoclinic.org", "webmd.com",
  "healthline.com", "medicalnewstoday.com",
  "everydayhealth.com", "rxlist.com", "drugs.com",
  "pubmed.ncbi.nlm.nih.gov", "medlineplus.gov",
  "clevelandclinic.org", "hopkinsmedicine.org",
  "mohfw.gov.in", "nhm.gov.in", "nhp.gov.in",
  "ncbi.nlm.nih.gov", "bmj.com", "thelancet.com",
  "jamanetwork.com", "nejm.org", "nature.com"
];

// CATEGORY: Fitness, Gym & Wellness
const FITNESS_WELLNESS = [
  "cult.fit", "cultfit.com", "healthifyme.com",
  "fittr.com", "myfitnesspal.com", "strava.com",
  "muscleblaze.com", "optimumnutrition.com",
  "bodybuilding.com", "gnc.in", "gnclivenwell.com",
  "truenutrition.com", "bigmuscles.in",
  "boldfit.in", "fitternity.com", "growfit.in",
  "wellversed.in", "oziva.in", "ritebite.in",
  "yoga.com", "yogajournal.com", "artofliving.org"
];

// CATEGORY: Indian Government & Regulatory
const INDIAN_GOVERNMENT = [
  "gov.in", "nic.in", "india.gov.in",
  "mca.gov.in", "sebi.gov.in", "rbi.org.in",
  "incometax.gov.in", "gst.gov.in",
  "uidai.gov.in", "digilocker.gov.in",
  "cowin.gov.in", "esic.in", "epfindia.gov.in"
];

var HIGH_REPUTATION_DOMAINS = new Set(
  [
    ...INDIAN_ECOMMERCE,
    ...INDIAN_HEALTHCARE,
    ...INDIAN_SKINCARE_BEAUTY,
    ...INTL_SKINCARE_BEAUTY,
    ...HEALTH_INFORMATION,
    ...FITNESS_WELLNESS,
    ...INDIAN_GOVERNMENT,
    // Existing global/core essentials
    "chatgpt.com", "openai.com", "claude.ai", "anthropic.com",
    "google.com", "github.com", "amazon.com", "youtube.com",
    "linkedin.com", "wikipedia.org", "dropbox.com", "notion.so",
  ].map((d) => String(d || "").toLowerCase().trim()).filter(Boolean)
);

function isRandomSubdomain(subdomain) {
  if (!subdomain) return false;
  if (subdomain.length > 20) return true;
  var vowels = (subdomain.match(/[aeiou]/gi) || []).length;
  var ratio = vowels / Math.max(1, subdomain.length);
  if (ratio < 0.15 && subdomain.length > 8) return true;
  if (/[^aeiou]{5,}/i.test(subdomain)) return true;
  if ((subdomain.match(/-/g) || []).length >= 3) return true;
  return false;
}

function isDeepSubdomain(parts) {
  return Array.isArray(parts) && parts.length > 4;
}

function isSentinelTrustedDomain(urlOrDomain) {
  var hostname = "";
  try {
    var raw = String(urlOrDomain || "");
    hostname = raw.startsWith("http") ? new URL(raw).hostname : raw;
  } catch (_) {
    return false;
  }
  hostname = String(hostname || "").toLowerCase();
  if (!hostname) return false;

  if (TRUSTED_FULL_DOMAINS.has(hostname)) return true;

  var parts = hostname.split(".").filter(Boolean);
  var apex = parts.slice(-2).join(".");
  if (!TRUSTED_APEX_DOMAINS.has(apex)) return false;

  if (parts.length > 2) {
    var subdomain = parts.slice(0, -2).join(".");
    if (isRandomSubdomain(subdomain)) return false;
    if (isDeepSubdomain(parts)) return false;
  }
  return true;
}

function isHighReputationDomain(urlOrHostname) {
  try {
    var raw = String(urlOrHostname || "").toLowerCase();
    var hostname = raw.includes("://")
      ? new URL(raw).hostname.replace(/^www\./, "")
      : raw.replace(/^www\./, "");
    // Exact match
    if (HIGH_REPUTATION_DOMAINS.has(hostname)) return true;

    // Subdomain match
    for (const domain of HIGH_REPUTATION_DOMAINS) {
      if (hostname === domain || hostname.endsWith("." + domain)) return true;
    }

    // Government/academic pattern match
    if (
      hostname.endsWith(".gov.in") || hostname.endsWith(".nic.in") ||
      hostname.endsWith(".edu.in") || hostname.endsWith(".ac.in") ||
      hostname.endsWith(".gov") || hostname.endsWith(".edu")
    ) {
      return true;
    }

    return false;
  } catch (_) {
    return false;
  }
}

var SENTINEL_TRUSTED_DOMAINS = Array.from(TRUSTED_APEX_DOMAINS);

if (typeof globalThis !== "undefined") {
  globalThis.isTrustedDomain = isSentinelTrustedDomain;
  globalThis.isHighReputationDomain = isHighReputationDomain;
  globalThis.SENTINEL_TRUSTED_DOMAINS = SENTINEL_TRUSTED_DOMAINS;
  globalThis.isRandomSubdomain = isRandomSubdomain;
  globalThis.isDeepSubdomain = isDeepSubdomain;
  globalThis.TRUSTED_APEX_DOMAINS = TRUSTED_APEX_DOMAINS;
  globalThis.HIGH_REPUTATION_DOMAINS = HIGH_REPUTATION_DOMAINS;
}
