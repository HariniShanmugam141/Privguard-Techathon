// Netlify Function: sanitize-text
// Performs regex-based PII/PHI text redaction (no Python dependencies needed)

exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json"
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Invalid JSON" }) };
  }

  const { text = "", strategy = "redact", profile = "HIPAA" } = body;

  if (!text.trim()) {
    return { statusCode: 400, headers, body: JSON.stringify({ status: "error", message: "No text provided" }) };
  }

  // ── PII Regex Patterns ─────────────────────────────────────────────────
  const patterns = [
    { label: "NAME",        regex: /(?:Patient\s+Name|Name|Patient)\s*:\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3})/gi,  group: 1 },
    { label: "EMAIL",       regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-z]{2,}/gi,                                     group: 0 },
    { label: "PHONE",       regex: /(?:\+?\d{1,2}[\s\-]?)?(?:\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4})/g,                    group: 0 },
    { label: "SSN",         regex: /\b\d{3}-\d{2}-\d{4}\b/g,                                                               group: 0 },
    { label: "DOB",         regex: /(?:DOB|Date of Birth)\s*:\s*(\d{1,2}[-\/\s]\d{1,2}[-\/\s]\d{2,4})/gi,                 group: 1 },
    { label: "MRN",         regex: /\bMRN\s*:\s*([A-Z0-9\-]{5,15})\b/gi,                                                  group: 1 },
    { label: "MEMBER_ID",   regex: /\b(?:Member ID|MID)\s*:\s*([A-Z0-9\-]{6,15})\b/gi,                                    group: 1 },
    { label: "GROUP_NUMBER",regex: /\b(?:Group Number|Group\s*#)\s*:\s*([A-Z0-9\-]{3,15})\b/gi,                            group: 1 },
    { label: "POLICY_ID",   regex: /\bPolicy ID\s*:\s*([A-Z0-9\-]{5,15})\b/gi,                                            group: 1 },
    { label: "CREDIT_CARD", regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g,                   group: 0 },
    { label: "IP_ADDRESS",  regex: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,                                                  group: 0 },
    { label: "ADDRESS",     regex: /\b\d{1,5}\s+[A-Za-z0-9\s,]{4,40}\s*(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct)\b/gi, group: 0 },
    { label: "GENDER",      regex: /\b(?:Gender|Sex)\s*:\s*(Male|Female)\b/gi,                                             group: 1 },
  ];

  // Profile filter
  const profileMap = {
    HIPAA:   ["NAME","DOB","MRN","SSN","MEMBER_ID","GROUP_NUMBER","POLICY_ID","PHONE","ADDRESS","EMAIL","GENDER"],
    GDPR:    ["NAME","EMAIL","PHONE","ADDRESS","SSN","DOB","IP_ADDRESS","GENDER"],
    "PCI-DSS": ["CREDIT_CARD","SSN"],
    CUSTOM:  patterns.map(p => p.label)
  };
  const allowed = profileMap[profile.toUpperCase()] || profileMap["HIPAA"];

  // ── Replacement helper ──────────────────────────────────────────────────
  const getMask = (val, label) => {
    if (strategy === "hash") {
      let h = 0;
      for (let i = 0; i < val.length; i++) h = (Math.imul(31, h) + val.charCodeAt(i)) >>> 0;
      return `[HASH_${label}:${h.toString(16).slice(0, 10)}]`;
    } else if (strategy === "anonymize") {
      const n = (val.split("").reduce((a, c) => a + c.charCodeAt(0), 0) % 900) + 100;
      return `[${label}_${n}]`;
    }
    return `[REDACTED_${label}]`;
  };

  // ── Detect & collect all matches ────────────────────────────────────────
  let redacted = text;
  const entities_summary = {};
  let pii_found_count = 0;

  for (const { label, regex, group } of patterns) {
    if (!allowed.includes(label)) continue;
    regex.lastIndex = 0;
    let match;
    const replacements = [];
    while ((match = regex.exec(text)) !== null) {
      const val = group === 0 ? match[0] : (match[group] || match[0]);
      if (val && val.trim().length >= 2) {
        replacements.push(val.trim());
        entities_summary[label] = (entities_summary[label] || 0) + 1;
        pii_found_count++;
      }
    }
    // Sort longest first to prevent partial replacements
    replacements.sort((a, b) => b.length - a.length);
    for (const val of replacements) {
      redacted = redacted.split(val).join(getMask(val, label));
    }
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      status: "success",
      redacted_text: redacted,
      entities_summary,
      pii_found_count
    })
  };
};
