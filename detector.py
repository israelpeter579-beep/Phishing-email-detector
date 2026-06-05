"""
Phishing Email Detection Engine
Uses rule-based heuristics + keyword analysis + URL inspection
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Tuple


# ── Suspicious keyword lists ──────────────────────────────────────────────────

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "limited time", "expire",
    "24 hours", "48 hours", "account suspended", "verify now",
    "confirm immediately", "respond asap", "action required",
]

THREAT_KEYWORDS = [
    "your account will be", "unauthorized access", "suspicious activity",
    "your account has been", "security alert", "unusual sign-in",
    "we detected", "breach", "compromised", "locked",
]

REWARD_KEYWORDS = [
    "you have won", "congratulations", "prize", "lottery", "free gift",
    "claim your", "selected", "winner", "reward", "bonus",
    "million dollars", "inheritance",
]

CREDENTIAL_KEYWORDS = [
    "enter your password", "verify your account", "confirm your details",
    "update your billing", "re-enter", "login required",
    "validate your", "click here to verify", "provide your",
]

FINANCIAL_KEYWORDS = [
    "bank account", "credit card", "social security", "ssn",
    "wire transfer", "western union", "bitcoin", "crypto transfer",
    "send money", "payment required", "billing information",
]

SUSPICIOUS_SENDER_PATTERNS = [
    r"no[_-]?reply@(?!gmail|yahoo|outlook|hotmail|company\.com)",
    r"support@(?!paypal|amazon|google|apple|microsoft)\w+\.(tk|ml|ga|cf|gq)",
    r"\d{4,}@",           # many digits in username
    r"@\d+\.",            # all-numeric domain
]

LEGITIMATE_DOMAINS = {
    "paypal.com", "amazon.com", "google.com", "apple.com", "microsoft.com",
    "facebook.com", "twitter.com", "instagram.com", "linkedin.com",
    "github.com", "dropbox.com", "netflix.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrandly.com", "short.link",
}


# ── Score weights ─────────────────────────────────────────────────────────────

WEIGHTS = {
    "urgency":          3,
    "threat":           4,
    "reward":           4,
    "credential":       5,
    "financial":        4,
    "bad_sender":       5,
    "spoofed_domain":   6,
    "url_shortener":    3,
    "suspicious_url":   4,
    "many_links":       2,
    "all_caps":         2,
    "exclamation":      1,
    "poor_grammar":     2,
    "missing_greeting": 1,
    "html_only":        2,
    "attachment_risk":  3,
}

THRESHOLDS = {
    "safe":       (0,  10),
    "suspicious": (10, 20),
    "likely":     (20, 30),
    "phishing":   (30, 9999),
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class EmailData:
    sender: str = ""
    subject: str = ""
    body: str = ""
    html_body: str = ""
    attachments: List[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)


@dataclass
class DetectionResult:
    score: int
    verdict: str            # safe / suspicious / likely_phishing / phishing
    confidence: float       # 0.0 – 1.0
    flags: List[Tuple[str, str, int]]   # (category, detail, score)
    summary: str

    def __str__(self) -> str:
        lines = [
            f"{'='*55}",
            f"  PHISHING DETECTION REPORT",
            f"{'='*55}",
            f"  Verdict    : {self.verdict.upper().replace('_', ' ')}",
            f"  Risk Score : {self.score}",
            f"  Confidence : {self.confidence:.0%}",
            f"{'─'*55}",
            "  Triggered Flags:",
        ]
        if self.flags:
            for cat, detail, pts in self.flags:
                lines.append(f"   [{pts:+d}]  {cat}: {detail}")
        else:
            lines.append("   None — email looks clean.")
        lines += [f"{'─'*55}", f"  {self.summary}", f"{'='*55}"]
        return "\n".join(lines)


# ── Helper functions ──────────────────────────────────────────────────────────

def _lower(text: str) -> str:
    return text.lower()


def _extract_urls(text: str) -> List[str]:
    return re.findall(r'https?://[^\s<>"\']+', text)


def _extract_domain(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def _count_keyword_hits(text: str, keywords: List[str]) -> List[str]:
    t = _lower(text)
    return [kw for kw in keywords if kw in t]


# ── Main detector class ───────────────────────────────────────────────────────

class PhishingDetector:
    """Rule-based phishing email detector."""

    def analyze(self, email: EmailData) -> DetectionResult:
        flags: List[Tuple[str, str, int]] = []
        full_text = f"{email.subject} {email.body} {email.html_body}"

        # 1. Urgency language
        hits = _count_keyword_hits(full_text, URGENCY_KEYWORDS)
        if hits:
            pts = min(WEIGHTS["urgency"] * len(hits), 8)
            flags.append(("Urgency Language", f"{hits[:3]}", pts))

        # 2. Threat language
        hits = _count_keyword_hits(full_text, THREAT_KEYWORDS)
        if hits:
            pts = min(WEIGHTS["threat"] * len(hits), 10)
            flags.append(("Threat Language", f"{hits[:3]}", pts))

        # 3. Reward / lottery scam
        hits = _count_keyword_hits(full_text, REWARD_KEYWORDS)
        if hits:
            pts = min(WEIGHTS["reward"] * len(hits), 10)
            flags.append(("Reward/Lottery Scam", f"{hits[:3]}", pts))

        # 4. Credential harvesting
        hits = _count_keyword_hits(full_text, CREDENTIAL_KEYWORDS)
        if hits:
            pts = min(WEIGHTS["credential"] * len(hits), 12)
            flags.append(("Credential Harvesting", f"{hits[:3]}", pts))

        # 5. Financial keywords
        hits = _count_keyword_hits(full_text, FINANCIAL_KEYWORDS)
        if hits:
            pts = min(WEIGHTS["financial"] * len(hits), 10)
            flags.append(("Financial Data Request", f"{hits[:3]}", pts))

        # 6. Suspicious sender
        for pattern in SUSPICIOUS_SENDER_PATTERNS:
            if re.search(pattern, email.sender, re.IGNORECASE):
                flags.append(("Suspicious Sender", email.sender, WEIGHTS["bad_sender"]))
                break

        # 7. Domain spoofing (e.g. paypa1.com, amazon-support.xyz)
        for legit in LEGITIMATE_DOMAINS:
            brand = legit.split(".")[0]
            pattern = rf"{brand}[^@\s]*\.(com|net|org|info|biz|xyz|tk|ml|ga|cf)"
            matches = re.findall(pattern, _lower(email.sender + full_text))
            if matches:
                sender_domain = _extract_domain(f"mailto:{email.sender}")
                if sender_domain and sender_domain != legit:
                    flags.append(("Domain Spoofing", f"Fake '{brand}' domain detected", WEIGHTS["spoofed_domain"]))
                    break

        # 8. URL analysis
        urls = _extract_urls(full_text)
        shortener_urls = [u for u in urls if _extract_domain(u) in URL_SHORTENERS]
        if shortener_urls:
            flags.append(("URL Shorteners", f"{len(shortener_urls)} shortener(s) found", WEIGHTS["url_shortener"]))

        # Suspicious URL patterns (IP addresses, long subdomains)
        suspicious_urls = []
        for url in urls:
            domain = _extract_domain(url)
            if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
                suspicious_urls.append(url)
            elif domain.count(".") > 3:
                suspicious_urls.append(url)
            elif any(tld in domain for tld in [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]):
                suspicious_urls.append(url)
        if suspicious_urls:
            flags.append(("Suspicious URLs", f"{len(suspicious_urls)} flagged URL(s)", WEIGHTS["suspicious_url"]))

        if len(urls) > 10:
            flags.append(("Excessive Links", f"{len(urls)} links in email", WEIGHTS["many_links"]))

        # 9. ALL CAPS subject
        if email.subject.isupper() and len(email.subject) > 5:
            flags.append(("ALL CAPS Subject", email.subject[:40], WEIGHTS["all_caps"]))

        # 10. Excessive exclamation marks
        excl = full_text.count("!")
        if excl > 5:
            flags.append(("Exclamation Abuse", f"{excl} exclamation marks", WEIGHTS["exclamation"] * min(excl // 5, 3)))

        # 11. Poor grammar signals
        grammar_patterns = [
            r"\bdear (valued|esteemed|beloved) (customer|user|member)\b",
            r"\bkindly (click|provide|send|update)\b",
            r"\bdo the needful\b",
            r"\byour (kind|good) self\b",
        ]
        grammar_hits = [p for p in grammar_patterns if re.search(p, _lower(full_text))]
        if grammar_hits:
            flags.append(("Poor Grammar Patterns", f"{len(grammar_hits)} pattern(s)", WEIGHTS["poor_grammar"]))

        # 12. Missing greeting / impersonal salutation
        if not re.search(r"(dear|hello|hi)\s+\w+", _lower(full_text[:200])):
            flags.append(("Impersonal Greeting", "No personalised salutation", WEIGHTS["missing_greeting"]))

        # 13. HTML-only (no plain text)
        if email.html_body and not email.body.strip():
            flags.append(("HTML Only", "No plain-text version provided", WEIGHTS["html_only"]))

        # 14. Risky attachments
        risky_ext = [".exe", ".zip", ".rar", ".js", ".vbs", ".bat", ".cmd", ".scr", ".jar"]
        risky_files = [a for a in email.attachments if any(a.lower().endswith(e) for e in risky_ext)]
        if risky_files:
            flags.append(("Dangerous Attachment", f"{risky_files}", WEIGHTS["attachment_risk"] * len(risky_files)))

        # ── Compute final score & verdict ─────────────────────────────────────
        score = sum(pts for _, _, pts in flags)

        if score < THRESHOLDS["suspicious"][0]:
            verdict = "safe"
        elif score < THRESHOLDS["likely"][0]:
            verdict = "suspicious"
        elif score < THRESHOLDS["phishing"][0]:
            verdict = "likely_phishing"
        else:
            verdict = "phishing"

        max_possible = 80
        confidence = min(score / max_possible, 1.0)

        summaries = {
            "safe":           "This email appears legitimate. No significant phishing signals detected.",
            "suspicious":     "This email has some unusual traits. Treat with caution.",
            "likely_phishing":"Strong phishing indicators present. Do NOT click links or reply.",
            "phishing":       "HIGH RISK — This is almost certainly a phishing attempt. Delete immediately.",
        }

        return DetectionResult(
            score=score,
            verdict=verdict,
            confidence=confidence,
            flags=flags,
            summary=summaries[verdict],
        )
