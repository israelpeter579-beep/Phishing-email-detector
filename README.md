# Phishing Email Detection Bot

A fully self-contained, rule-based phishing email detection engine written in pure Python — **no external dependencies required**.

---

## Features

| Check | What it detects |
|---|---|
| Urgency language | "Act now", "24 hours", "Account suspended" |
| Threat language | "Unauthorized access", "Security alert" |
| Reward / lottery | "You have won", "Claim your prize" |
| Credential harvesting | "Enter your password", "Verify your account" |
| Financial data | Bank account, SSN, wire transfer requests |
| Suspicious sender | Numeric domains, free TLDs (`.tk`, `.ml`) |
| Domain spoofing | Fake PayPal/Amazon/Google look-alike domains |
| URL shorteners | bit.ly, tinyurl, t.co, etc. |
| Suspicious URLs | IP-based URLs, excessive subdomains, shady TLDs |
| ALL CAPS subject | SHOUTING subject lines |
| Dangerous attachments | `.exe`, `.zip`, `.bat`, `.vbs`, etc. |
| Poor grammar patterns | "Kindly do the needful", "Dear valued customer" |

---

## Project structure

```
phishing_detector/
├── detector.py   ← Core detection engine (no dependencies)
├── main.py       ← CLI runner (demo + interactive modes)
├── tests.py      ← Unit tests (unittest, no extras needed)
└── README.md
```

---

## Setup in PyCharm

1. Open PyCharm → **File → Open** → select the `phishing_detector/` folder
2. No `pip install` needed — the project uses only the Python standard library
3. Set `main.py` as the run target

---

## Running

### Demo mode (5 built-in test emails)
```bash
python main.py
# or explicitly:
python main.py --demo
```

### Interactive mode (paste your own email)
```bash
python main.py --interactive
```

### Unit tests
```bash
python -m pytest tests.py -v
# or without pytest:
python tests.py
```

---

## Understanding the score

| Score | Verdict |
|---|---|
| 0 – 9 | ✅ Safe |
| 10 – 19 | ⚠️ Suspicious |
| 20 – 29 | 🚨 Likely Phishing |
| 30 + | ☠️ Phishing |

---

## Extending the bot

- Add keywords to the lists at the top of `detector.py`
- Add new check methods and wire them into `PhishingDetector.analyze()`
- Feed it real `.eml` files by parsing with Python's built-in `email` module
- Plug in a machine-learning classifier as a second opinion layer
