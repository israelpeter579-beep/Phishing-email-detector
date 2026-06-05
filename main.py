"""
Phishing Email Detection Bot — CLI runner
Run:  python main.py
      python main.py --demo          # run built-in test cases
      python main.py --interactive   # paste your own email
"""

import argparse
import textwrap
from detector import PhishingDetector, EmailData

detector = PhishingDetector()


# ── Colour helpers (works on most terminals) ──────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

VERDICT_COLOURS = {
    "safe":           GREEN,
    "suspicious":     YELLOW,
    "likely_phishing": RED,
    "phishing":       RED + BOLD,
}


def coloured_result(result) -> str:
    colour = VERDICT_COLOURS.get(result.verdict, RESET)
    text = str(result)
    # Colour the verdict line
    text = text.replace(
        f"Verdict    : {result.verdict.upper().replace('_', ' ')}",
        f"Verdict    : {colour}{result.verdict.upper().replace('_', ' ')}{RESET}"
    )
    return text


# ── Demo test cases ───────────────────────────────────────────────────────────

DEMO_EMAILS = [
    {
        "label": "Classic PayPal Phish",
        "email": EmailData(
            sender="support@paypa1-secure.tk",
            subject="URGENT: Your PayPal Account Has Been Suspended!",
            body=textwrap.dedent("""\
                Dear Valued Customer,

                We have detected suspicious activity on your PayPal account.
                Your account has been temporarily suspended due to unauthorized access.

                You must verify your account immediately to avoid permanent suspension.
                Act now — you have only 24 hours to confirm your details.

                Kindly click the link below and re-enter your password and billing information:
                https://bit.ly/paypal-verify-acct

                Do the needful immediately.

                PayPal Security Team
            """),
        ),
    },
    {
        "label": "Lottery Scam",
        "email": EmailData(
            sender="winner.notifications@freegifts.ml",
            subject="CONGRATULATIONS!!! YOU HAVE WON $1,000,000!!!",
            body=textwrap.dedent("""\
                CONGRATULATIONS!!!

                You have been selected as our lucky winner!
                You have won ONE MILLION DOLLARS in our international lottery!

                To claim your prize, send your bank account details and social security
                number to us immediately. Wire transfer will be arranged right away.

                Claim your reward before it expires!!! Limited time offer!!!
                Visit: http://192.168.99.12/claim-prize.exe

                Best regards,
                International Lottery Foundation
            """),
            attachments=["claim_form.exe"],
        ),
    },
    {
        "label": "IT Department Credential Harvest",
        "email": EmailData(
            sender="it-support@company-helpdesk.xyz",
            subject="Action Required: Password Expiry Notice",
            body=textwrap.dedent("""\
                Hello,

                Your company password will expire in 24 hours.
                Please click here to verify your account and update your password:

                https://tinyurl.com/company-it-portal

                Failure to respond will result in your account being locked.

                IT Support Team
            """),
        ),
    },
    {
        "label": "Legitimate Newsletter",
        "email": EmailData(
            sender="newsletter@github.com",
            subject="GitHub: Your monthly activity summary",
            body=textwrap.dedent("""\
                Hi Alex,

                Here is your GitHub activity summary for this month.
                You made 47 commits across 5 repositories.

                Check out what's trending in your communities:
                https://github.com/explore

                Thanks for being part of the GitHub community!

                The GitHub Team
            """),
        ),
    },
    {
        "label": "CEO Fraud / Business Email Compromise",
        "email": EmailData(
            sender="ceo.johnson@comp4ny-corp.net",
            subject="Urgent wire transfer needed",
            body=textwrap.dedent("""\
                Hi,

                I need you to action an urgent wire transfer of $45,000
                to a new vendor immediately. This is time sensitive —
                please process this before end of business today.

                Send the money via western union or bitcoin to the account
                details I will provide shortly. Do not discuss this with
                anyone else — security alert protocols require discretion.

                Respond ASAP.

                CEO, Johnson Williams
            """),
        ),
    },
]


def run_demo():
    print(f"\n{BOLD}{CYAN}  🛡️  PHISHING DETECTION BOT — DEMO MODE{RESET}\n")
    for i, case in enumerate(DEMO_EMAILS, 1):
        print(f"{BOLD}[{i}/{len(DEMO_EMAILS)}] Test Case: {case['label']}{RESET}")
        result = detector.analyze(case["email"])
        print(coloured_result(result))
        print()


# ── Interactive mode ──────────────────────────────────────────────────────────

def run_interactive():
    print(f"\n{BOLD}{CYAN}  🛡️  PHISHING DETECTION BOT — INTERACTIVE MODE{RESET}")
    print("  Enter email details below. Press ENTER twice to finish multi-line fields.\n")

    sender = input("  Sender address : ").strip()
    subject = input("  Subject line   : ").strip()

    print("  Email body (blank line to finish):")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    body = "\n".join(lines)

    attach_raw = input("  Attachments (comma-separated, or leave blank): ").strip()
    attachments = [a.strip() for a in attach_raw.split(",") if a.strip()]

    email = EmailData(sender=sender, subject=subject, body=body, attachments=attachments)
    result = detector.analyze(email)
    print()
    print(coloured_result(result))


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Phishing Email Detection Bot")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--demo",        action="store_true", help="Run built-in demo test cases")
    group.add_argument("--interactive", action="store_true", help="Manually enter an email to analyse")
    args = parser.parse_args()

    if args.demo or not (args.demo or args.interactive):
        # Default to demo if no flag given
        run_demo()
    elif args.interactive:
        run_interactive()


if __name__ == "__main__":
    main()
