"""
main.py — CLI entry point.
"""
import logging
import os
import re
import sys

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from src.agent import RedTeamAgent
from src.rag import RAGRetriever
from src.tools import ActionLibrary


def extract_target(text):
    match = re.search(r'(https?://[^\s"\']+)', text)
    if match:
        return match.group(1).rstrip("/")
    match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s"\']*)?)', text)
    if match:
        domain = match.group(1)
        return ("https://" + domain) if not domain.startswith(("http://", "https://")) else domain
    return None


def main():
    print("=" * 72)
    print("NEMESIS -- Autonomous Red-Team Assessment (CLI)")
    print("Only test systems you own or are explicitly authorized to test.")
    print("=" * 72)

    target = extract_target(input("\nTarget URL: ").strip())
    if not target:
        print("No valid URL found. Exiting.")
        sys.exit(1)

    print("\nScan mode:")
    print("  1. Full OWASP Top 10:2025 assessment")
    print("  2. Targeted -- specify a vulnerability category")
    choice = input("Choice [1/2]: ").strip()

    if choice == "2":
        cats = [
            ("A01:2025", "Broken Access Control"),
            ("A02:2025", "Security Misconfiguration"),
            ("A03:2025", "Software Supply Chain Failures"),
            ("A04:2025", "Cryptographic Failures"),
            ("A05:2025", "Injection"),
            ("A06:2025", "Insecure Design"),
            ("A07:2025", "Authentication Failures"),
            ("A08:2025", "Software or Data Integrity Failures"),
            ("A09:2025", "Security Logging and Alerting Failures"),
            ("A10:2025", "Mishandling of Exceptional Conditions"),
        ]
        print("\nAvailable categories:")
        for i, (oid, name) in enumerate(cats, 1):
            print(f"  {i:>2}. {oid}  {name}")

        sel = input("\nEnter number [1-10] (or type e.g. A05:2025 / injection): ").strip()

        oid = None
        if sel.isdigit():
            n = int(sel)
            if 1 <= n <= 10:
                oid = cats[n - 1][0]
        else:
            for c_oid, c_name in cats:
                if sel.upper() == c_oid or sel.lower() in c_name.lower():
                    oid = c_oid
                    break

        if not oid:
            print(f"Invalid selection '{sel}'. Enter a number 1-10.")
            sys.exit(1)

        goal = f"Find {oid} vulnerabilities on {target}"
    else:
        goal = f"Perform a full OWASP Top 10:2025 assessment on {target}"

    print(f"\nGoal: {goal}\n")

    retriever = RAGRetriever()
    retriever.build_index()

    actions = ActionLibrary(
        request_delay=float(os.getenv("REQUEST_DELAY_SECONDS", "0.25")),
        max_requests=int(os.getenv("MAX_REQUESTS_PER_RUN", "800")),
    )
    agent = RedTeamAgent(retriever=retriever, actions=actions)

    report = agent.run(goal, target)
    print("\n" + report)


if __name__ == "__main__":
    main()
