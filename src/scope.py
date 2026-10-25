import json
import os
import urllib.parse

DATA_DIR = "data"
TARGETS_FILE = os.path.join(DATA_DIR, "authorized_targets.json")


class ScopeViolation(Exception):
    pass


def _load():
    if not os.path.exists(TARGETS_FILE):
        return {}
    with open(TARGETS_FILE) as f:
        return json.load(f)


def _save(data):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(TARGETS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _domain(url):
    return urllib.parse.urlparse(url).netloc.lower()


def confirm_authorized(url: str) -> bool:
    domain = _domain(url)
    if not domain:
        return False
    known = _load()
    if domain in known:
        return True

    print(f"\n[SCOPE CHECK] This run will send live traffic to '{domain}'.")
    print("  Only proceed if you own this target or have explicit written")
    print("  authorization to test it (e.g. it is your own lab, a site you")
    print("  operate, or a purpose-built practice target like vulnbank.org).")
    typed = input(f"  Type the domain exactly ('{domain}') to confirm: ").strip().lower()
    if typed != domain:
        print("  Domain did not match -- refusing to proceed.")
        return False

    known[domain] = {"confirmed": True}
    _save(known)
    print(f"  Confirmed. '{domain}' is now authorized for future runs.\n")
    return True
