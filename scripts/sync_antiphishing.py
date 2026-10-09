#!/usr/bin/env python3
"""Sync upstream Antiphishing feeds and rules into the local repository.

This script compares the current local copies of the upstream feed files with the
latest files published in the upstream Antiphishing repository. If any source
file changed, the local copy is updated and the workflow can trigger the rebuild
of the AT JSON catalog.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib import request

BASE_URL = "https://raw.githubusercontent.com/julioliraup/Antiphishing/main"
FILES = {
    "rules/antiphishing.rules": "/antiphishing.rules",
    "rules/phishing.lst": "/phishing.lst",
    "rules/phishing_ips.lst": "/phishing_ips.lst",
    "rules/nrd_suspicious_domains.txt": "/nrd_suspicious_domains.txt",
}


def fetch_bytes(url: str) -> bytes:
    with request.urlopen(url, timeout=30) as resp:
        return resp.read()


def write_github_output(changed: bool) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    with open(output_file, "a", encoding="utf-8") as fh:
        fh.write(f"changed={'true' if changed else 'false'}\n")


def main() -> int:
    changed = False
    for local_path, relative in FILES.items():
        local = Path(local_path)
        local.parent.mkdir(parents=True, exist_ok=True)
        remote_url = f"{BASE_URL}{relative}"
        try:
            remote_bytes = fetch_bytes(remote_url)
        except Exception as exc:  # pragma: no cover - exercise in CI
            print(f"[sync] fetch failed for {remote_url}: {exc}", file=sys.stderr)
            raise

        if local.exists() and local.read_bytes() == remote_bytes:
            print(f"[sync] unchanged: {local_path}")
            continue

        local.write_bytes(remote_bytes)
        changed = True
        if local.exists():
            print(f"[sync] updated: {local_path}")
        else:
            print(f"[sync] created: {local_path}")

    if not changed:
        print("[sync] no upstream changes detected")

    write_github_output(changed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
