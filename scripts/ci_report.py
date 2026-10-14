"""Post pytest failure summary to GitHub commit comments."""

import json
import os
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    sha = os.environ.get("GITHUB_SHA")
    job = os.environ.get("JOB_NAME", "test")

    junit_path = Path("junit.xml")
    errors = []
    if junit_path.exists():
        try:
            tree = ET.parse(junit_path)
            for testcase in tree.iter("testcase"):
                for failure in testcase.iter("failure"):
                    msg = failure.get("message", "")
                    text = (failure.text or "")[:1000]
                    name = f"{testcase.get('classname')}.{testcase.get('name')}"
                    errors.append(f"FAILED: {name}\nMessage: {msg}\n{text}")
                for err in testcase.iter("error"):
                    msg = err.get("message", "")
                    text = (err.text or "")[:1000]
                    name = f"{testcase.get('classname')}.{testcase.get('name')}"
                    errors.append(f"ERROR: {name}\nMessage: {msg}\n{text}")
        except Exception as e:
            errors.append(f"Error parsing junit.xml: {e}")

    if not errors and Path("pytest.log").exists():
        lines = Path("pytest.log").read_text(encoding="utf-8", errors="ignore").splitlines()
        errors = [line for line in lines if "FAILED" in line or "ERROR" in line][:30]

    if not token or not repo or not sha:
        print("[ci_report] Missing GitHub env variables.")
        for err in errors:
            print(err)
        return

    body = f"### CI Failure: {job}\n\n" + "\n\n".join(errors[:10])
    if len(body) > 60000:
        body = body[:60000] + "\n...[truncated]"

    url = f"https://api.github.com/repos/{repo}/commits/{sha}/comments"
    req = urllib.request.Request(
        url,
        data=json.dumps({"body": body}).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "CI-Reporter",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"[ci_report] Posted comment: status {resp.status}")
    except Exception as exc:
        print(f"[ci_report] Failed to post comment: {exc}")


if __name__ == "__main__":
    main()
