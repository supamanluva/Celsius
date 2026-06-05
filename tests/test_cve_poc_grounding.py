"""The AI CVE-verification can be grounded in the public PoC write-up: fetch the
trickest/cve repo README, distil the technique (no raw exploit), feed it to the
planner prompt."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import cve  # noqa: E402
from celsius.ai import prompts  # noqa: E402

_README = """\
# Exploit PoC for CVE-2024-TEST

This abuses a **path traversal** in FooServer by requesting `/static/..%2f..%2fetc/passwd`.
A vulnerable host returns the file; a patched host returns 400.

## Usage
```bash
python3 exploit.py --target http://victim --shell "rm -rf /"
```
After onboarding, run the script above. More prose after the code block.
"""


def _patch_readme(text):
    cve._get_text = lambda url: text if "README.md" in url else ""


def test_technique_keeps_prose_drops_raw_exploit():
    _patch_readme(_README)
    t = cve.poc_technique("https://github.com/alice/foo-poc")
    assert "path traversal" in t
    assert "etc/passwd" in t                      # the benign trigger survives
    assert "rm -rf" not in t                       # fenced raw exploit is stripped
    assert "More prose after the code block" in t


def test_non_github_url_has_no_technique():
    assert cve.poc_technique("https://seclists.org/fulldisclosure/2024/Jul/18") == ""


def test_poc_techniques_only_poc_refs_and_capped():
    _patch_readme(_README)
    c = {"references": [
        {"url": "https://github.com/a/p1", "poc": True},
        {"url": "https://github.com/b/p2", "poc": True},
        {"url": "https://github.com/c/p3", "poc": False},   # not a PoC ref
        {"url": "https://example.com/advisory", "poc": True},  # non-github -> no technique
    ]}
    assert len(cve.poc_techniques(c, max_pocs=1)) == 1
    techs = cve.poc_techniques(c, max_pocs=5)
    assert [t["url"] for t in techs] == ["https://github.com/a/p1", "https://github.com/b/p2"]


def test_prompt_embeds_writeups_when_present():
    techs = [{"url": "https://github.com/a/p1", "technique": "TRIGGER_MARKER_XYZ"}]
    p = prompts.cve_verify_prompt({"id": "CVE-2024-TEST"}, {"host": "x"}, [], techs)
    assert "PUBLIC PoC WRITE-UPS" in p and "TRIGGER_MARKER_XYZ" in p


def test_prompt_omits_writeups_when_absent():
    p = prompts.cve_verify_prompt({"id": "CVE-2024-TEST"}, {"host": "x"}, [], None)
    assert "PUBLIC PoC WRITE-UPS" not in p


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
