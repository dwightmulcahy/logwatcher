"""Release helpers driven by conventional commits.

    python3 scripts/release_notes.py next          -> next version (vX.Y.Z) from commits since the last tag
    python3 scripts/release_notes.py notes <tag>   -> markdown release notes for <tag>

Bump rules: "type!:" or "BREAKING CHANGE" -> major, feat -> minor, anything else -> patch.
"""
import re
import subprocess
import sys

TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
CC_RE = re.compile(r"^(\w+)(\([^)]*\))?(!)?:\s*(.+)$")
SECTIONS = [
    ("feat", "✨ Features"), ("fix", "🐛 Bug Fixes"), ("security", "🔒 Security"), ("perf", "⚡ Performance"),
    ("refactor", "♻️ Refactoring"), ("docs", "📝 Documentation"), ("style", "💄 Style"), ("test", "✅ Tests"),
    ("build", "🏗️ Build"), ("ci", "👷 CI"), ("chore", "🧹 Chores"),
]
KNOWN = {k for k, _ in SECTIONS}


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()


def tags():
    return [t for t in git("tag", "--sort=-v:refname").splitlines() if TAG_RE.match(t)]


def commits(rng):
    out = git("log", rng, "--no-merges", "--pretty=format:%s%x1f%b%x1e")
    return [tuple((c.split("\x1f") + [""])[:2]) for c in out.split("\x1e") if c.strip()]


def next_version():
    all_tags = tags()
    last = all_tags[0] if all_tags else None
    if not last:
        return "v0.1.0"
    items = commits(f"{last}..HEAD")
    if not items:
        sys.exit(f"No commits since {last}; nothing to release.")
    major, minor, patch = map(int, TAG_RE.match(last).groups())
    breaking = any((m := CC_RE.match(s.strip())) and m.group(3) or "BREAKING CHANGE" in b for s, b in items)
    feat = any((m := CC_RE.match(s.strip())) and m.group(1).lower() == "feat" for s, _ in items)
    if breaking and major > 0:
        return f"v{major + 1}.0.0"
    if breaking or feat:
        return f"v{major}.{minor + 1}.0"
    return f"v{major}.{minor}.{patch + 1}"


def notes(tag):
    all_tags = tags()
    prev = next((t for t in all_tags[all_tags.index(tag) + 1:]), None) if tag in all_tags else (all_tags[0] if all_tags else None)
    ref = tag if tag in all_tags else "HEAD"
    rng = f"{prev}..{ref}" if prev else ref
    buckets = {}
    for subject, _ in reversed(commits(rng)):
        m = CC_RE.match(subject.strip())
        kind = m.group(1).lower() if m and m.group(1).lower() in KNOWN else "other"
        msg = m.group(4) if m and kind != "other" else subject.strip()
        scope = m.group(2)[1:-1] if m and m.group(2) and kind != "other" else None
        msg = msg[:1].upper() + msg[1:]
        if m and m.group(3):
            msg = f"**BREAKING:** {msg}"
        buckets.setdefault(kind, []).append(f"- {f'**{scope}:** ' if scope else ''}{msg}")
    out = []
    for kind, label in SECTIONS + [("other", "📦 Other Changes")]:
        if kind in buckets:
            out += [f"## {label}", *buckets[kind], ""]
    repo = "https://github.com/dwightmulcahy/logwatcher"
    image = "dwightmulcahy/logwatcher"
    out += [f"**Docker:** `docker pull {image}:{tag.lstrip('v')}`", ""]
    if prev:
        out.append(f"**Full Changelog**: {repo}/compare/{prev}...{tag}")
    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "next":
        print(next_version())
    elif len(sys.argv) == 3 and sys.argv[1] == "notes":
        print(notes(sys.argv[2]))
    else:
        sys.exit(__doc__)
