#!/usr/bin/env python3
"""The nginx builds Sundew ships for (release/targets.json).

  targets.py matrix release|images|ci|image-test   JSON for a GitHub matrix
  targets.py latest-image                          image tag for :latest
  targets.py update                                follow nginx.org and the distributions
  targets.py missing <tag>                         targets without assets in a release
  targets.py summary < targets                     one line naming targets (JSON list)
  targets.py next-patch <tag>                      next free patch tag after <tag>
  targets.py bump <version> <base> <summary>       version files and CHANGELOG entry
  targets.py changelog <version> <base> <summary>  CHANGELOG entry only
"""

import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TARGETS = os.path.join(ROOT, "release", "targets.json")
VERSIONS = os.path.join(ROOT, "versions.mk")
UA = {"User-Agent": "sundew-targets"}


def vkey(v):
    return tuple(int(x) for x in v.split("."))


def load():
    with open(TARGETS) as f:
        return json.load(f)


def save(data):
    with open(TARGETS, "w") as f:
        f.write("{\n")
        f.write(f'  "comment": {json.dumps(data["comment"])},\n')
        f.write(f'  "keep_per_track": {data["keep_per_track"]},\n')
        f.write(f'  "test_floor": {json.dumps(data["test_floor"])},\n')
        f.write('  "targets": [\n')
        order = {"stable": 0, "mainline": 1}
        data["targets"].sort(key=lambda t: (order.get(t["track"], 2), t["track"], vkey(t["nginx"]), t["base"]))
        lines = [json.dumps(t) for t in data["targets"]]
        f.write(",\n".join("    " + line for line in lines))
        f.write("\n  ]\n}\n")


def expand(t):
    e = {k: v.replace("{v}", t["nginx"]) if isinstance(v, str) else v for k, v in t.items()}
    e["sha256"] = shas().get(t["nginx"], "")
    e.setdefault("distro", "")
    return e


def shas():
    out = {}
    with open(VERSIONS) as f:
        for line in f:
            m = re.match(r"NGINX_SHA256_(\S+)\s*=\s*([0-9a-f]{64})", line)
            if m:
                out[m.group(1)] = m.group(2)
    return out


def add_sha(version):
    if version in shas():
        return False
    url = f"https://nginx.org/download/nginx-{version}.tar.gz"
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        digest = hashlib.sha256(r.read()).hexdigest()
    with open(VERSIONS) as f:
        lines = f.read().splitlines()
    i = max(n for n, line in enumerate(lines) if line.startswith("NGINX_SHA256_"))
    lines.insert(i + 1, f"NGINX_SHA256_{version} = {digest}")
    with open(VERSIONS, "w") as f:
        f.write("\n".join(lines) + "\n")
    return True


def matrix(kind):
    data = load()
    ts = [expand(t) for t in data["targets"]]
    if kind == "release":
        return ts
    if kind == "images":
        return [t for t in ts if t.get("image")]
    if kind == "image-test":
        newest = max((t for t in ts if t["track"] == "stable"), key=lambda t: vkey(t["nginx"]))
        return [t for t in ts if t.get("image") and t["nginx"] == newest["nginx"]]
    if kind == "ci":
        versions = sorted({t["nginx"] for t in ts} | {data["test_floor"]}, key=vkey)
        stable = max((t["nginx"] for t in ts if t["track"] == "stable"), key=vkey)
        sha = shas()
        cells = [{"nginx": v, "sha256": sha[v], "san": ""} for v in versions]
        cells.append({"nginx": stable, "sha256": sha[stable], "san": "1"})
        return cells
    raise SystemExit(f"unknown matrix {kind}")


def latest_image():
    ts = [expand(t) for t in load()["targets"]]
    newest = max((t for t in ts if t["track"] == "stable" and t.get("image") and "alpine" not in t["base"]),
                 key=lambda t: vkey(t["nginx"]))
    return newest["image"]


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read().decode()


def nginx_org():
    page = get("https://nginx.org/en/download.html")
    out = {}
    for track, label in (("mainline", "Mainline version"), ("stable", "Stable version")):
        m = re.search(label + r".*?nginx-(\d+\.\d+\.\d+)\.tar\.gz", page, re.S)
        if m:
            out[track] = m.group(1)
    return out


def hub_has(tag):
    try:
        get(f"https://hub.docker.com/v2/repositories/library/nginx/tags/{tag}")
        return True
    except Exception:
        return False


def distro_version(base):
    out = subprocess.run(
        ["docker", "run", "--rm", base, "sh", "-c", "apt-get update -qq >/dev/null && apt-cache policy nginx"],
        capture_output=True, text=True, check=True).stdout
    m = re.search(r"Candidate:\s*(?:\d+:)?(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def update():
    data = load()
    targets = data["targets"]
    before = {t["nginx"] for t in targets}
    changes = []

    for track, version in nginx_org().items():
        if any(t["track"] == track and t["nginx"] == version for t in targets):
            continue
        if not (hub_has(version) and hub_has(version + "-alpine")):
            print(f"nginx.org {track} {version}: official images not published yet", file=sys.stderr)
            continue
        templates = {}
        for t in targets:
            if t["track"] == track:
                templates.setdefault(t["base"], t)
        for template in templates.values():
            targets.append({**template, "nginx": version})
        changes.append(f"nginx.org {track} {version}")

    for track in ("stable", "mainline"):
        versions = sorted({t["nginx"] for t in targets if t["track"] == track}, key=vkey)
        drop = versions[: max(0, len(versions) - data["keep_per_track"])]
        if drop:
            targets[:] = [t for t in targets if not (t["track"] == track and t["nginx"] in drop)]
            changes.append(f"dropped nginx.org {track} {', '.join(drop)}")

    for t in targets:
        if t.get("distro"):
            version = distro_version(t["base"])
            if version and version != t["nginx"]:
                changes.append(f"{t['track']} nginx {t['nginx']} -> {version}")
                t["nginx"] = version

    for version in sorted({t["nginx"] for t in targets} | {data["test_floor"]}, key=vkey):
        add_sha(version)

    if changes:
        save(data)
    summary = "\n".join(f"- {c}" for c in changes)
    print(summary or "no changes")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"changed={'true' if changes else 'false'}\n")
            f.write(f"summary<<EOF\n{summary}\nEOF\n")
            new = sorted({t["nginx"] for t in targets} - before, key=vkey)
            f.write(f"new_versions={' '.join(new)}\n")


def api(path):
    repo = os.environ["GITHUB_REPOSITORY"]
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/{path}",
                                 headers={**UA, "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def missing(tag):
    release = api(f"releases/tags/{tag}")
    try:
        api(f"contents/release/targets.json?ref={tag}")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        print(f"::notice::{tag} predates release/targets.json", file=sys.stderr)
        return []
    assets = {a["name"] for a in release["assets"]}
    version = tag.lstrip("v")
    return [t for t in matrix("release")
            if any(f"sundew-{version}-{t['name']}-{arch}.tar.gz" not in assets for arch in ("amd64", "arm64"))]


TRACK_NAMES = {"stable": "nginx.org stable", "mainline": "nginx.org mainline",
               "debian13": "Debian 13 nginx", "ubuntu24.04": "Ubuntu 24.04 nginx"}


def summary(targets):
    seen = []
    for t in targets:
        s = f"{TRACK_NAMES.get(t['track'], t['track'])} {t['nginx']}"
        if s not in seen:
            seen.append(s)
    return ", ".join(seen)


def next_patch(tag):
    major, minor, patch = (int(x) for x in tag.lstrip("v").split("-")[0].split("."))
    tags = subprocess.run(["git", "tag", "-l", f"v{major}.{minor}.*"],
                          capture_output=True, text=True, check=True).stdout.split()
    taken = [int(m.group(1)) for t in tags if (m := re.fullmatch(rf"v{major}\.{minor}\.(\d+)", t))]
    return f"v{major}.{minor}.{max(taken + [patch]) + 1}"


def changelog(version, base, text):
    with open("CHANGELOG.md") as f:
        lines = f.read().splitlines()
    head = next(i for i, line in enumerate(lines) if re.match(r"## \[\d", line))
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    entry = [f"## [{version}] - {today}", "", "### Added",
             f"- Prebuilt modules for {text}.", ""]
    lines[head:head] = entry
    for i, line in enumerate(lines):
        m = re.match(r"\[Unreleased\]: (.*)/compare/v[^.]+\.[^.]+\.[^.]+\.\.\.HEAD$", line)
        if m:
            url = m.group(1)
            lines[i] = f"[Unreleased]: {url}/compare/v{version}...HEAD"
            lines.insert(i + 1, f"[{version}]: {url}/compare/v{base}...v{version}")
            break
    else:
        raise SystemExit("CHANGELOG.md has no [Unreleased] link")
    with open("CHANGELOG.md", "w") as f:
        f.write("\n".join(lines) + "\n")


def bump(version, base, text):
    edits = [("src/ngx_sundew.h", rf'#define SUNDEW_VERSION  "{re.escape(base)}"',
              f'#define SUNDEW_VERSION  "{version}"'),
             ("helper/Cargo.toml", rf'(?m)^version = "{re.escape(base)}"$', f'version = "{version}"'),
             ("helper/Cargo.lock", rf'name = "sundew-helper"\nversion = "{re.escape(base)}"',
              f'name = "sundew-helper"\nversion = "{version}"')]
    for path, pattern, new in edits:
        with open(path) as f:
            s = f.read()
        s, n = re.subn(pattern, new, s, count=1)
        if n != 1:
            raise SystemExit(f"{path}: version {base} not found")
        with open(path, "w") as f:
            f.write(s)
    changelog(version, base, text)


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    cmd = sys.argv[1]
    if cmd == "matrix":
        print(json.dumps(matrix(sys.argv[2])))
    elif cmd == "latest-image":
        print(latest_image())
    elif cmd == "update":
        update()
    elif cmd == "missing":
        print(json.dumps(missing(sys.argv[2])))
    elif cmd == "summary":
        print(summary(json.load(sys.stdin)))
    elif cmd == "next-patch":
        print(next_patch(sys.argv[2]))
    elif cmd == "bump":
        bump(*sys.argv[2:5])
    elif cmd == "changelog":
        changelog(*sys.argv[2:5])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
