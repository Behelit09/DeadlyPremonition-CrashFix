import os
import sys
import json
import urllib.request
import urllib.error

TOKEN = os.environ.get("GITHUB_TOKEN")
if not TOKEN:
    print("[ERROR] GITHUB_TOKEN environment variable not set.")
    sys.exit(1)

REPO = "Behelit09/DeadlyPremonition-CrashFix"
TAG = "v0.1.0"
RELEASE_NAME = "v0.1.0 (Beta)"
RELEASE_BODY = """Deadly Premonition: The Director's Cut - CrashFix and CrashLogger v0.1.0 (Beta).

This is a beta release targeting game stability and crash prevention.

Assets included in this release:
- CrashFix.asi / CrashFix.ini / CrashFix-v0.1.0.zip: Standalone crash fix plugin (Episode 2 Part 1 cutscene fix, NavTable bounds validation, dummy node fallbacks, position zeroing protection).
- CrashLogger.asi / CrashLogger.ini / CrashLogger-v0.1.0.zip: Standalone crash logger and minidump generator (VEH/SEH exception capture, stack trace logging, breadcrumbs).
- DeadlyPremonition-CrashFix-All-v0.1.0.zip: Full package containing both plugins, configuration files, and documentation.

Installation:
Place the desired .asi and .ini files into the scripts/ folder in your Deadly Premonition game directory. Requires Ultimate ASI Loader (d3d9.dll).
"""

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "User-Agent": "DP-Release-Uploader",
    "X-GitHub-Api-Version": "2022-11-28"
}

# Optional: Delete old v0.9.0-beta release if exists
try:
    old_req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/tags/v0.9.0-beta", headers=headers)
    with urllib.request.urlopen(old_req) as resp:
        old_release = json.loads(resp.read().decode("utf-8"))
        old_id = old_release["id"]
        del_req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/{old_id}", headers=headers, method="DELETE")
        with urllib.request.urlopen(del_req) as del_resp:
            print(f"[*] Deleted old v0.9.0-beta release (id: {old_id})")
except Exception as ex:
    pass

# Step 1: Create release or get existing
create_url = f"https://api.github.com/repos/{REPO}/releases"
data = {
    "tag_name": TAG,
    "target_commitish": "master",
    "name": RELEASE_NAME,
    "body": RELEASE_BODY,
    "draft": False,
    "prerelease": True
}

req = urllib.request.Request(create_url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")

try:
    with urllib.request.urlopen(req) as resp:
        release = json.loads(resp.read().decode("utf-8"))
        print(f"[*] Created release id: {release['id']}")
except urllib.error.HTTPError as e:
    err_body = e.read().decode("utf-8")
    if e.code == 422 and "already_exists" in err_body:
        print("[*] Release already exists, fetching existing release...")
        get_req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/tags/{TAG}", headers=headers)
        with urllib.request.urlopen(get_req) as resp:
            release = json.loads(resp.read().decode("utf-8"))
            print(f"[*] Fetched existing release id: {release['id']}")
    else:
        print(f"[!] Failed to create release: {e.code} {e.reason}\n{err_body}")
        sys.exit(1)

upload_url_template = release["upload_url"]
upload_url_base = upload_url_template.split("{")[0]

existing_assets = {a["name"]: a["id"] for a in release.get("assets", [])}

files_to_upload = [
    ("dist/CrashFix.asi", "application/octet-stream"),
    ("dist/CrashFix.ini", "text/plain"),
    ("dist/CrashFix-v0.1.0.zip", "application/zip"),
    ("dist/CrashLogger.asi", "application/octet-stream"),
    ("dist/CrashLogger.ini", "text/plain"),
    ("dist/CrashLogger-v0.1.0.zip", "application/zip"),
    ("dist/DeadlyPremonition-CrashFix-All-v0.1.0.zip", "application/zip"),
]

for file_path, content_type in files_to_upload:
    name = os.path.basename(file_path)
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        continue

    if name in existing_assets:
        asset_id = existing_assets[name]
        print(f"[*] Deleting existing asset {name} (id: {asset_id})...")
        del_req = urllib.request.Request(
            f"https://api.github.com/repos/{REPO}/releases/assets/{asset_id}",
            headers=headers,
            method="DELETE"
        )
        try:
            with urllib.request.urlopen(del_req) as resp:
                pass
        except Exception as ex:
            print(f"[!] Failed to delete existing asset {name}: {ex}")

    print(f"[*] Uploading {name} ({os.path.getsize(file_path)} bytes)...")
    upload_url = f"{upload_url_base}?name={name}"
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    upload_headers = dict(headers)
    upload_headers["Content-Type"] = content_type

    up_req = urllib.request.Request(upload_url, data=file_bytes, headers=upload_headers, method="POST")
    try:
        with urllib.request.urlopen(up_req) as resp:
            up_resp = json.loads(resp.read().decode("utf-8"))
            print(f"[+] Uploaded {name}: {up_resp['browser_download_url']}")
    except urllib.error.HTTPError as e:
        print(f"[!] Failed to upload {name}: {e.code} {e.reason}\n{e.read().decode('utf-8')}")

print("\n[*] Release publishing finished successfully!")
