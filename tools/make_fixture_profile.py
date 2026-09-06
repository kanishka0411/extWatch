#!/usr/bin/env python3
"""Build a synthetic Chrome user data directory containing the fixture extension.

Used for demos and manual testing of the watcher:

    tools/make_fixture_profile.py fixtures/generated/user-data --version 1.0.0
    EXTWATCH_USER_DATA_DIRS="chrome=$PWD/fixtures/generated/user-data" ./build/dev-mac/src/extwatch scan
    tools/make_fixture_profile.py fixtures/generated/user-data --update 1.2.0   # simulate a silent update
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE_ROOT = os.path.join(HERE, "..", "fixtures", "extensions", "screenshot-tool")
CHROME_EPOCH_OFFSET = 11644473600


def chrome_now():
    return str(int((time.time() + CHROME_EPOCH_OFFSET) * 1_000_000))


def extension_id(manifest):
    der = base64.b64decode(manifest["key"])
    digest = hashlib.sha256(der).digest()[:16]
    return "".join(chr(ord("a") + (b >> 4)) + chr(ord("a") + (b & 15)) for b in digest)


def load_manifest(version):
    with open(os.path.join(FIXTURE_ROOT, version, "manifest.json"), encoding="utf-8") as f:
        return json.load(f)


def install_version(profile_dir, ext_id, version):
    dst = os.path.join(profile_dir, "Extensions", ext_id, f"{version}_0")
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(os.path.join(FIXTURE_ROOT, version), dst)
    return dst


def write_prefs(profile_dir, ext_id, version, manifest, enabled=True, first_install=None):
    path = os.path.join(profile_dir, "Secure Preferences")
    prefs = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            prefs = json.load(f)
    settings = prefs.setdefault("extensions", {}).setdefault("settings", {})
    record = settings.get(ext_id, {})
    record.update({
        "path": f"{ext_id}/{version}_0",
        "location": 1,
        "from_webstore": True,
        "disable_reasons": [] if enabled else [1],
        "first_install_time": record.get("first_install_time") or first_install or chrome_now(),
        "last_update_time": chrome_now(),
        "manifest": manifest,
        "active_permissions": {"api": manifest.get("permissions", []),
                               "explicit_host": manifest.get("host_permissions", [])},
    })
    settings[ext_id] = record
    # A component extension entry, which ExtWatch must ignore.
    settings.setdefault("ahfgeienlihckogmohjhadlkjgocpleb", {
        "location": 5, "path": "/Applications/Browser.app/Contents/Resources/web_store",
        "manifest": {"name": "Web Store", "version": "0.2"}})
    with open(path, "w", encoding="utf-8") as f:
        json.dump(prefs, f, indent=2)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("user_data_dir")
    ap.add_argument("--profile", default="Default")
    ap.add_argument("--name", default="Demo Person")
    ap.add_argument("--version", default="1.0.0", help="version to install when creating the profile")
    ap.add_argument("--update", metavar="VERSION", help="simulate a silent update to this version")
    ap.add_argument("--pending", metavar="VERSION", help="download a version without activating it")
    ap.add_argument("--disable", action="store_true", help="mark the extension disabled by the user")
    args = ap.parse_args()

    profile_dir = os.path.join(args.user_data_dir, args.profile)
    os.makedirs(profile_dir, exist_ok=True)
    local_state_path = os.path.join(args.user_data_dir, "Local State")
    if not os.path.exists(local_state_path):
        with open(local_state_path, "w", encoding="utf-8") as f:
            json.dump({"profile": {"info_cache": {args.profile: {"name": args.name}},
                                   "last_used": args.profile}}, f, indent=2)

    if args.update:
        manifest = load_manifest(args.update)
        ext_id = extension_id(manifest)
        install_version(profile_dir, ext_id, args.update)
        write_prefs(profile_dir, ext_id, args.update, manifest, enabled=not args.disable)
        print(f"updated {ext_id} to {args.update} in {profile_dir}")
        return 0
    if args.pending:
        manifest = load_manifest(args.pending)
        ext_id = extension_id(manifest)
        install_version(profile_dir, ext_id, args.pending)
        print(f"downloaded {ext_id} {args.pending} (not activated) in {profile_dir}")
        return 0

    manifest = load_manifest(args.version)
    ext_id = extension_id(manifest)
    install_version(profile_dir, ext_id, args.version)
    write_prefs(profile_dir, ext_id, args.version, manifest, enabled=not args.disable)
    print(f"created {profile_dir} with {ext_id} {args.version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
