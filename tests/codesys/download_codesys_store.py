#!/usr/bin/env python3
"""Download CODESYS Control for Linux SL from the Store (2-hour demo).

Reads CODESYS_STORE_EMAIL / CODESYS_STORE_PASSWORD from the environment.
Never prints the password. Packages land in $CODESYS_CACHE (default
~/.cache/codesys-store) and are NOT committed.
"""
from __future__ import annotations

import os
import re
import sys
import zipfile
from pathlib import Path

import requests

EMAIL = os.environ.get("CODESYS_STORE_EMAIL", "").strip()
PASSWORD = os.environ.get("CODESYS_STORE_PASSWORD", "")
CACHE = Path(os.environ.get("CODESYS_CACHE", str(Path.home() / ".cache/codesys-store")))
STORE = "https://store.codesys.com"

# Public store SKUs (see docs/codesys_beta.md)
PRODUCTS = {
    "control-linux-sl": f"{STORE}/en/codesys-control-linux-sl-1.html",
    "edge-gateway-linux": f"{STORE}/en/codesys-edge-gateway-for-linux.html",
}


def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def login(sess: requests.Session) -> None:
    if not EMAIL or not PASSWORD:
        die("set CODESYS_STORE_EMAIL and CODESYS_STORE_PASSWORD")
    r = sess.get(f"{STORE}/en/customer/account/login/", timeout=60)
    r.raise_for_status()
    m = re.search(r'name="form_key"\s+type="hidden"\s+value="([^"]+)"', r.text)
    if not m:
        m = re.search(r'name="form_key" value="([^"]+)"', r.text)
    if not m:
        die("login form_key not found (store HTML changed)")
    form_key = m.group(1)
    payload = {
        "form_key": form_key,
        "login[username]": EMAIL,
        "login[password]": PASSWORD,
        "send": "",
    }
    r = sess.post(
        f"{STORE}/en/customer/account/loginPost/",
        data=payload,
        timeout=60,
        allow_redirects=True,
        headers={"Referer": f"{STORE}/en/customer/account/login/"},
    )
    r.raise_for_status()
    if "logout" not in r.text.lower() and "customer/account/logout" not in r.text.lower():
        # Some store skins only set a logged-in cookie.
        if "PHPSESSID" not in sess.cookies.get_dict() and "login" in r.url:
            die("CODESYS store login failed (check account)")
    print("store login: ok (email only, password not logged)")


def find_package_links(html: str) -> list[str]:
    links = re.findall(r'href="([^"]+\.package[^"]*)"', html, flags=re.I)
    links += re.findall(r'href="([^"]+downloadable/download[^"]+)"', html, flags=re.I)
    out = []
    for u in links:
        if u.startswith("//"):
            u = "https:" + u
        elif u.startswith("/"):
            u = STORE + u
        out.append(u)
    # unique preserve order
    seen = set()
    uniq = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def download(sess: requests.Session, url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"GET {url}")
    r = sess.get(url, timeout=300, stream=True, allow_redirects=True)
    r.raise_for_status()
    cd = r.headers.get("Content-Disposition", "")
    name = dest.name
    m = re.search(r'filename="?([^";]+)"?', cd)
    if m:
        name = Path(m.group(1)).name
        dest = dest.with_name(name)
    n = 0
    with dest.open("wb") as f:
        for chunk in r.iter_content(1024 * 256):
            if chunk:
                f.write(chunk)
                n += len(chunk)
    print(f"saved {dest} ({n} bytes)")
    return dest


def extract_debs(pkg: Path, outdir: Path) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    debs: list[Path] = []
    if pkg.suffix == ".deb":
        return [pkg]
    try:
        with zipfile.ZipFile(pkg) as z:
            for info in z.infolist():
                if info.filename.lower().endswith(".deb"):
                    target = outdir / Path(info.filename).name
                    with z.open(info) as src, target.open("wb") as dst:
                        dst.write(src.read())
                    debs.append(target)
                    print(f"extracted {target.name}")
    except zipfile.BadZipFile:
        print(f"not a zip/package: {pkg}")
    return debs


def main() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    sess = requests.Session()
    sess.headers["User-Agent"] = "Fieldbus-Archtecture-pooltest/1.0"
    login(sess)

    all_debs: list[Path] = []
    for key, url in PRODUCTS.items():
        print(f"--- product {key} ---")
        r = sess.get(url, timeout=60)
        print(f"product page status={r.status_code} url={r.url}")
        links = find_package_links(r.text)
        # Version table uses a license-popup JS widget; dlurl is a mediaasset
        # path that 404s until the EULA popup sets a signed cookie in a
        # real browser. Still try it so a future store change is picked up.
        dlurls = re.findall(r'dlurl":\s*"(https://store.codesys.com/en/mediaasset/[^"]+)"', r.text)
        links = links + [u.replace("\\/", "/") for u in dlurls[:3]]
        if not links:
            r2 = sess.get(f"{STORE}/en/downloadable/customer/products/", timeout=60)
            links = find_package_links(r2.text)
            print(f"customer downloads links={len(links)}")
        if not links:
            print(f"WARN no package link on {url} (EULA popup may be required in a browser)")
            (CACHE / f"{key}.html").write_text(r.text[:20000], encoding="utf-8")
            continue
        dest = download(sess, links[0], CACHE / f"{key}.package")
        all_debs.extend(extract_debs(dest, CACHE / "deb"))

    listing = CACHE / "debs.txt"
    listing.write_text("\n".join(str(p) for p in all_debs) + "\n", encoding="utf-8")
    print(f"deb list: {listing} count={len(all_debs)}")
    return 0 if all_debs else 2


if __name__ == "__main__":
    sys.exit(main())
