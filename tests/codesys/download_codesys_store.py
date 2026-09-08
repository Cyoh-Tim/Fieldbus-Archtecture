#!/usr/bin/env python3
"""Download CODESYS Control for Linux SL from the Store (2-hour demo).

Reads CODESYS_STORE_EMAIL / CODESYS_STORE_PASSWORD from the environment.
Never prints the password. Packages land in $CODESYS_CACHE (default
~/.cache/codesys-store) and are NOT committed.

Store download is behind a Magento EULA popup. A browser copies the HTML
form_key into a cookie; without that cookie, license/accept returns
"Invalid Form Key". Flow:

  1. Login, keep form_key in both the cookie jar and POST body.
  2. Parse data-mage-init license-popup widgets (fileHash + dlurl).
  3. POST /en/license-agreement/license/get  (EULA HTML)
  4. POST /en/license-agreement/license/accept with file=<dlurl>
  5. GET dlurl → store-archive.codesys.com .package (zip)
"""
from __future__ import annotations

import html as htmlmod
import json
import os
import re
import sys
import time
import zipfile
from pathlib import Path

import requests

EMAIL = os.environ.get("CODESYS_STORE_EMAIL", "").strip()
PASSWORD = os.environ.get("CODESYS_STORE_PASSWORD", "")
CACHE = Path(os.environ.get("CODESYS_CACHE", str(Path.home() / ".cache/codesys-store")))
STORE = "https://store.codesys.com"
UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

PRODUCTS = {
    "control-linux-sl": f"{STORE}/en/codesys-control-linux-sl-1.html",
    "edge-gateway-linux": f"{STORE}/en/codesys-edge-gateway-for-linux.html",
}

WIDGET_RE = re.compile(
    r"data-fillename=\"([^\"]+)\"[^>]*?"
    r"data-mage-init='(\{\"Codesys_LicenseAgreement/js/license-popup\":\{[^}]+\}\})'",
    re.I,
)


def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def _cookie_value(sess: requests.Session, name: str) -> str | None:
    value = None
    for cookie in sess.cookies:
        if cookie.name == name:
            value = cookie.value
    return value


def _set_form_key(sess: requests.Session, form_key: str) -> None:
    for cookie in list(sess.cookies):
        if cookie.name == "form_key":
            sess.cookies.clear(cookie.domain, cookie.path, cookie.name)
    sess.cookies.set("form_key", form_key, domain="store.codesys.com", path="/")


def _form_key_from_html(text: str) -> str | None:
    m = re.search(r'name="form_key"[^>]*value="([^"]+)"', text)
    if not m:
        m = re.search(r'name="form_key"\s+type="hidden"\s+value="([^"]+)"', text)
    return m.group(1) if m else None


def login(sess: requests.Session) -> None:
    if not EMAIL or not PASSWORD:
        die("set CODESYS_STORE_EMAIL and CODESYS_STORE_PASSWORD")
    r = sess.get(f"{STORE}/en/customer/account/login/", timeout=60)
    r.raise_for_status()
    form_key = _form_key_from_html(r.text)
    if not form_key:
        die("login form_key not found (store HTML changed)")
    _set_form_key(sess, form_key)
    r = sess.post(
        f"{STORE}/en/customer/account/loginPost/",
        data={
            "form_key": form_key,
            "login[username]": EMAIL,
            "login[password]": PASSWORD,
            "send": "",
        },
        timeout=60,
        allow_redirects=True,
        headers={"Referer": f"{STORE}/en/customer/account/login/"},
    )
    r.raise_for_status()
    if "customer/account/logout" not in r.text.lower() and "logout" not in r.text.lower():
        if "login" in r.url:
            die("CODESYS store login failed (check account)")
    print("store login: ok (email only, password not logged)")


def parse_widgets(page_html: str) -> list[tuple[str, str, str]]:
    """Return (filename, fileHash, dlurl) newest-first (store lists latest first)."""
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for raw_name, raw_json in WIDGET_RE.findall(page_html):
        name = htmlmod.unescape(raw_name.replace("&#x20;", " "))
        try:
            cfg = json.loads(raw_json)["Codesys_LicenseAgreement/js/license-popup"]
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        file_hash = cfg.get("fileHash") or ""
        dlurl = cfg.get("dlurl") or ""
        if not file_hash or not dlurl or dlurl in seen:
            continue
        seen.add(dlurl)
        out.append((name, file_hash, dlurl))
    return out


def accept_eula(sess: requests.Session, file_hash: str, dlurl: str, referer: str) -> None:
    form_key = _cookie_value(sess, "form_key")
    if not form_key:
        die("form_key cookie missing before EULA accept")
    hdr = {
        "Referer": referer,
        "X-Requested-With": "XMLHttpRequest",
    }
    # get returns the EULA HTML; required before accept on a fresh session.
    g = sess.post(
        f"{STORE}/en/license-agreement/license/get",
        data={"fileHash": file_hash, "form_key": form_key},
        headers=hdr,
        timeout=60,
    )
    g.raise_for_status()
    a = sess.post(
        f"{STORE}/en/license-agreement/license/accept",
        data={"file": dlurl, "form_key": form_key},
        headers=hdr,
        timeout=60,
    )
    a.raise_for_status()
    try:
        body = a.json()
    except ValueError:
        die(f"EULA accept returned non-JSON ({a.status_code})")
    if body.get("error"):
        die(f"EULA accept failed: {body}")
    print("EULA accept: ok")


def find_cached_package(product_key: str, name: str) -> Path | None:
    version = re.search(r"(\d+\.\d+\.\d+\.\d+)", name)
    globs = {
        "control-linux-sl": ["*Control*Linux*.package", "*Control*SL*.package"],
        "edge-gateway-linux": ["*Edge*Gateway*.package"],
    }.get(product_key, ["*.package"])
    candidates: list[Path] = []
    for pattern in globs:
        candidates.extend(CACHE.glob(pattern))
    for path in candidates:
        if path.stat().st_size <= 1_000_000:
            continue
        if version and version.group(1) not in path.name:
            continue
        try:
            with zipfile.ZipFile(path) as z:
                z.namelist()
        except zipfile.BadZipFile:
            continue
        return path
    return None


def download(sess: requests.Session, url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 1_000_000:
        try:
            with zipfile.ZipFile(dest) as z:
                z.namelist()
            print(f"cache hit {dest} ({dest.stat().st_size} bytes)")
            return dest
        except zipfile.BadZipFile:
            dest.unlink()
    last_err: Exception | None = None
    for attempt in range(1, 5):
        print(f"GET archive for {dest.name} (try {attempt})")
        try:
            r = sess.get(url, timeout=300, stream=True, allow_redirects=True)
            r.raise_for_status()
            cd = r.headers.get("Content-Disposition", "")
            m = re.search(r'filename="?([^";]+)"?', cd)
            if m:
                dest = dest.with_name(Path(htmlmod.unescape(m.group(1))).name)
            elif "store-archive.codesys.com" in r.url:
                dest = dest.with_name(Path(requests.utils.unquote(r.url.split("/")[-1])).name)
            n = 0
            with dest.open("wb") as f:
                for chunk in r.iter_content(1024 * 256):
                    if chunk:
                        f.write(chunk)
                        n += len(chunk)
            ctype = r.headers.get("Content-Type", "")
            if n < 1_000_000 or "html" in ctype.lower():
                dest.unlink(missing_ok=True)
                die(f"download was not a package ({n} bytes, {ctype})")
            print(f"saved {dest} ({n} bytes)")
            return dest
        except (requests.RequestException, OSError) as exc:
            last_err = exc
            print(f"WARN archive GET failed: {exc}")
            dest.unlink(missing_ok=True)
            time.sleep(2 * attempt)
    die(f"archive GET failed after retries: {last_err}")
    raise AssertionError


def extract_debs(pkg: Path, outdir: Path) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    debs: list[Path] = []
    if pkg.suffix == ".deb":
        return [pkg]
    try:
        with zipfile.ZipFile(pkg) as z:
            for info in z.infolist():
                lower = info.filename.lower()
                if not (lower.endswith(".deb") or lower.endswith(".ipk")):
                    continue
                target = outdir / Path(info.filename).name
                with z.open(info) as src, target.open("wb") as dst:
                    dst.write(src.read())
                debs.append(target)
                print(f"extracted {target.name}")
    except zipfile.BadZipFile:
        print(f"not a zip/package: {pkg}")
    return debs


def pick_latest_runtime(widgets: list[tuple[str, str, str]]) -> tuple[str, str, str] | None:
    if not widgets:
        return None
    return widgets[0]


def main() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    login(sess)

    all_debs: list[Path] = []
    for key, url in PRODUCTS.items():
        print(f"--- product {key} ---")
        r = sess.get(url, timeout=60)
        print(f"product page status={r.status_code}")
        r.raise_for_status()
        page_key = _form_key_from_html(r.text)
        if page_key:
            _set_form_key(sess, page_key)
        widgets = parse_widgets(r.text)
        print(f"EULA widgets={len(widgets)}")
        picked = pick_latest_runtime(widgets)
        if not picked:
            print(f"WARN no license-popup widget on {url}")
            (CACHE / f"{key}.html").write_text(r.text[:40000], encoding="utf-8")
            continue
        name, file_hash, dlurl = picked
        print(f"selected {name}")
        cached = find_cached_package(key, name)
        if cached is not None:
            dest = cached
            print(f"cache hit {dest} ({dest.stat().st_size} bytes)")
        else:
            safe = re.sub(r"[^\w.\-]+", "-", name).strip("-") + ".package"
            dest = CACHE / safe
            accept_eula(sess, file_hash, dlurl, url)
            dest = download(sess, dlurl, dest)
        all_debs.extend(extract_debs(dest, CACHE / "deb"))

    listing = CACHE / "debs.txt"
    listing.write_text("\n".join(str(p) for p in all_debs) + "\n", encoding="utf-8")
    print(f"deb list: {listing} count={len(all_debs)}")
    return 0 if all_debs else 2


if __name__ == "__main__":
    sys.exit(main())
