#!/usr/bin/env python3
"""Regenerate gms_certified_props.json from the current stock full OTA.

The device identity Google ships is all in the OTA zip's tiny metadata
member: post-build carries the whole fingerprint and
post-security-patch-level the SPL. Range-fetching that member beats
downloading or decoding anything else. Everything the metadata does not
carry is constant per device.

Prints CHANGED or UNCHANGED and writes the file only when the identity
moved. Exits non-zero on any fetch or parse failure so the workflow
leaves the last good file alone.
"""
import json
import re
import struct
import sys
import urllib.request

DEVICE = "yogi"
MODEL = "Pixel 11 Pro Fold"
HARDWARE = "yogi"
FIRST_API = "37"
OTA_PAGE = "https://developers.google.com/android/ota"
PAGE_HEADERS = {"Cookie": "devsite_wall_acks=nexus-ota-tos"}


def fetch(url, start=None, end=None, headers=None):
    h = dict(headers or {})
    if start is not None:
        h["Range"] = f"bytes={start}-{end}"
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def build_key(url):
    # cd1a.261005.003.b1 -> (0xcd1a is not numeric; sort dot-separated tokens,
    # numeric where possible, so .b1 sorts above .003 and later builds win)
    b = re.search(rf"{DEVICE}-ota-([a-z0-9.]+)-[0-9a-f]+\.zip", url).group(1)
    parts = []
    for tok in b.split("."):
        parts.append((1, int(tok)) if tok.isdigit() else (0, tok))
    return parts


def find_ota_url():
    page = fetch(OTA_PAGE, headers=PAGE_HEADERS).decode("utf-8", "replace")
    pat = re.compile(
        rf"https://dl\.google\.com/dl/android/aosp/{DEVICE}-ota-[a-z0-9.]+-[0-9a-f]+\.zip"
    )
    matches = list(pat.finditer(page))
    if not matches:
        sys.exit(f"no {DEVICE} OTA link on {OTA_PAGE}")
    mainline = []
    for i, m in enumerate(matches):
        before = page[matches[i - 1].end() if i else 0 : m.start()]
        # the row's version cell precedes its link; SB marks the satellite
        # variant build, which is not what this device runs
        if re.search(r"CD1A\.[A-Z0-9.]+[^)<]*,\s*SB\)", before):
            continue
        mainline.append(m.group(0))
    if not mainline:
        sys.exit("every OTA listed is an SB variant")
    return max(mainline, key=build_key)


def zip_size(url):
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers["Content-Length"])


def read_metadata(url):
    size = zip_size(url)
    tail = fetch(url, max(0, size - 65536), size - 1)
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0:
        sys.exit("no EOCD in zip tail")
    _, _, _, _, entries, cd_size, cd_off, _ = struct.unpack(
        "<IHHHHIIH", tail[eocd : eocd + 22]
    )
    cd = fetch(url, cd_off, cd_off + cd_size - 1)
    meta_off = meta_len = None
    i = 0
    while i + 46 <= len(cd):
        if cd[i : i + 4] != b"PK\x01\x02":
            break
        (n, m, k) = struct.unpack("<HHH", cd[i + 28 : i + 34])
        name = cd[i + 46 : i + 46 + n].decode("utf-8", "replace")
        if name == "META-INF/com/android/metadata":
            meta_off = struct.unpack("<I", cd[i + 42 : i + 46])[0]
            meta_len = struct.unpack("<I", cd[i + 24 : i + 28])[0]
            break
        i += 46 + n + m + k
    if meta_off is None:
        sys.exit("no metadata member in zip")
    head = fetch(url, meta_off, meta_off + 29)
    (hn, hm) = struct.unpack("<HH", head[26:30])
    data_off = meta_off + 30 + hn + hm
    return fetch(url, data_off, data_off + meta_len - 1).decode("utf-8", "replace")


def parse_identity(meta):
    fields = dict(
        line.split("=", 1) for line in meta.splitlines() if "=" in line
    )
    fp = fields.get("post-build")
    if not fp:
        sys.exit("metadata has no post-build")
    # brand/product/device:release/id/incremental:type/tags
    brand, product, dev_rel, build_id, tail = fp.split("/", 4)
    device, release = dev_rel.split(":", 1)
    incremental, typetags = tail.split(":", 1)
    typ, tags = typetags.split("/", 1)
    return {
        "MANUFACTURER": "Google",
        "MODEL": MODEL,
        "FINGERPRINT": fp,
        "BRAND": brand,
        "PRODUCT": product,
        "DEVICE": device,
        "HARDWARE": HARDWARE,
        "VERSION.RELEASE": release,
        "ID": build_id,
        "VERSION.INCREMENTAL": incremental,
        "TYPE": typ,
        "TAGS": tags,
        "VERSION.SECURITY_PATCH": fields.get("post-security-patch-level", ""),
        "VERSION.DEVICE_INITIAL_SDK_INT": FIRST_API,
    }


def main():
    url = find_ota_url()
    print(f"OTA: {url.rsplit('/', 1)[1]}")
    props = parse_identity(read_metadata(url))
    old = {}
    try:
        with open("gms_certified_props.json") as f:
            old = json.load(f)
    except (OSError, ValueError):
        pass
    if old == props:
        print("UNCHANGED")
        return
    with open("gms_certified_props.json", "w") as f:
        json.dump(props, f, indent=4)
        f.write("\n")
    print(f"CHANGED {props['FINGERPRINT']}")


if __name__ == "__main__":
    main()
