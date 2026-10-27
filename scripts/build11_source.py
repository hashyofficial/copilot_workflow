#!/usr/bin/env python3
"""Build 11 pinned Xiaomi Redmi Pad yunluo HyperOS Global source.
Keep MIUI Build 10 constants and downloader source unmodified.
"""
import argparse
import json
import sys
from pathlib import Path
from inventory import sha
import download as stock_downloader

VERSION = "OS1.0.9.0.ULYMIXM"
FILENAME = "yunluo_global_images_OS1.0.9.0.ULYMIXM_20250416.0000.00_14.0_global_f8dbb84a10.tgz"
MD5 = "f8dbb84a10dc96a9d3ce9e78883e87f3"
DEVICE = "yunluo"
REGION = "global"
ANDROID = "14"
SOURCE_URL = "https://bigota.d.miui.com/" + VERSION + "/" + FILENAME

def verify_archive(path):
    path = Path(path)
    if not path.is_file() or not path.stat().st_size:
        raise RuntimeError("Missing stock HyperOS fastboot archive")
    observed = sha(path, "md5")
    if observed.lower() != MD5:
        raise RuntimeError("Wrong/unverified ROM: " + observed + ", expected " + MD5)
    return observed

def download_archive(output, report):
    output, report = Path(output), Path(report)
    output.parent.mkdir(parents=True, exist_ok=True)
    report.parent.mkdir(parents=True, exist_ok=True)
    if not output.exists():
        # Reuse the proven Build 10 CDN probing, aria2 failover and stall detection.
        # Only the *new module's* runtime globals are changed, never any Build 10 file.
        stock_downloader.VERSION = VERSION
        stock_downloader.FILENAME = FILENAME
        previous = sys.argv[:]
        try:
            sys.argv = ["download.py", "--output", str(output), "--report", str(report)]
            stock_downloader.main()
        finally:
            sys.argv = previous
    observed = verify_archive(output)
    result = {"device": DEVICE, "region": REGION, "android": ANDROID,
              "version": VERSION, "archive": FILENAME, "published_md5": MD5,
              "observed_md5": observed, "official_source": SOURCE_URL}
    (report.parent / "build11-source.json").write_text(json.dumps(result, indent=2) + "\n")
    return output

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    download_archive(args.output, args.report)
