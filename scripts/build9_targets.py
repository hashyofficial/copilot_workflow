#!/usr/bin/env python3
"""Build 9 removal policy: original 108 targets, 16 kept and 92 deleted, plus two discovered."""
from pathlib import Path, PurePosixPath
import os
import re
import subprocess
from build8_targets import build8_targets, MIRAVISION_JNI

REMOVE_FROM_KEEP = frozenset({
    "product_a:/priv-app/Gallery_T_Global/Gallery_T_Global.apk",
    "product_a:/app/MIUIVideoPlayer/MIUIVideoPlayer.apk",
    "product_a:/data-app/MIMediaEditorGlobal/MIMediaEditorGlobal.apk",
    "product_a:/priv-app/ExtraPhotoGlobal/ExtraPhotoGlobal.apk",
})
RESTORE_CALENDAR = "product_a:/app/CalendarGoogle/CalendarGoogle.apk"
EXTRA_PACKAGE_IDS = frozenset({
    "com.google.android.apps.restore",
    "com.wdstechnology.android.kryten",
})
PHOTON_PACKAGE = "com.inferno.gallery"
PHOTON_PATH = "/app/PhotonGallery/PhotonGallery.apk"
PHOTON_SHA256 = "8a5039b05b7a8b57adb16de006c80e0a37f92debda9d745d3e3c398a4d311fe1"
PHOTON_VERSION = "v2.1.3"

def build9_targets():
    removed, ids, protected, kept = build8_targets()
    removed, ids, kept = dict(removed), dict(ids), dict(kept)
    if not REMOVE_FROM_KEEP.issubset(kept) or RESTORE_CALENDAR not in removed:
        raise RuntimeError("Build 9 source is missing media folders or stock Calendar")
    for location in REMOVE_FROM_KEEP:
        removed[location] = kept.pop(location)
    kept[RESTORE_CALENDAR] = removed.pop(RESTORE_CALENDAR)
    ids = {location: pkg for location,pkg in ids.items() if location in removed}
    if len(kept)!=16 or len(removed)!=92 or set(kept)&set(removed):
        raise RuntimeError("Build 9 needs exactly 16 kept and 92 base deleted app folders")
    return removed, ids, protected, kept

def discover_extra_packages(mounts, aapt, existing, protected, kept):
    """Locate two additional stock APKs by actual Android package ID, not guessed directory."""
    found = {}
    known = set(existing) | set(protected) | set(kept)
    known_folders = {(part,str(apk.parent)) for part,apk in list(existing.values()) + list(kept.values())}
    for partition, mount in mounts.items():
        for root, directories, files in os.walk(mount, followlinks=False):
            directories[:] = [d for d in directories if not (Path(root)/d).is_symlink()]
            for filename in files:
                if not filename.lower().endswith(".apk"):
                    continue
                actual=Path(root)/filename
                if actual.is_symlink() or not actual.is_file():
                    continue
                check=subprocess.run([str(aapt),"dump","badging",str(actual)],capture_output=True,text=True)
                if check.returncode:
                    continue
                match=re.search(r"(?m)^package: name='([^']+)'",check.stdout)
                if not match or match.group(1) not in EXTRA_PACKAGE_IDS:
                    continue
                package=match.group(1)
                rel=PurePosixPath("/"+actual.relative_to(mount).as_posix())
                location=partition+":"+str(rel)
                if location in known or (partition,str(rel.parent)) in known_folders:
                    raise RuntimeError("Build 9 extra stock APK overlaps another policy: "+location)
                if package in found or len(rel.parts)<4 or rel.suffix.lower()!=".apk":
                    raise RuntimeError("Duplicate or unsafe extra package "+package+": "+location)
                candidates=[x for x in actual.parent.rglob("*.apk") if x.is_file()]
                if len(candidates)!=1 or candidates[0]!=actual:
                    raise RuntimeError("Additional APK has a shared/ambiguous folder: "+location)
                found[package]=location
    if set(found)!=EXTRA_PACKAGE_IDS:
        raise RuntimeError("Original MIUI super lacks exact requested packages: found "
                           +str(found)+"; missing "+str(sorted(EXTRA_PACKAGE_IDS-set(found))))
    extra={loc:(loc.split(":",1)[0],PurePosixPath(loc.split(":",1)[1])) for loc in found.values()}
    ids={loc:pkg for pkg,loc in found.items()}
    return extra, ids, found
