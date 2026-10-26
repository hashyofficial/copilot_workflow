#!/usr/bin/env python3
"""Build 11 from verified original MIUI 14: retain Gallery and Mi Video.

Never source binary data from Build 9/10 releases. The fresh-source packer
re-extracts the MD5/SHA256 verified Xiaomi original. This is a policy-only
inheritance from Build 10, not a prebuilt firmware input.
"""
from build10_targets import (
    build10_targets, discover_extra_packages, EXTRA_PACKAGE_IDS,
    MIRAVISION_JNI, GALLERY_LOCATION, MIVIDEO_LOCATION, CALENDAR_LOCATION,
)

VERIFIED_RESTORATIONS = frozenset({GALLERY_LOCATION, MIVIDEO_LOCATION})
PHOTON_PACKAGE = "com.inferno.gallery"

def build11_targets():
    removed, package_ids, protected, kept=build10_targets()
    removed,package_ids,kept=dict(removed),dict(package_ids),dict(kept)
    if MIVIDEO_LOCATION not in removed:
        raise RuntimeError("Mi Video is not removed by Build 10; source policy changed")
    kept[MIVIDEO_LOCATION]=removed.pop(MIVIDEO_LOCATION)
    package_ids.pop(MIVIDEO_LOCATION,None)
    if len(removed)!=90 or len(kept)!=18 or len(protected)!=3:
        raise RuntimeError("Build 11 requires exactly 90 baseline removals, 18 kept and 3 protected")
    if not VERIFIED_RESTORATIONS.issubset(kept):
        raise RuntimeError("MIUI Gallery and Mi Video must both be kept")
    if CALENDAR_LOCATION not in kept or set(removed)&set(kept):
        raise RuntimeError("Build 11 Calendar or exclusion overlap")
    if any("PhotonGallery" in loc for loc in (*removed,*kept)):
        raise RuntimeError("No preinstalled Photon Gallery")
    if "product_a:/priv-app/MIServiceGlobalPad/MIServiceGlobalPad.apk" not in removed:
        raise RuntimeError("MIService has no proven mandatory dependency, leave removed")
    return removed,package_ids,protected,kept
