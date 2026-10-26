#!/usr/bin/env python3
"""Build 10: fresh-stock removal policy, restore only stock MIUI Gallery.

Build 9 is a *policy input*, NEVER the source image. The packer downloads,
MD5/SHA256-verifies and rebuilds from untouched original Xiaomi MIUI 14.
No Photon Gallery APK, no Mi Video. No speculative "needed" app restorations.
"""
from build9_targets import (
    build9_targets, discover_extra_packages, EXTRA_PACKAGE_IDS,
    MIRAVISION_JNI
)

GALLERY_LOCATION = "product_a:/priv-app/Gallery_T_Global/Gallery_T_Global.apk"
MIVIDEO_LOCATION = "product_a:/app/MIUIVideoPlayer/MIUIVideoPlayer.apk"
CALENDAR_LOCATION = "product_a:/app/CalendarGoogle/CalendarGoogle.apk"
PHOTON_PACKAGE = "com.inferno.gallery"

# Only confirmed repair: default SYSTEM_GALLERY points to com.miui.gallery.
# MIService is only referenced by the removed Feedback label in Settings,
# not established as a mandatory Security Center/firewall requirement.
VERIFIED_NECESSARY_RESTORATIONS = frozenset({GALLERY_LOCATION})

def build10_targets():
    removed,ids,protected,kept=build9_targets()
    removed,ids,kept=dict(removed),dict(ids),dict(kept)
    for location in VERIFIED_NECESSARY_RESTORATIONS:
        if location not in removed:
            raise RuntimeError("Build 9 no longer removes required restoration: "+location)
        kept[location]=removed.pop(location)
        ids.pop(location,None)
    if (len(removed),len(kept))!=(91,17):
        raise RuntimeError("Build 10 requires 91 baseline removals and 17 stock apps retained")
    if (GALLERY_LOCATION not in kept or CALENDAR_LOCATION not in kept
        or MIVIDEO_LOCATION not in removed or set(kept)&set(removed)):
        raise RuntimeError("Build 10 critical Gallery/Calendar/MiVideo policy mismatch")
    if any("PhotonGallery" in loc for loc in (*removed,*kept)):
        raise RuntimeError("Do not include Photon Gallery in the stock policy")
    return removed,ids,protected,kept
