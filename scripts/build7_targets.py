#!/usr/bin/env python3
"""Build 7: from 108 Build 6 removals, retain exactly 17 requested apps."""
from pathlib import Path, PurePosixPath
from build5_gallery_targets import targets_from_build4

KEEP_LIST = Path(__file__).resolve().parents[1] / "config/build7-keep-17.txt"
MIRAVISION_JNI = (
    "/system/lib/libMiraVision_jni.so",
    "/system/lib64/libMiraVision_jni.so",
)

def build7_targets():
    previous, package_ids, protected, _ = targets_from_build4()
    locations = []
    for raw in KEEP_LIST.read_text(encoding="utf-8").splitlines():
        location = raw.strip()
        if not location or location.startswith("#"):
            continue
        locations.append(location)
    if len(locations) != 17 or len(set(locations)) != 17:
        raise RuntimeError("Build 7 requires exactly 17 unique protected app locations")
    if not set(locations).issubset(previous):
        raise RuntimeError("Build 7 keep list has a location absent from Build 6's 108 apps: "
                           + str(sorted(set(locations) - set(previous))))
    for location in locations:
        partition, apk = previous[location]
        if apk.name != apk.parent.name + ".apk":
            raise RuntimeError("Build 7 keep-list folder does not match APK: " + location)
    if len(previous) != 108:
        raise RuntimeError("Build 7 source must have 108 original app removal candidates")
    keep = dict((loc, previous[loc]) for loc in locations)
    removed = {loc: value for loc, value in previous.items() if loc not in keep}
    if len(removed) != 91 or len(keep) != 17:
        raise RuntimeError("Build 7 policy must leave exactly 91 app-folder deletions")
    if set(removed) & set(keep):
        raise RuntimeError("Cannot remove a protected Build 7 app")
    # Avoid telling the cleanup scanner that the 17 kept APK identities are removed.
    deleted_package_ids = {loc: pkg for loc, pkg in package_ids.items() if loc in removed}
    return removed, deleted_package_ids, protected, keep
