#!/usr/bin/env python3
"""Build 7: identify *owned* leftovers of the 108 removed APKs.

Only exact, app-specific matches are eligible. Never remove an entire shared
lib, permission, sysconfig or overlay directory. All selections are audited.
"""
from collections import defaultdict
from pathlib import Path, PurePosixPath
import re
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from inventory import sha

# A short/generic stem is never enough evidence to delete a system library.
MIN_LIBRARY_STEM = 12
MIN_CONFIG_STEM = 9

# Build 7 reference-audit run 40204058606 checked 3,233 surviving files and
# 152,951 decompressed ZIP entries across product_a/system_a/system_ext_a.
# ONLY these three candidate .so files had zero observed surviving references;
# all other candidates, including MIUI monitor and voice-command JNI, are kept.
APPROVED_PINNED_NATIVE = {
    # Sole approved JNI deletion: printing app remains removed in Build 7.
    "/system/lib64/libprintspooler_jni.so": (
        "f40d77dabd994155d05f8380cf3d5183b9ddf97b73fa6c90701c94d8efaeb35b",
        "com.android.printspooler",
    ),
}
# Explicitly preserve both MiraVision JNI files formerly excluded in Build 7.
MIRAVISION_JNI = frozenset({
    "/system/lib/libMiraVision_jni.so",
    "/system/lib64/libMiraVision_jni.so",
})

def normalize(value):
    return re.sub(r"[^a-z0-9]", "", value.casefold())

def removed_under(path, folders):
    return any(path == f or path.startswith(f + "/") for f in folders)

def identities(targets, package_ids):
    """Return normalized, exact owners and the set of explicitly removed IDs."""
    alias = defaultdict(set)
    removed_ids = set(package_ids.values())
    for location, (_, apk) in targets.items():
        folder = normalize(apk.parent.name)
        if len(folder) >= MIN_CONFIG_STEM:
            alias[folder].add(location)
    for location, package in package_ids.items():
        for name in (package, package.rsplit(".", 1)[-1]):
            term = normalize(name)
            if len(term) >= MIN_CONFIG_STEM:
                alias[term].add(location)
    return alias, removed_ids

def retained_embedded_libs(mount, entries, deleted_dirs):
    """Never delete a library also bundled by a retained stock APK."""
    libs = set()
    for path, info in entries.items():
        if info["kind"] != "file" or not path.lower().endswith(".apk"):
            continue
        if removed_under(path, deleted_dirs):
            continue
        apk = mount / path.lstrip("/")
        try:
            with zipfile.ZipFile(apk) as z:
                libs.update(PurePosixPath(name).name for name in z.namelist()
                            if name.startswith("lib/") and name.endswith(".so"))
        except (OSError, zipfile.BadZipFile):
            # Fail closed if APK metadata cannot be safely inspected.
            raise RuntimeError("Cannot check native libraries in retained APK: " + path)
    return libs

def find_cleanup(mount, partition, targets, package_ids, entries, aapt):
    """Return (extra exclusions, full selection / skipped report).

    Extra exclusions are precise *files*, never broad glob patterns. Gallery,
    the other 107 folders, and protected/system shared files retain the same
    verification guarantees as Build 5.
    """
    deleted = sorted(str(apk.parent) for p, apk in targets.values() if p == partition)
    aliases, removed_ids = identities(targets, package_ids)
    selected, review = [], []
    pending_libs = []
    def record(kind, path, owners, reason, delete):
        item = {"kind": kind, "path": path, "owners": sorted(owners),
                "reason": reason, "bytes": entries[path].get("bytes", 0)}
        (selected if delete else review).append(item)

    for path, info in sorted(entries.items()):
        if info["kind"] != "file" or removed_under(path, deleted):
            continue
        p = PurePosixPath(path)
        parent = str(p.parent)
        filename = p.name
        if filename.endswith(".so") and any(parent == root or parent.startswith(root + "/")
                for root in ("/lib", "/lib64", "/system/lib", "/system/lib64")):
            if partition == "system_a" and (
                    path in MIRAVISION_JNI or "miravision" in filename.casefold()):
                # Protect all MiraVision JNI library files, even if name resembles a deleted app.
                continue
            if partition == "system_a" and path in APPROVED_PINNED_NATIVE:
                expected_sha, owner = APPROVED_PINNED_NATIVE[path]
                if owner not in removed_ids:
                    raise RuntimeError("Build 7 library owner not among deleted APKs: " + path)
                if sha(mount / path.lstrip("/")) != expected_sha:
                    raise RuntimeError("Reviewed native library SHA256 mismatch: " + path)
                linked = [p for p, d in entries.items() if d["kind"] == "symlink"
                          and not removed_under(p,deleted)
                          and PurePosixPath(d.get("link","")).name == filename]
                if linked:
                    record("native_library",path,[owner],"Still linked from retained firmware: "+str(linked[:8]),False)
                else:
                    record("native_library",path,[owner],
                           "Pinned SHA256, removed-app JNI owner, zero observed retained refs in Build 7 audit",True)
                continue
            stem = filename[3:-3] if filename.startswith("lib") else filename[:-3]
            key = normalize(stem)
            if len(key) >= MIN_LIBRARY_STEM and key in aliases:
                pending_libs.append((path, aliases[key]))
            continue

        is_config = p.suffix.lower() == ".xml" and any(
            parent == prefix or parent.startswith(prefix + "/") for prefix in (
                "/etc/permissions", "/etc/sysconfig", "/etc/default-permissions",
                "/etc/privapp-permissions", "/system/etc/permissions",
                "/system/etc/sysconfig", "/system/etc/default-permissions",
                "/system/etc/privapp-permissions"))
        if is_config:
            key = normalize(p.stem)
            if len(key) < MIN_CONFIG_STEM or key not in aliases:
                continue
            try:
                node = ET.parse(mount / path.lstrip("/")).getroot()
                named = {e.attrib["package"] for e in node.iter() if "package" in e.attrib}
                shared_libraries = any(e.tag.rsplit("}", 1)[-1] in ("library", "feature") for e in node.iter())
            except (ET.ParseError, OSError, UnicodeError) as exc:
                record("xml", path, aliases[key], "Unreadable XML; retained: " + str(exc), False)
                continue
            if named and named.issubset(removed_ids) and not shared_libraries:
                record("xml", path, aliases[key], "Filename exact match; all package declarations belong to removed APKs", True)
            else:
                record("xml", path, aliases[key], "Unproven ownership, mixed package declarations or shared configuration", False)
            continue

        # Overlay APKs: the Android package metadata, never the filename alone,
        # must prove an overlay targets a removed app. Shared overlay dirs stay.
        if filename.endswith(".apk") and (parent == "/overlay" or parent.startswith("/overlay/")
                or parent == "/system/overlay" or parent.startswith("/system/overlay/")):
            check = subprocess.run([aapt, "dump", "badging", str(mount / path.lstrip("/"))],
                                   capture_output=True, text=True)
            if check.returncode:
                record("overlay", path, [], "Cannot parse overlay APK; retained", False)
                continue
            match = re.search(r"(?m)^overlay:\s+targetPackage='([^']+)'", check.stdout)
            if match and match.group(1) in removed_ids:
                record("overlay", path, [match.group(1)], "Overlay targets only a removed Android package", True)

    if pending_libs:
        for path, owners in pending_libs:
            record("native_library",path,owners,
                   "Unreviewed library filename similarity is insufficient proof of exclusive ownership",False)
    if partition=="system_a":
        selected_pins={item["path"] for item in selected if item["kind"]=="native_library"}
        expected_pins=set(APPROVED_PINNED_NATIVE)
        if selected_pins!=expected_pins:
            raise RuntimeError("Not all three SHA256-reviewed Build 7 JNI libraries can safely be excluded")
    paths = [item["path"] for item in selected]
    if len(paths) != len(set(paths)):
        raise RuntimeError("Duplicate Build 7 exclusion")
    if any(removed_under(path, deleted) for path in paths):
        raise RuntimeError("Overlapping Build 7 folder and file deletion")
    for item in selected:
        if item["path"] not in entries:
            raise RuntimeError("Missing Build 7 original extra file")
    return paths, {"partition": partition, "selected": selected,
                   "retained_for_review": review,
                   "standalone_entries_selected": len(paths),
                   "bytes_selected": sum(x["bytes"] for x in selected)}
