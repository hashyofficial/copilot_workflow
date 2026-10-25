#!/usr/bin/env python3
"""Standalone Build 6 policy tests: no firmware download, root or mount needed."""
import pathlib
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
from build6_cleanup import find_cleanup, APPROVED_PINNED_NATIVE
from unittest.mock import patch

P = pathlib.PurePosixPath
WEATHER = "product_a:/data-app/MIUIWeatherGlobal/MIUIWeatherGlobal.apk"
GALLERY = "product_a:/priv-app/Gallery_T_Global/Gallery_T_Global.apk"
TARGETS = {
    WEATHER: ("product_a", P("/data-app/MIUIWeatherGlobal/MIUIWeatherGlobal.apk")),
    GALLERY: ("product_a", P("/priv-app/Gallery_T_Global/Gallery_T_Global.apk")),
}
PACKAGES = {WEATHER: "com.miui.weather2", GALLERY: "com.miui.gallery"}


def entry(size=2):
    return {"kind": "file", "bytes": size}


class Build6CleanupPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.entries = {}

    def add(self, path, data=b"test"):
        file = self.root / path.lstrip("/")
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
        self.entries[path] = entry(len(data))

    def plan(self):
        return find_cleanup(self.root, "product_a", TARGETS, PACKAGES,
                            self.entries, "/bin/false")

    def test_unreviewed_native_is_retained_but_exact_app_owned_xml_is_selected(self):
        self.add("/lib64/libMIUIWeatherGlobal.so")
        self.add("/etc/permissions/com.miui.weather2.xml",
                 b'<permissions><privapp-permissions package="com.miui.weather2"/></permissions>')
        removed, report = self.plan()
        self.assertEqual(set(removed), {"/etc/permissions/com.miui.weather2.xml"})
        self.assertEqual(report["standalone_entries_selected"], 1)
        self.assertTrue(any(x["kind"]=="native_library" for x in report["retained_for_review"]))

    def test_mixed_permissions_file_is_not_deleted(self):
        self.add("/etc/permissions/com.miui.weather2.xml",
                 b'<permissions><privapp-permissions package="com.miui.weather2"/>'
                 b'<privapp-permissions package="com.android.systemui"/></permissions>')
        removed, report = self.plan()
        self.assertFalse(removed)
        self.assertEqual(len(report["retained_for_review"]), 1)

    def test_library_shared_with_retained_apk_is_not_deleted(self):
        self.add("/lib64/libMIUIWeatherGlobal.so")
        apk = self.root / "app/Other/Other.apk"
        apk.parent.mkdir(parents=True)
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("lib/arm64-v8a/libMIUIWeatherGlobal.so", b"retained")
        self.entries["/app/Other/Other.apk"] = entry(apk.stat().st_size)
        removed, report = self.plan()
        self.assertFalse(removed)
        self.assertEqual(report["retained_for_review"][0]["kind"], "native_library")

    def test_never_selects_generic_or_inside_removed_folder(self):
        self.add("/lib64/libandroid.so")
        self.add("/data-app/MIUIWeatherGlobal/oat/libMIUIWeatherGlobal.so")
        removed, report = self.plan()
        self.assertFalse(removed)
        self.assertFalse(report["retained_for_review"])

    def test_only_three_sha256_pinned_orphan_jni_libraries_are_approved(self):
        files=list(APPROVED_PINNED_NATIVE)
        for path in files:
            self.add(path,b"pinned")
        targets={
            "system_a:/system/app/MiraVision/MiraVision.apk":
                ("system_a",P("/system/app/MiraVision/MiraVision.apk")),
            "system_a:/system/app/MiuiPrintSpooler/MiuiPrintSpooler.apk":
                ("system_a",P("/system/app/MiuiPrintSpooler/MiuiPrintSpooler.apk")),
        }
        ids={
            "system_a:/system/app/MiraVision/MiraVision.apk":"com.mediatek.miravision.ui",
            "system_a:/system/app/MiuiPrintSpooler/MiuiPrintSpooler.apk":"com.android.printspooler",
        }
        def pin_digest(path):
            key="/"+str(path.relative_to(self.root))
            return APPROVED_PINNED_NATIVE[key][0]
        with patch("build6_cleanup.sha",side_effect=pin_digest):
            selected,record=find_cleanup(self.root,"system_a",targets,ids,self.entries,"/bin/false")
        self.assertEqual(set(selected),set(files))
        self.assertEqual(record["standalone_entries_selected"],3)

    def test_pinned_native_library_digest_mismatch_blocks_deletion(self):
        for name in APPROVED_PINNED_NATIVE:self.add(name,b"incorrect")
        targets={
            "system_a:/system/app/MiraVision/MiraVision.apk":
                ("system_a",P("/system/app/MiraVision/MiraVision.apk")),
            "system_a:/system/app/MiuiPrintSpooler/MiuiPrintSpooler.apk":
                ("system_a",P("/system/app/MiuiPrintSpooler/MiuiPrintSpooler.apk")),
        }
        ids={
            "system_a:/system/app/MiraVision/MiraVision.apk":"com.mediatek.miravision.ui",
            "system_a:/system/app/MiuiPrintSpooler/MiuiPrintSpooler.apk":"com.android.printspooler",
        }
        with self.assertRaisesRegex(RuntimeError,"SHA256 mismatch"):
            find_cleanup(self.root,"system_a",targets,ids,self.entries,"/bin/false")

    def test_shared_feature_xml_is_not_deleted(self):
        self.add("/etc/permissions/com.miui.weather2.xml",
                 b'<permissions><library name="weather" file="/lib64/weather.so"/>'
                 b'<privapp-permissions package="com.miui.weather2"/></permissions>')
        removed, report = self.plan()
        self.assertFalse(removed)
        self.assertEqual(len(report["retained_for_review"]), 1)


if __name__ == "__main__":
    unittest.main()
