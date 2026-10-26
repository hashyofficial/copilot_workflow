#!/usr/bin/env python3
"""Build 8 regression tests: exact keep-list and protected MiraVision JNI."""
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build8_targets import build8_targets, MIRAVISION_JNI, KEEP_LIST
from build8_cleanup import find_cleanup, APPROVED_PINNED_NATIVE

class Build8KeepPolicyTests(TestCase):
    def test_exact_19_kept_and_89_removed(self):
        removed, package_ids, protected, kept = build8_targets()
        self.assertEqual(len(removed),89)
        self.assertEqual(len(kept),19)
        self.assertEqual(len(protected),3)
        self.assertFalse(set(removed) & set(kept))
        self.assertEqual(set(package_ids)-set(removed),set())
        folders={p.parent.name for _,p in kept.values()}
        self.assertEqual(folders,{
            "ContactsProvider","MiraVision","Turbo","MIUIXiaomiAccountGlobal",
            "MIUIVideoPlayer","MiuiScanner","MIUIDeskClockPadGlobal",
            "MIUICloudServiceGlobal","MIUICalculatorGlobalPad","MIMediaEditorGlobal",
            "GoogleContacts","ExtraPhotoGlobal","SoundPicker","FindDevice",
            "Gallery_T_Global","MIUICloudBackupGlobal","MIUIMiCloudSync", 
            "Backup","UserDictionaryProvider"})
        self.assertEqual(len(MIRAVISION_JNI),2)
        self.assertEqual(set(APPROVED_PINNED_NATIVE),{"/system/lib64/libprintspooler_jni.so"})

    def test_backup_dictionary_are_protected_and_parent_dirs_survive(self):
        removed, package_ids, _, kept = build8_targets()
        required = {
            "system_a:/system/priv-app/Backup/Backup.apk": "Backup",
            "system_a:/system/priv-app/UserDictionaryProvider/UserDictionaryProvider.apk": "UserDictionaryProvider",
        }
        for loc, dirname in required.items():
            self.assertIn(loc, kept)
            self.assertNotIn(loc, removed)
            self.assertEqual(kept[loc][1].parent.name, dirname)
            self.assertNotIn(loc, package_ids)
        self.assertEqual(len({(part, str(apk.parent)) for part,apk in removed.values()}),89)

    def test_duplicate_keep_entry_fails_closed(self):
        with TemporaryDirectory() as td:
            f=Path(td)/"kept.txt"
            value=KEEP_LIST.read_text()
            first=next(line for line in value.splitlines() if line and not line.startswith("#"))
            f.write_text(value + first + "\n")
            with patch("build8_targets.KEEP_LIST",f):
                with self.assertRaisesRegex(RuntimeError,"19 unique"):
                    build8_targets()

    def test_all_miravision_jni_protected_while_printspooler_removed(self):
        with TemporaryDirectory() as td:
            root=Path(td)
            entries={}
            paths=list(MIRAVISION_JNI)+list(APPROVED_PINNED_NATIVE)
            for p in paths:
                target=root/p.lstrip("/")
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(b"retained-original")
                entries[p]={"kind":"file","bytes":target.stat().st_size}
            deleted="system_a:/system/app/MiuiPrintSpooler/MiuiPrintSpooler.apk"
            targets={deleted:("system_a",PurePosixPath("/system/app/MiuiPrintSpooler/MiuiPrintSpooler.apk"))}
            package_ids={deleted:"com.android.printspooler"}
            with patch("build8_cleanup.sha",return_value=APPROVED_PINNED_NATIVE[paths[-1]][0]):
                selected, audit=find_cleanup(root,"system_a",targets,package_ids,entries,"/bin/false")
            self.assertEqual(selected,["/system/lib64/libprintspooler_jni.so"])
            self.assertFalse(set(selected)&set(MIRAVISION_JNI))
            self.assertEqual(audit["standalone_entries_selected"],1)

    def test_printspooler_hash_mismatch_stops_build(self):
        with TemporaryDirectory() as td:
            root=Path(td)
            p="/system/lib64/libprintspooler_jni.so"
            target=root/p.lstrip("/")
            target.parent.mkdir(parents=True)
            target.write_bytes(b"wrong-stock-binary")
            removed="system_a:/system/app/MiuiPrintSpooler/MiuiPrintSpooler.apk"
            with self.assertRaisesRegex(RuntimeError,"SHA256 mismatch"):
                find_cleanup(root,"system_a",
                    {removed:("system_a",PurePosixPath("/system/app/MiuiPrintSpooler/MiuiPrintSpooler.apk"))},
                    {removed:"com.android.printspooler"},
                    {p:{"kind":"file","bytes":target.stat().st_size}},"/bin/false")
