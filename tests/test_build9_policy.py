#!/usr/bin/env python3
"""Build 9 policy regression tests (no firmware download)."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from build9_targets import (build9_targets, REMOVE_FROM_KEEP, RESTORE_CALENDAR,
                            EXTRA_PACKAGE_IDS, PHOTON_PACKAGE, PHOTON_PATH,
                            PHOTON_SHA256, MIRAVISION_JNI)
class Build9PolicyTests(unittest.TestCase):
    def test_precise_changes(self):
        removed, ids, protected, kept=build9_targets()
        self.assertEqual(len(removed),92)
        self.assertEqual(len(kept),16)
        self.assertEqual(len(protected),3)
        self.assertTrue(REMOVE_FROM_KEEP.issubset(removed))
        self.assertIn(RESTORE_CALENDAR,kept)
        self.assertNotIn(RESTORE_CALENDAR,removed)
        self.assertEqual(set(ids)-set(removed),set())
        for name in ("Backup","UserDictionaryProvider","ContactsProvider","MiraVision"):
            self.assertIn(name,{p.parent.name for _,p in kept.values()})
        self.assertEqual(len(MIRAVISION_JNI),2)
    def test_only_signed_photon_and_exact_other_packages(self):
        self.assertEqual(EXTRA_PACKAGE_IDS,{"com.google.android.apps.restore",
                                            "com.wdstechnology.android.kryten"})
        self.assertEqual(PHOTON_PACKAGE,"com.inferno.gallery")
        self.assertEqual(PHOTON_PATH,"/app/PhotonGallery/PhotonGallery.apk")
        self.assertEqual(len(PHOTON_SHA256),64)
if __name__=="__main__":
    unittest.main()
