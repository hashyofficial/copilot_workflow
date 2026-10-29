#!/usr/bin/env python3
"""Build 11 exact-only 26 app removal and preservation policy tests."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from build11_google_mtk_targets import (
    build11_targets, GOOGLE, DIAGNOSTIC, KNOWN_PACKAGE_IDS, PRESERVE_APPS,
)
class Build11GoogleMtkTests(unittest.TestCase):
    def test_exact_26(self):
        removed, ids, protected, kept = build11_targets()
        self.assertEqual(len(GOOGLE),20)
        self.assertEqual(len(DIAGNOSTIC),6)
        self.assertEqual(len(removed),26)
        self.assertEqual(set(removed),set(GOOGLE)|set(DIAGNOSTIC))
        self.assertEqual(ids,KNOWN_PACKAGE_IDS)
        self.assertEqual(protected,PRESERVE_APPS)
        self.assertEqual(kept,{})
    def test_both_miui_media_apps_and_core_preserved(self):
        removed, _, protected, _ = build11_targets()
        for path in ("Gallery_T_Global","MIUIVideoPlayer","MIUISecurityCenterGlobalPad","CalendarGoogle"):
            self.assertTrue(any(path in x for x in protected))
            self.assertFalse(any(path in x for x in removed))
        self.assertTrue(any("/Velvet/" in x for x in removed))
        self.assertTrue(any("/SpeechServicesByGoogle/" in x for x in removed))
        self.assertTrue(any("/talkback/" in x for x in removed))
        self.assertFalse(any("PhotonGallery" in x for x in removed))
    def test_packer_excludes_no_extra_files(self):
        src=(Path(__file__).resolve().parents[1]/"scripts/pack_super_build11_google_mtk.py").read_text()
        self.assertNotIn("find_cleanup(",src)
        self.assertNotIn("discover_extra_packages(",src)
        self.assertIn('"standalone_entries_selected":0',src)
        self.assertIn("compare_trees(before,original_after,all_exclusions)",src)
        self.assertIn('if gallery not in after or video not in after or photon in after:',src)
        self.assertIn('"total_directories_removed":26',src)
        self.assertIn('"additional_apks_installed":0',src)
if __name__=="__main__": unittest.main()
