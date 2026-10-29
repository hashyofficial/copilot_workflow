#!/usr/bin/env python3
"""Build 12 removal-policy regression tests: 31 explicitly approved stock apps."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from build12_google_mtk_extra5_targets import (
    build12_targets,GOOGLE,DIAGNOSTIC,ADDITIONAL,KNOWN_PACKAGE_IDS,PRESERVE_APPS
)
class Build12Policy(unittest.TestCase):
    def test_exact_app_folder_set(self):
        removed,ids,protected,kept=build12_targets()
        self.assertEqual((len(GOOGLE),len(DIAGNOSTIC),len(ADDITIONAL)),(20,6,5))
        self.assertEqual(len(removed),31)
        self.assertEqual(set(removed),set(GOOGLE)|set(DIAGNOSTIC)|set(ADDITIONAL))
        self.assertEqual(ids,KNOWN_PACKAGE_IDS)
        self.assertEqual(protected,PRESERVE_APPS)
        self.assertEqual(kept,{})
    def test_new_packages_and_typo_fixed(self):
        _,ids,_,_=build12_targets()
        self.assertEqual({ids[x] for x in ADDITIONAL},{
            "com.mediatek.voicecommand","com.android.apps.tag","com.xiaomi.payment",
            "com.android.bookmarkprovider","com.android.bluetoothmidiservice"})
        self.assertNotIn("com.android.bookmakerprovider",ids.values())
    def test_stock_gallery_mivideo_security_preserved(self):
        removed,_,protected,_=build12_targets()
        for folder in ("Gallery_T_Global","MIUIVideoPlayer","MIUISecurityCenterGlobalPad","CalendarGoogle"):
            self.assertTrue(any(folder in x for x in protected))
            self.assertFalse(any(folder in x for x in removed))
    def test_packer_keeps_unrelated_files(self):
        base=Path(__file__).resolve().parents[1]/"scripts"
        src=(base/"pack_super_build12_google_mtk_extra5.py").read_text()
        self.assertNotIn("find_cleanup(",src)
        self.assertNotIn("discover_extra_packages(",src)
        self.assertIn('"standalone_entries_selected":0',src)
        self.assertIn("compare_trees(before,original_after,all_exclusions)",src)
        self.assertIn('if gallery not in after or video not in after or photon in after:',src)
        self.assertIn('"total_directories_removed":31',src)
        self.assertIn('"additional_apks_installed":0',src)
if __name__=="__main__":unittest.main()
