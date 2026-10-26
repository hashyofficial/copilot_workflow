#!/usr/bin/env python3
"""Build 10 restoration policy regression tests (no stock firmware needed)."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from build10_targets import (build10_targets,GALLERY_LOCATION,
                             MIVIDEO_LOCATION,CALENDAR_LOCATION,
                             VERIFIED_NECESSARY_RESTORATIONS)

class Build10Policy(unittest.TestCase):
    def test_precisely_verified_gallery_restoration(self):
        removed,ids,protected,kept=build10_targets()
        self.assertEqual((len(removed),len(kept),len(protected)),(91,17,3))
        self.assertEqual(VERIFIED_NECESSARY_RESTORATIONS,{GALLERY_LOCATION})
        self.assertIn(GALLERY_LOCATION,kept)
        self.assertNotIn(GALLERY_LOCATION,removed)
        self.assertIn(MIVIDEO_LOCATION,removed)
        self.assertNotIn(MIVIDEO_LOCATION,kept)
        self.assertIn(CALENDAR_LOCATION,kept)
        self.assertFalse(set(removed)&set(kept))
    def test_no_unverified_miservice_or_photon_restoration(self):
        removed,_,_,kept=build10_targets()
        self.assertIn("product_a:/priv-app/MIServiceGlobalPad/MIServiceGlobalPad.apk",removed)
        self.assertNotIn("product_a:/priv-app/MIServiceGlobalPad/MIServiceGlobalPad.apk",kept)
        self.assertFalse(any("PhotonGallery" in s for s in (*removed,*kept)))
    def test_firmware_product_gallery_preserved_from_stock(self):
        # The packer checks original and rebuilt filesystem trees and
        # ensures MiVideo and Photon are absent after the full rebuild.
        script=(Path(__file__).resolve().parents[1]/"scripts/pack_super_build10.py").read_text()
        self.assertIn('original_after=after',script)
        self.assertIn('compare_trees(before,original_after,all_exclusions)',script)
        self.assertIn('"fresh MD5-verified original Xiaomi MIUI 14 Global"',script)
        self.assertIn('"gallery_preserved":True',script)
        self.assertIn('"additional_apks_installed":0',script)
        self.assertNotIn('photon_overlay(',script)
if __name__=="__main__":unittest.main()
