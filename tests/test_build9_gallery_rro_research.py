#!/usr/bin/env python3
"""Unit checks for strict Build 9 Gallery role overlay eligibility policy."""
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"research/build9_fixes"))
from build_gallery_rro import select_target_name,layout,PACKAGE

class GalleryRoleResearch(unittest.TestCase):
    def test_product_overlay_supported(self):
        s='name="FrameworkResources" actor=""\n  policies="product|signature"\n    string/config_systemGallery\n'
        self.assertEqual(select_target_name(s),("FrameworkResources","product|signature"))
    def test_public_overlay_supported(self):
        self.assertEqual(select_target_name('name="Allowed"\n  policies="public"\n    string/config_systemGallery'),("Allowed","public"))
    def test_non_overlayable_refused(self):
        with self.assertRaises(ValueError):
            select_target_name('name="Allowed"\n policies="product"\n string/other')
    def test_signature_only_refused(self):
        with self.assertRaises(ValueError):
            select_target_name('name="Allowed"\n policies="signature"\n string/config_systemGallery')
    def test_vendor_only_refused(self):
        with self.assertRaises(ValueError):
            select_target_name('name="Allowed"\n policies="vendor"\n string/config_systemGallery')
    def test_generated_overlay_does_not_grant_gallery_privileges(self):
        with TemporaryDirectory() as td:
            m,res=layout(Path(td),"Allowed")
            assert PACKAGE in m.read_text()
            assert 'android:targetPackage="android"' in m.read_text()
            assert 'android:isStatic="true"' in m.read_text()
            assert 'config_systemGallery' in (res/"xml/gallery_role_map.xml").read_text()
            assert 'com.inferno.gallery' not in (res/"values/strings.xml").read_text()

if __name__=="__main__":
    unittest.main()
