#!/usr/bin/env python3
"""Fail-closed gallery RRO probe/build. Needs exact original MIUI framework-res.apk.

This is experimental tooling, NOT a tested fastboot image. If Xiaomi's
framework does not allow a product/public overlay of config_systemGallery,
refuse to generate any APK rather than patch or re-sign framework-res.
"""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from xml.etree import ElementTree

PACKAGE="org.hashy.yunluo.galleryroleoverlay"
RESOURCE="string/config_systemGallery"

def select_target_name(raw):
    current_name=current_policy=None
    matches=[]
    for line in raw.splitlines():
        if m:=re.search(r'\bname="([^"]+)"',line):
            current_name=m.group(1);current_policy=None
        elif m:=re.search(r'\bpolicies="([^"]+)"',line):
            current_policy=m.group(1)
        elif line.strip()==RESOURCE and current_name and current_policy:
            if set(current_policy.split('|'))&{"public","product"}:
                matches.append((current_name,current_policy))
            else:
                raise ValueError("Resource is inaccessible to unsigned product overlay: "+current_policy)
    if len(matches)!=1:
        raise ValueError("Stock framework must expose config_systemGallery to product/public overlay; found "+str(len(matches)))
    return matches[0]

def run(*args):
    cmd=subprocess.run(args,text=True,capture_output=True)
    if cmd.returncode:
        raise RuntimeError("Command failed: "+repr(args)+"\n"+cmd.stderr[-1500:])
    return cmd.stdout

def layout(root,target):
    values=root/"res/values";xml=root/"res/xml"
    values.mkdir(parents=True,exist_ok=True);xml.mkdir(parents=True,exist_ok=True)
    manifest=root/"AndroidManifest.xml"
    manifest.write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{PACKAGE}" android:versionCode="1" android:versionName="0.1-experimental">
  <application android:hasCode="false" />
  <overlay android:targetPackage="android" android:targetName="{target}"
           android:isStatic="true" android:priority="990"
           android:resourcesMap="@xml/gallery_role_map" />
</manifest>\n''')
    (values/"strings.xml").write_text('''<?xml version="1.0" encoding="utf-8"?>
<resources><string name="empty_system_gallery" translatable="false"></string></resources>\n''')
    (xml/"gallery_role_map.xml").write_text('''<?xml version="1.0" encoding="utf-8"?>
<overlay xmlns:android="http://schemas.android.com/apk/res/android">
  <item target="string/config_systemGallery" value="@string/empty_system_gallery" />
</overlay>\n''')
    ElementTree.parse(manifest)
    return manifest,root/"res"

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--framework-res",type=Path,required=True,
                   help="Stock Xiaomi framework-res.apk; Android SDK android.jar is NOT sufficient")
    p.add_argument("--aapt2",default="aapt2")
    p.add_argument("--zipalign",default="zipalign")
    p.add_argument("--apksigner",default="apksigner")
    p.add_argument("--keystore",type=Path,required=True)
    p.add_argument("--keystore-alias",default="galleryrole")
    p.add_argument("--keystore-password-file",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    if not a.framework_res.is_file():
        p.error("Original Xiaomi framework-res.apk missing")
    group,policy=select_target_name(run(a.aapt2,"dump","overlayable",str(a.framework_res)))
    a.out.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="galleryrole-") as tmp:
        root=Path(tmp);manifest,res=layout(root,group)
        archive=root/"resources.flata"
        run(a.aapt2,"compile","--dir",str(res),"-o",str(archive))
        raw=root/"raw.apk"
        run(a.aapt2,"link","--no-resource-deduping","--no-resource-removal",
            "-I",str(a.framework_res),"--manifest",str(manifest),
            "-o",str(raw),str(archive))
        aligned=root/"aligned.apk"
        run(a.zipalign,"-f","-p","4",str(raw),str(aligned))
        run(a.apksigner,"sign","--ks",str(a.keystore),"--ks-key-alias",a.keystore_alias,
            "--ks-pass","file:"+str(a.keystore_password_file),
            "--min-sdk-version","30","--out",str(a.out),str(aligned))
        run(a.apksigner,"verify","--verbose",str(a.out))
        if "package: name='"+PACKAGE+"'" not in run(a.aapt2,"dump","badging",str(a.out)):
            raise RuntimeError("Invalid overlay package")
    print(json.dumps({"experimental":True,"device_verified":False,"package":PACKAGE,
        "target":"android","targetName":group,"policy":policy,"resource":RESOURCE,
        "value":"","sha256":hashlib.sha256(a.out.read_bytes()).hexdigest()},indent=2))

if __name__=="__main__":main()
