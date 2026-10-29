#!/usr/bin/env python3
"""Build 12: exactly 31 Google/diagnostic/additional app folders removed from original Xiaomi MIUI.

Preserve Xiaomi's LP metadata and every non-target partition. Reuse the
previously validated EROFS exclusion process. Haptic Java framework untouched: no vibration hardware.
"""
import hashlib
import os
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile

from inventory import ROOT, NAME, MD5, TOOLS, sha, command, fstype
from build12_google_mtk_extra5_targets import (build12_targets, MIRAVISION_JNI, GOOGLE, DIAGNOSTIC, ADDITIONAL)
from combined_preflight import extract_archive, SUPER_RAW_SIZE, apk_identity
from erofs_trial import (SOURCE_SUPER_SHA256, exclusions,
                         check_folders, tree_map, compare_trees,
                         mkfs_report, mount_readonly, read_uuid,
                         run_checked, find_aapt)

RESULTS = Path(os.environ.get("BUILD12_REPORTS",str(ROOT/"reports-build12")))
BINARIES = Path(os.environ.get("BUILD12_PRIVATE",str(ROOT/"private-build12-parts")))
RESULTS.mkdir(exist_ok=True)
# Offset and number of 512-byte sectors, taken from the signed-off source LP audit.
REGIONS = {"product_a": (4096,5590248), "system_a": (5595136,1804456), "system_ext_a": (7587840,919248)}
CHUNK = 768 * 1024 * 1024

def report(name,text):
    (RESULTS/name).write_text(text, encoding="utf8")

def digest_span(file,offset,length):
    h=hashlib.sha256()
    with file.open("rb") as stream:
        stream.seek(offset)
        while length:
            data=stream.read(min(length,8*1024*1024))
            if not data: raise RuntimeError("Truncated super image")
            length-=len(data)
            h.update(data)
    return h.hexdigest()

def unpack(raw,partition,directory):
    directory.mkdir()
    run_checked(TOOLS/"lpunpack","--slot=0","--partition="+partition,raw,directory)
    image=directory/(partition+".img")
    if fstype(image)!="erofs": raise RuntimeError(partition+" is not EROFS")
    return image

def replace_region(raw,offset,capacity,newimage):
    length=newimage.stat().st_size
    if length>capacity or length%4096:
        raise RuntimeError("EROFS does not fit allocated extent")
    with raw.open("r+b") as target,newimage.open("rb") as original:
        target.seek(offset)
        shutil.copyfileobj(original,target,8*1024*1024)
        blank=b"\0"*(8*1024*1024)
        left=capacity-length
        while left:
            n=min(left,len(blank))
            target.write(blank[:n])
            left-=n

def build():
    trial,expected_packages,protected,kept=build12_targets()
    print("Build 12: 20 Google plus 6 diagnostic plus 5 specifically requested folders removed from fresh Xiaomi stock; all other stock files kept",flush=True)
    with tempfile.TemporaryDirectory(prefix="yunluo-build12-fresh-firmware-") as td:
        temp=Path(td)
        external_archive=os.environ.get("BUILD12_STOCK_ARCHIVE")
        archive=Path(external_archive) if external_archive else temp/NAME
        if not archive.is_file():
            subprocess.run(["python3",str(ROOT/"scripts/download.py"),
                            "--output",str(archive),
                            "--report",str(RESULTS/"download.json")],check=True)
        if sha(archive,"md5")!=MD5: raise RuntimeError("ROM MD5 mismatch")
        sparse,vbmeta=extract_archive(archive,temp)
        if not external_archive:archive.unlink()
        original=temp/"original.raw.img"
        with sparse.open("rb") as stream: is_sparse=stream.read(4)==bytes.fromhex("3aff26ed")
        if is_sparse:
            run_checked(TOOLS/"simg2img",sparse,original)
            sparse.unlink()
        else: sparse.rename(original)
        if original.stat().st_size!=SUPER_RAW_SIZE or sha(original)!=SOURCE_SUPER_SHA256:
            raise RuntimeError("Original super SHA256 mismatch")
        source_layout=[run_checked(TOOLS/"lpdump","-s",n,original).stdout for n in (0,1)]
        for name,(sector,count) in REGIONS.items():
            if "Name: "+name not in source_layout[0] or "linear super "+str(sector) not in source_layout[0]:
                raise RuntimeError("Unrecognized source extent "+name)
        candidate=temp/"candidate.raw.img"
        subprocess.run(["cp","--reflink=auto","--sparse=always",str(original),str(candidate)],check=True)
        aapt=find_aapt();rows=[]
        cleanup_reports=[]
        package_ids=dict(expected_packages)
        # Exactly 26 allowlisted folders, no extra discovery or generic debloat.
        exact_packages={}
        extras={}
        if len(trial)!=31 or set(trial)!=(set(GOOGLE)|set(DIAGNOSTIC)|set(ADDITIONAL)):
            raise RuntimeError("Build 12 must remove precisely the approved 31 apps")
        report("build12-removal-plan.json",json.dumps(sorted(trial),indent=2)+"\n")
        for name,(sector,count) in REGIONS.items():
            print("Build 12: rebuilding "+name+" from original EROFS",flush=True)
            src=unpack(original,name,temp/("scan-"+name))
            if not src.is_file(): raise RuntimeError("Missing verified original source partition "+name)
            if src.stat().st_size!=count*512:raise RuntimeError("Original LP extent mismatch")
            run_checked("fsck.erofs",src)
            uuid,_=read_uuid(src)
            mount=temp/("mount-"+name)
            mount_readonly(src,mount)
            try:
                excluded=exclusions(name,trial)
                files=check_folders(mount,name,excluded,aapt)
                package_ids.update({item['location']:item['android_package_id'] for item in files})
                retained_identities={}
                for location,(partition,original_apk) in kept.items():
                    if partition != name: continue
                    preserved_apk = mount / str(original_apk).lstrip("/")
                    if not preserved_apk.is_file() or preserved_apk.is_symlink():
                        raise RuntimeError("Build 12 required preserved APK missing: " + location)
                    observed, _ = apk_identity(aapt, preserved_apk)
                    retained_identities[location] = observed
                report("build12-kept-identities-"+name+".json",
                       json.dumps(retained_identities,sort_keys=True,indent=2)+"\n")
                for location,package in expected_packages.items():
                    if location.startswith(name+":"):
                        apk=mount/location.split(":",1)[1].lstrip("/")
                        observed,_=apk_identity(aapt,apk)
                        if observed!=package:
                            raise RuntimeError("Fresh firmware APK identity mismatch for "+
                                               location+": expected "+package+" observed "+observed)
                before=tree_map(mount)
                for location,pkg in protected.items():
                    if location.startswith(name+":"):
                        protected_apk=mount/location.split(":",1)[1].lstrip("/")
                        if not protected_apk.is_file():
                            raise RuntimeError("Required protected original app is missing: "+location)
                        observed,_=apk_identity(aapt,protected_apk)
                        if observed!=pkg:
                            raise RuntimeError("Protected original APK identity mismatch: "+location)
                # No additional native library, XML, or overlay removal.
                extra_exclusions=[]
                cleanup={"partition":name,"standalone_entries_selected":0,
                         "bytes_selected":0,"selected":[]}
                cleanup_reports.append(cleanup)
                all_exclusions=[path for _,path in excluded]
                rebuilt=temp/(name+"-rebuilt.erofs")
                mkfs_report(rebuilt,mount,all_exclusions,uuid)
                run_checked("fsck.erofs",rebuilt)
            finally:
                subprocess.run(["umount",str(mount)],check=True)
            replace_region(candidate,sector*512,count*512,rebuilt)
            out=unpack(candidate,name,temp/("check-"+name))
            run_checked("fsck.erofs",out)
            verified_mount=temp/("verified-"+name)
            mount_readonly(out,verified_mount)
            try:
                after=tree_map(verified_mount)
                original_after=after
                if name=="product_a":
                    gallery="/priv-app/Gallery_T_Global/Gallery_T_Global.apk"
                    video="/app/MIUIVideoPlayer/MIUIVideoPlayer.apk"
                    photon="/app/PhotonGallery/PhotonGallery.apk"
                    if gallery not in after or video not in after or photon in after:
                        raise RuntimeError("Build 12 Gallery/MiVideo/Photon EROFS contents incorrect")
                diff=compare_trees(before,original_after,all_exclusions)
                if not diff["passed"]:raise RuntimeError("Retained files changed in "+name)
                if any('/'+p.lstrip('/') in after for p in extra_exclusions):
                    raise RuntimeError('Build 12 selected leftover survived EROFS repack: '+name)
                for location,(partition,original_apk) in kept.items():
                    if partition != name: continue
                    target="/" + str(original_apk).lstrip("/")
                    if target not in before or target not in after:
                        raise RuntimeError("Build 12 restored APK not preserved: " + location)
                if name == "system_a":
                    for jni in MIRAVISION_JNI:
                        if jni not in before or jni not in after:
                            raise RuntimeError("Required MiraVision JNI library missing: " + jni)
                for location in protected:
                    if location.startswith(name+":"):
                        target="/"+location.split(":",1)[1].lstrip("/")
                        if target not in before or target not in after:
                            raise RuntimeError("Protected package missing after Build 3 rebuild")
                rows.append({"partition":name,"directories_removed":len(files),
                             "retained_paths_matched":diff["expected_retained"],
                             "reconstructed_erofs_bytes":rebuilt.stat().st_size,
                             "standalone_leftovers_removed":len(extra_exclusions)})
            finally:
                subprocess.run(["umount",str(verified_mount)],check=True)
        for slot in (0,1):
            if run_checked(TOOLS/"lpdump","-s",slot,candidate).stdout!=source_layout[slot]:
                raise RuntimeError("LP metadata was modified")
        intervals=sorted((sector*512,(sector+count)*512) for sector,count in REGIONS.values())
        cursor=0
        for start,end in intervals+[(SUPER_RAW_SIZE,SUPER_RAW_SIZE)]:
            if cursor<start and digest_span(original,cursor,start-cursor)!=digest_span(candidate,cursor,start-cursor):
                raise RuntimeError("Unexpected modifications outside target partitions")
            cursor=end
        if sum(x["directories_removed"] for x in rows)!=31:
            raise RuntimeError("Build 12 requires exactly 31 folder removals")
        sparse_out=temp/"candidate.sparse.img"
        run_checked(TOOLS/"img2simg",candidate,sparse_out)
        check=temp/"roundtrip.raw.img"
        run_checked(TOOLS/"simg2img",sparse_out,check)
        if check.stat().st_size!=SUPER_RAW_SIZE or sha(check)!=sha(candidate):
            raise RuntimeError("Sparse image round-trip failed")
        BINARIES.mkdir(exist_ok=True)
        parts=[]
        with sparse_out.open("rb") as stream:
            i=0
            while True:
                data=stream.read(CHUNK)
                if not data: break
                name=f"super.sparse.img.part-{i:03d}"
                (BINARIES/name).write_bytes(data)
                parts.append({"file":name,"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)})
                i+=1
        manifest={"slot":"a","model":"yunluo","build":"12-fresh-google-mtk-extra5",
                  "source":"fresh MD5-verified original Xiaomi MIUI 14 Global",
                  "original_firmware_md5":MD5,
                  "build12_original_candidates":31,"build12_original_kept":len(kept),
                  "build12_kept_locations":sorted(kept),
                  "build12_kept_folders":sorted([ap.parent.name for _,ap in kept.values()]),
                  "build12_extra_packages":exact_packages,
                  "build12_extra_locations":sorted(extras),
                  "total_directories_removed":31,
                  "build12_extra_files_removed":sum(x["standalone_entries_selected"] for x in cleanup_reports),
                  "build12_extra_bytes_removed":sum(x["bytes_selected"] for x in cleanup_reports),
                  "build12_cleanup_by_partition":cleanup_reports,
                  "build12_miravision_jni_preserved":list(MIRAVISION_JNI),
                  "additional_apks_installed":0,
                  "gallery_preserved":True,"calendar_restored":True,
                  "cell_broadcast_service_apex_modified":False,
                  "protected_packages":protected,
                  "overlays_removed":sum(1 for x in cleanup_reports for item in x["selected"] if item["kind"]=="overlay"),
                  "apex_runtime_packages_removed":0,"userdata_apps_removed":0,
                  "excluded_folders":sorted([{"location":loc,"folder":str(path.parent)} for loc,(part,path) in trial.items()],key=lambda x:x["location"]),
                  "modified_partitions":rows,
                  "original_super_sha256":SOURCE_SUPER_SHA256,
                  "modified_super_sha256":sha(candidate),"sparse_sha256":sha(sparse_out),
                  "parts":parts,"lp_metadata_preserved":True,"other_regions_unchanged":True,
                  "avb_compatible_with_stock_vbmeta":False,"flash_tested":False,
                  "haptic_framework_untouched":True}
        text=json.dumps(manifest,indent=2)+"\n"
        report("manifest.json",text)
        (BINARIES/"manifest.json").write_text(text)
        report('build12-cleanup-summary.json',json.dumps(cleanup_reports,indent=2)+'\n')
        report("result.txt","Offline Build 12: exactly 20 Google + 6 diagnostic + 5 additional stock app folders removed; Gallery and MiVideo preserved; no injected APKs.\n"+
               "No individual native libraries, XML files, or overlays removed.\n"+
               "The complete firmware repacker will patch original vbmeta and CRC lists.\n")
        print("Build 12 verified super assembled privately for complete ROM ZIP; never uploaded separately.",flush=True)

if __name__=="__main__":
    build()
