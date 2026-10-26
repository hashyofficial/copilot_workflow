#!/usr/bin/env python3
"""Build 7: fresh original Xiaomi firmware, 108 complete APK folders removed; no apps added.

Preserve Xiaomi's LP metadata and every non-target partition. Reuse the
previously validated EROFS exclusion process. No bootloader or flash actions.
"""
import hashlib
import os
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile

from inventory import ROOT, NAME, MD5, TOOLS, sha, command, fstype
from build7_targets import build7_targets, MIRAVISION_JNI
from build7_cleanup import find_cleanup
from combined_preflight import extract_archive, SUPER_RAW_SIZE, apk_identity
from erofs_trial import (SOURCE_SUPER_SHA256, proposed, exclusions,
                         check_folders, tree_map, compare_trees,
                         mkfs_report, mount_readonly, read_uuid,
                         run_checked, find_aapt)

RESULTS = Path(os.environ.get("BUILD7_REPORTS",str(ROOT/"reports-build7")))
BINARIES = Path(os.environ.get("BUILD7_PRIVATE",str(ROOT/"private-build7-parts")))
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

def build2_targets():
    """Stage 1's 24 targets + 42 verified dedicated-app-folder requests."""
    stage1,_=proposed()
    allow=ROOT/"config/build2-additional-42.tsv"
    new={}
    expected_packages={}
    counts={key:0 for key in REGIONS}
    for line in allow.read_text(encoding="utf8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        columns=line.split("\t")
        if len(columns)!=2:
            raise RuntimeError("Malformed Build 2 allowlist entry")
        pkg,location=columns
        if not pkg or ":" not in location or any(c.isspace() for c in pkg):
            raise RuntimeError("Invalid Build 2 package mapping")
        partition,path=location.split(":",1)
        pp=PurePosixPath(path)
        if partition not in REGIONS or not pp.is_absolute() or ".." in pp.parts or pp.suffix.lower()!=".apk":
            raise RuntimeError("Build 2 contains invalid partition or source APK location")
        if pp.parent in (PurePosixPath("/"),PurePosixPath("/app"),PurePosixPath("/priv-app"),
                         PurePosixPath("/system/app"),PurePosixPath("/system/priv-app"),
                         PurePosixPath("/overlay"),PurePosixPath("/data-app")):
            raise RuntimeError("Refusing whole-folder removal in shared directory")
        if location in stage1 or location in new:
            raise RuntimeError("Duplicate Build 2 target")
        new[location]=(partition,pp)
        expected_packages[location]=pkg
        counts[partition]+=1
    if len(new)!=42 or counts!={"product_a":22,"system_a":19,"system_ext_a":1}:
        raise RuntimeError("Unexpected Build 2 additional app counts "+str(counts))
    result={**stage1,**new}
    if len(result)!=66:
        raise RuntimeError("Expected exactly 66 unique directory exclusions")
    folder_keys=[(p,path.parent) for p,path in result.values()]
    if len(set(folder_keys))!=len(folder_keys):
        raise RuntimeError("Two APKs share a deleted folder")
    for p,a in folder_keys:
        for q,b in folder_keys:
            if p==q and a!=b and a in b.parents:
                raise RuntimeError("Refusing nested directory exclusions")
    return result,expected_packages

def build3_targets():
    """Extend 66 prior dedicated folders with 27 additional exact stock APK directories.

    The three explicitly retained packages are asserted in the rebuilt images.
    Overlay APKs, runtime APEX APKs and userdata-only APKs are NOT altered.
    """
    prior,expected_packages=build2_targets()
    additional={}
    counts={part:0 for part in REGIONS}
    allow=ROOT/"config/build3-additional-27.tsv"
    protected={
        "system_a:/system/priv-app/LPPeService/LPPeService.apk":"com.mediatek.location.lppe.main",
        "system_a:/system/priv-app/StatementService/StatementService.apk":"com.android.statementservice",
        "system_ext_a:/priv-app/Provision/Provision.apk":"com.android.provision"
    }
    for line in allow.read_text(encoding="utf8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols=line.split("\t")
        if len(cols)!=2:
            raise RuntimeError("Bad Build 3 allowlist line")
        pkg,location=cols
        if ":" not in location or not pkg or any(c.isspace() for c in pkg):
            raise RuntimeError("Malformed package/path mapping")
        part,path=location.split(":",1)
        pp=PurePosixPath(path)
        if part not in REGIONS or not pp.is_absolute() or ".." in pp.parts or pp.suffix.lower()!=".apk":
            raise RuntimeError("Bad source path in Build 3 mapping")
        if pp.parent in (PurePosixPath("/"),PurePosixPath("/app"),PurePosixPath("/priv-app"),
                         PurePosixPath("/system/app"),PurePosixPath("/system/priv-app"),
                         PurePosixPath("/overlay"),PurePosixPath("/data-app")):
            raise RuntimeError("A requested APK has no safely separable parent folder")
        if location in prior or location in additional or location in protected:
            raise RuntimeError("Overlapping Build 3 or protected path")
        counts[part]+=1
        additional[location]=(part,pp)
        expected_packages[location]=pkg
    if len(additional)!=27 or counts!={"product_a":3,"system_a":22,"system_ext_a":2}:
        raise RuntimeError("Build 3 manifest count mismatch: "+str(counts))
    result={**prior,**additional}
    if len(result)!=93:
        raise RuntimeError("Expected 93 dedicated app directories")
    roots=[(part,path.parent) for part,path in result.values()]
    if len(set(roots))!=93:
        raise RuntimeError("Shared folder in Build 3 target list")
    for i,(p,a) in enumerate(roots):
        for q,b in roots[i+1:]:
            if p==q and (a in b.parents or b in a.parents):
                raise RuntimeError("Nested Build 3 deletion request")
    return result,expected_packages,protected


BUILD4_NEW_LABELS = {
    "product_a:/app/MiLinkGlobal/MiLinkGlobal.apk": "Cast",
    "product_a:/priv-app/MIUICloudBackupGlobal/MIUICloudBackupGlobal.apk": "Cloud backup",
    "system_ext_a:/priv-app/FindDevice/FindDevice.apk": "Find Device",
    "product_a:/app/MIUIFrequentPhrase/MIUIFrequentPhrase.apk": "Frequent phrases",
    "product_a:/priv-app/MIShareGlobal/MIShareGlobal.apk": "Mi Share",
    "product_a:/app/MIUIMiCloudSync/MIUIMiCloudSync.apk": "MiCloudSync",
    "system_a:/system/app/MiuiAudioMonitor/MiuiAudioMonitor.apk": "Recording assistant",
    "product_a:/priv-app/MIServiceGlobalPad/MIServiceGlobalPad.apk": "Service & Feedback",
    "system_a:/system/priv-app/Stk1/Stk1.apk": "Sim Toolkit",
    "system_a:/system/priv-app/ManagedProvisioning/ManagedProvisioning.apk": "Work setup",
    "product_a:/app/MIUIXiaomiAccountGlobal/MIUIXiaomiAccountGlobal.apk": "Xiaomi Account",
    "product_a:/app/MIUICloudServiceGlobal/MIUICloudServiceGlobal.apk": "Xiaomi Cloud",
    "product_a:/app/MIUIDeskClockPadGlobal/MIUIDeskClockPadGlobal.apk": "Clock",
    "product_a:/app/MIUIVideoPlayer/MIUIVideoPlayer.apk": "Mi Video",
}

def build4_targets():
    """93 exact dedicated app folders inherited from Builds 1-3, plus 14 new folders.

    Cell Broadcast Service APEX is excluded from this allowlist and not modified.
    All source app identities are read from the freshly downloaded original ROM.
    """
    prior,expected_packages,protected=build3_targets()
    config=ROOT/"config/build4-additional-14.txt"
    new={}
    per_partition={part:0 for part in REGIONS}
    for line in config.read_text(encoding="utf8").splitlines():
        loc=line.strip()
        if not loc or loc.startswith("#"):
            continue
        if loc not in BUILD4_NEW_LABELS:
            raise RuntimeError("Unreviewed Build 4 stock APK location: "+loc)
        if ":" not in loc:
            raise RuntimeError("Missing Build 4 partition")
        part,path=loc.split(":",1)
        p=PurePosixPath(path)
        if part not in REGIONS or not p.is_absolute() or ".." in p.parts or p.suffix.lower()!=".apk":
            raise RuntimeError("Invalid Build 4 source path: "+loc)
        if p.parent in (PurePosixPath("/"),PurePosixPath("/app"),
                        PurePosixPath("/priv-app"),PurePosixPath("/system/app"),
                        PurePosixPath("/system/priv-app"),PurePosixPath("/overlay"),
                        PurePosixPath("/data-app")):
            raise RuntimeError("Cannot delete shared parent folder")
        if "cellbroadcast" in loc.lower() or loc in protected or loc in prior or loc in new:
            raise RuntimeError("Duplicate, protected, or excluded Build 4 target")
        new[loc]=(part,p)
        per_partition[part]+=1
    if len(new)!=14 or set(new)!=set(BUILD4_NEW_LABELS):
        raise RuntimeError("Build 4 must contain all 14 additional APK locations exactly once")
    if per_partition!={"product_a":10,"system_a":3,"system_ext_a":1}:
        raise RuntimeError("Build 4 new partition count mismatch "+str(per_partition))
    targets={**prior,**new}
    if len(targets)!=107:
        raise RuntimeError("Expected 107 target directories from Builds 1-4")
    folders=[(part,p.parent) for part,p in targets.values()]
    if len(set(folders))!=107:
        raise RuntimeError("Duplicated whole directory")
    for i,(part,path) in enumerate(folders):
        for other_part,other_path in folders[i+1:]:
            if part==other_part and (path in other_path.parents or other_path in path.parents):
                raise RuntimeError("Nested folder deletion is not allowed")
    for loc in protected:
        if loc in targets:
            raise RuntimeError("User's protected package included in Build 4")
    return targets,expected_packages,protected,new


def build():
    trial,expected_packages,protected,kept=build7_targets()
    print("Build 7: fresh original Xiaomi firmware; 91 full-folder removals and 17 explicitly protected stock apps; no APK installed",flush=True)
    with tempfile.TemporaryDirectory(prefix="yunluo-build7-fresh-firmware-") as td:
        temp=Path(td)
        external_archive=os.environ.get("BUILD7_STOCK_ARCHIVE")
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
        for name,(sector,count) in REGIONS.items():
            print("Build 7: rebuilding "+name+" from original EROFS",flush=True)
            src=unpack(original,name,temp/("orig-"+name))
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
                        raise RuntimeError("Build 7 required preserved APK missing: " + location)
                    observed, _ = apk_identity(aapt, preserved_apk)
                    retained_identities[location] = observed
                report("build7-kept-identities-"+name+".json",
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
                extra_exclusions, cleanup=find_cleanup(mount,name,trial,package_ids,before,aapt)
                cleanup_reports.append(cleanup)
                report('build7-leftovers-'+name+'.json',json.dumps(cleanup,indent=2)+'\n')
                all_exclusions=[path for _,path in excluded]+extra_exclusions
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
                diff=compare_trees(before,after,all_exclusions)
                if not diff["passed"]:raise RuntimeError("Retained files changed in "+name)
                if any('/'+p.lstrip('/') in after for p in extra_exclusions):
                    raise RuntimeError('Build 7 selected leftover survived EROFS repack: '+name)
                for location,(partition,original_apk) in kept.items():
                    if partition != name: continue
                    target="/" + str(original_apk).lstrip("/")
                    if target not in before or target not in after:
                        raise RuntimeError("Build 7 restored APK not preserved: " + location)
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
        if sum(x["directories_removed"] for x in rows)!=91:
            raise RuntimeError("Build 7 did not remove exactly 91 dedicated app folders")
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
        manifest={"slot":"a","model":"yunluo","build":"7-experimental",
                  "source":"fresh Xiaomi MIUI 14 stock ROM, not any Build 5 or Build 7 image",
                  "original_firmware_md5":MD5,
                  "build7_previous_app_folder_removals":108,
                  "build7_restored_app_folders":len(kept),
                  "build7_kept_locations":sorted(kept),
                  "build7_kept_folders":sorted([p.parent.name for _,p in kept.values()]),
                  "total_directories_removed":91,
                  "build7_extra_files_removed":sum(x["standalone_entries_selected"] for x in cleanup_reports),
                  "build7_extra_bytes_removed":sum(x["bytes_selected"] for x in cleanup_reports),
                  "build7_cleanup_by_partition":cleanup_reports,
                  "build7_cleanup_rule":"Only pinned printspooler JNI and proven app-specific XML/overlays; all MiraVision JNI kept",
                  "build7_miravision_jni_preserved":list(MIRAVISION_JNI),
                  "additional_apks_installed":0,
                  "gallery_preserved":True,
                  "cell_broadcast_service_apex_modified":False,
                  "protected_packages":protected,
                  "overlays_removed":sum(1 for x in cleanup_reports for item in x["selected"] if item["kind"]=="overlay"),
                  "apex_runtime_packages_removed":0,
                  "userdata_apps_removed":0,
                  "excluded_folders":sorted([{"location":loc,"folder":str(path.parent)} for loc,(p,path) in trial.items()],
                                           key=lambda item:item["location"]),
                  "modified_partitions":rows,
                  "original_super_sha256":SOURCE_SUPER_SHA256,
                  "modified_super_sha256":sha(candidate),
                  "sparse_sha256":sha(sparse_out),
                  "parts":parts,
                  "lp_metadata_preserved":True,
                  "other_regions_unchanged":True,
                  "avb_compatible_with_stock_vbmeta":False,
                  "flash_tested":False}
        text=json.dumps(manifest,indent=2)+"\n"
        report("manifest.json",text)
        (BINARIES/"manifest.json").write_text(text)
        report('build7-cleanup-summary.json',json.dumps(cleanup_reports,indent=2)+'\n')
        report("result.txt","Offline Build 7: 91 whole app folders excluded; 17 stock apps and MiraVision JNI retained, plus strictly matched standalone leftovers; no added APK, no standalone super artifact.\n"+
               "A separate installed APK in userdata is not deleted by rebuilding super.img.\n"+
               "No vbmeta image has been modified. Stock AVB is incompatible.\n")
        print("Build 7 verified super assembled privately for complete ROM ZIP; never uploaded separately.",flush=True)

if __name__=="__main__":
    build()
