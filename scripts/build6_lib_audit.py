#!/usr/bin/env python3
"""Read-only audit of removable-app library leftovers in the pristine yunluo EROFS images.

Avoid filename-only deletion. Emits evidence for review; does not modify partitions.
"""
import collections
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from inventory import MD5, TOOLS, sha
from combined_preflight import extract_archive, SUPER_RAW_SIZE, apk_identity
from erofs_trial import SOURCE_SUPER_SHA256, mount_readonly, run_checked, find_aapt
from build5_gallery_targets import targets_from_build4

PARTS=("product_a","system_a","system_ext_a")
SUFFIXES=(".so",".odex",".vdex",".art",".jar",".xml",".rc")
IGNORED={"miui","android","google","system","global","service","platform","vendor",
         "shared","library","lib","app","pad","main","framework","core","provider",
         "mediatek","device","overlay","support","feature","product","privapp"}
def norm(s):return re.sub(r"[^a-z0-9]","",s.lower())
def significant(s):
    s=norm(s)
    return len(s)>=7 and s not in IGNORED

def name_aliases(app):
    folder=Path(app["source_apk"]).parent.name
    stem=Path(app["source_apk"]).stem
    pkg=app["package_id"]
    out={}
    for value,kind in [(folder,"whole_folder"),(stem,"apk_stem"),(pkg,"package_id"),
                       (pkg.rsplit(".",1)[-1],"package_suffix")]:
        if significant(value):out[norm(value)]=kind
    for token in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z]|$)",folder.replace("_"," ")):
        if significant(token):out.setdefault(norm(token),"folder_token")
    return out

def score_candidate(filename,aliases):
    base=filename
    low=base.lower()
    for ext in SUFFIXES:
        if low.endswith(ext):
            base=base[:-len(ext)];break
    key=norm(base)
    prefix=key[3:] if key.startswith("lib") else key
    result=[]
    for app in aliases:
        for alias,typ in app["aliases"].items():
            if prefix==alias or key==alias:
                confidence="exact_name"
            elif len(alias)>=9 and (alias in prefix or alias in key):
                confidence="distinct_long_name"
            elif typ=="folder_token" and len(alias)>=7 and (alias in key):
                confidence="ambiguous_token"
            else:continue
            result.append({"apk":app["source_apk"],"package":app["package_id"],"match":alias,
                           "basis":typ,"strength":confidence})
    return result

def main():
    archive=Path(os.environ["BUILD6_STOCK_ARCHIVE"])
    report=Path(os.environ.get("BUILD6_AUDIT_REPORT","reports-build6-audit"))
    report.mkdir(parents=True,exist_ok=True)
    if not archive.is_file() or sha(archive,"md5")!=MD5:
        raise RuntimeError("Xiaomi firmware missing or incorrect MD5")
    targets,expected,protected,new=targets_from_build4()
    records={"source_rom_md5":MD5,"source_super_sha256":SOURCE_SUPER_SHA256,
             "removed_complete_folders":len(targets),"additional_apks":0,
             "rule":"Audit only. No library removed based on matching filename alone.",
             "removed_apks":[],"matched_outside_folders":[],"all_shared_libs":[],
             "packages_protected":protected,"potential_leftover_categories":{}}
    with tempfile.TemporaryDirectory(prefix="yunluo-build6-audit-") as tmpdir:
        t=Path(tmpdir)
        sparse,_=extract_archive(archive,t)
        raw=t/"super.raw.img"
        with sparse.open("rb") as f: is_sparse=f.read(4)==bytes.fromhex("3aff26ed")
        if is_sparse:
            run_checked(TOOLS/"simg2img",sparse,raw)
            sparse.unlink()
        else: sparse.rename(raw)
        if raw.stat().st_size!=SUPER_RAW_SIZE or sha(raw)!=SOURCE_SUPER_SHA256:
            raise RuntimeError("Source super image failed expected SHA256")
        aapt=find_aapt()
        for part in PARTS:
            dest=t/("unpack-"+part)
            dest.mkdir()
            run_checked(TOOLS/"lpunpack","--slot=0","--partition="+part,raw,dest)
            img=dest/(part+".img")
            mounted=t/("mnt-"+part)
            mount_readonly(img,mounted)
            try:
                removed=[]
                appdata=[]
                for loc,(p,apk) in targets.items():
                    if p!=part:continue
                    a=mounted/str(apk).lstrip("/")
                    folder=a.parent
                    if not a.is_file() or not folder.is_dir():
                        raise RuntimeError("Removed APK or folder absent in original stock: "+loc)
                    observed,_=apk_identity(aapt,a)
                    if loc in expected and observed!=expected[loc]:
                        raise RuntimeError("Original package identity mismatch: "+loc)
                    so_inside=[]
                    all_entries=0
                    for item in folder.rglob("*"):
                        all_entries+=1
                        if item.is_file() and item.name.lower().endswith(".so"):
                            so_inside.append("/"+str(item.relative_to(mounted)))
                    app={"source_apk":str(apk),"location":loc,"package_id":observed,
                         "folder":str(apk.parent),"entries_within_folder":all_entries,
                         "libraries_in_removed_folder":so_inside}
                    records["removed_apks"].append(app)
                    appdata.append({**app,"aliases":name_aliases(app)})
                    removed.append(str(apk.parent))
                def inside_removed(rel):
                    return any(rel==a or rel.startswith(a+"/") for a in removed)
                candidates=[]
                libcount=0
                for root,dirs,files in os.walk(mounted,followlinks=False):
                    here=Path(root)
                    relative="/"+str(here.relative_to(mounted)) if here!=mounted else "/"
                    dirs[:]=[d for d in dirs if not inside_removed((relative.rstrip("/")+"/"+d))]
                    for filename in files:
                        if not filename.lower().endswith(SUFFIXES):continue
                        item=here/filename
                        rel="/"+str(item.relative_to(mounted))
                        if inside_removed(rel) or item.is_symlink() or not item.is_file():continue
                        typ=item.suffix.lower()
                        if typ==".so":libcount+=1
                        matches=score_candidate(filename,appdata)
                        if not matches:continue
                        entry={"partition":part,"path":rel,"bytes":item.stat().st_size,
                               "kind":typ,"matches":matches}
                        candidates.append(entry)
                print(part,"removed app folders",len(appdata),"candidate leftover files",len(candidates),
                      "retained .so files",libcount,flush=True)
                records["matched_outside_folders"].extend(candidates)
                records["all_shared_libs"].append({"partition":part,"retained_shared_libs":libcount})
            finally:
                subprocess.run(["umount",str(mounted)],check=True)
            subprocess.run(["rm","-rf",str(dest)],check=True)
    if len(records["removed_apks"])!=108:
        raise RuntimeError("Original 108 source APKs not audited")
    counter=collections.Counter(x["kind"] for x in records["matched_outside_folders"])
    records["potential_leftover_categories"]=dict(counter)
    (report/"LIBRARY_CANDIDATES.json").write_text(json.dumps(records,indent=2,sort_keys=True)+"\n")
    lines=["# Build 6 leftover-library audit (READ ONLY)","",
           "Device: Xiaomi Redmi Pad (yunluo), MIUI 14 Android 13",
           "All 108 deleted whole app folders confirmed in pristine source ROM.",
           "Libraries within those whole folders are already removed by Build 5.",
           "These paths are matches only. Filename matching does not prove exclusive ownership.",
           "Do not delete unreviewed shared .so files or native libraries used by system services.",
           "", "## Possible leftover paths", ""]
    for x in records["matched_outside_folders"]:
        owners=sorted({m["package"] for m in x["matches"]})
        lines.append("- "+x["partition"]+":"+x["path"]+" ["+x["kind"]+"; "+str(x["bytes"])+" bytes] matched "+", ".join(owners))
    if not records["matched_outside_folders"]:
        lines.append("None with matching filenames found outside removed app folders.")
    (report/"LIBRARY_CANDIDATES.md").write_text("\n".join(lines)+"\n")
    print("Audit completed. Candidate files:",len(records["matched_outside_folders"]),flush=True)

if __name__=="__main__":
    main()
