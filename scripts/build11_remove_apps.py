#!/usr/bin/env python3
"""Build 11 offline HyperOS debloat, using ONLY user-approved TXT selectors.

Rebuild verified original EROFS app folders (not APK-only), preserving surviving
files/ownership/SELinux metadata. Reuse Build 10 tree comparison and AVB auditing,
but NEVER its hardcoded MIUI partition offsets, inventory, hashes or target list.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile

from inventory import TOOLS, sha, fstype
from combined_preflight import find_aapt
from erofs_trial import tree_map, compare_trees, read_uuid
from vbmeta_audit import audit_one
from build11_source import download_archive, verify_archive, MD5, VERSION, FILENAME
from build11_apk_inventory import extract_super, raw_super, layout, identity, run, device_path

CHUNK = 768 * 1024 * 1024
# Protect core tablet operation until a dependency audit proves a safe alternative.
PROTECTED_IDS = {
    "com.android.settings", "com.android.systemui", "com.android.permissioncontroller",
    "com.google.android.gms", "com.android.vending",
    "com.miui.securitycenter", "com.android.providers.settings",
    "com.android.providers.media", "com.android.providers.downloads",
    "com.android.documentsui", "com.google.android.documentsui",
    "com.android.bluetooth", "com.android.camera", "com.mediatek.camera",
    "com.android.provision", "com.android.statementservice",
    "com.mediatek.location.lppe.main",
}
SHARED = {"/","/app","/priv-app","/system/app","/system/priv-app",
          "/overlay","/system/overlay","/etc","/lib","/lib64",
          "/system","/product","/system_ext","/vendor","/odm"}

def parse_user_txt(path):
    if not path.exists():
        raise RuntimeError("Missing user-provided Build 11 remove TXT")
    items=[]
    for line in path.read_text(encoding="utf8").splitlines():
        line=line.strip()
        if line and not line.startswith("#"):
            if line in items: raise RuntimeError("Duplicate TXT selector: "+line)
            if any(c.isspace() for c in line):
                raise RuntimeError("Use exact package IDs or partition:/path.apk only: "+line)
            items.append(line)
    if not items:
        raise RuntimeError("No user-approved apps yet. Refusing to modify stock HyperOS.")
    return items

def read_stock_vbmeta(archive, output):
    found=False
    with tarfile.open(archive,mode="r|gz") as tf:
        for member in tf:
            p=PurePosixPath(member.name)
            if p.is_absolute() or ".." in p.parts or member.issym() or member.islnk() or member.isdev():
                raise RuntimeError("Unsafe source archive path")
            if member.isfile() and p.parent.name=="images" and p.name=="vbmeta.img":
                if found: raise RuntimeError("More than one stock vbmeta")
                output.write_bytes(tf.extractfile(member).read())
                found=True
    if not found:
        raise RuntimeError("Stock HyperOS vbmeta.img not found")

def patch_vbmeta(stock, dest):
    binary=stock.read_bytes()
    original=audit_one("vbmeta.img",binary)
    if len(binary)!=8192 or binary[:4]!=b"AVB0" or original["flags"]!=0:
        raise RuntimeError("Unexpected stock HyperOS vbmeta structure/flags")
    if original["algorithm"]!="SHA256_RSA2048":
        raise RuntimeError("Unexpected stock HyperOS AVB algorithm")
    altered=bytearray(binary)
    struct.pack_into(">I",altered,120,3)
    altered=bytes(altered)
    changed=audit_one("vbmeta.img",altered)
    if changed["flags"]!=3 or original["descriptors"]!=changed["descriptors"]:
        raise RuntimeError("AVB flags-only patch validation failed")
    if sum(a!=b for a,b in zip(binary,altered))!=1:
        raise RuntimeError("AVB flags-only patch changed unapproved bytes")
    dest.write_bytes(altered)
    return {"stock_sha256":sha(stock),"patched_sha256":sha(dest),
            "stock_flags":original["flags"],"modified_flags":changed["flags"]}

def partition_extent(dump, partition):
    if "Partition table:" not in dump:
        raise RuntimeError("lpdump is missing its partition table")
    table=dump.split("Partition table:",1)[1].split("Block device table:",1)[0]
    blocks=table.split("------------------------")
    for block in blocks:
        name=re.search(r"(?m)^\s*Name:\s*([A-Za-z0-9_.-]+)\s*$",block)
        if not name or name.group(1)!=partition:
            continue
        rows=re.findall(r"(?m)^\s*(\d+)\s*\.\.\s*(\d+):\s*linear\s+super\s+(\d+)\s*$",block)
        # Refuse to guess at multi-extents or new lpdump formats.
        if len(rows)!=1:
            raise RuntimeError("Cannot safely replace non-single-extent LP: "+partition)
        first,last,sector=map(int,rows[0])
        if first!=0 or last<first:
            raise RuntimeError("Unexpected LP logical sector mapping: "+partition)
        return sector*512,(last-first+1)*512
    raise RuntimeError("No usable extent for "+partition)

def mount_ro(img,path):
    path.mkdir(exist_ok=True)
    fs=fstype(img)
    if fs not in ("erofs","ext4"):
        raise RuntimeError("Unsupported source partition FS "+fs)
    opts="ro,loop" if fs=="erofs" else "ro,loop,noload"
    run("mount","-t",fs,"-o",opts,img,path)
    return fs

def original_index(raw, parts, root, aapt):
    """Full exact-package-to-location map from original image, before ANY selection."""
    by_loc={}; by_pkg={}
    for slot,part in parts:
        directory=root/("scan-"+part)
        directory.mkdir()
        mounted=root/("scanmnt-"+part)
        mounted.mkdir()
        try:
            run(TOOLS/"lpunpack","--slot="+str(slot),"--partition="+part,raw,directory)
            img=directory/(part+".img")
            if not img.exists():raise RuntimeError("Missing partition image: "+part)
            mount_ro(img,mounted)
            try:
                for base,_,names in os.walk(mounted,followlinks=False):
                    for filename in names:
                        if not filename.lower().endswith(".apk"):continue
                        src=Path(base)/filename
                        if not src.is_file() or src.is_symlink():continue
                        rel="/"+str(src.relative_to(mounted))
                        loc=part+":"+rel
                        pkg,label=identity(aapt,src)
                        by_loc[loc]={"package_id":pkg,"label":label,
                                     "folder":part+":"+str(PurePosixPath(rel).parent)}
                        by_pkg.setdefault(pkg,[]).append(loc)
            finally:
                subprocess.run(["umount",str(mounted)],check=True)
        finally:
            shutil.rmtree(directory,ignore_errors=True)
            mounted.rmdir()
    if not by_loc: raise RuntimeError("Empty original-stock package map")
    return by_loc,by_pkg

def resolve(selectors,by_loc,by_pkg):
    selected={}
    for selector in selectors:
        if selector in by_loc:
            matched=[selector]
        elif selector in by_pkg:
            matched=by_pkg[selector]
        else:
            raise RuntimeError("Unknown user TXT package or APK location: "+selector)
        for loc in matched:
            if loc in selected:
                continue
            part,path=loc.split(":",1)
            pure=PurePosixPath(path)
            if not pure.is_absolute() or ".." in pure.parts or pure.suffix.lower()!=".apk":
                raise RuntimeError("Malformed stock APK location: "+loc)
            folder=pure.parent
            if str(folder) in SHARED or len(folder.parts)<3:
                raise RuntimeError("Cannot delete an APK's SHARED parent directory: "+loc)
            if "/app/" not in path and "/priv-app/" not in path:
                raise RuntimeError("Manual audit needed: APK outside a dedicated app folder: "+loc)
            pkg=by_loc[loc]["package_id"]
            if pkg in PROTECTED_IDS:
                raise RuntimeError("Protected core system package selected: "+pkg)
            selected[loc]={"partition":part,"folder":str(folder),"package_id":pkg}
    folders={}
    for loc,item in selected.items():
        key=(item["partition"],item["folder"])
        folders.setdefault(key,set()).add(item["package_id"])
    for (part,folder),packages in folders.items():
        if len(packages)!=1:
            raise RuntimeError("Selected folder contains multiple selected package IDs: "+part+":"+folder)
        # Never delete additional unselected Android packages in a shared folder.
        extra={v["package_id"] for k,v in by_loc.items()
               if k.startswith(part+":"+folder+"/") and v["package_id"] not in packages}
        if extra:
            raise RuntimeError("Folder contains other packages; refusing deletion: "+part+":"+folder+" "+str(extra))
    by_part={}
    for part,folder in folders:
        by_part.setdefault(part,set()).add(folder)
    return selected,{k:sorted(v) for k,v in by_part.items()}

def digest_span(path,offset,count):
    h=hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        while count:
            block=stream.read(min(count,8*1024*1024))
            if not block: raise RuntimeError("Truncated original super")
            h.update(block);count-=len(block)
    return h.hexdigest()

def replace_extent(image,offset,capacity,rebuilt):
    size=rebuilt.stat().st_size
    if size>capacity or size%4096:
        raise RuntimeError("Rebuilt EROFS does not fit its original LP physical extent")
    with image.open("r+b") as target, rebuilt.open("rb") as source:
        target.seek(offset)
        shutil.copyfileobj(source,target,8*1024*1024)
        remaining=capacity-size
        zero=bytes(8*1024*1024)
        while remaining:
            amount=min(remaining,len(zero))
            target.write(zero[:amount]);remaining-=amount

def build(args):
    selectors=parse_user_txt(args.remove_txt)
    args.report.mkdir(parents=True,exist_ok=True)
    args.work.mkdir(parents=True,exist_ok=True)
    args.out.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yunluo-hyperos-build11-",dir=args.work) as td:
        root=Path(td)
        archive=args.work/FILENAME
        download_archive(archive,args.report/"download.json")
        stock_vbmeta=root/"vbmeta-stock.img"
        read_stock_vbmeta(archive,stock_vbmeta)
        sparse=root/"super.sparse.img"
        extract_super(archive,sparse)
        archive.unlink()
        raw=root/"super-original.img"
        raw_super(sparse,raw)
        raw_sha=sha(raw)
        partitions=layout(raw,args.report)
        original_dumps=[run(TOOLS/"lpdump","-s",slot,raw) for slot in (0,1)]
        aapt=find_aapt()
        by_loc,by_pkg=original_index(raw,partitions,root,aapt)
        selected,by_part=resolve(selectors,by_loc,by_pkg)
        (args.report/"approved-removals.json").write_text(json.dumps(selected,indent=2)+"\n")
        if not by_part:
            raise RuntimeError("No matching app directories: refusing modification")
        candidate=root/"super-candidate.raw.img"
        subprocess.run(["cp","--reflink=auto","--sparse=always",str(raw),str(candidate)],check=True)
        modified_extents=[]
        rebuilt_info=[]
        slot_map={name:slot for slot,name in partitions}
        for part in sorted(by_part):
            if part not in slot_map:
                raise RuntimeError("Selected partition absent: "+part)
            slot=slot_map[part]
            if slot!=0:
                raise RuntimeError("Unexpected non-primary logical metadata slot: "+part)
            offset,capacity=partition_extent(original_dumps[slot],part)
            work=root/("image-"+part)
            work.mkdir()
            run(TOOLS/"lpunpack","--slot="+str(slot),"--partition="+part,raw,work)
            original_img=work/(part+".img")
            if original_img.stat().st_size!=capacity:
                raise RuntimeError("Original LP partition capacity mismatch: "+part)
            if fstype(original_img)!="erofs":
                raise RuntimeError("Only EROFS partition debloat supported; refusing "+part)
            run("fsck.erofs",original_img)
            uuid,_=read_uuid(original_img)
            mount=root/("mount-"+part)
            mount_ro(original_img,mount)
            try:
                before=tree_map(mount)
                timestamps={info["mtime_ns"] for info in before.values()}
                if len(timestamps)!=1:
                    raise RuntimeError("Original EROFS timestamps vary; unsafe to use -T for "+part)
                timestamp=timestamps.pop()
                if timestamp%1_000_000_000:
                    raise RuntimeError("Original EROFS subsecond timestamps unsupported: "+part)
                excluded=by_part[part]
                for folder in excluded:
                    target=mount/folder.lstrip("/")
                    if target.is_symlink() or not target.is_dir():
                        raise RuntimeError("Selected original app folder missing: "+part+":"+folder)
                rebuilt=root/(part+"-rebuilt.erofs")
                cmd=["mkfs.erofs","-z","lz4hc,9","-T",str(timestamp//1_000_000_000),"-U",uuid]
                cmd.extend("--exclude-path="+p.lstrip("/") for p in excluded)
                run(*cmd,rebuilt,mount)
                run("fsck.erofs",rebuilt)
            finally:
                subprocess.run(["umount",str(mount)],check=True)
            replace_extent(candidate,offset,capacity,rebuilt)
            checkdir=root/("check-"+part)
            checkdir.mkdir()
            run(TOOLS/"lpunpack","--slot=0","--partition="+part,candidate,checkdir)
            verified=checkdir/(part+".img")
            run("fsck.erofs",verified)
            vmnt=root/("verify-"+part)
            mount_ro(verified,vmnt)
            try:
                after=tree_map(vmnt)
                audit=compare_trees(before,after,excluded)
                if not audit["passed"]:
                    (args.report/("FAILED-compare-"+part+".json")).write_text(json.dumps(audit,indent=2)+"\n")
                    raise RuntimeError("Surviving original files/SELinux/ownership differ in "+part)
            finally:
                subprocess.run(["umount",str(vmnt)],check=True)
            modified_extents.append((offset,offset+capacity))
            rebuilt_info.append({"partition":part,"removed_app_folders":excluded,
                                 "original_partition_bytes":capacity,
                                 "rebuilt_fs_bytes":rebuilt.stat().st_size,
                                 "survivor_entries_verified":audit["expected_retained"]})
        for slot,dump in enumerate(original_dumps):
            if run(TOOLS/"lpdump","-s",slot,candidate)!=dump:
                raise RuntimeError("Original LP metadata changed unexpectedly")
        cursor=0
        for start,end in sorted(modified_extents)+[(raw.stat().st_size,raw.stat().st_size)]:
            if cursor<start and digest_span(raw,cursor,start-cursor)!=digest_span(candidate,cursor,start-cursor):
                raise RuntimeError("Untargeted super.img regions changed")
            if start<cursor:
                raise RuntimeError("Overlapping modified LP extents")
            cursor=end
        sparse_new=root/"super-build11.sparse.img"
        run(TOOLS/"img2simg",candidate,sparse_new)
        roundtrip=root/"super-build11-roundtrip.img"
        run(TOOLS/"simg2img",sparse_new,roundtrip)
        if sha(roundtrip)!=sha(candidate) or roundtrip.stat().st_size!=raw.stat().st_size:
            raise RuntimeError("Sparse-to-raw round-trip checksum mismatch")
        meta=patch_vbmeta(stock_vbmeta,args.out/"vbmeta.img")
        pieces=[]
        with sparse_new.open("rb") as source:
            i=0
            while True:
                data=source.read(CHUNK)
                if not data:break
                name=f"super.sparse.img.part-{i:03d}"
                path=args.out/name
                path.write_bytes(data)
                pieces.append({"file":name,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
                i+=1
        manifest={"device":"yunluo","os":"HyperOS "+VERSION,
                  "base_source_md5":MD5,"source_super_raw_sha256":raw_sha,
                  "modified_super_raw_sha256":sha(candidate),
                  "modified_super_sparse_sha256":sha(sparse_new),
                  "selected_android_apk_locations":selected,
                  "partitions":rebuilt_info,"pieces":pieces,"vbmeta":meta,
                  "lp_metadata_identical":True,"untouched_regions_identical":True,
                  "surviving_metadata_identical":True,"flash_tested":False,
                  "full_fastboot_firmware_zip":False}
        text=json.dumps(manifest,indent=2)+"\n"
        (args.out/"manifest.json").write_text(text)
        (args.report/"manifest.json").write_text(text)
        (args.out/"PARTS_SHA256.txt").write_text(
            "".join(p["sha256"]+"  "+p["file"]+"\n" for p in pieces))
        print("Offline verified Build 11 super.img + vbmeta.img parts; NOT yet device-tested",flush=True)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--remove-txt",type=Path,required=True)
    p.add_argument("--work",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    build(p.parse_args())

if __name__=="__main__":
    main()
