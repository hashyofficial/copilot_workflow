#!/usr/bin/env python3
"""Build 11 READ-ONLY inventory of EVERY physically present APK in stock super.img.

No MIUI-era removal lists or hardcoded partition offsets. Active logical partitions
are discovered from lpdump; APK Android IDs and labels are read with aapt2.
Original firmware and partitions are NEVER changed by this script.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

from inventory import TOOLS, sha, fstype
from combined_preflight import find_aapt
from build11_source import download_archive, verify_archive, FILENAME, VERSION, MD5

SPARSE_MAGIC = bytes.fromhex("3aff26ed")

def run(*args):
    p = subprocess.run([str(x) for x in args], text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError("Command failed: " + " ".join(map(str,args)) +
                           "\n" + (p.stderr or p.stdout)[-1600:])
    return p.stdout

def extract_super(archive, destination):
    """Stream validated vendor tarball; save only images/super.img, never extract blindly."""
    verify_archive(archive)
    found = False
    with tarfile.open(archive, mode="r|gz") as stream:
        for member in stream:
            p = PurePosixPath(member.name)
            if p.is_absolute() or ".." in p.parts or member.issym() or member.islnk() or member.isdev():
                raise RuntimeError("Unsafe Xiaomi archive member: " + member.name)
            if member.isfile() and p.name == "super.img" and p.parent.name == "images":
                if found:
                    raise RuntimeError("Duplicate original super.img in firmware")
                with stream.extractfile(member) as src, destination.open("wb") as dst:
                    shutil.copyfileobj(src, dst, 8*1024*1024)
                found = True
    if not found or not destination.stat().st_size:
        raise RuntimeError("Original Xiaomi fastboot archive lacks super.img")
    return destination

def raw_super(sparse, raw):
    with sparse.open("rb") as handle:
        is_sparse = handle.read(4) == SPARSE_MAGIC
    if is_sparse:
        run(TOOLS/"simg2img", sparse, raw)
        sparse.unlink()
    else:
        sparse.rename(raw)
    if raw.stat().st_size < 1_000_000_000:
        raise RuntimeError("Unexpectedly tiny raw super image")
    return is_sparse

def layout(raw, report):
    seen = set()
    partitions = []
    for slot in (0, 1):
        try:
            output = run(TOOLS/"lpdump", "-s", slot, raw)
        except RuntimeError as exc:
            (report / ("lpdump-slot"+str(slot)+".txt")).write_text(str(exc)+"\n")
            continue
        (report / ("lpdump-slot"+str(slot)+".txt")).write_text(output)
        table = output.split("Partition table:",1)[-1].split("Block device table:",1)[0]
        for block in table.split("------------------------"):
            match = re.search(r"(?m)^\s*Name:\s*([A-Za-z0-9_.-]+)\s*$",block)
            if not match:
                continue
            if not re.search(r"(?m)^\s*\d+\s*\.\.\s*\d+\s+(linear|zero)\b",block):
                continue
            name = match.group(1)
            if name not in seen:
                seen.add(name)
                partitions.append((slot,name))
    if not partitions:
        raise RuntimeError("No populated dynamic partitions discovered")
    return partitions

def device_path(part, internal):
    p = re.sub(r"_[ab]$","",part)
    if p == "system" and internal.startswith("/system/"):
        return internal
    if p == "system" and internal == "/system":
        return internal
    return "/" + p + internal

def identity(aapt, path):
    p = subprocess.run([aapt, "dump", "badging", str(path)],
                       capture_output=True, text=True, timeout=90)
    if p.returncode:
        raise RuntimeError("aapt badging failed: "+(p.stderr or p.stdout)[-400:])
    txt = p.stdout
    package = re.search(r"(?m)^package:\s+name='([^']+)'",txt)
    if not package:
        raise RuntimeError("APK has no parsable Android package ID")
    label = re.search(r"(?m)^application-label:\s*'([^']*)'",txt)
    if not label:
        label = re.search(r"(?m)^application-label-en:\s*'([^']*)'",txt)
    if not label:
        label = re.search(r"(?m)^application:\s+label='([^']*)'",txt)
    return package.group(1), (label.group(1) if label else "(label not exported)")

def inventory(archive, work, report):
    work.mkdir(parents=True,exist_ok=True)
    report.mkdir(parents=True,exist_ok=True)
    archive = Path(archive)
    if not archive.exists():
        download_archive(archive, report/"download-sources.json")
    verify_archive(archive)
    sparse = work/"super.sparse.img"
    raw = work/"super.raw.img"
    extract_super(archive, sparse)
    # Preserve only the checksum-verified ROM's super for read-only inspection.
    archive.unlink()
    was_sparse = raw_super(sparse, raw)
    original_sha = sha(raw)
    partitions = layout(raw, report)
    aapt = find_aapt()
    rows,apex_rows,fs_rows,errors = [],[],[],[]
    for slot,part in partitions:
        extracted = work/("unpack-"+part)
        extracted.mkdir(exist_ok=True)
        image = extracted/(part+".img")
        mount = work/("mount-"+part)
        mount.mkdir(exist_ok=True)
        mounted = False
        try:
            run(TOOLS/"lpunpack", "--slot="+str(slot), "--partition="+part, raw, extracted)
            if not image.is_file():
                raise RuntimeError("lpunpack did not return expected image")
            fs = fstype(image)
            fs_rows.append([part,slot,fs,image.stat().st_size])
            if fs not in ("erofs","ext4"):
                raise RuntimeError("Unsupported mounted filesystem "+fs)
            if fs=="erofs":
                run("fsck.erofs",image)
            opts="ro,loop" if fs=="erofs" else "ro,loop,noload"
            run("mount","-t",fs,"-o",opts,image,mount)
            mounted=True
            for directory, _, names in os.walk(mount,followlinks=False):
                for name in names:
                    path=Path(directory)/name
                    if path.is_symlink() or not path.is_file():
                        continue
                    suffix=path.suffix.lower()
                    if suffix not in (".apk",".apex",".capex"):
                        continue
                    internal="/"+str(path.relative_to(mount))
                    full=device_path(part,internal)
                    if suffix in (".apex",".capex"):
                        apex_rows.append([part,part+":"+internal,full,name])
                        continue
                    size=path.stat().st_size
                    if size==0:
                        # HyperOS mi_ext uses zero-byte APK placeholders; NOT installed ZIP/APK packages.
                        pkg,label,status="NO_PACKAGE_ZERO_BYTES","(zero-byte placeholder)","placeholder"
                    else:
                        try:
                            pkg,label=identity(aapt,path)
                            status="valid-apk"
                        except (RuntimeError, subprocess.TimeoutExpired) as e:
                            pkg,label,status="UNPARSED","UNPARSED","invalid-apk"
                            errors.append(part+":"+internal+": "+str(e))
                    rows.append({"partition":part,"android_package_id":pkg,
                                 "app_name":label, "apk_filename":name,
                                 "apk_location":part+":"+internal,
                                 "device_destination":full,
                                 "app_folder":part+":"+str(PurePosixPath(internal).parent),
                                 "size_bytes":size,"parse_status":status,
                                 "split_or_base":"split" if name.startswith("split_") else "APK"})
            print(part,fs,"APKs so far:",len(rows),flush=True)
        except Exception as e:
            errors.append("PARTITION "+part+": "+str(e))
        finally:
            if mounted:
                subprocess.run(["umount",str(mount)],check=True)
            shutil.rmtree(extracted,ignore_errors=True)
            mount.rmdir()
    columns=["app_name","android_package_id","apk_filename","partition",
             "apk_location","device_destination","app_folder","split_or_base","size_bytes","parse_status"]
    rows.sort(key=lambda r:(r["partition"],r["apk_location"]))
    if not rows:
        errors.append("No APKs discovered: image/metadata decoding incorrect")
    with (report/"ALL_APPS_HYPEROS_BUILD11.tsv").open("w",newline="",encoding="utf8") as f:
        w=csv.DictWriter(f,fieldnames=columns,delimiter="\t");w.writeheader();w.writerows(rows)
    with (report/"ALL_APPS_HYPEROS_BUILD11.csv").open("w",newline="",encoding="utf8") as f:
        w=csv.DictWriter(f,fieldnames=columns);w.writeheader();w.writerows(rows)
    (report/"ALL_APPS_HYPEROS_BUILD11.json").write_text(json.dumps(rows,indent=2,ensure_ascii=False)+"\n")
    with (report/"ALL_APPS_HYPEROS_BUILD11.txt").open("w",encoding="utf8") as f:
        f.write("REDMI PAD YUNLUO / HYPEROS "+VERSION+" / GLOBAL\n")
        f.write("EXHAUSTIVE APK inventory from original super.img; NO removals.\n\n")
        for i,row in enumerate(rows,1):
            f.write(f"{i:04}. {row['app_name']}\n")
            f.write(f"     Package : {row['android_package_id']}\n")
            f.write(f"     APK     : {row['apk_filename']}\n")
            f.write(f"     Source  : {row['apk_location']}\n")
            f.write(f"     Device  : {row['device_destination']}\n")
            f.write(f"     Folder  : {row['app_folder']}\n\n")
    with (report/"apex-containers.tsv").open("w",newline="") as f:
        w=csv.writer(f,delimiter="\t");w.writerow(["partition","source","device","filename"])
        w.writerows(sorted(apex_rows))
    with (report/"partitions.tsv").open("w",newline="") as f:
        w=csv.writer(f,delimiter="\t");w.writerow(["partition","metadata_slot","filesystem","bytes"]);w.writerows(fs_rows)
    # TXT file for user to edit LATER; comments only, no apps selected for deletion.
    (report/"REMOVE_APPS_TEMPLATE.txt").write_text(
        "# Build 11 removal requests: paste complete apk_location values, one per line.\n"
        "# Example syntax ONLY (not selected): product_a:/app/SomeApp/SomeApp.apk\n"
        "# This template intentionally deletes NOTHING.\n")
    summary={"firmware":VERSION,"source_file":FILENAME,"stock_archive_md5":MD5,
             "raw_super_sha256":original_sha,"raw_super_size":raw.stat().st_size,
             "was_sparse":was_sparse,"apk_files":len(rows),
             "unique_package_ids":len({r["android_package_id"] for r in rows if r["parse_status"]=="valid-apk"}),
             "nonempty_apk_files":sum(r["parse_status"]=="valid-apk" for r in rows),
             "zero_byte_apk_placeholders":sum(r["parse_status"]=="placeholder" for r in rows),
             "unparsed_nonempty_apks":sum(r["parse_status"]=="invalid-apk" for r in rows),
             "apex_containers":len(apex_rows),
             "partitions":fs_rows,"errors":errors,
             "apex_note":"Runtime APKs packaged INSIDE .apex/.capex files are not regular .apk filesystem paths; see apex-containers.tsv"}
    (report/"SUMMARY.json").write_text(json.dumps(summary,indent=2)+"\n")
    (report/"ERRORS.txt").write_text("\n".join(errors)+"\n" if errors else "None; all mounted APKs parsed.\n")
    print(json.dumps(summary,indent=2),flush=True)
    if errors:
        raise RuntimeError("Inventory incomplete; see ERRORS.txt, never treat partial list as complete")
    return rows

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--archive",type=Path,required=True)
    parser.add_argument("--work",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    inventory(args.archive,args.work,args.report)

if __name__=="__main__":
    main()
