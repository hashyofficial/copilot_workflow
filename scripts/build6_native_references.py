#!/usr/bin/env python3
"""Build6: classify seven app-specific .so candidates using surviving-file references.

No modifications. Dynamically used shared libraries can evade this analysis; all results
are subject to conservative manual review before any removal is approved.
"""
import hashlib,json,os,re,subprocess,tempfile,zipfile
from pathlib import Path
from inventory import MD5,TOOLS,sha
from combined_preflight import extract_archive,SUPER_RAW_SIZE
from erofs_trial import SOURCE_SUPER_SHA256,mount_readonly,run_checked
from build5_gallery_targets import targets_from_build4

PARTS=("product_a","system_a","system_ext_a")
TRACK={
"libMiraVision_jni.so":"com.mediatek.miravision.ui",
"libmonitortrack.so":"com.miui.audiomonitor",
"libprintspooler_jni.so":"com.android.printspooler",
"libhidcommand_jni.so":"com.mediatek.voicecommand",
"libuinputcommand_jni.so":"com.mediatek.voicecommand"
}
PATTERNS={k:{k.lower().encode(),k[3:-3].lower().encode()} for k in TRACK}
REPORT_EXT={".so",".apk",".jar",".odex",".vdex",".art",".rc",".xml",".bin",".dex",".oat",".apex"}
CHUNK=2*1024*1024
def search_bytes(reader,needles):
    tail=b""
    while data:=reader.read(CHUNK):
        blob=(tail+data).lower()
        hits=[name for name,patterns in needles.items() if any(pattern in blob for pattern in patterns)]
        if hits:
            return hits
        tail=blob[-128:]
    return []

def candidate_key(p):
    base=p.name.lower()
    for key in TRACK:
        if base==key.lower():return key
    return None

def should_scan(file):
    if file.suffix.lower() in REPORT_EXT:return True
    return any(x in file.parts for x in ("bin","xbin","etc","framework"))

def main():
    archive=Path(os.environ["BUILD6_STOCK_ARCHIVE"])
    report=Path(os.environ.get("BUILD6_DEP_REPORT","reports-build6-dependency"))
    report.mkdir(parents=True,exist_ok=True)
    if sha(archive,"md5")!=MD5:raise RuntimeError("Incorrect Xiaomi source ROM")
    removed,_,_,_=targets_from_build4()
    data={"source_rom_md5":MD5,"source_super_sha256":SOURCE_SUPER_SHA256,
          "method":"Literal library basename/stem search through retained files and ZIP entries; negative result is not proof of no runtime dlopen.",
          "candidates":[],"references":{k:[] for k in TRACK},
          "unscanned":[],"total_scanned_files":0,"total_scanned_zip_entries":0}
    with tempfile.TemporaryDirectory(prefix="yunluo-build6-refaudit-") as temp:
        temp=Path(temp)
        sparse,_=extract_archive(archive,temp)
        raw=temp/"raw.img"
        with sparse.open("rb") as f: is_sparse=f.read(4)==bytes.fromhex("3aff26ed")
        if is_sparse:
            run_checked(TOOLS/"simg2img",sparse,raw)
            sparse.unlink()
        else:sparse.rename(raw)
        if raw.stat().st_size!=SUPER_RAW_SIZE or sha(raw)!=SOURCE_SUPER_SHA256:
            raise RuntimeError("Unexpected source super image")
        for part in PARTS:
            path=temp/("part-"+part);path.mkdir()
            run_checked(TOOLS/"lpunpack","--slot=0","--partition="+part,raw,path)
            mnt=temp/("mnt-"+part)
            mount_readonly(path/(part+".img"),mnt)
            omitted=[str(apk.parent) for loc,(p,apk) in removed.items() if p==part]
            def excluded(s):
                return any(s==a or s.startswith(a+"/") for a in omitted)
            try:
                for root,dirs,files in os.walk(mnt,followlinks=False):
                    folder=Path(root)
                    rel="/"+str(folder.relative_to(mnt)) if folder!=mnt else "/"
                    dirs[:]=[d for d in dirs if not excluded(rel.rstrip("/")+"/"+d)]
                    for basename in files:
                        f=folder/basename
                        relative="/"+str(f.relative_to(mnt))
                        if excluded(relative) or f.is_symlink() or not f.is_file():continue
                        lib=candidate_key(f)
                        if lib:
                            data["candidates"].append({"partition":part,"path":relative,"lib":lib,
                                                       "app_removed":TRACK[lib],
                                                       "bytes":f.stat().st_size,"sha256":sha(f)})
                            continue
                        if not should_scan(f):continue
                        if f.stat().st_size>300*1024*1024:
                            data["unscanned"].append({"partition":part,"path":relative,"reason":"too large"})
                            continue
                        try:
                            with f.open("rb") as stream:hits=search_bytes(stream,PATTERNS)
                            data["total_scanned_files"]+=1
                            for k in hits:data["references"][k].append({"partition":part,"path":relative,"source":"raw-bytes"})
                            if f.suffix.lower() in (".apk",".jar",".apex"):
                                with zipfile.ZipFile(f) as z:
                                    for member in z.infolist():
                                        if member.is_dir() or member.file_size>300*1024*1024:continue
                                        try:
                                            with z.open(member) as stream:zhits=search_bytes(stream,PATTERNS)
                                            data["total_scanned_zip_entries"]+=1
                                            for k in zhits:
                                                data["references"][k].append({"partition":part,"path":relative,
                                                                              "entry":member.filename,"source":"decompressed-zip-entry"})
                                        except (RuntimeError,ValueError,EOFError,OSError):
                                            data["unscanned"].append({"partition":part,"path":relative,
                                                                      "entry":member.filename,"reason":"failed to read zip entry"})
                        except (OSError,ValueError,EOFError,zipfile.BadZipFile,RuntimeError) as ex:
                            data["unscanned"].append({"partition":part,"path":relative,"error":str(ex)[:300]})
                print("Scanned",part,"total processed files",data["total_scanned_files"],
                      "candidates",len(data["candidates"]),flush=True)
            finally:
                subprocess.run(["umount",str(mnt)],check=True)
            subprocess.run(["rm","-rf",str(path)],check=True)
    if not data["candidates"]:raise RuntimeError("No source candidates found")
    (report/"CANDIDATE_REFERENCES.json").write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
    summary=["# Build 6 JNI library reference evidence","",
             "Negative string search cannot prove an app-specific native library has no hidden runtime consumer.",
             "Any match from retained firmware is a reason to avoid automatic removal.",""]
    for obj in data["candidates"]:
        refs=data["references"][obj["lib"]]
        summary.append("- "+obj["partition"]+":"+obj["path"]+" SHA256 "+obj["sha256"]+" retained refs="+str(len(refs)))
        for ref in refs[:12]:
            summary.append("    - "+ref["partition"]+":"+ref["path"]+" "+ref.get("entry",""))
    summary.append("Unscanned retained files/entries: "+str(len(data["unscanned"])))
    (report/"REFERENCE_SUMMARY.md").write_text("\n".join(summary)+"\n")
    print("Dependency search complete. Candidate libraries:",len(data["candidates"]),
          "unscanned:",len(data["unscanned"]),flush=True)

if __name__=="__main__":main()
