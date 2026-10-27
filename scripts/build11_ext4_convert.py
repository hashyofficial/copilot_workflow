#!/usr/bin/env python3
"""Build 11 experimental EROFS->ext4 conversion, preserving all stock apps.
Fail closed: no artifact until verified stock boot fstab, LP layout, metadata,
filesystem trees and original vendor/mi_ext bytes are validated offline.
THIS DOES NOT ESTABLISH THAT THE IMAGE BOOTS ON A PHYSICAL TABLET.
"""
import argparse, hashlib, json, os, re, shutil, stat, struct, subprocess, sys
from pathlib import Path
from inventory import TOOLS, fstype, sha
from build11_source import VERSION, MD5
from build11_ext4_preflight import main as stock_preflight
from build11_apk_inventory import run, layout
from erofs_trial import tree_map, compare_trees
from vbmeta_audit import audit_one

TARGETS = ("system_a","system_ext_a","product_a")
ALL_A = ("odm_dlkm_a","product_a","system_a","system_ext_a","vendor_a","vendor_dlkm_a","mi_ext_a")
SUPER_SHA = "965f791ef796d4346b4abf95fad216a90084ed869ef2b6fbae1993d5683c686c"
CHUNK = 700*1024*1024

def call(*argv):
    r=subprocess.run([str(x) for x in argv],text=True,capture_output=True)
    if r.returncode:
        raise RuntimeError("Failed: "+" ".join(map(str,argv))+"\n"+(r.stderr or r.stdout)[-1500:])
    return r.stdout

def source_map(dump):
    table=dump.split("Partition table:",1)[-1].split("Block device table:",1)[0]
    out={}
    for block in table.split("------------------------"):
        match=re.search(r"(?m)^\s*Name:\s*([-\w.]+)$",block)
        if match:
            name=match.group(1)
            spans=re.findall(r"(?m)^\s*(\d+)\s*\.\.\s*(\d+)\s+linear\s+super\s+(\d+)",block)
            if name.endswith("_a") and len(spans)!=1: raise RuntimeError("Unexpected source extent: "+name)
            if name.endswith("_b") and spans:raise RuntimeError("Unexpected populated B slot: "+name)
            out[name]=(int(spans[0][1])+1)*512 if spans else 0
    if set(out)!={x for name in ALL_A for x in (name,name[:-1]+"b")}:
        raise RuntimeError("Unexpected stock partition list, refusing LP rebuild")
    return out

def source_tree_size(mount):
    block_bytes=0; count=0
    for root,dirs,files in os.walk(mount,followlinks=False):
        for name in dirs+files:
            p=Path(root)/name
            info=p.lstat();count+=1
            if stat.S_ISREG(info.st_mode):block_bytes+=((info.st_size+4095)//4096)*4096
    # Conservatively sized ext4: 10% data headroom plus 64MiB / partition.
    # The stock super group cannot fit the first oversized 17% + 256MiB allocation.
    guess=((int(block_bytes*1.10)+count*2048+64*1024*1024+4095)//4096)*4096
    return block_bytes,count,guess

def scrub_root_ext4(root, before):
    """Restore root-directory metadata if mke2fs -d changed it."""
    x=before["/"]; mode=x["mode"]
    os.chown(root,x["uid"],x["gid"])
    os.chmod(root,mode)
    # All source xattrs are expected to have been carried by mke2fs -d.
    # Never synthesize missing SELinux policy labels here.
    os.utime(root,ns=(x["mtime_ns"],x["mtime_ns"]))

def convert_one(raw,part,work,report):
    inp=work/("input-"+part);inp.mkdir(exist_ok=True)
    run(TOOLS/"lpunpack","--slot=0","--partition="+part,raw,inp)
    old=inp/(part+".img")
    if fstype(old)!="erofs":raise RuntimeError("Only stock EROFS supported: "+part)
    call("fsck.erofs",old)
    m=work/("mount-"+part);m.mkdir(exist_ok=True)
    call("mount","-t","erofs","-o","ro,loop",old,m)
    try:
        original=tree_map(m)
        regular,count,size=source_tree_size(m)
        new=work/(part+".ext4.img")
        with new.open("wb") as dst:dst.truncate(size)
        call("mkfs.ext4","-F","-q","-m","0","-b","4096","-L",part[:-2],"-E","lazy_itable_init=0,lazy_journal_init=0","-d",m,new)
        fsout=work/("ext4mount-"+part);fsout.mkdir(exist_ok=True)
        call("e2fsck","-fn",new)
        call("mount","-t","ext4","-o","rw,loop",new,fsout)
        try:scrub_root_ext4(fsout,original)
        finally:call("umount",fsout)
        call("e2fsck","-fn",new)
        call("mount","-t","ext4","-o","ro,loop,noload",new,fsout)
        try:
            rebuilt=tree_map(fsout)
            if "/lost+found" in rebuilt:
                # ext4's standard recovery directory is not stock Android data.
                rebuilt.pop("/lost+found")
            results=compare_trees(original,rebuilt,[])
            if not results["passed"]:
                (report/("failed-comparison-"+part+".json")).write_text(json.dumps(results,indent=2)+"\n")
                raise RuntimeError("EXT4 metadata/file comparison FAILED "+part+
                        " (see report); no firmware artifact is permitted")
        finally:call("umount",fsout)
        (report/("converted-"+part+".json")).write_text(json.dumps({
           "filesystem":"ext4","name":part,"source_bytes":old.stat().st_size,
           "converted_bytes":size,"source_contents_rounded_4k":regular,
           "source_entries":count,"metadata_preserved":True,
           "original_tree_entries":len(original),"rebuilt_tree_entries":len(rebuilt),
           "source_sha256":sha(old),"converted_sha256":sha(new)
        },indent=2)+"\n")
        return new
    finally:
        call("umount",m)
        shutil.rmtree(inp)

def patch_vbmeta(stock,out):
    original=stock.read_bytes()
    audit=audit_one("vbmeta.img",original)
    if original[:4]!=b"AVB0" or audit["flags"]!=0:
        raise RuntimeError("Stock vbmeta not valid unmodified AVB")
    changed=bytearray(original)
    struct.pack_into(">I",changed,120,3)
    revised=audit_one("vbmeta.img",bytes(changed))
    if revised["flags"]!=3 or revised["descriptors"]!=audit["descriptors"]:
        raise RuntimeError("vbmeta flags/descriptor validation failed")
    out.write_bytes(changed)
    return {"stock_sha256":sha(stock),"patched_sha256":sha(out),
            "stock_flags":audit["flags"],"patched_flags":revised["flags"]}

def create_sparse(images,stock_sizes,super_size,group_max,out):
    total=sum(p.stat().st_size for p in images.values())
    if total>group_max-64*1024*1024:
        raise RuntimeError("Converted LP images require "+str(total)+" bytes, but main_a is "+
                           str(group_max)+" bytes; refusing to oversubscribe super")
    cmd=[str(TOOLS/"lpmake"),"--metadata-size","65536","--metadata-slots","3",
         "--device","super:"+str(super_size)+":1048576:0",
         "--group","main_a:"+str(group_max),"--group","main_b:"+str(group_max),
         "--virtual-ab","--sparse","--output",str(out)]
    for p in ALL_A:
        image=images[p]
        size=image.stat().st_size
        if size%4096:raise RuntimeError("Partition size unaligned: "+p)
        cmd+=["--partition",p+":readonly:"+str(size)+":main_a"]
        cmd+=["--image",p+"="+str(image)]
    for p in ALL_A:
        cmd+=["--partition",p[:-1]+"b:readonly:0:main_b"]
    call(*cmd)
    return total

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--work",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    for pth in (args.work,args.report,args.out):pth.mkdir(parents=True,exist_ok=True)
    original_args=sys.argv[:]
    try:
        sys.argv=["build11_ext4_preflight.py","--work",str(args.work),"--report",str(args.report)]
        stock_preflight()
    finally:sys.argv=original_args
    pre=json.loads((args.report/"build11-ext4-preflight.json").read_text())
    support=pre["ext4_first_stage_support"]
    if not all(support.values()):
        raise RuntimeError("Stock init fstab DOES NOT support ext4 first-stage for all three partitions")
    if pre["super_bytes"]!=9126805504 or sha(args.work/"super.raw.img")!=SUPER_SHA:
        raise RuntimeError("Wrong stock super")
    raw=args.work/"super.raw.img"
    original_dump=(args.report/"lpdump-slot0.txt").read_text()
    old_sizes=source_map(original_dump)
    images={};details={}
    # Unmodified partitions are byte-for-byte copied. No APK debloat performed.
    for part in ALL_A:
        if part in TARGETS:
            images[part]=convert_one(raw,part,args.work,args.report)
            details[part]=json.loads((args.report/("converted-"+part+".json")).read_text())
        else:
            tmp=args.work/("original-"+part);tmp.mkdir(exist_ok=True)
            run(TOOLS/"lpunpack","--slot=0","--partition="+part,raw,tmp)
            image=tmp/(part+".img")
            if sha(image)=="" or image.stat().st_size!=old_sizes[part]:
                raise RuntimeError("Invalid unmodified partition "+part)
            images[part]=image
    # Raw super is no longer needed; release 9.13GB before lpmake.
    raw.unlink()
    total=sum(f.stat().st_size for f in images.values())
    if total>pre["main_a_group_max"]-64*1024*1024:
        raise RuntimeError("Converted images do not fit original super LP group")
    built=args.work/"super-build11-ext4.sparse.img"
    allocated=create_sparse(images,old_sizes,pre["super_bytes"],pre["main_a_group_max"],built)
    # lpmake rebuilt the LP metadata; check declared filesystems and partition list.
    sparse_dump=call(TOOLS/"lpdump","-s","0",built)
    (args.report/"lpdump-ext4-sparse.txt").write_text(sparse_dump)
    for part in ALL_A:
        if not re.search(r"(?m)^\s*Name:\s*"+re.escape(part)+r"\s*$",sparse_dump):
            raise RuntimeError("LP output missing partition "+part)
    if "virtual_ab_device" not in sparse_dump:raise RuntimeError("Lost virtual_ab metadata flag")
    if built.stat().st_size<1_000_000:raise RuntimeError("Suspiciously small sparse image")
    for part in TARGETS:
        if fstype(images[part])!="ext4":raise RuntimeError("Conversion image not ext4: "+part)
    # Patched stock vbmeta flags are for unlocked test hardware only.
    avb=patch_vbmeta(args.work/"stock-images/vbmeta.img",args.out/"vbmeta.img")
    pieces=[]
    with built.open("rb") as src:
        while True:
            data=src.read(CHUNK)
            if not data:break
            name="super.sparse.img.part-"+str(len(pieces)).zfill(3)
            dest=args.out/name;dest.write_bytes(data)
            pieces.append({"name":name,"bytes":len(data),"sha256":sha(dest)})
    manifest={"project":"yunluo HyperOS Build11 EXT4 TEST ONLY",
      "rom":VERSION,"md5":MD5,"stock_boot_sha256":sha(args.work/"stock-images/boot.img"),
      "stock_vendor_boot_sha256":sha(args.work/"stock-images/vendor_boot.img"),
      "ext4_partitions":list(TARGETS),"unchanged_partitions":[x for x in ALL_A if x not in TARGETS],
      "no_app_debloat":True,"stock_fstab_ext4_support":support,
      "source_lp_group_max":pre["main_a_group_max"],"rebuilt_allocation":allocated,
      "filesystem_metadata_preserved":True,"repacked_virtual_ab":True,
      "converted_partitions":details,"vbmeta":avb,
      "super_sparse_sha256":sha(built),"super_sparse_bytes":built.stat().st_size,
      "pieces":pieces,"physical_device_boot_tested":False,
      "warning":"Experimental; never flash without a recovery route and exact device verification."}
    (args.out/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    (args.out/"SHA256SUMS.txt").write_text(
        "".join(x["sha256"]+"  "+x["name"]+"\n" for x in pieces)
        +sha(args.out/"vbmeta.img")+"  vbmeta.img\n")
    (args.out/"README-EXT4-TEST.txt").write_text(
       "Redmi Pad yunluo HyperOS 1 Global experimental ext4 image\n"
       "Test only: no apps deleted. Convert system_a, product_a, system_ext_a.\n"
       "Unchanged vendor/mi_ext, original boot.img and vendor_boot.img.\n"
       "Not boot tested. Output is not a complete automatic fastboot ROM.\n"
       "Join super.sparse.img.part-* in filename order before imaging.\n"
       "Unmodified stock firmware must be available as rollback.\n"
       "Only use on explicitly unlocked original yunluo with your own backups.\n")
    print("SUCCESS: ext4 Build 11 test sparse SUPER + vbmeta artifact verified OFFLINE",flush=True)
    print(json.dumps({"converted":list(TARGETS),"total_lp_bytes":allocated,
                      "sparse_bytes":built.stat().st_size,"pieces":len(pieces)},indent=2))

if __name__=="__main__":
    main()
