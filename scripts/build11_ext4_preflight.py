#!/usr/bin/env python3
"""Stock firmware ONLY: audit yunluo boot/vendor_boot fstabs and LP capacity.
No firmware modifications. Fails closed on extraction errors.
"""
import argparse, gzip, json, os, re, shutil, struct, subprocess, tarfile
from pathlib import Path, PurePosixPath
from inventory import TOOLS, fstype, sha
from build11_source import download_archive, verify_archive, VERSION, MD5, FILENAME
from build11_apk_inventory import raw_super, layout, run

def align(n,a):
    if a<=0 or a&(a-1): raise ValueError("Unsupported page alignment")
    return (n+a-1)//a*a

def extract_stock(archive, out):
    out.mkdir(parents=True,exist_ok=True)
    required={"boot.img","vendor_boot.img","super.img"}
    seen=set()
    verify_archive(archive)
    with tarfile.open(archive,mode="r|gz") as tar:
        for item in tar:
            name=PurePosixPath(item.name)
            if name.is_absolute() or ".." in name.parts or item.issym() or item.islnk() or item.isdev():
                raise RuntimeError("Unsafe ROM member "+item.name)
            if not item.isfile() or name.parent.name!="images" or name.name not in required:continue
            if name.name in seen: raise RuntimeError("Duplicate image "+name.name)
            seen.add(name.name)
            with tar.extractfile(item) as src,(out/name.name).open("wb") as dst:
                shutil.copyfileobj(src,dst,8*1024*1024)
    if seen!=required:raise RuntimeError("Missing official firmware images "+str(required-seen))

def ramdisk_blobs(image):
    data=image.read_bytes()
    if data.startswith(b"VNDRBOOT"):
        if len(data)<2130:raise RuntimeError("Short vendor_boot header")
        ver,page,ram_size=struct.unpack_from("<III",data,8)[0],struct.unpack_from("<I",data,12)[0],struct.unpack_from("<I",data,24)[0]
        header_size=struct.unpack_from("<I",data,2096)[0]
        if ver not in (3,4) or header_size not in (2112,2128,2096):raise RuntimeError("Unexpected vendor_boot header "+str((ver,header_size)))
        pos=align(header_size,page)
        blob=data[pos:pos+ram_size]
        if len(blob)!=ram_size or not blob:raise RuntimeError("Invalid vendor ramdisk payload")
        fragments=[blob]
        if ver==4:
            dtb_size=struct.unpack_from("<I",data,2100)[0]
            table_size,entries,entry_size,bootconf=struct.unpack_from("<IIII",data,2112)
            table_pos=align(pos+ram_size,page)+align(dtb_size,page)
            if entries and (entry_size<108 or entries*entry_size>table_size):raise RuntimeError("Invalid vendor ramdisk table")
            if entries:
                fragments=[]
                for i in range(entries):
                    sz,off,kind=struct.unpack_from("<III",data,table_pos+i*entry_size)
                    if not sz or off+sz>len(blob):raise RuntimeError("Ramdisk fragment out of range")
                    fragments.append(blob[off:off+sz])
        return {"format":"vendor_boot","version":ver,"page_size":page,"ramdisk_bytes":ram_size,"fragments":len(fragments)},fragments
    if data.startswith(b"ANDROID!"):
        version=struct.unpack_from("<I",data,40)[0]
        kernel_size,ram_size=struct.unpack_from("<II",data,8)
        if version<3:page=struct.unpack_from("<I",data,36)[0];offset=align(page,page)+align(kernel_size,page)
        elif version in (3,4):page=4096;offset=align(struct.unpack_from("<I",data,20)[0],page)+align(kernel_size,page)
        else:raise RuntimeError("Unknown boot header "+str(version))
        blob=data[offset:offset+ram_size]
        if len(blob)!=ram_size:raise RuntimeError("Truncated boot ramdisk")
        return {"format":"boot","version":version,"page_size":page,"ramdisk_bytes":ram_size,"fragments":int(bool(blob))},([blob] if blob else [])
    raise RuntimeError("Unknown Android boot image header")

def unpack_cpio(blob,dest):
    if blob.startswith(b"\x1f\x8b"):raw=gzip.decompress(blob)
    elif blob.startswith((bytes.fromhex("02214c18"),bytes.fromhex("04224d18"))):
        p=subprocess.run(["lz4","-d","-c"],input=blob,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if p.returncode:raise RuntimeError("LZ4 ramdisk failed: "+p.stderr.decode("utf8","replace")[-300:])
        raw=p.stdout
    elif blob.startswith((b"070701",b"070702")):raw=blob
    else:raise RuntimeError("Unexpected ramdisk compression: "+blob[:12].hex())
    dest.mkdir(parents=True,exist_ok=True)
    paths=subprocess.run(["cpio","-it","--quiet"],input=raw,capture_output=True)
    if paths.returncode:raise RuntimeError("Cannot list cpio contents")
    for entry in paths.stdout.decode("utf8","replace").splitlines():
        p=PurePosixPath(entry)
        if p.is_absolute() or ".." in p.parts:raise RuntimeError("Unsafe cpio path: "+entry)
    process=subprocess.run(["cpio","-idm","--no-absolute-filenames","--quiet"],cwd=dest,input=raw,capture_output=True)
    if process.returncode:raise RuntimeError("Cannot extract cpio: "+process.stderr.decode("utf8","replace")[-500:])

def read_fstabs(root,label):
    found=[]
    for p in root.rglob("fstab*"):
        if not p.is_file():continue
        if p.stat().st_size>2_000_000:continue
        raw=p.read_bytes()
        if b"\x00" in raw:continue
        content=raw.decode("utf8","replace")
        found.append({"source":label+":"+str(p.relative_to(root)),"lines":[x.strip() for x in content.splitlines() if x.strip() and not x.lstrip().startswith("#")]})
    return found

def summarize_fstab(found):
    matches={part:[] for part in ("system","product","system_ext")}
    for record in found:
        for line in record["lines"]:
            bits=line.split()
            if len(bits)<4:continue
            dev,mount,fs=bits[:3]
            for part in matches:
                if mount=="/"+part or (part=="system" and mount=="/system"):
                    if fs in ("erofs","ext4"):
                        matches[part].append({"source":record["source"],"fstab":line,"fs":fs,"first_stage_mount":"first_stage_mount" in line})
    return matches

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--work",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    a=p.parse_args(); a.work.mkdir(parents=True,exist_ok=True);a.report.mkdir(parents=True,exist_ok=True)
    stock=a.work/FILENAME
    download_archive(stock,a.report/"download.json")
    original=a.work/"stock-images";extract_stock(stock,original)
    # The source archive has passed MD5; release disk space before sparse-to-raw conversion.
    stock.unlink()
    infos={};fstabs=[]
    for name in ("boot.img","vendor_boot.img"):
        source=original/name;detail,blobs=ramdisk_blobs(source);detail["sha256"]=sha(source)
        infos[name]=detail
        for i,blob in enumerate(blobs):
            target=a.work/(name+"-ramdisk-"+str(i));unpack_cpio(blob,target)
            fstabs+=read_fstabs(target,name+":"+str(i))
    raw=a.work/"super.raw.img"
    raw_super(original/"super.img",raw)
    if sha(raw)!="965f791ef796d4346b4abf95fad216a90084ed869ef2b6fbae1993d5683c686c":
        raise RuntimeError("Wrong stock super raw image checksum")
    parts=layout(raw,a.report)
    vendor=a.work/"vendor-lpunpack";vendor.mkdir(exist_ok=True)
    run(TOOLS/"lpunpack","--slot=0","--partition=vendor_a",raw,vendor)
    vm=a.work/"vendor-mnt";vm.mkdir(exist_ok=True)
    run("mount","-t","erofs","-o","ro,loop",vendor/"vendor_a.img",vm)
    try:fstabs+=read_fstabs(vm,"vendor_a")
    finally:run("umount",vm)
    fstabmatch=summarize_fstab(fstabs)
    dmp=(a.report/"lpdump-slot0.txt").read_text()
    group=re.search(r"(?ms)^  Name: main_a\n  Maximum size: (\d+)",dmp)
    if not group:raise RuntimeError("Could not locate original LP main_a group")
    capacities={}
    for part in ("system_a","system_ext_a","product_a","vendor_a","vendor_dlkm_a","odm_dlkm_a","mi_ext_a"):
        block=re.search(r"(?ms)^  Name: "+re.escape(part)+r"\n.*?(?=------------------------)",dmp)
        if not block:raise RuntimeError("Missing LP "+part)
        spans=re.findall(r"(\d+) \.\. (\d+) linear super (\d+)",block.group(0))
        if len(spans)!=1:raise RuntimeError("Unusual LP extent count for "+part)
        start,end,offset=map(int,spans[0])
        capacities[part]={"bytes":(end-start+1)*512,"physical_sector":offset}
    result={"source":VERSION,"official_md5":MD5,"boot_images":infos,
      "fstab_matches":fstabmatch,"all_fstab_sources":[{"source":f["source"],"lines_count":len(f["lines"])} for f in fstabs],
      "ext4_first_stage_support":{k:any(m["fs"]=="ext4" and m["first_stage_mount"] for m in v) for k,v in fstabmatch.items()},
      "original_lp_bytes":capacities,"main_a_group_max":int(group.group(1)),
      "current_allocated":sum(x["bytes"] for x in capacities.values()),
      "super_bytes":raw.stat().st_size,
      "other_partitions":parts}
    result["free_group_bytes"]=result["main_a_group_max"]-result["current_allocated"]
    (a.report/"build11-ext4-preflight.json").write_text(json.dumps(result,indent=2)+"\n")
    for f in fstabs:
        (a.report/("fstab-"+re.sub("[^a-zA-Z0-9]","_",f["source"])+".txt")).write_text("\n".join(f["lines"])+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("all_fstab_sources","other_partitions","original_lp_bytes")},indent=2),flush=True)

if __name__=="__main__":
    main()
