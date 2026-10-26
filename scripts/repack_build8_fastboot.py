#!/usr/bin/env python3
"""Pack untouched original yunluo ROM with private Build 8 super and patched stock main vbmeta.
Only two firmware images and their two dependent CRC text files change.
Stock flash scripts, scatter layouts and all other images remain byte-identical.
"""
import argparse,datetime,hashlib,io,json,os,re,stat,struct,tarfile,zipfile,zlib
from pathlib import Path,PurePosixPath
import xml.etree.ElementTree as ET
from vbmeta_audit import audit_one
from inventory import MD5,NAME,sha

ROOT="yunluo_global_images_V14.0.4.0.TLYMIXM_13.0"
SUPER_SHA=""
RAW_SHA=""
STOCK_VBMETA_SHA="181b221211ed75bc94a1346d7e424f8fbfc8dc9032ce3f88561b54e287b33879"
SUPER_BYTES=0
RAW_BYTES=8926805504
MAXCRC=(256*1024*1024)-(28+2*12+4)
NREAD=8*1024*1024
MATCH_USER={
"flash_all.sh":"ae5947ade4d23cb63051b8275ab80d070a036530ede2883d0a8789900baba26c",
"images/MT6789_Android_scatter.txt":"3798589802eb620efdf6198b826af7b3c53f40acfbef2c05c6d79e4392fcdc04",
"images/MT6789_Android_scatter.xml":"c3d1d02e29dad232d1b05372968f04b5bf6fec1955ecb5c08b3f827ca5167057",
"images/crclist.txt":"8024ca50eab8465b9e69a6f92de5c479caabae4a1528be00337736a0ef36277c",
"images/sparsecrclist.txt":"5d2aab619c339d1512b90f7aa0e68e344051f5a450db42513a676d0be96c89e8",
"check_sum.sh":"4f33481fa59308a0e81cebf06199e9d08ecb25f700efbe29fe07488f00e13a26",
"images/download_agent/flash.xml":"e92497c308566de87ff44fab737c71419b4d694f03f53a62e064d71f8d1c0a76",
"flash_gen_crc_list.py":"7ab2ef76fd98998474194c863a494541a4d31822c41cf18d389f8ec5a723aa3f",
"flash_gen_md5_list.py":"301e4626454d884db58c85e46f7126c48cd59c05bc0e947896dd31bc4971d8cb",
"misc.txt":"cfefc38affcbdc04f7e77c57aa9fb5400a90e725ec728e16cd04fe8cb48b2f85",
"images/anti_version.txt":"4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"
}
CHANGED={"images/super.img","images/vbmeta.img","images/crclist.txt","images/sparsecrclist.txt"}
def fail(msg):raise RuntimeError(msg)
def hash_file(path,algo="sha256"):
    h=hashlib.new(algo)
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(NREAD),b""):h.update(b)
    return h.hexdigest()
def exact(f,n):
    b=f.read(n)
    if len(b)!=n:fail("Truncated file: expected "+str(n))
    return b
class Joined:
    def __init__(self,paths):self.paths=paths;self.index=0;self.handle=None
    def __enter__(self):return self
    def __exit__(self,*a):
        if self.handle:self.handle.close()
    def read(self,n=0):
        if n<0:fail("Unsupported unbounded input")
        b=bytearray()
        while len(b)<n and self.index<len(self.paths):
            if self.handle is None:self.handle=self.paths[self.index].open("rb")
            part=self.handle.read(n-len(b))
            if not part:
                self.handle.close();self.handle=None;self.index+=1
            else:b.extend(part)
        return bytes(b)
def stock_compatible_sparse_crc(stream):
    """Streaming Python3 port of uploaded Xiaomi flash_gen_crc_list.py CRC splitting."""
    h=struct.unpack("<I4H4I",exact(stream,28))
    magic,major,minor,header,chunk_head,block_size,total_blocks,total_chunks,checksum=h
    if (magic,major,minor,header,chunk_head)!=(0xED26FF3A,1,0,28,12):fail("Unexpected Android sparse format")
    if block_size%512 or block_size*total_blocks!=RAW_BYTES:fail("Invalid super logical capacity")
    crcs=[0]*68;idx=0;backed=28;accounted=0
    for ci in range(total_chunks):
        typ,res,blocks,total=struct.unpack("<2H2I",exact(stream,12))
        remaining=total-12
        if typ==0xCAC1 and remaining!=blocks*block_size:fail("Invalid sparse RAW payload")
        if typ in (0xCAC2,0xCAC4) and remaining!=4:fail("Invalid sparse fill/checksum payload")
        if typ==0xCAC3 and remaining!=0:fail("Unexpected sparse DONT_CARE bytes")
        if typ not in (0xCAC1,0xCAC2,0xCAC3,0xCAC4):fail("Unknown sparse chunk")
        if typ!=0xCAC4:accounted+=blocks
        fill=exact(stream,4) if typ in (0xCAC2,0xCAC4) else None
        while True:
            backed_real=backed-12-4
            split=False;before=False;after=False
            if backed_real+remaining<=MAXCRC:
                piece=remaining;backed+=remaining+12
            elif backed_real>=(MAXCRC*7)//8 and remaining+12<=MAXCRC:
                piece=remaining;backed=remaining+12+28+12;before=True
            else:
                over=backed_real>=(MAXCRC*7)//8
                if over:backed_real=0
                piece=block_size*((MAXCRC-backed_real)//block_size)
                if typ!=0xCAC1 or not 0<piece<remaining:fail("Unrecognized Xiaomi CRC splitting")
                split=True;backed=(piece+12 if over else 28+12)
                before=over;after=not over
            if before:idx+=1
            if idx>=len(crcs):fail("Too many Xiaomi CRC segments")
            if typ==0xCAC1:
                remaining_piece=piece
                while remaining_piece:
                    raw=exact(stream,min(remaining_piece,NREAD))
                    crcs[idx]=zlib.crc32(raw,crcs[idx])
                    remaining_piece-=len(raw)
            elif typ==0xCAC2:
                if piece!=4:fail("Fill segment unexpectedly split")
                fb=fill*(block_size//4)
                repeat=blocks
                while repeat:
                    n=min(repeat,max(1,NREAD//block_size))
                    crcs[idx]=zlib.crc32(fb*n,crcs[idx])
                    repeat-=n
            if after:idx+=1
            remaining-=piece
            if not split:break
    if accounted!=total_blocks or stream.read(1):fail("Unexpected Android sparse image length")
    return crcs[:idx+1]
def crc_line(text,key):
    matches=[l for l in text.splitlines() if l.startswith(key+" ")]
    if len(matches)!=1:fail("Missing/duplicate checksum row: "+key)
    return matches[0]
def replace_crc(text,key,new):
    prev=crc_line(text,key)
    return text.replace(prev+"\n",new+"\n",1)
def patched_vbmeta(original):
    if len(original)!=8192 or hashlib.sha256(original).hexdigest()!=STOCK_VBMETA_SHA:fail("Wrong stock vbmeta.img")
    orig=audit_one("vbmeta.img",original)
    if orig["flags"]!=0 or orig["algorithm"]!="SHA256_RSA2048":fail("Unexpected vbmeta AVB0 header")
    modified=bytearray(original)
    struct.pack_into(">I",modified,120,3)
    modified=bytes(modified)
    parsed=audit_one("vbmeta.img",modified)
    if parsed["flags"]!=3 or parsed["descriptors"]!=orig["descriptors"]:fail("AVB patch failed")
    if sum(x!=y for x,y in zip(original,modified))!=1:fail("AVB patch changed too many bytes")
    return modified
def check_scatter_and_script(data):
    sh=data["flash_all.sh"].decode()
    for token in ["flash vbmeta_ab ","/images/vbmeta.img","flash super ","/images/super.img","set_active a"]:
        if token not in sh:fail("Original flash script no longer matches expected instructions")
    for kind in ("txt","xml"):
        key="images/MT6789_Android_scatter."+kind
        content=data[key].decode()
        if kind=="xml":
            root=ET.fromstring(content)
            entries=[(e.findtext("partition_name"),e.findtext("file_name"),e.findtext("partition_size")) for e in root.iter("partition_index")]
        else:
            entries=[]
            for block in content.split("  - partition_index: ")[1:]:
                def get(name):
                    m=re.search(r"(?m)^\s*"+name+r":\s*(\S+)\s*$",block)
                    return m.group(1) if m else None
                entries.append((get("partition_name"),get("file_name"),get("partition_size")))
        for partition,image,size in [("super","super.img",RAW_BYTES),("vbmeta_a","vbmeta.img",0x800000)]:
            matches=[e for e in entries if e[0]==partition]
            if len(matches)!=2 or any(e[1]!=image or int(e[2],16)!=size for e in matches):
                fail("Original scatter incorrect for "+partition+"/"+kind)
def zinfo(name,mode,mtime,store=False):
    date=datetime.datetime.fromtimestamp(max(mtime,315532800),datetime.timezone.utc)
    z=zipfile.ZipInfo(name,(date.year,date.month,date.day,date.hour,date.minute,date.second))
    z.create_system=3
    z.external_attr=(stat.S_IFREG|(mode&0o7777))<<16
    z.compress_type=zipfile.ZIP_STORED if store else zipfile.ZIP_DEFLATED
    z._compresslevel=None if store else 1
    return z
def copy_entry(zout,info,source):
    h=hashlib.sha256()
    with zout.open(info,"w",force_zip64=True) as out:
        while b:=source.read(NREAD):
            out.write(b);h.update(b)
    return h.hexdigest()
def verify_parts(folder):
    """Check Build 8 image manifest before packaging any original firmware."""
    from build8_targets import build8_targets, MIRAVISION_JNI
    manifest=json.loads((folder/"manifest.json").read_text())
    removed,_,_,kept=build8_targets()
    if manifest.get("model")!="yunluo" or manifest.get("slot")!="a" or manifest.get("build")!="7-experimental":
        fail("Wrong Build 8 source")
    if manifest.get("build8_previous_app_folder_removals")!=108 or len(kept)!=19:
        fail("Build 8 source 108 / keep 19 mismatch")
    if manifest.get("total_directories_removed")!=89 or manifest.get("build8_restored_app_folders")!=19:
        fail("Build 8 must preserve 19 of 108 original apps")
    if sorted(manifest.get("build8_kept_locations",[]))!=sorted(kept):
        fail("Build 8 keep list differs from current protected configuration")
    if manifest.get("gallery_preserved") is not True or manifest.get("build8_miravision_jni_preserved")!=list(MIRAVISION_JNI):
        fail("Gallery or MiraVision native protections not validated")
    if not manifest.get("lp_metadata_preserved") or not manifest.get("other_regions_unchanged"):
        fail("Build 8 super metadata/region validation missing")
    if manifest.get("haptic_framework_untouched") is not True:
        fail("Build 8 must not patch shared haptic framework on no-vibration hardware")
    if manifest.get("additional_apks_installed")!=0:
        fail("Build 8 must not install APKs")
    cleanup=manifest.get("build8_cleanup_by_partition")
    if not isinstance(cleanup,list) or {x.get("partition") for x in cleanup}!={"product_a","system_a","system_ext_a"}:
        fail("Missing Build 8 per-partition leftover audit")
    if sum(int(x.get("standalone_entries_selected",-1)) for x in cleanup)!=manifest.get("build8_extra_files_removed"):
        fail("Build 8 leftover deletion counts disagree")
    if sum(int(x.get("bytes_selected",-1)) for x in cleanup)!=manifest.get("build8_extra_bytes_removed"):
        fail("Build 8 leftover deletion bytes disagree")
    deleted={d["location"] for d in manifest.get("excluded_folders",[])}
    if deleted!=set(removed) or deleted.intersection(kept):
        fail("Build 8 removals include an app from the 19-app keep list")
    libraries=[x["path"] for part in cleanup for x in part["selected"] if x["kind"]=="native_library"]
    if libraries!=["/system/lib64/libprintspooler_jni.so"]:
        fail("Build 8 native library policy differs from sole reviewed printspooler removal")
    if any("miravision" in x["path"].casefold() for part in cleanup for x in part["selected"]):
        fail("Build 8 selected a MiraVision dependency for deletion")
    global SUPER_SHA,RAW_SHA,SUPER_BYTES
    SUPER_SHA=manifest.get("sparse_sha256","")
    RAW_SHA=manifest.get("modified_super_sha256","")
    SUPER_BYTES=sum(int(p["bytes"]) for p in manifest.get("parts",[]))
    if len(SUPER_SHA)!=64 or len(RAW_SHA)!=64 or SUPER_BYTES<3000000000:
        fail("Malformed Build 8 super manifest digests/size")
    if manifest.get("original_firmware_md5")!=MD5:
        fail("Original MIUI stock archive hash mismatch")
    files=[];overall=hashlib.sha256();total=0
    for i,part in enumerate(manifest.get("parts",[])):
        name=f"super.sparse.img.part-{i:03d}"
        if part["file"]!=name:fail("Wrong part order")
        file=folder/name
        if not file.is_file() or file.stat().st_size!=part["bytes"]:fail("Missing part "+name)
        h=hashlib.sha256()
        with file.open("rb") as f:
            for chunk in iter(lambda:f.read(NREAD),b""):
                h.update(chunk);overall.update(chunk);total+=len(chunk)
        if h.hexdigest()!=part["sha256"]:fail("Incorrect Build 8 image part: "+name)
        files.append(file)
    if len(files)<3 or total!=SUPER_BYTES or overall.hexdigest()!=SUPER_SHA:
        fail("Build 8 combined super failed checksum")
    return files

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--archive",required=True,type=Path)
    ap.add_argument("--artifact",required=True,type=Path)
    ap.add_argument("--zip",required=True,type=Path)
    ap.add_argument("--report",required=True,type=Path)
    a=ap.parse_args()
    if sha(a.archive,"md5")!=MD5:fail("Wrong original Xiaomi firmware download")
    files=verify_parts(a.artifact)
    manifest=json.loads((a.artifact/"manifest.json").read_text())
    print("Verified original Xiaomi ROM MD5 and complete private Build 8 super parts SHA256",flush=True)
    stock={};modes={};old_crcs=None;seen=set();preserved={}
    tmp=a.zip.with_name(a.zip.name+".working")
    if tmp.exists():tmp.unlink()
    try:
        with zipfile.ZipFile(tmp,"w",allowZip64=True) as z,tarfile.open(a.archive,"r|gz") as t:
            for m in t:
                path=PurePosixPath(m.name)
                if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0]!=ROOT or m.issym() or m.islnk() or m.isdev():fail("Unexpected Xiaomi archive member")
                if m.isdir():continue
                if not m.isfile():fail("Unsupported Xiaomi archive type")
                relative=str(path.relative_to(ROOT))
                if relative in seen:fail("Duplicate Xiaomi firmware file")
                seen.add(relative)
                with t.extractfile(m) as source:
                    if relative=="images/super.img":
                        old_crcs=stock_compatible_sparse_crc(source)
                        modes[relative]=(m.mode,m.mtime)
                        print("Checked Xiaomi original super sparse CRC: "+str(len(old_crcs))+" parts",flush=True)
                    elif relative=="images/vbmeta.img":
                        stock[relative]=source.read()
                        modes[relative]=(m.mode,m.mtime)
                    elif relative in CHANGED or relative in MATCH_USER:
                        blob=source.read()
                        if relative in MATCH_USER and hashlib.sha256(blob).hexdigest()!=MATCH_USER[relative]:
                            fail("Attached file differs from stock: "+relative)
                        stock[relative]=blob
                        modes[relative]=(m.mode,m.mtime)
                        if relative not in CHANGED:
                            copy_entry(z,zinfo(str(path),m.mode,m.mtime),io.BytesIO(blob))
                    else:
                        preserved[relative]=copy_entry(z,zinfo(str(path),m.mode,m.mtime),source)
                if len(seen)%10==0:print("Processed stock files:",len(seen),flush=True)
            if len(seen)<35 or not CHANGED.issubset(seen) or old_crcs is None:fail("Missing source firmware components")
            original_vb=stock["images/vbmeta.img"]
            patched=patched_vbmeta(original_vb)
            print("AVB0 verification and hashtree flags validated: 0 -> 3",flush=True)
            check_scatter_and_script(stock)
            old_crc_text=stock["images/crclist.txt"].decode()
            old_sparse_text=stock["images/sparsecrclist.txt"].decode()
            stock_vb_crc=int(crc_line(old_crc_text,"vbmeta_a").split()[1],16)
            if stock_vb_crc!=zlib.crc32(original_vb):fail("Stock vbmeta CRC mismatch")
            fields=crc_line(old_sparse_text,"super").split()
            if len(fields)!=len(old_crcs)+2 or int(fields[1])!=len(old_crcs):fail("Stock sparse CRC count mismatch")
            if [int(x,16) for x in fields[2:]]!=old_crcs:fail("Python 3 CRC code does not reproduce Xiaomi's original super checksums")
            print("Validated stock Xiaomi super CRC algorithm",flush=True)
            with Joined(files) as reader:new_crcs=stock_compatible_sparse_crc(reader)
            print("New super CRC segments:",len(new_crcs),flush=True)
            new_crc_text=replace_crc(old_crc_text,"vbmeta_a","vbmeta_a "+hex(zlib.crc32(patched)))
            new_sparse_text=replace_crc(old_sparse_text,"super","super "+str(len(new_crcs))+" "+" ".join(hex(c) for c in new_crcs))
            for key,blob in [
                ("images/vbmeta.img",patched),
                ("images/crclist.txt",new_crc_text.encode()),
                ("images/sparsecrclist.txt",new_sparse_text.encode())
            ]:
                mode,mtime=modes[key]
                copy_entry(z,zinfo(ROOT+"/"+key,mode,mtime),io.BytesIO(blob))
            mode,mtime=modes["images/super.img"]
            with Joined(files) as reader:
                result=copy_entry(z,zinfo(ROOT+"/images/super.img",mode,mtime,store=True),reader)
            if result!=SUPER_SHA:fail("Modified super bytes differ inside ZIP")
        with zipfile.ZipFile(tmp,"r") as z:
            if z.testzip() is not None:fail("ZIP checksum test failed")
            if len(z.namelist())!=len(seen) or set(z.namelist())!={ROOT+"/"+p for p in seen}:fail("ZIP differs from source file listing")
            if z.read(ROOT+"/images/vbmeta.img")!=patched:fail("Patched vbmeta missing from ZIP")
            h=hashlib.sha256()
            with z.open(ROOT+"/images/super.img") as inp:
                for b in iter(lambda:inp.read(NREAD),b""):h.update(b)
            if h.hexdigest()!=SUPER_SHA:fail("Repacked Build 4 super hash failed")
        a.zip.parent.mkdir(parents=True,exist_ok=True)
        tmp.rename(a.zip)
        out={
          "model":"yunluo","build":"Build 8 Experimental, 89 entire folders removed and 19 original apps preserved; no injected APK",
          "status":"offline_verified_not_full_package_flash_tested",
          "original_rom_md5":MD5,"firmware_zip_filename":a.zip.name,
          "firmware_zip_sha256":hash_file(a.zip),"firmware_zip_bytes":a.zip.stat().st_size,
          "modified_images":["images/super.img","images/vbmeta.img"],
          "updated_checksum_text":["images/crclist.txt","images/sparsecrclist.txt"],
          "other_original_firmware_files_untouched":True,
          "flash_all_sh_preserved":True,"scatter_txt_xml_preserved":True,
          "vbmeta_system_vendor_img_stock_unchanged":True,
          "super_sha256":SUPER_SHA,"super_raw_size_bytes":RAW_BYTES,
          "gallery_preserved":True,"added_apks":0,"app_folders_removed":89,"original_apps_retained":19,
          "extra_app_owned_files_removed":manifest.get("build8_extra_files_removed"),
          "extra_app_owned_bytes_removed":manifest.get("build8_extra_bytes_removed"),
          "vbmeta_patched_sha256":hashlib.sha256(patched).hexdigest(),"vbmeta_flags":3,
          "vbmeta_original_signature_valid_after_patch":False,
          "notes":["UNLOCKED BOOTLOADER REQUIRED","DO NOT USE flash_all_lock.sh or flash_all_lock.bat",
                   "Original flash_all.sh erases metadata, expdb and boot_ab and flashes userdata.img; user data loss expected",
                   "flash_all.sh already flashes vbmeta_ab and super and sets slot A; no script editing needed"],
          "original_other_firmware_sha256":preserved,
          "stock_sparse_crc_segments":len(old_crcs),"new_sparse_crc_segments":len(new_crcs)
        }
        a.report.mkdir(parents=True,exist_ok=True)
        (a.report/"VERIFICATION.json").write_text(json.dumps(out,indent=2)+"\n")
        print(json.dumps({k:out[k] for k in ["firmware_zip_filename","firmware_zip_bytes","firmware_zip_sha256","vbmeta_patched_sha256","modified_images","updated_checksum_text"]},indent=2),flush=True)
    finally:
        if tmp.exists():tmp.unlink()
if __name__=="__main__":
    main()
