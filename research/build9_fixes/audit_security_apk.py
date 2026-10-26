#!/usr/bin/env python3
"""Read-only exact package-reference audit of stock MIUI Security Center.

Input: Security Center APK + tab-separated stock package inventory:
partition<TAB>path<TAB>package_id<TAB>removal_status.

Evidence levels:
  1. Manifest <uses-library> dependency (from external aapt evidence)
  2. Exact DEX constant reference to package name
  3. Incidental string mentions, NOT a dependency proof.
The script must never claim that a string reference requires the app for boot.
"""
import argparse
import json
import re
import struct
import zipfile
from pathlib import Path

def read_uleb(data, pos):
    value=0
    for shift in (0,7,14,21,28):
        if pos>=len(data): raise ValueError("Truncated ULEB128")
        byte=data[pos];pos+=1
        value|=(byte & 0x7f)<<shift
        if not byte&0x80:return value,pos
    raise ValueError("Invalid ULEB128 size")

def dex_strings(data):
    if len(data)<112 or not data.startswith(b"dex\n"):
        raise ValueError("Not an Android DEX")
    size,offset=struct.unpack_from("<II",data,0x38)
    if size>3_000_000 or offset+size*4>len(data):
        raise ValueError("Out-of-bounds DEX string table")
    out=set()
    for i in range(size):
        ptr=struct.unpack_from("<I",data,offset+i*4)[0]
        if ptr>=len(data): raise ValueError("Out-of-bounds DEX string")
        _,ptr=read_uleb(data,ptr)
        end=data.find(b"\0",ptr)
        if end<0: raise ValueError("Unterminated DEX string")
        out.add(data[ptr:end].decode("utf-8","replace"))
    return out

def inspect_apk(apk):
    observed=set()
    with zipfile.ZipFile(apk) as archive:
        for name in archive.namelist():
            if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",name):
                observed.update(dex_strings(archive.read(name)))
    if not observed:
        raise ValueError("Security Center APK contains no DEX string pools")
    return observed

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--security-apk",type=Path,required=True)
    p.add_argument("--inventory",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    ids=inspect_apk(a.security_apk)
    inventory={}
    for line in a.inventory.read_text().splitlines():
        if not line or line.startswith("#"):continue
        partition,path,pkg,status=line.split("\t")
        if status not in ("REMOVED","KEPT","PROTECTED"):
            raise RuntimeError("Invalid inventory status "+status)
        if pkg in inventory:raise RuntimeError("Duplicate package identity "+pkg)
        inventory[pkg]={"partition":partition,"original_path":path,"status":status}
    matches=[]
    for pkg,meta in sorted(inventory.items()):
        exact=pkg in ids
        class_descriptor="L"+pkg.replace(".","/")+";"
        dex_class=class_descriptor in ids or any(s.startswith("L"+pkg.replace(".","/")+"/") for s in ids)
        # substrings in embedded URI/URL/constant are weaker evidence
        incidental=[s[:300] for s in ids if pkg in s and s!=pkg]
        if exact or dex_class or incidental:
            matches.append(dict(package=pkg,**meta,
                               exact_package_const_string=exact,
                               dex_class_reference=dex_class,
                               incidental_examples=sorted(incidental,key=len)[:4]))
    result={"source":"original stock security APK; DEX string_id tables only",
            "limitations":"Matches are code references, NOT proof of a required runtime dependency. DEX reflection/encryption/native code may evade scanning.",
            "scanned_dex_strings":len(ids),"scanned_packages":len(inventory),
            "matches":matches,
            "removed_exact_const_refs":[x["package"] for x in matches if x["status"]=="REMOVED" and x["exact_package_const_string"]],
            "removed_class_refs":[x["package"] for x in matches if x["status"]=="REMOVED" and x["dex_class_reference"]],
            "removed_incidental_mentions":[x["package"] for x in matches if x["status"]=="REMOVED" and not x["exact_package_const_string"] and not x["dex_class_reference"]]}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="matches"},indent=2))

if __name__=="__main__":main()
