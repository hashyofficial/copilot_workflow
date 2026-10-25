#!/usr/bin/env python3
"""Build 6: apply only separately reviewed native-file exclusions.

Never remove native libraries by a substring/filename match alone. All exclusions
are sha256-pinned and must belong to the source app folders removed in Builds 1–5.
"""
import json,os
from pathlib import Path,PurePosixPath
from inventory import ROOT,sha

POLICY=ROOT/"config/build6-reviewed-native-files.json"
ONLY_ALLOWED_NAMES={
    "libMiraVision_jni.so","libmonitortrack.so","libprintspooler_jni.so",
    "libhidcommand_jni.so","libuinputcommand_jni.so"
}
LIB_PREFIXES={
    "system_a":("/system/lib/","/system/lib64/"),
    "product_a":("/lib/","/lib64/"),
    "system_ext_a":("/lib/","/lib64/")
}
def entries():
    doc=json.loads(POLICY.read_text())
    if doc.get("device")!="yunluo" or doc.get("source")!="stock-miui14-global-v14.0.4.0.tlymixm":
        raise RuntimeError("Reviewed Build 6 policy is not for this firmware")
    if not isinstance(doc.get("reviewed_files"),list) or not doc["reviewed_files"]:
        raise RuntimeError("No verified orphan native libraries approved")
    out={}
    for e in doc["reviewed_files"]:
        if set(e)!={"partition","path","sha256","removed_apk_package","reference_hits"}:
            raise RuntimeError("Malformed Build 6 native-file entry")
        p=e["partition"];name=e["path"]
        pp=PurePosixPath(name)
        if p not in LIB_PREFIXES or not pp.is_absolute() or ".." in pp.parts:
            raise RuntimeError("Bad Build 6 file location")
        if not any(name.startswith(prefix) for prefix in LIB_PREFIXES[p]) or pp.name not in ONLY_ALLOWED_NAMES:
            raise RuntimeError("Build 6 cannot exclude arbitrary shared library: "+name)
        if len(e["sha256"])!=64 or any(x not in "0123456789abcdef" for x in e["sha256"]):
            raise RuntimeError("Missing pinned Build 6 source SHA256")
        if e["reference_hits"]!=0:
            raise RuntimeError("Build 6 library still has an observed retained-file reference")
        key=p+":"+name
        if key in out:raise RuntimeError("Duplicated Build 6 orphan library")
        out[key]=e
    return out

def validate_files(mount,part,app_targets,policy):
    excluded_dirs=[str(apk.parent) for location,(p,apk) in app_targets.items() if p==part]
    results=[]
    for key,e in policy.items():
        if e["partition"]!=part:continue
        path=e["path"]
        if any(path==folder or path.startswith(folder+"/") for folder in excluded_dirs):
            raise RuntimeError("Orphan file is already inside a completely removed APK folder")
        source=mount/path.lstrip("/")
        if source.is_symlink() or not source.is_file():
            raise RuntimeError("Build 6 exact reviewed library missing/not regular: "+key)
        if sha(source)!=e["sha256"]:
            raise RuntimeError("Build 6 reviewed library SHA256 unexpectedly changed: "+key)
        # Do not leave symlinks referring to removed .so files.
        for root,dirs,files in os.walk(mount,followlinks=False):
            for name in files+dirs:
                other=Path(root)/name
                if not other.is_symlink():continue
                try:
                    if other.resolve()==source.resolve():
                        relative="/"+str(other.relative_to(mount))
                        if not any(relative==folder or relative.startswith(folder+"/") for folder in excluded_dirs):
                            raise RuntimeError("Retained symlink references removed Build 6 library: "+relative)
                except OSError:
                    raise RuntimeError("Unable to resolve a filesystem symlink: "+str(other))
        results.append({"partition":part,"path":path,"source_sha256":e["sha256"],
                        "bytes":source.stat().st_size,"removed_apk_package":e["removed_apk_package"]})
    return results
