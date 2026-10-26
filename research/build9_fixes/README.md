# Build 9 post-boot investigation — experimental, NO firmware release

Confirmed booted on Redmi Pad (yunluo). Build 9 and its release MUST remain intact.
This branch does not modify boot.img, vbmeta.img, super.img, Security Center or Wi-Fi HAL.

## Confirmed evidence
- `dumpsys role`: `android.app.role.SYSTEM_GALLERY` has **no holder**.
- `cmd overlay lookup --user 0 android android:string/config_systemGallery`:
  `com.miui.gallery` (removed as requested).
- Photon Gallery (`com.inferno.gallery`) loads correctly. Do not give it
  `SYSTEM_GALLERY`; that grants broad privileged media access and is unnecessary.
- Wi-Fi associates and is **VALIDATED**; RSSI around -50 dBm, link 433 Mbps.
  Link-layer statistics requests fail in MediaTek vendor HAL, already recorded
  on Builds 7/8. The vendor partition and Wi-Fi libraries were not modified.
- MIUI Security Center `com.miui.securitycenter`, Xiaomi-signed system-UID APK,
  still installed at `/product/priv-app/MIUISecurityCenterGlobalPad`.
  `ExtraNetwork -> MiuiNetdFirewall.getTempMobileRule` dereferences a null
  `ArrayMap` while scanning mobile data rules on this Wi-Fi-only tablet.
  A Java exception in a stock privileged app is NOT a missing `.so` symptom.

## Verified stock Xiaomi framework result (2026-10-26)

Read-only GitHub workflow run: https://github.com/hashyofficial/copilot_workflow/actions/runs/40279553022

The stock MIUI 14 archive passed the pinned MD5 check, and the original
`framework-res.apk` was read from the mounted original `system_a` EROFS.

Actual policy result from `aapt2 dump overlayable`:

```json
{
  "gallery_rro_allowed": false,
  "reason": "Stock framework must expose config_systemGallery to product/public overlay; found 0",
  "stock_product_overlay_config_exists": false
}
```

**Conclusion:** The proposed `/product/overlay` Gallery-role RRO cannot be
shipped under the tested public/product overlay policy. This is an expected,
successful fail-closed policy verdict, **not a patch success**. Do not force
an unsupported resource mapping, patch or resign Xiaomi's framework-res,
or call this a functional Galaxy/Gallery fix. The existing resource warning
is preferable to risking a boot regression.

Any true firmware correction now requires access to the correctly OEM-signed
framework image, a supported upstream build, or a proven alternative that
passes resource-id and signature checks. NONE has been verified here.

## Only proposed patch: config_systemGallery RRO

`build_gallery_rro.py` creates a single-purpose, no-code Android 13
`android` framework resource overlay that changes ONLY `string/config_systemGallery`
to an empty string. No Photon privileging and no framework-res re-signing.

**Fail-closed gate:** the builder requires the actual Xiaomi `framework-res.apk`,
calls `aapt2 dump overlayable`, and refuses the patch unless it finds exactly
one resource group exposing `string/config_systemGallery` with `product` or
`public` policy. It dynamically uses that targetName. No assumption that the
stock firmware permits this overlay.

The builder also needs a user-controlled signing key, aapt2, zipalign,
apksigner. It produces a signed APK **for experiment only**, not flashable
firmware. Tests cover parsing, rejection and generated XML.

To build after obtaining the exact stock framework-res:

```bash
python3 research/build9_fixes/build_gallery_rro.py \
 --framework-res original_framework-res.apk \
 --keystore local-test.keystore \
 --keystore-password-file ./local-test-keystore-pass.txt \
 --out GalleryRoleOverlay-UNTESTED.apk
```

AOSP references:
- https://source.android.com/docs/core/runtime/rros
- https://source.android.com/docs/core/runtime/rro-troubleshoot
- https://developer.android.com/tools/aapt2

**Required before any device flash:** prove `idmap2` accepts overlay policy
for the exact MIUI framework, verify `cmd overlay lookup` resolves an empty
string *after* installation, and ensure all original EROFS file metadata
(xattrs, owners, modes, mtime) remains unchanged. Run on an experimental
firmware, never overwrite the successful Build 9 release.

**Other references:** Xiaomi Security Center's separate `DefaultAppModel`
package lookup for `com.miui.gallery` is independent of framework's
`config_systemGallery` and might still log after this fix.

## Wi-Fi HAL
Do **not** delete `libwifi-hal.so`, vendor Wi-Fi `.so` files, kernel
modules or firmware blobs. Link-layer statistics errors originate from
the already-working stock vendor interface. No verified compatible driver
patch or feature-bit configuration is available. Silencing log output is
not equivalent to fixing the HAL. Preserve Wi-Fi, bluetooth coexistence,
and working Build 9 performance.

## MIUI Firewall
Do **not** remove `MIUISecurityCenterGlobalPad`, its native libraries,
provider declarations, permission XML or its DEX and resign it with a
different certificate. Such an operation can break system-UID and
signature-level permissions. A real fix requires locating the precise
initialization path and a compatible, correctly signed upstream APK/
source patch; not identified yet. Check repeatability after Wi-Fi
settles before accepting any firmware intervention.

## Read-only user diagnostics
```bash
adb shell cmd overlay lookup --user 0 android android:string/config_systemGallery
adb shell dumpsys role | grep -A4 -B3 SYSTEM_GALLERY
adb shell dumpsys wifi | grep -E 'L3ConnectedState|mIfaceIsUp|mAuthFailure'
adb shell pm path com.miui.securitycenter
adb shell getprop ro.product.device
```

**No Build 10/Final firmware** has been released or proven. Build 9 remains
the last device-boot-confirmed version.
