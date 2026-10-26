# MIUI 14 Build 9: source-level repair gates (no log suppression)

Baseline: Redmi Pad / yunluo / MIUI 14 V14.0.4.0.TLYMIXM Build 9 (device-booted).
Keep original Build 9 release/branch untouched. All experiments require isolated
research branch, binary identity audit, a stock firmware backup and reversible
on-device test. Do **not** ship a firmware revision that only removes diagnostics.

## Goal and stop conditions

Treat runtime breakage as a failure; treat standalone warnings as evidence for
investigation. Success is reliable hardware, no new FC/ANR/SELinux denials,
functioning Photon Gallery, Calendar, connectivity, OTA-disabled verified
fastboot and no reproducible critical crashes across reboot, network transition,
idle and app launch. "Zero logcat E lines" is **not** a release criterion:
vendor HALs and third-party apps may write errors without an actionable defect.

## Target A: MIUI Network Assistant / Security Center

- Package: `com.miui.securitycenter`, product privileged app
  `/product/priv-app/MIUISecurityCenterGlobalPad`. Package UID is `android.uid.system/1000`;
  certificate is Xiaomi stock.
- Stack: `ConnectivityChangeJobService2 -> ExtraNetwork.isMobileRestrict ->
  NetworkAssistantProvider.queryMobileRule -> FirewallService.getMobileRule ->
  MiuiNetdFirewall.getTempMobileRule -> ArrayMap.get(null)`.
- Next investigation: decompile only ORIGINAL APK from MD5-verified stock; inspect
  `MiuiNetdFirewall` constructor and all writes to the member read in
  `getTempMobileRule`. Correlate field initialization with network change,
  mobile/SIM capability, Settings provider and IPC lifecycle.
- Build 7 and 8 captures did not include an equivalent connectivity-change scan.
  A 200-occurrence Build 9 burst alone cannot attribute causality to debloat.
- Before considering a patch: reproduce the same action before and after with a
  controlled capture and device idle state. Compare `dumpsys activity service`
  and network state, not log E counts alone.
- A hypothetical Java guard `if (tempMobileRules == null) return DEFAULT`
  requires determining the correct DEFAULT behavior; returning "allow" or
  "deny" blindly can break the firewall.
- Re-signing this APK with a test certificate is NOT safe. Due to shared
  system UID / Xiaomi signature permissions, it may be rejected and break
  system features. No patched APK is approved absent a legitimate,
  signature-compatible delivery method.
- The original APK references 35 removed package IDs; none is proven a
  mandatory runtime dependency from DEX constants alone. Do NOT restore all 35.

## Target B: Gallery resource

- `dumpsys role`: `android.app.role.SYSTEM_GALLERY` holder empty.
- Live `cmd overlay lookup --user 0 android android:string/config_systemGallery`
  resolves `com.miui.gallery` (removed). Photon independently works.
- MD5-verified original `framework-res.apk` policy inspection (run
  40279553022) returned `gallery_rro_allowed=false` for product/public
  resource policy. Experimental unsigned/unprivileged overlay MUST NOT ship.
- A legitimate fix requires a signature-compatible framework build or a
  supported alternative verified against real resource policy. Do not
  repack/re-sign `framework-res.apk` based solely on hope that AVB flags=3
  disable PackageManager verification. They do not.
- Xiaomi Security Center's `DefaultAppModel` has an *independent*
  `com.miui.gallery` lookup. Even fixing framework config may not silence it.
- Don't give Photon the system-gallery privileged role just to suppress a log.

## Target C: MediaTek Wi-Fi HAL

- Build 7, 8 and 9 all show:
  `WifiCommand::requestResponse err=-14`, `wifi_get_link_stats` fail,
  `WifiVendorHal.getWifiLinkLayerStats_1_5_Internal ERROR_UNKNOWN`.
- Device is connected on `wlan0`, reported 433 Mbps, ~-50 dBm, and Android
  marked network VALIDATED; packet-level stats fallback exists in Android 13.
- This belongs to vendor Wi-Fi HAL/driver, **not MIUI Security Center** and not
  `framework-res.apk`.
- Next candidate requires matching exact MT6789 HAL binary, kernel module,
  firmware + driver source and verifying support bits and link-stats enable
  path. Do not swap random `vendor/lib*` libraries or disable wifi metrics
  as a fake "fix".
- Official AOSP WifiVendorHal Android 13 reference:
  https://android.googlesource.com/platform/packages/modules/Wifi/+/refs/tags/android-platform-13.0.0_r18/service/java/com/android/server/wifi/WifiVendorHal.java
- Android 13 ClientModeImpl fallback:
  https://android.googlesource.com/platform/packages/modules/Wifi/+/refs/heads/android13-release/service/java/com/android/server/wifi/ClientModeImpl.java

## Firmware integration gates for a future experimentally patched build

1. Dedicated new branch, never overwrite Build 9 release or successful ZIP.
2. Each change tied to an observed causal chain, precise component/file
   hash, and a regression test. One change per test build.
3. Preserve all unmodified EROFS file metadata, SELinux labels, owner UID/GID,
   LP super geometry, preserved native libraries, stock partitions, and original
   Build 9 APK removals / retained apps.
4. Validate APK signature compatibility and package scan **before boot**;
   if invalid, reject build and do not flash.
5. Boot and exercise Wi-Fi toggle/association, Photon view/media scan,
   Settings, Security Center app detail, app restrictions, Play,
   Calendar and idle power. Compare with baseline logs under same triggers.
6. Do not release "fixed" until affected functionality actually works and
   original failure is resolved, not hidden.

## Current status

Research reports and policy checks only. **No actual signed MIUI framework,
Security Center, or Wi-Fi HAL patch is available or device-verified**.
No Build 10 image has been prepared. Build 9 remains the verified baseline.

Useful sources:
- https://source.android.com/docs/core/runtime/rros
- https://source.android.com/docs/core/ota/sign_builds
- https://source.android.com/docs/core/ota/modular-system/wifi
