# Security Center versus Build 9 removal list — completed stock APK audit

**Audit:** [successful GitHub Actions run 40281949482](https://github.com/hashyofficial/copilot_workflow/actions/runs/40281949482) (2026-10-26). This is forensic analysis **only**, not a patch, firmware or proof of runtime requirements.

## Provenance

The workflow independently downloaded Xiaomi MIUI 14 V14.0.4.0.TLYMIXM fastboot stock ROM, verified the pinned original archive MD5, reconstructed the sparse original super image, and mounted original `product_a`, `system_a`, `system_ext_a` EROFS read-only.

It verified all **94 removed** and **16 deliberately retained** app-folder APK identities with `aapt`; extracted the *original* `com.miui.securitycenter` at `/product/priv-app/MIUISecurityCenterGlobalPad`, and inspected **165,348 DEX strings** across its `classes*.dex` files.

Raw reports, including `securitycenter-dependency-references.json`, `stock-package-locations.json`, and `all_110_stock_apks.tsv`, are attached to the Actions run as artifact `build9-securitycenter-dependency-analysis` (GitHub artifact expires under the project's retention rules).

## Results

**35 removed Android package IDs appear as exact constants in the OEM Security Center DEX.** Only two additionally resemble binary class-name references. A DEX `const-string` or type reference alone does *not* prove that another app must be installed, that code is executed, or that the app is a required boot/runtime dependency.

Full exact-match list (35):

```text
com.android.apps.tag
com.android.chrome
com.android.phone
com.android.providers.telephony
com.android.server.telecom
com.android.soundrecorder
com.android.stk
com.android.updater
com.google.android.apps.docs
com.google.android.apps.googleassistant
com.google.android.apps.magazines
com.google.android.apps.maps
com.google.android.apps.photos
com.google.android.apps.subscriptions.red
com.google.android.apps.tachyon
com.google.android.apps.wellbeing
com.google.android.googlequicksearchbox
com.google.android.marvin.talkback
com.google.android.printservice.recommendation
com.google.android.videos
com.google.android.youtube
com.mi.globalbrowser
com.milink.service
com.miui.analytics
com.miui.bugreport
com.miui.fmservice
com.miui.gallery
com.miui.miservice
com.miui.mishare.connectivity
com.miui.msa.global
com.miui.notes
com.miui.screenrecorder
com.miui.videoplayer
com.miui.weather2
com.xiaomi.payment
```

`com.milink.service` and `com.miui.analytics` also show DEX class-name references. This still does NOT make them proven mandatory external libraries.

Some explicit constants for deleted apps:

- `com.miui.gallery`, `content://com.miui.gallery.open`, `com.miui.gallery.cloud.provider` — expected stale media/gallery integration.
- `com.miui.bugreport.ui.FeedbackActivity` — removed OEM feedback destination.
- `content://com.miui.analytics.OneTrackProvider/insId` — removed OEM analytics provider.
- `com.miui.miservice` — deleted MIService package that `com.android.settings.MiuiSettings.getFeedbackSettingsLabel` also queries in logcat.
- `com.android.phone`, `com.android.providers.telephony`, `com.android.server.telecom` — deleted optional telephony stack; relevant *hypothesis* for a Wi-Fi-only device's mobile-rule paths, not proven cause of the firewall exception.

### Required shared Android libraries

OEM Security Center's own `aapt dump badging` reports **no required external shared-library declaration**. Its six `uses-library-not-required` declarations are:

```text
micloud-sdk
android-support-v7-recyclerview.jar
protobuf.jar
security-device-credential-sdk.jar
org.apache.http.legacy
com.miui.system
```

The user's Build 9 `dumpsys package com.miui.securitycenter` shows several of these resolved (including `micloud-sdk`, `security-device-credential-sdk.jar`, `org.apache.http.legacy`, `com.miui.system`). No removed Build 9 app was identified as a *mandatory* `uses-library` dependency.

### Why firewall error remains unproven as a removed-app dependency

Build 9 logcat 200× error:

```
com.miui.securitycenter.service.ConnectivityChangeJobService2
  -> NetworkAssistantProvider.queryMobileRule
  -> FirewallService.getMobileRule
  -> MiuiNetdFirewall.getTempMobileRule
  -> NullPointerException (ArrayMap field null)
```

The failure also occurs for **present packages** such as `com.google.android.networkstack.tethering`; it's not necessarily caused by a deleted package being queried.

Build 7 and 8 captures have 0 observed `getTempMobileRule` exceptions, but also no observed `ConnectivityChangeJobService2` jobs; they do not exclude a pre-existing bug that was not exercised.

Therefore no single deleted app can yet be named the proven fix. The removed telephony stack and uninitialized mobile-rule maps are hypotheses only. Restoring all 35 referenced apps would defeat debloating without compelling evidence.

### Secondary installation discrepancy

The retained `MiuiScanner` app's *original* APK (stock identity `com.xiaomi.scanner`) is on the Build 9 keep list, but the runtime logcat shows `AppOpsAdapter` `NameNotFoundException: com.xiaomi.scanner`. Retaining a preloaded APK directory under `/product/data-app` does not itself confirm it was actually installed/enabled for user 0. Check on the live device:

```bash
adb shell pm path com.xiaomi.scanner
adb shell pm list packages -u | grep -F com.xiaomi.scanner
```

This scanner discrepancy is in a **separate** permission manager, not the mobile firewall stack trace.

## Safety decision

- **No change** to working Build 9, full firmware or its GitHub release.
- **No evidence** for deleting Security Center, `.so` files, telephony config or changing its `AndroidManifest.xml`.
- Prioritize checking whether the firewall exception recurs after settled network initialization; do not claim restoration of any deleted package is the fix without A/B evidence.
