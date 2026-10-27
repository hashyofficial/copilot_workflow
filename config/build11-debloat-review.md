# Redmi Pad (yunluo) — Build 11 HyperOS Global debloat review

Source: official Xiaomi fastboot ROM `OS1.0.9.0.ULYMIXM` Android 14,
`yunluo_global_images_OS1.0.9.0.ULYMIXM_20250416.0000.00_14.0_global_f8dbb84a10.tgz`.
Verified archive MD5: `f8dbb84a10dc96a9d3ce9e78883e87f3`.
Read-only super image inventory from successful Actions run [40473373465](https://github.com/hashyofficial/copilot_workflow/actions/runs/40473373465).

## Goal and bounds

Conservative aggressive **optional-feature** cleanup for the **Wi-Fi-only** Redmi Pad.
Target stock dedicated app directories selected by exact observed Android package ID.
All app folders, related in-folder splits/OAT files are excluded together.
There are 80 user-approved package IDs mapped to 81 physical app directories.

No blanket deletion of framework/APEX modules, shared libraries, overlays,
privileged permission configs, vendor HAL binaries, modem services or app-data.
Removing an APK's containing folder is not proof that unrelated `.so` files belong
to it; do not delete generic libraries without source ownership evidence.

## Core protected
- Google Play Services, Play Store, Google Services Framework, Gboard, WebView,
  Trichrome, network stack, captive portal login, package installer and core Mainline modules
- MIUI Home launcher, SystemUI and its plugin, Xiaomi Security Center and
  security helpers, Settings/MISettings, Camera, Files, original Gallery
- ContactsProvider, CalendarProvider, Media/Download providers, Credential Manager,
  SettingsProvider, core permission/role services and required RROs
- Bluetooth extension and related framework, Wi-Fi HAL and overlays, PowerKeeper,
  DuraSpeed, Xiaomi system services, provisioning and trusted components
- Device setup, safety, supervision, managed provisioning, Family Link and
  Digital Wellbeing controls. A clean firmware must not remove protections.
- Telephony framework services remain to avoid violating platform/vendor dependencies
  even though the tablet has no SIM. Only optional SIM user interfaces and diagnostics
  are selected for removal.

## Optional features selected
- **Google**: Assistant, both hotword enrollment apps, search, Google speech/TTS,
  Android System Intelligence / Private Compute Services, Chrome, Gmail,
  Contacts app, Calendar app/sync, Drive, Photos, Maps, Google One, News,
  Podcasts, Meet, YouTube, YouTube Music, Google TV, Google feedback,
  and location-history application.
- **Xiaomi**: ads, analytics, bug reports, log collection, cloud services,
  account application, system-app updater and OTA interface, Mi Video,
  Mi Browser, Mi Home, Mi Share, WPS Viewer, Notes, Clock, Recorder,
  Screen Recorder, Calculator, Scanner, Weather, Mi Canvas, Mi Coin,
  Mi Link/Cast, Service & Feedback, Xiaomi cleaner UI, AI/voice features.
- **Engineering and optional interfaces**: test/logger UIs, modem test tools,
  voice unlock/voice command, recording-assistant UI, SIM Toolkit UI,
  carrier default app/Sim App Dialog, basic screensaver, Easter Egg,
  trace/debug interface, legacy bookmarks, optional print services,
  MusicFX, NFC tag UI, Dynamic System installation.

## Expected functional tradeoffs
- Voice assistant, voice typing, spoken Google TTS, hotword recognition gone.
- No browser in stock image (WebView remains; install a browser through Play).
- No local Calendar, Google Contacts UI, media streaming or cloud frontends.
- Printing, screen recording, sound recording, optional advanced audio FX,
  Xiaomi device-sharing, OTA and app-store updating UI removed.
- Xiaomi Security Center's cleaner shortcut and specific Settings links may show
  absent-package warnings. Do not claim all framework warnings are resolved.
- Core call and radio services deliberately preserved: removal of SIM UI alone
  will not erase every telephony-related code path.
- Stock Gallery retained because a MIUI framework default gallery reference
  was proven in the previous project. Gallery Editor and camera auxiliaries retained.

## Why no Google Module/AdServices APEX removal?

Most APEX runtime components are not standalone app folders and cannot safely be
deleted using this package-ID removal script. Core modular Android services require
consistent packaging and signatures, even when their names sound optional.

## Verification bar

- Read TXT list before downloading any firmware; refuse unknown or protected IDs
- MD5-verify official unmodified HyperOS fastboot source
- Derive all logical partition layouts and bounds from this exact stock super
- Reject removal if a folder contains an unrelated, unselected Android package
- Rebuild only EROFS partitions containing selected apps
- Validate EROFS images, preserved file contents and UID/GID/SELinux metadata
- Compare original LP metadata and all untouched super regions
- Verify raw/sparse roundtrip checksums; validate patched vbmeta flags
- Publish image parts and audit report *only* after offline validation
- **Do not claim physical boot success** without device verification

## Sources
- [Xiaomi Global stock firmware listing](https://mirom.ezbox.idv.tw/en/phone/YUNLUO/)
- [Android network stack modules](https://source.android.com/docs/core/ota/modular-system/networking)
- [Android PermissionController](https://source.android.com/docs/core/ota/modular-system/permissioncontroller)
- [Android runtime resource overlays](https://source.android.com/docs/core/runtime/rros)
- [Android Mainline module format](https://source.android.com/docs/core/ota/modular-system)
- [Xiaomi system-app removal warnings](https://www.mi.com/uk/support/article/KA-06740/)
