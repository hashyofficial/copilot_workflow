#!/usr/bin/env python3
"""MIUI 14 Build 11: remove ONLY 20 Google + 6 MTK/diagnostic app folders.

Source of image bytes: MD5-verified Xiaomi original V14.0.4.0.TLYMIXM.
NOT derived from Build 9/10's modified super, policy, or release.
Every other original APK, native library, overlay, property and APEX is kept.
"""
from pathlib import PurePosixPath

GOOGLE = (
    "product_a:/data-app/Drive/Drive.apk",
    "product_a:/data-app/Meet/Meet.apk",
    "product_a:/data-app/GoogleNews/GoogleNews.apk",
    "product_a:/data-app/Podcasts/Podcasts.apk",
    "product_a:/data-app/Photos/Photos.apk",
    "product_a:/data-app/Videos/Videos.apk",
    "product_a:/data-app/YTMusic/YTMusic.apk",
    "product_a:/app/GoogleOne/GoogleOne.apk",
    "product_a:/app/Maps/Maps.apk",
    "product_a:/app/YouTube/YouTube.apk",
    "product_a:/app/GoogleLocationHistory/GoogleLocationHistory.apk",
    "product_a:/priv-app/GoogleAssistant/GoogleAssistant.apk",
    "product_a:/priv-app/Velvet/Velvet.apk",
    "product_a:/priv-app/HotwordEnrollmentOKGoogleRISCV/HotwordEnrollmentOKGoogleRISCV.apk",
    "product_a:/priv-app/HotwordEnrollmentXGoogleRISCV/HotwordEnrollmentXGoogleRISCV.apk",
    "product_a:/priv-app/Wellbeing/Wellbeing.apk",
    "system_ext_a:/priv-app/GoogleFeedback/GoogleFeedback.apk",
    "system_a:/system/app/GooglePrintRecommendationService/GooglePrintRecommendationService.apk",
    "product_a:/app/SpeechServicesByGoogle/SpeechServicesByGoogle.apk",
    "product_a:/app/talkback/talkback.apk",
)
DIAGNOSTIC = (
    "system_a:/system/priv-app/EngineerMode/EngineerMode.apk",
    "system_a:/system/priv-app/YGPS/YGPS.apk",
    "system_a:/system/app/LocationEM2/LocationEM2.apk",
    "system_a:/system/app/MDMLSample/MDMLSample.apk",
    "system_a:/system/app/CatchLog/CatchLog.apk",
    "system_a:/system/app/DebugLoggerUI/DebugLoggerUI.apk",
)
# Explicit package-ID checks only where original inventory established them.
KNOWN_PACKAGE_IDS = {
    "product_a:/data-app/Meet/Meet.apk": "com.google.android.apps.tachyon",
    "product_a:/data-app/Photos/Photos.apk": "com.google.android.apps.photos",
    "product_a:/priv-app/GoogleAssistant/GoogleAssistant.apk": "com.google.android.apps.googleassistant",
    "product_a:/priv-app/Velvet/Velvet.apk": "com.google.android.googlequicksearchbox",
    "product_a:/priv-app/HotwordEnrollmentOKGoogleRISCV/HotwordEnrollmentOKGoogleRISCV.apk": "com.android.hotwordenrollment.okgoogle",
    "product_a:/priv-app/HotwordEnrollmentXGoogleRISCV/HotwordEnrollmentXGoogleRISCV.apk": "com.android.hotwordenrollment.xgoogle",
    "product_a:/priv-app/Wellbeing/Wellbeing.apk": "com.google.android.apps.wellbeing",
    "system_ext_a:/priv-app/GoogleFeedback/GoogleFeedback.apk": "com.google.android.feedback",
    "product_a:/app/SpeechServicesByGoogle/SpeechServicesByGoogle.apk": "com.google.android.tts",
    "product_a:/app/talkback/talkback.apk": "com.google.android.marvin.talkback",
    "system_a:/system/priv-app/EngineerMode/EngineerMode.apk": "com.mediatek.engineermode",
    "system_a:/system/priv-app/YGPS/YGPS.apk": "com.mediatek.ygps",
    "system_a:/system/app/MDMLSample/MDMLSample.apk": "com.mediatek.mdmlsample",
}
PRESERVE_APPS = {
    "product_a:/priv-app/Gallery_T_Global/Gallery_T_Global.apk": "com.miui.gallery",
    "product_a:/app/MIUIVideoPlayer/MIUIVideoPlayer.apk": "com.miui.videoplayer",
    "product_a:/priv-app/MIUISecurityCenterGlobalPad/MIUISecurityCenterGlobalPad.apk": "com.miui.securitycenter",
    "product_a:/app/CalendarGoogle/CalendarGoogle.apk": "com.google.android.calendar",
}
# Preserve these standalone JNI files and the full parent lib folders.
MIRAVISION_JNI = (
    "/system/lib/libMiraVision_jni.so",
    "/system/lib64/libMiraVision_jni.so",
)
def build11_targets():
    items = GOOGLE + DIAGNOSTIC
    if len(GOOGLE) != 20 or len(DIAGNOSTIC) != 6 or len(set(items)) != 26:
        raise RuntimeError("Build 11 exact 20 Google + 6 diagnostics policy changed")
    if set(items) & set(PRESERVE_APPS):
        raise RuntimeError("Unsafe protected/removed policy overlap")
    targets={}
    folders=set()
    for loc in items:
        part, apk = loc.split(":",1)
        p=PurePosixPath(apk)
        if part not in ("product_a","system_a","system_ext_a") or not p.is_absolute() or ".." in p.parts or p.suffix!=".apk" or len(p.parts)<4:
            raise RuntimeError("Unsafe unreviewed app folder "+loc)
        key=(part,p.parent)
        if key in folders: raise RuntimeError("Duplicate app folder "+loc)
        folders.add(key)
        targets[loc]=(part,p)
    for loc in PRESERVE_APPS:
        part,apk=loc.split(":",1)
        assert (part,PurePosixPath(apk).parent) not in folders
    return targets,dict(KNOWN_PACKAGE_IDS),dict(PRESERVE_APPS),{}
