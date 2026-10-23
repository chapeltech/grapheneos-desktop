package org.wonad.desktop.api;
import org.wonad.desktop.api.DesktopLaunchEntry;

/** At most MAX_LAUNCH_PAGE entries; no Intent, UID or native window handle. */
parcelable DesktopLaunchPage {
    long generation;
    long catalogId;
    long displayToken;
    int offset;
    int totalEntries;
    long expiresAt;
    DesktopLaunchEntry[] entries;
}
