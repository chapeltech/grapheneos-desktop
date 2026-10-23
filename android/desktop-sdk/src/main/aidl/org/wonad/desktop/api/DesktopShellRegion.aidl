package org.wonad.desktop.api;
import org.wonad.desktop.api.DesktopRect;

/** Touchable rectangle for the OS-resolved fixed external shell Activity. */
parcelable DesktopShellRegion {
    long generation;
    long displayToken;
    DesktopRect bounds;
}
