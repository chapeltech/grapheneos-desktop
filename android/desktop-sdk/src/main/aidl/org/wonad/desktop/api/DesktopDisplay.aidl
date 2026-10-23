package org.wonad.desktop.api;
import org.wonad.desktop.api.DesktopRect;

/** OS observation of an authorized external monitor, never the phone. */
parcelable DesktopDisplay {
    long token;
    int displayId;
    DesktopRect bounds;
    int densityDpi;
    boolean secure;
    // Zero until the fixed APK shell has drawn on this exact display.
    long shellGeneration;
    // Opaque, epoch/user-scoped physical identity hint; never authority.
    long identityHint;
}
