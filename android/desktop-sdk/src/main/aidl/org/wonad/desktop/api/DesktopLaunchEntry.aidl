package org.wonad.desktop.api;

/** Display text and an index into an OS-owned, short-lived catalogue. */
parcelable DesktopLaunchEntry {
    int index;
    String label;
    String component;
}
