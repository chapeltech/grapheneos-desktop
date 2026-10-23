package org.wonad.desktop.api;
import org.wonad.desktop.api.DesktopRect;

/** Opaque broker identity, never Android taskId or WindowContainerToken. */
parcelable DesktopTask {
    long token;
    long displayToken;
    DesktopRect bounds;
    int minimumWidth;
    int minimumHeight;
    boolean resizable;
    boolean visible;
    boolean inputEnabled;
    int zOrder;
    String title;
    String packageName;
}
