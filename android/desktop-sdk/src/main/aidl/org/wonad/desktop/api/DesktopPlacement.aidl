package org.wonad.desktop.api;
import org.wonad.desktop.api.DesktopRect;

parcelable DesktopPlacement {
    long token;
    long destinationDisplayToken;
    DesktopRect bounds;
    boolean visible;
    boolean inputEnabled;
    // Complete unique sequence 0..taskCount-1; larger numbers are above.
    int zOrder;
}
