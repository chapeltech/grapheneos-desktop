package org.wonad.desktop.api;
import org.wonad.desktop.api.DesktopPlacement;
import org.wonad.desktop.api.DesktopShellRegion;

/** Complete placement request. Workspace assignment, floating policy, borders
 * and panels belong solely to the APK. */
parcelable DesktopFrame {
    long topologyRevision;
    // Both zero retain focus; nonzero display/zero task focuses empty desktop.
    long focusedDisplayToken;
    long focusedToken;
    DesktopPlacement[] placements;
    DesktopShellRegion[] shellRegions;
}
