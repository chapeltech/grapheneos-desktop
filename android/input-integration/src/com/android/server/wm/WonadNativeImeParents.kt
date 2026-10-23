package com.android.server.wm

import android.view.Display

/** WM-lock-only readiness for stock IME parent recomputation, not reparenting.
 * A native launcher can disappear before the ordinary editor input target
 * arrives. An unchanged remote control target must not retain that removed
 * Activity surface as the parent of the IME container and system chooser. */
internal object WonadNativeImeParents {
    @JvmStatic fun needsParentUpdate(dc: DisplayContent, parent: WindowContainer<*>?): Boolean =
        dc.displayId != Display.DEFAULT_DISPLAY && dc.isAttached && !dc.isRemoved &&
            dc.mWmService.mRoot.getDisplayContent(dc.displayId) === dc &&
            WonadUiBridge.nativeMode(dc) && !dc.imeContainer.isOrganized &&
            parent != null && parent.surfaceControl == null
}
