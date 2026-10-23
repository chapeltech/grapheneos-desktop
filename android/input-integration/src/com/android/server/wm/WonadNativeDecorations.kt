package com.android.server.wm

import android.view.Display
import android.view.WindowManager
import java.util.function.Consumer

/** WM-lock-only stock decoration boundary. No workspace or APK UI policy. */
internal object WonadNativeDecorations {
    /** Use the root/base type, so stock children cannot evade this boundary
     * by requesting TYPE_APPLICATION_PANEL. Ordinary Wonad application panels,
     * IME and trusted dialogs are not stock decorations. */
    @JvmStatic fun rejects(dc: DisplayContent, baseType: Int): Boolean =
        dc.displayId != Display.DEFAULT_DISPLAY &&
            dc.mWmService.mRoot.getDisplayContent(dc.displayId) === dc &&
            WonadUiBridge.nativeMode(dc) && when (baseType) {
                WindowManager.LayoutParams.TYPE_STATUS_BAR,
                WindowManager.LayoutParams.TYPE_NOTIFICATION_SHADE,
                WindowManager.LayoutParams.TYPE_NAVIGATION_BAR,
                WindowManager.LayoutParams.TYPE_NAVIGATION_BAR_PANEL,
                WindowManager.LayoutParams.TYPE_STATUS_BAR_ADDITIONAL,
                WindowManager.LayoutParams.TYPE_STATUS_BAR_SUB_PANEL -> true
                else -> false
            }

    /** Retire actual pre-takeover windows, not merely their pixels. Copy the
     * exact display traversal before removal, and revalidate every native
     * object. The ordinary removal path disposes input channels; immediate
     * completion is necessary for an already-running stock exit animation.
     * Both server removal and the later normal client stop are idempotent. */
    @JvmStatic fun retire(dc: DisplayContent) {
        WonadNativeWallpapers.retire(dc)
        val stock = mutableListOf<WindowState>()
        dc.forAllWindows(Consumer { window ->
            if (!window.mRemoved && window.displayContent === dc && rejects(dc, window.baseType)) stock.add(window)
        }, true)
        stock.forEach { window ->
            if (!window.mRemoved && window.displayContent === dc && rejects(dc, window.baseType)) {
                window.cancelAnimation()
                window.hide(false, false)
                window.removeIfPossible()
                if (!window.mRemoved && window.displayContent === dc && rejects(dc, window.baseType))
                    window.removeImmediately()
            }
        }
    }
}
