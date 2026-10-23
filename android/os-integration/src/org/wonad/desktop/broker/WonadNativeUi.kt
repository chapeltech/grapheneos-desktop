package org.wonad.desktop.broker

import android.view.WindowManagerGlobal
import android.view.Display
import android.view.WindowManager
import java.util.function.Consumer
import java.util.function.Supplier

/** Stock Shell must not decorate or apply desktop/desk policy to a native
 * Wonad attachment. Observe WM's sticky ownership, not the APK session's
 * liveness: parked screens retain ownership until the actual display dies.
 * This runs on Shell's executor, never on InputDispatcher's thread.
 */
object WonadNativeUi {
    /** A null result is deliberately distinct from an affirmative unowned
     * result. Stock Shell may proceed only after WM says that the current
     * numeric display is unowned; a failed/absent/mismatched facade must not
     * recreate Android policy on a sticky native attachment. */
    private fun ownership(display: Int): Boolean? = try {
        WindowManagerGlobal.getWindowManagerService()?.isWonadNativeUiDisplay(display)
    } catch (error: Throwable) {
        if (error !is Exception && error !is LinkageError) throw error
        null
    }

    @JvmStatic fun owns(display: Int): Boolean =
        display > Display.DEFAULT_DISPLAY && ownership(display) == true

    /** Positive admission for stock task/desk/decoration policy. This differs
     * from [owns]: unknown ownership is neither owned nor safe for stock work. */
    @JvmStatic fun allowStockPolicy(display: Int): Boolean {
        if (display == Display.DEFAULT_DISPLAY) return true
        if (display < Display.DEFAULT_DISPLAY) return false
        return ownership(display) == false
    }

    /** A restarted SystemUI must not recreate a stock input spy on a parked
     * native attachment. Keep the phone's existing gesture path unchanged;
     * external input observation requires an affirmative unowned WM result.
     * This checks sticky physical-display ownership, not session readiness.
     */
    @JvmStatic fun allowStockGestures(display: Int): Boolean {
        return allowStockPolicy(display)
    }

    /** Queued stock decoration events may predate native takeover. Recheck the
     * exact sticky WM claim when consuming them and before constructing a bar;
     * a parked desktop is still Wonad-owned. The phone never depends on Binder.
     */
    @JvmStatic fun allowStockDecorations(display: Int): Boolean = allowStockGestures(display)

    /** WM can claim an external display after the stock precheck but before
     * admitting its navigation panel. Only a fresh affirmative native claim
     * explains that InvalidDisplayException; phone, ordinary and unknown
     * failures must retain the stock exception. A completed handler that loses
     * admission is disposed before the caller publishes it in its display map.
     * This is a client lifecycle boundary, not an atomic cross-service lock.
     */
    @JvmStatic fun <T> createStockGestureHandler(
        display: Int, factory: Supplier<T>, dispose: Consumer<T>
    ): T? {
        if (!allowStockGestures(display)) return null
        val handler = try {
            factory.get()
        } catch (failure: WindowManager.InvalidDisplayException) {
            if (display > Display.DEFAULT_DISPLAY && owns(display)) return null
            throw failure
        }
        if (!allowStockGestures(display)) {
            dispose.accept(handler)
            return null
        }
        return handler
    }
}
