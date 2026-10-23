package org.wonad.desktop

import android.app.Activity
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Display
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.view.WindowManager

/** Pure lifecycle gate for the asynchronously attached ordinary child window.
 * Returning INSTALL reserves the only installation before any framework call,
 * so duplicate callbacks cannot create a second child. */
internal class ConformanceShellObserverLifecycle {
    enum class Action { STOP, RETRY, INSTALL }
    private enum class State { OPEN, INSTALLING, INSTALLED, TERMINAL }
    private var state = State.OPEN

    fun next(claimValid: Boolean, parentReady: Boolean): Action {
        if (state != State.OPEN) return Action.STOP
        if (!claimValid) { state = State.TERMINAL; return Action.STOP }
        if (!parentReady) return Action.RETRY
        state = State.INSTALLING
        return Action.INSTALL
    }

    fun installed() {
        check(state == State.INSTALLING) { "observer installation was not reserved" }
        state = State.INSTALLED
    }

    /** Returns whether this lifecycle owned an installed child to remove. */
    fun terminate(): Boolean {
        val remove = state == State.INSTALLED
        state = State.TERMINAL
        return remove
    }
}

/** Exact transparent shell facade. The OS supplies only the two frozen scalar
 * extras; this APK receives no Surface, InputChannel, task ID or WM handle. */
class ExternalShellActivity : Activity() {
    private val ui = Handler(Looper.getMainLooper())
    private val observerLifecycle = ConformanceShellObserverLifecycle()
    private var generation = 0L
    private var displayToken = 0L
    private var pointerObserver: View? = null
    private var shellOwner: AutoCloseable? = null
    private val installObserver = Runnable { installPointerObserver() }

    private fun currentClaim(): Boolean {
        val displayId = display?.displayId ?: Display.INVALID_DISPLAY
        val claim = ConformanceRegistry.display(displayToken)
        val uri = intent.data
        return displayId > Display.DEFAULT_DISPLAY && generation > 0 && displayToken > 0 &&
            claim?.generation == generation && claim.displayId == displayId &&
            uri?.scheme == "wonad-shell" && uri.host == generation.toString() &&
            uri.path == "/$displayToken"
    }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        generation = intent.getLongExtra(ConformanceContract.SHELL_GENERATION, 0)
        displayToken = intent.getLongExtra(ConformanceContract.SHELL_DISPLAY_TOKEN, 0)
        val displayId = display?.displayId ?: Display.INVALID_DISPLAY
        if (!currentClaim()) {
            observerLifecycle.terminate()
            ConformanceRegistry.record("ExternalShellActivity", false, displayId); finish(); return
        }
        val claim = ConformanceRegistry.DisplayClaim(generation, displayToken, displayId)
        try {
            shellOwner = ConformanceRegistry.ownShell(claim) {
                check(ui.post {
                    // This closure captures THIS immutable-generation Activity.
                    // No lookup by numeric display/token can select its successor.
                    ConformanceShellRetirement.complete(
                        { ui.removeCallbacks(installObserver); observerLifecycle.terminate() },
                        {
                            val observer = pointerObserver
                            pointerObserver = null
                            observer?.let { windowManager.removeViewImmediate(it) }
                        },
                        { finish() },
                    )
                }) { "original shell retirement scheduling rejected" }
            }
        } catch (_: IllegalStateException) { finish(); return }
        title = "Wonad conformance shell"
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE or
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL)
        window.setDecorFitsSystemWindows(false)
        setContentView(object : View(this) {
            override fun onDraw(canvas: Canvas) {
                canvas.drawColor(Color.TRANSPARENT)
            }
        })
        // The native fixed-role registry authenticates this exact ordinary
        // child before granting its SPY input bit. The APK requests no hidden
        // flag, overlay permission, Surface or InputChannel handle.
        ui.post(installObserver)
        window.insetsController?.hide(WindowInsets.Type.systemBars())
    }

    private fun installPointerObserver() {
        if (isFinishing || isDestroyed) {
            observerLifecycle.terminate()
            return
        }
        val valid = currentClaim()
        val parent = window.decorView.windowToken
        when (observerLifecycle.next(valid, parent != null)) {
            ConformanceShellObserverLifecycle.Action.STOP -> {
                if (!valid) {
                    ConformanceRegistry.record("ExternalShellActivity", false,
                        display?.displayId ?: Display.INVALID_DISPLAY)
                    finish()
                }
            }
            ConformanceShellObserverLifecycle.Action.RETRY ->
                ui.postDelayed(installObserver, 16)
            ConformanceShellObserverLifecycle.Action.INSTALL -> {
                val observer = object : View(this) {
                    private var recorded = false
                    init { setWillNotDraw(false) }
                    override fun onDraw(canvas: Canvas) {
                        canvas.drawColor(Color.TRANSPARENT)
                        if (!recorded) {
                            recorded = true
                            val current = currentClaim()
                            ConformanceRegistry.record("ExternalShellActivity", current,
                                display?.displayId ?: Display.INVALID_DISPLAY)
                            if (!current) finish()
                        }
                    }
                }
                val attributes = WindowManager.LayoutParams(
                    WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.TYPE_APPLICATION_PANEL,
                    WindowManager.LayoutParams.FLAG_SECURE or
                        WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                        WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                        WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                    PixelFormat.TRANSLUCENT,
                ).apply {
                    token = parent
                    gravity = Gravity.TOP or Gravity.LEFT
                    setTitle("Wonad pointer observer")
                }
                windowManager.addView(observer, attributes)
                pointerObserver = observer
                observerLifecycle.installed()
            }
        }
    }

    override fun onDestroy() {
        ui.removeCallbacks(installObserver)
        shellOwner?.close()
        shellOwner = null
        observerLifecycle.terminate()
        val observer = pointerObserver
        pointerObserver = null
        try {
            observer?.let { windowManager.removeViewImmediate(it) }
        } finally {
            super.onDestroy()
        }
    }
}
