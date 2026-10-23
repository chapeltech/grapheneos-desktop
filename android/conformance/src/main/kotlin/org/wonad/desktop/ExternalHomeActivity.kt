package org.wonad.desktop

import android.app.Activity
import android.graphics.Canvas
import android.graphics.Color
import android.os.Bundle
import android.view.Display
import android.view.View
import android.view.WindowInsets
import android.view.WindowManager

/** Exact fixed secondary HOME facade. It contains no layout policy. */
class ExternalHomeActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val displayId = display?.displayId ?: Display.INVALID_DISPLAY
        val valid = displayId > Display.DEFAULT_DISPLAY && ConformanceRegistry.expectedDisplay(displayId)
        if (!valid) {
            ConformanceRegistry.record("ExternalHomeActivity", false, displayId); finish(); return
        }
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.setDecorFitsSystemWindows(false)
        setContentView(object : View(this) {
            private var recorded = false
            override fun onDraw(canvas: Canvas) {
                canvas.drawColor(Color.BLACK)
                if (!recorded) { recorded = true; ConformanceRegistry.record("ExternalHomeActivity", true, displayId) }
            }
        })
        window.insetsController?.hide(WindowInsets.Type.systemBars())
    }
}
