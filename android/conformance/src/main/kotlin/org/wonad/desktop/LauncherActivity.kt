package org.wonad.desktop

import android.app.Activity
import android.graphics.Canvas
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Display
import android.view.Gravity
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.TextView

/** Exact launcher facade. It displays only the already-bounded catalogue ID;
 * the runner cancels it through selectLauncher(-1) without launching an app. */
class LauncherActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private var expectedCatalog = 0L
    private val watch = object : Runnable {
        override fun run() {
            if (ConformanceRegistry.launcher()?.catalogId != expectedCatalog) finish()
            else handler.postDelayed(this, 100)
        }
    }
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val catalog = intent.getLongExtra(ConformanceContract.LAUNCHER_CATALOG, 0)
        val generation = intent.getLongExtra(ConformanceContract.LAUNCHER_GENERATION, 0)
        val displayId = display?.displayId ?: Display.INVALID_DISPLAY
        val claim = ConformanceRegistry.launcher()
        val valid = displayId > Display.DEFAULT_DISPLAY && catalog > 0 && generation > 0 &&
            claim?.catalogId == catalog && claim.generation == generation && claim.displayId == displayId
        if (!valid) { ConformanceRegistry.record("LauncherActivity", false, displayId); finish(); return }
        expectedCatalog = catalog
        title = "Wonad conformance launcher"
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.setDecorFitsSystemWindows(false)
        setContentView(object : TextView(this) {
            private var recorded = false
            init {
                text = getString(R.string.launcher_status, catalog)
                setTextColor(Color.WHITE); setBackgroundColor(Color.BLACK); gravity = Gravity.CENTER
            }
            override fun onDraw(canvas: Canvas) {
                super.onDraw(canvas)
                if (!recorded) { recorded = true; ConformanceRegistry.record("LauncherActivity", true, displayId) }
            }
        })
        window.insetsController?.hide(WindowInsets.Type.systemBars())
        handler.post(watch)
    }
    override fun onDestroy() { handler.removeCallbacks(watch); super.onDestroy() }
}
