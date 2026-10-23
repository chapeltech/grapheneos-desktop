package org.wonad.fixture

import android.app.Activity
import android.app.ActivityManager.TaskDescription
import android.content.res.Configuration
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileDescriptor
import java.io.PrintWriter

/** Ordinary RGB bands in actual physical View pixels; no fonts/CSD/animation. */
abstract class BandedPaletteActivity : Activity() {
    protected abstract val client: String
    protected abstract val bands: IntArray
    private val ledger = PaletteProbeLedger()
    private val paint = Paint().apply { isAntiAlias = false; isDither = false }
    @Volatile private var observation = "{}"
    private var lifecycle = "created"
    private var topResumed = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setTaskDescription(TaskDescription(javaClass.name))
        require(bands.size == 3)
        window.setDecorFitsSystemWindows(false)
        window.setBackgroundDrawable(ColorDrawable(bands[0]))
        setContentView(object : View(this) {
            init {
                isFocusableInTouchMode = true
                // Keep real keyboard focus, without View.draw's theme ripple over the RGB bands.
                setDefaultFocusHighlightEnabled(false)
            }
            override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
                super.onSizeChanged(w, h, oldw, oldh)
                if (w > 0 && h > 0) ledger.configured(w, h)
                record("configure")
            }
            override fun onDraw(canvas: Canvas) {
                val edges = intArrayOf(0, height / 3, height * 2 / 3, height)
                for (index in 0..2) {
                    paint.color = bands[index]
                    canvas.drawRect(0f, edges[index].toFloat(), width.toFloat(), edges[index + 1].toFloat(), paint)
                }
                ledger.drawn(); record("draw")
            }
            override fun onTouchEvent(event: MotionEvent): Boolean {
                if (event.actionMasked == MotionEvent.ACTION_UP) performClick()
                return true
            }
            override fun performClick(): Boolean { super.performClick(); return true }
        })
        record("created")
    }
    override fun onResume() { super.onResume(); lifecycle = "resumed"; record("resume") }
    override fun onPause() { lifecycle = "paused"; record("pause"); super.onPause() }
    override fun onStop() { lifecycle = "stopped"; record("stop"); super.onStop() }
    override fun onConfigurationChanged(newConfig: Configuration) { super.onConfigurationChanged(newConfig); record("configuration") }
    override fun onWindowFocusChanged(hasFocus: Boolean) { super.onWindowFocusChanged(hasFocus); ledger.focused(hasFocus); record("focus") }
    override fun onTopResumedActivityChanged(isTopResumedActivity: Boolean) {
        super.onTopResumedActivityChanged(isTopResumedActivity)
        topResumed = isTopResumedActivity; record("top_resumed")
    }
    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        if (event.action == KeyEvent.ACTION_DOWN) { ledger.keyDown(event.keyCode); record("key") }
        return true
    }
    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_DOWN) {
            ledger.pointerDown(event.source, event.isFromSource(InputDevice.SOURCE_MOUSE)); record("pointer")
        }
        return super.dispatchTouchEvent(event)
    }
    private fun record(event: String) {
        val actual = ledger.snapshot()
        val bounds = windowManager.currentWindowMetrics.bounds
        observation = JSONObject().put("client", client).put("component", componentName.flattenToShortString())
            .put("bands", JSONArray(bands.map { String.format("%06x", it and 0xffffff) }))
            .put("instance", actual.instance).put("pid", Process.myPid()).put("uid", Process.myUid())
            .put("task", taskId).put("display", display?.displayId ?: -1)
            .put("left", bounds.left).put("top", bounds.top).put("right", bounds.right).put("bottom", bounds.bottom)
            .put("width", actual.width).put("height", actual.height).put("configurations", actual.configurations).put("draws", actual.draws)
            .put("focused", actual.focused).put("top_resumed", topResumed).put("key_downs", actual.keyDowns).put("last_key", actual.lastKey)
            .put("pointer_downs", actual.pointerDowns).put("mouse_downs", actual.mouseDowns).put("last_pointer_source", actual.lastPointerSource)
            .put("lifecycle", lifecycle).put("event", event).toString()
        Log.i("WonadBandedPalette", "WONAD_BANDED_PALETTE $observation")
    }
    override fun dump(prefix: String, fd: FileDescriptor?, writer: PrintWriter, args: Array<out String>?) {
        super.dump(prefix, fd, writer, args)
        writer.println(prefix + "WONAD_BANDED_PALETTE " + observation)
    }
}

class BandedOneActivity : BandedPaletteActivity() {
    override val client = "one"
    override val bands = intArrayOf(0xffcc4422.toInt(), 0xffff8844.toInt(), 0xffffc488.toInt())
}
class BandedTwoActivity : BandedPaletteActivity() {
    override val client = "two"
    override val bands = intArrayOf(0xff22aa66.toInt(), 0xff66dd88.toInt(), 0xffaaffcc.toInt())
}
class BandedThreeActivity : BandedPaletteActivity() {
    override val client = "three"
    override val bands = intArrayOf(0xff7744bb.toInt(), 0xffaa77ee.toInt(), 0xffddbbff.toInt())
}
class BandedFourActivity : BandedPaletteActivity() {
    override val client = "four"
    override val bands = intArrayOf(0xff2266cc.toInt(), 0xff55aaff.toInt(), 0xff99ddff.toInt())
}
class BandedFiveActivity : BandedPaletteActivity() {
    override val client = "five"
    override val bands = intArrayOf(0xffccaa22.toInt(), 0xffffdd55.toInt(), 0xffffffaa.toInt())
}
