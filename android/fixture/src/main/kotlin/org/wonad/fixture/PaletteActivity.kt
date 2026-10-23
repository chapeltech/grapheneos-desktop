package org.wonad.fixture

import android.app.Activity
import android.app.ActivityManager.TaskDescription
import android.content.res.Configuration
import android.graphics.Canvas
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import org.json.JSONObject
import java.io.FileDescriptor
import java.io.PrintWriter

/** Ordinary opaque Activity; no text, shader, inset, animation or privilege. */
abstract class PaletteActivity : Activity() {
    protected abstract val palette: Int
    private val ledger = PaletteProbeLedger()
    @Volatile private var observation = "{}"
    private var lifecycle = "created"
    private var topResumed = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setTaskDescription(TaskDescription(javaClass.name))
        window.setDecorFitsSystemWindows(false)
        window.setBackgroundDrawable(ColorDrawable(palette))
        setContentView(object : View(this) {
            init { isFocusableInTouchMode = true }
            override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
                super.onSizeChanged(w, h, oldw, oldh)
                if (w > 0 && h > 0) ledger.configured(w, h)
                record("configure")
            }
            override fun onDraw(canvas: Canvas) {
                // Same opaque RGB bytes as the independent Linux SHM client.
                canvas.drawColor(palette)
                ledger.drawn()
                record("draw")
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
    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig); record("configuration")
    }
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus); ledger.focused(hasFocus); record("focus")
    }
    override fun onTopResumedActivityChanged(isTopResumedActivity: Boolean) {
        super.onTopResumedActivityChanged(isTopResumedActivity)
        topResumed = isTopResumedActivity; record("top_resumed")
    }
    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        if (event.action == KeyEvent.ACTION_DOWN) { ledger.keyDown(event.keyCode); record("key") }
        // This palette has no launcher commands or keyboard text/IME policy.
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
        observation = JSONObject().put("component", componentName.flattenToShortString())
            .put("instance", actual.instance).put("pid", Process.myPid()).put("uid", Process.myUid())
            .put("task", taskId).put("display", display?.displayId ?: -1)
            .put("left", bounds.left).put("top", bounds.top).put("right", bounds.right).put("bottom", bounds.bottom)
            .put("width", actual.width).put("height", actual.height)
            .put("configurations", actual.configurations).put("draws", actual.draws)
            .put("focused", actual.focused).put("top_resumed", topResumed)
            .put("key_downs", actual.keyDowns).put("last_key", actual.lastKey)
            .put("pointer_downs", actual.pointerDowns).put("mouse_downs", actual.mouseDowns)
            .put("last_pointer_source", actual.lastPointerSource)
            .put("color", String.format("%06x", palette and 0xffffff))
            .put("lifecycle", lifecycle).put("event", event).toString()
        Log.i("WonadPalette", "WONAD_PALETTE $observation")
    }
    override fun dump(prefix: String, fd: FileDescriptor?, writer: PrintWriter, args: Array<out String>?) {
        super.dump(prefix, fd, writer, args)
        writer.println(prefix + "WONAD_PALETTE " + observation)
    }
}

class PaletteOneActivity : PaletteActivity() { override val palette = 0xffcc4422.toInt() }
class PaletteTwoActivity : PaletteActivity() { override val palette = 0xff22aa66.toInt() }
