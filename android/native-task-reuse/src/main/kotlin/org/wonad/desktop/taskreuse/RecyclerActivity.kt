package org.wonad.desktop.taskreuse

import android.app.Activity
import android.content.res.Configuration
import android.os.Bundle
import android.os.Process
import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent
import android.widget.TextView
import java.io.FileDescriptor
import java.io.PrintWriter
import java.util.UUID
import org.json.JSONObject

/** Ordinary opaque app UI. Observations count genuine delivered hardware
 * events, forward every Android callback, and never set native window state. */
class RecyclerActivity : Activity() {
    private val instance = UUID.randomUUID().toString()
    private var keys = 0; private var mouse = 0; private var pointers = 0
    private var lastKey = 0; private var top = false; private var configurations = 0
    @Volatile private var observation = "{}"
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setContentView(TextView(this).apply {
            setBackgroundColor(0xff228844.toInt()); setTextColor(0xffeeeeee.toInt())
            text = "Ordinary task recycler\nClick below and type B."; textSize = 24f
            isFocusableInTouchMode = true; requestFocus()
            addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ -> record() }
        })
        record()
    }
    override fun onResume() { super.onResume(); record() }
    override fun onPause() { super.onPause(); record() }
    override fun onConfigurationChanged(configuration: Configuration) {
        super.onConfigurationChanged(configuration); configurations++; record()
    }
    override fun onWindowFocusChanged(focused: Boolean) { super.onWindowFocusChanged(focused); record() }
    override fun onTopResumedActivityChanged(resumed: Boolean) { super.onTopResumedActivityChanged(resumed); top = resumed; record() }
    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        if (event.action == KeyEvent.ACTION_DOWN) { keys++; lastKey = event.keyCode; record() }
        return super.dispatchKeyEvent(event)
    }
    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_DOWN) {
            pointers++; if (event.isFromSource(InputDevice.SOURCE_MOUSE)) mouse++; record()
        }
        return super.dispatchTouchEvent(event)
    }
    private fun record() {
        val bounds = windowManager.currentWindowMetrics.bounds
        observation = JSONObject().put("component", componentName.flattenToShortString()).put("instance", instance)
            .put("task", taskId).put("display", display?.displayId ?: -1).put("uid", Process.myUid()).put("pid", Process.myPid())
            .put("role", intent.getStringExtra("role")).put("run", intent.getStringExtra("run"))
            .put("bounds", org.json.JSONArray(listOf(bounds.left,bounds.top,bounds.right,bounds.bottom)))
            .put("focused", hasWindowFocus()).put("top_resumed", top).put("key_downs", keys).put("last_key", lastKey)
            .put("mouse_downs", mouse).put("pointer_downs", pointers).put("configurations", configurations).toString()
    }
    override fun dump(prefix: String, fd: FileDescriptor?, writer: PrintWriter, args: Array<out String>?) {
        super.dump(prefix, fd, writer, args)
        writer.println(prefix + "WONAD_REUSE_OBSERVATION " + observation)
    }
}
