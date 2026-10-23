package org.wonad.fixture

import android.app.Activity
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.os.Bundle
import android.os.Process
import android.view.KeyEvent
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject
import java.io.FileDescriptor
import java.io.PrintWriter
import java.util.UUID

/** Ordinary document task. It neither inherits the text-recording fixture nor requests privileges. */
abstract class KeyboardCaptureActivity : Activity() {
    protected abstract val captureRole: String
    private val instance = UUID.randomUUID().toString()
    private val counters = KeyboardCaptureCounters()
    private val captureApi = PublicKeyboardCaptureRequest(WindowManager.LayoutParams::class.java)
    private var requestedCapture = false
    private var permissionGranted = false
    private var result = PublicKeyboardCaptureRequest.Result(
        PublicKeyboardCaptureRequest.Status.API_UNAVAILABLE, null, "NotRequested")
    private var lifecycle = "created"
    private var topResumed = false
    private lateinit var statusView: TextView
    @Volatile private var observation = "{}"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            isFocusableInTouchMode = true
        }
        content.addView(TextView(this).apply {
            text = "Wonad keyboard capture: $captureRole"
            textSize = 22f
        })
        statusView = TextView(this).apply {
            contentDescription = "Wonad keyboard capture status"
            textSize = 18f
        }
        content.addView(statusView)
        fun control(label: String, action: () -> Unit) {
            content.addView(Button(this).apply {
                text = label
                contentDescription = label
                setOnClickListener { action() }
            })
        }
        control("Enable keyboard capture") { requestCapture(true) }
        control("Disable keyboard capture") { requestCapture(false) }
        control("Reset key counters") { counters.clear(); record() }
        content.addView(TextView(this).apply {
            text = "Only aggregate DOWN/UP/Escape counts are retained. No text is entered or logged. " +
                "Requested attributes do not prove capture; use actual focused callbacks and OS window evidence."
        })
        setContentView(content)
        content.requestFocus()
        // Safe default. ON requires the explicit visible button, not a boot/permission/settings shortcut.
        requestCapture(false)
    }

    private fun requestCapture(enabled: Boolean) {
        requestedCapture = enabled
        permissionGranted = checkSelfPermission(CAPTURE_PERMISSION) == PackageManager.PERMISSION_GRANTED
        result = captureApi.request(window.attributes, enabled, permissionGranted,
            updateWindow = { window.attributes = it as WindowManager.LayoutParams },
            currentParams = { window.attributes })
        record()
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        // The only key-code classification retained is Escape/not-Escape; no unicode/characters/key history.
        counters.observe(event.action, event.keyCode == KeyEvent.KEYCODE_ESCAPE,
            event.repeatCount, event.isCanceled)
        record()
        return if (requestedCapture && result.status == PublicKeyboardCaptureRequest.Status.ATTRIBUTES_APPLIED
            && result.attributeEnabled == true) true else super.dispatchKeyEvent(event)
    }

    override fun onResume() { super.onResume(); lifecycle = "resumed"; record() }
    override fun onPause() { lifecycle = "paused"; record(); super.onPause() }
    override fun onStop() { lifecycle = "stopped"; record(); super.onStop() }
    override fun onDestroy() { lifecycle = "destroyed"; record(); super.onDestroy() }
    override fun onWindowFocusChanged(hasFocus: Boolean) { super.onWindowFocusChanged(hasFocus); record() }
    override fun onTopResumedActivityChanged(isTopResumedActivity: Boolean) {
        super.onTopResumedActivityChanged(isTopResumedActivity)
        topResumed = isTopResumedActivity; record()
    }
    override fun onConfigurationChanged(newConfig: Configuration) { super.onConfigurationChanged(newConfig); record() }

    private fun record() {
        val keys = counters.snapshot()
        val publicToken = window.decorView.windowToken
        observation = JSONObject().put("schema", 1).put("role", captureRole)
            .put("component", componentName.flattenToShortString()).put("instance", instance)
            .put("uid", Process.myUid()).put("pid", Process.myPid()).put("task", taskId)
            .put("display", display?.displayId ?: -1).put("focused", hasWindowFocus())
            .put("top_resumed", topResumed).put("lifecycle", lifecycle)
            .put("capture_requested", requestedCapture).put("permission_granted", permissionGranted)
            .put("public_api_status", result.status.name)
            .put("attribute_enabled", result.attributeEnabled ?: JSONObject.NULL)
            .put("error_class", result.errorClass ?: JSONObject.NULL)
            .put("actual_system_capture_proven", false)
            .put("public_window_token_present", publicToken != null)
            .put("public_window_token_local_identity", publicToken?.let {
                Integer.toHexString(System.identityHashCode(it)) } ?: JSONObject.NULL)
            .put("down_count", keys.downs).put("up_count", keys.ups)
            .put("escape_down_count", keys.escapeDowns).put("escape_up_count", keys.escapeUps)
            .put("other_action_count", keys.otherActions).put("repeat_count", keys.repeats)
            .put("canceled_count", keys.canceled).put("counter_limit", KeyboardCaptureCounters.LIMIT)
            .put("counters_saturated", keys.saturated).toString()
        if (::statusView.isInitialized) {
            statusView.text = "Requested: ${if (requestedCapture) "ON" else "OFF"} / ${result.status}\n" +
                "DOWN=${keys.downs} UP=${keys.ups}\n" +
                "Escape DOWN=${keys.escapeDowns} UP=${keys.escapeUps}\n" +
                "Task=$taskId Display=${display?.displayId ?: -1} Focus=${hasWindowFocus()}"
        }
    }

    override fun dump(prefix: String, fd: FileDescriptor?, writer: PrintWriter, args: Array<out String>?) {
        super.dump(prefix, fd, writer, args)
        writer.println(prefix + "WONAD_KEYBOARD_CAPTURE " + observation)
    }

    companion object { const val CAPTURE_PERMISSION = "android.permission.CAPTURE_KEYBOARD" }
}

class KeyboardCaptureOneActivity : KeyboardCaptureActivity() { override val captureRole = "capture-one" }
class KeyboardCaptureTwoActivity : KeyboardCaptureActivity() { override val captureRole = "capture-two" }
class KeyboardCapturePhoneActivity : KeyboardCaptureActivity() { override val captureRole = "capture-phone" }
