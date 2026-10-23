package org.wonad.imefixture

import android.inputmethodservice.InputMethodService
import android.os.Process
import android.view.KeyEvent
import android.view.inputmethod.EditorInfo
import java.io.FileDescriptor
import java.io.PrintWriter
import org.json.JSONObject

private val compositionProcessMetrics = CompositionProcessMetrics()

/** Test-only IME in its own unprivileged UID. Normal Android InputConnection
 * calls cross into the fixture app; no shell text insertion simulates composition.
 * It never edits any package other than the dedicated native test fixture.
 */
class CompositionIme : InputMethodService() {
    private data class Press(val device: Int, val code: Int, val downTime: Long)
    private val consumed = mutableSetOf<Press>()
    private val metricInstance = compositionProcessMetrics.create()
    private var editor = ""
    @Volatile private var observation = "{}"

    override fun onStartInput(attribute: EditorInfo, restarting: Boolean) {
        super.onStartInput(attribute, restarting)
        compositionProcessMetrics.start(metricInstance, restarting)
        editor = attribute.packageName ?: ""
        record()
    }

    override fun onFinishInput() {
        editor = ""
        super.onFinishInput()
        record()
    }

    override fun onDestroy() {
        compositionProcessMetrics.destroy(metricInstance)
        record()
        super.onDestroy()
    }

    // This gate is for hardware-keyboard IME composition, not a software keyboard UI.
    override fun onEvaluateInputViewShown(): Boolean {
        super.onEvaluateInputViewShown()
        return false
    }
    override fun onEvaluateFullscreenMode() = false

    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        compositionProcessMetrics.keyDown(metricInstance)
        record()
        val press = Press(event.deviceId, keyCode, event.downTime)
        if (press in consumed) return true
        if (editor != "org.wonad.fixture" || event.repeatCount != 0 || consumed.size >= 4 ||
            event.isCtrlPressed || event.isAltPressed || event.isMetaPressed) return super.onKeyDown(keyCode, event)
        val connection = currentInputConnection ?: return super.onKeyDown(keyCode, event)
        val accepted = when (keyCode) {
            KeyEvent.KEYCODE_F7 -> connection.setComposingText("か", 1)
            KeyEvent.KEYCODE_F8 -> connection.setComposingText("かな", 1)
            KeyEvent.KEYCODE_F9 -> connection.commitText("仮名", 1)
            KeyEvent.KEYCODE_F10 -> connection.setComposingText("", 1) && connection.finishComposingText()
            else -> return super.onKeyDown(keyCode, event)
        }
        consumed.add(press)
        compositionProcessMetrics.action(metricInstance, keyCode, accepted)
        record()
        return true
    }

    override fun onKeyUp(keyCode: Int, event: KeyEvent): Boolean {
        compositionProcessMetrics.keyUp(metricInstance)
        record()
        // Match the data-class value, not listener/SAM object identity.
        if (consumed.removeAll { it == Press(event.deviceId, keyCode, event.downTime) }) return true
        return super.onKeyUp(keyCode, event)
    }

    private fun record() {
        val metrics = compositionProcessMetrics.snapshot(metricInstance)
        observation = JSONObject().put("uid", Process.myUid()).put("pid", Process.myPid())
            .put("schema", 2).put("process_epoch", metrics.epoch)
            .put("service_instance", metrics.instance).put("service_sequence", metrics.sequence)
            .put("service_creates", metrics.creates).put("service_destroys", metrics.destroys)
            .put("service_alive", metrics.alive).put("editor_package", editor)
            .put("starts", metrics.starts).put("restarts", metrics.restarts).put("actions", metrics.actions)
            .put("key_downs", metrics.keyDowns).put("key_ups", metrics.keyUps).put("last_action", metrics.lastAction)
            .put("local_starts", metrics.localStarts).put("local_restarts", metrics.localRestarts)
            .put("local_actions", metrics.localActions).put("local_key_downs", metrics.localKeyDowns)
            .put("local_key_ups", metrics.localKeyUps).toString()
    }

    override fun dump(fd: FileDescriptor, writer: PrintWriter, args: Array<out String>?) {
        super.dump(fd, writer, args)
        writer.println("WONAD_IME_OBSERVATION $observation")
    }
}
