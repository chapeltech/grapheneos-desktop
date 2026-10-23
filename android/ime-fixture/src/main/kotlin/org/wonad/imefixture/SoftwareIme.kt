package org.wonad.imefixture

import android.graphics.Color
import android.inputmethodservice.InputMethodService
import android.os.Process
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.LinearLayout
import java.io.FileDescriptor
import java.io.PrintWriter
import org.json.JSONObject

/** Real, separately-UIDed software IME. The host must click its native input
 * view; no receiver, instrumentation command, or hardware key inserts text.
 * It only edits the test fixture and respects Android's keyboard visibility.
 */
class SoftwareIme : InputMethodService() {
    private var editor = ""
    private var starts = 0
    private var restarts = 0
    private var viewStarts = 0
    private var viewFinishes = 0
    private var shows = 0
    private var hides = 0
    private var actions = 0
    private var lastAction = "none"
    private var keys: View? = null
    @Volatile private var observation = "{}"

    override fun onCreateInputView(): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.rgb(30, 35, 45))
            val pad = (12 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
        }
        for (label in listOf("Compose", "Update", "Commit", "Cancel", "Delete", "Hide")) {
            row.addView(Button(this).apply {
                text = label
                contentDescription = "Wonad software key $label"
                setOnClickListener { press(label) }
            }, LinearLayout.LayoutParams(0, (96 * resources.displayMetrics.density).toInt(), 1f))
        }
        keys = row
        return row
    }

    override fun onStartInput(attribute: EditorInfo, restarting: Boolean) {
        super.onStartInput(attribute, restarting)
        starts++
        if (restarting) restarts++
        editor = attribute.packageName ?: ""
        record()
    }

    override fun onFinishInput() {
        editor = ""
        super.onFinishInput()
        record()
    }

    override fun onStartInputView(info: EditorInfo, restarting: Boolean) {
        super.onStartInputView(info, restarting)
        viewStarts++
        record()
    }

    override fun onFinishInputView(finishingInput: Boolean) {
        viewFinishes++
        super.onFinishInputView(finishingInput)
        record()
    }

    override fun onWindowShown() {
        super.onWindowShown()
        shows++
        record()
    }

    override fun onWindowHidden() {
        super.onWindowHidden()
        hides++
        record()
    }

    override fun onEvaluateInputViewShown(): Boolean =
        super.onEvaluateInputViewShown() && editor == "org.wonad.fixture"

    override fun onEvaluateFullscreenMode() = false

    private fun press(label: String) {
        if (editor != "org.wonad.fixture" || !isInputViewShown) return
        val connection = currentInputConnection ?: return
        val accepted = when (label) {
            "Compose" -> connection.setComposingText("か", 1)
            "Update" -> connection.setComposingText("かな", 1)
            "Commit" -> connection.commitText("仮名", 1)
            "Cancel" -> connection.setComposingText("", 1) && connection.finishComposingText()
            "Delete" -> connection.deleteSurroundingText(1, 0)
            "Hide" -> { requestHideSelf(0); true }
            else -> return
        }
        actions++
        lastAction = "$label:$accepted"
        record()
    }

    private fun record() {
        observation = JSONObject().put("uid", Process.myUid()).put("pid", Process.myPid())
            .put("editor_package", editor).put("starts", starts).put("restarts", restarts)
            .put("actions", actions).put("last_action", lastAction)
            .put("view_starts", viewStarts).put("view_finishes", viewFinishes)
            .put("shows", shows).put("hides", hides)
            .put("view_display", keys?.display?.displayId ?: -1).toString()
    }

    override fun dump(fd: FileDescriptor, writer: PrintWriter, args: Array<out String>?) {
        super.dump(fd, writer, args)
        writer.println("WONAD_SOFTWARE_IME_OBSERVATION $observation")
    }
}
