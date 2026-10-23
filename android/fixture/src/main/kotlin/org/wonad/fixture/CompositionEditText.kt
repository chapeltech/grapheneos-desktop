package org.wonad.fixture

import android.content.Context
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputConnectionWrapper
import android.widget.EditText
import org.json.JSONObject

/** Observe actual composing spans after the native editor has applied an IME call.
 * TextWatcher alone runs before setComposingText finishes installing its spans.
 */
class CompositionEditText(context: Context, private val changed: Runnable) : EditText(context) {
    private var connections = 0
    private var composingCalls = 0
    private var commitCalls = 0
    private var finishCalls = 0
    private var closes = 0

    override fun onCreateInputConnection(attributes: EditorInfo): InputConnection? {
        val target = super.onCreateInputConnection(attributes) ?: return null
        connections++
        changed.run()
        return object : InputConnectionWrapper(target, false) {
            override fun setComposingText(text: CharSequence?, cursor: Int): Boolean {
                val result = super.setComposingText(text, cursor)
                composingCalls++; changed.run()
                return result
            }
            override fun commitText(text: CharSequence?, cursor: Int): Boolean {
                val result = super.commitText(text, cursor)
                commitCalls++; changed.run()
                return result
            }
            override fun finishComposingText(): Boolean {
                val result = super.finishComposingText()
                finishCalls++; changed.run()
                return result
            }
            override fun closeConnection() {
                // Native BaseInputConnection.closeConnection itself finishes
                // composing text. Observe it; never replace that OS behavior.
                super.closeConnection()
                closes++; changed.run()
            }
        }
    }

    fun diagnostics(): JSONObject = JSONObject()
        .put("start", BaseInputConnection.getComposingSpanStart(text))
        .put("end", BaseInputConnection.getComposingSpanEnd(text))
        .put("connections", connections).put("closes", closes).put("composing_calls", composingCalls)
        .put("commit_calls", commitCalls).put("finish_calls", finishCalls)
}
