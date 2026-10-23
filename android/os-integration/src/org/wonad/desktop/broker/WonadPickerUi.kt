package org.wonad.desktop.broker

import android.app.AlertDialog
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.UserHandle
import android.text.Editable
import android.text.InputFilter
import android.text.InputType
import android.text.TextWatcher
import android.util.Log
import android.view.Display
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.WindowManager
import java.util.concurrent.atomic.AtomicBoolean

/** System-owned UI only. Selection returns an index, never an Intent or task handle.
 * All windows live on the main thread; cancel invalidates callbacks immediately.
 * The Shell executor independently revalidates the live session and selected object.
 */
internal class WonadPickerUi(private val context: Context) {
    class Handle {
        val active = AtomicBoolean(true)
        var dialog: AlertDialog? = null // main thread only
    }
    data class Item(val label: String, val confirmation: String)
    private val main = Handler(Looper.getMainLooper())

    fun dismiss(handle: Handle) {
        handle.active.set(false)
        main.post { close(handle) }
    }

    private fun close(handle: Handle) {
        handle.dialog?.setOnDismissListener(null)
        handle.dialog?.dismiss()
        handle.dialog = null
    }

    /** Trusted confirmation stays on the phone; APK launcher UI cannot style it. */
    fun confirm(handle: Handle, user: Int, title: String, message: String,
        complete: (Boolean) -> Unit) = main.post {
        if (!handle.active.get()) return@post
        fun finish(confirmed: Boolean) {
            if (!handle.active.getAndSet(false)) return
            close(handle)
            complete(confirmed)
        }
        try {
            val display = context.getSystemService(android.hardware.display.DisplayManager::class.java)
                .getDisplay(Display.DEFAULT_DISPLAY)
            val ui = context.createContextAsUser(UserHandle.of(user), 0).createDisplayContext(display)
                .createWindowContext(WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG, null)
            val dialog = object : AlertDialog(ui, com.android.internal.R.style.Theme_DeviceDefault_Dialog_Alert) {
                override fun dispatchTouchEvent(event: MotionEvent): Boolean {
                    if (event.flags and (MotionEvent.FLAG_WINDOW_IS_OBSCURED or
                            MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0) return true
                    return super.dispatchTouchEvent(event)
                }
                override fun dispatchKeyEvent(event: KeyEvent): Boolean {
                    // Match the trusted picker: Escape cancels on release and
                    // never forwards either half of the pair to phone apps.
                    if (event.keyCode == KeyEvent.KEYCODE_ESCAPE) {
                        if (event.action == KeyEvent.ACTION_UP) cancel()
                        return true
                    }
                    return super.dispatchKeyEvent(event)
                }
            }.apply {
                setTitle(title); setMessage(message)
                setButton(AlertDialog.BUTTON_POSITIVE, "Open app") { _, _ -> finish(true) }
                setButton(AlertDialog.BUTTON_NEGATIVE, "Cancel") { _, _ -> finish(false) }
                setCanceledOnTouchOutside(false)
                window!!.apply {
                    setType(WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG)
                    addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    setHideOverlayWindows(true)
                    setTitle(title)
                }
                setOnCancelListener { finish(false) }
                setOnDismissListener { if (handle.dialog === this) finish(false) }
            }
            close(handle); handle.dialog = dialog; dialog.show()
            dialog.window!!.decorView.filterTouchesWhenObscured = true
        } catch (error: Exception) {
            Log.w("WonadBroker", "Phone launch confirmation failed", error)
            finish(false)
        }
    }

    /** Workspace-free v3 transfer UI; destination is not its phone rendering display. */
    fun showNativeTransfer(handle: Handle, user: Int, destinationDisplayId: Int,
        items: List<Item>, complete: (Int?) -> Unit) = main.post {
        if (!handle.active.get()) return@post
        val phone = context.getSystemService(android.hardware.display.DisplayManager::class.java)
            .getDisplay(Display.DEFAULT_DISPLAY)
        if (phone == null || destinationDisplayId <= Display.DEFAULT_DISPLAY) {
            if (handle.active.getAndSet(false)) complete(null)
            return@post
        }
        showOnDisplay(handle, phone, user, destinationDisplayId, true, items, complete)
    }

    private fun showOnDisplay(handle: Handle, display: Display, user: Int, destinationDisplayId: Int,
        transfer: Boolean, items: List<Item>, complete: (Int?) -> Unit) = main.post {
        if (!handle.active.get()) return@post
        fun finish(index: Int?) {
            if (!handle.active.getAndSet(false)) return
            close(handle)
            complete(index)
        }
        try {
            val ui = context.createContextAsUser(UserHandle.of(user), 0).createDisplayContext(display)
                .createWindowContext(WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG, null)
            fun dialog(title: String): AlertDialog = object : AlertDialog(ui,
                com.android.internal.R.style.Theme_DeviceDefault_Dialog_Alert) {
                override fun dispatchTouchEvent(event: MotionEvent): Boolean {
                    if (event.flags and (MotionEvent.FLAG_WINDOW_IS_OBSCURED or
                            MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0) return true
                    return super.dispatchTouchEvent(event)
                }
                override fun dispatchKeyEvent(event: KeyEvent): Boolean {
                    // EditText consumes Escape itself; intercept the complete pair
                    // before child dispatch, and dismiss only on release.
                    if (event.keyCode == KeyEvent.KEYCODE_ESCAPE) {
                        if (event.action == KeyEvent.ACTION_UP) cancel()
                        return true
                    }
                    return super.dispatchKeyEvent(event)
                }
            }.apply {
                setTitle(title)
                setButton(AlertDialog.BUTTON_NEGATIVE, "Cancel") { _, _ -> finish(null) }
                setCanceledOnTouchOutside(false)
                window!!.apply {
                    setType(WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG)
                    addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    setHideOverlayWindows(true)
                    setTitle(title)
                }
            }
            fun present(next: AlertDialog) {
                if (!handle.active.get()) return
                close(handle)
                handle.dialog = next
                next.setOnDismissListener { if (handle.dialog === next) finish(null) }
                next.show()
                next.window!!.decorView.filterTouchesWhenObscured = true
            }
            fun confirm(index: Int) {
                if (!handle.active.get() || index !in items.indices) return
                val item = items[index]
                val next = dialog(if (transfer) "Move this phone window?" else "Open on external desktop?")
                val destination = "External display $destinationDisplayId."
                next.setMessage(item.confirmation + "\n\n" + destination)
                next.setButton(AlertDialog.BUTTON_POSITIVE, if (transfer) "Move window" else "Open app") {
                    _, _ -> finish(index)
                }
                present(next)
                next.getButton(AlertDialog.BUTTON_POSITIVE)?.apply {
                    isFocusableInTouchMode = true
                    requestFocus()
                }
            }
            val picker = dialog(if (transfer) "Wonad: Move from phone" else "Wonad: Open an app")
            if (items.isEmpty()) {
                picker.setMessage(if (transfer) "No eligible phone windows." else "No launchable applications.")
            } else {
                // Use the dialog's themed context for its content, not SystemUI's
                // unrelated application theme. Filtering retains original consent indices.
                val themed = picker.context
                var visible = items.indices.toList()
                val rows = android.widget.ArrayAdapter(themed, android.R.layout.simple_list_item_1,
                    items.map { it.label }.toMutableList())
                val list = android.widget.ListView(themed).apply {
                    adapter = rows
                    setOnItemClickListener { _, _, index, _ -> visible.getOrNull(index)?.let { confirm(it) } }
                }
                val search = android.widget.EditText(themed).apply {
                    hint = "Filter by app name or component"
                    contentDescription = hint
                    setSingleLine(true)
                    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                    filters = arrayOf(InputFilter.LengthFilter(512))
                    addTextChangedListener(object : TextWatcher {
                        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) { }
                        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                            val query = s?.toString().orEmpty()
                            visible = items.indices.filter { items[it].label.contains(query, ignoreCase = true) }
                            rows.clear(); rows.addAll(visible.map { items[it].label }); rows.notifyDataSetChanged()
                        }
                        override fun afterTextChanged(s: Editable?) { }
                    })
                    setOnKeyListener { _, code, event ->
                        if (code == KeyEvent.KEYCODE_ENTER || code == KeyEvent.KEYCODE_NUMPAD_ENTER) {
                            if (event.action == KeyEvent.ACTION_UP) visible.singleOrNull()?.let { confirm(it) }
                            true
                        } else false
                    }
                }
                val content = android.widget.LinearLayout(themed).apply {
                    orientation = android.widget.LinearLayout.VERTICAL
                    val width = android.view.ViewGroup.LayoutParams.MATCH_PARENT
                    val wrap = android.view.ViewGroup.LayoutParams.WRAP_CONTENT
                    addView(search, android.widget.LinearLayout.LayoutParams(width, wrap))
                    addView(list, android.widget.LinearLayout.LayoutParams(width, wrap))
                }
                picker.setView(content)
                present(picker)
                search.requestFocus()
                return@post
            }
            present(picker)
        } catch (error: Exception) {
            Log.e("WonadBroker", "System picker unavailable", error)
            finish(null)
        }
    }
}
