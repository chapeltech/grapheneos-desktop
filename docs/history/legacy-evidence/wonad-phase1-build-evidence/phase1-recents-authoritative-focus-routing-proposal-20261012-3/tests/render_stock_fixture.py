#!/usr/bin/env python3
"""Extract exact old/new focus methods and continuation condition into named local doubles."""
import runpy
from pathlib import Path
value = runpy.run_path(str(Path(__file__).with_name('render_wiring_patch.py')))
old, new = value['snapshots']['packages/apps/Launcher3/quickstep/src/com/android/quickstep/OverviewCommandHelper.kt']
method = value['method']
original_focus = method(old, '    private fun updateRecentsViewFocus(command: CommandInfo)')
new_focus = method(new, '    private fun updateRecentsViewFocus(command: CommandInfo)')
original_extension = method(old, '    private fun View?.requestFocus(): Boolean')
guarded_extension = method(new, '    private fun View?.requestFocus(command: CommandInfo): Boolean')
continuation_stock = '                    continuation.resume(Unit)'
continuation_new = '                    if (!command.hasExecutionGuard() || continuation.isActive)\n                        continuation.resume(Unit)'
assert continuation_stock in old and continuation_new in new
header = '''package org.wonad.focusproposal.v3
import org.wonad.focusproposal.v3.CommandType.SHOW_ALT_TAB
import org.wonad.focusproposal.v3.CommandType.HIDE_ALT_TAB
import org.wonad.focusproposal.v3.CommandType.TOGGLE_WITH_FOCUS
private enum class CommandType { SHOW_ALT_TAB, HIDE_ALT_TAB, TOGGLE_WITH_FOCUS, TOGGLE }
private class CommandInfo(val type: CommandType = SHOW_ALT_TAB, val displayId: Int = 0,
                          private val executionGuard: (() -> Boolean)? = null) {
    fun hasExecutionGuard(): Boolean = executionGuard != null
    fun isExecutionAllowed(): Boolean = try { executionGuard?.invoke() ?: true }
        catch (_: RuntimeException) { false }
}
private class Events {
    val values = mutableListOf<String>()
    val tasks = mutableListOf<() -> Unit>()
    fun drain() { while (tasks.isNotEmpty()) tasks.removeAt(0).invoke() }
}
private open class View(val name: String, val events: Events) {
    var rejectPost = false
    fun post(action: () -> Unit): Boolean {
        if (rejectPost) return false
        events.tasks += action; return true
    }
    fun requestFocus(): Boolean { events.values += "focus:$name"; return true }
    fun requestAccessibilityFocus(): Boolean { events.values += "a11y:$name"; return true }
}
private class Root(val events: Events) {
    fun touchModeChanged(mode: Boolean) { events.values += "touch:$mode" }
}
// Named nullable TaskView getters match pinned RecentsView.java @Nullable annotations.
private class RecentsView<A, B>(events: Events) : View("recents", events) {
    var keyboardFocusTaskView: View? = null
    var nextTaskView: View? = null
    var firstTaskView: View? = null
    var isAttachedToWindow = true
    val viewRootImpl = Root(events)
}
private class Continuation(var isActive: Boolean) {
    var attempts = 0
    fun resume(value: Unit) { attempts++; check(isActive) { "already inactive" }; isActive = false }
}
'''
def wrapper(name, body, extensions):
    return f'''private class {name}(private val view: RecentsView<Any, Any>?) {{
    fun update(command: CommandInfo) = updateRecentsViewFocus(command)
    private fun getVisibleRecentsView(displayId: Int) = if (displayId == 0) view else null
''' + body + '\n' + extensions + '\n}\n'
print(header + wrapper('Original', original_focus, original_extension) +
    wrapper('Proposed', new_focus, original_extension + '\n' + guarded_extension) +
'''private fun originalComplete(continuation: Continuation) {
''' + continuation_stock + '''
}
private fun proposedComplete(command: CommandInfo, continuation: Continuation) {
''' + continuation_new + '''
}
private var proofs = 0
private fun proof(ok: Boolean, name: String) { proofs++; check(ok) { name } }
private fun view(events: Events, profile: Int): RecentsView<Any, Any> = RecentsView<Any, Any>(events).also {
    if (profile == 0) it.keyboardFocusTaskView = View("keyboard", events)
    if (profile == 1) it.nextTaskView = View("next", events)
    if (profile == 2) it.firstTaskView = View("first", events)
    if (profile == 4) it.isAttachedToWindow = false
}
fun main() {
    for (profile in 0..4) {
        val old = Events(); val next = Events()
        val original = Original(view(old, profile)); val proposed = Proposed(view(next, profile))
        original.update(CommandInfo()); proposed.update(CommandInfo())
        proof(old.values == next.values, "stock immediate focus/touch behavior identical profile=$profile")
        proof(old.tasks.size == next.tasks.size, "stock nullable fallback queue shape identical profile=$profile")
        old.drain(); next.drain()
        proof(old.values == next.values, "stock deferred nullable fallback behavior identical profile=$profile")
    }
    run {
        val events = Events(); val proposed = Proposed(view(events, 3)); var live = true
        proposed.update(CommandInfo(executionGuard = { live }))
        proof(events.values == listOf("touch:false"), "guarded phone admission doesn't execute posted focus early")
        events.drain()
        proof(events.values == listOf("touch:false", "focus:recents", "a11y:recents"), "healthy guarded phone focus")
    }
    run {
        val events = Events(); val proposed = Proposed(view(events, 4)); var connection: Any? = Any()
        val captured = connection
        proposed.update(CommandInfo(executionGuard = { connection === captured }))
        connection = Any() // new incarnation before deferred touch/focus effects
        events.drain()
        proof(events.values.isEmpty(), "replacement before deferred guarded work suppresses all uncommitted effects")
    }
    run {
        val events = Events(); val proposed = Proposed(view(events, 3))
        proposed.update(CommandInfo(executionGuard = { false }))
        proof(events.tasks.isEmpty() && events.values.isEmpty(), "invalid guarded owner rejected before lookup/effect")
    }
    run {
        val events = Events(); val target = view(events, 0)
        target.keyboardFocusTaskView!!.rejectPost = true
        target.nextTaskView = View("next", events)
        Proposed(target).update(CommandInfo(executionGuard = { true }))
        events.drain()
        proof(events.values == listOf("touch:false", "focus:next", "a11y:next"),
            "new guarded extension observes failed post and uses legitimate nullable fallback")
    }
    for (active in listOf(true, false)) {
        val old = Continuation(active); val next = Continuation(active)
        var oldThrows = false; var nextThrows = false
        try { originalComplete(old) } catch (_: IllegalStateException) { oldThrows = true }
        try { proposedComplete(CommandInfo(), next) } catch (_: IllegalStateException) { nextThrows = true }
        proof(oldThrows == nextThrows && old.attempts == next.attempts, "stock continuation including inactive exact behavior")
    }
    run {
        val guarded = CommandInfo(executionGuard = { true }); val inactive = Continuation(false)
        proposedComplete(guarded, inactive)
        proof(inactive.attempts == 0, "late guarded inactive completion cannot resume again")
        val active = Continuation(true); proposedComplete(guarded, active)
        proof(active.attempts == 1, "normal guarded continuation resumes once")
    }
    println("PASS side-by-side exact old/proposed focus and continuation extraction; proofs=$proofs; local view/continuation doubles, no Android/coroutine/platform/runtime proof")
}
''')
