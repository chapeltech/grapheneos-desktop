#!/usr/bin/env python3
"""Compile-fixture renderer: extracts exact proposed queue methods, with named local doubles."""
import runpy
from pathlib import Path

value = runpy.run_path(str(Path(__file__).with_name('render_wiring_patch.py')))
source = value['snapshots']['packages/apps/Launcher3/quickstep/src/com/android/quickstep/OverviewCommandHelper.kt'][1]

def method(signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        char = source[end]
        if char == '{': depth += 1
        elif char == '}': depth -= 1
        end += 1
    return source[start:end]

execute = method('    fun executeCommand(command: CommandInfo, onCallbackResult: () -> Unit): Boolean')
finished = method('    private fun onCommandFinished(command: CommandInfo)')
canceled = method('    private fun cancelCommand(command: CommandInfo, throwable: Throwable?)')
guard = source[source.index('        fun isExecutionAllowed()'):source.index('\n\n', source.index('        fun isExecutionAllowed()'))]
print('''package org.wonad.focusproposal.v2
import java.util.concurrent.ConcurrentLinkedDeque
private var checks = 0
private fun proof(value: Boolean, name: String) { checks++; check(value) { name } }
private class RecentsView
private object OverviewCommandHelperProtoLogProxy {
    fun logExecutingCommand(command: CommandInfo, view: RecentsView?) {}
    fun logCommandFinishedButNotScheduled(head: CommandInfo?, command: CommandInfo) {}
    fun logCommandFinishedSuccessfully(command: CommandInfo) {}
    fun logCommandCanceled(command: CommandInfo, throwable: Throwable?) {}
}
private enum class CommandStatus { IDLE, COMPLETED, CANCELED }
private class CommandInfo(val displayId: Int, private val executionGuard: (() -> Boolean)? = null) {
    var status = CommandStatus.IDLE
''' + guard + '''
}
private class QueueFixture {
    val commandQueue = ConcurrentLinkedDeque<CommandInfo>()
    var effects = 0
    var readViews = 0
    var processCalls = 0
    fun finish(command: CommandInfo) = onCommandFinished(command)
    fun cancel(command: CommandInfo) = cancelCommand(command, null)
    private fun processNextCommand() { processCalls++ }
    private fun getVisibleRecentsView(display: Int): RecentsView? { readViews++; return RecentsView() }
    private fun executeWhenRecentsIsVisible(command: CommandInfo, view: RecentsView, callback: () -> Unit): Boolean { effects++; return true }
    private fun executeWhenRecentsIsNotVisible(command: CommandInfo, callback: () -> Unit): Boolean { effects++; return true }
''' + execute + '\n' + finished + '\n' + canceled + '''
}
fun main() {
    val binder = Any(); var connection: Any? = Any(); val original = connection
    var tis: Any? = Any(); val capturedTis = tis
    var userUnlocked = true; var eligible = true; var main = true
    val guard = { main && connection === original && tis === capturedTis && userUnlocked && eligible }
    val queue = QueueFixture(); val old = CommandInfo(0, guard)
    queue.commandQueue.add(old)
    connection = Any() // same raw Binder, new connection incarnation BEFORE execution
    proof(queue.executeCommand(old) {}, "stale command settles without side effect")
    proof(queue.effects == 0 && queue.readViews == 0, "replacement checked before even view lookup")
    val replacement = CommandInfo(3); queue.commandQueue.clear(); queue.commandQueue.add(replacement)
    queue.finish(old)
    proof(queue.commandQueue.peek() === replacement && replacement.status == CommandStatus.IDLE,
        "late old completion cannot mutate/remove replacement")
    proof(old.status == CommandStatus.IDLE && queue.processCalls == 0,
        "late stale completion does not issue shared status/next command work")
    queue.cancel(old)
    proof(queue.commandQueue.peek() === replacement && queue.processCalls == 0,
        "late old cancellation cannot process replacement queue")
    connection = original
    proof(queue.executeCommand(old) {} && queue.effects == 1, "healthy current connection executes")
    tis = null
    queue.executeCommand(old) {}; proof(queue.effects == 1, "destroyed TIS rejected")
    tis = capturedTis; userUnlocked = false
    queue.executeCommand(old) {}; proof(queue.effects == 1, "locked user rejected")
    userUnlocked = true; eligible = false
    queue.executeCommand(old) {}; proof(queue.effects == 1, "ineligible current display rejected")
    eligible = true; main = false
    queue.executeCommand(old) {}; proof(queue.effects == 1, "off MAIN cannot execute guarded command")
    queue.executeCommand(CommandInfo(0)) {}
    proof(queue.effects == 2, "unaffected stock null-guard behavior preserved")
    queue.executeCommand(CommandInfo(0) { throw RuntimeException("failed eligibility") }) {}
    proof(queue.effects == 2, "failed guard drops without default")
    proof(binder === binder, "test same raw Binder identity deliberately unchanged")
    println("PASS exact proposed queue method extraction; checks=$checks; local dependency doubles, no Android/coroutine/animation/runtime proof")
}
''')
