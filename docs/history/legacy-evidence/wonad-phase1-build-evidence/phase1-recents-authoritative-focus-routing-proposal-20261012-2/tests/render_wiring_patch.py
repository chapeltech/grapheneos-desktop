#!/usr/bin/env python3
"""Read-only exact-preimage patch renderer; prints patch, never writes/edits source7."""
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path('/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7')
HERE = Path(__file__).resolve().parents[1]
LEDGER = json.loads((HERE.parent / 'phase1-recents-authoritative-focus-routing-proposal-20261012-1/source-inputs.json').read_text())['source_ledger']
for row in json.loads((HERE / 'source-inputs-v2.json').read_text())['additional_named_sources']:
    data = Path(row['path']).read_bytes()
    if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
        raise ValueError('additional source7 preimage changed')

def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError(f'exact single preimage absent: {old[:90]!r}')
    return source.replace(old, new)

def load(name):
    row = LEDGER[name]
    data = Path(row['path']).read_bytes()
    if hashlib.sha256(data).hexdigest() != row['sha256'] or len(data) != row['bytes']:
        raise ValueError('source7 preimage changed')
    return str(Path(row['path']).relative_to(ROOT)), data.decode()

patches = []
snapshots = {}
def emit(path, old, new):
    snapshots[path] = (old, new)
    patches.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
        fromfile='a/' + path, tofile='b/' + path))

path, old = load('shell_interface')
new = once(old, 'import android.view.SurfaceControl;', 'import android.os.RemoteCallback;\nimport android.view.SurfaceControl;')
new = once(new, '= 10;\n}', '= 10;\n\n    /** Private bounded authoritative focus request; no public APK SDK authority. */\n    oneway void requestFocusedDisplay(long requestToken, in RemoteCallback callback) = 11;\n}')
emit(path, old, new)

path, old = load('transitions')
new = once(old, 'import java.io.PrintWriter;', 'import android.os.Binder;\nimport android.os.Bundle;\nimport android.os.RemoteCallback;\nimport android.os.UserHandle;\nimport org.wonad.focusproposal.v2.FocusQueryCoordinator2;\n\nimport java.io.PrintWriter;')
new = once(new, '        private Transitions mTransitions;', '        private Transitions mTransitions;\n        private final Context mFocusQueryContext;\n        private final Object mFocusQueryOwner = new Object();\n        private final FocusQueryCoordinator2 mFocusQueries = ShellFocusQueries.coordinator;')
new = once(new, '            mTransitions = transitions;\n        }', '            mTransitions = transitions;\n            mFocusQueryContext = transitions.mContext;\n            mFocusQueries.attach(mFocusQueryOwner);\n        }')
new = once(new, '        public void invalidate() {\n', '        public void invalidate() {\n            mFocusQueries.invalidate(mFocusQueryOwner);\n')
fragment = (HERE / 'wiring/Transitions.java.fragment').read_text().split('// Additional actual private endpoint method:\n')[1]
new = once(new, '            mTransitions = null;\n        }\n\n        @Override\n        public void registerRemote(@NonNull RemoteTransition remoteTransition) {', '            mTransitions = null;\n        }\n\n' + fragment + '\n        @Override\n        public void registerRemote(@NonNull RemoteTransition remoteTransition) {')
emit(path, old, new)

path, old = load('systemui_proxy')
new = once(old, '    private var shellTransitions: IShellTransitions? = null', '    private var shellTransitions: IShellTransitions? = null\n' + (HERE / 'wiring/SystemUiProxy.kt.fragment').read_text().split('// Add fields beside existing shellTransitions field. This is private OS glue, not APK SDK.\n')[1].split('// In setInitializationParams')[0].rstrip())
new = once(new, '            IShellTransitions.Stub.asInterface(params.getBinder(IShellTransitions.DESCRIPTOR))\n', '            IShellTransitions.Stub.asInterface(params.getBinder(IShellTransitions.DESCRIPTOR))\n' + (HERE / 'wiring/SystemUiProxy.kt.fragment').read_text().split('// In setInitializationParams on MAIN, immediately after shellTransitions assignment:\n')[1].split('// Existing stateChangeCallbacks')[0])
emit(path, old, new)

path, old = load('tis_binder')
new = once(old, 'import android.os.IRemoteCallback', 'import android.os.IRemoteCallback\nimport android.os.Looper')
new = once(new, 'import com.android.quickstep.OverviewCommandHelper\n', 'import com.android.quickstep.OverviewCommandHelper\nimport com.android.quickstep.OverviewCommandHelper.CommandType\n')
fragment = (HERE / 'wiring/TISBinder.kt.fragment').read_text()
fields = fragment.split('// Fields immediately after state; construction via TouchInteractionService.onBind is MAIN.\n')[1].split('// In init,')[0]
new = once(new, '    private var state: BindData? = bindData\n', '    private var state: BindData? = bindData\n' + fields)
cleanup = fragment.split('// In init, replace existing cleanupTasks.addTask(uiExecutor) { state = null } with:\n')[1].split('// Replace all three Overview')[0].rstrip()
new = once(new, '        cleanupTasks.addTask(uiExecutor) { state = null }', cleanup)
start = new.index('    @BinderThread\n    override fun onOverviewToggle()')
end = new.index('    @BinderThread\n    override fun onAssistantAvailable', start)
body = fragment.split('// Replace all three Overview entry bodies; no transition focus cache/default fallback.\n')[1].split('// Remove both unused')[0]
new = new[:start] + body + new[end:]
for name in ['Overview', 'AltTabKqs']:
    new = once(new, f'        fun focusedDisplayIdFor{name}OnConnectedDisplays() =\n            sysUIProxy.focusState.focusedDisplayId\n', '')
emit(path, old, new)

path = 'packages/apps/Launcher3/quickstep/src/com/android/quickstep/OverviewCommandHelper.kt'
old = (ROOT / path).read_text()
new = once(old, '        isLastOfBatch: Boolean = true,\n    ): CommandInfo?', '        isLastOfBatch: Boolean = true,\n        executionGuard: (() -> Boolean)? = null,\n    ): CommandInfo?')
new = once(new, '                statusChangedCallback = this::onCommandStatusChanged,', '                statusChangedCallback = this::onCommandStatusChanged,\n                executionGuard = executionGuard,')
new = once(new, '        val statusChangedCallback: (CommandInfo) -> Unit,\n    ) {', '        val statusChangedCallback: (CommandInfo) -> Unit,\n        private val executionGuard: (() -> Boolean)? = null,\n    ) {\n        fun isExecutionAllowed(): Boolean = try { executionGuard?.invoke() ?: true }\n            catch (_: RuntimeException) { false }\n')
new = once(new, '    fun executeCommand(command: CommandInfo, onCallbackResult: () -> Unit): Boolean {', '    fun executeCommand(command: CommandInfo, onCallbackResult: () -> Unit): Boolean {\n        if (!command.isExecutionAllowed()) return true')
new = once(new, '                    continuation.resume(Unit)', '                    if (continuation.isActive) continuation.resume(Unit)')
new = once(new, '            command.status = CommandStatus.PROCESSING', '            if (!command.isExecutionAllowed()) {\n                commandQueue.remove(command)\n                processNextCommand()\n                return@traceSection\n            }\n            command.status = CommandStatus.PROCESSING')
for name in ['onCommandStatusChanged', 'updateRecentsViewFocus', 'onRecentsViewFocusUpdated', 'logShowOverviewFrom']:
    start = f'    private fun {name}(command: CommandInfo) {{'
    new = once(new, start, start + '\n        if (!command.isExecutionAllowed()) return')
for signature in ['onCommandFinished(command: CommandInfo)', 'cancelCommand(command: CommandInfo, throwable: Throwable?)']:
    start = f'    private fun {signature} {{'
    new = once(new, start, start + '\n        if (!command.isExecutionAllowed()) {\n            val wasHead = commandQueue.firstOrNull() === command\n            commandQueue.remove(command)\n            if (wasHead) processNextCommand()\n            return\n        }')
new = once(new, '                        if (runningTaskId != null) {', '                        if (runningTaskId != null && command.isExecutionAllowed()) {')
new = once(new, '                    OverviewCommandHelperProtoLogProxy.logRecentsAnimStarted(command)', '                    if (!command.isExecutionAllowed()) {\n                        command.removeListener(this)\n                        return\n                    }\n                    OverviewCommandHelperProtoLogProxy.logRecentsAnimStarted(command)')
new = once(new, '                    containerInterface.runOnInitBackgroundStateUI {', '                    containerInterface.runOnInitBackgroundStateUI {\n                        if (!command.isExecutionAllowed()) return@runOnInitBackgroundStateUI')
new = once(new, '                    containerInterface.getCreatedContainer() ?: return', '                    if (!command.isExecutionAllowed()) return\n                    containerInterface.getCreatedContainer() ?: return')
new = once(new, '            recentsView.post { recentsView.viewRootImpl.touchModeChanged(false) }', '            recentsView.post {\n                if (command.isExecutionAllowed()) recentsView.viewRootImpl.touchModeChanged(false)\n            }')
new = once(new, '        recentsView.keyboardFocusTaskView.requestFocus() ||\n            recentsView.nextTaskView.requestFocus() ||\n            recentsView.firstTaskView.requestFocus() ||\n            recentsView.requestFocus()', '        recentsView.keyboardFocusTaskView.requestFocus(command) ||\n            recentsView.nextTaskView.requestFocus(command) ||\n            recentsView.firstTaskView.requestFocus(command) ||\n            recentsView.requestFocus(command)')
new = once(new, '    private fun View?.requestFocus(): Boolean {\n        if (this == null) return false\n        post {\n            requestFocus()\n            requestAccessibilityFocus()\n        }\n        return true\n    }', '    private fun View?.requestFocus(command: CommandInfo): Boolean {' + (HERE / 'wiring/OverviewCommandHelper.kt.fragment').read_text().split('    private fun View?.requestFocus(command: CommandInfo): Boolean {')[1].split('// No claim')[0].rstrip())
emit(path, old, new)

if __name__ == '__main__':
    print(''.join(patches), end='')
