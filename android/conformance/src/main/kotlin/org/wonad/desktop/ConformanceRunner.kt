package org.wonad.desktop

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.SystemClock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.wonad.desktop.api.*

/** Pure startup ordering shared by the real runner and its host JVM tests.
 * The broker deliberately withholds application tasks until external UI is
 * enabled, so the first valid snapshot establishes only lease/display
 * identity. */
internal object ConformanceStartup {
    data class Display(val token: Long, val displayId: Int, val shellGeneration: Long)
    data class State(val generation: Long, val displays: List<Display>,
        val taskCount: Int, val interactionBlocked: Boolean)

    fun observe(value: DesktopSnapshot) = State(value.generation,
        value.displays.map { Display(it.token, it.displayId, it.shellGeneration) },
        value.tasks.size, value.interactionBlocked)

    fun initialReady(value: State): Boolean =
        value.generation > 0 && value.displays.isNotEmpty()

    fun externallyReady(value: State, generation: Long): Boolean =
        value.generation == generation && value.displays.isNotEmpty() && value.taskCount >= 2 &&
            value.displays.all { it.shellGeneration == generation } && !value.interactionBlocked

    /** Register/start the live lease before requesting the state transition
     * which makes ordinary external tasks observable. Exceptions propagate to
     * ConformanceRunner's existing fail-closed release/heartbeat cleanup. */
    fun activate(value: State, register: (Long, List<Pair<Long, Int>>) -> Unit,
        startHeartbeat: () -> Unit, enableExternalUi: () -> Unit,
        showShell: (Long) -> Unit) {
        check(initialReady(value)) { "initial external display snapshot is not ready" }
        register(value.generation, value.displays.map { it.token to it.displayId })
        startHeartbeat()
        enableExternalUi()
        value.displays.forEach { showShell(it.token) }
    }
}

/** Pure callback progress checks shared by the real runner and host JVM tests.
 * A command may be delivered only after a newer focus observation, and a
 * successful mutation may be followed only by an observation at least as new
 * as the revision named by its result callback. */
internal object ConformanceProgress {
    data class State(val generation: Long, val revision: Long, val interactionBlocked: Boolean,
        val focusedDisplayToken: Long, val focusedToken: Long,
        val displays: Set<Long>, val tasks: Set<Long>)
    data class Command(val generation: Long, val taskToken: Long, val displayToken: Long)
    data class Result(val generation: Long, val result: Int, val revision: Long)

    fun observe(value: DesktopSnapshot) = State(value.generation, value.revision,
        value.interactionBlocked, value.focusedDisplayToken, value.focusedToken,
        value.displays.mapTo(linkedSetOf()) { it.token },
        value.tasks.mapTo(linkedSetOf()) { it.token })

    fun afterCommand(value: State, generation: Long, command: Command): Boolean =
        generation > 0 && value.generation == generation && command.generation == generation &&
            value.revision > 0 && !value.interactionBlocked && value.tasks.size >= 2 &&
            command.displayToken > 0 && command.displayToken in value.displays &&
            command.taskToken > 0 && command.taskToken in value.tasks &&
            value.focusedDisplayToken == command.displayToken &&
            value.focusedToken == command.taskToken

    fun afterApplied(value: State, generation: Long, result: Result,
        minimumTasks: Int): Boolean =
        generation > 0 && minimumTasks >= 0 && value.generation == generation &&
            result.generation == generation && result.result == DesktopProtocol.RESULT_APPLIED &&
            result.revision > 0 && value.revision >= result.revision &&
            !value.interactionBlocked && value.displays.isNotEmpty() &&
            value.tasks.size >= minimumTasks
}

/** Deterministic policy-free API exerciser. It copies observed placement state;
 * it never decides a workspace, tiling scheme, floating rule, panel or border. */
internal class ConformanceRunner(
    private val context: Context,
    private val ledger: ConformanceLedger,
) : Runnable {
    private class BoundBroker(private val context: Context) : AutoCloseable {
        private val latch = CountDownLatch(1)
        private val binder = AtomicReference<IBinder?>()
        private val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                binder.set(service); latch.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName) { binder.set(null) }
            override fun onNullBinding(name: ComponentName) { latch.countDown() }
            override fun onBindingDied(name: ComponentName) { binder.set(null); latch.countDown() }
        }
        init {
            check(context.bindService(Intent(ConformanceContract.BIND_ACTION).setComponent(ComponentName(
                ConformanceContract.BROKER_PACKAGE, ConformanceContract.BROKER_CLASS)),
                connection, Context.BIND_AUTO_CREATE)) { "OS broker bind was rejected" }
        }
        fun get(): IDesktopBroker {
            check(latch.await(10, TimeUnit.SECONDS)) { "OS broker bind timed out" }
            val remote = checkNotNull(binder.get()) { "OS broker returned no Binder" }
            check(remote.isBinderAlive) { "OS broker Binder is dead" }
            return IDesktopBroker.Stub.asInterface(remote)
        }
        override fun close() { context.unbindService(connection) }
    }

    private val stopped = AtomicBoolean()
    private val sequence = AtomicLong()
    private var heartbeat: ScheduledExecutorService? = null
    private var session: IDesktopSession? = null
    private var events: ConformanceEvents? = null
    private var generation = 0L

    private fun copy(rect: DesktopRect) = DesktopRect().also {
        it.left = rect.left; it.top = rect.top; it.right = rect.right; it.bottom = rect.bottom
    }
    private fun frame(snapshot: DesktopSnapshot) = DesktopFrame().also { value ->
        value.topologyRevision = snapshot.topologyRevision
        value.focusedDisplayToken = 0
        value.focusedToken = 0
        value.placements = snapshot.tasks.map { task -> DesktopPlacement().also {
            it.token = task.token; it.destinationDisplayToken = task.displayToken; it.bounds = copy(task.bounds)
            it.visible = task.visible; it.inputEnabled = task.inputEnabled; it.zOrder = task.zOrder
        } }.toTypedArray()
        value.shellRegions = emptyArray()
    }
    private fun requireSnapshot(value: DesktopSnapshot, minimumTasks: Int = 0) {
        check(value.generation > 0 && value.revision > 0 && value.topologyRevision > 0 && value.identityEpoch > 0)
        check(value.displays.size in 1..DesktopProtocol.MAX_DISPLAYS)
        check(value.tasks.size in minimumTasks..DesktopProtocol.MAX_TASKS)
        check(value.displays.all { it.token > 0 && it.displayId > 0 && it.identityHint > 0 && it.secure &&
            it.bounds.right > it.bounds.left && it.bounds.bottom > it.bounds.top })
        check(value.displays.map { it.token }.distinct().size == value.displays.size)
        check(value.tasks.map { it.token }.distinct().size == value.tasks.size)
        check(value.tasks.none { it.packageName == context.packageName }) {
            "Broker exposed the policy client as an eligible application task"
        }
    }
    private fun operation(name: String, action: () -> Unit) { ledger.operation(name); action() }
    private fun applied(request: Long): ConformanceEvents.Result {
        val result = checkNotNull(events).awaitResult(request)
        check(result.generation == generation && result.result == DesktopProtocol.RESULT_APPLIED) {
            "request $request returned ${result.result}"
        }
        check(result.revision > 0) { "request $request returned an invalid revision" }
        return result
    }
    private fun startHeartbeat(remote: IDesktopSession) {
        heartbeat = Executors.newSingleThreadScheduledExecutor().also { scheduler ->
            scheduler.scheduleWithFixedDelay({
                if (!stopped.get()) try {
                    ledger.operation("heartbeat")
                    remote.heartbeat(generation, sequence.incrementAndGet())
                } catch (error: Throwable) {
                    stopped.set(true)
                }
            }, 0, 500, TimeUnit.MILLISECONDS)
        }
    }
    private fun stopHeartbeat() {
        stopped.set(true)
        heartbeat?.shutdownNow()
        heartbeat?.awaitTermination(2, TimeUnit.SECONDS)
        heartbeat = null
    }

    override fun run() {
        var explicitRelease = false
        try {
            ledger.phase("binding")
            BoundBroker(context).use { bound ->
                val broker = bound.get()
                ledger.operation("getApiVersion")
                val version = broker.apiVersion
                ledger.operation("getCapabilities")
                val capabilities = broker.capabilities
                ledger.negotiated(version, capabilities)
                check(version == DesktopProtocol.API_VERSION) { "OS API $version is not frozen v3" }
                val missing = ConformanceContract.requiredCapabilities and capabilities.inv()
                check(missing == 0L) { "OS capability bits missing: $missing" }

                val callback = ConformanceEvents(ledger)
                events = callback
                ledger.operation("openSession")
                val remote = broker.openSession(DesktopProtocol.API_VERSION, callback)
                session = remote
                ledger.phase("waiting-initial-snapshot")
                var snapshot = callback.awaitSnapshot("initial eligible external displays") {
                    ConformanceStartup.initialReady(ConformanceStartup.observe(it))
                }
                requireSnapshot(snapshot)
                val startup = ConformanceStartup.observe(snapshot)
                val displayIds = startup.displays.map { it.displayId }
                ConformanceStartup.activate(startup,
                    register = { observedGeneration, displays ->
                        generation = observedGeneration
                        ledger.generation(generation, displays.map { it.second })
                        ConformanceRegistry.displays(generation, displays)
                    },
                    startHeartbeat = { startHeartbeat(remote) },
                    enableExternalUi = {
                        ledger.phase("enabling-external-ui", displayIds)
                        operation("enableExternalUi") { remote.enableExternalUi(generation) }
                    },
                    showShell = { token ->
                        operation("showShell") { remote.showShell(generation, token) }
                    })

                snapshot = callback.awaitSnapshot("all exact facade planes drawn with two fixture tasks") {
                    ConformanceStartup.externallyReady(ConformanceStartup.observe(it), generation)
                }
                requireSnapshot(snapshot, 2)

                operation("enableShortcuts") { remote.enableShortcuts(generation, true) }
                ledger.phase("wait-shortcut", displayIds)
                val command = callback.awaitCommand()
                check(command.generation == generation && command.command in 1..16 &&
                    snapshot.displays.any { it.token == command.displayToken })
                val progressCommand = ConformanceProgress.Command(
                    command.generation, command.taskToken, command.displayToken)
                snapshot = callback.awaitSnapshot("current shortcut focus") {
                    ConformanceProgress.afterCommand(
                        ConformanceProgress.observe(it), generation, progressCommand)
                }
                requireSnapshot(snapshot, 2)

                ledger.phase("applying-contained-frame", displayIds)
                val boundedRequest = 0x3001L
                operation("applyFrame") {
                    remote.applyFrame(generation, boundedRequest, snapshot.revision, frame(snapshot))
                }
                val boundedResult = applied(boundedRequest)
                val boundedProgress = ConformanceProgress.Result(
                    boundedResult.generation, boundedResult.result, boundedResult.revision)
                snapshot = callback.awaitSnapshot("contained frame completion") {
                    ConformanceProgress.afterApplied(
                        ConformanceProgress.observe(it), generation, boundedProgress, 2)
                }
                requireSnapshot(snapshot, 2)

                val signedRequest = 0x3002L
                operation("applySignedFrame") {
                    remote.applySignedFrame(generation, signedRequest, snapshot.revision, frame(snapshot))
                }
                val signedResult = applied(signedRequest)
                val signedProgress = ConformanceProgress.Result(
                    signedResult.generation, signedResult.result, signedResult.revision)
                snapshot = callback.awaitSnapshot("signed frame completion") {
                    ConformanceProgress.afterApplied(
                        ConformanceProgress.observe(it), generation, signedProgress, 2)
                }
                requireSnapshot(snapshot, 2)

                val focusToken = snapshot.tasks.first { it.visible && it.inputEnabled }.token
                val focusRequest = 0x3003L
                operation("focusTask") { remote.focusTask(generation, focusRequest, snapshot.revision, focusToken) }
                val focusResult = applied(focusRequest)
                val focusProgress = ConformanceProgress.Result(
                    focusResult.generation, focusResult.result, focusResult.revision)
                snapshot = callback.awaitSnapshot("focused task") {
                    ConformanceProgress.afterApplied(
                        ConformanceProgress.observe(it), generation, focusProgress, 2) &&
                        it.focusedToken == focusToken
                }
                requireSnapshot(snapshot, 2)

                val closeToken = snapshot.tasks.last { it.token != focusToken }.token
                val closeRequest = 0x3004L
                operation("closeTask") { remote.closeTask(generation, closeRequest, snapshot.revision, closeToken) }
                val closeResult = applied(closeRequest)
                val closeProgress = ConformanceProgress.Result(
                    closeResult.generation, closeResult.result, closeResult.revision)
                snapshot = callback.awaitSnapshot("closed task absent") {
                    ConformanceProgress.afterApplied(
                        ConformanceProgress.observe(it), generation, closeProgress, 1) &&
                        it.tasks.none { task -> task.token == closeToken }
                }
                requireSnapshot(snapshot, 1)

                ledger.phase("exercising-launcher", displayIds)
                val display = snapshot.displays.first()
                val beforeCatalogueRevision = snapshot.revision
                ledger.operation("launcherPage")
                val first = checkNotNull(remote.launcherPage(generation, 0, display.token, 0)) {
                    "initial launcher catalogue was rejected"
                }
                val catalogueReturnedElapsed = SystemClock.elapsedRealtime()
                check(first.generation == generation && first.catalogId > 0 && first.displayToken == display.token &&
                    first.offset == 0 && first.entries.size <= DesktopProtocol.MAX_LAUNCH_PAGE &&
                    first.totalEntries in first.entries.size..DesktopProtocol.MAX_LAUNCH_ENTRIES)
                snapshot = callback.awaitSnapshot("fresh launcher catalogue blocking") {
                    ConformancePickerProgress.opened(ConformancePickerProgress.observe(it),
                        generation, beforeCatalogueRevision)
                }
                requireSnapshot(snapshot, 1)
                val catalogueBlockedRevision = snapshot.revision
                var offset = first.entries.size
                while (offset < first.totalEntries) {
                    ledger.operation("launcherPage")
                    val page = checkNotNull(remote.launcherPage(generation, first.catalogId, display.token, offset))
                    check(page.catalogId == first.catalogId && page.offset == offset && page.entries.isNotEmpty())
                    offset += page.entries.size
                }
                ConformanceRegistry.launcher(ConformanceRegistry.LauncherClaim(
                    generation, first.catalogId, display.displayId))
                operation("showLauncher") { remote.showLauncher(generation, first.catalogId) }
                ConformanceRegistry.await("LauncherActivity", 10_000)
                val beforeCancel = checkNotNull(callback.latestSnapshot()) {
                    "launcher cancellation has no callback observation"
                }
                val cancellationFloor = ConformancePickerProgress.cancellationFloor(
                    ConformancePickerProgress.observe(beforeCancel), generation, catalogueBlockedRevision)
                operation("selectLauncher") { remote.selectLauncher(generation, first.catalogId, -1) }
                ConformanceRegistry.launcher(null)
                snapshot = callback.awaitSnapshot("launcher cancellation") {
                    ConformancePickerProgress.cancelled(ConformancePickerProgress.observe(it),
                        generation, cancellationFloor)
                }
                requireSnapshot(snapshot, 1)

                ledger.phase("waiting-picker-cadence", displayIds)
                ConformancePickerProgress.awaitCatalogueCadence(catalogueReturnedElapsed,
                    clock = { SystemClock.elapsedRealtime() }, sleep = { Thread.sleep(it) })
                ledger.phase("wait-transfer-cancel", displayIds)
                operation("showTransferPicker") { remote.showTransferPicker(generation, display.token) }
                callback.awaitSnapshot("trusted phone transfer picker") {
                    it.generation == generation && it.interactionBlocked
                }
                ledger.phase("wait-transfer-back", displayIds)
                callback.awaitSnapshot("trusted phone transfer picker cancellation", 60_000) {
                    it.generation == generation && !it.interactionBlocked
                }

                operation("enableShortcuts") { remote.enableShortcuts(generation, false) }
                stopHeartbeat()
                ledger.phase("releasing", displayIds)
                operation("release") { remote.release(generation) }
                explicitRelease = true
                val revoked = callback.awaitRevocation()
                check(revoked.generation == generation && revoked.reason == DesktopProtocol.REVOKED_DISABLED)
                session = null
            }
            check(sequence.get() > 0) { "No heartbeat was sent" }
            ledger.pass()
        } catch (error: Throwable) {
            stopHeartbeat()
            if (!explicitRelease && generation > 0) try { session?.release(generation) } catch (_: Throwable) { }
            ledger.fail(error)
        } finally {
            stopHeartbeat()
            session = null
        }
    }
}
