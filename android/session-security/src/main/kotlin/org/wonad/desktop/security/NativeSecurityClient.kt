package org.wonad.desktop.security

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ApplicationInfo
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.os.SystemClock
import android.util.Base64
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONArray
import org.json.JSONObject
import org.wonad.desktop.api.*

/** Ordinary owner-UID test client. It uses the actual remote v3 Binder and the
 * target APK's public shell model, never hidden Android handles/permissions.
 * Host-side native window, Task/UID, pixel and input evidence remains required. */
internal object NativeSecurityClient {
    const val PACKAGE = "org.wonad.desktop"
    const val FIXTURE = "org.wonad.fixture"
    const val ADMISSION_DENIED = "Enable Wonad external desktop and unlock the phone"
    val METHODS = listOf("applyFrame", "focusTask", "closeTask", "enableShortcuts", "heartbeat", "release",
        "enableExternalUi", "showShell", "launcherPage", "showLauncher", "selectLauncher", "showTransferPicker",
        "applySignedFrame")

    fun requireOwner(context: Context, user: Int) {
        check(context.packageName == PACKAGE && context.applicationInfo.uid == Process.myUid())
        check(Process.myUid() / 100000 == user && Process.myUid() % 100000 in 10000..19999)
        check(context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0)
    }

    class Events : IDesktopCallback.Stub() {
        val snapshot = AtomicReference<DesktopSnapshot?>()
        val snapshots = AtomicLong()
        val commands = AtomicLong()
        val results = LinkedBlockingQueue<List<Long>>()
        val revoked = LinkedBlockingQueue<Pair<Long, Int>>()
        override fun onSnapshot(value: DesktopSnapshot) { snapshot.set(value); snapshots.incrementAndGet() }
        override fun onCommand(generation: Long, command: Int, argument: Int, taskToken: Long, displayToken: Long) {
            commands.incrementAndGet()
        }
        override fun onResult(generation: Long, requestId: Long, result: Int, revision: Long) {
            results.add(listOf(generation, requestId, result.toLong(), revision))
        }
        override fun onRevoked(generation: Long, reason: Int) { revoked.add(generation to reason) }
        fun empty() = snapshots.get() == 0L && commands.get() == 0L && results.isEmpty() && revoked.isEmpty()
        fun terminal() = snapshots.get() to fingerprint(checkNotNull(snapshot.get()))
        fun requireSilent(terminal: Pair<Long, String>) {
            check(snapshots.get() == terminal.first && fingerprint(checkNotNull(snapshot.get())) == terminal.second)
            check(commands.get() == 0L && results.isEmpty() && revoked.isEmpty()) {
                "Retained native session produced a callback after revocation"
            }
        }
    }

    class Bound(private val context: Context) : AutoCloseable {
        private val ready = CountDownLatch(1)
        private val remote = AtomicReference<IBinder?>()
        private val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) { remote.set(service); ready.countDown() }
            override fun onServiceDisconnected(name: ComponentName) { remote.set(null) }
            override fun onNullBinding(name: ComponentName) { ready.countDown() }
            override fun onBindingDied(name: ComponentName) { remote.set(null); ready.countDown() }
        }
        init {
            check(context.bindService(Intent("org.wonad.desktop.BIND").setComponent(ComponentName(
                "com.android.systemui", "org.wonad.desktop.broker.WonadBrokerService")), connection, Context.BIND_AUTO_CREATE))
        }
        fun broker(): IDesktopBroker {
            check(ready.await(5, TimeUnit.SECONDS))
            val binder = checkNotNull(remote.get())
            check(binder.isBinderAlive && binder.queryLocalInterface("org.wonad.desktop.api.IDesktopBroker") == null)
            return IDesktopBroker.Stub.asInterface(binder).also(::requireApi)
        }
        override fun close() = context.unbindService(connection)
    }

    fun requireApi(broker: IDesktopBroker) {
        check(broker.apiVersion == DesktopProtocol.API_VERSION)
        val caps = broker.capabilities
        check(caps and DesktopProtocol.CAP_FRAME != 0L && caps and DesktopProtocol.CAP_SHELL != 0L &&
            caps and DesktopProtocol.CAP_SHORTCUTS != 0L && caps and DesktopProtocol.CAP_SIGNED_PLACEMENT != 0L)
    }

    fun open(context: Context, broker: IDesktopBroker): Lease {
        val deadline = SystemClock.elapsedRealtime() + 10000
        while (true) {
            val events = Events()
            try { return Lease(context, broker.openSession(DesktopProtocol.API_VERSION, events), events) }
            catch (error: IllegalStateException) {
                if (error.message !in listOf("Native desktop session is already open", "Broker operation failed") ||
                    SystemClock.elapsedRealtime() >= deadline) throw error
                SystemClock.sleep(100)
            }
        }
    }

    class Lease(private val context: Context, val session: IDesktopSession, val events: Events) : AutoCloseable {
        private val timer = Executors.newSingleThreadScheduledExecutor()
        private val stopped = AtomicBoolean()
        private val sequence = AtomicLong()
        private val failure = AtomicReference<Throwable?>()
        private var uiRequested = false
        private val shells = mutableSetOf<Long>()
        init { timer.scheduleWithFixedDelay({
            try { events.snapshot.get()?.let { session.heartbeat(it.generation, sequence.incrementAndGet()) } }
            catch (error: Throwable) { failure.compareAndSet(null, error) }
        }, 0, 500, TimeUnit.MILLISECONDS) }

        fun stable(): DesktopSnapshot {
            val deadline = SystemClock.elapsedRealtime() + 15000
            var previous = ""; var repeats = 0
            while (SystemClock.elapsedRealtime() < deadline) {
                check(failure.get() == null && events.revoked.isEmpty()) { "Native lease lost before stable readiness" }
                events.snapshot.get()?.let { snapshot ->
                    check(snapshot.generation > 0 && snapshot.identityEpoch > 0 && snapshot.revision > 0 &&
                        snapshot.displays.isNotEmpty() && snapshot.displays.size <= 9 &&
                        snapshot.capabilities and DesktopProtocol.CAP_SIGNED_PLACEMENT != 0L)
                    if (!uiRequested) { uiRequested = true; session.enableExternalUi(snapshot.generation) }
                    snapshot.displays.forEach { display ->
                        check(display.token > 0 && display.displayId > 0 && display.identityHint > 0 && display.secure)
                        if (display.shellGeneration != snapshot.generation) {
                            publishOrdinaryModel(context, snapshot, display)
                            if (shells.add(display.token)) session.showShell(snapshot.generation, display.token)
                        }
                    }
                    if (snapshot.tasks.size == 2 && snapshot.tasks.all { it.packageName == FIXTURE } &&
                        !snapshot.interactionBlocked && snapshot.displays.all { it.shellGeneration == snapshot.generation }) {
                        check(snapshot.tasks.map { it.token }.distinct().size == 2 &&
                            snapshot.tasks.all { it.token > 0 && it.displayToken in snapshot.displays.map { d -> d.token } })
                        val next = fingerprint(snapshot)
                        repeats = if (next == previous) repeats + 1 else 1; previous = next
                        if (repeats == 5) return snapshot
                    } else repeats = 0
                }
                SystemClock.sleep(200)
            }
            error("No complete stable v3 two-fixture snapshot/readiness")
        }

        fun stopHeartbeat() {
            if (stopped.compareAndSet(false, true)) {
                timer.shutdownNow(); check(timer.awaitTermination(2, TimeUnit.SECONDS))
            }
            check(failure.get() == null)
        }

        fun heartbeatsSent(): Long = sequence.get()

        fun armShortcuts(snapshot: DesktopSnapshot) {
            check(snapshot.displays.all { it.shellGeneration == snapshot.generation } && !snapshot.interactionBlocked)
            session.enableShortcuts(snapshot.generation, true)
            // The one-way request uses the live authenticated lease; the host
            // must also prove normal pre-lock input and no post-lock callback.
            Thread.sleep(150)
            check(failure.get() == null && events.revoked.isEmpty())
        }

        fun apply(request: Long, hidden: Boolean = false, vertical: Boolean = false,
            restore: DesktopSnapshot? = null, signed: Boolean = false): DesktopSnapshot {
            val current = stable()
            val frame = DesktopFrame().apply {
                topologyRevision = current.topologyRevision; focusedDisplayToken = 0; focusedToken = 0
                placements = current.tasks.mapIndexed { index, task -> DesktopPlacement().apply {
                    token = task.token; destinationDisplayToken = task.displayToken
                    val saved = restore?.tasks?.single { it.token == task.token }
                    bounds = saved?.bounds ?: if (vertical) {
                        val monitor = current.displays.single { it.token == task.displayToken }
                        val area = monitor.bounds
                        check(current.tasks.all { it.displayToken == monitor.token }) { "Vertical probe requires one monitor" }
                        DesktopRect().apply {
                            left = area.left + 3; right = area.right - 3
                            top = area.top + index * (area.bottom - area.top) / 2 + 3
                            bottom = area.top + (index + 1) * (area.bottom - area.top) / 2 - 3
                        }
                    } else task.bounds
                    visible = !hidden; inputEnabled = !hidden; zOrder = task.zOrder
                } }.toTypedArray()
                shellRegions = emptyArray()
            }
            if (signed) session.applySignedFrame(current.generation, request, current.revision, frame)
            else session.applyFrame(current.generation, request, current.revision, frame)
            val result = checkNotNull(events.results.poll(20, TimeUnit.SECONDS)) { "No real native frame completion" }
            check(result.take(3) == listOf(current.generation, request, DesktopProtocol.RESULT_APPLIED.toLong()))
            return stable().also { applied ->
                check(applied.tasks.all { it.visible != hidden && it.inputEnabled != hidden })
                check(applied.tasks.all { task -> frame.placements.single { it.token == task.token }.let { desired ->
                    task.displayToken == desired.destinationDisplayToken && rect(task.bounds) == rect(desired.bounds)
                } })
            }
        }

        override fun close() {
            try { stopHeartbeat() } finally { events.snapshot.get()?.let { session.release(it.generation) } }
        }
    }

    fun retainedCalls(session: IDesktopSession, snapshot: DesktopSnapshot) {
        val gen = snapshot.generation
        session.applyFrame(gen, 1, snapshot.revision, null)
        session.focusTask(gen, 2, snapshot.revision, snapshot.tasks.first().token)
        session.closeTask(gen, 3, snapshot.revision, snapshot.tasks.first().token)
        session.enableShortcuts(gen, true)
        session.heartbeat(gen, 1000000)
        session.release(gen)
        session.enableExternalUi(gen)
        session.showShell(gen, snapshot.displays.first().token)
        check(session.launcherPage(gen, 0, snapshot.displays.first().token, 0) == null)
        session.showLauncher(gen, 1)
        session.selectLauncher(gen, 1, 0)
        session.showTransferPicker(gen, snapshot.displays.first().token)
        session.applySignedFrame(gen, 4, snapshot.revision, null)
    }

    fun continuity(snapshot: DesktopSnapshot) = NativeProbeContinuity(snapshot.generation,
        snapshot.identityEpoch, snapshot.tasks.map { it.token }.toSet())

    fun proof(snapshot: DesktopSnapshot) = JSONObject().put("generation", snapshot.generation)
        .put("identity_epoch", snapshot.identityEpoch).put("revision", snapshot.revision)
        .put("topology_revision", snapshot.topologyRevision).put("interaction_blocked", snapshot.interactionBlocked)
        .put("focused_display_token", snapshot.focusedDisplayToken).put("focused_token", snapshot.focusedToken)
        .put("displays", JSONArray(snapshot.displays.map { display -> JSONObject()
            .put("token", display.token).put("display_id", display.displayId).put("identity_hint", display.identityHint)
            .put("shell_generation", display.shellGeneration).put("secure", display.secure).put("bounds", JSONArray(rect(display.bounds))) }))
        .put("tasks", JSONArray(snapshot.tasks.map { task -> JSONObject().put("token", task.token)
            .put("display_token", task.displayToken).put("package", task.packageName).put("bounds", JSONArray(rect(task.bounds)))
            .put("visible", task.visible).put("input", task.inputEnabled).put("z", task.zOrder) }))

    fun await(timeout: Long, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeout
        while (!condition()) { check(SystemClock.elapsedRealtime() < deadline) { "Native security phase timed out" }; SystemClock.sleep(100) }
    }

    private fun rect(value: DesktopRect) = listOf(value.left, value.top, value.right, value.bottom)
    private fun fingerprint(snapshot: DesktopSnapshot): String {
        val parcel = Parcel.obtain()
        try { snapshot.writeToParcel(parcel, 0); return Base64.encodeToString(parcel.marshall(), Base64.NO_WRAP) }
        finally { parcel.recycle() }
    }

    private fun publishOrdinaryModel(context: Context, snapshot: DesktopSnapshot, display: DesktopDisplay) {
        val loader = context.classLoader
        val rect = loader.loadClass("org.wonad.desktop.ShellRect").getConstructor(
            Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            .newInstance(display.bounds.left, display.bounds.top, display.bounds.right, display.bounds.bottom)
        val sceneClass = loader.loadClass("org.wonad.desktop.ShellScene")
        val scene = sceneClass.constructors.single { it.parameterCount == 9 }.newInstance(snapshot.generation,
            snapshot.revision, display.token, display.displayId, rect, emptyList<Any>(), null, true,
            snapshot.capabilities and DesktopProtocol.CAP_SIGNED_PLACEMENT != 0L)
        val ui = loader.loadClass("org.wonad.desktop.ShellUi")
        val publish = ui.methods.single { it.name == "publish" && it.parameterCount == 2 }
        val unit = loader.loadClass("kotlin.Unit").getField("INSTANCE").get(null)
        val callback = Proxy.newProxyInstance(loader, arrayOf(publish.parameterTypes[1])) { _, method, args -> when (method.name) {
            "invoke" -> unit; "toString" -> "Native lock/user test shell"; "hashCode" -> 1; "equals" -> args?.singleOrNull() === ui; else -> null
        } }
        publish.invoke(ui.getField("INSTANCE").get(null), scene, callback)
    }
}
