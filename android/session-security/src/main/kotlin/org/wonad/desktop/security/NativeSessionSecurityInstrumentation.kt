package org.wonad.desktop.security

import android.app.Instrumentation
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.os.SystemClock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.lang.reflect.Proxy
import org.json.JSONArray
import org.json.JSONObject
import org.wonad.desktop.api.*

/** Independent v3 proof under real owner/foreign APK UIDs. Instrumentation
 * replaces the normal policy process, but adopts no Shell/system permissions
 * and installs no production endpoint. Native readiness uses the target APK's
 * own public ordinary shell model through its own class loader, not a hidden
 * Android API or a synthetic surface/input handle.
 */
class NativeSessionSecurityInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) { super.onCreate(arguments); start() }

    private class Bound(private val context: Context, intent: Intent) : AutoCloseable {
        private val ready = CountDownLatch(1)
        private val value = AtomicReference<IBinder?>()
        private val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) { value.set(service); ready.countDown() }
            override fun onServiceDisconnected(name: ComponentName) { value.set(null) }
            override fun onNullBinding(name: ComponentName) { ready.countDown() }
            override fun onBindingDied(name: ComponentName) { value.set(null); ready.countDown() }
        }
        init { check(context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) }
        fun binder(): IBinder { check(ready.await(5, TimeUnit.SECONDS)); return checkNotNull(value.get()).also { check(it.isBinderAlive) } }
        override fun close() = context.unbindService(connection)
    }

    private class Events : IDesktopCallback.Stub() {
        val snapshot = AtomicReference<DesktopSnapshot?>()
        val snapshots = AtomicLong()
        val revoked = LinkedBlockingQueue<Pair<Long, Int>>()
        val revocations = AtomicLong()
        val results = LinkedBlockingQueue<List<Long>>()
        val resultCallbacks = AtomicLong()
        val commands = AtomicLong()
        override fun onSnapshot(snapshot: DesktopSnapshot) { snapshots.incrementAndGet(); this.snapshot.set(snapshot) }
        override fun onCommand(generation: Long, command: Int, argument: Int, taskToken: Long, displayToken: Long) { commands.incrementAndGet() }
        override fun onResult(generation: Long, requestId: Long, result: Int, revision: Long) {
            resultCallbacks.incrementAndGet()
            results.add(listOf(generation, requestId, result.toLong(), revision))
        }
        override fun onRevoked(generation: Long, reason: Int) { revocations.incrementAndGet(); revoked.add(generation to reason) }
    }

    private data class UnsupportedAttempt(val version: Int, val events: Events,
        val exception: String, val message: String)

    private fun rejectUnsupported(broker: IDesktopBroker, phase: String): List<UnsupportedAttempt> {
        check(phase == "before_live" || phase == "during_live")
        return intArrayOf(Int.MIN_VALUE, 0, 2, 4, Int.MAX_VALUE).map { version ->
            val events = Events()
            val failure = try {
                broker.openSession(version, events)
                null
            } catch (error: IllegalArgumentException) { error }
            val denied = checkNotNull(failure) { "Unsupported desktop API version $version opened a session" }
            check(denied.javaClass.name == "java.lang.IllegalArgumentException" &&
                denied.message == "Unsupported desktop API version $version") {
                "Wrong rejection for unsupported desktop API version $version"
            }
            UnsupportedAttempt(version, events, denied.javaClass.name, checkNotNull(denied.message))
        }
    }

    private fun unsupportedEvidence(phase: String, attempts: List<UnsupportedAttempt>): JSONObject {
        val versions = intArrayOf(Int.MIN_VALUE, 0, 2, 4, Int.MAX_VALUE)
        check(attempts.map { it.version } == versions.toList())
        val rows = JSONArray()
        attempts.forEach { attempt ->
            val callbacks = JSONObject()
                .put("snapshots", attempt.events.snapshots.get())
                .put("commands", attempt.events.commands.get())
                .put("results", attempt.events.resultCallbacks.get())
                .put("revocations", attempt.events.revocations.get())
            check(callbacks.getLong("snapshots") == 0L && callbacks.getLong("commands") == 0L &&
                callbacks.getLong("results") == 0L && callbacks.getLong("revocations") == 0L &&
                attempt.events.snapshot.get() == null && attempt.events.results.isEmpty() &&
                attempt.events.revoked.isEmpty()) { "Unsupported-version callback escaped in $phase" }
            rows.put(JSONObject().put("version", attempt.version).put("exception", attempt.exception)
                .put("message", attempt.message).put("callbacks", callbacks))
        }
        return JSONObject().put("phase", phase).put("attempts", rows)
    }

    private fun unsupportedControl(before: DesktopSnapshot, after: DesktopSnapshot): JSONObject {
        check(fingerprint(before) == fingerprint(after)) { "Unsupported opens changed the healthy v3 snapshot" }
        return JSONObject()
            .put("generation_before", before.generation).put("generation_after", after.generation)
            .put("identity_epoch_before", before.identityEpoch).put("identity_epoch_after", after.identityEpoch)
            .put("display_tokens_before", JSONArray(before.displays.map { it.token }))
            .put("display_tokens_after", JSONArray(after.displays.map { it.token }))
            .put("task_tokens_before", JSONArray(before.tasks.map { it.token }))
            .put("task_tokens_after", JSONArray(after.tasks.map { it.token }))
    }

    private inner class Lease(val session: IDesktopSession, val events: Events) : AutoCloseable {
        private val timer = Executors.newSingleThreadScheduledExecutor()
        private val sequence = AtomicLong()
        private val failure = AtomicReference<Throwable?>()
        private var uiRequested = false
        private val shells = mutableSetOf<Long>()
        init { timer.scheduleAtFixedRate({
            try { events.snapshot.get()?.let { session.heartbeat(it.generation, sequence.incrementAndGet()) } }
            catch (error: Throwable) { failure.compareAndSet(null, error) }
        }, 0, 500, TimeUnit.MILLISECONDS) }

        fun stable(): DesktopSnapshot {
            val deadline = SystemClock.elapsedRealtime() + 15000
            var previous = ""; var count = 0
            while (SystemClock.elapsedRealtime() < deadline) {
                check(failure.get() == null && events.revoked.isEmpty()) { "Native lease lost before a stable snapshot" }
                events.snapshot.get()?.let { snapshot ->
                    check(snapshot.generation > 0 && snapshot.identityEpoch > 0 && snapshot.revision > 0 &&
                        snapshot.displays.isNotEmpty() && snapshot.displays.size <= 9 && !snapshot.interactionBlocked &&
                        snapshot.capabilities and DesktopProtocol.CAP_SIGNED_PLACEMENT != 0L)
                    if (!uiRequested) { uiRequested = true; session.enableExternalUi(snapshot.generation) }
                    snapshot.displays.forEach { display ->
                        check(display.token > 0 && display.displayId > 0 && display.identityHint > 0 && display.secure)
                        if (display.shellGeneration != snapshot.generation) {
                            publishOrdinaryModel(snapshot, display)
                            if (shells.add(display.token)) session.showShell(snapshot.generation, display.token)
                        }
                    }
                    if (snapshot.tasks.size == 2 && snapshot.tasks.all { it.packageName == "org.wonad.fixture" } &&
                        snapshot.displays.all { it.shellGeneration == snapshot.generation }) {
                        val key = fingerprint(snapshot)
                        count = if (key == previous) count + 1 else 1; previous = key
                        if (count == 5) return snapshot
                    }
                }
                SystemClock.sleep(200)
            }
            error("No complete stable v3 two-fixture snapshot/readiness")
        }

        fun unchanged(snapshot: DesktopSnapshot) {
            repeat(10) {
                check(failure.get() == null && events.revoked.isEmpty() && events.results.isEmpty() && events.commands.get() == 0L)
                check(events.snapshot.get()?.let(::fingerprint) == fingerprint(snapshot)) { "Rejected v3 calls changed native state" }
                SystemClock.sleep(100)
            }
        }

        override fun close() {
            timer.shutdownNow(); check(timer.awaitTermination(2, TimeUnit.SECONDS))
            events.snapshot.get()?.let { session.release(it.generation) }
        }
    }

    private fun publishOrdinaryModel(snapshot: DesktopSnapshot, display: DesktopDisplay) {
        val loader = targetContext.classLoader
        val rect = loader.loadClass("org.wonad.desktop.ShellRect").getConstructor(
            Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            .newInstance(display.bounds.left, display.bounds.top, display.bounds.right, display.bounds.bottom)
        val sceneClass = loader.loadClass("org.wonad.desktop.ShellScene")
        val scene = sceneClass.constructors.single { it.parameterCount == 9 }.newInstance(snapshot.generation,
            snapshot.revision, display.token, display.displayId, rect, emptyList<Any>(), null, true,
            snapshot.capabilities and DesktopProtocol.CAP_SIGNED_PLACEMENT != 0L)
        val ui = loader.loadClass("org.wonad.desktop.ShellUi")
        val publish = ui.methods.single { it.name == "publish" && it.parameterCount == 2 }
        // Test and target APKs may load their own Kotlin runtime. Implement the
        // target's exact public callback interface, not a cross-loader cast.
        val unit = loader.loadClass("kotlin.Unit").getField("INSTANCE").get(null)
        val callback = Proxy.newProxyInstance(loader, arrayOf(publish.parameterTypes[1])) { _, method, _ ->
            when (method.name) { "invoke" -> unit; "toString" -> "Native test model callback"; "hashCode" -> 1; "equals" -> false; else -> null }
        }
        publish.invoke(ui.getField("INSTANCE").get(null), scene, callback)
    }

    private fun open(broker: IDesktopBroker): Lease {
        val deadline = SystemClock.elapsedRealtime() + 10000
        while (true) {
            val events = Events()
            try { return Lease(broker.openSession(DesktopProtocol.API_VERSION, events), events) }
            catch (error: IllegalStateException) {
                // Instrumentation first terminates the normal client. Allow
                // only its bounded Binder-death/recovery race, not a security
                // denial, timeout or any arbitrary admission error.
                if (error.message !in listOf("Native desktop session is already open", "Broker operation failed") ||
                    SystemClock.elapsedRealtime() >= deadline) throw error
                SystemClock.sleep(100)
            }
        }
    }

    private fun staleCalls(session: IDesktopSession, gen: Long, snapshot: DesktopSnapshot) {
        session.applyFrame(gen, 1, snapshot.revision, null)
        session.focusTask(gen, 2, snapshot.revision, snapshot.tasks.first().token)
        session.closeTask(gen, 3, snapshot.revision, snapshot.tasks.first().token)
        session.enableShortcuts(gen, true); session.heartbeat(gen, 1000000); session.release(gen)
        session.enableExternalUi(gen); session.showShell(gen, snapshot.displays.first().token)
        check(session.launcherPage(gen, 0, snapshot.displays.first().token, 0) == null)
        session.showLauncher(gen, 1); session.selectLauncher(gen, 1, 0)
        session.showTransferPicker(gen, snapshot.displays.first().token)
        session.applySignedFrame(gen, 4, snapshot.revision, null)
    }

    private fun frame(snapshot: DesktopSnapshot) = DesktopFrame().apply {
        topologyRevision = snapshot.topologyRevision; focusedDisplayToken = 0; focusedToken = 0
        placements = snapshot.tasks.map { task -> DesktopPlacement().apply {
            token = task.token; destinationDisplayToken = task.displayToken; bounds = task.bounds
            visible = task.visible; inputEnabled = task.inputEnabled; zOrder = task.zOrder
        } }.toTypedArray()
        shellRegions = emptyArray()
    }

    private fun invalidFrames(lease: Lease, snapshot: DesktopSnapshot): JSONObject {
        val cases = listOf<Pair<String, (DesktopFrame) -> Unit>>(
            "oversized_placements" to { it.placements = Array(129) { _ -> it.placements.first() } },
            "oversized_regions" to { it.shellRegions = Array(769) { _ -> DesktopShellRegion().apply {
                generation = snapshot.generation; displayToken = snapshot.displays.first().token; bounds = snapshot.displays.first().bounds } } },
            "duplicate_task" to { it.placements[1].token = it.placements[0].token },
            "duplicate_z_order" to { it.placements[1].zOrder = it.placements[0].zOrder },
            "missing_task" to { it.placements = it.placements.take(1).toTypedArray() },
            "phone_destination" to { it.placements[0].destinationDisplayToken = 0 },
            "unknown_destination" to { it.placements[0].destinationDisplayToken = Long.MAX_VALUE },
            "unknown_task" to { it.placements[0].token = Long.MAX_VALUE },
            "out_of_bounds" to { it.placements[0].bounds = DesktopRect().apply { left = -1; top = 0; right = 100; bottom = 100 } },
            "visibility_input_mismatch" to { it.placements[0].inputEnabled = !it.placements[0].visible },
            "wrong_shell_generation" to { it.shellRegions = arrayOf(DesktopShellRegion().apply {
                generation = 0; displayToken = snapshot.displays.first().token; bounds = snapshot.displays.first().bounds }) },
            "phone_shell_region" to { it.shellRegions = arrayOf(DesktopShellRegion().apply {
                generation = snapshot.generation; displayToken = 0; bounds = snapshot.displays.first().bounds }) },
            "stale_topology" to { it.topologyRevision = snapshot.topologyRevision - 1 })
        val proof = JSONObject()
        cases.forEachIndexed { index, (name, corrupt) ->
            val candidate = frame(snapshot).also(corrupt)
            val id = 100L + index
            lease.session.applyFrame(snapshot.generation, id, snapshot.revision, candidate)
            val result = checkNotNull(lease.events.results.poll(5, TimeUnit.SECONDS)) { "No rejection for $name" }
            val expected = if (name == "stale_topology") DesktopProtocol.RESULT_STALE else DesktopProtocol.RESULT_INVALID
            check(result.take(3) == listOf(snapshot.generation, id, expected.toLong())) { "Wrong rejection for $name: $result" }
            lease.unchanged(snapshot); proof.put(name, expected)
        }
        return proof
    }

    override fun onStart() {
        val report = Bundle()
        try {
            check(targetContext.packageName == "org.wonad.desktop" && Process.myUid() in 10000..19999 &&
                targetContext.applicationInfo.uid == Process.myUid() &&
                targetContext.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE == 0)
            val proof = JSONObject().put("api", 3).put("owner_uid", Process.myUid()).put("owner_pid", Process.myPid())
            Bound(targetContext, Intent("org.wonad.desktop.BIND").setComponent(ComponentName(
                "com.android.systemui", "org.wonad.desktop.broker.WonadBrokerService"))).use { binding ->
                val broker = IDesktopBroker.Stub.asInterface(binding.binder())
                report.putString("phase", "v3_admission")
                check(broker.apiVersion == 3 && broker.capabilities and DesktopProtocol.CAP_FRAME != 0L &&
                    broker.capabilities and DesktopProtocol.CAP_SHELL != 0L &&
                    broker.capabilities and DesktopProtocol.CAP_SIGNED_PLACEMENT != 0L)
                report.putString("phase", "unsupported_before_live")
                val unsupportedBefore = rejectUnsupported(broker, "before_live")
                var unsupportedDuring: List<UnsupportedAttempt>? = null
                var liveControl: JSONObject? = null
                val first = open(broker); val original: DesktopSnapshot
                try {
                    report.putString("phase", "v3_readiness")
                    original = first.stable()
                    proof.put("old_generation", original.generation).put("identity_epoch", original.identityEpoch)
                        .put("display_tokens", JSONArray(original.displays.map { it.token }))
                        .put("task_tokens", JSONArray(original.tasks.map { it.token }))
                    report.putString("phase", "foreign_uid")
                    Bound(targetContext, Intent().setComponent(ComponentName(
                        "org.wonad.desktop.test", "org.wonad.desktop.security.NativeAttackService"))).use { attack ->
                        val request = Parcel.obtain(); val response = Parcel.obtain()
                        try {
                            request.writeInterfaceToken(NativeAttackService.PROBE)
                            request.writeStrongBinder(first.session.asBinder()); request.writeStrongBinder(broker.asBinder())
                            request.writeTypedObject(original, 0)
                            check(attack.binder().transact(IBinder.FIRST_CALL_TRANSACTION, request, response, 0)); response.readException()
                            val uid = response.readInt(); val pid = response.readInt(); val caller = response.readInt()
                            val denied = checkNotNull(response.createStringArrayList())
                            val brokerDenied = checkNotNull(response.createStringArrayList())
                            val uiDenied = checkNotNull(response.createStringArrayList()); response.enforceNoDataAvail()
                            check(uid in 10000..19999 && uid != Process.myUid() && pid != Process.myPid() && caller == Process.myUid())
                            check(denied == NativeAttackService.METHODS && brokerDenied == listOf("getApiVersion", "getCapabilities", "openSession") &&
                                uiDenied == listOf("ExternalHomeActivity", "ExternalShellActivity", "LauncherActivity",
                                    "WonadClientSettingsActivity", "WonadSettingsActivity"))
                            proof.put("attacker_uid", uid).put("attacker_pid", pid).put("denied_methods", JSONArray(denied))
                                .put("denied_broker_methods", JSONArray(brokerDenied)).put("denied_ui_components", JSONArray(uiDenied))
                        } finally { request.recycle(); response.recycle() }
                    }
                    report.putString("phase", "unsupported_during_live")
                    unsupportedDuring = rejectUnsupported(broker, "during_live")
                    first.unchanged(original)
                    liveControl = unsupportedControl(original, checkNotNull(first.events.snapshot.get()))
                } finally { first.close() }
                check(first.events.revoked.poll(5, TimeUnit.SECONDS) == (original.generation to DesktopProtocol.REVOKED_DISABLED))
                open(broker).use { second ->
                    report.putString("phase", "retained_stale_v3")
                    val fresh = second.stable()
                    check(fresh.generation != original.generation && fresh.identityEpoch == original.identityEpoch &&
                        fresh.tasks.map { it.token } == original.tasks.map { it.token } &&
                        fresh.displays.map { it.token } == original.displays.map { it.token })
                    staleCalls(first.session, original.generation, original)
                    staleCalls(first.session, fresh.generation, fresh)
                    staleCalls(second.session, original.generation, fresh)
                    second.unchanged(fresh)
                    check(first.events.revoked.isEmpty() && first.events.results.isEmpty())
                    report.putString("phase", "bounded_invalid_v3_frames")
                    proof.put("invalid_frames", invalidFrames(second, fresh))
                    second.session.applyFrame(fresh.generation, 1000, fresh.revision, frame(fresh))
                    val applied = checkNotNull(second.events.results.poll(20, TimeUnit.SECONDS))
                    check(applied.take(3) == listOf(fresh.generation, 1000L, DesktopProtocol.RESULT_APPLIED.toLong()))
                    check(second.events.revoked.isEmpty())
                    // Exercise the new method as its real owner as well: a
                    // method that simply rejects everyone is not a UID proof.
                    val current = second.stable()
                    second.session.applySignedFrame(current.generation, 1001, current.revision, frame(current))
                    val signed = checkNotNull(second.events.results.poll(20, TimeUnit.SECONDS))
                    check(signed.take(3) == listOf(current.generation, 1001L, DesktopProtocol.RESULT_APPLIED.toLong()))
                    check(second.events.revoked.isEmpty())
                    proof.put("new_generation", fresh.generation).put("stale_calls", 3 * NativeAttackService.METHODS.size)
                        .put("owner_frame", "applied").put("owner_signed_frame", "applied")
                }
                val liveAttempts = checkNotNull(unsupportedDuring)
                val unsupported = JSONArray()
                    .put(unsupportedEvidence("before_live", unsupportedBefore))
                    .put(unsupportedEvidence("during_live", liveAttempts))
                proof.put("unsupported_version_calls", unsupportedBefore.size + liveAttempts.size)
                    .put("unsupported_versions", unsupported)
                    .put("unsupported_control", checkNotNull(liveControl))
            }
            report.putString("native_session_security", "passed"); report.putString("api", "3")
            report.putString("evidence", proof.toString()); report.putString("fingerprint", Build.FINGERPRINT)
            report.putString("native_abi", Build.SUPPORTED_ABIS.first()); report.putString("scope", "v3_unsupported_versions_foreign_retained_stale_and_bounded_frame_signed_rpc")
            finish(-1, report)
        } catch (error: Throwable) {
            report.putString("native_session_security", "not_passed"); report.putString("failure_details", error.stackTraceToString())
            finish(0, report)
        }
    }

    companion object {
        private fun fingerprint(snapshot: DesktopSnapshot): String {
            val parcel = Parcel.obtain()
            try { snapshot.writeToParcel(parcel, 0); return android.util.Base64.encodeToString(parcel.marshall(), android.util.Base64.NO_WRAP) }
            finally { parcel.recycle() }
        }
    }
}
