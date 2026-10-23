package org.wonad.desktop

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.os.SystemClock
import android.util.Base64
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONArray
import org.json.JSONObject
import org.wonad.desktop.api.*

/** Bounded TEST phase on the CURRENT held lease: no open/release of live owner,
 * no shell model, layout policy, permissions or platform-private entry point. */
internal object ConformanceMalformedCalls {
    const val MARKER = "WONAD_CONFORMANCE_MALFORMED "
    const val MAX_MILLIS = 60_000L
    private const val FOREIGN_PACKAGE = "org.wonad.desktop.test"
    private const val FOREIGN_CLASS = "org.wonad.desktop.security.NeutralMalformedCallerService"
    private const val FOREIGN_PROTOCOL = "org.wonad.desktop.security.NeutralMalformedProbe"

    private class Foreign(context: Context) : AutoCloseable {
        private val context = context
        private val ready = CountDownLatch(1)
        private val binder = AtomicReference<IBinder?>()
        private val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, value: IBinder) { binder.set(value); ready.countDown() }
            override fun onServiceDisconnected(name: ComponentName) { binder.set(null) }
            override fun onNullBinding(name: ComponentName) { ready.countDown() }
            override fun onBindingDied(name: ComponentName) { binder.set(null); ready.countDown() }
        }
        init { check(context.bindService(Intent().setComponent(ComponentName(FOREIGN_PACKAGE, FOREIGN_CLASS)), connection, Context.BIND_AUTO_CREATE)) }
        fun get(): IBinder { check(ready.await(5, TimeUnit.SECONDS)); return checkNotNull(binder.get()).also { check(it.isBinderAlive) } }
        override fun close() { context.unbindService(connection) }
    }

    private fun frame(value: DesktopSnapshot) = DesktopFrame().also { frame ->
        frame.topologyRevision = value.topologyRevision; frame.focusedToken = 0; frame.focusedDisplayToken = 0
        frame.placements = value.tasks.map { task -> DesktopPlacement().also {
            it.token = task.token; it.destinationDisplayToken = task.displayToken
            it.bounds = DesktopRect().also { r -> r.left = task.bounds.left; r.top = task.bounds.top; r.right = task.bounds.right; r.bottom = task.bounds.bottom }
            it.visible = task.visible; it.inputEnabled = task.inputEnabled; it.zOrder = task.zOrder
        } }.toTypedArray()
        frame.shellRegions = emptyArray()
    }
    private fun fingerprint(value: DesktopSnapshot): String {
        val parcel = Parcel.obtain()
        return try { value.writeToParcel(parcel, 0); Base64.encodeToString(parcel.marshall(), Base64.NO_WRAP) }
        finally { parcel.recycle() }
    }

    fun run(context: Context, instruction: RuntimeHostInstruction, broker: IDesktopBroker,
        session: IDesktopSession, events: ConformanceEvents, before: DesktopSnapshot,
        nextRequest: () -> Long, counters: () -> JSONObject): JSONObject {
        check(instruction.phase == ConformanceContract.RUNTIME_MALFORMED_OBSERVED &&
            ConformanceContract.validRun(instruction.run) && ConformanceContract.validNonce(instruction.nonce))
        check(context.packageName == "org.wonad.desktop" && Process.myUid() in 10000..19999 &&
            context.applicationInfo.uid == Process.myUid() &&
            context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE == 0)
        check(before.generation > 0 && before.identityEpoch > 0 && !before.interactionBlocked &&
            before.displays.size == 3 && before.tasks.size == 3 && before.displays.all { it.shellGeneration == before.generation } &&
            before.tasks.all { it.packageName == "org.wonad.fixture" })
        val began = SystemClock.elapsedRealtime(); val deadline = began + MAX_MILLIS
        val original = fingerprint(before); val statBefore = File("/proc/self/stat").readText()
        val countsBefore = counters(); val foreign: JSONObject
        fun unchanged() {
            check(SystemClock.elapsedRealtime() <= deadline && events.pollRevocation() == null &&
                events.latestSnapshot()?.let(::fingerprint) == original) { "Rejected calls changed owner authority/native snapshot" }
        }
        check(events.pollResult(0) == null) { "Unconsumed result before malformed phase" }
        Foreign(context).use { bound ->
            val request = Parcel.obtain(); val response = Parcel.obtain()
            val challenge = JSONObject().put("run", instruction.run).put("nonce", instruction.nonce)
                .put("generation", before.generation).put("identity_epoch", before.identityEpoch).put("revision", before.revision)
            try {
                request.writeInterfaceToken(FOREIGN_PROTOCOL); request.writeStrongBinder(session.asBinder())
                request.writeStrongBinder(broker.asBinder()); request.writeTypedObject(before, 0)
                request.writeString(challenge.toString())
                check(bound.get().transact(IBinder.FIRST_CALL_TRANSACTION, request, response, 0)); response.readException()
                foreign = JSONObject(checkNotNull(response.readString())); response.enforceNoDataAvail()
                val echoed = foreign.getJSONObject("challenge")
                check(echoed.keys().asSequence().toSet() == setOf("run", "nonce", "generation", "identity_epoch", "revision"))
                for (key in listOf("run", "nonce")) check(echoed.get(key) is String && echoed.getString(key) == challenge.getString(key))
                for (key in listOf("generation", "identity_epoch", "revision")) {
                    check(echoed.get(key) is Int || echoed.get(key) is Long)
                    check(echoed.getLong(key) == challenge.getLong(key))
                }
                check(foreign.getInt("caller_uid") == Process.myUid() && foreign.getInt("uid") in 10000..19999 &&
                    foreign.getInt("uid") != Process.myUid() && foreign.getInt("pid") != Process.myPid())
            } finally { request.recycle(); response.recycle() }
        }
        unchanged(); check(events.pollResult(0) == null)
        val afterForeign = counters()
        for (key in listOf("onCommand", "onResult", "onRevoked")) check(afterForeign.getLong(key) == countsBefore.getLong(key))
        val wrongGeneration = if (before.generation == Long.MAX_VALUE) 1L else Long.MAX_VALUE
        val stale = JSONArray()
        for (method in listOf("applyFrame", "focusTask", "closeTask", "applySignedFrame")) {
            val id = nextRequest(); check(id > 0)
            when (method) {
                "applyFrame" -> session.applyFrame(wrongGeneration, id, before.revision, frame(before))
                "focusTask" -> session.focusTask(wrongGeneration, id, before.revision, before.tasks.first().token)
                "closeTask" -> session.closeTask(wrongGeneration, id, before.revision, before.tasks.first().token)
                "applySignedFrame" -> session.applySignedFrame(wrongGeneration, id, before.revision, frame(before))
            }
            val result = events.awaitResult(id, (deadline - SystemClock.elapsedRealtime()).coerceAtMost(5000).also { check(it > 0) })
            check(result.generation == before.generation && result.result == DesktopProtocol.RESULT_STALE && result.revision == before.revision)
            stale.put(JSONObject().put("method", method).put("request_id", id).put("sent_generation", wrongGeneration)
                .put("result_generation", result.generation).put("result", result.result).put("result_revision", result.revision))
            unchanged()
        }
        session.enableShortcuts(wrongGeneration, true); session.heartbeat(wrongGeneration, 1)
        session.release(wrongGeneration); session.enableExternalUi(wrongGeneration)
        session.showShell(wrongGeneration, before.displays.first().token)
        check(session.launcherPage(wrongGeneration, 0, before.displays.first().token, 0) == null)
        session.showLauncher(wrongGeneration, 1); session.selectLauncher(wrongGeneration, 1, 0)
        session.showTransferPicker(wrongGeneration, before.displays.first().token)
        val mutations = listOf<Pair<String, (DesktopFrame) -> Unit>>(
            "oversized_placements" to { it.placements = Array(DesktopProtocol.MAX_TASKS + 1) { _ -> it.placements.first() } },
            "oversized_regions" to { it.shellRegions = Array(DesktopProtocol.MAX_SHELL_REGIONS + 1) { _ -> DesktopShellRegion().apply {
                generation = before.generation; displayToken = before.displays.first().token; bounds = before.displays.first().bounds } } },
            "duplicate_task" to { it.placements[1].token = it.placements[0].token },
            "duplicate_z_order" to { it.placements[1].zOrder = it.placements[0].zOrder },
            "missing_task" to { it.placements = it.placements.take(1).toTypedArray() },
            "phone_destination" to { it.placements[0].destinationDisplayToken = 0 },
            "unknown_destination" to { it.placements[0].destinationDisplayToken = -1 },
            "unknown_task" to { it.placements[0].token = -1 },
            "out_of_bounds" to { it.placements[0].bounds.left = -1 },
            "visibility_input_mismatch" to { it.placements[0].inputEnabled = !it.placements[0].visible },
            "wrong_shell_generation" to { it.shellRegions = arrayOf(DesktopShellRegion().apply {
                generation = 0; displayToken = before.displays.first().token; bounds = before.displays.first().bounds }) },
            "phone_shell_region" to { it.shellRegions = arrayOf(DesktopShellRegion().apply {
                generation = before.generation; displayToken = 0; bounds = before.displays.first().bounds }) },
            "stale_topology" to { it.topologyRevision = before.topologyRevision - 1 })
        val malformed = JSONArray()
        mutations.forEach { (name, corrupt) ->
            val candidate = frame(before).also(corrupt); val id = nextRequest(); check(id > 0)
            session.applyFrame(before.generation, id, before.revision, candidate)
            val result = events.awaitResult(id, (deadline - SystemClock.elapsedRealtime()).coerceAtMost(5000).also { check(it > 0) })
            val expected = if (name == "stale_topology") DesktopProtocol.RESULT_STALE else DesktopProtocol.RESULT_INVALID
            check(result.generation == before.generation && result.result == expected && result.revision == before.revision)
            malformed.put(JSONObject().put("case", name).put("request_id", id).put("sent_generation", before.generation)
                .put("result_generation", result.generation).put("result", result.result).put("result_revision", result.revision))
            unchanged()
        }
        SystemClock.sleep(250); unchanged(); check(events.pollResult(0) == null)
        val countsAfter = counters()
        check(countsAfter.getLong("onResult") == countsBefore.getLong("onResult") + 17 &&
            countsAfter.getLong("onCommand") == countsBefore.getLong("onCommand") && countsAfter.getLong("onRevoked") == countsBefore.getLong("onRevoked"))
        return JSONObject().put("schema", 1).put("run", instruction.run).put("nonce", instruction.nonce)
            .put("phase", instruction.phase).put("status", "completed_actual_rejections")
            .put("owner_uid", Process.myUid()).put("owner_pid", Process.myPid()).put("fingerprint", Build.FINGERPRINT)
            .put("proc_stat_before_b64", Base64.encodeToString(statBefore.toByteArray(Charsets.UTF_8), Base64.NO_WRAP))
            .put("proc_stat_after_b64", Base64.encodeToString(File("/proc/self/stat").readBytes(), Base64.NO_WRAP))
            .put("generation", before.generation).put("identity_epoch", before.identityEpoch).put("revision", before.revision)
            .put("topology_revision", before.topologyRevision).put("snapshot_before_b64", original)
            .put("snapshot_after_b64", fingerprint(checkNotNull(events.latestSnapshot())))
            .put("began_elapsed_ms", began).put("ended_elapsed_ms", SystemClock.elapsedRealtime()).put("deadline_elapsed_ms", deadline)
            .put("foreign", foreign).put("stale_results", stale).put("stale_inert_methods", JSONArray(listOf("enableShortcuts", "heartbeat", "release",
                "enableExternalUi", "showShell", "launcherPage", "showLauncher", "selectLauncher", "showTransferPicker")))
            .put("malformed_results", malformed).put("callbacks_before", countsBefore).put("callbacks_after_foreign", afterForeign).put("callbacks_after", countsAfter)
    }
}
