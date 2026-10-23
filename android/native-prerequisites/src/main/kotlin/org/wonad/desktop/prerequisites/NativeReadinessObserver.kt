package org.wonad.desktop.prerequisites

import android.os.Parcel
import android.os.SystemClock
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.wonad.desktop.api.*

/** Ordinary probe-only callback tee. It grants no authority and forwards EVERY callback. */
internal class NativeReadinessObserver(private val clock: () -> Long = { SystemClock.elapsedRealtime() }) {
    private val journal = NativeReadinessJournal()
    private val started = clock()

    fun broker(remote: IDesktopBroker): IDesktopBroker = object : IDesktopBroker by remote {
        override fun openSession(apiVersion: Int, callback: IDesktopCallback): IDesktopSession =
            remote.openSession(apiVersion, object : IDesktopCallback.Stub() {
                override fun onSnapshot(snapshot: DesktopSnapshot) {
                    try { observe(snapshot) } finally { callback.onSnapshot(snapshot) }
                }
                override fun onCommand(generation: Long, command: Int, argument: Int, taskToken: Long, displayToken: Long) =
                    callback.onCommand(generation, command, argument, taskToken, displayToken)
                override fun onResult(generation: Long, requestId: Long, result: Int, revision: Long) =
                    callback.onResult(generation, requestId, result, revision)
                override fun onRevoked(generation: Long, reason: Int) = callback.onRevoked(generation, reason)
            })
    }

    private fun observe(snapshot: DesktopSnapshot) {
        // Diagnostic failures cannot suppress or mutate the real callback.
        // The exact original Lease.stable implementation remains the ONLY readiness predicate.
        journal.append { sequence ->
            val observed = clock()
            try {
                val displays = snapshot.displays
                val tasks = snapshot.tasks
                check(displays.size <= 9 && tasks.size <= 128)
                val parcel = Parcel.obtain()
                val raw = try { snapshot.writeToParcel(parcel, 0); parcel.marshall() } finally { parcel.recycle() }
                check(raw.size <= 128 * 1024)
                val words = mutableListOf(3L, snapshot.generation, snapshot.revision, snapshot.topologyRevision,
                    snapshot.capabilities, snapshot.focusedDisplayToken, snapshot.focusedToken, snapshot.identityEpoch,
                    if (snapshot.interactionBlocked) 1L else 0L, displays.size.toLong(), tasks.size.toLong())
                val decoded = JSONObject().put("generation", snapshot.generation).put("revision", snapshot.revision)
                    .put("topology_revision", snapshot.topologyRevision).put("capabilities", snapshot.capabilities)
                    .put("focused_display_token", snapshot.focusedDisplayToken).put("focused_token", snapshot.focusedToken)
                    .put("identity_epoch", snapshot.identityEpoch).put("interaction_blocked", snapshot.interactionBlocked)
                decoded.put("displays", JSONArray(displays.map { display ->
                    val bounds = listOf(display.bounds.left, display.bounds.top, display.bounds.right, display.bounds.bottom)
                    words.addAll(listOf(display.token, display.displayId.toLong(), *bounds.map { it.toLong() }.toTypedArray(),
                        display.densityDpi.toLong(), if (display.secure) 1L else 0L, display.shellGeneration, display.identityHint))
                    JSONObject().put("token", display.token).put("display_id", display.displayId)
                        .put("bounds", JSONArray(bounds)).put("density", display.densityDpi).put("secure", display.secure)
                        .put("shell_generation", display.shellGeneration).put("identity_hint", display.identityHint)
                }))
                decoded.put("tasks", JSONArray(tasks.map { task ->
                    val bounds = listOf(task.bounds.left, task.bounds.top, task.bounds.right, task.bounds.bottom)
                    words.addAll(listOf(task.token, task.displayToken, *bounds.map { it.toLong() }.toTypedArray(),
                        task.minimumWidth.toLong(), task.minimumHeight.toLong(), if (task.resizable) 1L else 0L,
                        if (task.visible) 1L else 0L, if (task.inputEnabled) 1L else 0L, task.zOrder.toLong()))
                    JSONObject().put("token", task.token).put("display_token", task.displayToken)
                        .put("bounds", JSONArray(bounds)).put("minimum_width", task.minimumWidth)
                        .put("minimum_height", task.minimumHeight).put("resizable", task.resizable)
                        .put("visible", task.visible).put("input", task.inputEnabled).put("z", task.zOrder)
                        .put("package", task.packageName).put("title", task.title)
                }))
                JSONObject().put("sequence", sequence).put("elapsed_ms", observed).put("word_schema", "native_snapshot_diagnostic_v1")
                    .put("words", JSONArray(words)).put("parcel_base64", Base64.encodeToString(raw, Base64.NO_WRAP))
                    .put("parcel_bytes", raw.size).put("decoded", decoded)
                    .put("two_fixture_tasks", tasks.size == 2 && tasks.all { it.packageName == "org.wonad.fixture" })
                    .put("unblocked", !snapshot.interactionBlocked)
                    .put("all_shells_ready", displays.all { it.shellGeneration == snapshot.generation }).toString()
            } catch (error: Exception) {
                JSONObject().put("sequence", sequence).put("elapsed_ms", observed)
                    .put("observation_error", error.javaClass.name.take(160)).toString()
            }
        }
    }

    fun failure(): JSONObject {
        val capture = journal.capture()
        val finished = clock()
        return JSONObject().put("schema", 1).put("kind", "test_only_pre_release_native_readiness_callbacks")
            .put("started_elapsed_ms", started).put("captured_elapsed_ms", finished)
            .put("maximum_rows", NativeReadinessJournal.MAXIMUM_ROWS)
            .put("maximum_bytes", NativeReadinessJournal.MAXIMUM_BYTES).put("retained_bytes", capture.bytes)
            .put("callbacks_seen", capture.seen).put("callbacks_dropped", capture.dropped)
            .put("stable_deadline_ms", 15000).put("stable_required_identical_polls", 5)
            .put("stable_poll_repeats", "not_observed")
            // Preserve original JSON UTF-8 strings so the host can rederive
            // the exact retained-byte bound without assuming JSON formatting.
            .put("callbacks", JSONArray(capture.rows))
    }
}
