package org.wonad.desktop

import org.wonad.desktop.api.DesktopProtocol
import org.wonad.desktop.api.DesktopSnapshot

internal data class RuntimeRect(val left: Int, val top: Int, val right: Int, val bottom: Int)
internal data class RuntimeDisplay(
    val token: Long,
    val displayId: Int,
    val identityHint: Long,
    val shellGeneration: Long,
    val densityDpi: Int,
    val bounds: RuntimeRect,
)
internal data class RuntimeTask(
    val token: Long,
    val displayToken: Long,
    val minimumWidth: Int,
    val minimumHeight: Int,
    val resizable: Boolean,
    val visible: Boolean,
    val inputEnabled: Boolean,
    val zOrder: Int,
    val title: String,
    val packageName: String,
    val bounds: RuntimeRect,
)
internal data class RuntimeSnapshot(
    val generation: Long,
    val revision: Long,
    val topologyRevision: Long,
    val identityEpoch: Long,
    val focusedDisplayToken: Long,
    val focusedToken: Long,
    val interactionBlocked: Boolean,
    val displays: List<RuntimeDisplay>,
    val tasks: List<RuntimeTask>,
) {
    companion object {
        private fun rect(value: org.wonad.desktop.api.DesktopRect): RuntimeRect {
            check(value.left in -DesktopProtocol.MAX_COORDINATE..DesktopProtocol.MAX_COORDINATE &&
                value.top in -DesktopProtocol.MAX_COORDINATE..DesktopProtocol.MAX_COORDINATE &&
                value.right in -DesktopProtocol.MAX_COORDINATE..DesktopProtocol.MAX_COORDINATE &&
                value.bottom in -DesktopProtocol.MAX_COORDINATE..DesktopProtocol.MAX_COORDINATE &&
                value.right > value.left && value.bottom > value.top) { "invalid observed rectangle" }
            return RuntimeRect(value.left, value.top, value.right, value.bottom)
        }

        fun capture(value: DesktopSnapshot): RuntimeSnapshot {
            check(value.generation > 0 && value.revision > 0 && value.topologyRevision > 0 &&
                value.identityEpoch > 0) { "invalid runtime snapshot epoch" }
            check(value.displays.size in 1..DesktopProtocol.MAX_DISPLAYS &&
                value.tasks.size <= DesktopProtocol.MAX_TASKS) { "runtime snapshot exceeds frozen bounds" }
            val displays = value.displays.map { display ->
                check(display.token > 0 && display.displayId > 0 && display.identityHint > 0 &&
                    display.densityDpi > 0 && display.secure &&
                    (display.shellGeneration == 0L || display.shellGeneration == value.generation)) {
                    "invalid observed display incarnation"
                }
                RuntimeDisplay(display.token, display.displayId, display.identityHint,
                    display.shellGeneration, display.densityDpi, rect(display.bounds))
            }
            check(displays.map { it.token }.distinct().size == displays.size &&
                displays.map { it.displayId }.distinct().size == displays.size &&
                displays.map { it.token } == displays.map { it.token }.sorted()) {
                "duplicate observed display incarnation"
            }
            val liveDisplays = displays.map { it.token }.toSet()
            val tasks = value.tasks.map { task ->
                check(task.token > 0 && task.displayToken in liveDisplays &&
                    task.minimumWidth >= 0 && task.minimumHeight >= 0 &&
                    task.visible == task.inputEnabled && task.title.length <= 160 &&
                    task.packageName.isNotEmpty() && task.packageName.length <= 255) {
                    "invalid observed task identity"
                }
                RuntimeTask(task.token, task.displayToken, task.minimumWidth, task.minimumHeight,
                    task.resizable, task.visible, task.inputEnabled, task.zOrder,
                    task.title, task.packageName, rect(task.bounds))
            }
            check(tasks.map { it.token }.distinct().size == tasks.size &&
                tasks.map { it.token } == tasks.map { it.token }.sorted() &&
                tasks.map { it.zOrder }.sorted() == tasks.indices.toList()) {
                "duplicate task identity or incomplete observed z-order"
            }
            check((value.focusedDisplayToken == 0L || value.focusedDisplayToken in liveDisplays) &&
                (value.focusedToken == 0L || tasks.any { it.token == value.focusedToken && it.visible })) {
                "invalid observed focus identity"
            }
            return RuntimeSnapshot(value.generation, value.revision, value.topologyRevision,
                value.identityEpoch, value.focusedDisplayToken, value.focusedToken,
                value.interactionBlocked, displays, tasks)
        }
    }
}

internal data class RuntimeHostInstruction(val run: String, val nonce: String, val phase: String,
    val revocation: RuntimeRevocationRequest? = null, val brokerDeath: Pair<Long, Long>? = null) {
    companion object {
        fun parse(args: Array<out String>): RuntimeHostInstruction {
            require(args.size in setOf(4, 6, 7) && args[0] == ConformanceContract.RUNTIME_COMMAND) {
                "expected exact runtime-command/run/nonce/phase tuple or seven-field revocation expectation"
            }
            require(ConformanceContract.validRun(args[1])) { "invalid runtime run" }
            require(ConformanceContract.validNonce(args[2])) { "invalid runtime nonce" }
            require(args[3] in ConformanceContract.runtimePhases) { "invalid runtime phase" }
            val request = if (args[3] == ConformanceContract.RUNTIME_EXPECT_REVOCATION) {
                require(args.size == 7 && args[4].matches(Regex("[1-9][0-9]*")) &&
                    args[5].matches(Regex("[1-9][0-9]*")) &&
                    args[6] in ConformanceContract.expectedRevocationReasons.map { it.toString() }) {
                    "expected exact positive generation/identity epoch and LOCKED/USER_CHANGED/CLIENT_FAILED reason"
                }
                RuntimeRevocationRequest(checkNotNull(args[4].toLongOrNull()),
                    checkNotNull(args[5].toLongOrNull()), args[6].toInt())
            } else if (args[3] == ConformanceContract.RUNTIME_EXPECT_BROKER_DEATH) {
                require(args.size == 6 && args[4].matches(Regex("[1-9][0-9]*")) &&
                    args[5].matches(Regex("[1-9][0-9]*"))) { "expected exact broker-death generation/epoch" }
                return RuntimeHostInstruction(args[1], args[2], args[3], brokerDeath =
                    checkNotNull(args[4].toLongOrNull()) to checkNotNull(args[5].toLongOrNull()))
            } else {
                require(args.size == 4) { "ordinary runtime instruction has extra fields" }; null
            }
            return RuntimeHostInstruction(args[1], args[2], args[3], request)
        }
    }
}

/** Bounded dumpsys journal for the policy-free runtime mode. API coverage is
 * deliberately reported as a separate, unrun one-shot mode. */
internal class ConformanceRuntimeLedger(
    val run: String,
    private val initialNonce: String,
    private val clock: () -> Long,
) : ConformanceStatus {
    private data class Handshake(val nonce: String, val phase: String, val result: String)

    private val started = clock()
    private var updated = started
    private var state = "running"
    private var phase = "opening"
    private var failure: String? = null
    private var controlError: String? = null
    private var initialReadiness = false
    private var apiVersion = 0
    private var capabilities = 0L
    private var heartbeatCount = 0L
    private var sessionOpen = false
    private var runtimeReady = false
    private var reopenRequired = false
    private var revocationReason: Int? = null
    private var snapshot: RuntimeSnapshot? = null
    private var handshake = Handshake(initialNonce, ConformanceContract.RUNTIME_START, "pending")
    private val nonces = linkedSetOf(initialNonce)
    private val callbackCounts = ConformanceContract.callbacks.associateWith { 0L }.toMutableMap()
    private val facades = mutableListOf<String>()

    init {
        require(ConformanceContract.validRun(run) && ConformanceContract.validNonce(initialNonce))
    }

    private fun touched() { updated = clock() }
    private fun requirePending(nonce: String, requestedPhase: String) {
        check(handshake == Handshake(nonce, requestedPhase, "pending")) {
            "runtime handshake does not match the pending host instruction"
        }
    }

    @Synchronized fun request(nonce: String, requestedPhase: String) {
        require(ConformanceContract.validNonce(nonce) && requestedPhase in ConformanceContract.runtimePhases)
        check(handshake.result != "pending") { "another host instruction is pending" }
        check(nonces.size < ConformanceContract.MAX_RUNTIME_HANDSHAKES) { "runtime handshake bound reached" }
        check(nonces.add(nonce)) { "runtime nonce replay" }
        handshake = Handshake(nonce, requestedPhase, "pending")
        controlError = null; phase = "host-$requestedPhase"; touched()
    }

    @Synchronized fun negotiated(version: Int, bits: Long) {
        apiVersion = version; capabilities = bits; sessionOpen = true
        runtimeReady = false; reopenRequired = false; revocationReason = null
        snapshot = null; state = "running"; phase = "opening"; touched()
    }

    @Synchronized fun snapshot(value: RuntimeSnapshot) {
        val previous = snapshot
        check(previous == null || (value.generation == previous.generation &&
            value.identityEpoch == previous.identityEpoch && value.revision >= previous.revision &&
            value.topologyRevision >= previous.topologyRevision)) {
            "runtime snapshot identity or revision regressed"
        }
        snapshot = value; touched()
    }

    @Synchronized fun syncingShells() {
        runtimeReady = false; state = "running"; phase = "syncing-shells"; touched()
    }

    @Synchronized fun settled() {
        val value = checkNotNull(snapshot)
        check(sessionOpen && !value.interactionBlocked &&
            value.displays.all { it.shellGeneration == value.generation })
        runtimeReady = true; state = "ready"; phase = "ready"; touched()
    }

    @Synchronized fun ready(nonce: String, requestedPhase: String) {
        requirePending(nonce, requestedPhase)
        val value = checkNotNull(snapshot) { "runtime cannot be ready without a snapshot" }
        check(sessionOpen && !value.interactionBlocked && value.displays.isNotEmpty() &&
            value.displays.all { it.shellGeneration == value.generation }) {
            "runtime cannot be ready before every display shell"
        }
        handshake = Handshake(nonce, requestedPhase, "accepted")
        if (requestedPhase == ConformanceContract.RUNTIME_START && nonce == initialNonce)
            initialReadiness = true
        controlError = null; runtimeReady = true; reopenRequired = false
        state = "ready"; phase = "ready"; touched()
    }

    @Synchronized fun accepted(nonce: String, requestedPhase: String) {
        requirePending(nonce, requestedPhase)
        handshake = Handshake(nonce, requestedPhase, "accepted")
        controlError = null; phase = "ready"; touched()
    }

    @Synchronized fun rejected(nonce: String, requestedPhase: String, reason: String) {
        requirePending(nonce, requestedPhase)
        handshake = Handshake(nonce, requestedPhase, "rejected")
        controlError = reason.take(512)
        phase = if (reopenRequired) "waiting-reopen" else "ready"; touched()
    }

    @Synchronized fun undocked(reason: Int) {
        sessionOpen = false; runtimeReady = false; reopenRequired = true
        revocationReason = reason; state = "waiting-reopen"; phase = "waiting-reopen"; touched()
    }

    @Synchronized fun heartbeat() { heartbeatCount++; touched() }

    /** Local TEST observation, not an invented SDK onRevoked reason. */
    @Synchronized fun brokerDied() {
        sessionOpen = false; runtimeReady = false; reopenRequired = true
        revocationReason = null; state = "waiting-reopen"; phase = "waiting-reopen"; touched()
    }

    @Synchronized fun stopped(nonce: String, requestedPhase: String) {
        requirePending(nonce, requestedPhase)
        handshake = Handshake(nonce, requestedPhase, "accepted")
        sessionOpen = false; runtimeReady = false; reopenRequired = false
        state = "stopped"; phase = "stopped"; touched()
    }

    @Synchronized fun fail(error: Throwable) {
        sessionOpen = false; runtimeReady = false; reopenRequired = false
        state = "failed"; phase = "failed"
        failure = (error.javaClass.name + ": " + (error.message ?: "no message")).take(1024)
        touched()
    }

    @Synchronized override fun callback(name: String) {
        require(name in ConformanceContract.callbacks)
        callbackCounts[name] = callbackCounts.getValue(name) + 1; touched()
    }

    @Synchronized override fun facade(name: String, valid: Boolean) {
        require(name in listOf("ExternalHomeActivity", "ExternalShellActivity", "LauncherActivity"))
        if (facades.size < 64) facades.add(name + ":" + if (valid) "valid" else "rejected")
        touched()
    }

    @Synchronized override fun terminalState(): String = state
    @Synchronized fun initialReady(nonce: String): Boolean =
        nonce == initialNonce && initialReadiness

    private fun quote(value: String): String = buildString {
        append('"')
        value.forEach { character -> when (character) {
            '"' -> append("\\\""); '\\' -> append("\\\\"); '\n' -> append("\\n")
            '\r' -> append("\\r"); '\t' -> append("\\t")
            else -> if (character.code < 32) append("\\u%04x".format(character.code)) else append(character)
        } }
        append('"')
    }
    private fun rect(value: RuntimeRect) =
        "[${value.left},${value.top},${value.right},${value.bottom}]"

    @Synchronized override fun json(): String {
        val callbacks = ConformanceContract.callbacks.joinToString(",", "{", "}") {
            quote(it) + ":" + callbackCounts.getValue(it)
        }
        val snapshotJson = snapshot?.let { value -> buildString {
            append('{')
            append("\"generation\":").append(value.generation)
            append(",\"revision\":").append(value.revision)
            append(",\"topology_revision\":").append(value.topologyRevision)
            append(",\"identity_epoch\":").append(value.identityEpoch)
            append(",\"focused_display_token\":").append(value.focusedDisplayToken)
            append(",\"focused_token\":").append(value.focusedToken)
            append(",\"interaction_blocked\":").append(value.interactionBlocked)
            append(",\"display_incarnations\":[")
            append(value.displays.joinToString(",") { display ->
                "{\"token\":${display.token},\"display_id\":${display.displayId}," +
                    "\"identity_hint\":${display.identityHint},\"shell_generation\":${display.shellGeneration}," +
                    "\"density_dpi\":${display.densityDpi},\"bounds\":${rect(display.bounds)}}"
            })
            append("],\"tasks\":[")
            append(value.tasks.joinToString(",") { task ->
                "{\"token\":${task.token},\"display_token\":${task.displayToken}," +
                    "\"minimum_width\":${task.minimumWidth},\"minimum_height\":${task.minimumHeight}," +
                    "\"resizable\":${task.resizable}," +
                    "\"visible\":${task.visible},\"input_enabled\":${task.inputEnabled}," +
                    "\"z_order\":${task.zOrder},\"title\":${quote(task.title)}," +
                    "\"package_name\":${quote(task.packageName)},\"bounds\":${rect(task.bounds)}}"
            })
            append("]}")
        } } ?: "null"
        return buildString {
            append('{')
            append("\"schema\":1,\"kind\":\"policy_free_conformance_runtime_v1\"")
            append(",\"run\":").append(quote(run)).append(",\"mode\":\"runtime\"")
            append(",\"state\":").append(quote(state)).append(",\"phase\":").append(quote(phase))
            append(",\"started_elapsed_ms\":").append(started)
            append(",\"updated_elapsed_ms\":").append(updated)
            append(",\"api_version\":").append(apiVersion)
            append(",\"capabilities\":").append(capabilities)
            append(",\"one_shot_api_coverage\":{\"mode\":\"full\",\"status\":\"not_run\"}")
            append(",\"runtime_readiness\":{\"ready\":").append(runtimeReady)
            append(",\"session_open\":").append(sessionOpen)
            append(",\"reopen_required\":").append(reopenRequired).append('}')
            append(",\"revocation_reason\":").append(revocationReason ?: "null")
            append(",\"heartbeat_count\":").append(heartbeatCount)
            append(",\"handshake\":{\"nonce\":").append(quote(handshake.nonce))
            append(",\"phase\":").append(quote(handshake.phase))
            append(",\"result\":").append(quote(handshake.result)).append('}')
            append(",\"snapshot\":").append(snapshotJson)
            append(",\"callbacks\":").append(callbacks)
            append(",\"facades\":[").append(facades.joinToString(",") { quote(it) }).append(']')
            append(",\"failure\":").append(failure?.let(::quote) ?: "null")
            append(",\"control_error\":").append(controlError?.let(::quote) ?: "null")
            append('}')
        }
    }
}
