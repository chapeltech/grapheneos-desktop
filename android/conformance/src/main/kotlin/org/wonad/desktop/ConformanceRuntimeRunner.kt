package org.wonad.desktop

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.SystemClock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.wonad.desktop.api.DesktopFrame
import org.wonad.desktop.api.DesktopPlacement
import org.wonad.desktop.api.DesktopProtocol
import org.wonad.desktop.api.DesktopRect
import org.wonad.desktop.api.DesktopSnapshot
import org.wonad.desktop.api.IDesktopBroker
import org.wonad.desktop.api.IDesktopSession

/** Long-lived, policy-free v3 probe. It owns no workspace, layout, floating,
 * panel or border decision: placement requests copy a bounded live observation
 * or explicitly replay that observation after same-mode connector replacement.
 * Both require an exact host handshake; neither invents layout geometry. */
internal class ConformanceRuntimeRunner(
    private val context: Context,
    private val ledger: ConformanceRuntimeLedger,
    private val initialNonce: String,
) : Runnable {
    private class BoundBroker(private val context: Context) : AutoCloseable {
        private val latch = CountDownLatch(1)
        private val binder = AtomicReference<IBinder?>()
        private val connection = object : android.content.ServiceConnection {
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

    private val instructions = LinkedBlockingQueue<RuntimeHostInstruction>(32)
    private val request = AtomicLong(0x7000L)
    /** A scheduler may outlive its bounded shutdown wait. Nothing it publishes
     * may belong to another lease, even if the OS reuses a numeric generation. */
    private class HeartbeatOwner(val generation: Long) {
        val sequence = AtomicLong()
        val failure = AtomicReference<Throwable?>()
    }
    private val heartbeatPublication = Any()
    private var heartbeatOwner: HeartbeatOwner? = null
    private var heartbeat: ScheduledExecutorService? = null
    private var binding: BoundBroker? = null
    private var session: IDesktopSession? = null
    private var events: ConformanceEvents? = null
    private var snapshot: DesktopSnapshot? = null
    private var remembered: RuntimeSnapshot? = null
    private var plannedRecovery: RuntimeSnapshot? = null
    private var recoveryLease: Pair<Long, Long>? = null
    private var generation = 0L
    private var identityEpoch = 0L
    private var explicitRelease = false
    private var finished = false
    private var waitingForReopen = false
    private var reopenReason: Int? = null
    private val expectedRevocation = ConformanceExpectedRevocation { SystemClock.elapsedRealtime() }
    private val expectedBrokerDeath = ConformanceExpectedBrokerDeath { SystemClock.elapsedRealtime() }
    private val malformedProof = AtomicReference<String?>()
    private var reopenAfterBrokerDeath = false
    private val shellRequested = mutableSetOf<Long>()

    fun expectedRevocationJson(): String = expectedRevocation.json()
    fun expectedBrokerDeathJson(): String = expectedBrokerDeath.json()
    fun malformedProofJson(): String = malformedProof.get() ?: "null"

    @Synchronized fun submit(instruction: RuntimeHostInstruction) {
        check(instruction.run == ledger.run) { "runtime command targets another run" }
        check(instructions.remainingCapacity() > 0) { "runtime command queue is full" }
        ledger.request(instruction.nonce, instruction.phase)
        check(instructions.offer(instruction)) { "runtime command queue admission changed" }
    }

    private fun copy(rect: DesktopRect) = DesktopRect().also {
        it.left = rect.left; it.top = rect.top; it.right = rect.right; it.bottom = rect.bottom
    }

    private fun copiedFrame(value: DesktopSnapshot) = DesktopFrame().also { frame ->
        frame.topologyRevision = value.topologyRevision
        frame.focusedDisplayToken = 0
        frame.focusedToken = 0
        frame.placements = value.tasks.map { task -> DesktopPlacement().also { placement ->
            placement.token = task.token
            placement.destinationDisplayToken = task.displayToken
            placement.bounds = copy(task.bounds)
            placement.visible = task.visible
            placement.inputEnabled = task.inputEnabled
            placement.zOrder = task.zOrder
        } }.toTypedArray()
        frame.shellRegions = emptyArray()
    }

    private fun publish(value: DesktopSnapshot): RuntimeSnapshot {
        val record = RuntimeSnapshot.capture(value)
        check(record.generation == generation && record.identityEpoch == identityEpoch) {
            "runtime session identity changed without revocation"
        }
        check(value.tasks.none { it.packageName == context.packageName }) {
            "broker exposed the policy-free client as an eligible task"
        }
        snapshot = value
        ledger.snapshot(record)
        ConformanceRegistry.displays(generation,
            record.displays.map { display -> display.token to display.displayId })
        return record
    }

    /** `awaitSnapshot` is allowed to return the atomic latest value without
     * consuming older queue entries.  Those entries are harmless transport
     * backlog, not an identity/revision rollback.  Discard only a provably
     * older observation from this exact lease; every other mismatch still
     * reaches [publish] and fails closed. */
    private fun isQueuedBacklog(value: DesktopSnapshot): Boolean {
        val current = snapshot ?: return false
        return value.generation == generation && value.identityEpoch == identityEpoch &&
            (value.revision < current.revision ||
                value.topologyRevision < current.topologyRevision)
    }

    private fun showMissingShells(remote: IDesktopSession, value: DesktopSnapshot): Boolean {
        val live = value.displays.map { it.token }.toSet()
        shellRequested.retainAll(live)
        value.displays.forEach { display ->
            if (display.shellGeneration == generation) shellRequested.remove(display.token)
            else if (shellRequested.add(display.token)) remote.showShell(generation, display.token)
        }
        return !value.interactionBlocked && value.displays.isNotEmpty() &&
            value.displays.all { it.shellGeneration == generation }
    }

    private fun startHeartbeat(remote: IDesktopSession) {
        val owner = HeartbeatOwner(generation)
        synchronized(heartbeatPublication) {
            check(heartbeatOwner == null && owner.generation > 0) { "heartbeat owner is not a fresh live lease" }
            heartbeatOwner = owner
        }
        heartbeat = Executors.newSingleThreadScheduledExecutor().also { scheduler ->
            scheduler.scheduleWithFixedDelay({
                try {
                    remote.heartbeat(owner.generation, owner.sequence.incrementAndGet())
                    synchronized(heartbeatPublication) {
                        if (heartbeatOwner === owner) ledger.heartbeat()
                    }
                } catch (error: Throwable) {
                    synchronized(heartbeatPublication) {
                        if (heartbeatOwner === owner) owner.failure.compareAndSet(null, error)
                    }
                }
            }, 0, 500, TimeUnit.MILLISECONDS)
        }
    }

    private fun currentHeartbeatFailure(): Throwable? = synchronized(heartbeatPublication) {
        heartbeatOwner?.failure?.get()
    }

    private fun stopHeartbeat() {
        // Retire publication BEFORE cancellation/wait. Binder work may ignore
        // interruption; a timeout cannot make its later completion current.
        synchronized(heartbeatPublication) { heartbeatOwner = null }
        val retired = heartbeat
        heartbeat = null
        retired?.shutdownNow()
        retired?.awaitTermination(2, TimeUnit.SECONDS)
    }

    private fun closeSession(release: Boolean) {
        expectedRevocation.cancelPending()
        malformedProof.set(null)
        var retirementFailure: Throwable? = null
        try { stopHeartbeat() } catch (error: Throwable) { retirementFailure = error }
        try { expectedBrokerDeath.retire() } catch (error: Throwable) {
            val primary = retirementFailure
            if (primary == null) retirementFailure = error
            else if (primary !== error) primary.addSuppressed(error)
        }
        if (release && generation > 0) try { session?.release(generation) } catch (_: Throwable) { }
        session = null; events = null; snapshot = null; generation = 0; identityEpoch = 0
        remembered = null; plannedRecovery = null; recoveryLease = null
        shellRequested.clear()
        try { ConformanceRegistry.displays(0, emptyList()) } catch (error: Throwable) {
            retirementFailure = ConformanceShellRetirement.preserve(retirementFailure, error)
        }
        try { binding?.close() } catch (_: Throwable) { }
        binding = null
        retirementFailure?.let { throw it }
    }

    /** A cleanup failure must not replace the cause being published to the
     * TEST ledger, or prevent publication after authority has been cleared. */
    private fun closePreserving(primary: Throwable?, release: Boolean): Throwable? {
        try { closeSession(release) } catch (cleanup: Throwable) {
            return ConformanceShellRetirement.preserve(primary, cleanup)
        }
        return primary
    }

    private fun open(nonce: String, requestedPhase: String) {
        check(session == null && binding == null)
        val bound = BoundBroker(context)
        binding = bound
        val broker = bound.get()
        val version = broker.apiVersion
        val capabilities = broker.capabilities
        check(version == DesktopProtocol.API_VERSION) { "OS API $version is not frozen v3" }
        val missing = ConformanceContract.runtimeCapabilities and capabilities.inv()
        check(missing == 0L) { "OS runtime capability bits missing: $missing" }
        val callback = ConformanceEvents(ledger)
        val remote = broker.openSession(DesktopProtocol.API_VERSION, callback)
        session = remote; events = callback
        var value = callback.awaitSnapshot("runtime initial eligible external displays") {
            it.generation > 0 && it.displays.isNotEmpty()
        }
        generation = value.generation; identityEpoch = value.identityEpoch
        expectedBrokerDeath.register(remote, remote.asBinder(), generation, identityEpoch)
        waitingForReopen = false
        ledger.negotiated(version, capabilities)
        publish(value)
        startHeartbeat(remote)
        remote.enableExternalUi(generation)

        val deadline = SystemClock.elapsedRealtime() + 20_000
        while (true) {
            publish(value)
            if (showMissingShells(remote, value)) break
            ledger.syncingShells()
            val remaining = deadline - SystemClock.elapsedRealtime()
            check(remaining > 0) { "timed out waiting for every external shell" }
            val next = callback.pollSnapshot(remaining.coerceAtMost(500))
            if (next == null) {
                currentHeartbeatFailure()?.let { throw it }
                continue
            }
            if (isQueuedBacklog(next)) continue
            value = next
        }
        plannedRecovery?.let { saved ->
            check(generation > 0 && generation != saved.generation && identityEpoch > 0) {
                "planned recovery did not open a fresh authorized lease"
            }
            recoveryLease = generation to identityEpoch
        }
        ledger.ready(nonce, requestedPhase)
        reopenReason = null
        reopenAfterBrokerDeath = false
    }

    private fun copyObserved(instruction: RuntimeHostInstruction) {
        val remote = checkNotNull(session) { "no live runtime session" }
        val callback = checkNotNull(events)
        if (consumeUndock(callback, instruction)) return
        val before = checkNotNull(snapshot)
        val record = RuntimeSnapshot.capture(before)
        check(!record.interactionBlocked &&
            record.displays.all { it.shellGeneration == record.generation }) {
            "runtime observation is not ready for a copied placement"
        }
        val id = request.incrementAndGet()
        val frame = copiedFrame(before)
        val recovery = plannedRecovery
        if (instruction.phase == ConformanceContract.RUNTIME_RESTORE_OBSERVED) {
            val placements = if (recovery != null) {
                check(recoveryLease == (generation to identityEpoch)) { "planned replay targets another lease" }
                ConformanceObservedReplay.afterExpectedRevocation(recovery, record)
            } else {
                ConformanceObservedReplay.placements(checkNotNull(remembered) { "no exact observation was remembered" }, record)
            }
            frame.placements = placements.map { task ->
                DesktopPlacement().also { placement ->
                    placement.token = task.token
                    placement.destinationDisplayToken = task.displayToken
                    placement.bounds = DesktopRect().also {
                        it.left = task.bounds.left; it.top = task.bounds.top
                        it.right = task.bounds.right; it.bottom = task.bounds.bottom
                    }
                    placement.visible = task.visible; placement.inputEnabled = task.inputEnabled
                    placement.zOrder = task.zOrder
                }
            }.toTypedArray()
        }
        remote.applyFrame(generation, id, before.revision, frame)
        val resultDeadline = SystemClock.elapsedRealtime() + 20_000
        var result: ConformanceEvents.Result? = null
        while (result == null) {
            if (consumeUndock(callback, instruction)) return
            val remaining = resultDeadline - SystemClock.elapsedRealtime()
            check(remaining > 0) { "timed out waiting for copied-placement result" }
            val candidate = callback.pollResult(remaining.coerceAtMost(100)) ?: continue
            if (candidate.request == id) result = candidate
        }
        val appliedResult = checkNotNull(result)
        check(appliedResult.generation == generation) { "copied-placement result changed generation" }
        if (appliedResult.result == DesktopProtocol.RESULT_STALE ||
            appliedResult.result == DesktopProtocol.RESULT_BUSY ||
            appliedResult.result == DesktopProtocol.RESULT_REVOKED) {
            if (appliedResult.result == DesktopProtocol.RESULT_REVOKED &&
                consumeUndock(callback, instruction, 1_000)) return
            ledger.rejected(instruction.nonce, instruction.phase,
                "copied observed placement returned ${appliedResult.result}")
            return
        }
        check(appliedResult.result == DesktopProtocol.RESULT_APPLIED) {
            "exact copied placement returned ${appliedResult.result}"
        }
        val snapshotDeadline = SystemClock.elapsedRealtime() + 20_000
        var after: DesktopSnapshot? = null
        while (after == null) {
            if (consumeUndock(callback, instruction)) return
            val candidate = callback.latestSnapshot()
            if (candidate != null && candidate.generation == generation &&
                candidate.revision >= appliedResult.revision && candidate.displays.isNotEmpty()) {
                after = candidate
                break
            }
            val remaining = snapshotDeadline - SystemClock.elapsedRealtime()
            check(remaining > 0) { "timed out waiting for copied-placement snapshot" }
            callback.pollSnapshot(remaining.coerceAtMost(100))
        }
        val appliedSnapshot = checkNotNull(after)
        publish(appliedSnapshot)
        check(showMissingShells(remote, appliedSnapshot)) { "copied placement lost runtime readiness" }
        if (instruction.phase == ConformanceContract.RUNTIME_RESTORE_OBSERVED && recovery != null) {
            plannedRecovery = null; recoveryLease = null
        }
        ledger.accepted(instruction.nonce, instruction.phase)
    }

    private fun checkpoint(instruction: RuntimeHostInstruction) {
        if (consumeUndock(checkNotNull(events), instruction)) return
        val value = checkNotNull(snapshot) { "runtime has no current observation" }
        publish(value)
        check(showMissingShells(checkNotNull(session), value)) { "runtime checkpoint is not ready" }
        if (instruction.phase == ConformanceContract.RUNTIME_REMEMBER_OBSERVED) {
            remembered = RuntimeSnapshot.capture(value)
            // A new explicit observation replaces any earlier recovery plan.
            plannedRecovery = null; recoveryLease = null
        }
        ledger.accepted(instruction.nonce, instruction.phase)
    }

    private fun malformedObserved(instruction: RuntimeHostInstruction) {
        val remote = checkNotNull(session); val callback = checkNotNull(events)
        check(!waitingForReopen && expectedRevocation.json().let {
            it == "null" || org.json.JSONObject(it).getString("state") != "armed"
        } && expectedBrokerDeath.json().let {
            it == "null" || org.json.JSONObject(it).getString("state") != "armed"
        }) { "Malformed phase requires the current owner, without pending terminal expectations" }
        val before = checkNotNull(snapshot)
        malformedProof.set(null)
        val proof = ConformanceMalformedCalls.run(context, instruction, checkNotNull(binding).get(),
            remote, callback, before, { request.incrementAndGet() },
            { org.json.JSONObject(ledger.json()).getJSONObject("callbacks") })
        publish(checkNotNull(callback.latestSnapshot()))
        check(showMissingShells(remote, checkNotNull(snapshot)))
        malformedProof.set(proof.toString())
        ledger.accepted(instruction.nonce, instruction.phase)
    }

    private fun stop(instruction: RuntimeHostInstruction) {
        explicitRelease = true
        var primary: Throwable? = null
        try { session?.release(generation) } catch (error: Throwable) { primary = error }
        closePreserving(primary, release = false)?.let { throw it }
        ledger.stopped(instruction.nonce, instruction.phase)
        finished = true
    }

    private fun expectRevocation(instruction: RuntimeHostInstruction) {
        check(!expectedBrokerDeath.pending()) { "another terminal expectation is armed" }
        val record = RuntimeSnapshot.capture(checkNotNull(snapshot))
        check(session != null && !waitingForReopen && !record.interactionBlocked &&
            record.displays.all { it.shellGeneration == record.generation }) { "exact lease is not ready for expectation" }
        expectedRevocation.arm(instruction.nonce, checkNotNull(instruction.revocation), generation, identityEpoch)
        ledger.accepted(instruction.nonce, instruction.phase)
    }

    private fun expectBrokerDeath(instruction: RuntimeHostInstruction) {
        val remote = checkNotNull(session)
        val record = RuntimeSnapshot.capture(checkNotNull(snapshot))
        check(!waitingForReopen && !expectedRevocation.pending() && !record.interactionBlocked &&
            record.displays.all { it.shellGeneration == record.generation }) { "broker-death owner is not ready" }
        val requested = checkNotNull(instruction.brokerDeath)
        check(requested == (generation to identityEpoch)) { "broker-death expectation lease differs" }
        expectedBrokerDeath.arm(instruction.nonce, remote, generation, identityEpoch)
        remembered = record // Descriptive observations only, never old Binder authority.
        ledger.accepted(instruction.nonce, instruction.phase)
    }

    private fun consumeBrokerDeath(): Boolean {
        val remote = session ?: return false
        if (!expectedBrokerDeath.consume(remote, generation, identityEpoch)) return false
        check(events?.pollRevocation() == null) { "planned broker death also received an unexpected SDK revocation" }
        val saved = checkNotNull(remembered) { "planned broker death lacks descriptive observation" }
        closeSession(release = false)
        plannedRecovery = saved
        waitingForReopen = true; reopenReason = null; reopenAfterBrokerDeath = true
        ledger.brokerDied()
        return true
    }

    private fun process(instruction: RuntimeHostInstruction) {
        if (instruction.phase in setOf(ConformanceContract.RUNTIME_CHECKPOINT,
                ConformanceContract.RUNTIME_COPY_OBSERVED, ConformanceContract.RUNTIME_REMEMBER_OBSERVED,
                ConformanceContract.RUNTIME_RESTORE_OBSERVED, ConformanceContract.RUNTIME_MALFORMED_OBSERVED) &&
                (session == null || snapshot?.let { value ->
                    val record = RuntimeSnapshot.capture(value)
                    record.interactionBlocked ||
                        record.displays.any { it.shellGeneration != record.generation }
                } != false)) {
            ledger.rejected(instruction.nonce, instruction.phase,
                "runtime observation is not ready")
            return
        }
        when (instruction.phase) {
            ConformanceContract.RUNTIME_EXPECT_REVOCATION -> expectRevocation(instruction)
            ConformanceContract.RUNTIME_EXPECT_BROKER_DEATH -> expectBrokerDeath(instruction)
            ConformanceContract.RUNTIME_MALFORMED_OBSERVED -> malformedObserved(instruction)
            ConformanceContract.RUNTIME_CHECKPOINT -> checkpoint(instruction)
            ConformanceContract.RUNTIME_REMEMBER_OBSERVED -> checkpoint(instruction)
            ConformanceContract.RUNTIME_COPY_OBSERVED -> copyObserved(instruction)
            ConformanceContract.RUNTIME_RESTORE_OBSERVED -> copyObserved(instruction)
            ConformanceContract.RUNTIME_STOP -> stop(instruction)
            ConformanceContract.RUNTIME_REOPEN -> {
                if (session != null || !waitingForReopen) {
                    ledger.rejected(instruction.nonce, instruction.phase,
                        "reopen is valid only after observed undock or exact planned revocation")
                    return
                }
                val brokerDeath = reopenAfterBrokerDeath
                val actualReason = reopenReason
                check(brokerDeath || actualReason != null) { "reopen lacks an actual terminal observation" }
                val savedRecovery = plannedRecovery
                try {
                    open(instruction.nonce, instruction.phase)
                } catch (error: Throwable) {
                    val failure = checkNotNull(closePreserving(error, release = true))
                    plannedRecovery = savedRecovery
                    waitingForReopen = true
                    reopenReason = actualReason
                    reopenAfterBrokerDeath = brokerDeath
                    if (brokerDeath) ledger.brokerDied() else ledger.undocked(checkNotNull(actualReason))
                    ledger.rejected(instruction.nonce, instruction.phase,
                        failure.javaClass.name + ": " + (failure.message ?: "reopen failed"))
                }
            }
            else -> error("unsupported runtime instruction")
        }
    }

    private fun revoked(value: ConformanceEvents.Revocation) {
        check(!expectedBrokerDeath.pending()) {
            "planned broker death received SDK terminal generation=${value.generation} reason=${value.reason}"
        }
        check(value.generation == generation) { "revocation generation changed" }
        val planned = expectedRevocation.consume(generation, identityEpoch, value.generation, value.reason)
        val saved = if (planned) remembered else null
        closeSession(release = false)
        // Retain data, not old authority, only after the exact expected callback.
        // Ordinary undock/unexpected failure never enters this recovery path.
        plannedRecovery = saved
        if (value.reason == DesktopProtocol.REVOKED_UNDOCKED || planned) {
            waitingForReopen = true
            reopenReason = value.reason
            ledger.undocked(value.reason)
        }
        else error("runtime lease revoked for reason ${value.reason}")
    }

    /** Complete a host command as rejected, but keep the runtime alive and
     * explicitly reopenable, when its exact lease ended with final undock. */
    private fun consumeUndock(callback: ConformanceEvents,
        instruction: RuntimeHostInstruction, timeoutMillis: Long = 0): Boolean {
        val value = if (timeoutMillis == 0L) callback.pollRevocation()
            else callback.pollRevocation(timeoutMillis)
        if (value == null) return false
        revoked(value)
        ledger.rejected(instruction.nonce, instruction.phase,
            "final external display was removed")
        return true
    }

    override fun run() {
        var primaryFailure: Throwable? = null
        try {
            open(initialNonce, ConformanceContract.RUNTIME_START)
            while (!finished) {
                if (consumeBrokerDeath()) continue
                var terminal = events?.pollRevocation()
                val heartbeatError = currentHeartbeatFailure()
                if (terminal == null && heartbeatError != null)
                    terminal = events?.pollRevocation(500)
                if (terminal != null) {
                    revoked(terminal)
                    continue
                }
                // Do not drop a terminal already dequeued above: SDK callbacks
                // must be handled before considering a later local death.
                // A heartbeat exception with no actual recipient still fails.
                if (consumeBrokerDeath()) continue
                heartbeatError?.let { throw it }
                val observed = events?.pollSnapshot(100)
                if (observed != null) {
                    if (isQueuedBacklog(observed)) continue
                    if (observed.displays.isEmpty()) {
                        val removal = checkNotNull(events?.pollRevocation(1_000)) {
                            "empty topology arrived without terminal revocation"
                        }
                        revoked(removal)
                        continue
                    }
                    val value = observed
                    publish(value)
                    if (showMissingShells(checkNotNull(session), value)) ledger.settled()
                    else ledger.syncingShells()
                }
                val instruction = if (session == null)
                    instructions.poll(250, TimeUnit.MILLISECONDS) else instructions.poll()
                instruction?.let(::process)
            }
        } catch (error: Throwable) {
            primaryFailure = error
        } finally {
            closePreserving(primaryFailure, release = !explicitRelease)?.let { ledger.fail(it) }
        }
    }
}
