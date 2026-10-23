package org.wonad.desktop

/** TEST-client-only expectation for the next exact callback, never OS policy.
 * A host must arm while the exact lease is ready, receive its nonce ack, then
 * deliberately trigger one reviewed lock/user-change/frozen-client disturbance
 * within 120s. This is an expectation of the actual onRevoked callback: Binder
 * death or a heartbeat exception is not a substitute for that callback.
 * Any different/late/duplicate callback still fails the runtime. */
internal data class RuntimeRevocationRequest(val generation: Long, val identityEpoch: Long, val reason: Int)

internal class ConformanceExpectedRevocation(private val clock: () -> Long) {
    private data class Record(val nonce: String, val request: RuntimeRevocationRequest, val deadline: Long)
    private var armed: Record? = null
    private var consumed: Record? = null
    private val used = linkedSetOf<String>()

    @Synchronized fun arm(nonce: String, request: RuntimeRevocationRequest,
        currentGeneration: Long, currentIdentityEpoch: Long) {
        require(ConformanceContract.validNonce(nonce)) { "invalid expectation nonce" }
        require(request.generation > 0 && request.identityEpoch > 0 && request.reason in ConformanceContract.expectedRevocationReasons) {
            "only exact LOCKED/USER_CHANGED/CLIENT_FAILED expectations are reviewed"
        }
        check(armed == null) { "another next-revocation expectation is armed" }
        check(request.generation == currentGeneration && request.identityEpoch == currentIdentityEpoch) {
            "expected lease generation/identity epoch is stale"
        }
        check(used.size < ConformanceContract.MAX_RUNTIME_HANDSHAKES && used.add(nonce)) { "expectation nonce replay/bound" }
        val now = clock()
        check(now >= 0 && now <= Long.MAX_VALUE - 120_000) { "invalid expectation clock" }
        consumed = null; armed = Record(nonce, request, now + 120_000)
    }

    @Synchronized fun consume(currentGeneration: Long, currentIdentityEpoch: Long,
        callbackGeneration: Long, callbackReason: Int): Boolean {
        val expected = armed ?: return false
        // It is the NEXT callback even if wrong; cannot leave a reusable
        // expectation behind after observing an unrelated terminal event.
        armed = null
        val now = clock()
        check(now in (expected.deadline - 120_000)..expected.deadline && currentGeneration == expected.request.generation &&
            currentIdentityEpoch == expected.request.identityEpoch && callbackGeneration == expected.request.generation &&
            callbackReason == expected.request.reason) { "next revocation does not match exact armed expectation" }
        consumed = expected
        return true
    }

    @Synchronized fun cancelPending() { armed = null }
    @Synchronized fun pending(): Boolean = armed != null

    @Synchronized fun json(): String {
        val record = armed ?: consumed ?: return "null"
        return "{\"nonce\":\"${record.nonce}\",\"generation\":${record.request.generation}," +
            "\"identity_epoch\":${record.request.identityEpoch},\"reason\":${record.request.reason}," +
            "\"deadline_elapsed_ms\":${record.deadline},\"state\":\"${if (armed != null) "armed" else "consumed"}\"}"
    }
}

/** TEST-only local Binder transport observation. Death is never synthesized
 * from a heartbeat exception or confused with the SDK onRevoked callback. */
internal class ConformanceExpectedBrokerDeath(private val clock: () -> Long) {
    private class Owner(val session: Any, val binder: android.os.IBinder,
        val generation: Long, val identityEpoch: Long, val label: Long) {
        lateinit var recipient: android.os.IBinder.DeathRecipient
        var registered = false
        var callbacks = 0
        var observed: Long? = null
        var retired = false
    }
    private data class Arm(val nonce: String, val owner: Owner, val began: Long, val deadline: Long)
    private var live: Owner? = null
    private var armed: Arm? = null
    private var consumed: String? = null
    private var labels = 0L
    private val used = linkedSetOf<String>()

    @Synchronized fun register(session: Any, binder: android.os.IBinder, generation: Long, epoch: Long) {
        check(live == null && generation > 0 && epoch > 0 && labels < Long.MAX_VALUE)
        val owner = Owner(session, binder, generation, epoch, ++labels)
        owner.recipient = android.os.IBinder.DeathRecipient {
            synchronized(this) {
                // Exact reference fence makes an already-dispatched old recipient inert.
                if (live === owner && !owner.retired) {
                    owner.callbacks++
                    if (owner.observed == null) owner.observed = clock()
                }
            }
        }
        live = owner
        try { binder.linkToDeath(owner.recipient, 0); owner.registered = true }
        catch (error: Throwable) { live = null; throw error }
    }

    @Synchronized fun arm(nonce: String, session: Any, generation: Long, epoch: Long) {
        val owner = checkNotNull(live)
        check(owner.registered && owner.callbacks == 0 && owner.session === session &&
            owner.generation == generation && owner.identityEpoch == epoch && owner.binder.isBinderAlive)
        check(armed == null && ConformanceContract.validNonce(nonce) &&
            used.size < ConformanceContract.MAX_RUNTIME_HANDSHAKES && used.add(nonce)) { "broker-death expectation replay/owner" }
        val now = clock(); check(now >= 0 && now <= Long.MAX_VALUE - 120_000)
        consumed = null; armed = Arm(nonce, owner, now, now + 120_000)
    }

    @Synchronized fun consume(session: Any, generation: Long, epoch: Long): Boolean {
        val owner = checkNotNull(live)
        if (owner.observed == null) return false
        val expectation = checkNotNull(armed) { "unplanned actual broker Binder death" }
        armed = null
        val observed = checkNotNull(owner.observed)
        check(owner.registered && owner.callbacks == 1 && expectation.owner === owner && owner.session === session &&
            owner.generation == generation && owner.identityEpoch == epoch &&
            observed in expectation.began..expectation.deadline && clock() in observed..expectation.deadline &&
            !owner.binder.isBinderAlive) { "broker Binder death differs from exact armed owner/deadline" }
        owner.retired = true
        consumed = render(expectation, "consumed")
        return true
    }

    @Synchronized fun retire() {
        val owner = live; live = null; armed = null
        // Retire exact callback publication before unlink. A dead Binder may
        // already have removed the recipient, but no foreign owner is touched.
        if (owner != null && owner.registered) owner.binder.unlinkToDeath(owner.recipient, 0)
    }

    @Synchronized fun pending(): Boolean = armed != null

    @Synchronized fun json(): String {
        return armed?.let { render(it, "armed") } ?: consumed ?: "null"
    }

    private fun render(record: Arm, state: String): String {
        val owner = record.owner
        return "{\"nonce\":\"${record.nonce}\",\"generation\":${owner.generation}," +
            "\"identity_epoch\":${owner.identityEpoch},\"owner_label\":${owner.label}," +
            "\"registered\":${owner.registered},\"callback_count\":${owner.callbacks}," +
            "\"armed_elapsed_ms\":${record.began},\"deadline_elapsed_ms\":${record.deadline}," +
            "\"observed_elapsed_ms\":${owner.observed ?: "null"}," +
            "\"state\":\"$state\"}"
    }
}
