package org.wonad.imefixture

import java.util.UUID

/** Test measurements only. One production object survives service rebindings
 * in the same process; there is deliberately no persistence or reset method.
 */
internal class CompositionProcessMetrics {
    val epoch: String = UUID.randomUUID().toString()

    internal class Instance internal constructor(val id: String, val sequence: Int) {
        internal var alive = true
        internal var starts = 0
        internal var restarts = 0
        internal var actions = 0
        internal var keyDowns = 0
        internal var keyUps = 0
    }

    data class Snapshot(
        val epoch: String, val instance: String, val sequence: Int,
        val creates: Int, val destroys: Int, val alive: Boolean,
        val starts: Int, val restarts: Int, val actions: Int,
        val keyDowns: Int, val keyUps: Int, val lastAction: String,
        val localStarts: Int, val localRestarts: Int, val localActions: Int,
        val localKeyDowns: Int, val localKeyUps: Int
    )

    private val instances = mutableSetOf<Instance>()
    private var creates = 0
    private var destroys = 0
    private var starts = 0
    private var restarts = 0
    private var actions = 0
    private var keyDowns = 0
    private var keyUps = 0
    private var lastAction = "none"

    @Synchronized fun create(): Instance {
        creates = Math.addExact(creates, 1)
        return Instance(UUID.randomUUID().toString(), creates).also { instances.add(it) }
    }

    private fun live(instance: Instance) {
        check(instance in instances && instance.alive) { "Foreign or destroyed IME metrics instance" }
    }

    @Synchronized fun start(instance: Instance, restarting: Boolean) {
        live(instance)
        starts = Math.addExact(starts, 1); instance.starts = Math.addExact(instance.starts, 1)
        if (restarting) {
            restarts = Math.addExact(restarts, 1); instance.restarts = Math.addExact(instance.restarts, 1)
        }
    }

    /** Every actual InputConnection attempt counts, including failed attempts.
     * The caller's existing Press guard decides whether an attempt occurs.
     */
    @Synchronized fun action(instance: Instance, code: Int, accepted: Boolean) {
        live(instance)
        require(code in 137..140)
        actions = Math.addExact(actions, 1); instance.actions = Math.addExact(instance.actions, 1)
        lastAction = "$code:$accepted"
    }

    @Synchronized fun keyDown(instance: Instance) {
        live(instance)
        keyDowns = Math.addExact(keyDowns, 1); instance.keyDowns = Math.addExact(instance.keyDowns, 1)
    }

    @Synchronized fun keyUp(instance: Instance) {
        live(instance)
        keyUps = Math.addExact(keyUps, 1); instance.keyUps = Math.addExact(instance.keyUps, 1)
    }

    @Synchronized fun destroy(instance: Instance) {
        live(instance)
        instance.alive = false
        destroys = Math.addExact(destroys, 1)
    }

    @Synchronized fun snapshot(instance: Instance): Snapshot {
        check(instance in instances) { "Foreign IME metrics instance" }
        return Snapshot(epoch, instance.id, instance.sequence, creates, destroys, instance.alive,
            starts, restarts, actions, keyDowns, keyUps, lastAction,
            instance.starts, instance.restarts, instance.actions, instance.keyDowns, instance.keyUps)
    }
}
