package org.wonad.desktop.broker

/** V3 completion uses an actual native observation, not a Shell animation ACK.
 * Read `now` AFTER all native proof calls: a late first positive observation
 * must not win over the unchanged transaction deadline. Rust checks the strict
 * boundary independently; a live heartbeat does not extend this deadline.
 */
internal object NativeFrameCompletion {
    const val WAITING = 0
    const val APPLIED = 1
    const val PLATFORM_CONSTRAINT = 2
    const val TIMED_OUT = 3

    fun observe(matches: Boolean, now: Long, deadline: Long): Int =
        BrokerNative.completion(matches, false, now, deadline, matches)
}
