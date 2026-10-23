package org.wonad.desktop.broker

/** Private Kotlin/Rust bridge for the sole workspace-free API3 broker.
 * Arrays contain copied scalar values only; Android object handles never cross
 * this boundary and validation never substitutes for session authorization. */
internal object BrokerNative {
    init { System.loadLibrary("wonad_broker_jni") }

    @JvmStatic external fun initialize(allowedSigner: ByteArray, generationSeed: Long): Boolean

    /** 0 wait, 1 observed application, 2 platform constraint, 3 timeout. */
    @JvmStatic external fun completion(finished: Boolean, aborted: Boolean, now: Long,
        deadline: Long, matches: Boolean): Int

    /** Header: now/generation/sequence/baseRevision/actualRevision/version/
     * callerUID/callerUser/packageMatches/sharedUID/signer(4)/activeUser/
     * topologyRevision/enabled/locked/displayCount, then trusted nine-long
     * display rows. Operations 1..8 are open, reconcile, heartbeat, admit,
     * finish, release, death and topology update. */
    @JvmStatic external fun nativeSession(operation: Int, values: LongArray): Long

    /** Workspace-free contained frame validation. */
    @JvmStatic external fun nativeValidateFrame(current: LongArray, desired: LongArray): Int

    /** Capability-gated finite signed/off-screen task placement validation. */
    @JvmStatic external fun nativeValidateSignedFrame(current: LongArray, desired: LongArray): Int

    /** Actual observed placements; focus and shell regions are checked separately. */
    @JvmStatic external fun nativeFrameMatches(current: LongArray, desired: LongArray): Boolean

    /** Exact tracked task identity and optional input eligibility. */
    @JvmStatic external fun nativeTaskAllowed(current: LongArray, taskToken: Long,
        needsInput: Boolean): Boolean

    /** One-shot picker: now/ticket/generation/user/displayToken/kind/count-or-index. */
    @JvmStatic external fun nativePicker(operation: Int, values: LongArray): Long
}
