package org.wonad.server.input

/** Internal to the OS, not the APK API. Rust owns bounded key-pair tracking. */
internal object InputNative {
    init { System.loadLibrary("wonad_input_jni") }
    // Pure fixed alphabet only; event() remains the sole lease/input authority.
    @JvmStatic external fun commandKey(keyCode: Int): Boolean
    @JvmStatic external fun shortcutPrefix(): Int
    @JvmStatic external fun renewKeys(generation: Long, user: Int, display: Int, expires: Long, now: Long): Boolean
    @JvmStatic external fun renew(generation: Long, user: Int, display: Int, expires: Long, now: Long): Boolean
    @JvmStatic external fun release(generation: Long)
    @JvmStatic external fun releaseDisplay(generation: Long, display: Int)
    // now/user/display/focused-display/unlocked/eligible/trusted/code/modifiers/
    // action/repeat/device/down-time/cancelled. 0=pass, -1=drain, positive=command.
    @JvmStatic external fun event(values: LongArray): Long
    // System-server UI ownership core: 0=Android, 1=live Wonad, 2=claimed/blank.
    @JvmStatic external fun uiRenew(display: Int, incarnation: Long, user: Int,
        generation: Long, expires: Long, now: Long, authorized: Boolean): Boolean
    @JvmStatic external fun uiMode(display: Int, incarnation: Long, now: Long,
        eligible: Boolean, activeUser: Int): Int
    @JvmStatic external fun uiPark(display: Int, incarnation: Long, generation: Long)
    @JvmStatic external fun uiDetach(display: Int, incarnation: Long)
}
