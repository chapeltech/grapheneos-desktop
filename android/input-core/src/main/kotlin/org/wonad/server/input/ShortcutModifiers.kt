package org.wonad.server.input

/** Scalar Android modifier arithmetic, shared by tests and WM pointer routing. */
internal object ShortcutModifiers {
    fun held(key: Int, action: Int, state: Int, cancelled: Boolean, prefix: Int, strict: Boolean = false): Boolean {
        if (cancelled || prefix !in setOf(0x10000, 0x11000)) return false
        var bits = state
        // Key-up metaState can still include the released side. Preserve the
        // opposite side only, then normalize the two aggregate modifier bits.
        if (action == 1) when (key) {
            117 -> if (state and 0x40000 == 0) bits = bits and 0x10000.inv()
            118 -> if (state and 0x20000 == 0) bits = bits and 0x10000.inv()
            113 -> if (state and 0x4000 == 0) bits = bits and 0x1000.inv()
            114 -> if (state and 0x2000 == 0) bits = bits and 0x1000.inv()
        }
        return if (strict) bits and (0x11000 or 1 or 2 or 4 or 8) == prefix
            else bits and prefix == prefix && bits and (1 or 2 or 4 or 8) == 0
    }
}
