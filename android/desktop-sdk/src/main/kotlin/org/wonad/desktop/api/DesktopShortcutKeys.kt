package org.wonad.desktop.api

/** Finite v1 control alphabet. No device, text, repeat or release data. */
object DesktopShortcutKeys {
    fun valid(argument: Int): Boolean {
        if (argument < 0) return false
        val shifted = argument and 1 != 0
        return when (argument ushr 1) {
            in 8..16, 33, 38, 39, 46, 51, 62, 66, 70, 76 -> true
            36, 40, 42, 47, 69 -> !shifted
            31, 74 -> shifted
            else -> false
        }
    }
}
