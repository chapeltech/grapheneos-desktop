package org.wonad.desktop.security

/** Test-only geometry selector. Never invents an application minimum. */
internal object NativeFrameConstraintSpec {
    fun impossible(box: List<Int>, minimumWidth: Int, minimumHeight: Int, resizable: Boolean,
        area: List<Int>): Pair<String, List<Int>>? {
        require(box.size == 4 && area.size == 4 && minimumWidth >= 0 && minimumHeight >= 0)
        val (left, top, right, bottom) = box
        require(area[0] <= left && left < right && right <= area[2] &&
            area[1] <= top && top < bottom && bottom <= area[3])
        require(right - left >= minimumWidth && bottom - top >= minimumHeight)
        return when {
            minimumWidth > 1 -> "minimum_width" to listOf(left, top, left + minimumWidth - 1, bottom)
            minimumHeight > 1 -> "minimum_height" to listOf(left, top, right, top + minimumHeight - 1)
            !resizable && right - left > 1 -> "nonresizable_width" to listOf(left, top, right - 1, bottom)
            !resizable && bottom - top > 1 -> "nonresizable_height" to listOf(left, top, right, bottom - 1)
            !resizable && right < area[2] -> "nonresizable_width" to listOf(left, top, right + 1, bottom)
            !resizable && bottom < area[3] -> "nonresizable_height" to listOf(left, top, right, bottom + 1)
            else -> null
        }
    }
}
