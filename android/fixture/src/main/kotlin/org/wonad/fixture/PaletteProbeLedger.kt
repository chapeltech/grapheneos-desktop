package org.wonad.fixture

import java.util.UUID

/** Observations only. Geometry is supplied by real View/Window callbacks. */
internal class PaletteProbeLedger {
    val instance: String = UUID.randomUUID().toString()
    data class Snapshot(val instance: String, val width: Int, val height: Int,
        val configurations: Long, val draws: Long, val focused: Boolean,
        val keyDowns: Long, val lastKey: Int, val pointerDowns: Long,
        val mouseDowns: Long, val lastPointerSource: Int)
    private var width = 0
    private var height = 0
    private var configurations = 0L
    private var draws = 0L
    private var focused = false
    private var keyDowns = 0L
    private var lastKey = 0
    private var pointerDowns = 0L
    private var mouseDowns = 0L
    private var lastPointerSource = 0

    @Synchronized fun configured(actualWidth: Int, actualHeight: Int) {
        require(actualWidth in 1..32768 && actualHeight in 1..32768)
        if (width != actualWidth || height != actualHeight) {
            width = actualWidth; height = actualHeight
            configurations = Math.addExact(configurations, 1)
        }
    }
    @Synchronized fun drawn() { draws = Math.addExact(draws, 1) }
    @Synchronized fun focused(actualFocus: Boolean) { focused = actualFocus }
    @Synchronized fun keyDown(actualKey: Int) {
        require(actualKey >= 0)
        keyDowns = Math.addExact(keyDowns, 1); lastKey = actualKey
    }
    @Synchronized fun pointerDown(actualSource: Int, mouse: Boolean) {
        require(actualSource >= 0)
        pointerDowns = Math.addExact(pointerDowns, 1)
        if (mouse) mouseDowns = Math.addExact(mouseDowns, 1)
        lastPointerSource = actualSource
    }
    @Synchronized fun snapshot() = Snapshot(instance, width, height, configurations,
        draws, focused, keyDowns, lastKey, pointerDowns, mouseDowns, lastPointerSource)
}
