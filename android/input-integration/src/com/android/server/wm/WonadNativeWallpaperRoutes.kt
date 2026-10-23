package com.android.server.wm

import java.util.IdentityHashMap
import java.util.Collections
import java.util.function.Consumer

/** Proposal only. Every caller holds the WM lock. No policy, focus, or mutation.
 * Authority is the existing PM-authenticated exact Wallpaper/attachment guard.
 */
internal object WonadNativeWallpaperRoutes {
    @JvmStatic fun enforceReparent(child: WindowContainer<*>?, parent: WindowContainer<*>?) {
        if (child == null || parent == null || !parent.isAttached) return
        val dc = parent.displayContent ?: return
        val saved = Transaction()
        child.asTask()?.let { WonadNativeWallpaperLaunches.addSavedTask(saved, it, parent) }
        child.forAllTasks(Consumer { WonadNativeWallpaperLaunches.addSavedTask(saved, it, parent) })
        saved.enforce()
        child.forAllActivities(Consumer { activity ->
            if (parent.isAttached && parent.displayContent === dc &&
                WonadNativeWallpapers.rejectsLaunch(dc.defaultTaskDisplayArea, activity) &&
                parent.isAttached && parent.displayContent === dc &&
                (child === activity || activity.isDescendantOf(child)))
                throw IllegalArgumentException("Stock desktop wallpaper cannot enter native display")
        }, true)
    }

    /** A read-only overapproximation, NOT a synthesized final task hierarchy.
     * Retaining original edges deliberately rejects ambiguous compound routes
     * which could publish this exact Wallpaper on a native attachment at ANY
     * intermediate step, even if a later operation would move it back out.
     * Ordinary records and transactions confined to phone/unowned DCs pass.
     */
    class Transaction {
        private data class Launch(val info: android.content.pm.ActivityInfo,
            val user: Int, val parent: WindowContainer<*>)
        private val launches = mutableListOf<Launch>()
        fun addLaunch(info: android.content.pm.ActivityInfo, user: Int, parent: WindowContainer<*>?) {
            if (parent != null) launches.add(Launch(info, user, parent))
        }
        private val edges = IdentityHashMap<WindowContainer<*>, MutableList<WindowContainer<*>>>()

        fun add(child: WindowContainer<*>?, parent: WindowContainer<*>?) {
            if (child == null || parent == null || child === parent) return
            val values = edges.getOrPut(child) { mutableListOf() }
            if (values.any { it === parent }) return
            values.add(parent)
            child.asTask()?.let { WonadNativeWallpaperLaunches.addSavedTask(this, it, parent) }
            child.forAllTasks(Consumer {
                WonadNativeWallpaperLaunches.addSavedTask(this, it, parent)
            })
        }

        fun mayBeUnder(child: WindowContainer<*>?, ancestor: WindowContainer<*>?): Boolean {
            if (child == null || ancestor == null) return false
            return reachable(child).any { it === ancestor }
        }

        private fun reachable(first: WindowContainer<*>): List<WindowContainer<*>> {
            val seen = Collections.newSetFromMap(IdentityHashMap<WindowContainer<*>, Boolean>())
            val pending = ArrayDeque<WindowContainer<*>>()
            pending.add(first)
            while (pending.isNotEmpty()) {
                val next = pending.removeFirst()
                if (!seen.add(next)) continue
                next.parent?.let { pending.add(it) }
                edges[next]?.forEach { pending.add(it) }
            }
            return seen.toList()
        }

        fun enforce() {
            launches.forEach { launch ->
                reachable(launch.parent).forEach { target ->
                    val dc = target.asDisplayContent()
                    if (dc != null && WonadNativeWallpaperLaunches.rejects(
                            dc.defaultTaskDisplayArea, launch.info, launch.user))
                        throw IllegalArgumentException("Stock wallpaper launch reaches native display")
                }
            }
            // Inspect every actual source that might be moved. A parent/root
            // containing a Wallpaper is included; no top-Activity shortcut.
            edges.forEach { (source, parents) ->
                val activities = mutableListOf<ActivityRecord>()
                source.forAllActivities(Consumer { activities.add(it) }, true)
                parents.flatMap { reachable(it) }.forEach targetLoop@ { target ->
                    val dc = target.asDisplayContent() ?: return@targetLoop
                    if (!dc.isAttached) return@targetLoop
                    activities.forEach { activity ->
                        if (dc.isAttached &&
                            WonadNativeWallpapers.rejectsLaunch(dc.defaultTaskDisplayArea, activity) &&
                            (source === activity || activity.isDescendantOf(source)))
                            throw IllegalArgumentException(
                                "Stock desktop wallpaper transaction reaches native display")
                    }
                }
            }
        }
    }
}
