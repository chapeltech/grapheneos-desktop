package org.wonad.desktop

/** Replay an exact host-requested bounded observation, not a desktop policy.
 * Same-lease hotplug retains task authority. Planned cross-lease recovery
 * retains only descriptive layout data and always uses freshly observed tokens.
 * Neither path invents rectangles, visibility, input or z-order. */
internal object ConformanceObservedReplay {
    fun placements(saved: RuntimeSnapshot, current: RuntimeSnapshot): List<RuntimeTask> {
        check(saved.generation == current.generation && saved.identityEpoch == current.identityEpoch &&
            current.revision >= saved.revision && current.topologyRevision > saved.topologyRevision) {
            "observed replay crossed or regressed its exact lease"
        }
        return exactPlacements(saved, current)
    }

    /** TEST-only recovery after the runner consumed its exact host-armed
     * callback and explicitly opened a fresh authorized lease. The runner
     * separately binds this operation to that new lease. Descriptor matching
     * does not prove task continuity: the host's Android lifetime audit must
     * establish that independently. No old token becomes current authority. */
    fun afterExpectedRevocation(saved: RuntimeSnapshot, current: RuntimeSnapshot): List<RuntimeTask> {
        check(saved.generation > 0 && current.generation > 0 && saved.generation != current.generation &&
            saved.identityEpoch > 0 && current.identityEpoch > 0 &&
            current.revision > 0 && current.topologyRevision > 0) {
            "planned observation recovery requires a fresh authorized lease"
        }
        check(!saved.interactionBlocked && !current.interactionBlocked &&
            saved.displays.all { it.shellGeneration == saved.generation } &&
            current.displays.all { it.shellGeneration == current.generation }) { "planned observation recovery is not ready" }
        val previous = saved.displays.associateBy { it.token }
        val destinations = current.displays.associateBy { it.identityHint }
        check(previous.size == saved.displays.size && destinations.size == current.displays.size &&
            saved.displays.map { it.identityHint }.toSet() == destinations.keys &&
            saved.displays.map { it.identityHint }.distinct().size == saved.displays.size) {
            "planned observation recovery has a missing or ambiguous connector"
        }
        val previousTasks = saved.tasks.associateBy { description(it) }
        val liveTasks = current.tasks.associateBy { description(it) }
        check(previousTasks.isNotEmpty() && previousTasks.size == saved.tasks.size &&
            liveTasks.size == current.tasks.size && previousTasks.keys == liveTasks.keys &&
            current.tasks.map { it.token }.toSet().size == current.tasks.size) {
            "planned observation recovery has missing, changed or ambiguous task descriptions"
        }
        return saved.tasks.map { task ->
            val original = checkNotNull(previous[task.displayToken])
            val destination = checkNotNull(destinations[original.identityHint])
            check(original.bounds == destination.bounds && original.densityDpi == destination.densityDpi) {
                "planned observation recovery cannot fit or rescale changed connector geometry"
            }
            val live = checkNotNull(liveTasks[description(task)])
            task.copy(token = live.token, displayToken = destination.token)
        }
    }

    private data class Description(val packageName: String, val title: String,
        val minimumWidth: Int, val minimumHeight: Int, val resizable: Boolean)

    private fun description(task: RuntimeTask) = Description(task.packageName, task.title,
        task.minimumWidth, task.minimumHeight, task.resizable)

    private fun exactPlacements(saved: RuntimeSnapshot, current: RuntimeSnapshot): List<RuntimeTask> {
        check(!saved.interactionBlocked && !current.interactionBlocked &&
            saved.displays.all { it.shellGeneration == saved.generation } &&
            current.displays.all { it.shellGeneration == current.generation }) { "observed replay is not ready" }
        val previous = saved.displays.associateBy { it.token }
        val destinations = current.displays.associateBy { it.identityHint }
        check(previous.size == saved.displays.size && destinations.size == current.displays.size &&
            saved.displays.map { it.identityHint }.toSet() == destinations.keys &&
            saved.displays.map { it.identityHint }.distinct().size == saved.displays.size) {
            "observed replay has a missing or ambiguous connector"
        }
        check(saved.tasks.map { it.token }.toSet() == current.tasks.map { it.token }.toSet() &&
            saved.tasks.size == current.tasks.size && saved.tasks.isNotEmpty()) {
            "observed replay cannot bind a replaced, missing or additional task"
        }
        return saved.tasks.map { task ->
            val original = checkNotNull(previous[task.displayToken])
            val destination = checkNotNull(destinations[original.identityHint])
            check(original.bounds == destination.bounds && original.densityDpi == destination.densityDpi) {
                "observed replay cannot fit or rescale changed connector geometry"
            }
            val live = current.tasks.single { it.token == task.token }
            check(live.packageName == task.packageName && live.title == task.title &&
                live.minimumWidth == task.minimumWidth && live.minimumHeight == task.minimumHeight &&
                live.resizable == task.resizable) { "observed replay task constraints changed" }
            task.copy(displayToken = destination.token)
        }
    }
}
