package org.wonad.desktop.transitionfault

import android.app.ActivityManager
import android.app.Instrumentation
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ActivityInfo
import android.graphics.Point
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** A test-only fault injector, attached with Android's --no-restart instrumentation.
 * It delays ONE real Shell transition, selected by the broker's pending Binder
 * object plus the exact owner/generation/display. It never changes broker state,
 * the timeout, permission checks, or the framework. Reflection accesses existing
 * SystemUI objects inside their own process; no production test API is added.
 *
 * The finish callback is withheld without blocking Shell's executor, so normal
 * Binder calls, client heartbeats and the real broker watchdog keep running.
 * Cleanup removes only this handler and delivers its native completion callback.
 */
class TransitionDelayInstrumentation : Instrumentation() {
    private lateinit var run: String
    private var generation = 0L
    private var ownerUid = -1
    private var display = -1
    private var taskIds = emptySet<Int>()
    private var constraint = false
    private data class Held(val token: IBinder, val callback: Any, val started: Long, val deadline: Long, val id: Int,
        val tasks: String, val finishOverride: Any?, val restoredBounds: String)
    private val held = AtomicReference<Held?>()
    private val failure = AtomicReference<Throwable?>()
    private val started = CountDownLatch(1)
    private val release = CountDownLatch(1)

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        // Report bad arguments through instrumentation, never throw on SystemUI's main thread.
        try {
            val args = checkNotNull(arguments)
            run = checkNotNull(args.getString("run"))
            check(run.matches(Regex("[0-9a-f]{32}")))
            generation = checkNotNull(args.getString("generation")).toLong()
            ownerUid = checkNotNull(args.getString("owner_uid")).toInt()
            display = checkNotNull(args.getString("display")).toInt()
            taskIds = checkNotNull(args.getString("tasks")).split(',').map { it.toInt() }.toSet()
            val mode = args.getString("mode", "timeout")
            check(mode in setOf("timeout", "constraint"))
            constraint = mode == "constraint"
            check(generation > 0 && ownerUid in 10000..19999 && display > 0 && taskIds.size == 2 && taskIds.all { it > 0 })
        } catch (error: Throwable) { failure.set(error) }
        start()
    }

    private fun field(target: Any, name: String): Any? = target.javaClass.getDeclaredField(name).apply {
        isAccessible = true
    }.get(target)

    private fun call(target: Any, name: String, vararg args: Any?): Any? {
        val matches = target.javaClass.methods.filter { it.name == name && it.parameterCount == args.size }
        check(matches.size == 1) { "Expected one ${target.javaClass.name}.$name/${args.size}, found ${matches.size}" }
        val method = matches.single()
        method.isAccessible = true
        return method.invoke(target, *args)
    }

    private fun <T> onShell(executor: Executor, action: () -> T): T {
        val task = FutureTask(action)
        executor.execute(task)
        return task.get(3, TimeUnit.SECONDS)
    }

    private fun status(phase: String, value: Held? = held.get()) = sendStatus(1, Bundle().apply {
        putString("run", run); putString("phase", phase); putLong("generation", generation)
        putInt("systemui_pid", Process.myPid()); putInt("systemui_uid", Process.myUid())
        value?.let { putInt("transition", it.id); putLong("deadline", it.deadline); putLong("started", it.started) }
    })

    override fun onStart() {
        val report = Bundle()
        var registered = false
        var installed = false
        var executor: Executor? = null
        var transitions: Any? = null
        var proxy: Any? = null
        var originalHandlers = emptyList<Any>()
        var outcome = 0
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action == ACTION && intent.getStringExtra("run") == run) release.countDown()
            }
        }
        try {
            check(failure.get() == null) { "Invalid isolated injector arguments: ${failure.get()}" }
            check(targetContext.packageName == "com.android.systemui" && targetContext.applicationInfo.uid == Process.myUid())
            check(Build.SUPPORTED_ABIS.first() == "x86_64" && Build.FINGERPRINT.contains("/wonad.2026092500:"))
            val loader = targetContext.classLoader
            val controllerClass = Class.forName("org.wonad.desktop.broker.WonadController", false, loader)
            val controller = checkNotNull(controllerClass.getDeclaredField("instance").apply { isAccessible = true }.get(null))
            val shellTransitions = checkNotNull(field(controller, "transitions"))
            transitions = shellTransitions
            // The public Transitions getter is inlined away in the actual OS APK.
            // Use the controller's existing Shell executor, not another thread.
            val shell = checkNotNull(field(controller, "executor")) as Executor
            executor = shell
            val handlerClass = Class.forName("com.android.wm.shell.transition.Transitions\$TransitionHandler", false, loader)
            var claimed = false
            val handler = Proxy.newProxyInstance(loader, arrayOf(handlerClass)) { self, method, arguments ->
                val args = arguments ?: emptyArray()
                when (method.name) {
                    "equals" -> self === args.singleOrNull()
                    "hashCode" -> System.identityHashCode(self)
                    "toString" -> if (constraint) "WonadTransitionConstraintProbe($run)" else "WonadTransitionTimeoutProbe($run)"
                    "startAnimation" -> {
                        if (claimed || args.getOrNull(1) == null) false else try {
                            val live = field(controller, "session")
                            val pending = live?.let { field(it, "pending") }
                            if (pending == null || field(pending, "transition") !== args[0] ||
                                field(live, "generation") != generation || call(live, "getDisplay") != display ||
                                field(checkNotNull(field(live, "owner")), "uid") != ownerUid) false else {
                                val info = checkNotNull(args[1])
                                check(call(info, "getType") == 6) { "Expected native TRANSIT_CHANGE" }
                                val rootCount = call(info, "getRootCount") as Int
                                check(rootCount > 0 && (0 until rootCount).all {
                                    call(checkNotNull(call(info, "getRoot", it)), "getDisplayId") == display
                                }) { "Transition extends outside the selected external display" }
                                val changed = (call(info, "getChanges") as List<*>).mapNotNull { change ->
                                    call(checkNotNull(change), "getTaskInfo") as? ActivityManager.RunningTaskInfo
                                }
                                val taskSummary = changed.joinToString(";") { "${it.taskId}:${it.baseIntent.component}:${it.topActivity}" }
                                check(changed.filter { it.taskId in taskIds }.map { it.taskId }.toSet() == taskIds)
                                check(changed.filter { it.baseIntent.component != null }.all {
                                    val wallpaper = ComponentName("com.android.systemui",
                                        "com.android.wm.shell.desktopmode.DesktopWallpaperActivity")
                                    // Android's native empty-desktop transition also changes
                                    // its own wallpaper Activity. Admit only that exact
                                    // SystemUI-owned component, never another application.
                                    val selected = it.taskId in taskIds && it.topActivity?.packageName == "org.wonad.fixture"
                                    val nativeWallpaper = it.baseIntent.component == wallpaper && it.topActivity == wallpaper &&
                                        (it.javaClass.getField("topActivityInfo").get(it) as? ActivityInfo)?.applicationInfo?.uid == Process.myUid()
                                    (selected || nativeWallpaper) && it.javaClass.getField("userId").getInt(it) == 0 &&
                                        it.javaClass.getField("displayId").getInt(it) == display
                                }) { "Native transition contains a different application task: $taskSummary" }
                                val now = SystemClock.elapsedRealtime()
                                val deadline = field(pending, "deadline") as Long
                                check(deadline - now in 10000..15000)
                                var finishOverride: Any? = null
                                var restoredBounds = ""
                                if (constraint) {
                                    // Model a native Shell policy overriding the requested
                                    // bounds at actual transition completion. Do not alter
                                    // broker state or forge its completion callback. Only
                                    // the two exact fixture leaf tokens are changed, using
                                    // their real pre-transition rectangles from Android.
                                    val wct = Class.forName("android.window.WindowContainerTransaction", false, loader)
                                        .getConstructor().newInstance()
                                    val rows = (call(info, "getChanges") as List<*>).mapNotNull { change ->
                                        val item = checkNotNull(change)
                                        val task = call(item, "getTaskInfo") as? ActivityManager.RunningTaskInfo
                                        if (task?.taskId !in taskIds) null else {
                                            val start = Rect(call(item, "getStartAbsBounds") as Rect)
                                            val end = call(item, "getEndAbsBounds") as Rect
                                            check(!start.isEmpty && start != end)
                                            check(call(item, "getLastParent") == null) { "Fixture was reparented" }
                                            call(item, "getParent")?.let { parent ->
                                                call(info, "getChange", parent)?.let { parentChange ->
                                                    check(call(parentChange, "getStartAbsBounds") ==
                                                        call(parentChange, "getEndAbsBounds")) { "Fixture parent moved" }
                                                }
                                            }
                                            call(wct, "setBounds", checkNotNull(call(item, "getContainer")), start)
                                            // A Shell handler owns organized surfaces through
                                            // completion. Its finish SurfaceControl transaction
                                            // must agree with its finish WCT, just as Android's
                                            // native resize handlers update both. Leaving the
                                            // prebuilt end-position/crop would inject unrelated
                                            // broken input geometry, not just a bounds override.
                                            val position = call(item, "getEndRelOffset") as Point
                                            val leash = checkNotNull(call(item, "getLeash"))
                                            val finish = checkNotNull(args[args.size - 2])
                                            call(finish, "setPosition", leash,
                                                (position.x + start.left - end.left).toFloat(),
                                                (position.y + start.top - end.top).toFloat())
                                            call(finish, "setWindowCrop", leash, start.width(), start.height())
                                            "${checkNotNull(task).taskId}:${start.left},${start.top},${start.right},${start.bottom}"
                                        }
                                    }
                                    check(rows.size == 2)
                                    finishOverride = wct
                                    restoredBounds = rows.sorted().joinToString(";")
                                }
                                // Both overloads end with startT, finishT, callback.
                                call(checkNotNull(args[args.size - 3]), "apply")
                                val value = Held(args[0] as IBinder, checkNotNull(args.last()), now, deadline,
                                    call(info, "getDebugId") as Int, taskSummary, finishOverride, restoredBounds)
                                held.set(value); claimed = true; started.countDown()
                                true
                            }
                        } catch (error: Throwable) {
                            failure.compareAndSet(null, error); started.countDown(); false
                        }
                    }
                    // Reject merges while holding the selected transition. Android queues
                    // its recovery transaction, which runs after native completion below.
                    "mergeAnimation", "setAnimScaleSetting", "handleRequest", "handleRequestOnly",
                    "getHandlerForTakeover" -> null
                    "takeOverAnimation" -> false
                    "onTransitionConsumed" -> {
                        if (held.get()?.token === args.firstOrNull()) {
                            failure.compareAndSet(null, IllegalStateException("Held native transition was consumed early"))
                            release.countDown()
                        }
                        null
                    }
                    else -> {
                        failure.compareAndSet(null, IllegalStateException("Unexpected transition handler call: ${method.name}"))
                        if (method.returnType == Boolean::class.javaPrimitiveType) false else null
                    }
                }
            }
            proxy = handler
            targetContext.registerReceiver(receiver, IntentFilter(ACTION), "android.permission.DUMP",
                Handler(Looper.getMainLooper()), Context.RECEIVER_EXPORTED)
            registered = true
            onShell(shell) {
                @Suppress("UNCHECKED_CAST")
                originalHandlers = (field(shellTransitions, "mHandlers") as List<Any>).toList()
                call(shellTransitions, "addHandler", handler)
                installed = true
            }
            status("injector_ready")
            check(started.await(45, TimeUnit.SECONDS)) { "No matching native transition reached the injector" }
            check(failure.get() == null) { "Injector selection failed: ${failure.get()?.stackTraceToString()}" }
            val value = checkNotNull(held.get())
            status("transition_held", value)
            // Bounded automatic cleanup even if the host dies. This doesn't block
            // either SystemUI's main thread or Shell's executor.
            check(release.await(40, TimeUnit.SECONDS)) { "Host did not release the native transition" }
            check(failure.get() == null) { "Native transition changed unexpectedly: ${failure.get()}" }
            if (constraint) {
                check(SystemClock.elapsedRealtime() < value.deadline - 5000) { "Native override must complete before the deadline" }
                onShell(shell) {
                    val live = checkNotNull(field(controller, "session"))
                    check(field(live, "generation") == generation && field(live, "pending") != null)
                }
                report.putString("restored_bounds", value.restoredBounds)
                report.putString("finish_surfaces", "matched_restored_bounds")
            } else {
                check(SystemClock.elapsedRealtime() >= value.deadline) { "Host released before the real deadline" }
                onShell(shell) { check(field(controller, "session") == null) { "Broker lease survived its transaction deadline" } }
            }
            report.putInt("transition", value.id)
            report.putString("native_tasks", value.tasks)
            report.putLong("deadline", value.deadline)
            report.putLong("held_started", value.started)
            report.putLong("released_at", SystemClock.elapsedRealtime())
            report.putString("transition_fault", "passed")
            outcome = -1
        } catch (error: Throwable) {
            report.putString("transition_fault", "not_passed")
            report.putString("failure_details", error.stackTraceToString())
        } finally {
            try {
                if (installed) onShell(checkNotNull(executor)) {
                    @Suppress("UNCHECKED_CAST")
                    val handlers = field(checkNotNull(transitions), "mHandlers") as MutableList<Any>
                    val index = handlers.indexOfFirst { it === proxy }
                    check(index >= 0)
                    handlers.removeAt(index) // Preserve every unrelated handler; never overwrite the list.
                    held.getAndSet(null)?.let { call(it.callback, "onTransitionFinished", it.finishOverride) }
                    check(handlers.size == originalHandlers.size && handlers.indices.all { handlers[it] === originalHandlers[it] })
                    report.putString("handler_restored", "true")
                }
                if (registered) targetContext.unregisterReceiver(receiver)
            } catch (error: Throwable) { report.putString("cleanup_error", error.stackTraceToString()); outcome = 0 }
        }
        if (::run.isInitialized) report.putString("run", run)
        report.putString("scope", if (constraint) "isolated_native_transition_bounds_override" else "isolated_native_transition_callback_delay")
        report.putLong("generation", generation); report.putInt("systemui_pid", Process.myPid()); report.putInt("systemui_uid", Process.myUid())
        report.putString("fingerprint", Build.FINGERPRINT); report.putString("native_abi", Build.SUPPORTED_ABIS.first())
        finish(outcome, report)
    }

    companion object { private const val ACTION = "org.wonad.desktop.transitionfault.RELEASE" }
}
