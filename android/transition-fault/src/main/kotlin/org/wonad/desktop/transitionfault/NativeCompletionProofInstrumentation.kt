package org.wonad.desktop.transitionfault

import android.app.Instrumentation
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Proxy
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** PLATFORM-SIGNED isolated no-restart test ONLY. Applies no native frame and
 * alters no broker state/deadline/authority. A temporary IWM decorator forwards
 * every actual call unchanged, except false for one exact already-applied
 * frame's completion-proof query while its genuine broker Pending is live.
 * This is NOT an animation/Shell-transition delay. Finally restores only its
 * exact cache reference; never overwrites a concurrent unrelated replacement. */
class NativeCompletionProofInstrumentation : Instrumentation() {
    companion object {
        private const val DISPATCH_DELAY_MILLIS = 4500L
        private const val DISPATCH_CANCEL = "org.wonad.desktop.transitionfault.BROKER_DISPATCH_CANCEL"
    }
    private lateinit var run: String
    private var dispatchMode = false
    private var launcherDispatchMode = false
    private var launcherDisplayToken = 0L
    private var generation = 0L
    private var ownerUid = -1
    private var fixtureUid = -1
    private var displayTokens = emptySet<Long>()
    private var taskTokens = emptySet<Long>()
    private val failure = AtomicReference<Throwable?>()
    private val captured = AtomicReference<NativeCompletionScope?>()
    private data class Held(val request: Long, val deadline: Long, val started: Long)
    private val held = AtomicReference<Held?>()
    private val started = CountDownLatch(1)
    private val release = CountDownLatch(1)
    private val withheld = AtomicLong()
    private val genuineProofs = AtomicLong()

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        // Bad arguments report failure from the instrumentation thread, never
        // throw from Android's SystemUI main-thread instrumentation callback.
        try {
            val args = checkNotNull(arguments)
            run = checkNotNull(args.getString("run")); check(run.matches(Regex("[0-9a-f]{32}")))
            val mode = args.getString("mode", "completion")
            check(mode in setOf("completion", "dispatch", "launcher-dispatch"))
            launcherDispatchMode = mode == "launcher-dispatch"
            dispatchMode = mode == "dispatch" || launcherDispatchMode
            ownerUid = checkNotNull(args.getString("owner_uid")).toInt()
            if (dispatchMode) {
                check(ownerUid in 10000..19999)
                if (launcherDispatchMode) {
                    generation = checkNotNull(args.getString("generation")).toLong()
                    launcherDisplayToken = checkNotNull(args.getString("display_token")).toLong()
                    check(generation > 0 && launcherDisplayToken > 0)
                }
                start(); return
            }
            generation = checkNotNull(args.getString("generation")).toLong()
            fixtureUid = checkNotNull(args.getString("fixture_uid")).toInt()
            val displays = checkNotNull(args.getString("display_tokens")).split(',').map { it.toLong() }
            val tasks = checkNotNull(args.getString("task_tokens")).split(',').map { it.toLong() }
            displayTokens = displays.toSet(); taskTokens = tasks.toSet()
            check(generation > 0 && ownerUid in 10000..19999 && fixtureUid in 10000..19999 && ownerUid != fixtureUid)
            check(displays.size in 1..9 && displays.size == displayTokens.size && displays.all { it > 0 })
            check(tasks.size == 2 && tasks.size == taskTokens.size && tasks.all { it > 0 })
        } catch (error: Throwable) { failure.set(error) }
        start()
    }

    /** Delay one real API3 open on Shell's actual serial executor. The public
     * Binder caller must hit BrokerDispatch's unchanged two-second deadline;
     * once this real observation resumes, its unreceived Session must be
     * abandoned by the queued production cleanup. No production fault API is
     * installed and every IWM result is forwarded unchanged. */
    private fun runDispatchFault() {
        val report = Bundle()
        val dispatchFailure = AtomicReference<Throwable?>()
        val started = CountDownLatch(1)
        val completed = CountDownLatch(1)
        val cancelled = AtomicBoolean()
        val calls = AtomicLong()
        val delayStarted = AtomicLong()
        val delayFinished = AtomicLong()
        val identityEpoch = AtomicLong()
        val catalogueId = AtomicLong()
        var exactSession: Any? = null
        var exactPicker: Any? = null
        var registered = false
        var installed = false
        var original: Any? = null
        var proxy: Any? = null
        var global: Class<*>? = null
        var cache: java.lang.reflect.Field? = null
        var outcome = 0
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action == DISPATCH_CANCEL && intent.getStringExtra("run") == run) cancelled.set(true)
            }
        }
        try {
            check(failure.get() == null) { "Invalid broker dispatch injector arguments: ${failure.get()}" }
            check(targetContext.packageName == "com.android.systemui" &&
                targetContext.applicationInfo.uid == Process.myUid())
            check(Build.SUPPORTED_ABIS.first() == "x86_64" && Build.TYPE == "userdebug" &&
                Build.FINGERPRINT.contains("/wonad.")) {
                "Never install broker dispatch faults on a physical/release phone"
            }
            val loader = targetContext.classLoader
            val parentClass = Class.forName("org.wonad.desktop.broker.WonadController", false, loader)
            val parent = checkNotNull(parentClass.getDeclaredField("instance").apply { isAccessible = true }.get(null))
            val executor = checkNotNull(field(parent, "executor")) as Executor
            val native = nativeDesktop(parentClass, parent, loader)
            val wmGlobal = Class.forName("android.view.WindowManagerGlobal", false, loader)
            val wmInterface = Class.forName("android.view.IWindowManager", false, loader)
            val wmCache = wmGlobal.getDeclaredField("sWindowManagerService").apply { isAccessible = true }
            global = wmGlobal; cache = wmCache
            lateinit var shellThread: Thread
            val idleDeadline = SystemClock.elapsedRealtime() + 10000
            while (true) {
                val idle = onShell(executor) {
                    shellThread = Thread.currentThread()
                    val live = field(native, "session")
                    if (!launcherDispatchMode) live == null else {
                        checkNotNull(live)
                        check(field(live, "generation") == generation &&
                            field(checkNotNull(field(live, "owner")), "uid") == ownerUid &&
                            field(live, "uiEnabled") == true && field(live, "pending") == null &&
                            field(live, "pick") == null)
                        exactSession = live
                        true
                    }
                }
                if (idle) break
                check(SystemClock.elapsedRealtime() < idleDeadline) { "Previous native owner did not release" }
                SystemClock.sleep(100)
            }
            original = onShell(executor) {
                wmGlobal.getDeclaredMethod("getWindowManagerService").invoke(null).also {
                    check(it != null && wmInterface.isInstance(it))
                }
            }
            val delegate = checkNotNull(original)
            val decorator = Proxy.newProxyInstance(wmInterface.classLoader, arrayOf(wmInterface)) { _, method, supplied ->
                val args = supplied ?: emptyArray()
                val actual = try { method.invoke(delegate, *args) }
                catch (error: InvocationTargetException) { throw checkNotNull(error.targetException) }
                val eligibleRead = Thread.currentThread() === shellThread &&
                    method.name == "getWonadNativeIdentityEpoch" && args.isEmpty()
                val live = if (eligibleRead) field(native, "session") else null
                val picker = if (live == null) null else field(live, "pick")
                val selected = eligibleRead && if (!launcherDispatchMode) live == null else
                    live === exactSession && live != null && picker != null &&
                        field(live, "generation") == generation &&
                        field(checkNotNull(field(live, "owner")), "uid") == ownerUid &&
                        field(live, "pending") == null && field(picker, "kind") == 1 &&
                        field(picker, "displayToken") == launcherDisplayToken &&
                        (field(picker, "id") as Long) > 0
                if (Thread.currentThread() !== shellThread || method.name != "getWonadNativeIdentityEpoch" ||
                    args.isNotEmpty() || !selected || !calls.compareAndSet(0, 1)) actual else {
                    try {
                        val epoch = actual as Long
                        check(epoch > 0)
                        identityEpoch.set(epoch)
                        if (launcherDispatchMode) {
                            check(epoch == field(checkNotNull(live), "identityEpoch"))
                            exactPicker = picker
                            catalogueId.set(field(checkNotNull(picker), "id") as Long)
                        }
                        delayStarted.set(SystemClock.elapsedRealtime()); started.countDown()
                        SystemClock.sleep(DISPATCH_DELAY_MILLIS)
                        delayFinished.set(SystemClock.elapsedRealtime()); completed.countDown()
                    } catch (error: Throwable) {
                        dispatchFailure.compareAndSet(null, error); completed.countDown()
                    }
                    actual
                }
            }
            proxy = decorator
            targetContext.registerReceiver(receiver, IntentFilter(DISPATCH_CANCEL), null,
                Handler(Looper.getMainLooper()), Context.RECEIVER_EXPORTED)
            registered = true
            onShell(executor) {
                synchronized(wmGlobal) {
                    check(wmCache.get(null) === delegate); wmCache.set(null, decorator); installed = true
                }
            }
            sendStatus(1, Bundle().apply {
                putString("run", run); putString("phase", "injector_ready"); putInt("api", 3)
                putInt("owner_uid", ownerUid); putInt("systemui_pid", Process.myPid()); putInt("systemui_uid", Process.myUid())
            })
            val invokeDeadline = SystemClock.elapsedRealtime() + 45000
            while (!started.await(100, TimeUnit.MILLISECONDS)) {
                check(!cancelled.get()) { "Host cancelled before dispatch fault invocation" }
                check(SystemClock.elapsedRealtime() < invokeDeadline) { "No exact API3 identity observation reached the delay" }
            }
            sendStatus(1, Bundle().apply {
                putString("run", run); putString("phase", "dispatch_delayed"); putInt("api", 3)
                putInt("owner_uid", ownerUid); putInt("systemui_pid", Process.myPid()); putInt("systemui_uid", Process.myUid())
                putLong("started", delayStarted.get()); putLong("identity_epoch", identityEpoch.get())
                if (launcherDispatchMode) {
                    putLong("generation", generation); putLong("display_token", launcherDisplayToken)
                    putLong("catalogue_id", catalogueId.get()); putString("selected_after_picker_created", "true")
                }
            })
            check(completed.await(12, TimeUnit.SECONDS)) { "Exact dispatch delay did not complete" }
            check(dispatchFailure.get() == null) {
                "Dispatch delay failed: ${dispatchFailure.get()?.stackTraceToString()}"
            }
            val elapsed = delayFinished.get() - delayStarted.get()
            check(calls.get() == 1L && elapsed in 4300..8000 && identityEpoch.get() > 0)
            onShell(executor) {
                if (!launcherDispatchMode) check(field(native, "session") == null) { "Unreceived native Session survived abandonment" }
                else {
                    val live = checkNotNull(field(native, "session"))
                    check(live === exactSession && field(live, "generation") == generation &&
                        field(live, "identityEpoch") == identityEpoch.get() &&
                        field(checkNotNull(field(live, "owner")), "uid") == ownerUid)
                    check(exactPicker != null && catalogueId.get() > 0 && field(live, "pick") == null &&
                        field(live, "pending") == null && field(live, "shortcuts") == true) {
                        "Unreceived initial catalogue survived or cleanup damaged its session"
                    }
                }
            }
            sendStatus(1, Bundle().apply {
                putString("run", run); putString("phase", "cleanup_observed"); putInt("api", 3)
                putInt("owner_uid", ownerUid); putInt("systemui_pid", Process.myPid()); putInt("systemui_uid", Process.myUid())
                putLong("started", delayStarted.get()); putLong("finished", delayFinished.get()); putLong("elapsed", elapsed)
                putLong("identity_epoch", identityEpoch.get())
                if (launcherDispatchMode) {
                    putLong("generation", generation); putLong("catalogue_id", catalogueId.get())
                    putString("same_session_survived", "true"); putString("initial_picker_cleaned", "true")
                }
            })
            report.putString("broker_dispatch_fault", "passed")
            report.putLong("delay_started", delayStarted.get()); report.putLong("delay_finished", delayFinished.get())
            report.putLong("delay_elapsed", elapsed); report.putLong("identity_epoch", identityEpoch.get())
            report.putLong("delay_calls", calls.get()); report.putString("session_cleaned", "true"); outcome = -1
            if (launcherDispatchMode) {
                report.putString("session_cleaned", "false")
                report.putString("same_session_survived", "true")
                report.putString("initial_picker_cleaned", "true")
                report.putLong("generation", generation)
                report.putLong("display_token", launcherDisplayToken)
                report.putLong("catalogue_id", catalogueId.get())
                report.putString("replacement_before_cleanup", "not_tested")
            }
        } catch (error: Throwable) {
            report.putString("broker_dispatch_fault", "not_passed")
            report.putString("failure_details", error.stackTraceToString())
        } finally {
            try {
                if (installed) {
                    synchronized(checkNotNull(global)) {
                        val wmCache = checkNotNull(cache)
                        check(wmCache.get(null) === proxy) { "IWM cache changed independently; refusing overwrite" }
                        wmCache.set(null, original); check(wmCache.get(null) === original)
                    }
                    report.putString("proxy_restored", "true")
                }
            } catch (error: Throwable) {
                outcome = 0; report.putString("broker_dispatch_fault", "not_passed")
                report.putString("cleanup_error", error.stackTraceToString())
            }
            try { if (registered) targetContext.unregisterReceiver(receiver) }
            catch (error: Throwable) {
                outcome = 0; report.putString("broker_dispatch_fault", "not_passed")
                report.putString("receiver_cleanup_error", error.stackTraceToString())
            }
        }
        report.putInt("api", 3); report.putString("scope", if (launcherDispatchMode)
            "v3_initial_launcher_page_after_picker_creation_2s_timeout_fault" else "v3_actual_broker_dispatch_2s_timeout_fault")
        report.putString("run", run); report.putInt("owner_uid", ownerUid)
        report.putInt("systemui_pid", Process.myPid()); report.putInt("systemui_uid", Process.myUid())
        report.putString("fingerprint", Build.FINGERPRINT); report.putString("native_abi", Build.SUPPORTED_ABIS.first())
        finish(outcome, report)
    }

    private fun field(target: Any, name: String): Any? {
        var type: Class<*>? = target.javaClass
        while (type != null) {
            try { return type.getDeclaredField(name).apply { isAccessible = true }.get(target) }
            catch (_: NoSuchFieldException) { type = type.superclass }
        }
        error("Missing exact native test field $name")
    }

    private fun nativeDesktop(parentClass: Class<*>, parent: Any, loader: ClassLoader): Any {
        check(parentClass.name == "org.wonad.desktop.broker.WonadController" && parent.javaClass === parentClass)
        val nativeClass = Class.forName("org.wonad.desktop.broker.NativeDesktopController", false, loader)
        val getter = parentClass.declaredMethods.single {
            it.declaringClass === parentClass && it.parameterCount == 0 && it.returnType === nativeClass &&
                !java.lang.reflect.Modifier.isStatic(it.modifiers)
        }
        val native = checkNotNull(getter.apply { isAccessible = true }.invoke(parent))
        check(native.javaClass === nativeClass)
        return native
    }
    private fun call(target: Any, name: String): Any? {
        val method = target.javaClass.methods.single { it.name == name && it.parameterCount == 0 }
        return method.apply { isAccessible = true }.invoke(target)
    }
    private fun <T> onShell(executor: Executor, action: () -> T): T {
        val task = FutureTask(action); executor.execute(task); return task.get(3, TimeUnit.SECONDS)
    }

    private fun status(phase: String, value: Held? = held.get()) = sendStatus(1, Bundle().apply {
        putString("run", run); putString("phase", phase); putInt("api", 3); putLong("generation", generation)
        putInt("owner_uid", ownerUid); putInt("fixture_uid", fixtureUid)
        putInt("systemui_pid", Process.myPid()); putInt("systemui_uid", Process.myUid())
        value?.let { putLong("request", it.request); putLong("deadline", it.deadline); putLong("started", it.started) }
    })

    override fun onStart() {
        if (dispatchMode) { runDispatchFault(); return }
        val report = Bundle()
        var registered = false
        var installed = false
        var original: Any? = null
        var proxy: Any? = null
        var wmClass: Class<*>? = null
        var cache: java.lang.reflect.Field? = null
        var outcome = 0
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action == "org.wonad.desktop.transitionfault.NATIVE_PROOF_RELEASE" && intent.getStringExtra("run") == run)
                    release.countDown()
            }
        }
        try {
            check(failure.get() == null) { "Invalid native injector arguments: ${failure.get()}" }
            check(targetContext.packageName == "com.android.systemui" && targetContext.applicationInfo.uid == Process.myUid())
            check(Build.SUPPORTED_ABIS.first() == "x86_64" && Build.TYPE == "userdebug" && Build.FINGERPRINT.contains("/wonad.")) {
                "Never install native completion faults on a physical/release phone"
            }
            val loader = targetContext.classLoader
            val parentClass = Class.forName("org.wonad.desktop.broker.WonadController", false, loader)
            val parent = checkNotNull(parentClass.getDeclaredField("instance").apply { isAccessible = true }.get(null))
            val executor = checkNotNull(field(parent, "executor")) as Executor
            // The compiled property name is not a test ABI. Discover only the
            // unique exact typed zero-argument getter on this exact parent.
            val native = nativeDesktop(parentClass, parent, loader)
            val global = Class.forName("android.view.WindowManagerGlobal", false, loader)
            val nativeInterface = Class.forName("android.view.IWindowManager", false, loader)
            val wmCache = global.getDeclaredField("sWindowManagerService").apply { isAccessible = true }
            wmClass = global; cache = wmCache
            lateinit var shellThread: Thread
            var delegate: Any? = null
            onShell(executor) {
                shellThread = Thread.currentThread()
                val live = checkNotNull(field(native, "session"))
                check(field(live, "generation") == generation && field(checkNotNull(field(live, "owner")), "uid") == ownerUid)
                check(field(live, "pending") == null && field(live, "uiEnabled") == true)
                delegate = global.getDeclaredMethod("getWindowManagerService").invoke(null)
                check(delegate != null && nativeInterface.isInstance(delegate))
            }
            original = delegate
            val decorator = Proxy.newProxyInstance(nativeInterface.classLoader, arrayOf(nativeInterface)) { _, method, supplied ->
                val args = supplied ?: emptyArray()
                // Always execute the real method first. False is the ONLY
                // substituted value; a real proof must return true repeatedly
                // to qualify actual application independently of withholding.
                val actual = try { method.invoke(delegate, *args) }
                catch (error: InvocationTargetException) { throw checkNotNull(error.targetException) }
                if (Thread.currentThread() !== shellThread || args.size != 7 ||
                    method.name !in listOf("applyWonadNativeFrame", "isWonadNativeFrameApplied")) actual else {
                    try {
                        val user = args[0] as Int
                        val gen = args[1] as Long
                        val owner = args[2] as IBinder
                        val binders = (args[3] as Array<*>).map { it as IBinder }
                        val uids = args[4] as IntArray
                        val current = args[5] as LongArray
                        val desired = args[6] as LongArray
                        val live = field(native, "session")
                        val selected = user == 0 && gen == generation && live != null &&
                            field(live, "generation") == generation && field(checkNotNull(field(live, "owner")), "uid") == ownerUid &&
                            call(live, "asBinder") === owner
                        if (!selected) actual else if (method.name == "applyWonadNativeFrame") {
                            if (actual == true && captured.get() == null) captured.compareAndSet(null,
                                NativeCompletionScope.capture(user, gen, owner, binders, uids, current, desired,
                                    fixtureUid, displayTokens, taskTokens))
                            actual
                        } else {
                            val scope = captured.get()
                            val pending = field(checkNotNull(live), "pending")
                            if (scope == null || pending == null || !scope.matches(user, gen, owner, binders, uids, current, desired) ||
                                field(pending, "request") != 1000L || field(pending, "topology") != current[2] ||
                                !(field(pending, "capturedCurrent") as LongArray).contentEquals(current) ||
                                !(field(pending, "desired") as LongArray).contentEquals(desired) ||
                                !(field(pending, "taskUids") as IntArray).contentEquals(uids) ||
                                !(field(pending, "taskBinders") as Array<*>).let { values ->
                                    values.size == binders.size && values.indices.all { values[it] === binders[it] }
                                }) actual else {
                                val now = SystemClock.elapsedRealtime()
                                val deadline = field(pending, "deadline") as Long
                                if (held.get() == null) {
                                    check(deadline - now in 10000..15000) { "No unchanged real native Pending deadline" }
                                    if (held.compareAndSet(null, Held(1000, deadline, now))) started.countDown()
                                }
                                withheld.incrementAndGet()
                                if (actual == true) genuineProofs.incrementAndGet()
                                false
                            }
                        }
                    } catch (error: Throwable) {
                        // An unexpected private ABI must never broaden the
                        // fault scope or turn a real failure into a success.
                        failure.compareAndSet(null, error); actual
                    }
                }
            }
            proxy = decorator
            targetContext.registerReceiver(receiver,
                IntentFilter("org.wonad.desktop.transitionfault.NATIVE_PROOF_RELEASE"), null,
                Handler(Looper.getMainLooper()), Context.RECEIVER_EXPORTED)
            registered = true
            onShell(executor) {
                synchronized(global) { check(wmCache.get(null) === delegate); wmCache.set(null, decorator); installed = true }
            }
            status("injector_ready")
            check(started.await(45, TimeUnit.SECONDS)) { "No exact native Pending frame reached proof withholding" }
            check(failure.get() == null) { "Native proof selector failed: ${failure.get()?.stackTraceToString()}" }
            val value = checkNotNull(held.get())
            status("proof_withheld", value)
            check(release.await(40, TimeUnit.SECONDS)) { "Host did not release isolated native proof decorator" }
            check(SystemClock.elapsedRealtime() >= value.deadline) { "Decorator released before real native deadline" }
            check(failure.get() == null && withheld.get() >= 20 && genuineProofs.get() >= 20) {
                "No repeated genuine applied proof under the exact withholding scope"
            }
            onShell(executor) { check(field(native, "session") == null) { "Native session survived completion deadline" } }
            val digest = MessageDigest.getInstance("SHA-256")
            val scope = checkNotNull(captured.get())
            (scope.current + scope.desired).forEach { value ->
                for (shift in 56 downTo 0 step 8) digest.update((value ushr shift).toByte())
            }
            report.putString("payload_sha256", digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) })
            report.putLong("request", value.request); report.putLong("deadline", value.deadline); report.putLong("held_started", value.started)
            report.putLong("released_at", SystemClock.elapsedRealtime()); report.putLong("withheld_queries", withheld.get())
            report.putLong("genuine_applied_proofs", genuineProofs.get())
            report.putString("native_completion_proof", "passed"); outcome = -1
        } catch (error: Throwable) {
            report.putString("native_completion_proof", "not_passed"); report.putString("failure_details", error.stackTraceToString())
        } finally {
            try {
                if (installed) {
                    // Restore even if the host vanished or Shell ceased
                    // responding. Never block cleanup on its watchdog thread.
                    synchronized(checkNotNull(wmClass)) {
                        val wmCache = checkNotNull(cache)
                        check(wmCache.get(null) === proxy) { "IWM cache changed independently; refusing overwrite" }
                        wmCache.set(null, original)
                        check(wmCache.get(null) === original)
                    }
                    report.putString("proxy_restored", "true")
                }
            } catch (error: Throwable) {
                outcome = 0; report.putString("native_completion_proof", "not_passed"); report.putString("cleanup_error", error.stackTraceToString())
            }
            try { if (registered) targetContext.unregisterReceiver(receiver) }
            catch (error: Throwable) {
                outcome = 0; report.putString("native_completion_proof", "not_passed"); report.putString("receiver_cleanup_error", error.stackTraceToString())
            }
        }
        report.putInt("api", 3); report.putString("scope", "v3_exact_native_completion_proof_withholding")
        report.putString("run", if (::run.isInitialized) run else "invalid"); report.putLong("generation", generation)
        report.putInt("owner_uid", ownerUid); report.putInt("fixture_uid", fixtureUid)
        report.putInt("systemui_pid", Process.myPid()); report.putInt("systemui_uid", Process.myUid())
        report.putString("fingerprint", Build.FINGERPRINT); report.putString("native_abi", Build.SUPPORTED_ABIS.first())
        finish(outcome, report)
    }
}
