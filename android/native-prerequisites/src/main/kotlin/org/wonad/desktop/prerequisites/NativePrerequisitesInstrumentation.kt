package org.wonad.desktop.prerequisites

import android.app.ActivityManager
import android.app.Instrumentation
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import java.io.File
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import org.json.JSONArray
import org.json.JSONObject
import org.wonad.desktop.api.DesktopProtocol
import org.wonad.desktop.api.DesktopSnapshot
import org.wonad.desktop.api.DesktopFrame
import org.wonad.desktop.api.DesktopPlacement
import org.wonad.desktop.api.DesktopRect
import org.wonad.desktop.security.NativeSecurityClient

/** Ordinary, separately signed test APK. Target NativePolicy is reflected from
 * the ACTUAL installed target classloader; public native WM RPCs are observed
 * independently by the host, never substituted by policy/JNI status. */
class NativePrerequisitesInstrumentation : Instrumentation() {
    companion object {
        const val NEXT="org.wonad.desktop.prerequisites.NEXT"
        const val SCOPE="native_v3_prerequisites"
        val DIRECT=listOf("direct-ready","direct-one-input","direct-two-input","direct-vertical",
            "vertical-one-input","vertical-two-input")
    }
    private lateinit var run: String
    private lateinit var mode: String
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        run=checkNotNull(arguments?.getString("run")); check(run.matches(Regex("[0-9a-f]{32}")))
        mode=checkNotNull(arguments.getString("mode")); check(mode in listOf("abi","denied","direct")); start()
    }
    private fun serviceNames(): List<String> = targetContext.getSystemService(ActivityManager::class.java)
        .getRunningServices(Int.MAX_VALUE).map { it.service.flattenToShortString() }
    private fun checkNoPolicyService() { check("org.wonad.desktop/.DesktopService" !in serviceNames()) }
    private fun common()=JSONObject().put("api",3).put("run",run).put("mode",mode).put("scope",SCOPE)
        .put("owner_uid",Process.myUid()).put("owner_pid",Process.myPid()).put("fingerprint",Build.FINGERPRINT)
        .put("native_abi",Build.SUPPORTED_ABIS.first()).put("target_package",targetContext.packageName)
        .put("target_apk",targetContext.applicationInfo.sourceDir)
    private fun phase(name: String, snapshot: DesktopSnapshot) {
        sendStatus(1,Bundle().apply {
            putString("phase",name); putString("run",run); putString("mode",mode); putInt("api",3)
            putInt("owner_uid",Process.myUid()); putInt("owner_pid",Process.myPid())
            putString("evidence",NativeSecurityClient.proof(snapshot).toString())
        })
    }
    private fun liveComplete(evidence: JSONObject) {
        // Android may kill the target at finish(). Keep the genuine process
        // alive until the host observes its actual UID/PID, stopped policy,
        // and mapped library bytes. This is correlation, not extra authority.
        sendStatus(1,Bundle().apply {
            putString("phase","live-complete"); putString("run",run); putString("mode",mode)
            putInt("api",3); putInt("owner_uid",Process.myUid()); putInt("owner_pid",Process.myPid())
            putString("evidence",evidence.toString())
        })
    }
    private fun readinessFailure(result: Bundle, observer: NativeReadinessObserver,
        diagnosticGate: NativeFailureDiagnosticGate, diagnosticAcks: LinkedBlockingQueue<Boolean>) {
        val diagnostic = common().put("readiness", observer.failure()).toString()
        result.putString("readiness_failure", diagnostic)
        // The ORIGINAL readiness has already failed. Keep THIS same lease,
        // including its normal heartbeat, only for bounded read-only diagnostics.
        // No stable()/showShell()/HOME/input operation is retried here.
        diagnosticGate.begin()
        try {
            sendStatus(1, Bundle().apply {
                putString("phase", "readiness-failure"); putString("run", run); putString("mode", mode)
                putInt("api", 3); putInt("owner_uid", Process.myUid()); putInt("owner_pid", Process.myPid())
                putString("evidence", diagnostic)
            })
            diagnosticAcks.poll(diagnosticGate.remainingMillis(), TimeUnit.MILLISECONDS)
        } finally {
            val closed = diagnosticGate.close()
            val wait = JSONObject().put("schema",1).put("kind","failure_only_same_lease_diagnostic_wait")
                .put("run",run).put("mode",mode).put("owner_uid",Process.myUid()).put("owner_pid",Process.myPid())
                .put("step",NativeFailureDiagnosticGate.STEP).put("timeout_ms",NativeFailureDiagnosticGate.WAIT_MS)
                .put("started_elapsed_ms",closed.started).put("deadline_elapsed_ms",closed.deadline)
                .put("closed_elapsed_ms",closed.finished).put("acknowledged",closed.acknowledgedAt != null)
                .put("acknowledged_elapsed_ms",closed.acknowledgedAt ?: JSONObject.NULL)
                .put("qualifying",false).put("callbacks_at_close",observer.failure())
            result.putString("readiness_diagnostic_wait",wait.toString())
            sendStatus(1, Bundle().apply {
                putString("phase","readiness-diagnostic-closed"); putString("run",run); putString("mode",mode)
                putInt("api",3); putInt("owner_uid",Process.myUid()); putInt("owner_pid",Process.myPid())
                putString("evidence",wait.toString())
            })
        }
    }
    private fun mappedLibraries(): Map<String,List<String>> {
        val names=listOf("libwonad_policy_jni.so","libwonad_policy_hs.so","libwonad_broker_jni.so")
        val maps=File("/proc/self/maps").readLines()
        return names.associateWith { name -> maps.mapNotNull { line ->
            line.substringAfterLast(' ',"").takeIf { it.endsWith("/"+name) }
        }.distinct().also { check(it.size==1) { "Not one actual mapped $name" } } }
    }
    private fun apply(lease: NativeSecurityClient.Lease, request: Long, vertical: Boolean): Pair<DesktopSnapshot,JSONObject> {
        val current=lease.stable(); val area=current.displays.single().bounds
        val frame=DesktopFrame().apply {
            topologyRevision=current.topologyRevision; focusedDisplayToken=0; focusedToken=0; shellRegions=emptyArray()
            placements=current.tasks.mapIndexed { index,task -> DesktopPlacement().apply {
                token=task.token; destinationDisplayToken=task.displayToken
                bounds=DesktopRect().apply {
                    left=area.left + (if(vertical) 0 else index*(area.right-area.left)/2) + 3
                    right=area.left + (if(vertical) area.right-area.left else (index+1)*(area.right-area.left)/2) - 3
                    top=area.top + (if(vertical) index*(area.bottom-area.top)/2 else 0) + 3
                    bottom=area.top + (if(vertical) (index+1)*(area.bottom-area.top)/2 else area.bottom-area.top) - 3
                }
                visible=true; inputEnabled=true; zOrder=task.zOrder
            } }.toTypedArray()
        }
        lease.session.applySignedFrame(current.generation,request,current.revision,frame)
        val callback=checkNotNull(lease.events.results.poll(20,TimeUnit.SECONDS))
        check(callback.take(3)==listOf(current.generation,request,DesktopProtocol.RESULT_APPLIED.toLong()))
        val actual=lease.stable(); check(actual.tasks.all { task -> frame.placements.single { it.token==task.token }.let {
            task.bounds.left==it.bounds.left && task.bounds.top==it.bounds.top && task.bounds.right==it.bounds.right && task.bounds.bottom==it.bounds.bottom && task.visible && task.inputEnabled
        } })
        return actual to JSONObject().put("method","applySignedFrame").put("transaction",13).put("request",request)
            .put("base",current.revision).put("topology_revision",frame.topologyRevision).put("focused_display_token",0).put("focused_token",0)
            .put("shell_regions",JSONArray()).put("callback",JSONArray(callback)).put("vertical",vertical)
            .put("placements",JSONArray(frame.placements.map { p -> JSONObject().put("token",p.token)
                .put("display_token",p.destinationDisplayToken).put("bounds",JSONArray(listOf(p.bounds.left,p.bounds.top,p.bounds.right,p.bounds.bottom)))
                .put("visible",p.visible).put("input",p.inputEnabled).put("z",p.zOrder) }))
    }
    override fun onStart() {
        val result=Bundle(); var outcome=0; var registered=false; var failureStage="owner"
        val commands=LinkedBlockingQueue<String>()
        val diagnosticAcks=LinkedBlockingQueue<Boolean>()
        val diagnosticGate=if(mode=="direct") NativeFailureDiagnosticGate(run,mode,Process.myPid()) {
            SystemClock.elapsedRealtime()
        } else null
        val receiver=object:BroadcastReceiver() {
            override fun onReceive(context: Context,intent: Intent) {
                val step=intent.getStringExtra("step")
                if(diagnosticGate?.acknowledge(intent.action,intent.getStringExtra("run"),
                    intent.getStringExtra("mode"),intent.getIntExtra("owner_pid",-1),step)==true) {
                    diagnosticAcks.offer(true)
                    return
                }
                if(intent.action==NEXT && intent.getStringExtra("run")==run &&
                    ((mode=="direct" && step in DIRECT) || (step=="live-complete" &&
                        intent.getStringExtra("mode")==mode && intent.getIntExtra("owner_pid",-1)==Process.myPid())))
                    commands.add(checkNotNull(step))
            }
        }
        try {
            NativeSecurityClient.requireOwner(targetContext,0); checkNoPolicyService()
            targetContext.registerReceiver(receiver,IntentFilter(NEXT),null,Handler(Looper.getMainLooper()),Context.RECEIVER_EXPORTED); registered=true
            val evidence=common()
            when(mode) {
                "abi" -> {
                    failureStage="target-policy-abi"
                    val policy=NativePolicyAbiChecks(targetContext.classLoader)
                    val policyJournal=policy.run(); checkNoPolicyService()
                    failureStage="ordinary-rust-jni-abi"
                    val rust=NativeRustAbiChecks(javaClass.classLoader)
                    val rustJournal=rust.run(); checkNoPolicyService()
                    failureStage="mapped-library-observation"
                    evidence.put("policy",JSONArray(policyJournal)).put("rust",JSONArray(rustJournal))
                        .put("service_names",JSONArray(serviceNames())).put("mapped_libraries",JSONObject(mappedLibraries()))
                        .put("test_apk",context.applicationInfo.sourceDir)
                        .put("policy_authority","none").put("rust_scope","unprivileged_apk_validation_not_privileged_os_application")
                }
                "denied" -> {
                    NativeSecurityClient.Bound(targetContext).use { binding ->
                        val broker=binding.broker(); val callbacks=NativeSecurityClient.Events()
                        var denied=false
                        try { broker.openSession(DesktopProtocol.API_VERSION,callbacks) }
                        catch(error:IllegalStateException) { check(error.message==NativeSecurityClient.ADMISSION_DENIED); denied=true
                            evidence.put("exception",error.javaClass.name).put("message",error.message) }
                        check(denied && callbacks.empty()); evidence.put("callbacks",0).put("admission","denied")
                    }
                }
                "direct" -> {
                    NativeSecurityClient.Bound(targetContext).use { bound ->
                        val broker=bound.broker()
                        val observer=NativeReadinessObserver()
                        NativeSecurityClient.open(targetContext,observer.broker(broker)).use { lease ->
                          try {
                            val initial=lease.stable(); check(initial.displays.size==1)
                            val (baseline,horizontalCall)=apply(lease,1000,false); check(baseline.tasks.all { it.visible && it.inputEnabled })
                            val calls=JSONArray().put(horizontalCall)
                            val tokens=baseline.tasks.map { it.token }.toSet(); val phases=JSONArray()
                            var vertical=false
                            for(name in DIRECT) {
                                if(name=="direct-vertical") { calls.put(apply(lease,1001,true).second); vertical=true }
                                val observed=lease.stable(); checkNoPolicyService()
                                check(observed.generation==baseline.generation && observed.identityEpoch==baseline.identityEpoch && observed.tasks.map { it.token }.toSet()==tokens)
                                phases.put(JSONObject().put("phase",name).put("snapshot",NativeSecurityClient.proof(observed))
                                    .put("signed_request",if(vertical) 1001 else 0))
                                phase(name,observed)
                                check(commands.poll(90,TimeUnit.SECONDS)==name) { "Missing exact original host observation: $name" }
                            }
                            check(lease.heartbeatsSent()>0 && lease.events.revoked.isEmpty()); evidence.put("phases",phases).put("calls",calls)
                                .put("signed_result",DesktopProtocol.RESULT_APPLIED).put("heartbeats",lease.heartbeatsSent())
                          } catch(error:Throwable) {
                            try { readinessFailure(result,observer,checkNotNull(diagnosticGate),diagnosticAcks) } catch(diagnosticError:Exception) {
                                result.putString("readiness_diagnostic_error",diagnosticError.javaClass.name)
                            }
                            throw error
                          }
                        }
                    }
                    evidence.put("lease_released",true); checkNoPolicyService()
                }
            }
            checkNoPolicyService(); failureStage="live-process-observation"
            liveComplete(evidence)
            check(commands.poll(90,TimeUnit.SECONDS)=="live-complete") { "Missing exact live process observation" }
            checkNoPolicyService()
            result.putString("native_prerequisite","passed"); result.putInt("api",3); result.putString("scope",SCOPE)
            result.putString("run",run); result.putString("mode",mode); result.putString("evidence",evidence.toString()); outcome=-1
        } catch(error:Throwable) {
            result.putString("native_prerequisite","failed"); result.putString("failure_details",error.toString())
            result.putString("failure_stage",failureStage)
            result.putString("failure_trace",error.stackTraceToString())
        } finally {
            if(registered) try { targetContext.unregisterReceiver(receiver) } catch(error:Throwable) {
                outcome=0; result.putString("cleanup_error",error.toString())
            }
            finish(outcome,result)
        }
    }
}
