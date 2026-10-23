package org.wonad.desktop.taskreuse

import android.app.ActivityManager
import android.app.Instrumentation
import android.os.Build
import android.os.Bundle
import android.os.Parcel
import android.os.Process
import android.os.SystemClock
import android.util.Base64
import java.lang.reflect.Proxy
import java.util.concurrent.TimeUnit
import org.json.JSONArray
import org.json.JSONObject
import org.wonad.desktop.api.*
import org.wonad.desktop.security.NativeSecurityClient

/** Signature-authorized instrumentation runs as the real ordinary Wonad UID.
 * It does not allocate tasks (the distinct recycler UID does), adopt identity,
 * write a checkpoint, or call any privileged/hidden Android endpoint. */
class NativeTaskReuseOwnerInstrumentation : Instrumentation() {
    private lateinit var run: String
    private val calls = JSONArray()
    private val snapshots = JSONArray()
    private val uiEnabled = mutableSetOf<Long>()
    private val requestedShells = mutableSetOf<Pair<Long,Long>>()
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments); run=checkNotNull(arguments?.getString("run"))
        check(run.matches(Regex("[0-9a-f]{32}"))); start()
    }
    private fun checkpoint(): LongArray = targetContext.classLoader.loadClass("org.wonad.desktop.NativePolicy")
        .getDeclaredMethod("nativeCheckpoint").invoke(null).let {
            check(it is LongArray && it.size in 7..2073); it
        }
    private fun serviceRunning(): Boolean = targetContext.getSystemService(ActivityManager::class.java)
        .getRunningServices(Int.MAX_VALUE).any { it.service.flattenToShortString()=="org.wonad.desktop/.DesktopService" }
    private fun phase(name: String, snapshot: DesktopSnapshot? = null, words: LongArray? = null) {
        val body=JSONObject().put("snapshot",snapshot?.let(NativeSecurityClient::proof) ?: JSONObject.NULL)
            .put("checkpoint",words?.let { JSONArray(it.toList()) } ?: JSONObject.NULL)
            .put("service_running",serviceRunning()).put("calls",JSONArray(calls.toString()))
        snapshots.put(JSONObject().put("phase",name).put("evidence",body))
        sendStatus(1,Bundle().apply {
            putInt("api",3); putString("scope",NativeTaskReuseSpec.SCOPE); putString("run",run); putString("role","owner")
            putString("phase",name); putInt("uid",Process.myUid()); putInt("pid",Process.myPid())
            putString("evidence",body.toString())
        })
    }
    private fun publish(snapshot: DesktopSnapshot, display: DesktopDisplay) {
        val loader=targetContext.classLoader
        val rect=loader.loadClass("org.wonad.desktop.ShellRect").getConstructor(Int::class.javaPrimitiveType,
            Int::class.javaPrimitiveType,Int::class.javaPrimitiveType,Int::class.javaPrimitiveType)
            .newInstance(display.bounds.left,display.bounds.top,display.bounds.right,display.bounds.bottom)
        val scene=loader.loadClass("org.wonad.desktop.ShellScene").constructors.single { it.parameterCount==9 }
            .newInstance(snapshot.generation,snapshot.revision,display.token,display.displayId,rect,emptyList<Any>(),null,true,true)
        val ui=loader.loadClass("org.wonad.desktop.ShellUi"); val publish=ui.methods.single { it.name=="publish" && it.parameterCount==2 }
        val unit=loader.loadClass("kotlin.Unit").getField("INSTANCE").get(null)
        val callback=Proxy.newProxyInstance(loader,arrayOf(publish.parameterTypes[1])) { _,method,_ -> when(method.name) {
            "invoke"->unit; "toString"->"Ordinary task-reuse test shell"; "hashCode"->1; "equals"->false; else->null
        } }
        publish.invoke(ui.getField("INSTANCE").get(null),scene,callback)
    }
    private fun fingerprint(snapshot: DesktopSnapshot): String {
        val parcel=Parcel.obtain()
        return try { snapshot.writeToParcel(parcel,0); Base64.encodeToString(parcel.marshall(),Base64.NO_WRAP) }
        finally { parcel.recycle() }
    }
    private fun stable(lease: NativeSecurityClient.Lease, count: Int): DesktopSnapshot {
        val deadline=SystemClock.elapsedRealtime()+30000; var previous=""; var repeats=0
        while(SystemClock.elapsedRealtime()<deadline) {
            check(lease.events.revoked.isEmpty())
            lease.events.snapshot.get()?.let { s ->
                check(s.identityEpoch>0 && s.generation>0 && s.displays.size==1 &&
                    s.capabilities and DesktopProtocol.CAP_SIGNED_PLACEMENT!=0L)
                if(uiEnabled.add(s.generation)) lease.session.enableExternalUi(s.generation)
                s.displays.forEach { d -> if(d.shellGeneration!=s.generation && requestedShells.add(s.generation to d.token)) {
                    publish(s,d); lease.session.showShell(s.generation,d.token)
                } }
                if(!s.interactionBlocked && s.displays.all { it.shellGeneration==s.generation } && s.tasks.size==2+count &&
                    s.tasks.count { it.packageName==NativeSecurityClient.FIXTURE }==2 &&
                    s.tasks.count { it.packageName==NativeTaskReuseSpec.PACKAGE }==count) {
                    val key=fingerprint(s); repeats=if(key==previous) repeats+1 else 1; previous=key
                    if(repeats==5) return s
                } else repeats=0
            }
            SystemClock.sleep(200)
        }
        error("Actual complete native task-reuse frame did not settle")
    }
    private fun frame(s: DesktopSnapshot, old: Long=0, replacement: Long=0) = DesktopFrame().apply {
        topologyRevision=s.topologyRevision; focusedDisplayToken=0; focusedToken=0; shellRegions=emptyArray()
        placements=s.tasks.map { t -> DesktopPlacement().apply {
            token=if(t.token==replacement) old else t.token; destinationDisplayToken=t.displayToken
            bounds=t.bounds; visible=t.visible; inputEnabled=t.inputEnabled; zOrder=t.zOrder
        } }.toTypedArray()
    }
    private fun call(lease: NativeSecurityClient.Lease, method: String, id: Long, current: DesktopSnapshot,
        expected: Int, token: Long=0, desired: DesktopFrame?=null) {
        when(method) {
            "focusTask"->lease.session.focusTask(current.generation,id,current.revision,token)
            "closeTask"->lease.session.closeTask(current.generation,id,current.revision,token)
            "applyFrame"->lease.session.applyFrame(current.generation,id,current.revision,desired)
            "applySignedFrame"->lease.session.applySignedFrame(current.generation,id,current.revision,desired)
            else->error("Unknown test method")
        }
        val result=checkNotNull(lease.events.results.poll(20,TimeUnit.SECONDS))
        check(result.take(3)==listOf(current.generation,id,expected.toLong()) && lease.events.revoked.isEmpty())
        calls.put(JSONObject().put("method",method).put("request",id).put("generation",current.generation)
            .put("base",current.revision).put("token",token).put("before",NativeSecurityClient.proof(current))
            .put("callback",JSONArray(result)).put("placements",desired?.placements?.let { ps -> JSONArray(ps.map { p -> JSONObject()
                .put("token",p.token).put("display_token",p.destinationDisplayToken).put("bounds",JSONArray(listOf(p.bounds.left,p.bounds.top,p.bounds.right,p.bounds.bottom)))
                .put("visible",p.visible).put("input",p.inputEnabled).put("z",p.zOrder) }) } ?: JSONObject.NULL))
    }
    override fun onStart() {
        val report=Bundle(); var outcome=0
        try {
            NativeSecurityClient.requireOwner(targetContext,0); check(serviceRunning())
            NativeTaskReuseSignals(targetContext,run,"owner").use { signals ->
                phase("owner-ready",words=checkpoint()); signals.await("metadata-seeded")
                val originalMetadata=checkpoint(); phase("original-metadata",words=originalMetadata)
                signals.await("policy-stopped"); check(!serviceRunning())
                NativeSecurityClient.Bound(targetContext).use { binding ->
                    NativeSecurityClient.open(targetContext,binding.broker()).use { lease ->
                        val original=stable(lease,1); val old=original.tasks.single { it.packageName==NativeTaskReuseSpec.PACKAGE }.token
                        val survivors=original.tasks.filter { it.packageName==NativeSecurityClient.FIXTURE }.map { it.token }.toSet()
                        check(!original.tasks.single { it.token==old }.visible)
                        phase("direct-original",original); signals.await("direct-original-observed")
                        call(lease,"closeTask",100,original,DesktopProtocol.RESULT_APPLIED,old)
                        val absent=stable(lease,0); check(absent.generation==original.generation && absent.identityEpoch==original.identityEpoch)
                        phase("original-closed",absent); signals.await("original-closed-observed")
                        signals.await("replacement-phone",1250)
                        lease.session.showTransferPicker(original.generation,original.displays.single().token)
                        phase("replacement-picker",stableBlockedSnapshot(lease)); signals.await("replacement-transferred")
                        val fresh=stable(lease,1); val token=fresh.tasks.single { it.packageName==NativeTaskReuseSpec.PACKAGE }.token
                        check(fresh.generation==original.generation && fresh.identityEpoch==original.identityEpoch && token!=old &&
                            fresh.tasks.filter { it.packageName==NativeSecurityClient.FIXTURE }.map { it.token }.toSet()==survivors)
                        phase("replacement-native",fresh); signals.await("replacement-native-observed")
                        NativeTaskReuseSpec.STALE.forEachIndexed { index,method ->
                            val current=stable(lease,1); val candidate=if(method.startsWith("apply")) frame(current,old,token) else null
                            call(lease,method,110L+index,current,DesktopProtocol.RESULT_INVALID,old,candidate)
                            check(fingerprint(stable(lease,1))==fingerprint(current)) { "Stale identity changed actual native state" }
                        }
                        var current=stable(lease,1); call(lease,"focusTask",120,current,DesktopProtocol.RESULT_APPLIED,token)
                        current=stable(lease,1); check(current.focusedToken==token)
                        for((index,method) in listOf("applyFrame","applySignedFrame").withIndex()) {
                            val desired=frame(current); val p=desired.placements.single { it.token==token }; val area=current.displays.single().bounds
                            p.bounds=DesktopRect().apply { left=area.left+(area.right-area.left)*3/5+3; top=area.top+3; right=area.right-3; bottom=area.bottom-3 }
                            p.visible=true; p.inputEnabled=true
                            call(lease,method,121L+index,current,DesktopProtocol.RESULT_APPLIED,token,desired)
                            current=stable(lease,1)
                            check(current.tasks.single { it.token==token }.let { it.visible && it.inputEnabled && it.bounds.left==p.bounds.left && it.bounds.right==p.bounds.right })
                        }
                        phase("fresh-frame",current); signals.await("fresh-input")
                        check(stable(lease,1).generation==original.generation && lease.heartbeatsSent()>0)
                        report.putLong("generation",original.generation); report.putLong("identity_epoch",original.identityEpoch)
                        report.putLong("old_token",old); report.putLong("new_token",token)
                    }
                }
                phase("released",words=checkpoint()); signals.await("policy-recovered")
                check(serviceRunning()); phase("recovered-metadata",words=checkpoint())
                signals.await("replacement-closed"); check(serviceRunning()); phase("final-metadata",words=checkpoint())
                report.putString("native_task_reuse_owner","passed"); outcome=-1
            }
        } catch(error:Throwable) { report.putString("native_task_reuse_owner","not_passed"); report.putString("failure_details",error.stackTraceToString()) }
        finally {
            report.putInt("api",3); report.putString("scope",NativeTaskReuseSpec.SCOPE); report.putString("run",run); report.putString("role","owner")
            report.putInt("uid",Process.myUid()); report.putInt("pid",Process.myPid()); report.putString("fingerprint",Build.FINGERPRINT)
            report.putString("native_abi",Build.SUPPORTED_ABIS.first()); report.putString("calls",calls.toString()); report.putString("phases",snapshots.toString())
            finish(outcome,report)
        }
    }
    private fun stableBlockedSnapshot(lease: NativeSecurityClient.Lease): DesktopSnapshot {
        val deadline=SystemClock.elapsedRealtime()+10000
        while(SystemClock.elapsedRealtime()<deadline) {
            check(lease.events.revoked.isEmpty())
            lease.events.snapshot.get()?.let { if(it.interactionBlocked) return it }
            SystemClock.sleep(100)
        }
        error("Trusted picker did not block the native lease")
    }
}
