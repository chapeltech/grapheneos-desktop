package org.wonad.desktop.prerequisites

/** Pure APK JNI validation is explicitly NOT privileged OS authorization or
 * actual native application. The host binds this separately packaged library
 * and independently observes the later public OS transaction. */
internal class NativeRustAbiChecks(loader: ClassLoader) {
    private val native=loader.loadClass("org.wonad.desktop.broker.BrokerNative")
    private val journal=mutableListOf<Map<String,Any?>>()
    private fun call(name: String, method: String, args: List<Any>, expected: Any) {
        val types=args.map { when(it) { is LongArray -> LongArray::class.java; is Long -> Long::class.javaPrimitiveType!!
            is Int -> Int::class.javaPrimitiveType!!; is Boolean -> Boolean::class.javaPrimitiveType!!; else -> error("Unknown JNI type") } }
        val result=native.getDeclaredMethod(method,*types.toTypedArray()).invoke(null,*args.toTypedArray())
        journal.add(mapOf("name" to name,"method" to method,"arguments" to args.map { if(it is LongArray) it.toList() else it },"output" to result))
        check(result==expected) { "Pure native ABI differed: $name" }
    }
    fun run(): List<Map<String,Any?>> {
        val current=longArrayOf(91,5,7,1,1,101,2,0,0,1920,1080,160,1,91,71,101,3,3,1003,1003,320,200,1,1,1,0)
        val desired=longArrayOf(91,5,7,101,71,1,0,71,101,3,3,1003,1003,1,1,0)
        call("bounded","nativeValidateFrame",listOf(current,desired),0)
        call("signed-contained","nativeValidateSignedFrame",listOf(current,desired),0)
        call("actual-match","nativeFrameMatches",listOf(current,desired),true)
        call("actual-task","nativeTaskAllowed",listOf(current,71L,true),true)
        call("foreign-task","nativeTaskAllowed",listOf(current,72L,false),false)
        call("stale-revision","nativeValidateFrame",listOf(current,desired.copyOf().also { it[1]=4 }),1)
        call("duplicate-placement","nativeValidateFrame",listOf(current,desired.copyOf().also { it[5]=2 }),2)
        call("unknown-display","nativeValidateFrame",listOf(current,desired.copyOf().also { it[8]=102 }),2)
        call("invalid-input","nativeValidateFrame",listOf(current,desired.copyOf().also { it[14]=2 }),2)
        call("native-minimum","nativeValidateFrame",listOf(current,desired.copyOf().also { it[11]=100 }),6)
        call("changed-observation","nativeFrameMatches",listOf(current,desired.copyOf().also { it[9]=4 }),false)
        call("oversized-current","nativeValidateFrame",listOf(LongArray(1700),desired),2)
        call("oversized-frame","nativeValidateFrame",listOf(current,LongArray(6000)),2)
        for ((index,box) in listOf(longArrayOf(-100,-50,900,950),longArrayOf(-2000,-2000,-1000,-1000)).withIndex()) {
            val signed=desired.copyOf().also { box.copyInto(it,9) }
            call("signed-offscreen-"+index,"nativeValidateSignedFrame",listOf(current,signed),0)
            call("bounded-offscreen-"+index,"nativeValidateFrame",listOf(current,signed),2)
            val actual=current.copyOf().also { box.copyInto(it,16) }
            call("signed-actual-"+index,"nativeFrameMatches",listOf(actual,signed),true)
        }
        call("completion-wait","completion",listOf(false,false,100L,200L,true),0)
        call("completion-observed","completion",listOf(true,false,101L,200L,true),1)
        call("completion-timeout","completion",listOf(false,false,200L,200L,true),3)
        return journal
    }
}
