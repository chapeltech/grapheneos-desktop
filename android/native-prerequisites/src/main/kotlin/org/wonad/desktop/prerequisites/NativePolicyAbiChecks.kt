package org.wonad.desktop.prerequisites

import java.lang.reflect.InvocationTargetException

/** Invoke the ACTUAL target NativePolicy and preserve every native argument,
 * returned word and exception. This contains checks, not a policy renderer.
 * No target class or native library is copied into the test APK. */
internal class NativePolicyAbiChecks(loader: ClassLoader) {
    private val policy = loader.loadClass("org.wonad.desktop.NativePolicy")
    val journal = mutableListOf<Map<String, Any?>>()
    private val stepMethod = policy.getDeclaredMethod("nativeStep", LongArray::class.java,
        Long::class.javaPrimitiveType, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType,
        Long::class.javaPrimitiveType, LongArray::class.java)
    private val resetMethod = policy.getDeclaredMethod("nativeReset")
    private val checkpointMethod = policy.getDeclaredMethod("nativeCheckpoint")
    private val restoreMethod = policy.getDeclaredMethod("nativeRestore", LongArray::class.java, LongArray::class.java)

    companion object {
        fun observation(generation: Long = 42, display: Long = 100, tasks: List<Long> = listOf(7, 8)): LongArray =
            (listOf(3L, generation, 9L, 0L, 0L, 1L, tasks.size.toLong()) +
                listOf(display, 2L, 0L, 0L, 4000L, 2000L, 160L, 1L, generation, 1000L) +
                tasks.flatMapIndexed { index, token -> listOf(token, display, 10L + index * 600,
                    10L, 500L + index * 600, 400L, 80L, 60L, 1L, 1L, 1L, index.toLong()) }).toLongArray()

        fun placements(words: LongArray): List<List<Long>> {
            check(words.size >= 10 && words[0] == 3L && words[8] in 1..9 && words[9] in 0..128)
            check(words.size == 10 + words[8].toInt()*2 + words[9].toInt()*10)
            return words.drop(10 + words[8].toInt()*2).chunked(10)
        }
    }

    private fun record(name: String, method: String, args: Map<String, Any?>, invoke: () -> Any?): Any? {
        var result: Any? = null; var error: Throwable? = null
        try { result = invoke() } catch (caught: InvocationTargetException) { error = caught.targetException }
        catch (caught: Throwable) { error = caught }
        journal.add(mapOf("name" to name, "method" to method, "arguments" to args,
            "output" to if (result is LongArray) result.toList() else result,
            "exception" to error?.javaClass?.name, "message" to error?.message))
        return if (error != null) error else result
    }
    private fun reset(name: String) { check(record(name,"nativeReset", emptyMap()) { resetMethod.invoke(null) } == null) }
    private fun checkpoint(name: String): LongArray {
        val value=record(name,"nativeCheckpoint", emptyMap()) { checkpointMethod.invoke(null) }
        check(value is LongArray && value.size in 7..2073 && value[0] == 1L); return value
    }
    private fun step(name: String, snapshot: LongArray, origin: Long = 0, command: Int = 0,
        argument: Int = 0, target: Long = 0, box: LongArray = longArrayOf(), rejected: Boolean = false): LongArray {
        val value=record(name,"nativeStep",mapOf("snapshot" to snapshot.toList(),"origin" to origin,
            "command" to command,"argument" to argument,"target" to target,"bounds" to box.toList())) {
            stepMethod.invoke(null,snapshot,origin,command,argument,target,box)
        }
        if (rejected) { check(value is IllegalArgumentException) { "Native ABI accepted $name" }; return longArrayOf() }
        check(value is LongArray && value[1] == snapshot[1] && value[2] == snapshot[2]) {
            "Actual NativePolicy ABI failed $name: ${value?.javaClass?.name}: $value"
        }; placements(value); return value
    }
    private fun restore(name: String, snapshot: LongArray, payload: LongArray, accepted: Boolean) {
        check(record(name,"nativeRestore",mapOf("snapshot" to snapshot.toList(),"checkpoint" to payload.toList())) {
            restoreMethod.invoke(null,snapshot,payload)
        } == accepted) { "Native checkpoint admission differed: $name" }
    }
    fun run(): List<Map<String, Any?>> {
        val base=observation(); reset("reset-initial"); checkpoint("checkpoint-empty")
        check(placements(step("zero-tasks",observation(tasks=emptyList()))).isEmpty())
        reset("reset-two")
        val columns=step("columns",base)
        check(placements(columns).map { it.subList(2,6) } == listOf(listOf(0L,0L,1024L,2000L),listOf(1024L,0L,2048L,2000L)))
        step("focus-one",base,100,17,target=7)
        val full=step("full",base,100,7); check(placements(full).single { it[6] == 1L }.let { it[0]==7L && it.subList(2,6)==listOf(0L,0L,4000L,2000L) })
        step("columns-return",base,100,7)
        val box=longArrayOf(100,120,800,620)
        check(placements(step("float-one",base,100,18,target=7,box=box)).single { it[0]==7L }.let { it[7]==1L && it.subList(2,6)==box.toList() })
        val saved=checkpoint("checkpoint-float"); reset("reset-saved"); restore("restore-float",base,saved,true)
        check(placements(step("passive-restored",base)).single { it[0]==7L }.subList(2,6)==box.toList())
        val before=checkpoint("checkpoint-atomic-before")
        restore("restore-truncated-rejected",base,saved.copyOf(saved.size-1),false)
        check(checkpoint("checkpoint-atomic-after").contentEquals(before))
        val fresh=observation(43,201); restore("fresh-rebind-restore",fresh,saved,true)
        val rebound=step("fresh-rebind-step",fresh)
        check(placements(rebound).all { it[1]==201L } && placements(rebound).single { it[0]==7L }.subList(2,6)==box.toList())
        val pruned=observation(44,202,listOf(8)); restore("removed-prune-restore",pruned,saved,true)
        check(placements(step("removed-prune-step",pruned)).map { it[0] }==listOf(8L))
        val negative=longArrayOf(-200,-150,824,618)
        check(placements(step("negative-float",base,100,18,target=7,box=negative)).single { it[0]==7L }.subList(2,6)==negative.toList())
        val offscreen=longArrayOf(-3000,-2000,-1976,-1232)
        check(placements(step("offscreen-float",base,100,18,target=7,box=offscreen)).single { it[0]==7L }.subList(2,6)==offscreen.toList())
        check(placements(step("sink-one",base,100,19,target=7)).single { it[0]==7L }[7]==0L)
        check(placements(step("hidden-workspace",base,100,8,9)).none { it[6]==1L })
        check(placements(step("returned-workspace",base,100,8,1)).all { it[6]==1L })
        val malformed=listOf("short" to base.copyOf(6),"version" to base.copyOf().also { it[0]=2 },
            "count" to base.copyOf().also { it[6]=3 },"duplicate-task" to base.copyOf().also { it[29]=7 },
            "phone-display" to base.copyOf().also { it[8]=0 },"foreign-focus" to base.copyOf().also { it[4]=999 },
            "coordinate" to base.copyOf().also { it[9]=-1 },"boolean" to base.copyOf().also { it[25]=2 },
            "oversized" to LongArray(1634))
        malformed.forEach { (name,snapshot) -> step("malformed-"+name,snapshot,rejected=true) }
        step("gesture-shape",base,100,18,target=7,box=longArrayOf(0,0,20),rejected=true)
        step("gesture-overflow",base,100,18,target=7,box=longArrayOf(Long.MAX_VALUE,0,20,20),rejected=true)
        step("foreign-gesture-task",base,100,17,target=999,rejected=true)
        step("stale-display-gesture",fresh,100,17,target=7,rejected=true)
        repeat(64) { index -> val result=step("stress-"+index,base); check(placements(result).size==2); if (index%8==0) System.gc() }
        reset("reset-final"); checkpoint("checkpoint-final")
        return journal
    }
}
