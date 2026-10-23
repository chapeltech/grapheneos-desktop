package org.wonad.desktop.prerequisites

import org.junit.Assert.*
import org.junit.Test

/** Pure matrix/shape contracts; actual target JNI runs only on Android. */
class NativePrerequisiteContractTest {
    @Test fun neutralSnapshotHasExactNativeWireAndNoWorkspacePolicy() {
        val values=NativePolicyAbiChecks.observation()
        assertEquals(41,values.size); assertArrayEquals(longArrayOf(3,42,9,0,0,1,2),values.copyOfRange(0,7))
        assertEquals(100L,values[7]); assertEquals(2L,values[8]); assertEquals(7L,values[17]); assertEquals(8L,values[29])
        assertEquals(17,NativePolicyAbiChecks.observation(tasks=emptyList()).size)
    }
    @Test fun freshNativeTokensAreNotRecycledAndroidDisplayIds() {
        val fresh=NativePolicyAbiChecks.observation(43,201,listOf(8))
        assertEquals(43L,fresh[1]); assertEquals(201L,fresh[7]); assertEquals(2L,fresh[8])
        assertEquals(8L,fresh[17]); assertEquals(201L,fresh[18]); assertEquals(0L,fresh[28])
    }
    @Test fun decisionParserRejectsTruncationTrailingOrInvalidCardinality() {
        val good=longArrayOf(3,42,9,0,0,0,0,0,1,1,100,1,7,100,0,0,1024,2000,1,0,1,0)
        assertEquals(listOf(7L),NativePolicyAbiChecks.placements(good).map { it[0] })
        for(bad in listOf(good.copyOf(good.size-1),good+longArrayOf(0),good.copyOf().also { it[8]=0 },good.copyOf().also { it[9]=129 })) {
            assertThrows(IllegalStateException::class.java) { NativePolicyAbiChecks.placements(bad) }
        }
    }
}
