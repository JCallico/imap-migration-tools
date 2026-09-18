package com.callicode.imaptools.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class StorageCapacityTest {
    @Test
    fun requiredBytesIncludesMarginAndReserve() {
        val oneGib = 1024L * 1024L * 1024L
        val required = StorageCapacity.requiredBytes(oneGib)

        assertEquals(oneGib + (oneGib * 15L / 100L) + StorageCapacity.RESERVED_BYTES, required)
        assertTrue(required > oneGib)
    }
}
