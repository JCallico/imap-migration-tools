package com.callicode.imaptools

import com.callicode.imaptools.model.Operation
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkConfirmationTest {
    @Test
    fun largeTransfersRequireConfirmationOutsideUnmeteredWifi() {
        assertTrue(shouldConfirmLargeTransfer(Operation.BACKUP, false))
        assertTrue(shouldConfirmLargeTransfer(Operation.RESTORE, false))
        assertTrue(shouldConfirmLargeTransfer(Operation.MIGRATE, false))
        assertFalse(shouldConfirmLargeTransfer(Operation.COUNT, false))
        assertFalse(shouldConfirmLargeTransfer(Operation.COMPARE, false))
        assertFalse(shouldConfirmLargeTransfer(Operation.MIGRATE, true))
    }
}
