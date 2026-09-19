package com.callicode.imaptools.operation

import com.callicode.imaptools.model.Operation
import org.junit.Assert.assertEquals
import org.junit.Test

class OperationDispatcherTest {
    @Test
    fun allOperationsUseUserInitiatedJobsOnAndroid14AndNewer() {
        Operation.entries.forEach {
            assertEquals(OperationExecutionMode.USER_INITIATED_JOB, executionMode(34))
            assertEquals(OperationExecutionMode.USER_INITIATED_JOB, executionMode(36))
        }
    }

    @Test
    fun allOperationsUseForegroundServiceBeforeAndroid14() {
        Operation.entries.forEach {
            assertEquals(OperationExecutionMode.FOREGROUND_SERVICE, executionMode(33))
        }
    }
}
