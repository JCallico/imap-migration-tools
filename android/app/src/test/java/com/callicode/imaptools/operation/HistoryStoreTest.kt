package com.callicode.imaptools.operation

import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationEvent
import com.callicode.imaptools.model.OperationState
import com.callicode.imaptools.model.RunStatus
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class HistoryStoreTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun completedOutputRoundTripsWithEventsAndResult() {
        val store = HistoryStore(File(temporaryFolder.root, "operation-history.json"))
        val state = OperationState(
            status = RunStatus.SUCCEEDED,
            operation = Operation.COUNT,
            events = listOf(
                OperationEvent(
                    operation = "count",
                    phase = "complete",
                    message = "Counted INBOX",
                    severity = "success",
                    folder = "INBOX",
                    current = 12,
                    total = 12,
                ),
            ),
            result = """{"total":12}""",
        )

        store.append(state)

        assertEquals(state, store.entries().single().state)
    }

    @Test
    fun legacySummaryRemainsViewableAsOutput() {
        File(temporaryFolder.root, "operation-history.json").writeText(
            """[{"timestamp":"2026-01-01T12:00:00Z","operation":"Count","status":"succeeded","summary":"12 messages"}]""",
        )

        val entry = HistoryStore(File(temporaryFolder.root, "operation-history.json")).entries().single()

        assertEquals(Operation.COUNT, entry.state.operation)
        assertEquals(RunStatus.SUCCEEDED, entry.state.status)
        assertEquals("12 messages", entry.state.result)
    }
}
