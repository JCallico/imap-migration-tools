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
        assertEquals(36, store.entries().single().id.length)
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

    @Test
    fun deletingOneEntryLeavesOtherSavedOutputIntact() {
        val store = HistoryStore(File(temporaryFolder.root, "operation-history.json"))
        store.append(OperationState(status = RunStatus.SUCCEEDED, operation = Operation.COUNT, result = "first"))
        store.append(OperationState(status = RunStatus.FAILED, operation = Operation.BACKUP, error = "second"))
        val entries = store.entries()

        assertEquals(true, store.delete(entries.first().id))

        assertEquals(listOf("first"), store.entries().map { it.summary })
        assertEquals(false, store.delete("missing"))
    }
}
