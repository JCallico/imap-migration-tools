package com.callicode.imaptools.operation

import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationEvent
import com.callicode.imaptools.model.OperationState
import com.callicode.imaptools.model.RunStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
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

    @Test
    fun eachProjectScopeSeesOnlyItsOwnRuns() {
        val acme = HistoryStore.historyFile(temporaryFolder.root, "project-acme")
        val other = HistoryStore.historyFile(temporaryFolder.root, "project-other")
        HistoryStore(acme).append(OperationState(status = RunStatus.SUCCEEDED, operation = Operation.COUNT, result = "acme"))
        HistoryStore(other).append(OperationState(status = RunStatus.FAILED, operation = Operation.BACKUP, error = "other"))

        assertEquals(listOf("acme"), HistoryStore(acme).entries().map { it.state.result })
        assertEquals(listOf("other"), HistoryStore(other).entries().map { it.state.error })
        assertEquals(File(temporaryFolder.root, "history/project-acme.json"), acme)

        val entry = HistoryStore(acme).entries().single()
        assertEquals(false, HistoryStore(other).delete(entry.id))
        assertEquals(1, HistoryStore(acme).entries().size)
    }

    @Test
    fun unsafeScopesAreRejected() {
        listOf("", ".", "..", "../outside", "a/b", "a\\b", "bad\u0000name").forEach { scope ->
            assertThrows(IllegalArgumentException::class.java) {
                HistoryStore.historyFile(temporaryFolder.root, scope)
            }
        }
    }

    @Test
    fun historyBeforeProjectsIsAdoptedByTheDefaultProjectOnce() {
        val legacy = File(temporaryFolder.root, "operation-history.json")
        legacy.writeText("""[{"timestamp":"2026-01-01T12:00:00Z","operation":"Count","status":"succeeded","summary":"12"}]""")

        HistoryStore.adoptLegacyHistory(temporaryFolder.root, "default")
        HistoryStore.adoptLegacyHistory(temporaryFolder.root, "default")

        assertEquals(false, legacy.exists())
        assertEquals(1, HistoryStore(HistoryStore.historyFile(temporaryFolder.root, "default")).entries().size)
        assertEquals(0, HistoryStore(HistoryStore.historyFile(temporaryFolder.root, "project-acme")).entries().size)
    }

    @Test
    fun renamingMovesHistoryAndNeverMergesIntoExistingHistory() {
        val root = temporaryFolder.root
        HistoryStore(HistoryStore.historyFile(root, "project-acme"))
            .append(OperationState(status = RunStatus.SUCCEEDED, operation = Operation.COUNT, result = "acme"))
        HistoryStore(HistoryStore.historyFile(root, "project-leftover"))
            .append(OperationState(status = RunStatus.SUCCEEDED, operation = Operation.COUNT, result = "leftover"))

        HistoryStore.moveScope(root, "project-acme", "project-acme-corp")
        HistoryStore.moveScope(root, "project-missing", "project-anything")
        HistoryStore.moveScope(root, "project-acme-corp", "project-acme-corp")

        assertEquals(1, HistoryStore(HistoryStore.historyFile(root, "project-acme-corp")).entries().size)
        assertEquals(0, HistoryStore(HistoryStore.historyFile(root, "project-acme")).entries().size)
        assertThrows(IllegalStateException::class.java) {
            HistoryStore.moveScope(root, "project-acme-corp", "project-leftover")
        }
        assertEquals(1, HistoryStore(HistoryStore.historyFile(root, "project-acme-corp")).entries().size)
    }

    @Test
    fun deletingAScopeRemovesOnlyThatProjectsHistory() {
        val root = temporaryFolder.root
        HistoryStore(HistoryStore.historyFile(root, "project-acme"))
            .append(OperationState(status = RunStatus.SUCCEEDED, operation = Operation.COUNT, result = "acme"))
        HistoryStore(HistoryStore.historyFile(root, "project-other"))
            .append(OperationState(status = RunStatus.SUCCEEDED, operation = Operation.COUNT, result = "other"))

        HistoryStore.deleteScope(root, "project-acme")
        HistoryStore.deleteScope(root, "project-acme")

        assertEquals(0, HistoryStore(HistoryStore.historyFile(root, "project-acme")).entries().size)
        assertEquals(1, HistoryStore(HistoryStore.historyFile(root, "project-other")).entries().size)
    }
}
