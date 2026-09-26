package com.callicode.imaptools.ui.output

import com.callicode.imaptools.model.Operation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResultFormatterTest {
    @Test
    fun formatsCountResultAsMetricsAndSortedFolders() {
        val result = ResultFormatter.format(
            Operation.COUNT,
            """{"folder_counts":{"Sent":4,"INBOX":8},"total":12}""",
        )

        assertEquals("COUNT COMPLETE", result.heading)
        assertEquals(ResultLine("Total messages", "12"), result.metrics.first())
        assertEquals(listOf("INBOX", "Sent"), result.details.map(ResultLine::label))
    }

    @Test
    fun highlightsComparisonDifferences() {
        val result = ResultFormatter.format(
            Operation.COMPARE,
            """{"rows":[{"folder":"INBOX","source":12,"destination":10}],"source_total":12,"destination_total":10}""",
        )

        assertEquals("DIFFERENCES FOUND", result.heading)
        assertTrue(result.details.single().isError)
        assertTrue(result.details.single().value.contains("Δ +2"))
    }

    @Test
    fun unavailableComparisonCountCannotBeReportedAsMatch() {
        val result = ResultFormatter.format(
            Operation.COMPARE,
            """{"rows":[{"folder":"INBOX","source":12,"destination":null}],"source_total":12,"destination_total":0}""",
        )

        assertEquals("COMPARISON INCOMPLETE", result.heading)
        assertTrue(result.details.single().isError)
    }

    @Test
    fun aggregatesTransferFolderResults() {
        val result = ResultFormatter.format(
            Operation.MIGRATE,
            """{"folders":[{"name":"INBOX","processed":7,"skipped":2,"failed":1,"deleted":3}],"artifacts":[]}""",
        )

        assertEquals("MIGRATE COMPLETE", result.heading)
        assertEquals("7", result.metrics.first { it.label == "Processed" }.value)
        assertTrue(result.metrics.first { it.label == "Failed" }.isError)
        assertFalse(result.details.isEmpty())
    }

    @Test
    fun unavailableTransferCountsAreNotPresentedAsZero() {
        val result = ResultFormatter.format(
            Operation.BACKUP,
            """{"folders":[{"name":"INBOX","processed":null,"skipped":null,"failed":null,"deleted":null}],"artifacts":[]}""",
        )

        assertFalse(result.metrics.any { it.label == "Processed" })
        assertTrue(result.details.single().value.contains("unavailable"))
    }
}
