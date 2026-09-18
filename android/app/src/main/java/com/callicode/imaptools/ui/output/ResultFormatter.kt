package com.callicode.imaptools.ui.output

import com.callicode.imaptools.model.Operation
import org.json.JSONArray
import org.json.JSONObject

data class ResultLine(val label: String, val value: String, val isError: Boolean = false)

data class ResultPresentation(
    val heading: String,
    val metrics: List<ResultLine>,
    val details: List<ResultLine> = emptyList(),
    val fallback: String? = null,
)

object ResultFormatter {
    fun format(operation: Operation?, raw: String): ResultPresentation = runCatching {
        val value = JSONObject(raw)
        when (operation) {
            Operation.COUNT -> count(value)
            Operation.COMPARE -> compare(value)
            Operation.BACKUP, Operation.RESTORE, Operation.MIGRATE -> transfer(operation, value)
            null -> fallback(value)
        }
    }.getOrElse {
        ResultPresentation("OPERATION COMPLETE", emptyList(), fallback = raw)
    }

    private fun count(value: JSONObject): ResultPresentation {
        val counts = value.optJSONObject("folder_counts") ?: JSONObject()
        val details = counts.keys().asSequence().toList().sorted().map { folder ->
            ResultLine(folder, if (counts.isNull(folder)) "—" else counts.optInt(folder).toString())
        }
        return ResultPresentation(
            heading = "COUNT COMPLETE",
            metrics = listOf(
                ResultLine("Total messages", value.optInt("total").toString()),
                ResultLine("Folders", details.size.toString()),
            ),
            details = details,
        )
    }

    private fun compare(value: JSONObject): ResultPresentation {
        val rows = value.optJSONArray("rows") ?: JSONArray()
        var incomplete = false
        val details = (0 until rows.length()).map { index ->
            val row = rows.getJSONObject(index)
            val source = nullableNumber(row, "source")
            val destination = nullableNumber(row, "destination")
            val difference = if (source != null && destination != null) source - destination else null
            if (difference == null) incomplete = true
            ResultLine(
                row.optString("folder", "Unknown folder"),
                "SRC ${source ?: "—"}  DST ${destination ?: "—"}  Δ ${signed(difference)}",
                isError = difference == null || difference != 0,
            )
        }
        val matches = !incomplete && details.none(ResultLine::isError)
        return ResultPresentation(
            heading = when {
                incomplete -> "COMPARISON INCOMPLETE"
                matches -> "MAILBOXES MATCH"
                else -> "DIFFERENCES FOUND"
            },
            metrics = listOf(
                ResultLine("Source total", value.optInt("source_total").toString()),
                ResultLine("Destination total", value.optInt("destination_total").toString()),
                ResultLine("Status", if (matches) "MATCH" else "REVIEW REQUIRED", isError = !matches),
            ),
            details = details,
        )
    }

    private fun transfer(operation: Operation, value: JSONObject): ResultPresentation {
        val folders = value.optJSONArray("folders") ?: JSONArray()
        val details = (0 until folders.length()).map { index ->
            val folder = folders.getJSONObject(index)
            val processed = nullableNumber(folder, "processed")
            val skipped = nullableNumber(folder, "skipped")
            val failed = nullableNumber(folder, "failed")
            val values = buildList {
                if (processed != null) add("$processed done")
                if (skipped != null) add("$skipped skipped")
                if (failed != null) add("$failed failed")
            }
            ResultLine(
                folder.optString("name", "Unknown folder"),
                values.takeIf { it.isNotEmpty() }?.joinToString(" · ") ?: "Completed; detailed counts unavailable",
                isError = (failed ?: 0) > 0,
            )
        }
        val artifacts = value.optJSONArray("artifacts")?.length() ?: 0
        val processed = folders.sumNullable("processed")
        val skipped = folders.sumNullable("skipped")
        val failed = folders.sumNullable("failed")
        val deleted = folders.sumNullable("deleted")
        return ResultPresentation(
            heading = "${operation.title.uppercase()} COMPLETE",
            metrics = buildList {
                add(ResultLine("Folders", folders.length().toString()))
                if (processed != null) add(ResultLine("Processed", processed.toString()))
                if (skipped != null) add(ResultLine("Skipped", skipped.toString()))
                if (failed != null) add(ResultLine("Failed", failed.toString(), isError = failed > 0))
                if (deleted != null) add(ResultLine("Deleted", deleted.toString()))
                add(ResultLine("Artifacts", artifacts.toString()))
            },
            details = details,
        )
    }

    private fun fallback(value: JSONObject) = ResultPresentation(
        heading = "OPERATION COMPLETE",
        metrics = emptyList(),
        fallback = value.toString(2),
    )

    private fun nullableNumber(value: JSONObject, name: String): Int? =
        if (value.isNull(name)) null else value.optInt(name)

    private fun JSONArray.sumNullable(name: String): Int? {
        val values = (0 until length()).map { nullableNumber(getJSONObject(it), name) }
        return if (values.any { it == null }) null else values.filterNotNull().sum()
    }

    private fun signed(value: Int?): String = when {
        value == null -> "—"
        value > 0 -> "+$value"
        else -> value.toString()
    }
}
