package com.callicode.imaptools.operation

import android.content.Context
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationEvent
import com.callicode.imaptools.model.OperationState
import com.callicode.imaptools.model.RunStatus
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class HistoryEntry(val timestamp: String, val state: OperationState) {
    val operation: String = state.operation?.title ?: "Unknown"
    val status: String = state.status.name.lowercase()
    val summary: String = state.error ?: state.result ?: state.events.lastOrNull()?.message.orEmpty()
}

class HistoryStore internal constructor(private val file: File) {
    constructor(context: Context) : this(File(context.filesDir, "operation-history.json"))

    @Synchronized
    fun append(state: OperationState) {
        val entries = readJson()
        entries.put(
            JSONObject()
                .put("timestamp", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date()))
                .put("operation", state.operation?.title ?: "Unknown")
                .put("status", state.status.name.lowercase())
                .put("summary", state.error ?: state.result ?: state.events.lastOrNull()?.message.orEmpty())
                .putNullable("result", state.result)
                .putNullable("error", state.error)
                .put("events", state.events.toJson()),
        )
        while (entries.length() > 100) entries.remove(0)
        val temporary = File(file.parentFile, "${file.name}.tmp")
        temporary.writeText(entries.toString())
        if (!temporary.renameTo(file)) {
            file.writeText(entries.toString())
            temporary.delete()
        }
    }

    @Synchronized
    fun entries(): List<HistoryEntry> {
        val values = readJson()
        return (values.length() - 1 downTo 0).map { index ->
            values.getJSONObject(index).let { value ->
                val status = enumValueOrDefault(value.optString("status").uppercase(), RunStatus.IDLE)
                val summary = value.optString("summary")
                HistoryEntry(
                    timestamp = value.getString("timestamp"),
                    state = OperationState(
                        status = status,
                        operation = operation(value.optString("operation")),
                        events = value.optJSONArray("events").toEvents(),
                        result = value.nullableString("result") ?: summary.takeUnless { status == RunStatus.FAILED },
                        error = value.nullableString("error") ?: summary.takeIf { status == RunStatus.FAILED },
                    ),
                )
            }
        }
    }

    private fun readJson(): JSONArray =
        runCatching { if (file.exists()) JSONArray(file.readText()) else JSONArray() }.getOrDefault(JSONArray())

    private fun List<OperationEvent>.toJson(): JSONArray = JSONArray().apply {
        forEach { event ->
            put(
                JSONObject()
                    .put("operation", event.operation)
                    .put("phase", event.phase)
                    .put("message", event.message)
                    .put("severity", event.severity)
                    .putNullable("folder", event.folder)
                    .putNullable("current", event.current)
                    .putNullable("total", event.total),
            )
        }
    }

    private fun JSONArray?.toEvents(): List<OperationEvent> {
        if (this == null) return emptyList()
        return (0 until length()).mapNotNull { index ->
            optJSONObject(index)?.let { value ->
                OperationEvent(
                    operation = value.optString("operation"),
                    phase = value.optString("phase"),
                    message = value.optString("message"),
                    severity = value.optString("severity", "info"),
                    folder = value.nullableString("folder"),
                    current = value.nullableInt("current"),
                    total = value.nullableInt("total"),
                )
            }
        }
    }

    private fun operation(value: String): Operation? = Operation.entries.firstOrNull {
        it.name.equals(value, ignoreCase = true) || it.title.equals(value, ignoreCase = true)
    }

    private fun JSONObject.nullableString(name: String): String? =
        if (has(name) && !isNull(name)) getString(name) else null

    private fun JSONObject.nullableInt(name: String): Int? =
        if (has(name) && !isNull(name)) getInt(name) else null

    private fun JSONObject.putNullable(name: String, value: Any?): JSONObject = put(name, value ?: JSONObject.NULL)

    private inline fun <reified T : Enum<T>> enumValueOrDefault(value: String, default: T): T =
        runCatching { enumValueOf<T>(value) }.getOrDefault(default)
}
