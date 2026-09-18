package com.callicode.imaptools.engine

import com.chaquo.python.Python
import com.callicode.imaptools.model.OperationEvent
import com.callicode.imaptools.auth.SilentTokenProvider
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

class CancellationSignal {
    private val cancelled = AtomicBoolean(false)

    fun cancel() = cancelled.set(true)

    @Suppress("unused")
    fun isCancelled(): Boolean = cancelled.get()
}

class EventListener(private val onEvent: (OperationEvent) -> Unit) {
    @Suppress("unused")
    fun onEvent(json: String) {
        val value = JSONObject(json)
        onEvent(
            OperationEvent(
                operation = value.getString("operation"),
                phase = value.getString("phase"),
                message = value.getString("message"),
                severity = value.optString("severity", "info"),
                folder = value.optNullableString("folder"),
                current = value.optNullableInt("current"),
                total = value.optNullableInt("total"),
            ),
        )
    }
}

class PythonEngine {
    fun run(
        requestJson: String,
        listener: EventListener,
        cancellation: CancellationSignal,
        tokenProvider: SilentTokenProvider,
    ): EngineResult {
        val response = Python.getInstance().getModule("mobile.bridge")
            .callAttr("run_operation", requestJson, listener, cancellation, tokenProvider)
            .toString()
        val envelope = JSONObject(response)
        return when (envelope.getString("status")) {
            "succeeded" -> EngineResult.Succeeded(envelope.opt("result")?.toString() ?: "{}")
            "cancelled" -> EngineResult.Cancelled
            else -> EngineResult.Failed(envelope.optJSONObject("error")?.optString("message") ?: "Operation failed")
        }
    }

    fun estimateBackup(
        requestJson: String,
        cancellation: CancellationSignal,
        tokenProvider: SilentTokenProvider,
    ): BackupEstimateResult {
        val response = Python.getInstance().getModule("mobile.bridge")
            .callAttr("estimate_backup", requestJson, cancellation, tokenProvider)
            .toString()
        val envelope = JSONObject(response)
        return when (envelope.getString("status")) {
            "succeeded" -> BackupEstimateResult.Ready(
                envelope.getLong("estimatedBytes"),
                envelope.getInt("messageCount"),
            )
            "cancelled" -> BackupEstimateResult.Cancelled
            else -> BackupEstimateResult.Failed(
                envelope.optJSONObject("error")?.optString("message") ?: "Storage estimate unavailable",
            )
        }
    }
}

sealed interface EngineResult {
    data class Succeeded(val result: String) : EngineResult
    data class Failed(val message: String) : EngineResult
    data object Cancelled : EngineResult
}

sealed interface BackupEstimateResult {
    data class Ready(val estimatedBytes: Long, val messageCount: Int) : BackupEstimateResult
    data class Failed(val message: String) : BackupEstimateResult
    data object Cancelled : BackupEstimateResult
}

private fun JSONObject.optNullableString(name: String): String? =
    if (isNull(name)) null else optString(name).takeIf { it.isNotEmpty() }

private fun JSONObject.optNullableInt(name: String): Int? = if (isNull(name)) null else optInt(name)
