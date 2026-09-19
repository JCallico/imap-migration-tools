package com.callicode.imaptools.operation

import com.callicode.imaptools.model.OperationEvent
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Removes credentials, account identifiers, private paths, and per-message details from retained output. */
class PrivacyRedactor(requestJson: String, privateRoot: File) {
    private val sensitiveValues = buildList {
        collectSensitiveValues(runCatching { JSONObject(requestJson) }.getOrNull(), this)
        add(privateRoot.absolutePath)
        add(privateRoot.canonicalPath)
    }.distinct().sortedByDescending(String::length)

    fun event(event: OperationEvent): OperationEvent = event.copy(
        message = redactMessage(event.message),
    )

    fun text(value: String): String = redactMessage(value)

    private fun redactMessage(value: String): String {
        val redacted = redactKnownValues(value)
            .replace(EMAIL_ADDRESS, REDACTED_ACCOUNT)
            .replace(EML_PATH, REDACTED_MESSAGE)
        if (!MESSAGE_DETAIL_ACTION.containsMatchIn(redacted)) return redacted
        val fields = redacted.split('|')
        return if (fields.size >= 2) {
            fields.dropLast(1).joinToString("|").trimEnd() + " | $REDACTED_MESSAGE"
        } else {
            redacted
        }
    }

    private fun redactKnownValues(value: String): String = sensitiveValues.fold(value) { output, secret ->
        output.replace(secret, if (secret.contains('@')) REDACTED_ACCOUNT else REDACTED_VALUE, ignoreCase = true)
    }

    companion object {
        private const val REDACTED_VALUE = "[redacted]"
        private const val REDACTED_ACCOUNT = "[account hidden]"
        private const val REDACTED_MESSAGE = "[message details hidden]"
        private val SENSITIVE_KEYS = setOf(
            "password",
            "accesstoken",
            "refreshtoken",
            "clientsecret",
            "username",
            "oauthaccountid",
        )
        private val SECRET_KEYS = setOf("password", "accesstoken", "refreshtoken", "clientsecret")
        private val EMAIL_ADDRESS = Regex("(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b")
        private val EML_PATH = Regex("(?i)(?:[^\\s|/]+/)*[^\\s|]+\\.eml\\b")
        private val MESSAGE_DETAIL_ACTION = Regex(
            "(?i)\\b(?:SAVED|UPLOADED|COPIED|SKIP \\(cached\\)|SKIP \\(exists\\)|SKIP \\(already present\\)|FAILED)\\b",
        )

        private fun collectSensitiveValues(value: Any?, output: MutableList<String>, key: String = "") {
            when (value) {
                is JSONObject -> value.keys().forEach { childKey ->
                    collectSensitiveValues(value.opt(childKey), output, childKey)
                }
                is JSONArray -> (0 until value.length()).forEach { collectSensitiveValues(value.opt(it), output, key) }
                is String -> {
                    val normalizedKey = key.lowercase()
                    if (normalizedKey in SENSITIVE_KEYS &&
                        value.isNotBlank() &&
                        (normalizedKey in SECRET_KEYS || value.length >= 3)
                    ) {
                        output += value
                    }
                }
            }
        }
    }
}
