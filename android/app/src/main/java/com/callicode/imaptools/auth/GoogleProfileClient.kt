package com.callicode.imaptools.auth

import org.json.JSONObject
import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection

internal object GoogleProfileClient {
    fun emailAddress(accessToken: String): String {
        require(accessToken.isNotBlank()) { "Google access token is missing" }
        val connection = URL(PROFILE_URL).openConnection() as HttpsURLConnection
        return try {
            connection.requestMethod = "GET"
            connection.connectTimeout = TIMEOUT_MILLIS
            connection.readTimeout = TIMEOUT_MILLIS
            connection.setRequestProperty("Authorization", "Bearer $accessToken")
            connection.setRequestProperty("Accept", "application/json")
            val status = connection.responseCode
            if (status !in 200..299) throw GoogleProfileHttpException(status)
            val body = connection.inputStream.bufferedReader().use { it.readText() }
            parseGoogleProfileEmail(body)
        } finally {
            connection.disconnect()
        }
    }

    private const val PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
    private const val TIMEOUT_MILLIS = 15_000
}

internal class GoogleProfileHttpException(val statusCode: Int) : IOException("Google profile request failed")

internal fun googleProfileFailureMessage(error: Throwable): String =
    if ((error as? GoogleProfileHttpException)?.statusCode == HttpsURLConnection.HTTP_UNAUTHORIZED) {
        "Google access needs to be renewed. Connect Google again."
    } else {
        "Google account details are temporarily unavailable. Try again."
    }

internal fun isExpiredGoogleAuthorization(error: Throwable): Boolean =
    (error as? GoogleProfileHttpException)?.statusCode == HttpsURLConnection.HTTP_UNAUTHORIZED

internal fun parseGoogleProfileEmail(payload: String): String =
    JSONObject(payload).optString("emailAddress").trim().takeIf { it.isNotEmpty() }
        ?: throw IOException("Google profile did not contain an email address")
