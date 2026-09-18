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
            if (status !in 200..299) throw IOException("Google profile request failed (HTTP $status)")
            val body = connection.inputStream.bufferedReader().use { it.readText() }
            parseGoogleProfileEmail(body)
        } finally {
            connection.disconnect()
        }
    }

    private const val PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
    private const val TIMEOUT_MILLIS = 15_000
}

internal fun parseGoogleProfileEmail(payload: String): String =
    JSONObject(payload).optString("emailAddress").trim().takeIf { it.isNotEmpty() }
        ?: throw IOException("Google profile did not contain an email address")
