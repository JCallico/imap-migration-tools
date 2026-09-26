package com.callicode.imaptools.auth

import android.accounts.Account
import android.content.Context
import com.callicode.imaptools.BuildConfig
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.common.api.Scope
import com.google.android.gms.tasks.Tasks
import com.microsoft.identity.client.AcquireTokenSilentParameters
import com.microsoft.identity.client.IAccount
import com.microsoft.identity.client.IAuthenticationResult
import com.microsoft.identity.client.IMultipleAccountPublicClientApplication
import com.microsoft.identity.client.IPublicClientApplication
import com.microsoft.identity.client.PublicClientApplication
import com.microsoft.identity.client.SilentAuthenticationCallback
import com.microsoft.identity.client.exception.MsalException
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Supplies refreshed native OAuth tokens to Python reconnects without retaining an Activity. */
class SilentTokenProvider(context: Context, requestJson: String) {
    private val applicationContext = context.applicationContext
    private val accounts = requestAccounts(JSONObject(requestJson))
    private var microsoftApplication: IMultipleAccountPublicClientApplication? = null

    @Synchronized
    @Suppress("unused")
    fun getAccessToken(slot: String): String {
        val account = accounts[slot] ?: error("No OAuth account is configured for $slot")
        return when (account.provider) {
            GOOGLE -> googleToken(account)
            MICROSOFT -> microsoftToken(account)
            else -> error("Unsupported OAuth provider: ${account.provider}")
        }
    }

    private fun googleToken(account: NativeAccount): String {
        val request = AuthorizationRequest.builder()
            .setRequestedScopes(listOf(Scope(GOOGLE_IMAP_SCOPE)))
            .setAccount(Account(account.email, GOOGLE_ACCOUNT_TYPE))
            .build()
        val result = Tasks.await(
            Identity.getAuthorizationClient(applicationContext).authorize(request),
            TOKEN_TIMEOUT_SECONDS,
            TimeUnit.SECONDS,
        )
        check(!result.hasResolution()) {
            "Google needs user interaction. Return to the app and run the operation again."
        }
        return result.accessToken?.takeIf(String::isNotBlank)
            ?: error("Google did not return an access token")
    }

    private fun microsoftToken(saved: NativeAccount): String {
        val application = microsoftApplication ?: createMicrosoftApplication().also { microsoftApplication = it }
        val account = awaitMicrosoft<IAccount?> { complete ->
            application.getAccount(saved.accountId, object : IMultipleAccountPublicClientApplication.GetAccountCallback {
                override fun onTaskCompleted(result: IAccount?) = complete(Result.success(result))
                override fun onError(exception: MsalException) = complete(Result.failure(exception))
            })
        } ?: error("Microsoft account is no longer available. Reconnect it in the app.")
        return awaitMicrosoft<IAuthenticationResult> { complete ->
            val parameters = AcquireTokenSilentParameters.Builder()
                .forAccount(account)
                .fromAuthority(account.authority)
                .withScopes(listOf(MICROSOFT_IMAP_SCOPE))
                .withCallback(object : SilentAuthenticationCallback {
                    override fun onSuccess(authenticationResult: IAuthenticationResult) =
                        complete(Result.success(authenticationResult))

                    override fun onError(exception: MsalException) = complete(Result.failure(exception))
                })
                .build()
            application.acquireTokenSilentAsync(parameters)
        }.accessToken.takeIf(String::isNotBlank) ?: error("Microsoft did not return an access token")
    }

    private fun createMicrosoftApplication(): IMultipleAccountPublicClientApplication {
        check(BuildConfig.MICROSOFT_CLIENT_ID.isNotBlank() && BuildConfig.MICROSOFT_REDIRECT_URI.isNotBlank()) {
            "Microsoft sign-in is not configured in this build"
        }
        return awaitMicrosoft<IPublicClientApplication> { complete ->
            PublicClientApplication.create(
                applicationContext,
                BuildConfig.MICROSOFT_CLIENT_ID,
                MICROSOFT_AUTHORITY,
                BuildConfig.MICROSOFT_REDIRECT_URI,
                object : IPublicClientApplication.ApplicationCreatedListener {
                    override fun onCreated(application: IPublicClientApplication) =
                        complete(Result.success(application))

                    override fun onError(exception: MsalException) = complete(Result.failure(exception))
                },
            )
        } as? IMultipleAccountPublicClientApplication
            ?: error("Microsoft multiple-account support is unavailable")
    }

    private fun <T> awaitMicrosoft(start: ((Result<T>) -> Unit) -> Unit): T {
        val latch = CountDownLatch(1)
        val outcome = AtomicReference<Result<T>>()
        val completed = AtomicBoolean(false)
        start {
            if (completed.compareAndSet(false, true)) {
                outcome.set(it)
                latch.countDown()
            }
        }
        check(latch.await(TOKEN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) { "Microsoft token refresh timed out" }
        return outcome.get().getOrThrow()
    }

    private data class NativeAccount(
        val provider: String,
        val email: String,
        val accountId: String,
    )

    companion object {
        private const val GOOGLE = "google"
        private const val MICROSOFT = "microsoft"
        private const val GOOGLE_IMAP_SCOPE = "https://mail.google.com/"
        private const val GOOGLE_ACCOUNT_TYPE = "com.google"
        private const val MICROSOFT_AUTHORITY = "https://login.microsoftonline.com/common"
        private const val MICROSOFT_IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All"
        private const val TOKEN_TIMEOUT_SECONDS = 60L

        private fun requestAccounts(request: JSONObject): Map<String, NativeAccount> = buildMap {
            listOf("source", "destination", "target").forEach { key ->
                val value = request.optJSONObject(key) ?: return@forEach
                val account = if (value.optString("kind") == "imap") value.optJSONObject("account") else value
                if (account == null) return@forEach
                val oauth = account.optJSONObject("oauth2") ?: return@forEach
                val slot = account.optString("tokenSlot")
                if (slot.isBlank()) return@forEach
                put(
                    slot,
                    NativeAccount(
                        provider = oauth.optString("provider"),
                        email = account.optString("username"),
                        accountId = account.optString("oauthAccountId"),
                    ),
                )
            }
        }
    }
}
