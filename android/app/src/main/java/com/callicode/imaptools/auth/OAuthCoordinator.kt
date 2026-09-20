package com.callicode.imaptools.auth

import android.accounts.Account
import android.app.Activity
import android.content.Intent
import androidx.activity.ComponentActivity
import androidx.activity.result.IntentSenderRequest
import androidx.lifecycle.lifecycleScope
import com.callicode.imaptools.BuildConfig
import com.callicode.imaptools.MainViewModel
import com.callicode.imaptools.model.AccountSlot
import com.callicode.imaptools.model.AccountState
import com.callicode.imaptools.model.AppConfiguration
import com.callicode.imaptools.model.Authentication
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.TargetType
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.AuthorizationResult
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.auth.api.identity.RevokeAccessRequest
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.common.api.Scope
import com.microsoft.identity.client.AcquireTokenParameters
import com.microsoft.identity.client.AcquireTokenSilentParameters
import com.microsoft.identity.client.AuthenticationCallback
import com.microsoft.identity.client.IAccount
import com.microsoft.identity.client.IAuthenticationResult
import com.microsoft.identity.client.IMultipleAccountPublicClientApplication
import com.microsoft.identity.client.IPublicClientApplication
import com.microsoft.identity.client.Prompt
import com.microsoft.identity.client.PublicClientApplication
import com.microsoft.identity.client.SilentAuthenticationCallback
import com.microsoft.identity.client.exception.MsalException
import com.microsoft.identity.client.exception.MsalUiRequiredException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class OAuthCoordinator(
    private val activity: ComponentActivity,
    private val viewModel: MainViewModel,
    private val launchGoogleAuthorization: (IntentSenderRequest) -> Unit,
) {
    private val googleClient = Identity.getAuthorizationClient(activity)
    private val googleScopes = listOf(Scope(GOOGLE_IMAP_SCOPE))
    private var pendingGoogle: GoogleRequest? = null
    private var microsoftClient: IMultipleAccountPublicClientApplication? = null
    private val microsoftWaiters = mutableListOf<(Result<IMultipleAccountPublicClientApplication>) -> Unit>()
    private var microsoftInitializing = false

    fun connect(slot: AccountSlot, provider: Authentication, complete: (String?) -> Unit = {}) {
        if (viewModel.operationRunning()) {
            complete("Wait for the current operation to finish")
            return
        }
        if (!begin()) return
        when (provider) {
            Authentication.GOOGLE -> authorizeGoogle(slot, null) { error -> finish(error, complete) }
            Authentication.MICROSOFT -> acquireMicrosoftInteractive(slot, "") { error -> finish(error, complete) }
            Authentication.PASSWORD -> finish("Choose Google or Microsoft before connecting", complete)
        }
    }

    fun disconnect(slot: AccountSlot, account: AccountState, complete: (String?) -> Unit = {}) {
        if (viewModel.operationRunning()) {
            complete("Wait for the current operation to finish")
            return
        }
        if (!begin()) return
        if (viewModel.oauthAccountReferenceCount(account) > 1) {
            viewModel.clearOAuthAccount(slot)
            finish(null, complete)
            return
        }
        when (account.authentication) {
            Authentication.GOOGLE -> revokeGoogle(slot, account, complete)
            Authentication.MICROSOFT -> removeMicrosoft(slot, account, complete)
            Authentication.PASSWORD -> finish(null, complete)
        }
    }

    fun prepare(configuration: AppConfiguration, complete: (String?) -> Unit) {
        if (!begin()) {
            complete("Authentication is already in progress")
            return
        }
        val accounts = requiredAccounts(configuration).filter { (_, account) ->
            account.authentication != Authentication.PASSWORD
        }
        refreshNext(accounts, 0) { error -> finish(error, complete) }
    }

    fun onGoogleAuthorizationResult(resultCode: Int, data: Intent?) {
        val pending = pendingGoogle
        if (pending == null) {
            viewModel.reportAuthenticationMessage("Google authentication was interrupted. Please try again.")
            return
        }
        pendingGoogle = null
        if (data == null) {
            pending.complete(googleAuthorizationDidNotComplete(resultCode))
            return
        }
        runCatching { googleClient.getAuthorizationResultFromIntent(data) }
            .onSuccess {
                continueGoogleAuthorization(
                    pending.slot,
                    it,
                    pending.complete,
                    pending.resolutionCount,
                )
            }
            .onFailure {
                val message = if (resultCode == Activity.RESULT_OK) {
                    friendlyGoogleError(it)
                } else {
                    googleAuthorizationDidNotComplete(resultCode, it)
                }
                pending.complete(message)
            }
    }

    private fun refreshNext(
        accounts: List<Pair<AccountSlot, AccountState>>,
        index: Int,
        complete: (String?) -> Unit,
    ) {
        if (index == accounts.size) {
            complete(null)
            return
        }
        val (slot, account) = accounts[index]
        val next: (String?) -> Unit = { error ->
            if (error == null) refreshNext(accounts, index + 1, complete) else complete(error)
        }
        when (account.authentication) {
            Authentication.GOOGLE -> authorizeGoogle(slot, account.oauthEmail, next)
            Authentication.MICROSOFT -> refreshMicrosoft(slot, account, next)
            Authentication.PASSWORD -> next(null)
        }
    }

    private fun authorizeGoogle(slot: AccountSlot, email: String?, complete: (String?) -> Unit) {
        val builder = AuthorizationRequest.builder().setRequestedScopes(googleScopes)
        if (email.isNullOrBlank()) {
            builder.setPrompt(AuthorizationRequest.Prompt.SELECT_ACCOUNT)
        } else {
            builder.setAccount(Account(email, GOOGLE_ACCOUNT_TYPE))
        }
        googleClient.authorize(builder.build())
            .addOnSuccessListener { result -> continueGoogleAuthorization(slot, result, complete, 0) }
            .addOnFailureListener { complete(friendlyGoogleError(it)) }
    }

    private fun continueGoogleAuthorization(
        slot: AccountSlot,
        result: AuthorizationResult,
        complete: (String?) -> Unit,
        resolutionCount: Int,
    ) {
        if (!result.hasResolution()) {
            acceptGoogleResult(slot, result, complete)
            return
        }
        val pendingIntent = result.pendingIntent
        if (pendingIntent == null || resolutionCount >= MAX_GOOGLE_RESOLUTIONS) {
            complete("Google sign-in needs another step. Try connecting again.")
            return
        }
        pendingGoogle = GoogleRequest(slot, complete, resolutionCount + 1)
        launchGoogleAuthorization(IntentSenderRequest.Builder(pendingIntent.intentSender).build())
    }

    private fun acceptGoogleResult(slot: AccountSlot, result: AuthorizationResult, complete: (String?) -> Unit) {
        val token = result.accessToken
        if (token.isNullOrBlank()) {
            complete("Google did not return an access token")
            return
        }
        val returnedEmail = result.toGoogleSignInAccount()?.email.orEmpty()
        if (returnedEmail.isNotBlank()) {
            viewModel.updateOAuthAccount(slot, returnedEmail, returnedEmail, token)
            complete(null)
            return
        }
        activity.lifecycleScope.launch {
            val emailResult = withContext(Dispatchers.IO) {
                runCatching { GoogleProfileClient.emailAddress(token) }
            }
            emailResult
                .onSuccess { email ->
                    viewModel.updateOAuthAccount(slot, email, email, token)
                    complete(null)
                }
                .onFailure { error ->
                    if (isExpiredGoogleAuthorization(error)) viewModel.clearOAuthAccount(slot)
                    complete(googleProfileFailureMessage(error))
                }
        }
    }

    private fun revokeGoogle(
        slot: AccountSlot,
        account: AccountState,
        complete: (String?) -> Unit,
    ) {
        if (account.oauthEmail.isBlank()) {
            viewModel.clearOAuthAccount(slot)
            finish(null, complete)
            return
        }
        val request = RevokeAccessRequest.builder()
            .setScopes(googleScopes)
            .setAccount(Account(account.oauthEmail, GOOGLE_ACCOUNT_TYPE))
            .build()
        googleClient.revokeAccess(request)
            .addOnSuccessListener {
                viewModel.clearOAuthAccount(slot)
                finish(null, complete)
            }
            .addOnFailureListener { finish(friendlyGoogleError(it), complete) }
    }

    private fun refreshMicrosoft(slot: AccountSlot, saved: AccountState, complete: (String?) -> Unit) {
        withMicrosoftClient { clientResult ->
            clientResult.onSuccess { client ->
                client.getAccount(saved.oauthAccountId, object : IMultipleAccountPublicClientApplication.GetAccountCallback {
                    override fun onTaskCompleted(account: IAccount?) {
                        if (account == null) {
                            acquireMicrosoftInteractive(slot, saved.oauthEmail, complete)
                            return
                        }
                        val parameters = AcquireTokenSilentParameters.Builder()
                            .forAccount(account)
                            .fromAuthority(account.authority)
                            .withScopes(MICROSOFT_SCOPES)
                            .withCallback(object : SilentAuthenticationCallback {
                                override fun onSuccess(authenticationResult: IAuthenticationResult) {
                                    acceptMicrosoftResult(slot, authenticationResult, complete)
                                }

                                override fun onError(exception: MsalException) {
                                    if (exception is MsalUiRequiredException) {
                                        acquireMicrosoftInteractive(slot, saved.oauthEmail, complete)
                                    } else {
                                        complete(friendlyMicrosoftError(exception))
                                    }
                                }
                            })
                            .build()
                        client.acquireTokenSilentAsync(parameters)
                    }

                    override fun onError(exception: MsalException) {
                        complete(friendlyMicrosoftError(exception))
                    }
                })
            }.onFailure { complete(friendlyMicrosoftError(it)) }
        }
    }

    private fun acquireMicrosoftInteractive(slot: AccountSlot, loginHint: String, complete: (String?) -> Unit) {
        withMicrosoftClient { clientResult ->
            clientResult.onSuccess { client ->
                val builder = AcquireTokenParameters.Builder()
                    .startAuthorizationFromActivity(activity)
                    .withScopes(MICROSOFT_SCOPES)
                    .withPrompt(Prompt.SELECT_ACCOUNT)
                    .withCallback(object : AuthenticationCallback {
                        override fun onSuccess(authenticationResult: IAuthenticationResult) {
                            acceptMicrosoftResult(slot, authenticationResult, complete)
                        }

                        override fun onError(exception: MsalException) {
                            complete(friendlyMicrosoftError(exception))
                        }

                        override fun onCancel() {
                            complete("Microsoft sign-in was cancelled")
                        }
                    })
                if (loginHint.isNotBlank()) builder.withLoginHint(loginHint)
                client.acquireToken(builder.build())
            }.onFailure { complete(friendlyMicrosoftError(it)) }
        }
    }

    private fun acceptMicrosoftResult(
        slot: AccountSlot,
        result: IAuthenticationResult,
        complete: (String?) -> Unit,
    ) {
        val email = result.account.username.orEmpty()
        if (email.isBlank() || result.accessToken.isBlank()) {
            complete("Microsoft did not return an authorized email account")
            return
        }
        viewModel.updateOAuthAccount(slot, email, result.account.id, result.accessToken)
        complete(null)
    }

    private fun removeMicrosoft(
        slot: AccountSlot,
        account: AccountState,
        complete: (String?) -> Unit,
    ) {
        withMicrosoftClient { clientResult ->
            clientResult.onSuccess { client ->
                client.getAccount(account.oauthAccountId, object : IMultipleAccountPublicClientApplication.GetAccountCallback {
                    override fun onTaskCompleted(result: IAccount?) {
                        if (result == null) {
                            viewModel.clearOAuthAccount(slot)
                            finish(null, complete)
                            return
                        }
                        client.removeAccount(result, object : IMultipleAccountPublicClientApplication.RemoveAccountCallback {
                            override fun onRemoved() {
                                viewModel.clearOAuthAccount(slot)
                                finish(null, complete)
                            }

                            override fun onError(exception: MsalException) {
                                finish(friendlyMicrosoftError(exception), complete)
                            }
                        })
                    }

                    override fun onError(exception: MsalException) {
                        finish(friendlyMicrosoftError(exception), complete)
                    }
                })
            }.onFailure { finish(friendlyMicrosoftError(it), complete) }
        }
    }

    private fun withMicrosoftClient(complete: (Result<IMultipleAccountPublicClientApplication>) -> Unit) {
        microsoftClient?.let { complete(Result.success(it)); return }
        if (BuildConfig.MICROSOFT_CLIENT_ID.isBlank() || BuildConfig.MICROSOFT_REDIRECT_URI.isBlank()) {
            complete(Result.failure(IllegalStateException("Microsoft sign-in is not configured in this build")))
            return
        }
        microsoftWaiters += complete
        if (microsoftInitializing) return
        microsoftInitializing = true
        PublicClientApplication.create(
            activity.applicationContext,
            BuildConfig.MICROSOFT_CLIENT_ID,
            MICROSOFT_AUTHORITY,
            BuildConfig.MICROSOFT_REDIRECT_URI,
            object : IPublicClientApplication.ApplicationCreatedListener {
                override fun onCreated(application: IPublicClientApplication) {
                    val result = if (application is IMultipleAccountPublicClientApplication) {
                        microsoftClient = application
                        Result.success(application)
                    } else {
                        Result.failure(IllegalStateException("Microsoft multiple-account support is unavailable"))
                    }
                    completeMicrosoftInitialization(result)
                }

                override fun onError(exception: MsalException) {
                    completeMicrosoftInitialization(Result.failure(exception))
                }
            },
        )
    }

    private fun completeMicrosoftInitialization(result: Result<IMultipleAccountPublicClientApplication>) {
        microsoftInitializing = false
        val waiters = microsoftWaiters.toList()
        microsoftWaiters.clear()
        waiters.forEach { it(result) }
    }

    private fun begin(): Boolean {
        if (viewModel.authenticationBusy.value) return false
        viewModel.setAuthenticationBusy(true)
        return true
    }

    private fun finish(error: String?, complete: (String?) -> Unit) {
        viewModel.setAuthenticationBusy(false)
        complete(error)
    }

    private data class GoogleRequest(
        val slot: AccountSlot,
        val complete: (String?) -> Unit,
        val resolutionCount: Int,
    )

    companion object {
        private const val GOOGLE_IMAP_SCOPE = "https://mail.google.com/"
        private const val GOOGLE_ACCOUNT_TYPE = "com.google"
        private const val MAX_GOOGLE_RESOLUTIONS = 3
        private const val MICROSOFT_AUTHORITY = "https://login.microsoftonline.com/common"
        private val MICROSOFT_SCOPES = listOf("https://outlook.office.com/IMAP.AccessAsUser.All")

        private fun requiredAccounts(configuration: AppConfiguration): List<Pair<AccountSlot, AccountState>> = when (
            configuration.operation
        ) {
            Operation.COUNT -> when (configuration.countTarget) {
                TargetType.SOURCE_ACCOUNT -> listOf(AccountSlot.SOURCE to configuration.source)
                TargetType.DESTINATION_ACCOUNT -> listOf(AccountSlot.DESTINATION to configuration.destination)
                TargetType.LOCAL_BACKUP -> emptyList()
            }
            Operation.COMPARE -> buildList {
                when (configuration.compareSource) {
                    TargetType.SOURCE_ACCOUNT -> add(AccountSlot.SOURCE to configuration.source)
                    TargetType.DESTINATION_ACCOUNT -> add(AccountSlot.DESTINATION to configuration.destination)
                    TargetType.LOCAL_BACKUP -> Unit
                }
                when (configuration.compareDestination) {
                    TargetType.SOURCE_ACCOUNT -> add(AccountSlot.SOURCE to configuration.source)
                    TargetType.DESTINATION_ACCOUNT -> add(AccountSlot.DESTINATION to configuration.destination)
                    TargetType.LOCAL_BACKUP -> Unit
                }
            }.distinctBy { it.first }
            Operation.BACKUP -> listOf(AccountSlot.SOURCE to configuration.source)
            Operation.RESTORE -> listOf(AccountSlot.DESTINATION to configuration.destination)
            Operation.MIGRATE -> listOf(
                AccountSlot.SOURCE to configuration.source,
                AccountSlot.DESTINATION to configuration.destination,
            )
        }

        private fun friendlyGoogleError(error: Throwable): String {
            if ((error as? ApiException)?.statusCode == CommonStatusCodes.DEVELOPER_ERROR) {
                return "Google sign-in is not configured for this build. The app provider must register its " +
                    "Android package and signing certificate with Google."
            }
            return error.message?.takeIf { it.isNotBlank() }?.let { "Google sign-in failed: $it" }
                ?: "Google sign-in failed"
        }

        private fun googleAuthorizationDidNotComplete(resultCode: Int, error: Throwable? = null): String {
            if ((error as? ApiException)?.statusCode == CommonStatusCodes.DEVELOPER_ERROR) {
                return friendlyGoogleError(error)
            }
            if (resultCode != Activity.RESULT_CANCELED) {
                return error?.let(::friendlyGoogleError) ?: "Google sign-in failed"
            }
            return "Google sign-in did not complete. If you did not cancel it, the app provider must verify this " +
                "build's Android OAuth package and signing certificate registration."
        }

        private fun friendlyMicrosoftError(error: Throwable): String =
            error.message?.takeIf { it.isNotBlank() }?.let { "Microsoft sign-in failed: $it" }
                ?: "Microsoft sign-in failed"
    }
}
