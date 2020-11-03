package com.sudoplatform.sudosecurevault.extensions

import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoDevice
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUser
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserSession
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.AuthenticationContinuation
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.AuthenticationDetails
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.ChallengeContinuation
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.MultiFactorAuthenticationContinuation
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.AuthenticationHandler
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.GenericHandler
import com.amazonaws.services.cognitoidentityprovider.model.NotAuthorizedException
import com.sudoplatform.sudosecurevault.AuthenticationTokens
import com.sudoplatform.sudosecurevault.exceptions.SudoSecureVaultException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine


internal suspend fun CognitoUser.getSession(uid: String, password: String) =
    suspendCoroutine<AuthenticationTokens> { cont ->

        getSession(object : AuthenticationHandler {

            override fun onSuccess(userSession: CognitoUserSession?, newDevice: CognitoDevice?) {
                if (userSession != null) {
                    cont.resume(AuthenticationTokens(userSession.idToken.jwtToken))
                } else {
                    cont.resumeWithException(SudoSecureVaultException.FailedException("Sign in completed successfully but no user session found."))
                }
            }

            override fun getAuthenticationDetails(
                authenticationContinuation: AuthenticationContinuation?,
                userId: String?
            ) {
                val authDetails =
                    AuthenticationDetails(uid, password, mapOf())
                authenticationContinuation?.setAuthenticationDetails(authDetails)
                authenticationContinuation?.continueTask()
            }

            override fun authenticationChallenge(continuation: ChallengeContinuation?) {
            }

            override fun getMFACode(continuation: MultiFactorAuthenticationContinuation?) {
            }

            override fun onFailure(exception: Exception?) {
                if (exception != null) {
                    if (exception is NotAuthorizedException) {
                        cont.resumeWithException(SudoSecureVaultException.NotAuthorizedException())
                    } else {
                        cont.resumeWithException(SudoSecureVaultException.FailedException(cause = exception))
                    }
                } else {
                    cont.resumeWithException(SudoSecureVaultException.FailedException("Expected failure detail not found."))
                }
            }
        })
    }


internal suspend fun CognitoUser.changePassword(uid: String, oldPassword: String, newPassword: String) =
    suspendCoroutine<String> { cont ->

        changePassword(oldPassword, newPassword, object : GenericHandler {

            override fun onSuccess() {
                cont.resume(uid)
            }

            override fun onFailure(exception: Exception?) {
                if (exception != null) {
                    if (exception is NotAuthorizedException) {
                        cont.resumeWithException(SudoSecureVaultException.NotAuthorizedException())
                    } else {
                        cont.resumeWithException(SudoSecureVaultException.FailedException(cause = exception))
                    }
                } else {
                    cont.resumeWithException(SudoSecureVaultException.FailedException("Expected failure detail not found."))
                }
            }
        })
    }
