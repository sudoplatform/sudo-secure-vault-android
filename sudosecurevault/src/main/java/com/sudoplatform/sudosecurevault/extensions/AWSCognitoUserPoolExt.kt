package com.sudoplatform.sudosecurevault.extensions

import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUser
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserAttributes
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserPool
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.SignUpHandler
import com.amazonaws.services.cognitoidentityprovider.model.SignUpResult
import com.sudoplatform.sudosecurevault.CognitoUserPoolIdentityProvider
import com.sudoplatform.sudosecurevault.exceptions.SudoSecureVaultException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

internal suspend fun CognitoUserPool.signUp(
    uid: String,
    password: String,
    cognitoAttributes: CognitoUserAttributes,
    parameters: Map<String, String>
) = suspendCoroutine<String> { cont ->

    signUp(uid, password, cognitoAttributes, parameters,
        object : SignUpHandler {

            override fun onSuccess(
                user: CognitoUser?,
                signUpResult: SignUpResult
            ) {
                if (user?.userId != null) {
                    if (signUpResult.isUserConfirmed) {
                        cont.resume(user.userId)
                    } else {
                        cont.resumeWithException(
                            SudoSecureVaultException.FailedException(
                                "Identity was created but is not confirmed."
                            )
                        )
                    }
                } else {
                    cont.resumeWithException(SudoSecureVaultException.FailedException("Sign up succeeded but not user ID was returned."))
                }
            }

            override fun onFailure(exception: Exception?) {
                if (exception != null) {
                    val message = exception.message
                    if (message != null) {
                        if (message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_SERVICE_ERROR)) {
                            cont.resumeWithException(SudoSecureVaultException.InternalServerException(message))
                        } else if (message.contains(CognitoUserPoolIdentityProvider.SERVICE_ERROR_DECODING_ERROR)) {
                            cont.resumeWithException(SudoSecureVaultException.InvalidInputException(message))
                        }
                    } else {
                        cont.resumeWithException(SudoSecureVaultException.FailedException(cause = exception))
                    }
                } else {
                    cont.resumeWithException(SudoSecureVaultException.FailedException("Expected failure detail not found."))
                }
            }

        }
    )
}
