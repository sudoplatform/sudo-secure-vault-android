/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudosecurevault

import android.content.Context
import com.amazonaws.ClientConfiguration
import com.amazonaws.auth.AnonymousAWSCredentials
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserAttributes
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserPool
import com.amazonaws.regions.Region
import com.amazonaws.regions.Regions
import com.amazonaws.services.cognitoidentityprovider.AmazonCognitoIdentityProviderClient
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudosecurevault.exceptions.*
import com.sudoplatform.sudosecurevault.extensions.changePassword
import com.sudoplatform.sudosecurevault.extensions.signUp
import com.sudoplatform.sudosecurevault.extensions.getSession
import org.json.JSONObject

/**
 * Encapsulates the authentication tokens obtained from a successful authentication.
 *
 * @param idToken ID token containing the user's identity attributes.
 */
data class AuthenticationTokens(
    val idToken: String
)

/**
 * Encapsulates interface requirements for an external identity provider to register and authenticate an identity
 * within Sudo platform ecosystem.
 */
interface IdentityProvider {

    /**
     * Registers a new user against the identity provider.
     *
     * @param uid user ID.
     * @param password password.
     * @param token ID token from Identity service.
     * @param authenticationSalt Authentication salt.
     * @param encryptionSalt Encryption salt.
     * @param pbkdfRounds PBKDF rounds.
     * @return user ID
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun register(
        uid: String,
        password: String,
        token: String,
        authenticationSalt: String,
        encryptionSalt: String,
        pbkdfRounds: Int
    ): String

    /**
     * Sign into the identity provider.
     *
     * @param uid user ID.
     * @param password password.
     * @returns successful authentication result [AuthenticationTokens]
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun signIn(
        uid: String,
        password: String
    ): AuthenticationTokens

    /**
     * Changes the user's password.
     *
     * @param uid user ID.
     * @param oldPassword old password.
     * @param newPassword old password.
     * @returns user ID when the password change was successfully.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun changePassword(
        uid: String,
        oldPassword: String,
        newPassword: String
    ): String
}

/**
 * Identity provider implementation that uses AWS Cognito User Pool.
 */
internal class CognitoUserPoolIdentityProvider(
    config: JSONObject,
    context: Context,
    private val logger: Logger = DefaultLogger.instance
) : IdentityProvider {

    companion object {
        private const val CONFIG_REGION = "region"
        private const val CONFIG_POOL_ID = "poolId"
        private const val CONFIG_CLIENT_ID = "clientId"

        private const val REGISTRATION_PARAMETER_ID_TOKEN = "idToken"
        private const val REGISTRATION_PARAMETER_AUTHENTICATION_SALT = "authenticationSalt"
        private const val REGISTRATION_PARAMETER_ENCRYPTION_SALT = "encryptionSalt"
        private const val REGISTRATION_PARAMETER_PBKDF_ROUNDS = "pbkdfRounds"

        const val SERVICE_ERROR_SERVICE_ERROR = "sudoplatform.ServiceError"
        const val SERVICE_ERROR_DECODING_ERROR = "sudoplatform.vault.DecodingError"
    }

    /**
     * Cognito user pool used for authentication and registration.
     */
    private var userPool: CognitoUserPool

    /**
     * Cognito identity provider used for custom authentication flow.
     */
    private var idpClient: AmazonCognitoIdentityProviderClient

    init {
        val region = config[CONFIG_REGION] as String?
        val poolId = config[CONFIG_POOL_ID] as String?
        val clientId = config[CONFIG_CLIENT_ID] as String?

        require(region != null) { "region is missing from config."}
        require(poolId != null) { "poolId is missing from config."}
        require(clientId != null) { "clientId is missing from config."}

        this.userPool = CognitoUserPool(
            context,
            poolId,
            clientId,
            null,
            Regions.fromName(region)
        )

        this.idpClient =
            AmazonCognitoIdentityProviderClient(AnonymousAWSCredentials(), ClientConfiguration())
        this.idpClient.setRegion(Region.getRegion(region))
    }

    override suspend fun register(
        uid: String,
        password: String,
        token: String,
        authenticationSalt: String,
        encryptionSalt: String,
        pbkdfRounds: Int
    ): String {
        this.logger.info("Registering uid: $uid.")

        val cognitoAttributes = CognitoUserAttributes()

        val parameters: Map<String, String> = mapOf(
            REGISTRATION_PARAMETER_ID_TOKEN to token,
            REGISTRATION_PARAMETER_AUTHENTICATION_SALT to authenticationSalt,
            REGISTRATION_PARAMETER_ENCRYPTION_SALT to encryptionSalt,
            REGISTRATION_PARAMETER_PBKDF_ROUNDS to "$pbkdfRounds"
        )

        return userPool.signUp(uid, password, cognitoAttributes, parameters)
    }

    override suspend fun signIn(
        uid: String,
        password: String
    ): AuthenticationTokens {
        this.logger.info("Signing in uid: $uid.")

        val user = this.userPool.getUser(uid)
        val tokens = user.getSession(uid, password)

        // Clear any cached session state.
        user.signOut()

        return tokens
    }

    override suspend fun changePassword(
        uid: String,
        oldPassword: String,
        newPassword: String
    ): String {
        val user = this.userPool.getUser(uid)
        user.getSession(uid, oldPassword)

        user.changePassword(uid, oldPassword, newPassword)

        // Clear any cached session state.
        user.signOut()

        return uid
    }

}


