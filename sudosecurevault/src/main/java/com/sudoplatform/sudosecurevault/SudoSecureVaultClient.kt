/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudosecurevault

import android.content.Context
import android.util.Base64
import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.amazonaws.mobileconnectors.appsync.fetcher.AppSyncResponseFetchers
import com.amazonaws.regions.Regions
import com.babylon.certificatetransparency.certificateTransparencyInterceptor
import com.sudoplatform.sudoconfigmanager.DefaultSudoConfigManager
import com.sudoplatform.sudokeymanager.KeyManagerFactory
import com.sudoplatform.sudokeymanager.KeyManagerInterface
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudosecurevault.exceptions.SudoSecureVaultException
import com.sudoplatform.sudosecurevault.exceptions.SudoSecureVaultException.Companion.toSudoSecureVaultException
import com.sudoplatform.sudosecurevault.extensions.xor
import com.sudoplatform.sudouser.ConvertSslErrorsInterceptor
import com.sudoplatform.sudouser.GraphQLAuthProvider
import com.sudoplatform.sudouser.SudoUserClient
import com.sudoplatform.sudosecurevault.extensions.enqueue
import com.sudoplatform.sudosecurevault.type.CreateVaultInput
import com.sudoplatform.sudosecurevault.type.DeleteVaultInput
import com.sudoplatform.sudosecurevault.type.UpdateVaultInput
import okhttp3.OkHttpClient
import org.json.JSONObject
import java.util.Date

/**
 * Supported symmetric key algorithms.
 */
enum class SymmetricKeyEncryptionAlgorithm(private val stringValue: String) {
    AES_CBC_PKCS7PADDING("AES/CBC/PKCS7Padding");

    override fun toString(): String {
        when (this) {
            AES_CBC_PKCS7PADDING -> return this.stringValue
        }
    }

}

/**
 * Data required to initialize the client.
 */
data class InitializationData(
    val owner: String,
    val authenticationSalt: ByteArray,
    val encryptionSalt: ByteArray,
    val pbkdfRounds: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as InitializationData

        if (owner != other.owner) return false
        if (!authenticationSalt.contentEquals(other.authenticationSalt)) return false
        if (!encryptionSalt.contentEquals(other.encryptionSalt)) return false
        if (pbkdfRounds != other.pbkdfRounds) return false

        return true
    }

    override fun hashCode(): Int {
        var result = owner.hashCode()
        result = 31 * result + authenticationSalt.contentHashCode()
        result = 31 * result + encryptionSalt.contentHashCode()
        result = 31 * result + pbkdfRounds
        return result
    }
}

/**
 * Vault owner.
 */
data class Owner(
    /**
     * Owner ID.
     */
    val id: String,

    /**
     * Issuer.
     */
    val issuer: String
)

/**
 * Vault metadata.
 */
interface Metadata {
    /**
     * Unique ID.
     */
    val id: String

    /**
     * Vault owner (User).
     */
    val owner: String

    /**
     * Object version.
     */
    val version: Int

    /**
     * Blob format specifier.
     */
    val blobFormat: String

    /**
     * Date/time at which the vault was created.
     */
    val createdAt: Date

    /**
     * Date/time at which the vault was last modified.
     */
    val updatedAt: Date

    /**
     * List of vault owners.
     */
    val owners: List<Owner>
}

data class VaultMetadata(
    override val id: String,
    override val owner: String,
    override val version: Int,
    override val blobFormat: String,
    override val createdAt: Date,
    override val updatedAt: Date,
    override val owners: List<Owner>
) : Metadata

/**
 * Vault.
 */
data class Vault(
    override val id: String,
    override val owner: String,
    override val version: Int,
    override val blobFormat: String,
    override val createdAt: Date,
    override val updatedAt: Date,
    override val owners: List<Owner>,

    /**
     * Blob stored securely in the vault.
     */
    var blob: ByteArray
) : Metadata {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Vault

        if (id != other.id) return false
        if (owner != other.owner) return false
        if (version != other.version) return false
        if (blobFormat != other.blobFormat) return false
        if (createdAt != other.createdAt) return false
        if (updatedAt != other.updatedAt) return false
        if (owners != other.owners) return false
        if (!blob.contentEquals(other.blob)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + owner.hashCode()
        result = 31 * result + version
        result = 31 * result + blobFormat.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + updatedAt.hashCode()
        result = 31 * result + owners.hashCode()
        result = 31 * result + blob.contentHashCode()
        return result
    }
}

/**
 * Interface encapsulating a library of functions for calling Sudo Platform Secure Vault service, managing keys, performing
 * cryptographic operations.
 */
interface SudoSecureVaultClient {

    companion object {

        /**
         * Creates a [Builder] for [SudoSecureVaultClient].
         */
        fun builder(context: Context, sudoUserClient: SudoUserClient) =
            Builder(context, sudoUserClient)

    }

    /**
     * Builder used to construct [SudoSecureVaultClient].
     *
     * @param context app context.
     * @param sudoUserClient [SudoUserClient] instance to used for authenticating to Sudo Platform.
     */
    class Builder(private val context: Context, private val sudoUserClient: SudoUserClient) {
        private var apiClient: AWSAppSyncClient? = null
        private var logger: Logger? = null
        private var config: JSONObject? = null
        private var keyManager: KeyManagerInterface? = null
        private var identityProvider: IdentityProvider? = null

        /**
         * Provide an [AWSAppSyncClient] for the [SudoSecureVaultClient]. If this is not supplied,
         * a default [AWSAppSyncClient] will be used. This is mainly used for unit testing.
         */
        fun setApiClient(apiClient: AWSAppSyncClient) = also {
            this.apiClient = apiClient
        }

        /**
         * Provide the implementation of the [Logger] used for logging. If a value is not supplied
         * a default implementation will be used.
         */
        fun setLogger(logger: Logger) = also {
            this.logger = logger
        }

        /**
         * Provide the configuration parameters.
         */
        fun setConfig(config: JSONObject) = also {
            this.config = config
        }

        /**
         * Provide custom [KeyManagerInterface] implementation. This is mainly used for unit testing (optional).
         */
        fun setKeyManager(keyManager: KeyManagerInterface) = also {
            this.keyManager = keyManager
        }

        /**
         * Provide a custom identity provider. This is mainly used for unit testing (optional).
         */
        fun setIdentityProvider(identityProvider: IdentityProvider) = also {
            this.identityProvider = identityProvider
        }

        /**
         * Constructs and returns an [SudoSecureVaultClient].
         *
         */
        fun build(): SudoSecureVaultClient {
            return DefaultSudoSecureVaultClient(
                this.context,
                this.sudoUserClient,
                this.logger ?: DefaultLogger.instance,
                this.config,
                this.keyManager,
                this.identityProvider,
                this.apiClient
            )
        }
    }

    /**
     * Checksum's for each file are generated and are used to create a checksum that is used when publishing to maven central.
     * In order to retry a failed publish without needing to change any functionality, we need a way to generate a different checksum
     * for the source code.  We can change the value of this property which will generate a different checksum for publishing
     * and allow us to retry.  The value of `version` doesn't need to be kept up-to-date with the version of the code.
     */
    val version: String

    /**
     * Registers a new user with Secure Vault service.
     *
     * @param key key deriving key. The key size can be 128 - 256 bit.
     * @param password vault password.
     *
     * @return Username of the newly registered user.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun register(key: ByteArray, password: ByteArray): String

    /**
     * Indicates whether or not this client is registered with Sudo Platform backend.
     *
     * @return *true* if the client is registered.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun isRegistered(): Boolean

    /**
     * Returns the initialization data. If the client has a cached copy then the cached initialization data will be returned otherwise
     * it will be fetched from the backend. This is mainly used for testing and the consuming app is not expected to use this method.
     *
     * @return initialization data if one exists.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun getInitializationData(): InitializationData?

    /**
     * Creates a new vault.
     *
     * @param key key deriving key.
     * @param password vault password.
     * @param blob blob to encrypt and store.
     * @param blobFormat specifier for the format/structure of information represented in the blob.
     * @param ownershipProof ownership proof of the Sudo to be associate with the vault. The ownership proof
     *                       must contain audience of "sudoplatform.secure-vault.vault".
     *
     * @return newly created vault's metadata.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun createVault(
        key: ByteArray,
        password: ByteArray,
        blob: ByteArray,
        blobFormat: String,
        ownershipProof: String
    ): VaultMetadata

    /**
     * Updates an existing vault.
     *
     * @param key key deriving key.
     * @param password vault password.
     * @param id ID of the vault to update.
     * @param version version of the vault that the update is being applied to.
     * @param blob blob to encrypt and store.
     * @param blobFormat specifier for the format/structure of information represented in the blob.
     *
     * @return updated vault's metadata.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun updateVault(
        key: ByteArray,
        password: ByteArray,
        id: String,
        version: Int,
        blob: ByteArray,
        blobFormat: String
    ): VaultMetadata

    /**
     * Deletes an existing vault.
     *
     * @param id ID of the vault to delete.
     *
     * @return deleted vault's metadata.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun deleteVault(id: String): VaultMetadata?

    /**
     * Retrieve a single vault matching the specified ID.
     *
     * @param key key deriving key.
     * @param password vault password.
     * @param id ID of the vault to retrieve.
     *
     * @return retrieved vault.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun getVault(
        key: ByteArray,
        password: ByteArray,
        id: String
    ): Vault?

    /**
     * Retrieves all vaults owned by the authenticated user.
     *
     * @param key key deriving key.
     * @param password vault password.
     *
     * @return list containing the vaults retrieved.
     *
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun listVaults(key: ByteArray, password: ByteArray): List<Vault>

    /**
     * Retrieves metadata for all vaults. This can be used to determine if any vault was
     * updated without requiring the extra authentication and decryption.
     *
     * @return list containing the metadata of vaults retrieved.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun listVaultsMetadataOnly(): List<VaultMetadata>

    /**
     * Changes the vault password. Existing vaults will be downloaded, re-encrypted and
     * uploaded so this API may take some time to complete.
     *
     * @param key key deriving key.
     * @param oldPassword old vault password.
     * @param newPassword new vault password.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun changeVaultPassword(
        key: ByteArray,
        oldPassword: ByteArray,
        newPassword: ByteArray
    )

    /**
     * Resets the client state and remove any cached data.
     */
    fun reset()

    /**
     * De-registers a user.
     */
    @Throws(SudoSecureVaultException::class)
    suspend fun deregister()

}

/**
 * Default implementation of [SudoSecureVaultClient] interface.
 *
 * @param context Android app context.
 * @param sudoUserClient [SudoUserClient] instance authenticating to Sudo Platform.
 * @param logger logger to use for logging messages.
 * @param config configuration parameters.
 * @param keyManager custom [KeyManagerInterface] implementation. Mainly used for unit testing (optional)
 * @param identityProvider custom identity provider. Mainly used for unit testing (optional).
 * @param apiClient custom API client. Mainly used for unit testing (optional).
 */
class DefaultSudoSecureVaultClient(
    private val context: Context,
    private val sudoUserClient: SudoUserClient,
    private val logger: Logger = DefaultLogger.instance,
    config: JSONObject? = null,
    keyManager: KeyManagerInterface? = null,
    identityProvider: IdentityProvider? = null,
    apiClient: AWSAppSyncClient? = null
) : SudoSecureVaultClient {

    companion object {
        private const val CONFIG_NAMESPACE_SECURE_VAULT_SERVICE = "secureVaultService"

        private const val CONFIG_REGION = "region"
        private const val CONFIG_API_URL = "apiUrl"
        private const val CONFIG_PBKDF_ROUNDS = "pbkdfRounds"

        private const val PBKDF_SALT_SIZE = 32
        private const val AES_BLOCK_SIZE = 16

        private const val DEFAULT_KEY_NAMESPACE = "svs"
    }

    override val version: String = "1.0.0"

    /**
     * [KeyManagerInterface] instance needed for cryptographic operations.
     */
    private val keyManager: KeyManagerInterface

    /**
     * Identity provider to use for registration and authentication.
     */
    private val identityProvider: IdentityProvider

    /**
     * AWS region hosting Secure Vault service.
     */
    private val region: String

    /**
     * API URL to Secure Vault Service.
     */
    private val apiUrl: String

    /**
     * Default PBKDF rounds to use for key derivation
     */
    private val pbkdfRounds: Int

    /**
     * GraphQL client used for calling Secure Vault service API.
     */
    private val apiClient: AWSAppSyncClient

    /**
     * Client initialization data.
     */
    private var initializationData: InitializationData? = null

    init {
        val configManager = DefaultSudoConfigManager(context)

        @Suppress("UNCHECKED_CAST")
        val secureVaultServiceConfig =
            config?.opt(CONFIG_NAMESPACE_SECURE_VAULT_SERVICE) as JSONObject?
                ?: configManager.getConfigSet(CONFIG_NAMESPACE_SECURE_VAULT_SERVICE)

        require(secureVaultServiceConfig != null) { "Client configuration not found." }

        this.logger.info("Initializing the client using config: $secureVaultServiceConfig")

        this.keyManager = keyManager ?: KeyManagerFactory(context).createAndroidKeyManager(DEFAULT_KEY_NAMESPACE)
        this.identityProvider = identityProvider ?: CognitoUserPoolIdentityProvider(
            secureVaultServiceConfig,
            context,
            this.logger
        )

        val apiUrl = secureVaultServiceConfig[CONFIG_API_URL] as String?
        val region = secureVaultServiceConfig[CONFIG_REGION] as String?
        val pbkdfRounds = secureVaultServiceConfig[CONFIG_PBKDF_ROUNDS] as Int?

        require(region != null) { "region missing from config." }
        require(apiUrl != null) { "apiUrl missing from config." }
        require(pbkdfRounds != null) { "pbkdfRounds missing from config or value is not Int." }

        this.region = region
        this.apiUrl = apiUrl
        this.pbkdfRounds = pbkdfRounds

        val authProvider = GraphQLAuthProvider(this.sudoUserClient)

        this.apiClient = apiClient ?: AWSAppSyncClient.builder()
            .serverUrl(apiUrl)
            .region(Regions.fromName(region))
            .cognitoUserPoolsAuthProvider(authProvider)
            .context(this.context)
            .okHttpClient(buildOkHttpClient())
            .build()
    }

    override suspend fun register(key: ByteArray, password: ByteArray): String {
        this.logger.info("Registering a new vault user.")

        val sub = this.sudoUserClient.getSubject()
        val token = this.sudoUserClient.getIdToken()

        if (sub == null || token == null) {
            throw SudoSecureVaultException.NotSignedInException()
        }

        val authenticationSalt = this.keyManager.createRandomData(PBKDF_SALT_SIZE)
        val encryptionSalt = this.keyManager.createRandomData(PBKDF_SALT_SIZE)
        val secretBits =
            this.generateSecretKeyBytes(key, password, authenticationSalt, this.pbkdfRounds)

        val uid = this.identityProvider.register(
            sub,
            Base64.encodeToString(secretBits, Base64.NO_WRAP),
            token,
            authenticationSalt = Base64.encodeToString(authenticationSalt, Base64.NO_WRAP),
            encryptionSalt = Base64.encodeToString(encryptionSalt, Base64.NO_WRAP),
            pbkdfRounds = this.pbkdfRounds
        )

        secretBits.fill(0)

        return uid
    }

    override suspend fun isRegistered(): Boolean {
        if (this.initializationData != null) {
            return true
        }

        this.initializationData = this.getInitializationData()
        return this.initializationData != null
    }

    override suspend fun getInitializationData(): InitializationData? {
        this.logger.info("Retrieving initialization data.")

        val query = GetInitializationDataQuery.builder().build()

        val response =
            this.apiClient.query(query).responseFetcher(AppSyncResponseFetchers.NETWORK_ONLY)
                .enqueue()

        if (response.hasErrors()) {
            throw response.errors().first().toSudoSecureVaultException()
        }

        val result = response.data()?.getInitializationData
        return if (result != null) {
            val initializationData = InitializationData(
                result.owner(),
                Base64.decode(result.authenticationSalt(), Base64.NO_WRAP),
                Base64.decode(result.encryptionSalt(), Base64.NO_WRAP),
                result.pbkdfRounds()
            )
            this.initializationData = initializationData
            initializationData
        } else {
            null
        }
    }

    override suspend fun createVault(
        key: ByteArray,
        password: ByteArray,
        blob: ByteArray,
        blobFormat: String,
        ownershipProof: String
    ): VaultMetadata {
        this.logger.info("Creating a vault.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoSecureVaultException.NotSignedInException()
        }

        val sub = this.sudoUserClient.getSubject()
            ?: throw SudoSecureVaultException.FailedException("Cannot retrieve sub of signed in user.")

        if (!this.isRegistered()) {
            throw SudoSecureVaultException.NotRegisteredException()
        }

        val initializationData = this.initializationData
            ?: throw SudoSecureVaultException.NotRegisteredException()

        val authenticationSecret = this.generateSecretKeyBytes(
            key,
            password,
            initializationData.authenticationSalt,
            initializationData.pbkdfRounds
        )

        // Obtain one-time-token from Secure Vault authentication provider.
        val token = this.identityProvider.signIn(
            sub,
            Base64.encodeToString(authenticationSecret, Base64.NO_WRAP)
        )

        authenticationSecret.fill(0)

        // Encrypt the blob using the encryption key derived from the key deriving key and the password.
        val encrypted = this.encrypt(key, password, blob, initializationData.encryptionSalt, initializationData.pbkdfRounds)

        val input = CreateVaultInput.builder()
            .token(token.idToken)
            .encryptionMethod(SymmetricKeyEncryptionAlgorithm.AES_CBC_PKCS7PADDING.toString())
            .blobFormat(blobFormat)
            .blob(Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .ownershipProofs(listOf(ownershipProof))
            .build()
        val mutation = CreateVaultMutation.builder().input(input).build()

        val response = this.apiClient.mutate(mutation).enqueue()

        if (response.hasErrors()) {
            throw response.errors().first().toSudoSecureVaultException()
        }

        val result = response.data()?.createVault
            ?: throw SudoSecureVaultException.FailedException("Mutation completed successfully but result was missing.")

        return VaultMetadata(
            result.id(),
            result.owner(),
            result.version(),
            result.blobFormat(),
            Date(result.createdAtEpochMs().toLong()),
            Date(result.updatedAtEpochMs().toLong()),
            result.owners()
                .map {
                    Owner(it.id(), it.issuer())
                }
        )
    }

    override suspend fun updateVault(
        key: ByteArray,
        password: ByteArray,
        id: String,
        version: Int,
        blob: ByteArray,
        blobFormat: String
    ): VaultMetadata {
        this.logger.info("Updating a vault: $id.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoSecureVaultException.NotSignedInException()
        }

        val sub = this.sudoUserClient.getSubject()
            ?: throw SudoSecureVaultException.FailedException("Cannot retrieve sub of signed in user.")

        if (!this.isRegistered()) {
            throw SudoSecureVaultException.NotRegisteredException()
        }

        val initializationData = this.initializationData
            ?: throw SudoSecureVaultException.NotRegisteredException()

        val authenticationSecret = this.generateSecretKeyBytes(
            key,
            password,
            initializationData.authenticationSalt,
            initializationData.pbkdfRounds
        )

        // Obtain one-time-token from Secure Vault authentication provider.
        val token = this.identityProvider.signIn(
            sub,
            Base64.encodeToString(authenticationSecret, Base64.NO_WRAP)
        )

        authenticationSecret.fill(0)

        // Encrypt the blob using the encryption key derived from the key deriving key and the password.
        val encrypted = this.encrypt(key, password, blob, initializationData.encryptionSalt, initializationData.pbkdfRounds)

        val input = UpdateVaultInput.builder()
            .token(token.idToken)
            .id(id)
            .expectedVersion(version)
            .encryptionMethod(SymmetricKeyEncryptionAlgorithm.AES_CBC_PKCS7PADDING.toString())
            .blobFormat(blobFormat)
            .blob(Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .build()
        val mutation = UpdateVaultMutation.builder().input(input).build()

        val response = this.apiClient.mutate(mutation).enqueue()

        if (response.hasErrors()) {
            throw response.errors().first().toSudoSecureVaultException()
        }

        val result = response.data()?.updateVault
            ?: throw SudoSecureVaultException.FailedException("Mutation completed successfully but result was missing.")

        return VaultMetadata(
            result.id(),
            result.owner(),
            result.version(),
            result.blobFormat(),
            Date(result.createdAtEpochMs().toLong()),
            Date(result.updatedAtEpochMs().toLong()),
            result.owners()
                .map {
                    Owner(it.id(), it.issuer())
                }
        )
    }

    override suspend fun deleteVault(id: String): VaultMetadata? {
        this.logger.info("Deleting a vault: $id.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoSecureVaultException.NotSignedInException()
        }

        val input = DeleteVaultInput.builder()
            .id(id)
            .build()
        val mutation = DeleteVaultMutation.builder().input(input).build()

        val response = this.apiClient.mutate(mutation).enqueue()

        if (response.hasErrors()) {
            throw response.errors().first().toSudoSecureVaultException()
        }

        val result = response.data()?.deleteVault
            ?: return null

        return VaultMetadata(
            result.id(),
            result.owner(),
            result.version(),
            result.blobFormat(),
            Date(result.createdAtEpochMs().toLong()),
            Date(result.updatedAtEpochMs().toLong()),
            result.owners()
                .map {
                    Owner(it.id(), it.issuer())
                }
        )
    }

    override suspend fun getVault(key: ByteArray, password: ByteArray, id: String): Vault? {
        this.logger.info("Retrieving a vault: $id")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoSecureVaultException.NotSignedInException()
        }

        val sub = this.sudoUserClient.getSubject()
            ?: throw SudoSecureVaultException.FailedException("Cannot retrieve sub of signed in user.")

        if (!this.isRegistered()) {
            throw SudoSecureVaultException.NotRegisteredException()
        }

        val initializationData = this.initializationData
            ?: throw SudoSecureVaultException.NotRegisteredException()

        val authenticationSecret = this.generateSecretKeyBytes(
            key,
            password,
            initializationData.authenticationSalt,
            initializationData.pbkdfRounds
        )

        // Obtain one-time-token from Secure Vault authentication provider.
        val token = this.identityProvider.signIn(
            sub,
            Base64.encodeToString(authenticationSecret, Base64.NO_WRAP)
        )

        authenticationSecret.fill(0)

        val query = GetVaultQuery.builder().token(token.idToken).id(id).build()

        val response =
            this.apiClient.query(query).responseFetcher(AppSyncResponseFetchers.NETWORK_ONLY)
                .enqueue()

        if (response.hasErrors()) {
            throw response.errors().first().toSudoSecureVaultException()
        }

        val result = response.data()?.getVault ?: return null

        val encrypted = Base64.decode(result.blob, Base64.NO_WRAP)

        // Decrypt the vault content using the key deriving key and the password.
        val blob = this.decrypt(
            key,
            password,
            encrypted,
            initializationData.encryptionSalt,
            initializationData.pbkdfRounds
        )

        return Vault(
            result.id(),
            result.owner(),
            result.version(),
            result.blobFormat(),
            Date(result.createdAtEpochMs().toLong()),
            Date(result.updatedAtEpochMs().toLong()),
            result.owners()
                .map {
                    Owner(it.id(), it.issuer())
                },
            blob
        )
    }

    override suspend fun listVaults(key: ByteArray, password: ByteArray): List<Vault> {
        this.logger.info("Listing vaults.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoSecureVaultException.NotSignedInException()
        }

        val sub = this.sudoUserClient.getSubject()
            ?: throw SudoSecureVaultException.FailedException("Cannot retrieve sub of signed in user.")

        if (!this.isRegistered()) {
            throw SudoSecureVaultException.NotRegisteredException()
        }

        val initializationData = this.initializationData
            ?: throw SudoSecureVaultException.NotRegisteredException()

        val authenticationSecret = this.generateSecretKeyBytes(
            key,
            password,
            initializationData.authenticationSalt,
            initializationData.pbkdfRounds
        )

        // Obtain one-time-token from Secure Vault authentication provider.
        val token = this.identityProvider.signIn(
            sub,
            Base64.encodeToString(authenticationSecret, Base64.NO_WRAP)
        )

        authenticationSecret.fill(0)

        val query = ListVaultsQuery.builder().token(token.idToken).build()

        val response =
            this.apiClient.query(query).responseFetcher(AppSyncResponseFetchers.NETWORK_ONLY)
                .enqueue()

        if (response.hasErrors()) {
            throw response.errors().first().toSudoSecureVaultException()
        }

        val vaults: MutableList<Vault> = mutableListOf()

        // Iterate over vaults.
        val items = response.data()?.listVaults()?.items()
        if (items != null) {
            for (item in items) {
                val encrypted = Base64.decode(item.blob, Base64.NO_WRAP)

                // Decrypt the vault content using the key deriving key and the password.
                val blob = this.decrypt(key, password, encrypted, initializationData.encryptionSalt, initializationData.pbkdfRounds)

                val vault = Vault(
                    item.id(),
                    item.owner(),
                    item.version(),
                    item.blobFormat(),
                    Date(item.createdAtEpochMs().toLong()),
                    Date(item.updatedAtEpochMs().toLong()),
                    item.owners()
                        .map {
                            Owner(it.id(), it.issuer())
                        },
                    blob
                )
                vaults.add(vault)
            }
        }

        return vaults
    }

    override suspend fun listVaultsMetadataOnly(): List<VaultMetadata> {
        this.logger.info("Listing vaults (metadata only).")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoSecureVaultException.NotSignedInException()
        }

        val query = ListVaultsMetadataOnlyQuery.builder().build()

        val response =
            this.apiClient.query(query).responseFetcher(AppSyncResponseFetchers.NETWORK_ONLY)
                .enqueue()

        if (response.hasErrors()) {
            throw response.errors().first().toSudoSecureVaultException()
        }

        val vaults: MutableList<VaultMetadata> = mutableListOf()

        // Iterate over vaults.
        val items = response.data()?.listVaultsMetadataOnly()?.items()
        if (items != null) {
            for (item in items) {
                val vault = VaultMetadata(
                    item.id(),
                    item.owner(),
                    item.version(),
                    item.blobFormat(),
                    Date(item.createdAtEpochMs().toLong()),
                    Date(item.updatedAtEpochMs().toLong()),
                    item.owners()
                        .map {
                            Owner(it.id(), it.issuer())
                        },
                )
                vaults.add(vault)
            }
        }

        return vaults
    }

    override suspend fun changeVaultPassword(
        key: ByteArray,
        oldPassword: ByteArray,
        newPassword: ByteArray
    ) {
        this.logger.info("Changing vault password.")

        // Retrieve all vaults.
        val vaults = this.listVaults(key, oldPassword)

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoSecureVaultException.NotSignedInException()
        }

        val sub = this.sudoUserClient.getSubject()
            ?: throw SudoSecureVaultException.FailedException("Cannot retrieve sub of signed in user.")

        if (!this.isRegistered()) {
            throw SudoSecureVaultException.NotRegisteredException()
        }

        val initializationData = this.initializationData
            ?: throw SudoSecureVaultException.NotRegisteredException()

        val oldAuthenticationSecret = this.generateSecretKeyBytes(
            key,
            oldPassword,
            initializationData.authenticationSalt,
            initializationData.pbkdfRounds
        )

        val newAuthenticationSecret = this.generateSecretKeyBytes(
            key,
            newPassword,
            initializationData.authenticationSalt,
            initializationData.pbkdfRounds
        )

        // Change the vault user password.
        this.identityProvider.changePassword(sub, Base64.encodeToString(oldAuthenticationSecret, Base64.NO_WRAP), Base64.encodeToString(newAuthenticationSecret, Base64.NO_WRAP))

        for (vault in vaults) {
            this.updateVault(key, newPassword, vault.id, vault.version, vault.blob, vault.blobFormat)
        }
    }


    override fun reset() {
        this.logger.info("Resetting client.")
        this.initializationData = null
        this.apiClient.clearCaches()
    }

    override suspend fun deregister() {
        this.logger.info("Deregister the vault user.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoSecureVaultException.NotSignedInException()
        }

        val mutation = DeregisterMutation.builder().build()

        val response = this.apiClient.mutate(mutation).enqueue()

        if (response.hasErrors()) {
            throw response.errors().first().toSudoSecureVaultException()
        }

        response.data()?.deregister
            ?: throw SudoSecureVaultException.FailedException("Mutation completed successfully but result was missing.")

        this.initializationData = null
    }

    /**
     * Construct the [OkHttpClient] configured with the certificate transparency checking interceptor.
     */
    private fun buildOkHttpClient(): OkHttpClient {
        val interceptor = certificateTransparencyInterceptor {
            // Enable for AWS hosts. The document says I can use *.* for all hosts
            // but that enhancement hasn't been released yet (v0.2.0)
            +"*.amazonaws.com"
            +"*.amazon.com"

            // Enabled for testing
            +"*.badssl.com"
        }
        val okHttpClient = OkHttpClient.Builder().apply {
            // Convert exceptions from certificate transparency into http errors that stop the
            // exponential backoff retrying of [AWSAppSyncClient]
            addInterceptor(ConvertSslErrorsInterceptor())

            // Certificate transparency checking
            addNetworkInterceptor(interceptor)
        }
        return okHttpClient.build()
    }

    /**
     * Generates a secret used for authentication or encryption. The secret is generated by performing
     * PBKDF on the password and the key deriving key and XORing the results.
     *
     * @param key key deriving key.
     * @param password password.
     * @param salt random salt.
     * @param rounds PBKDF rounds to use.
     */
    private fun generateSecretKeyBytes(
        key: ByteArray,
        password: ByteArray,
        salt: ByteArray,
        rounds: Int
    ): ByteArray {
        // Stretch the key by performing 1 round of PBKDF.
        val keyBits = this.keyManager.createSymmetricKeyFromPassword(key, salt, 1)
        val passwordBits = this.keyManager.createSymmetricKeyFromPassword(password, salt, rounds)
        val xor = passwordBits.xor(keyBits)

        keyBits.fill(0)
        passwordBits.fill(0)

        return xor
    }

    /**
     * Encrypt the specified data using the key deriving key and the password.
     *
     * @param key key deriving key.
     * @param password password.
     * @param data data to encrypt.
     * @param salt salt to use for PBKDF.
     * @param rounds number of PBKDF rounds to applied to the password.
     */
    private fun encrypt(
        key: ByteArray,
        password: ByteArray,
        data: ByteArray,
        salt: ByteArray,
        rounds: Int
    ): ByteArray {
        val encryptionSecret = this.generateSecretKeyBytes(
            key,
            password,
            salt,
            rounds
        )

        val iv = this.keyManager.createRandomData(AES_BLOCK_SIZE)
        val encrypted =  this.keyManager.encryptWithSymmetricKey(encryptionSecret, data, iv) + iv

        encryptionSecret.fill(0)

        return encrypted
    }

    /**
     * Decrypt the specified data using the key deriving key and the password.
     *
     * @param key key deriving key.
     * @param password password.
     * @param data data to decrypt.
     * @param salt salt to use for PBKDF.
     * @param rounds number of PBKDF rounds to applied to the password.
     */
    private fun decrypt(
        key: ByteArray,
        password: ByteArray,
        data: ByteArray,
        salt: ByteArray,
        rounds: Int
    ): ByteArray {
        val encryptionSecret = this.generateSecretKeyBytes(
            key,
            password,
            salt,
            rounds
        )

        // Separate out IV from the ciphertext.
        val encryptedData =
            data.copyOfRange(0, data.count() - AES_BLOCK_SIZE)
        val iv = data.copyOfRange(
            data.count() - AES_BLOCK_SIZE,
            data.count()
        )

        val decrypted = keyManager.decryptWithSymmetricKey(
            encryptionSecret,
            encryptedData,
            iv,
            KeyManagerInterface.SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256
        )

        encryptionSecret.fill(0)

        return decrypted
    }

}