package com.sudoplatform.sudosecurevault.exceptions

import com.apollographql.apollo.api.Error

open class SudoSecureVaultException(message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause) {

    companion object {
        private const val GRAPHQL_ERROR_TYPE = "errorType"
        private const val GRAPHQL_ERROR_TOKEN_NOT_AUTHORIZED_ERROR = "sudoplatform.vault.NotAuthorizedError"
        private const val GRAPHQL_ERROR_INVALID_OWNERSHIP_PROOF_ERROR = "sudoplatform.vault.InvalidOwnershipProofError"
        private const val GRAPHQL_ERROR_TOKEN_VALIDATION_ERROR = "sudoplatform.vault.TokenValidationError"
        private const val GRAPHQL_ERROR_INSUFFICIENT_ENTITLEMENTS_ERROR = "sudoplatform.InsufficientEntitlementsError"
        private const val GRAPHQL_ERROR_CONDITIONAL_CHECK_FAILED =
            "DynamoDB:ConditionalCheckFailedException"
        private const val GRAPHQL_ERROR_SERVICE_ERROR = "sudoplatform.ServiceError"

        /**
         * Convert from a GraphQL [Error] into a custom exception of type [SudoSecureVaultException]
         */
        fun Error.toSudoSecureVaultException(): SudoSecureVaultException {
            return when (this.customAttributes()[GRAPHQL_ERROR_TYPE]) {
                GRAPHQL_ERROR_TOKEN_NOT_AUTHORIZED_ERROR -> NotAuthorizedException(this.message())
                GRAPHQL_ERROR_TOKEN_VALIDATION_ERROR -> NotAuthorizedException(this.message())
                GRAPHQL_ERROR_INVALID_OWNERSHIP_PROOF_ERROR -> InvalidOwnershipProofException(this.message())
                GRAPHQL_ERROR_INSUFFICIENT_ENTITLEMENTS_ERROR -> InsufficientEntitlementsException(this.message())
                GRAPHQL_ERROR_CONDITIONAL_CHECK_FAILED -> VersionMismatchException(this.message())
                GRAPHQL_ERROR_SERVICE_ERROR -> InternalServerException(this.message())
                else -> GraphQLException(this.message())
            }
        }
    }

    /**
     * Indicates invalid ownership proof was provided when creating a vault.
     */
    class InvalidOwnershipProofException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

    /**
     * Indicates that invalid input was provided to the API call.
     */
    class InvalidInputException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

    /**
     * Indicates that the user is not authorized to perform the requested operation.
     */
    class NotAuthorizedException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

    /**
     * Indicates the user is not registered but requested an operation that requires registration.
     */
    class NotRegisteredException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

    /**
     * Indicates the user is already registered.
     */
    class AlreadyRegisteredException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

    /**
     * Indicates the user is not signed in but requested an operation that requires authentication.
     */
    class NotSignedInException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

    /**
     * Indicates the user does not have sufficient entitlements to perform the requested operation.
     */
    class InsufficientEntitlementsException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

    /**
     * The version of the vault that's being updated does not match the version
     * stored in the backed. It is likely that another client updated the vault
     * first so the caller should reconcile the changes before attempting to
     * update the vault.
     */
    class VersionMismatchException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

    /**
     * Indicates that an internal server error caused the operation to fail. The error is
     * possibly transient and retrying at a later time may cause the operation to complete
     * successfully.
     */
    class InternalServerException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

    /**
     * Indicates that GraphQL API returned an error that is not recognized by the client.
     */
    class GraphQLException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

    /**
     * Indicates that an unexpected error occurred. This could be due to coding error, out-of-
     * memory conditions or other conditions that is beyond control of the client.
     *
     */
    class FailedException(message: String? = null, cause: Throwable? = null) :
        SudoSecureVaultException(message = message, cause = cause)

}