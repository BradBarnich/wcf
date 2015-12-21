// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Resources;
using System.Runtime.CompilerServices;

namespace System
{
    internal partial class SR
    {
        private static ResourceManager s_resourceManager;

        private static ResourceManager ResourceManager
        {
            get
            {
                if (SR.s_resourceManager == null)
                {
                    SR.s_resourceManager = new ResourceManager(SR.ResourceType);
                }
                return SR.s_resourceManager;
            }
        }

        // This method is used to decide if we need to append the exception message parameters to the message when calling SR.Format. 
        // by default it returns false.
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool UsingResourceKeys()
        {
            return false;
        }

        internal static string GetResourceString(string resourceKey, string defaultString)
        {
            string resourceString = null;
            try { resourceString = ResourceManager.GetString(resourceKey); }
            catch (MissingManifestResourceException) { }

            if (defaultString != null && resourceKey.Equals(resourceString, StringComparison.Ordinal))
            {
                return defaultString;
            }

            return resourceString;
        }

        internal static string Format(string resourceFormat, params object[] args)
        {
            if (args != null)
            {
                if (UsingResourceKeys())
                {
                    return resourceFormat + String.Join(", ", args);
                }

                return String.Format(resourceFormat, args);
            }

            return resourceFormat;
        }
        
        internal static string GetString(string resourceFormat, params object[] args)
        {
            return SR.Format(resourceFormat, args);
        }
        
        internal static string GetString(string resourceFormat, object p1)
        {
            return SR.Format(resourceFormat, p1);
        }

        internal static string Format(string resourceFormat, object p1)
        {
            if (UsingResourceKeys())
            {
                return String.Join(", ", resourceFormat, p1);
            }

            return String.Format(resourceFormat, p1);
        }

        internal static string Format(string resourceFormat, object p1, object p2)
        {
            if (UsingResourceKeys())
            {
                return String.Join(", ", resourceFormat, p1, p2);
            }

            return String.Format(resourceFormat, p1, p2);
        }

        internal static string Format(string resourceFormat, object p1, object p2, object p3)
        {
            if (UsingResourceKeys())
            {
                return String.Join(", ", resourceFormat, p1, p2, p3);
            }
            return String.Format(resourceFormat, p1, p2, p3);
        }
    }
    
    internal static partial class SR
    {
#pragma warning disable 0414
        private const string s_resourcesName = "FxResources.System.Private.ServiceModel.SR";
#pragma warning restore 0414

#if !DEBUGRESOURCES
        internal static string NoIPEndpointsFoundForHost {
              get { return SR.GetResourceString("NoIPEndpointsFoundForHost", null); }
        }
        internal static string DnsResolveFailed {
              get { return SR.GetResourceString("DnsResolveFailed", null); }
        }
        internal static string RequiredAttributeMissing {
              get { return SR.GetResourceString("RequiredAttributeMissing", null); }
        }
        internal static string UnsupportedCryptoAlgorithm {
              get { return SR.GetResourceString("UnsupportedCryptoAlgorithm", null); }
        }
        internal static string CustomCryptoAlgorithmIsNotValidHashAlgorithm {
              get { return SR.GetResourceString("CustomCryptoAlgorithmIsNotValidHashAlgorithm", null); }
        }
        internal static string InvalidClientCredentials {
              get { return SR.GetResourceString("InvalidClientCredentials", null); }
        }
        internal static string SspiErrorOrInvalidClientCredentials {
              get { return SR.GetResourceString("SspiErrorOrInvalidClientCredentials", null); }
        }
        internal static string CustomCryptoAlgorithmIsNotValidAsymmetricSignature {
              get { return SR.GetResourceString("CustomCryptoAlgorithmIsNotValidAsymmetricSignature", null); }
        }
        internal static string TokenSerializerNotSetonFederationProvider {
              get { return SR.GetResourceString("TokenSerializerNotSetonFederationProvider", null); }
        }
        internal static string IssuerBindingNotPresentInTokenRequirement {
              get { return SR.GetResourceString("IssuerBindingNotPresentInTokenRequirement", null); }
        }
        internal static string IssuerChannelBehaviorsCannotContainSecurityCredentialsManager {
              get { return SR.GetResourceString("IssuerChannelBehaviorsCannotContainSecurityCredentialsManager", null); }
        }
        internal static string ServiceBusyCountTrace {
              get { return SR.GetResourceString("ServiceBusyCountTrace", null); }
        }
        internal static string SecurityTokenManagerCannotCreateProviderForRequirement {
              get { return SR.GetResourceString("SecurityTokenManagerCannotCreateProviderForRequirement", null); }
        }
        internal static string SecurityTokenManagerCannotCreateAuthenticatorForRequirement {
              get { return SR.GetResourceString("SecurityTokenManagerCannotCreateAuthenticatorForRequirement", null); }
        }
        internal static string FailedSignatureVerification {
              get { return SR.GetResourceString("FailedSignatureVerification", null); }
        }
        internal static string SecurityTokenManagerCannotCreateSerializerForVersion {
              get { return SR.GetResourceString("SecurityTokenManagerCannotCreateSerializerForVersion", null); }
        }
        internal static string SupportingSignatureIsNotDerivedFrom {
              get { return SR.GetResourceString("SupportingSignatureIsNotDerivedFrom", null); }
        }
        internal static string PrimarySignatureWasNotSignedByDerivedKey {
              get { return SR.GetResourceString("PrimarySignatureWasNotSignedByDerivedKey", null); }
        }
        internal static string PrimarySignatureWasNotSignedByDerivedWrappedKey {
              get { return SR.GetResourceString("PrimarySignatureWasNotSignedByDerivedWrappedKey", null); }
        }
        internal static string MessageWasNotEncryptedByDerivedWrappedKey {
              get { return SR.GetResourceString("MessageWasNotEncryptedByDerivedWrappedKey", null); }
        }
        internal static string SecurityStateEncoderDecodingFailure {
              get { return SR.GetResourceString("SecurityStateEncoderDecodingFailure", null); }
        }
        internal static string SecurityStateEncoderEncodingFailure {
              get { return SR.GetResourceString("SecurityStateEncoderEncodingFailure", null); }
        }
        internal static string MessageWasNotEncryptedByDerivedEncryptionToken {
              get { return SR.GetResourceString("MessageWasNotEncryptedByDerivedEncryptionToken", null); }
        }
        internal static string TokenAuthenticatorRequiresSecurityBindingElement {
              get { return SR.GetResourceString("TokenAuthenticatorRequiresSecurityBindingElement", null); }
        }
        internal static string TokenProviderRequiresSecurityBindingElement {
              get { return SR.GetResourceString("TokenProviderRequiresSecurityBindingElement", null); }
        }
        internal static string UnexpectedSecuritySessionCloseResponse {
              get { return SR.GetResourceString("UnexpectedSecuritySessionCloseResponse", null); }
        }
        internal static string UnexpectedSecuritySessionClose {
              get { return SR.GetResourceString("UnexpectedSecuritySessionClose", null); }
        }
        internal static string CannotObtainSslConnectionInfo {
              get { return SR.GetResourceString("CannotObtainSslConnectionInfo", null); }
        }
        internal static string HeaderEncryptionNotSupportedInWsSecurityJan2004 {
              get { return SR.GetResourceString("HeaderEncryptionNotSupportedInWsSecurityJan2004", null); }
        }
        internal static string EncryptedHeaderNotSigned {
              get { return SR.GetResourceString("EncryptedHeaderNotSigned", null); }
        }
        internal static string EncodingBindingElementDoesNotHandleReaderQuotas {
              get { return SR.GetResourceString("EncodingBindingElementDoesNotHandleReaderQuotas", null); }
        }
        internal static string HeaderDecryptionNotSupportedInWsSecurityJan2004 {
              get { return SR.GetResourceString("HeaderDecryptionNotSupportedInWsSecurityJan2004", null); }
        }
        internal static string DecryptionFailed {
              get { return SR.GetResourceString("DecryptionFailed", null); }
        }
        internal static string AuthenticationManagerShouldNotReturnNull {
              get { return SR.GetResourceString("AuthenticationManagerShouldNotReturnNull", null); }
        }
        internal static string ErrorSerializingSecurityToken {
              get { return SR.GetResourceString("ErrorSerializingSecurityToken", null); }
        }
        internal static string ErrorDeserializingKeyIdentifierClauseFromTokenXml {
              get { return SR.GetResourceString("ErrorDeserializingKeyIdentifierClauseFromTokenXml", null); }
        }
        internal static string ErrorDeserializingTokenXml {
              get { return SR.GetResourceString("ErrorDeserializingTokenXml", null); }
        }
        internal static string TokenRequirementDoesNotSpecifyTargetAddress {
              get { return SR.GetResourceString("TokenRequirementDoesNotSpecifyTargetAddress", null); }
        }
        internal static string DerivedKeyNotInitialized {
              get { return SR.GetResourceString("DerivedKeyNotInitialized", null); }
        }
        internal static string IssuedKeySizeNotCompatibleWithAlgorithmSuite {
              get { return SR.GetResourceString("IssuedKeySizeNotCompatibleWithAlgorithmSuite", null); }
        }
        internal static string IssuedTokenAuthenticationModeRequiresSymmetricIssuedKey {
              get { return SR.GetResourceString("IssuedTokenAuthenticationModeRequiresSymmetricIssuedKey", null); }
        }
        internal static string InvalidBearerKeyUsage {
              get { return SR.GetResourceString("InvalidBearerKeyUsage", null); }
        }
        internal static string MultipleIssuerEndpointsFound {
              get { return SR.GetResourceString("MultipleIssuerEndpointsFound", null); }
        }
        internal static string MultipleAuthenticationManagersInServiceBindingParameters {
              get { return SR.GetResourceString("MultipleAuthenticationManagersInServiceBindingParameters", null); }
        }
        internal static string MultipleAuthenticationSchemesInServiceBindingParameters {
              get { return SR.GetResourceString("MultipleAuthenticationSchemesInServiceBindingParameters", null); }
        }
        internal static string NoSecurityBindingElementFound {
              get { return SR.GetResourceString("NoSecurityBindingElementFound", null); }
        }
        internal static string MultipleSecurityCredentialsManagersInServiceBindingParameters {
              get { return SR.GetResourceString("MultipleSecurityCredentialsManagersInServiceBindingParameters", null); }
        }
        internal static string MultipleSecurityCredentialsManagersInChannelBindingParameters {
              get { return SR.GetResourceString("MultipleSecurityCredentialsManagersInChannelBindingParameters", null); }
        }
        internal static string NoClientCertificate {
              get { return SR.GetResourceString("NoClientCertificate", null); }
        }
        internal static string SecurityTokenParametersHasIncompatibleInclusionMode {
              get { return SR.GetResourceString("SecurityTokenParametersHasIncompatibleInclusionMode", null); }
        }
        internal static string CannotCreateTwoWayListenerForNegotiation {
              get { return SR.GetResourceString("CannotCreateTwoWayListenerForNegotiation", null); }
        }
        internal static string NegotiationQuotasExceededFaultReason {
              get { return SR.GetResourceString("NegotiationQuotasExceededFaultReason", null); }
        }
        internal static string PendingSessionsExceededFaultReason {
              get { return SR.GetResourceString("PendingSessionsExceededFaultReason", null); }
        }
        internal static string RequestSecurityTokenDoesNotMatchEndpointFilters {
              get { return SR.GetResourceString("RequestSecurityTokenDoesNotMatchEndpointFilters", null); }
        }
        internal static string SecuritySessionRequiresIssuanceAuthenticator {
              get { return SR.GetResourceString("SecuritySessionRequiresIssuanceAuthenticator", null); }
        }
        internal static string SecuritySessionRequiresSecurityContextTokenCache {
              get { return SR.GetResourceString("SecuritySessionRequiresSecurityContextTokenCache", null); }
        }
        internal static string SessionTokenIsNotSecurityContextToken {
              get { return SR.GetResourceString("SessionTokenIsNotSecurityContextToken", null); }
        }
        internal static string SessionTokenIsNotGenericXmlToken {
              get { return SR.GetResourceString("SessionTokenIsNotGenericXmlToken", null); }
        }
        internal static string SecurityStandardsManagerNotSet {
              get { return SR.GetResourceString("SecurityStandardsManagerNotSet", null); }
        }
        internal static string SecurityNegotiationMessageTooLarge {
              get { return SR.GetResourceString("SecurityNegotiationMessageTooLarge", null); }
        }
        internal static string PreviousChannelDemuxerOpenFailed {
              get { return SR.GetResourceString("PreviousChannelDemuxerOpenFailed", null); }
        }
        internal static string SecurityChannelListenerNotSet {
              get { return SR.GetResourceString("SecurityChannelListenerNotSet", null); }
        }
        internal static string SecurityChannelListenerChannelExtendedProtectionNotSupported {
              get { return SR.GetResourceString("SecurityChannelListenerChannelExtendedProtectionNotSupported", null); }
        }
        internal static string SecurityChannelBindingMissing {
              get { return SR.GetResourceString("SecurityChannelBindingMissing", null); }
        }
        internal static string SecuritySettingsLifetimeManagerNotSet {
              get { return SR.GetResourceString("SecuritySettingsLifetimeManagerNotSet", null); }
        }
        internal static string SecurityListenerClosing {
              get { return SR.GetResourceString("SecurityListenerClosing", null); }
        }
        internal static string SecurityListenerClosingFaultReason {
              get { return SR.GetResourceString("SecurityListenerClosingFaultReason", null); }
        }
        internal static string SslCipherKeyTooSmall {
              get { return SR.GetResourceString("SslCipherKeyTooSmall", null); }
        }
        internal static string DerivedKeyTokenNonceTooLong {
              get { return SR.GetResourceString("DerivedKeyTokenNonceTooLong", null); }
        }
        internal static string DerivedKeyTokenLabelTooLong {
              get { return SR.GetResourceString("DerivedKeyTokenLabelTooLong", null); }
        }
        internal static string DerivedKeyTokenOffsetTooHigh {
              get { return SR.GetResourceString("DerivedKeyTokenOffsetTooHigh", null); }
        }
        internal static string DerivedKeyTokenGenerationAndLengthTooHigh {
              get { return SR.GetResourceString("DerivedKeyTokenGenerationAndLengthTooHigh", null); }
        }
        internal static string DerivedKeyLimitExceeded {
              get { return SR.GetResourceString("DerivedKeyLimitExceeded", null); }
        }
        internal static string WrappedKeyLimitExceeded {
              get { return SR.GetResourceString("WrappedKeyLimitExceeded", null); }
        }
        internal static string BufferQuotaExceededReadingBase64 {
              get { return SR.GetResourceString("BufferQuotaExceededReadingBase64", null); }
        }
        internal static string MessageSecurityDoesNotWorkWithManualAddressing {
              get { return SR.GetResourceString("MessageSecurityDoesNotWorkWithManualAddressing", null); }
        }
        internal static string TargetAddressIsNotSet {
              get { return SR.GetResourceString("TargetAddressIsNotSet", null); }
        }
        internal static string IssuedTokenCacheNotSet {
              get { return SR.GetResourceString("IssuedTokenCacheNotSet", null); }
        }
        internal static string SecurityAlgorithmSuiteNotSet {
              get { return SR.GetResourceString("SecurityAlgorithmSuiteNotSet", null); }
        }
        internal static string SecurityTokenFoundOutsideSecurityHeader {
              get { return SR.GetResourceString("SecurityTokenFoundOutsideSecurityHeader", null); }
        }
        internal static string SecurityTokenNotResolved {
              get { return SR.GetResourceString("SecurityTokenNotResolved", null); }
        }
        internal static string SecureConversationCancelNotAllowedFaultReason {
              get { return SR.GetResourceString("SecureConversationCancelNotAllowedFaultReason", null); }
        }
        internal static string BootstrapSecurityBindingElementNotSet {
              get { return SR.GetResourceString("BootstrapSecurityBindingElementNotSet", null); }
        }
        internal static string IssuerBuildContextNotSet {
              get { return SR.GetResourceString("IssuerBuildContextNotSet", null); }
        }
        internal static string StsBindingNotSet {
              get { return SR.GetResourceString("StsBindingNotSet", null); }
        }
        internal static string SslCertMayNotDoKeyExchange {
              get { return SR.GetResourceString("SslCertMayNotDoKeyExchange", null); }
        }
        internal static string SslCertMustHavePrivateKey {
              get { return SR.GetResourceString("SslCertMustHavePrivateKey", null); }
        }
        internal static string NoOutgoingEndpointAddressAvailableForDoingIdentityCheck {
              get { return SR.GetResourceString("NoOutgoingEndpointAddressAvailableForDoingIdentityCheck", null); }
        }
        internal static string NoOutgoingEndpointAddressAvailableForDoingIdentityCheckOnReply {
              get { return SR.GetResourceString("NoOutgoingEndpointAddressAvailableForDoingIdentityCheckOnReply", null); }
        }
        internal static string NoSigningTokenAvailableToDoIncomingIdentityCheck {
              get { return SR.GetResourceString("NoSigningTokenAvailableToDoIncomingIdentityCheck", null); }
        }
        internal static string Psha1KeyLengthInvalid {
              get { return SR.GetResourceString("Psha1KeyLengthInvalid", null); }
        }
        internal static string CloneNotImplementedCorrectly {
              get { return SR.GetResourceString("CloneNotImplementedCorrectly", null); }
        }
        internal static string BadIssuedTokenType {
              get { return SR.GetResourceString("BadIssuedTokenType", null); }
        }
        internal static string OperationDoesNotAllowImpersonation {
              get { return SR.GetResourceString("OperationDoesNotAllowImpersonation", null); }
        }
        internal static string RstrHasMultipleIssuedTokens {
              get { return SR.GetResourceString("RstrHasMultipleIssuedTokens", null); }
        }
        internal static string RstrHasMultipleProofTokens {
              get { return SR.GetResourceString("RstrHasMultipleProofTokens", null); }
        }
        internal static string ProofTokenXmlUnexpectedInRstr {
              get { return SR.GetResourceString("ProofTokenXmlUnexpectedInRstr", null); }
        }
        internal static string InvalidKeyLengthRequested {
              get { return SR.GetResourceString("InvalidKeyLengthRequested", null); }
        }
        internal static string IssuedSecurityTokenParametersNotSet {
              get { return SR.GetResourceString("IssuedSecurityTokenParametersNotSet", null); }
        }
        internal static string InvalidOrUnrecognizedAction {
              get { return SR.GetResourceString("InvalidOrUnrecognizedAction", null); }
        }
        internal static string UnsupportedTokenInclusionMode {
              get { return SR.GetResourceString("UnsupportedTokenInclusionMode", null); }
        }
        internal static string CannotImportProtectionLevelForContract {
              get { return SR.GetResourceString("CannotImportProtectionLevelForContract", null); }
        }
        internal static string OnlyOneOfEncryptedKeyOrSymmetricBindingCanBeSelected {
              get { return SR.GetResourceString("OnlyOneOfEncryptedKeyOrSymmetricBindingCanBeSelected", null); }
        }
        internal static string ClientCredentialTypeMustBeSpecifiedForMixedMode {
              get { return SR.GetResourceString("ClientCredentialTypeMustBeSpecifiedForMixedMode", null); }
        }
        internal static string SecuritySessionIdAlreadyPresentInFilterTable {
              get { return SR.GetResourceString("SecuritySessionIdAlreadyPresentInFilterTable", null); }
        }
        internal static string SupportingTokenNotProvided {
              get { return SR.GetResourceString("SupportingTokenNotProvided", null); }
        }
        internal static string SupportingTokenIsNotEndorsing {
              get { return SR.GetResourceString("SupportingTokenIsNotEndorsing", null); }
        }
        internal static string SupportingTokenIsNotSigned {
              get { return SR.GetResourceString("SupportingTokenIsNotSigned", null); }
        }
        internal static string SupportingTokenIsNotEncrypted {
              get { return SR.GetResourceString("SupportingTokenIsNotEncrypted", null); }
        }
        internal static string BasicTokenNotExpected {
              get { return SR.GetResourceString("BasicTokenNotExpected", null); }
        }
        internal static string FailedAuthenticationTrustFaultCode {
              get { return SR.GetResourceString("FailedAuthenticationTrustFaultCode", null); }
        }
        internal static string AuthenticationOfClientFailed {
              get { return SR.GetResourceString("AuthenticationOfClientFailed", null); }
        }
        internal static string InvalidRequestTrustFaultCode {
              get { return SR.GetResourceString("InvalidRequestTrustFaultCode", null); }
        }
        internal static string SignedSupportingTokenNotExpected {
              get { return SR.GetResourceString("SignedSupportingTokenNotExpected", null); }
        }
        internal static string SenderSideSupportingTokensMustSpecifySecurityTokenParameters {
              get { return SR.GetResourceString("SenderSideSupportingTokensMustSpecifySecurityTokenParameters", null); }
        }
        internal static string SignatureAndEncryptionTokenMismatch {
              get { return SR.GetResourceString("SignatureAndEncryptionTokenMismatch", null); }
        }
        internal static string RevertingPrivilegeFailed {
              get { return SR.GetResourceString("RevertingPrivilegeFailed", null); }
        }
        internal static string UnknownSupportingToken {
              get { return SR.GetResourceString("UnknownSupportingToken", null); }
        }
        internal static string MoreThanOneSupportingSignature {
              get { return SR.GetResourceString("MoreThanOneSupportingSignature", null); }
        }
        internal static string UnsecuredMessageFaultReceived {
              get { return SR.GetResourceString("UnsecuredMessageFaultReceived", null); }
        }
        internal static string FailedAuthenticationFaultReason {
              get { return SR.GetResourceString("FailedAuthenticationFaultReason", null); }
        }
        internal static string BadContextTokenOrActionFaultReason {
              get { return SR.GetResourceString("BadContextTokenOrActionFaultReason", null); }
        }
        internal static string BadContextTokenFaultReason {
              get { return SR.GetResourceString("BadContextTokenFaultReason", null); }
        }
        internal static string NegotiationFailedIO {
              get { return SR.GetResourceString("NegotiationFailedIO", null); }
        }
        internal static string SecurityNegotiationCannotProtectConfidentialEndpointHeader {
              get { return SR.GetResourceString("SecurityNegotiationCannotProtectConfidentialEndpointHeader", null); }
        }
        internal static string InvalidSecurityTokenFaultReason {
              get { return SR.GetResourceString("InvalidSecurityTokenFaultReason", null); }
        }
        internal static string InvalidSecurityFaultReason {
              get { return SR.GetResourceString("InvalidSecurityFaultReason", null); }
        }
        internal static string AnonymousLogonsAreNotAllowed {
              get { return SR.GetResourceString("AnonymousLogonsAreNotAllowed", null); }
        }
        internal static string UnableToObtainIssuerMetadata {
              get { return SR.GetResourceString("UnableToObtainIssuerMetadata", null); }
        }
        internal static string ErrorImportingIssuerMetadata {
              get { return SR.GetResourceString("ErrorImportingIssuerMetadata", null); }
        }
        internal static string MultipleCorrelationTokensFound {
              get { return SR.GetResourceString("MultipleCorrelationTokensFound", null); }
        }
        internal static string NoCorrelationTokenFound {
              get { return SR.GetResourceString("NoCorrelationTokenFound", null); }
        }
        internal static string MultipleSupportingAuthenticatorsOfSameType {
              get { return SR.GetResourceString("MultipleSupportingAuthenticatorsOfSameType", null); }
        }
        internal static string TooManyIssuedSecurityTokenParameters {
              get { return SR.GetResourceString("TooManyIssuedSecurityTokenParameters", null); }
        }
        internal static string UnknownTokenAuthenticatorUsedInTokenProcessing {
              get { return SR.GetResourceString("UnknownTokenAuthenticatorUsedInTokenProcessing", null); }
        }
        internal static string TokenMustBeNullWhenTokenParametersAre {
              get { return SR.GetResourceString("TokenMustBeNullWhenTokenParametersAre", null); }
        }
        internal static string SecurityTokenParametersCloneInvalidResult {
              get { return SR.GetResourceString("SecurityTokenParametersCloneInvalidResult", null); }
        }
        internal static string CertificateUnsupportedForHttpTransportCredentialOnly {
              get { return SR.GetResourceString("CertificateUnsupportedForHttpTransportCredentialOnly", null); }
        }
        internal static string BasicHttpMessageSecurityRequiresCertificate {
              get { return SR.GetResourceString("BasicHttpMessageSecurityRequiresCertificate", null); }
        }
        internal static string EntropyModeRequiresRequestorEntropy {
              get { return SR.GetResourceString("EntropyModeRequiresRequestorEntropy", null); }
        }
        internal static string BearerKeyTypeCannotHaveProofKey {
              get { return SR.GetResourceString("BearerKeyTypeCannotHaveProofKey", null); }
        }
        internal static string BearerKeyIncompatibleWithWSFederationHttpBinding {
              get { return SR.GetResourceString("BearerKeyIncompatibleWithWSFederationHttpBinding", null); }
        }
        internal static string UnableToCreateKeyTypeElementForUnknownKeyType {
              get { return SR.GetResourceString("UnableToCreateKeyTypeElementForUnknownKeyType", null); }
        }
        internal static string EntropyModeCannotHaveProofTokenOrIssuerEntropy {
              get { return SR.GetResourceString("EntropyModeCannotHaveProofTokenOrIssuerEntropy", null); }
        }
        internal static string EntropyModeCannotHaveRequestorEntropy {
              get { return SR.GetResourceString("EntropyModeCannotHaveRequestorEntropy", null); }
        }
        internal static string EntropyModeRequiresProofToken {
              get { return SR.GetResourceString("EntropyModeRequiresProofToken", null); }
        }
        internal static string EntropyModeRequiresComputedKey {
              get { return SR.GetResourceString("EntropyModeRequiresComputedKey", null); }
        }
        internal static string EntropyModeRequiresIssuerEntropy {
              get { return SR.GetResourceString("EntropyModeRequiresIssuerEntropy", null); }
        }
        internal static string EntropyModeCannotHaveComputedKey {
              get { return SR.GetResourceString("EntropyModeCannotHaveComputedKey", null); }
        }
        internal static string UnknownComputedKeyAlgorithm {
              get { return SR.GetResourceString("UnknownComputedKeyAlgorithm", null); }
        }
        internal static string NoncesCachedInfinitely {
              get { return SR.GetResourceString("NoncesCachedInfinitely", null); }
        }
        internal static string ChannelMustBeOpenedToGetSessionId {
              get { return SR.GetResourceString("ChannelMustBeOpenedToGetSessionId", null); }
        }
        internal static string SecurityVersionDoesNotSupportEncryptedKeyBinding {
              get { return SR.GetResourceString("SecurityVersionDoesNotSupportEncryptedKeyBinding", null); }
        }
        internal static string SecurityVersionDoesNotSupportThumbprintX509KeyIdentifierClause {
              get { return SR.GetResourceString("SecurityVersionDoesNotSupportThumbprintX509KeyIdentifierClause", null); }
        }
        internal static string SecurityBindingSupportsOneWayOnly {
              get { return SR.GetResourceString("SecurityBindingSupportsOneWayOnly", null); }
        }
        internal static string DownlevelNameCannotMapToUpn {
              get { return SR.GetResourceString("DownlevelNameCannotMapToUpn", null); }
        }
        internal static string ResolvingExternalTokensRequireSecurityTokenParameters {
              get { return SR.GetResourceString("ResolvingExternalTokensRequireSecurityTokenParameters", null); }
        }
        internal static string SecurityRenewFaultReason {
              get { return SR.GetResourceString("SecurityRenewFaultReason", null); }
        }
        internal static string ClientSecurityOutputSessionCloseTimeout {
              get { return SR.GetResourceString("ClientSecurityOutputSessionCloseTimeout", null); }
        }
        internal static string ClientSecurityNegotiationTimeout {
              get { return SR.GetResourceString("ClientSecurityNegotiationTimeout", null); }
        }
        internal static string ClientSecuritySessionRequestTimeout {
              get { return SR.GetResourceString("ClientSecuritySessionRequestTimeout", null); }
        }
        internal static string ServiceSecurityCloseOutputSessionTimeout {
              get { return SR.GetResourceString("ServiceSecurityCloseOutputSessionTimeout", null); }
        }
        internal static string ServiceSecurityCloseTimeout {
              get { return SR.GetResourceString("ServiceSecurityCloseTimeout", null); }
        }
        internal static string ClientSecurityCloseTimeout {
              get { return SR.GetResourceString("ClientSecurityCloseTimeout", null); }
        }
        internal static string UnableToRenewSessionKey {
              get { return SR.GetResourceString("UnableToRenewSessionKey", null); }
        }
        internal static string SessionKeyRenewalNotSupported {
              get { return SR.GetResourceString("SessionKeyRenewalNotSupported", null); }
        }
        internal static string SctCookieXmlParseError {
              get { return SR.GetResourceString("SctCookieXmlParseError", null); }
        }
        internal static string SctCookieValueMissingOrIncorrect {
              get { return SR.GetResourceString("SctCookieValueMissingOrIncorrect", null); }
        }
        internal static string SctCookieBlobDecodeFailure {
              get { return SR.GetResourceString("SctCookieBlobDecodeFailure", null); }
        }
        internal static string SctCookieNotSupported {
              get { return SR.GetResourceString("SctCookieNotSupported", null); }
        }
        internal static string CannotImportSupportingTokensForOperationWithoutRequestAction {
              get { return SR.GetResourceString("CannotImportSupportingTokensForOperationWithoutRequestAction", null); }
        }
        internal static string SignatureConfirmationsNotExpected {
              get { return SR.GetResourceString("SignatureConfirmationsNotExpected", null); }
        }
        internal static string SignatureConfirmationsOccursAfterPrimarySignature {
              get { return SR.GetResourceString("SignatureConfirmationsOccursAfterPrimarySignature", null); }
        }
        internal static string SignatureConfirmationWasExpected {
              get { return SR.GetResourceString("SignatureConfirmationWasExpected", null); }
        }
        internal static string SecurityVersionDoesNotSupportSignatureConfirmation {
              get { return SR.GetResourceString("SecurityVersionDoesNotSupportSignatureConfirmation", null); }
        }
        internal static string SignatureConfirmationRequiresRequestReply {
              get { return SR.GetResourceString("SignatureConfirmationRequiresRequestReply", null); }
        }
        internal static string NotAllSignaturesConfirmed {
              get { return SR.GetResourceString("NotAllSignaturesConfirmed", null); }
        }
        internal static string FoundUnexpectedSignatureConfirmations {
              get { return SR.GetResourceString("FoundUnexpectedSignatureConfirmations", null); }
        }
        internal static string TooManyPendingSessionKeys {
              get { return SR.GetResourceString("TooManyPendingSessionKeys", null); }
        }
        internal static string SecuritySessionKeyIsStale {
              get { return SR.GetResourceString("SecuritySessionKeyIsStale", null); }
        }
        internal static string MultipleMatchingCryptosFound {
              get { return SR.GetResourceString("MultipleMatchingCryptosFound", null); }
        }
        internal static string CannotFindMatchingCrypto {
              get { return SR.GetResourceString("CannotFindMatchingCrypto", null); }
        }
        internal static string SymmetricSecurityBindingElementNeedsProtectionTokenParameters {
              get { return SR.GetResourceString("SymmetricSecurityBindingElementNeedsProtectionTokenParameters", null); }
        }
        internal static string AsymmetricSecurityBindingElementNeedsInitiatorTokenParameters {
              get { return SR.GetResourceString("AsymmetricSecurityBindingElementNeedsInitiatorTokenParameters", null); }
        }
        internal static string AsymmetricSecurityBindingElementNeedsRecipientTokenParameters {
              get { return SR.GetResourceString("AsymmetricSecurityBindingElementNeedsRecipientTokenParameters", null); }
        }
        internal static string CachedNegotiationStateQuotaReached {
              get { return SR.GetResourceString("CachedNegotiationStateQuotaReached", null); }
        }
        internal static string LsaAuthorityNotContacted {
              get { return SR.GetResourceString("LsaAuthorityNotContacted", null); }
        }
        internal static string KeyRolloverGreaterThanKeyRenewal {
              get { return SR.GetResourceString("KeyRolloverGreaterThanKeyRenewal", null); }
        }
        internal static string AtLeastOneContractOperationRequestRequiresProtectionLevelNotSupportedByBinding {
              get { return SR.GetResourceString("AtLeastOneContractOperationRequestRequiresProtectionLevelNotSupportedByBinding", null); }
        }
        internal static string AtLeastOneContractOperationResponseRequiresProtectionLevelNotSupportedByBinding {
              get { return SR.GetResourceString("AtLeastOneContractOperationResponseRequiresProtectionLevelNotSupportedByBinding", null); }
        }
        internal static string UnknownHeaderCannotProtected {
              get { return SR.GetResourceString("UnknownHeaderCannotProtected", null); }
        }
        internal static string NoStreamingWithSecurity {
              get { return SR.GetResourceString("NoStreamingWithSecurity", null); }
        }
        internal static string CurrentSessionTokenNotRenewed {
              get { return SR.GetResourceString("CurrentSessionTokenNotRenewed", null); }
        }
        internal static string IncorrectSpnOrUpnSpecified {
              get { return SR.GetResourceString("IncorrectSpnOrUpnSpecified", null); }
        }
        internal static string IncomingSigningTokenMustBeAnEncryptedKey {
              get { return SR.GetResourceString("IncomingSigningTokenMustBeAnEncryptedKey", null); }
        }
        internal static string SecuritySessionAbortedFaultReason {
              get { return SR.GetResourceString("SecuritySessionAbortedFaultReason", null); }
        }
        internal static string NoAppliesToPresent {
              get { return SR.GetResourceString("NoAppliesToPresent", null); }
        }
        internal static string UnsupportedKeyLength {
              get { return SR.GetResourceString("UnsupportedKeyLength", null); }
        }
        internal static string ForReplayDetectionToBeDoneRequireIntegrityMustBeSet {
              get { return SR.GetResourceString("ForReplayDetectionToBeDoneRequireIntegrityMustBeSet", null); }
        }
        internal static string CantInferReferenceForToken {
              get { return SR.GetResourceString("CantInferReferenceForToken", null); }
        }
        internal static string TrustDriverIsUnableToCreatedNecessaryAttachedOrUnattachedReferences {
              get { return SR.GetResourceString("TrustDriverIsUnableToCreatedNecessaryAttachedOrUnattachedReferences", null); }
        }
        internal static string TrustDriverVersionDoesNotSupportSession {
              get { return SR.GetResourceString("TrustDriverVersionDoesNotSupportSession", null); }
        }
        internal static string TrustDriverVersionDoesNotSupportIssuedTokens {
              get { return SR.GetResourceString("TrustDriverVersionDoesNotSupportIssuedTokens", null); }
        }
        internal static string CannotPerformS4UImpersonationOnPlatform {
              get { return SR.GetResourceString("CannotPerformS4UImpersonationOnPlatform", null); }
        }
        internal static string CannotPerformImpersonationOnUsernameToken {
              get { return SR.GetResourceString("CannotPerformImpersonationOnUsernameToken", null); }
        }
        internal static string RevertImpersonationFailure {
              get { return SR.GetResourceString("RevertImpersonationFailure", null); }
        }
        internal static string TransactionFlowRequiredIssuedTokens {
              get { return SR.GetResourceString("TransactionFlowRequiredIssuedTokens", null); }
        }
        internal static string SignatureConfirmationNotSupported {
              get { return SR.GetResourceString("SignatureConfirmationNotSupported", null); }
        }
        internal static string SecureConversationDriverVersionDoesNotSupportSession {
              get { return SR.GetResourceString("SecureConversationDriverVersionDoesNotSupportSession", null); }
        }
        internal static string SoapSecurityNegotiationFailed {
              get { return SR.GetResourceString("SoapSecurityNegotiationFailed", null); }
        }
        internal static string SoapSecurityNegotiationFailedForIssuerAndTarget {
              get { return SR.GetResourceString("SoapSecurityNegotiationFailedForIssuerAndTarget", null); }
        }
        internal static string OneWayOperationReturnedFault {
              get { return SR.GetResourceString("OneWayOperationReturnedFault", null); }
        }
        internal static string OneWayOperationReturnedLargeFault {
              get { return SR.GetResourceString("OneWayOperationReturnedLargeFault", null); }
        }
        internal static string OneWayOperationReturnedMessage {
              get { return SR.GetResourceString("OneWayOperationReturnedMessage", null); }
        }
        internal static string CannotFindSecuritySession {
              get { return SR.GetResourceString("CannotFindSecuritySession", null); }
        }
        internal static string SecurityContextKeyExpired {
              get { return SR.GetResourceString("SecurityContextKeyExpired", null); }
        }
        internal static string SecurityContextKeyExpiredNoKeyGeneration {
              get { return SR.GetResourceString("SecurityContextKeyExpiredNoKeyGeneration", null); }
        }
        internal static string SecuritySessionRequiresMessageIntegrity {
              get { return SR.GetResourceString("SecuritySessionRequiresMessageIntegrity", null); }
        }
        internal static string RequiredTimestampMissingInSecurityHeader {
              get { return SR.GetResourceString("RequiredTimestampMissingInSecurityHeader", null); }
        }
        internal static string ReceivedMessageInRequestContextNull {
              get { return SR.GetResourceString("ReceivedMessageInRequestContextNull", null); }
        }
        internal static string KeyLifetimeNotWithinTokenLifetime {
              get { return SR.GetResourceString("KeyLifetimeNotWithinTokenLifetime", null); }
        }
        internal static string EffectiveGreaterThanExpiration {
              get { return SR.GetResourceString("EffectiveGreaterThanExpiration", null); }
        }
        internal static string NoSessionTokenPresentInMessage {
              get { return SR.GetResourceString("NoSessionTokenPresentInMessage", null); }
        }
        internal static string LengthMustBeGreaterThanZero {
              get { return SR.GetResourceString("LengthMustBeGreaterThanZero", null); }
        }
        internal static string KeyLengthMustBeMultipleOfEight {
              get { return SR.GetResourceString("KeyLengthMustBeMultipleOfEight", null); }
        }
        internal static string InvalidX509RawData {
              get { return SR.GetResourceString("InvalidX509RawData", null); }
        }
        internal static string ExportOfBindingWithTransportSecurityBindingElementAndNoTransportSecurityNotSupported {
              get { return SR.GetResourceString("ExportOfBindingWithTransportSecurityBindingElementAndNoTransportSecurityNotSupported", null); }
        }
        internal static string UnsupportedSecureConversationBootstrapProtectionRequirements {
              get { return SR.GetResourceString("UnsupportedSecureConversationBootstrapProtectionRequirements", null); }
        }
        internal static string UnsupportedBooleanAttribute {
              get { return SR.GetResourceString("UnsupportedBooleanAttribute", null); }
        }
        internal static string NoTransportTokenAssertionProvided {
              get { return SR.GetResourceString("NoTransportTokenAssertionProvided", null); }
        }
        internal static string PolicyRequiresConfidentialityWithoutIntegrity {
              get { return SR.GetResourceString("PolicyRequiresConfidentialityWithoutIntegrity", null); }
        }
        internal static string PrimarySignatureIsRequiredToBeEncrypted {
              get { return SR.GetResourceString("PrimarySignatureIsRequiredToBeEncrypted", null); }
        }
        internal static string TokenCannotCreateSymmetricCrypto {
              get { return SR.GetResourceString("TokenCannotCreateSymmetricCrypto", null); }
        }
        internal static string TokenDoesNotMeetKeySizeRequirements {
              get { return SR.GetResourceString("TokenDoesNotMeetKeySizeRequirements", null); }
        }
        internal static string MessageProtectionOrderMismatch {
              get { return SR.GetResourceString("MessageProtectionOrderMismatch", null); }
        }
        internal static string PrimarySignatureMustBeComputedBeforeSupportingTokenSignatures {
              get { return SR.GetResourceString("PrimarySignatureMustBeComputedBeforeSupportingTokenSignatures", null); }
        }
        internal static string ElementToSignMustHaveId {
              get { return SR.GetResourceString("ElementToSignMustHaveId", null); }
        }
        internal static string StandardsManagerCannotWriteObject {
              get { return SR.GetResourceString("StandardsManagerCannotWriteObject", null); }
        }
        internal static string SigningWithoutPrimarySignatureRequiresTimestamp {
              get { return SR.GetResourceString("SigningWithoutPrimarySignatureRequiresTimestamp", null); }
        }
        internal static string OperationCannotBeDoneAfterProcessingIsStarted {
              get { return SR.GetResourceString("OperationCannotBeDoneAfterProcessingIsStarted", null); }
        }
        internal static string MaximumPolicyRedirectionsExceeded {
              get { return SR.GetResourceString("MaximumPolicyRedirectionsExceeded", null); }
        }
        internal static string InvalidAttributeInSignedHeader {
              get { return SR.GetResourceString("InvalidAttributeInSignedHeader", null); }
        }
        internal static string StsAddressNotSet {
              get { return SR.GetResourceString("StsAddressNotSet", null); }
        }
        internal static string MoreThanOneSecurityBindingElementInTheBinding {
              get { return SR.GetResourceString("MoreThanOneSecurityBindingElementInTheBinding", null); }
        }
        internal static string ClientCredentialsUnableToCreateLocalTokenProvider {
              get { return SR.GetResourceString("ClientCredentialsUnableToCreateLocalTokenProvider", null); }
        }
        internal static string SecurityBindingElementCannotBeExpressedInConfig {
              get { return SR.GetResourceString("SecurityBindingElementCannotBeExpressedInConfig", null); }
        }
        internal static string SecurityProtocolCannotDoReplayDetection {
              get { return SR.GetResourceString("SecurityProtocolCannotDoReplayDetection", null); }
        }
        internal static string UnableToFindSecurityHeaderInMessage {
              get { return SR.GetResourceString("UnableToFindSecurityHeaderInMessage", null); }
        }
        internal static string UnableToFindSecurityHeaderInMessageNoActor {
              get { return SR.GetResourceString("UnableToFindSecurityHeaderInMessageNoActor", null); }
        }
        internal static string NoPrimarySignatureAvailableForSupportingTokenSignatureVerification {
              get { return SR.GetResourceString("NoPrimarySignatureAvailableForSupportingTokenSignatureVerification", null); }
        }
        internal static string SupportingTokenSignaturesNotExpected {
              get { return SR.GetResourceString("SupportingTokenSignaturesNotExpected", null); }
        }
        internal static string CannotReadToken {
              get { return SR.GetResourceString("CannotReadToken", null); }
        }
        internal static string ExpectedElementMissing {
              get { return SR.GetResourceString("ExpectedElementMissing", null); }
        }
        internal static string ExpectedOneOfTwoElementsFromNamespace {
              get { return SR.GetResourceString("ExpectedOneOfTwoElementsFromNamespace", null); }
        }
        internal static string RstDirectDoesNotExpectRstr {
              get { return SR.GetResourceString("RstDirectDoesNotExpectRstr", null); }
        }
        internal static string RequireNonCookieMode {
              get { return SR.GetResourceString("RequireNonCookieMode", null); }
        }
        internal static string RequiredSignatureMissing {
              get { return SR.GetResourceString("RequiredSignatureMissing", null); }
        }
        internal static string RequiredMessagePartNotSigned {
              get { return SR.GetResourceString("RequiredMessagePartNotSigned", null); }
        }
        internal static string RequiredMessagePartNotSignedNs {
              get { return SR.GetResourceString("RequiredMessagePartNotSignedNs", null); }
        }
        internal static string RequiredMessagePartNotEncrypted {
              get { return SR.GetResourceString("RequiredMessagePartNotEncrypted", null); }
        }
        internal static string RequiredMessagePartNotEncryptedNs {
              get { return SR.GetResourceString("RequiredMessagePartNotEncryptedNs", null); }
        }
        internal static string SignatureVerificationFailed {
              get { return SR.GetResourceString("SignatureVerificationFailed", null); }
        }
        internal static string CannotIssueRstTokenType {
              get { return SR.GetResourceString("CannotIssueRstTokenType", null); }
        }
        internal static string NoNegotiationMessageToSend {
              get { return SR.GetResourceString("NoNegotiationMessageToSend", null); }
        }
        internal static string InvalidIssuedTokenKeySize {
              get { return SR.GetResourceString("InvalidIssuedTokenKeySize", null); }
        }
        internal static string CannotObtainIssuedTokenKeySize {
              get { return SR.GetResourceString("CannotObtainIssuedTokenKeySize", null); }
        }
        internal static string NegotiationIsNotCompleted {
              get { return SR.GetResourceString("NegotiationIsNotCompleted", null); }
        }
        internal static string NegotiationIsCompleted {
              get { return SR.GetResourceString("NegotiationIsCompleted", null); }
        }
        internal static string MissingMessageID {
              get { return SR.GetResourceString("MissingMessageID", null); }
        }
        internal static string SecuritySessionLimitReached {
              get { return SR.GetResourceString("SecuritySessionLimitReached", null); }
        }
        internal static string SecuritySessionAlreadyPending {
              get { return SR.GetResourceString("SecuritySessionAlreadyPending", null); }
        }
        internal static string SecuritySessionNotPending {
              get { return SR.GetResourceString("SecuritySessionNotPending", null); }
        }
        internal static string SecuritySessionListenerNotFound {
              get { return SR.GetResourceString("SecuritySessionListenerNotFound", null); }
        }
        internal static string SessionTokenWasNotClosed {
              get { return SR.GetResourceString("SessionTokenWasNotClosed", null); }
        }
        internal static string ProtocolMustBeInitiator {
              get { return SR.GetResourceString("ProtocolMustBeInitiator", null); }
        }
        internal static string ProtocolMustBeRecipient {
              get { return SR.GetResourceString("ProtocolMustBeRecipient", null); }
        }
        internal static string SendingOutgoingmessageOnRecipient {
              get { return SR.GetResourceString("SendingOutgoingmessageOnRecipient", null); }
        }
        internal static string OnlyBodyReturnValuesSupported {
              get { return SR.GetResourceString("OnlyBodyReturnValuesSupported", null); }
        }
        internal static string UnknownTokenAttachmentMode {
              get { return SR.GetResourceString("UnknownTokenAttachmentMode", null); }
        }
        internal static string ProtocolMisMatch {
              get { return SR.GetResourceString("ProtocolMisMatch", null); }
        }
        internal static string AttemptToCreateMultipleRequestContext {
              get { return SR.GetResourceString("AttemptToCreateMultipleRequestContext", null); }
        }
        internal static string ServerReceivedCloseMessageStateIsCreated {
              get { return SR.GetResourceString("ServerReceivedCloseMessageStateIsCreated", null); }
        }
        internal static string ShutdownRequestWasNotReceived {
              get { return SR.GetResourceString("ShutdownRequestWasNotReceived", null); }
        }
        internal static string UnknownFilterType {
              get { return SR.GetResourceString("UnknownFilterType", null); }
        }
        internal static string StandardsManagerDoesNotMatch {
              get { return SR.GetResourceString("StandardsManagerDoesNotMatch", null); }
        }
        internal static string FilterStrictModeDifferent {
              get { return SR.GetResourceString("FilterStrictModeDifferent", null); }
        }
        internal static string SSSSCreateAcceptor {
              get { return SR.GetResourceString("SSSSCreateAcceptor", null); }
        }
        internal static string TransactionFlowBadOption {
              get { return SR.GetResourceString("TransactionFlowBadOption", null); }
        }
        internal static string TokenManagerCouldNotReadToken {
              get { return SR.GetResourceString("TokenManagerCouldNotReadToken", null); }
        }
        internal static string InvalidActionForNegotiationMessage {
              get { return SR.GetResourceString("InvalidActionForNegotiationMessage", null); }
        }
        internal static string InvalidKeySizeSpecifiedInNegotiation {
              get { return SR.GetResourceString("InvalidKeySizeSpecifiedInNegotiation", null); }
        }
        internal static string GetTokenInfoFailed {
              get { return SR.GetResourceString("GetTokenInfoFailed", null); }
        }
        internal static string UnexpectedEndOfFile {
              get { return SR.GetResourceString("UnexpectedEndOfFile", null); }
        }
        internal static string TimeStampHasCreationAheadOfExpiry {
              get { return SR.GetResourceString("TimeStampHasCreationAheadOfExpiry", null); }
        }
        internal static string TimeStampHasExpiryTimeInPast {
              get { return SR.GetResourceString("TimeStampHasExpiryTimeInPast", null); }
        }
        internal static string TimeStampHasCreationTimeInFuture {
              get { return SR.GetResourceString("TimeStampHasCreationTimeInFuture", null); }
        }
        internal static string TimeStampWasCreatedTooLongAgo {
              get { return SR.GetResourceString("TimeStampWasCreatedTooLongAgo", null); }
        }
        internal static string InvalidOrReplayedNonce {
              get { return SR.GetResourceString("InvalidOrReplayedNonce", null); }
        }
        internal static string MessagePartSpecificationMustBeImmutable {
              get { return SR.GetResourceString("MessagePartSpecificationMustBeImmutable", null); }
        }
        internal static string UnsupportedIssuerEntropyType {
              get { return SR.GetResourceString("UnsupportedIssuerEntropyType", null); }
        }
        internal static string NoRequestSecurityTokenResponseElements {
              get { return SR.GetResourceString("NoRequestSecurityTokenResponseElements", null); }
        }
        internal static string NoCookieInSct {
              get { return SR.GetResourceString("NoCookieInSct", null); }
        }
        internal static string TokenProviderReturnedBadToken {
              get { return SR.GetResourceString("TokenProviderReturnedBadToken", null); }
        }
        internal static string ItemNotAvailableInDeserializedRST {
              get { return SR.GetResourceString("ItemNotAvailableInDeserializedRST", null); }
        }
        internal static string ItemAvailableInDeserializedRSTOnly {
              get { return SR.GetResourceString("ItemAvailableInDeserializedRSTOnly", null); }
        }
        internal static string ItemNotAvailableInDeserializedRSTR {
              get { return SR.GetResourceString("ItemNotAvailableInDeserializedRSTR", null); }
        }
        internal static string ItemAvailableInDeserializedRSTROnly {
              get { return SR.GetResourceString("ItemAvailableInDeserializedRSTROnly", null); }
        }
        internal static string MoreThanOneRSTRInRSTRC {
              get { return SR.GetResourceString("MoreThanOneRSTRInRSTRC", null); }
        }
        internal static string Hosting_VirtualPathExtenstionCanNotBeDetached {
              get { return SR.GetResourceString("Hosting_VirtualPathExtenstionCanNotBeDetached", null); }
        }
        internal static string Hosting_NotSupportedProtocol {
              get { return SR.GetResourceString("Hosting_NotSupportedProtocol", null); }
        }
        internal static string Hosting_BaseUriDeserializedNotValid {
              get { return SR.GetResourceString("Hosting_BaseUriDeserializedNotValid", null); }
        }
        internal static string Hosting_RelativeAddressFormatError {
              get { return SR.GetResourceString("Hosting_RelativeAddressFormatError", null); }
        }
        internal static string Hosting_NoAbsoluteRelativeAddress {
              get { return SR.GetResourceString("Hosting_NoAbsoluteRelativeAddress", null); }
        }
        internal static string SecureConversationNeedsBootstrapSecurity {
              get { return SR.GetResourceString("SecureConversationNeedsBootstrapSecurity", null); }
        }
        internal static string Hosting_MemoryGatesCheckFailedUnderPartialTrust {
              get { return SR.GetResourceString("Hosting_MemoryGatesCheckFailedUnderPartialTrust", null); }
        }
        internal static string Hosting_CompatibilityServiceNotHosted {
              get { return SR.GetResourceString("Hosting_CompatibilityServiceNotHosted", null); }
        }
        internal static string Hosting_MisformattedPort {
              get { return SR.GetResourceString("Hosting_MisformattedPort", null); }
        }
        internal static string Hosting_MisformattedBinding {
              get { return SR.GetResourceString("Hosting_MisformattedBinding", null); }
        }
        internal static string Hosting_MisformattedBindingData {
              get { return SR.GetResourceString("Hosting_MisformattedBindingData", null); }
        }
        internal static string Hosting_NoHttpTransportManagerForUri {
              get { return SR.GetResourceString("Hosting_NoHttpTransportManagerForUri", null); }
        }
        internal static string Hosting_NoTcpPipeTransportManagerForUri {
              get { return SR.GetResourceString("Hosting_NoTcpPipeTransportManagerForUri", null); }
        }
        internal static string Hosting_ProcessNotExecutingUnderHostedContext {
              get { return SR.GetResourceString("Hosting_ProcessNotExecutingUnderHostedContext", null); }
        }
        internal static string Hosting_ServiceActivationFailed {
              get { return SR.GetResourceString("Hosting_ServiceActivationFailed", null); }
        }
        internal static string Hosting_ServiceTypeNotProvided {
              get { return SR.GetResourceString("Hosting_ServiceTypeNotProvided", null); }
        }
        internal static string SharedEndpointReadDenied {
              get { return SR.GetResourceString("SharedEndpointReadDenied", null); }
        }
        internal static string SharedEndpointReadNotFound {
              get { return SR.GetResourceString("SharedEndpointReadNotFound", null); }
        }
        internal static string SharedManagerBase {
              get { return SR.GetResourceString("SharedManagerBase", null); }
        }
        internal static string SharedManagerServiceStartFailure {
              get { return SR.GetResourceString("SharedManagerServiceStartFailure", null); }
        }
        internal static string SharedManagerServiceStartFailureDisabled {
              get { return SR.GetResourceString("SharedManagerServiceStartFailureDisabled", null); }
        }
        internal static string SharedManagerServiceStartFailureNoError {
              get { return SR.GetResourceString("SharedManagerServiceStartFailureNoError", null); }
        }
        internal static string SharedManagerServiceLookupFailure {
              get { return SR.GetResourceString("SharedManagerServiceLookupFailure", null); }
        }
        internal static string SharedManagerServiceSidLookupFailure {
              get { return SR.GetResourceString("SharedManagerServiceSidLookupFailure", null); }
        }
        internal static string SharedManagerServiceEndpointReadFailure {
              get { return SR.GetResourceString("SharedManagerServiceEndpointReadFailure", null); }
        }
        internal static string SharedManagerServiceSecurityFailed {
              get { return SR.GetResourceString("SharedManagerServiceSecurityFailed", null); }
        }
        internal static string SharedManagerUserSidLookupFailure {
              get { return SR.GetResourceString("SharedManagerUserSidLookupFailure", null); }
        }
        internal static string SharedManagerCurrentUserSidLookupFailure {
              get { return SR.GetResourceString("SharedManagerCurrentUserSidLookupFailure", null); }
        }
        internal static string SharedManagerLogonSidLookupFailure {
              get { return SR.GetResourceString("SharedManagerLogonSidLookupFailure", null); }
        }
        internal static string SharedManagerDataConnectionFailure {
              get { return SR.GetResourceString("SharedManagerDataConnectionFailure", null); }
        }
        internal static string SharedManagerDataConnectionCreateFailure {
              get { return SR.GetResourceString("SharedManagerDataConnectionCreateFailure", null); }
        }
        internal static string SharedManagerDataConnectionPipeFailed {
              get { return SR.GetResourceString("SharedManagerDataConnectionPipeFailed", null); }
        }
        internal static string SharedManagerVersionUnsupported {
              get { return SR.GetResourceString("SharedManagerVersionUnsupported", null); }
        }
        internal static string SharedManagerAllowDupHandleFailed {
              get { return SR.GetResourceString("SharedManagerAllowDupHandleFailed", null); }
        }
        internal static string SharedManagerPathTooLong {
              get { return SR.GetResourceString("SharedManagerPathTooLong", null); }
        }
        internal static string SharedManagerRegistrationQuotaExceeded {
              get { return SR.GetResourceString("SharedManagerRegistrationQuotaExceeded", null); }
        }
        internal static string SharedManagerProtocolUnsupported {
              get { return SR.GetResourceString("SharedManagerProtocolUnsupported", null); }
        }
        internal static string SharedManagerConflictingRegistration {
              get { return SR.GetResourceString("SharedManagerConflictingRegistration", null); }
        }
        internal static string SharedManagerFailedToListen {
              get { return SR.GetResourceString("SharedManagerFailedToListen", null); }
        }
        internal static string Sharing_ConnectionDispatchFailed {
              get { return SR.GetResourceString("Sharing_ConnectionDispatchFailed", null); }
        }
        internal static string Sharing_EndpointUnavailable {
              get { return SR.GetResourceString("Sharing_EndpointUnavailable", null); }
        }
        internal static string Sharing_EmptyListenerEndpoint {
              get { return SR.GetResourceString("Sharing_EmptyListenerEndpoint", null); }
        }
        internal static string Sharing_ListenerProxyStopped {
              get { return SR.GetResourceString("Sharing_ListenerProxyStopped", null); }
        }
        internal static string UnexpectedEmptyElementExpectingClaim {
              get { return SR.GetResourceString("UnexpectedEmptyElementExpectingClaim", null); }
        }
        internal static string UnexpectedElementExpectingElement {
              get { return SR.GetResourceString("UnexpectedElementExpectingElement", null); }
        }
        internal static string UnexpectedDuplicateElement {
              get { return SR.GetResourceString("UnexpectedDuplicateElement", null); }
        }
        internal static string UnsupportedSecurityPolicyAssertion {
              get { return SR.GetResourceString("UnsupportedSecurityPolicyAssertion", null); }
        }
        internal static string MultipleIdentities {
              get { return SR.GetResourceString("MultipleIdentities", null); }
        }
        internal static string InvalidUriValue {
              get { return SR.GetResourceString("InvalidUriValue", null); }
        }
        internal static string BindingDoesNotSupportProtectionForRst {
              get { return SR.GetResourceString("BindingDoesNotSupportProtectionForRst", null); }
        }
        internal static string TransportDoesNotProtectMessage {
              get { return SR.GetResourceString("TransportDoesNotProtectMessage", null); }
        }
        internal static string BindingDoesNotSupportWindowsIdenityForImpersonation {
              get { return SR.GetResourceString("BindingDoesNotSupportWindowsIdenityForImpersonation", null); }
        }
        internal static string ListenUriNotSet {
              get { return SR.GetResourceString("ListenUriNotSet", null); }
        }
        internal static string UnsupportedChannelInterfaceType {
              get { return SR.GetResourceString("UnsupportedChannelInterfaceType", null); }
        }
        internal static string TransportManagerOpen {
              get { return SR.GetResourceString("TransportManagerOpen", null); }
        }
        internal static string TransportManagerNotOpen {
              get { return SR.GetResourceString("TransportManagerNotOpen", null); }
        }
        internal static string UnrecognizedIdentityType {
              get { return SR.GetResourceString("UnrecognizedIdentityType", null); }
        }
        internal static string InvalidIdentityElement {
              get { return SR.GetResourceString("InvalidIdentityElement", null); }
        }
        internal static string UnableToLoadCertificateIdentity {
              get { return SR.GetResourceString("UnableToLoadCertificateIdentity", null); }
        }
        internal static string UnrecognizedClaimTypeForIdentity {
              get { return SR.GetResourceString("UnrecognizedClaimTypeForIdentity", null); }
        }
        internal static string AsyncCallbackException {
              get { return SR.GetResourceString("AsyncCallbackException", null); }
        }
        internal static string SendCannotBeCalledAfterCloseOutputSession {
              get { return SR.GetResourceString("SendCannotBeCalledAfterCloseOutputSession", null); }
        }
        internal static string CommunicationObjectCannotBeModifiedInState {
              get { return SR.GetResourceString("CommunicationObjectCannotBeModifiedInState", null); }
        }
        internal static string CommunicationObjectCannotBeModified {
              get { return SR.GetResourceString("CommunicationObjectCannotBeModified", null); }
        }
        internal static string CommunicationObjectCannotBeUsed {
              get { return SR.GetResourceString("CommunicationObjectCannotBeUsed", null); }
        }
        internal static string CommunicationObjectFaulted1 {
              get { return SR.GetResourceString("CommunicationObjectFaulted1", null); }
        }
        internal static string CommunicationObjectFaultedStack2 {
              get { return SR.GetResourceString("CommunicationObjectFaultedStack2", null); }
        }
        internal static string CommunicationObjectAborted1 {
              get { return SR.GetResourceString("CommunicationObjectAborted1", null); }
        }
        internal static string CommunicationObjectAbortedStack2 {
              get { return SR.GetResourceString("CommunicationObjectAbortedStack2", null); }
        }
        internal static string CommunicationObjectBaseClassMethodNotCalled {
              get { return SR.GetResourceString("CommunicationObjectBaseClassMethodNotCalled", null); }
        }
        internal static string CommunicationObjectInInvalidState {
              get { return SR.GetResourceString("CommunicationObjectInInvalidState", null); }
        }
        internal static string CommunicationObjectCloseInterrupted1 {
              get { return SR.GetResourceString("CommunicationObjectCloseInterrupted1", null); }
        }
        internal static string ChannelFactoryCannotBeUsedToCreateChannels {
              get { return SR.GetResourceString("ChannelFactoryCannotBeUsedToCreateChannels", null); }
        }
        internal static string ChannelParametersCannotBeModified {
              get { return SR.GetResourceString("ChannelParametersCannotBeModified", null); }
        }
        internal static string ChannelParametersCannotBePropagated {
              get { return SR.GetResourceString("ChannelParametersCannotBePropagated", null); }
        }
        internal static string OneWayInternalTypeNotSupported {
              get { return SR.GetResourceString("OneWayInternalTypeNotSupported", null); }
        }
        internal static string ChannelTypeNotSupported {
              get { return SR.GetResourceString("ChannelTypeNotSupported", null); }
        }
        internal static string SecurityContextMissing {
              get { return SR.GetResourceString("SecurityContextMissing", null); }
        }
        internal static string SecurityContextDoesNotAllowImpersonation {
              get { return SR.GetResourceString("SecurityContextDoesNotAllowImpersonation", null); }
        }
        internal static string InvalidEnumValue {
              get { return SR.GetResourceString("InvalidEnumValue", null); }
        }
        internal static string InvalidDecoderStateMachine {
              get { return SR.GetResourceString("InvalidDecoderStateMachine", null); }
        }
        internal static string OperationPropertyIsRequiredForAttributeGeneration {
              get { return SR.GetResourceString("OperationPropertyIsRequiredForAttributeGeneration", null); }
        }
        internal static string InvalidMembershipProviderSpecifiedInConfig {
              get { return SR.GetResourceString("InvalidMembershipProviderSpecifiedInConfig", null); }
        }
        internal static string InvalidRoleProviderSpecifiedInConfig {
              get { return SR.GetResourceString("InvalidRoleProviderSpecifiedInConfig", null); }
        }
        internal static string ObjectDisposed {
              get { return SR.GetResourceString("ObjectDisposed", null); }
        }
        internal static string InvalidReaderPositionOnCreateMessage {
              get { return SR.GetResourceString("InvalidReaderPositionOnCreateMessage", null); }
        }
        internal static string DuplicateMessageProperty {
              get { return SR.GetResourceString("DuplicateMessageProperty", null); }
        }
        internal static string MessagePropertyNotFound {
              get { return SR.GetResourceString("MessagePropertyNotFound", null); }
        }
        internal static string HeaderAlreadyUnderstood {
              get { return SR.GetResourceString("HeaderAlreadyUnderstood", null); }
        }
        internal static string HeaderAlreadyNotUnderstood {
              get { return SR.GetResourceString("HeaderAlreadyNotUnderstood", null); }
        }
        internal static string MultipleMessageHeaders {
              get { return SR.GetResourceString("MultipleMessageHeaders", null); }
        }
        internal static string MultipleMessageHeadersWithActor {
              get { return SR.GetResourceString("MultipleMessageHeadersWithActor", null); }
        }
        internal static string MultipleRelatesToHeaders {
              get { return SR.GetResourceString("MultipleRelatesToHeaders", null); }
        }
        internal static string ExtraContentIsPresentInFaultDetail {
              get { return SR.GetResourceString("ExtraContentIsPresentInFaultDetail", null); }
        }
        internal static string MessageIsEmpty {
              get { return SR.GetResourceString("MessageIsEmpty", null); }
        }
        internal static string MessageClosed {
              get { return SR.GetResourceString("MessageClosed", null); }
        }
        internal static string StreamClosed {
              get { return SR.GetResourceString("StreamClosed", null); }
        }
        internal static string BodyWriterReturnedIsNotBuffered {
              get { return SR.GetResourceString("BodyWriterReturnedIsNotBuffered", null); }
        }
        internal static string BodyWriterCanOnlyBeWrittenOnce {
              get { return SR.GetResourceString("BodyWriterCanOnlyBeWrittenOnce", null); }
        }
        internal static string RstrKeySizeNotProvided {
              get { return SR.GetResourceString("RstrKeySizeNotProvided", null); }
        }
        internal static string RequestMessageDoesNotHaveAMessageID {
              get { return SR.GetResourceString("RequestMessageDoesNotHaveAMessageID", null); }
        }
        internal static string HeaderNotFound {
              get { return SR.GetResourceString("HeaderNotFound", null); }
        }
        internal static string MessageBufferIsClosed {
              get { return SR.GetResourceString("MessageBufferIsClosed", null); }
        }
        internal static string MessageTextEncodingNotSupported {
              get { return SR.GetResourceString("MessageTextEncodingNotSupported", null); }
        }
        internal static string AtLeastOneFaultReasonMustBeSpecified {
              get { return SR.GetResourceString("AtLeastOneFaultReasonMustBeSpecified", null); }
        }
        internal static string NoNullTranslations {
              get { return SR.GetResourceString("NoNullTranslations", null); }
        }
        internal static string FaultDoesNotHaveAnyDetail {
              get { return SR.GetResourceString("FaultDoesNotHaveAnyDetail", null); }
        }
        internal static string InvalidXmlQualifiedName {
              get { return SR.GetResourceString("InvalidXmlQualifiedName", null); }
        }
        internal static string UnboundPrefixInQName {
              get { return SR.GetResourceString("UnboundPrefixInQName", null); }
        }
        internal static string MessageBodyIsUnknown {
              get { return SR.GetResourceString("MessageBodyIsUnknown", null); }
        }
        internal static string MessageBodyIsStream {
              get { return SR.GetResourceString("MessageBodyIsStream", null); }
        }
        internal static string MessageBodyToStringError {
              get { return SR.GetResourceString("MessageBodyToStringError", null); }
        }
        internal static string NoMatchingTranslationFoundForFaultText {
              get { return SR.GetResourceString("NoMatchingTranslationFoundForFaultText", null); }
        }
        internal static string CannotDetermineSPNBasedOnAddress {
              get { return SR.GetResourceString("CannotDetermineSPNBasedOnAddress", null); }
        }
        internal static string XmlLangAttributeMissing {
              get { return SR.GetResourceString("XmlLangAttributeMissing", null); }
        }
        internal static string EncoderUnrecognizedCharSet {
              get { return SR.GetResourceString("EncoderUnrecognizedCharSet", null); }
        }
        internal static string EncoderUnrecognizedContentType {
              get { return SR.GetResourceString("EncoderUnrecognizedContentType", null); }
        }
        internal static string EncoderBadContentType {
              get { return SR.GetResourceString("EncoderBadContentType", null); }
        }
        internal static string EncoderEnvelopeVersionMismatch {
              get { return SR.GetResourceString("EncoderEnvelopeVersionMismatch", null); }
        }
        internal static string EncoderMessageVersionMismatch {
              get { return SR.GetResourceString("EncoderMessageVersionMismatch", null); }
        }
        internal static string MtomEncoderBadMessageVersion {
              get { return SR.GetResourceString("MtomEncoderBadMessageVersion", null); }
        }
        internal static string SPS_ReadNotSupported {
              get { return SR.GetResourceString("SPS_ReadNotSupported", null); }
        }
        internal static string SPS_SeekNotSupported {
              get { return SR.GetResourceString("SPS_SeekNotSupported", null); }
        }
        internal static string WriterAsyncWritePending {
              get { return SR.GetResourceString("WriterAsyncWritePending", null); }
        }
        internal static string ChannelInitializationTimeout {
              get { return SR.GetResourceString("ChannelInitializationTimeout", null); }
        }
        internal static string SocketCloseReadTimeout {
              get { return SR.GetResourceString("SocketCloseReadTimeout", null); }
        }
        internal static string SocketCloseReadReceivedData {
              get { return SR.GetResourceString("SocketCloseReadReceivedData", null); }
        }
        internal static string SessionValueInvalid {
              get { return SR.GetResourceString("SessionValueInvalid", null); }
        }
        internal static string PackageFullNameInvalid {
              get { return SR.GetResourceString("PackageFullNameInvalid", null); }
        }
        internal static string SocketAbortedReceiveTimedOut {
              get { return SR.GetResourceString("SocketAbortedReceiveTimedOut", null); }
        }
        internal static string SocketAbortedSendTimedOut {
              get { return SR.GetResourceString("SocketAbortedSendTimedOut", null); }
        }
        internal static string OperationInvalidBeforeSecurityNegotiation {
              get { return SR.GetResourceString("OperationInvalidBeforeSecurityNegotiation", null); }
        }
        internal static string FramingError {
              get { return SR.GetResourceString("FramingError", null); }
        }
        internal static string FramingPrematureEOF {
              get { return SR.GetResourceString("FramingPrematureEOF", null); }
        }
        internal static string FramingRecordTypeMismatch {
              get { return SR.GetResourceString("FramingRecordTypeMismatch", null); }
        }
        internal static string FramingVersionNotSupported {
              get { return SR.GetResourceString("FramingVersionNotSupported", null); }
        }
        internal static string FramingModeNotSupported {
              get { return SR.GetResourceString("FramingModeNotSupported", null); }
        }
        internal static string FramingSizeTooLarge {
              get { return SR.GetResourceString("FramingSizeTooLarge", null); }
        }
        internal static string FramingViaTooLong {
              get { return SR.GetResourceString("FramingViaTooLong", null); }
        }
        internal static string FramingViaNotUri {
              get { return SR.GetResourceString("FramingViaNotUri", null); }
        }
        internal static string FramingFaultTooLong {
              get { return SR.GetResourceString("FramingFaultTooLong", null); }
        }
        internal static string FramingContentTypeTooLong {
              get { return SR.GetResourceString("FramingContentTypeTooLong", null); }
        }
        internal static string FramingValueNotAvailable {
              get { return SR.GetResourceString("FramingValueNotAvailable", null); }
        }
        internal static string FramingAtEnd {
              get { return SR.GetResourceString("FramingAtEnd", null); }
        }
        internal static string RemoteSecurityNotNegotiatedOnStreamUpgrade {
              get { return SR.GetResourceString("RemoteSecurityNotNegotiatedOnStreamUpgrade", null); }
        }
        internal static string BinaryEncoderSessionTooLarge {
              get { return SR.GetResourceString("BinaryEncoderSessionTooLarge", null); }
        }
        internal static string BinaryEncoderSessionInvalid {
              get { return SR.GetResourceString("BinaryEncoderSessionInvalid", null); }
        }
        internal static string BinaryEncoderSessionMalformed {
              get { return SR.GetResourceString("BinaryEncoderSessionMalformed", null); }
        }
        internal static string ReceiveShutdownReturnedFault {
              get { return SR.GetResourceString("ReceiveShutdownReturnedFault", null); }
        }
        internal static string ReceiveShutdownReturnedLargeFault {
              get { return SR.GetResourceString("ReceiveShutdownReturnedLargeFault", null); }
        }
        internal static string ReceiveShutdownReturnedMessage {
              get { return SR.GetResourceString("ReceiveShutdownReturnedMessage", null); }
        }
        internal static string MaxReceivedMessageSizeExceeded {
              get { return SR.GetResourceString("MaxReceivedMessageSizeExceeded", null); }
        }
        internal static string MaxSentMessageSizeExceeded {
              get { return SR.GetResourceString("MaxSentMessageSizeExceeded", null); }
        }
        internal static string FramingMaxMessageSizeExceeded {
              get { return SR.GetResourceString("FramingMaxMessageSizeExceeded", null); }
        }
        internal static string StreamDoesNotSupportTimeout {
              get { return SR.GetResourceString("StreamDoesNotSupportTimeout", null); }
        }
        internal static string FilterExists {
              get { return SR.GetResourceString("FilterExists", null); }
        }
        internal static string FilterUnexpectedError {
              get { return SR.GetResourceString("FilterUnexpectedError", null); }
        }
        internal static string FilterNodeQuotaExceeded {
              get { return SR.GetResourceString("FilterNodeQuotaExceeded", null); }
        }
        internal static string FilterCapacityNegative {
              get { return SR.GetResourceString("FilterCapacityNegative", null); }
        }
        internal static string ActionFilterEmptyList {
              get { return SR.GetResourceString("ActionFilterEmptyList", null); }
        }
        internal static string FilterUndefinedPrefix {
              get { return SR.GetResourceString("FilterUndefinedPrefix", null); }
        }
        internal static string FilterMultipleMatches {
              get { return SR.GetResourceString("FilterMultipleMatches", null); }
        }
        internal static string FilterTableTypeMismatch {
              get { return SR.GetResourceString("FilterTableTypeMismatch", null); }
        }
        internal static string FilterTableInvalidForLookup {
              get { return SR.GetResourceString("FilterTableInvalidForLookup", null); }
        }
        internal static string FilterBadTableType {
              get { return SR.GetResourceString("FilterBadTableType", null); }
        }
        internal static string FilterQuotaRange {
              get { return SR.GetResourceString("FilterQuotaRange", null); }
        }
        internal static string FilterEmptyString {
              get { return SR.GetResourceString("FilterEmptyString", null); }
        }
        internal static string FilterInvalidInner {
              get { return SR.GetResourceString("FilterInvalidInner", null); }
        }
        internal static string FilterInvalidAttribute {
              get { return SR.GetResourceString("FilterInvalidAttribute", null); }
        }
        internal static string FilterInvalidDialect {
              get { return SR.GetResourceString("FilterInvalidDialect", null); }
        }
        internal static string FilterCouldNotCompile {
              get { return SR.GetResourceString("FilterCouldNotCompile", null); }
        }
        internal static string FilterReaderNotStartElem {
              get { return SR.GetResourceString("FilterReaderNotStartElem", null); }
        }
        internal static string SeekableMessageNavInvalidPosition {
              get { return SR.GetResourceString("SeekableMessageNavInvalidPosition", null); }
        }
        internal static string SeekableMessageNavNonAtomized {
              get { return SR.GetResourceString("SeekableMessageNavNonAtomized", null); }
        }
        internal static string SeekableMessageNavIDNotSupported {
              get { return SR.GetResourceString("SeekableMessageNavIDNotSupported", null); }
        }
        internal static string SeekableMessageNavBodyForbidden {
              get { return SR.GetResourceString("SeekableMessageNavBodyForbidden", null); }
        }
        internal static string SeekableMessageNavOverrideForbidden {
              get { return SR.GetResourceString("SeekableMessageNavOverrideForbidden", null); }
        }
        internal static string QueryNotImplemented {
              get { return SR.GetResourceString("QueryNotImplemented", null); }
        }
        internal static string QueryNotSortable {
              get { return SR.GetResourceString("QueryNotSortable", null); }
        }
        internal static string QueryMustBeSeekable {
              get { return SR.GetResourceString("QueryMustBeSeekable", null); }
        }
        internal static string QueryContextNotSupportedInSequences {
              get { return SR.GetResourceString("QueryContextNotSupportedInSequences", null); }
        }
        internal static string QueryFunctionTypeNotSupported {
              get { return SR.GetResourceString("QueryFunctionTypeNotSupported", null); }
        }
        internal static string QueryVariableTypeNotSupported {
              get { return SR.GetResourceString("QueryVariableTypeNotSupported", null); }
        }
        internal static string QueryVariableNull {
              get { return SR.GetResourceString("QueryVariableNull", null); }
        }
        internal static string QueryFunctionStringArg {
              get { return SR.GetResourceString("QueryFunctionStringArg", null); }
        }
        internal static string QueryItemAlreadyExists {
              get { return SR.GetResourceString("QueryItemAlreadyExists", null); }
        }
        internal static string QueryBeforeNodes {
              get { return SR.GetResourceString("QueryBeforeNodes", null); }
        }
        internal static string QueryAfterNodes {
              get { return SR.GetResourceString("QueryAfterNodes", null); }
        }
        internal static string QueryIteratorOutOfScope {
              get { return SR.GetResourceString("QueryIteratorOutOfScope", null); }
        }
        internal static string QueryCantGetStringForMovedIterator {
              get { return SR.GetResourceString("QueryCantGetStringForMovedIterator", null); }
        }
        internal static string AddressingVersionNotSupported {
              get { return SR.GetResourceString("AddressingVersionNotSupported", null); }
        }
        internal static string SupportedAddressingModeNotSupported {
              get { return SR.GetResourceString("SupportedAddressingModeNotSupported", null); }
        }
        internal static string MessagePropertyReturnedNullCopy {
              get { return SR.GetResourceString("MessagePropertyReturnedNullCopy", null); }
        }
        internal static string MessageVersionUnknown {
              get { return SR.GetResourceString("MessageVersionUnknown", null); }
        }
        internal static string EnvelopeVersionUnknown {
              get { return SR.GetResourceString("EnvelopeVersionUnknown", null); }
        }
        internal static string EnvelopeVersionNotSupported {
              get { return SR.GetResourceString("EnvelopeVersionNotSupported", null); }
        }
        internal static string CannotDetectAddressingVersion {
              get { return SR.GetResourceString("CannotDetectAddressingVersion", null); }
        }
        internal static string HeadersCannotBeAddedToEnvelopeVersion {
              get { return SR.GetResourceString("HeadersCannotBeAddedToEnvelopeVersion", null); }
        }
        internal static string AddressingHeadersCannotBeAddedToAddressingVersion {
              get { return SR.GetResourceString("AddressingHeadersCannotBeAddedToAddressingVersion", null); }
        }
        internal static string AddressingExtensionInBadNS {
              get { return SR.GetResourceString("AddressingExtensionInBadNS", null); }
        }
        internal static string MessageHeaderVersionNotSupported {
              get { return SR.GetResourceString("MessageHeaderVersionNotSupported", null); }
        }
        internal static string MessageHasBeenCopied {
              get { return SR.GetResourceString("MessageHasBeenCopied", null); }
        }
        internal static string MessageHasBeenWritten {
              get { return SR.GetResourceString("MessageHasBeenWritten", null); }
        }
        internal static string MessageHasBeenRead {
              get { return SR.GetResourceString("MessageHasBeenRead", null); }
        }
        internal static string InvalidMessageState {
              get { return SR.GetResourceString("InvalidMessageState", null); }
        }
        internal static string MessageBodyReaderInvalidReadState {
              get { return SR.GetResourceString("MessageBodyReaderInvalidReadState", null); }
        }
        internal static string XmlBufferQuotaExceeded {
              get { return SR.GetResourceString("XmlBufferQuotaExceeded", null); }
        }
        internal static string XmlBufferInInvalidState {
              get { return SR.GetResourceString("XmlBufferInInvalidState", null); }
        }
        internal static string MessageBodyMissing {
              get { return SR.GetResourceString("MessageBodyMissing", null); }
        }
        internal static string MessageHeaderVersionMismatch {
              get { return SR.GetResourceString("MessageHeaderVersionMismatch", null); }
        }
        internal static string ManualAddressingRequiresAddressedMessages {
              get { return SR.GetResourceString("ManualAddressingRequiresAddressedMessages", null); }
        }
        internal static string OneWayHeaderNotFound {
              get { return SR.GetResourceString("OneWayHeaderNotFound", null); }
        }
        internal static string ReceiveTimedOut {
              get { return SR.GetResourceString("ReceiveTimedOut", null); }
        }
        internal static string ReceiveTimedOut2 {
              get { return SR.GetResourceString("ReceiveTimedOut2", null); }
        }
        internal static string WaitForMessageTimedOut {
              get { return SR.GetResourceString("WaitForMessageTimedOut", null); }
        }
        internal static string ReceiveTimedOutNoLocalAddress {
              get { return SR.GetResourceString("ReceiveTimedOutNoLocalAddress", null); }
        }
        internal static string ReceiveRequestTimedOutNoLocalAddress {
              get { return SR.GetResourceString("ReceiveRequestTimedOutNoLocalAddress", null); }
        }
        internal static string ReceiveRequestTimedOut {
              get { return SR.GetResourceString("ReceiveRequestTimedOut", null); }
        }
        internal static string SendToViaTimedOut {
              get { return SR.GetResourceString("SendToViaTimedOut", null); }
        }
        internal static string CloseTimedOut {
              get { return SR.GetResourceString("CloseTimedOut", null); }
        }
        internal static string OpenTimedOutEstablishingTransportSession {
              get { return SR.GetResourceString("OpenTimedOutEstablishingTransportSession", null); }
        }
        internal static string RequestTimedOutEstablishingTransportSession {
              get { return SR.GetResourceString("RequestTimedOutEstablishingTransportSession", null); }
        }
        internal static string TcpConnectingToViaTimedOut {
              get { return SR.GetResourceString("TcpConnectingToViaTimedOut", null); }
        }
        internal static string RequestChannelSendTimedOut {
              get { return SR.GetResourceString("RequestChannelSendTimedOut", null); }
        }
        internal static string RequestChannelWaitForReplyTimedOut {
              get { return SR.GetResourceString("RequestChannelWaitForReplyTimedOut", null); }
        }
        internal static string HttpTransportCannotHaveMultipleAuthenticationSchemes {
              get { return SR.GetResourceString("HttpTransportCannotHaveMultipleAuthenticationSchemes", null); }
        }
        internal static string MultipleCCbesInParameters {
              get { return SR.GetResourceString("MultipleCCbesInParameters", null); }
        }
        internal static string CookieContainerBindingElementNeedsHttp {
              get { return SR.GetResourceString("CookieContainerBindingElementNeedsHttp", null); }
        }
        internal static string HttpIfModifiedSinceParseError {
              get { return SR.GetResourceString("HttpIfModifiedSinceParseError", null); }
        }
        internal static string HttpSoapActionMismatch {
              get { return SR.GetResourceString("HttpSoapActionMismatch", null); }
        }
        internal static string HttpSoapActionMismatchContentType {
              get { return SR.GetResourceString("HttpSoapActionMismatchContentType", null); }
        }
        internal static string HttpSoapActionMismatchFault {
              get { return SR.GetResourceString("HttpSoapActionMismatchFault", null); }
        }
        internal static string HttpContentTypeFormatException {
              get { return SR.GetResourceString("HttpContentTypeFormatException", null); }
        }
        internal static string HttpServerTooBusy {
              get { return SR.GetResourceString("HttpServerTooBusy", null); }
        }
        internal static string HttpRequestAborted {
              get { return SR.GetResourceString("HttpRequestAborted", null); }
        }
        internal static string HttpRequestTimedOut {
              get { return SR.GetResourceString("HttpRequestTimedOut", null); }
        }
        internal static string HttpResponseTimedOut {
              get { return SR.GetResourceString("HttpResponseTimedOut", null); }
        }
        internal static string HttpTransferError {
              get { return SR.GetResourceString("HttpTransferError", null); }
        }
        internal static string HttpReceiveFailure {
              get { return SR.GetResourceString("HttpReceiveFailure", null); }
        }
        internal static string HttpSendFailure {
              get { return SR.GetResourceString("HttpSendFailure", null); }
        }
        internal static string HttpAuthDoesNotSupportRequestStreaming {
              get { return SR.GetResourceString("HttpAuthDoesNotSupportRequestStreaming", null); }
        }
        internal static string ReplyAlreadySent {
              get { return SR.GetResourceString("ReplyAlreadySent", null); }
        }
        internal static string HttpInvalidListenURI {
              get { return SR.GetResourceString("HttpInvalidListenURI", null); }
        }
        internal static string RequestContextAborted {
              get { return SR.GetResourceString("RequestContextAborted", null); }
        }
        internal static string ReceiveContextCannotBeUsed {
              get { return SR.GetResourceString("ReceiveContextCannotBeUsed", null); }
        }
        internal static string ReceiveContextInInvalidState {
              get { return SR.GetResourceString("ReceiveContextInInvalidState", null); }
        }
        internal static string ReceiveContextFaulted {
              get { return SR.GetResourceString("ReceiveContextFaulted", null); }
        }
        internal static string UnrecognizedHostNameComparisonMode {
              get { return SR.GetResourceString("UnrecognizedHostNameComparisonMode", null); }
        }
        internal static string BadData {
              get { return SR.GetResourceString("BadData", null); }
        }
        internal static string InvalidRenewResponseAction {
              get { return SR.GetResourceString("InvalidRenewResponseAction", null); }
        }
        internal static string InvalidCloseResponseAction {
              get { return SR.GetResourceString("InvalidCloseResponseAction", null); }
        }
        internal static string IncompatibleBehaviors {
              get { return SR.GetResourceString("IncompatibleBehaviors", null); }
        }
        internal static string NullSessionRequestMessage {
              get { return SR.GetResourceString("NullSessionRequestMessage", null); }
        }
        internal static string IssueSessionTokenHandlerNotSet {
              get { return SR.GetResourceString("IssueSessionTokenHandlerNotSet", null); }
        }
        internal static string RenewSessionTokenHandlerNotSet {
              get { return SR.GetResourceString("RenewSessionTokenHandlerNotSet", null); }
        }
        internal static string WrongIdentityRenewingToken {
              get { return SR.GetResourceString("WrongIdentityRenewingToken", null); }
        }
        internal static string InvalidRstRequestType {
              get { return SR.GetResourceString("InvalidRstRequestType", null); }
        }
        internal static string NoCloseTargetSpecified {
              get { return SR.GetResourceString("NoCloseTargetSpecified", null); }
        }
        internal static string FailedSspiNegotiation {
              get { return SR.GetResourceString("FailedSspiNegotiation", null); }
        }
        internal static string BadCloseTarget {
              get { return SR.GetResourceString("BadCloseTarget", null); }
        }
        internal static string RenewSessionMissingSupportingToken {
              get { return SR.GetResourceString("RenewSessionMissingSupportingToken", null); }
        }
        internal static string NoRenewTargetSpecified {
              get { return SR.GetResourceString("NoRenewTargetSpecified", null); }
        }
        internal static string BadRenewTarget {
              get { return SR.GetResourceString("BadRenewTarget", null); }
        }
        internal static string BadEncryptedBody {
              get { return SR.GetResourceString("BadEncryptedBody", null); }
        }
        internal static string BadEncryptionState {
              get { return SR.GetResourceString("BadEncryptionState", null); }
        }
        internal static string NoSignaturePartsSpecified {
              get { return SR.GetResourceString("NoSignaturePartsSpecified", null); }
        }
        internal static string NoEncryptionPartsSpecified {
              get { return SR.GetResourceString("NoEncryptionPartsSpecified", null); }
        }
        internal static string SecuritySessionFaultReplyWasSent {
              get { return SR.GetResourceString("SecuritySessionFaultReplyWasSent", null); }
        }
        internal static string InnerListenerFactoryNotSet {
              get { return SR.GetResourceString("InnerListenerFactoryNotSet", null); }
        }
        internal static string SecureConversationBootstrapCannotUseSecureConversation {
              get { return SR.GetResourceString("SecureConversationBootstrapCannotUseSecureConversation", null); }
        }
        internal static string InnerChannelFactoryWasNotSet {
              get { return SR.GetResourceString("InnerChannelFactoryWasNotSet", null); }
        }
        internal static string SecurityProtocolFactoryDoesNotSupportDuplex {
              get { return SR.GetResourceString("SecurityProtocolFactoryDoesNotSupportDuplex", null); }
        }
        internal static string SecurityProtocolFactoryDoesNotSupportRequestReply {
              get { return SR.GetResourceString("SecurityProtocolFactoryDoesNotSupportRequestReply", null); }
        }
        internal static string SecurityProtocolFactoryShouldBeSetBeforeThisOperation {
              get { return SR.GetResourceString("SecurityProtocolFactoryShouldBeSetBeforeThisOperation", null); }
        }
        internal static string SecuritySessionProtocolFactoryShouldBeSetBeforeThisOperation {
              get { return SR.GetResourceString("SecuritySessionProtocolFactoryShouldBeSetBeforeThisOperation", null); }
        }
        internal static string SecureConversationSecurityTokenParametersRequireBootstrapBinding {
              get { return SR.GetResourceString("SecureConversationSecurityTokenParametersRequireBootstrapBinding", null); }
        }
        internal static string PropertySettingErrorOnProtocolFactory {
              get { return SR.GetResourceString("PropertySettingErrorOnProtocolFactory", null); }
        }
        internal static string ProtocolFactoryCouldNotCreateProtocol {
              get { return SR.GetResourceString("ProtocolFactoryCouldNotCreateProtocol", null); }
        }
        internal static string IdentityCheckFailedForOutgoingMessage {
              get { return SR.GetResourceString("IdentityCheckFailedForOutgoingMessage", null); }
        }
        internal static string IdentityCheckFailedForIncomingMessage {
              get { return SR.GetResourceString("IdentityCheckFailedForIncomingMessage", null); }
        }
        internal static string DnsIdentityCheckFailedForIncomingMessageLackOfDnsClaim {
              get { return SR.GetResourceString("DnsIdentityCheckFailedForIncomingMessageLackOfDnsClaim", null); }
        }
        internal static string DnsIdentityCheckFailedForOutgoingMessageLackOfDnsClaim {
              get { return SR.GetResourceString("DnsIdentityCheckFailedForOutgoingMessageLackOfDnsClaim", null); }
        }
        internal static string DnsIdentityCheckFailedForIncomingMessage {
              get { return SR.GetResourceString("DnsIdentityCheckFailedForIncomingMessage", null); }
        }
        internal static string DnsIdentityCheckFailedForOutgoingMessage {
              get { return SR.GetResourceString("DnsIdentityCheckFailedForOutgoingMessage", null); }
        }
        internal static string SerializedTokenVersionUnsupported {
              get { return SR.GetResourceString("SerializedTokenVersionUnsupported", null); }
        }
        internal static string AuthenticatorNotPresentInRSTRCollection {
              get { return SR.GetResourceString("AuthenticatorNotPresentInRSTRCollection", null); }
        }
        internal static string RSTRAuthenticatorHasBadContext {
              get { return SR.GetResourceString("RSTRAuthenticatorHasBadContext", null); }
        }
        internal static string ServerCertificateNotProvided {
              get { return SR.GetResourceString("ServerCertificateNotProvided", null); }
        }
        internal static string RSTRAuthenticatorNotPresent {
              get { return SR.GetResourceString("RSTRAuthenticatorNotPresent", null); }
        }
        internal static string RSTRAuthenticatorIncorrect {
              get { return SR.GetResourceString("RSTRAuthenticatorIncorrect", null); }
        }
        internal static string ClientCertificateNotProvided {
              get { return SR.GetResourceString("ClientCertificateNotProvided", null); }
        }
        internal static string ClientCertificateNotProvidedOnServiceCredentials {
              get { return SR.GetResourceString("ClientCertificateNotProvidedOnServiceCredentials", null); }
        }
        internal static string ClientCertificateNotProvidedOnClientCredentials {
              get { return SR.GetResourceString("ClientCertificateNotProvidedOnClientCredentials", null); }
        }
        internal static string ServiceCertificateNotProvidedOnServiceCredentials {
              get { return SR.GetResourceString("ServiceCertificateNotProvidedOnServiceCredentials", null); }
        }
        internal static string ServiceCertificateNotProvidedOnClientCredentials {
              get { return SR.GetResourceString("ServiceCertificateNotProvidedOnClientCredentials", null); }
        }
        internal static string UserNamePasswordNotProvidedOnClientCredentials {
              get { return SR.GetResourceString("UserNamePasswordNotProvidedOnClientCredentials", null); }
        }
        internal static string ObjectIsReadOnly {
              get { return SR.GetResourceString("ObjectIsReadOnly", null); }
        }
        internal static string EmptyXmlElementError {
              get { return SR.GetResourceString("EmptyXmlElementError", null); }
        }
        internal static string UnexpectedXmlChildNode {
              get { return SR.GetResourceString("UnexpectedXmlChildNode", null); }
        }
        internal static string ContextAlreadyRegistered {
              get { return SR.GetResourceString("ContextAlreadyRegistered", null); }
        }
        internal static string ContextAlreadyRegisteredNoKeyGeneration {
              get { return SR.GetResourceString("ContextAlreadyRegisteredNoKeyGeneration", null); }
        }
        internal static string ContextNotPresent {
              get { return SR.GetResourceString("ContextNotPresent", null); }
        }
        internal static string ContextNotPresentNoKeyGeneration {
              get { return SR.GetResourceString("ContextNotPresentNoKeyGeneration", null); }
        }
        internal static string InvalidSecurityContextCookie {
              get { return SR.GetResourceString("InvalidSecurityContextCookie", null); }
        }
        internal static string SecurityContextNotRegistered {
              get { return SR.GetResourceString("SecurityContextNotRegistered", null); }
        }
        internal static string SecurityContextExpired {
              get { return SR.GetResourceString("SecurityContextExpired", null); }
        }
        internal static string SecurityContextExpiredNoKeyGeneration {
              get { return SR.GetResourceString("SecurityContextExpiredNoKeyGeneration", null); }
        }
        internal static string NoSecurityContextIdentifier {
              get { return SR.GetResourceString("NoSecurityContextIdentifier", null); }
        }
        internal static string MessageMustHaveViaOrToSetForSendingOnServerSideCompositeDuplexChannels {
              get { return SR.GetResourceString("MessageMustHaveViaOrToSetForSendingOnServerSideCompositeDuplexChannels", null); }
        }
        internal static string MessageViaCannotBeAddressedToAnonymousOnServerSideCompositeDuplexChannels {
              get { return SR.GetResourceString("MessageViaCannotBeAddressedToAnonymousOnServerSideCompositeDuplexChannels", null); }
        }
        internal static string MessageToCannotBeAddressedToAnonymousOnServerSideCompositeDuplexChannels {
              get { return SR.GetResourceString("MessageToCannotBeAddressedToAnonymousOnServerSideCompositeDuplexChannels", null); }
        }
        internal static string SecurityBindingNotSetUpToProcessOutgoingMessages {
              get { return SR.GetResourceString("SecurityBindingNotSetUpToProcessOutgoingMessages", null); }
        }
        internal static string SecurityBindingNotSetUpToProcessIncomingMessages {
              get { return SR.GetResourceString("SecurityBindingNotSetUpToProcessIncomingMessages", null); }
        }
        internal static string TokenProviderCannotGetTokensForTarget {
              get { return SR.GetResourceString("TokenProviderCannotGetTokensForTarget", null); }
        }
        internal static string UnsupportedKeyDerivationAlgorithm {
              get { return SR.GetResourceString("UnsupportedKeyDerivationAlgorithm", null); }
        }
        internal static string CannotFindCorrelationStateForApplyingSecurity {
              get { return SR.GetResourceString("CannotFindCorrelationStateForApplyingSecurity", null); }
        }
        internal static string ReplyWasNotSignedWithRequiredSigningToken {
              get { return SR.GetResourceString("ReplyWasNotSignedWithRequiredSigningToken", null); }
        }
        internal static string EncryptionNotExpected {
              get { return SR.GetResourceString("EncryptionNotExpected", null); }
        }
        internal static string SignatureNotExpected {
              get { return SR.GetResourceString("SignatureNotExpected", null); }
        }
        internal static string InvalidQName {
              get { return SR.GetResourceString("InvalidQName", null); }
        }
        internal static string UnknownICryptoType {
              get { return SR.GetResourceString("UnknownICryptoType", null); }
        }
        internal static string SameProtocolFactoryCannotBeSetForBothDuplexDirections {
              get { return SR.GetResourceString("SameProtocolFactoryCannotBeSetForBothDuplexDirections", null); }
        }
        internal static string SuiteDoesNotAcceptAlgorithm {
              get { return SR.GetResourceString("SuiteDoesNotAcceptAlgorithm", null); }
        }
        internal static string TokenDoesNotSupportKeyIdentifierClauseCreation {
              get { return SR.GetResourceString("TokenDoesNotSupportKeyIdentifierClauseCreation", null); }
        }
        internal static string UnableToCreateICryptoFromTokenForSignatureVerification {
              get { return SR.GetResourceString("UnableToCreateICryptoFromTokenForSignatureVerification", null); }
        }
        internal static string MessageSecurityVerificationFailed {
              get { return SR.GetResourceString("MessageSecurityVerificationFailed", null); }
        }
        internal static string TransportSecurityRequireToHeader {
              get { return SR.GetResourceString("TransportSecurityRequireToHeader", null); }
        }
        internal static string TransportSecuredMessageMissingToHeader {
              get { return SR.GetResourceString("TransportSecuredMessageMissingToHeader", null); }
        }
        internal static string UnsignedToHeaderInTransportSecuredMessage {
              get { return SR.GetResourceString("UnsignedToHeaderInTransportSecuredMessage", null); }
        }
        internal static string TransportSecuredMessageHasMoreThanOneToHeader {
              get { return SR.GetResourceString("TransportSecuredMessageHasMoreThanOneToHeader", null); }
        }
        internal static string TokenNotExpectedInSecurityHeader {
              get { return SR.GetResourceString("TokenNotExpectedInSecurityHeader", null); }
        }
        internal static string CannotFindCert {
              get { return SR.GetResourceString("CannotFindCert", null); }
        }
        internal static string CannotFindCertForTarget {
              get { return SR.GetResourceString("CannotFindCertForTarget", null); }
        }
        internal static string FoundMultipleCerts {
              get { return SR.GetResourceString("FoundMultipleCerts", null); }
        }
        internal static string FoundMultipleCertsForTarget {
              get { return SR.GetResourceString("FoundMultipleCertsForTarget", null); }
        }
        internal static string MissingKeyInfoInEncryptedKey {
              get { return SR.GetResourceString("MissingKeyInfoInEncryptedKey", null); }
        }
        internal static string EncryptedKeyWasNotEncryptedWithTheRequiredEncryptingToken {
              get { return SR.GetResourceString("EncryptedKeyWasNotEncryptedWithTheRequiredEncryptingToken", null); }
        }
        internal static string MessageWasNotEncryptedWithTheRequiredEncryptingToken {
              get { return SR.GetResourceString("MessageWasNotEncryptedWithTheRequiredEncryptingToken", null); }
        }
        internal static string TimestampMustOccurFirstInSecurityHeaderLayout {
              get { return SR.GetResourceString("TimestampMustOccurFirstInSecurityHeaderLayout", null); }
        }
        internal static string TimestampMustOccurLastInSecurityHeaderLayout {
              get { return SR.GetResourceString("TimestampMustOccurLastInSecurityHeaderLayout", null); }
        }
        internal static string AtMostOnePrimarySignatureInReceiveSecurityHeader {
              get { return SR.GetResourceString("AtMostOnePrimarySignatureInReceiveSecurityHeader", null); }
        }
        internal static string SigningTokenHasNoKeys {
              get { return SR.GetResourceString("SigningTokenHasNoKeys", null); }
        }
        internal static string SigningTokenHasNoKeysSupportingTheAlgorithmSuite {
              get { return SR.GetResourceString("SigningTokenHasNoKeysSupportingTheAlgorithmSuite", null); }
        }
        internal static string DelayedSecurityApplicationAlreadyCompleted {
              get { return SR.GetResourceString("DelayedSecurityApplicationAlreadyCompleted", null); }
        }
        internal static string UnableToResolveKeyInfoClauseInDerivedKeyToken {
              get { return SR.GetResourceString("UnableToResolveKeyInfoClauseInDerivedKeyToken", null); }
        }
        internal static string UnableToDeriveKeyFromKeyInfoClause {
              get { return SR.GetResourceString("UnableToDeriveKeyFromKeyInfoClause", null); }
        }
        internal static string UnableToResolveKeyInfoForVerifyingSignature {
              get { return SR.GetResourceString("UnableToResolveKeyInfoForVerifyingSignature", null); }
        }
        internal static string UnableToResolveKeyInfoForUnwrappingToken {
              get { return SR.GetResourceString("UnableToResolveKeyInfoForUnwrappingToken", null); }
        }
        internal static string UnableToResolveKeyInfoForDecryption {
              get { return SR.GetResourceString("UnableToResolveKeyInfoForDecryption", null); }
        }
        internal static string EmptyBase64Attribute {
              get { return SR.GetResourceString("EmptyBase64Attribute", null); }
        }
        internal static string RequiredSecurityHeaderElementNotSigned {
              get { return SR.GetResourceString("RequiredSecurityHeaderElementNotSigned", null); }
        }
        internal static string RequiredSecurityTokenNotSigned {
              get { return SR.GetResourceString("RequiredSecurityTokenNotSigned", null); }
        }
        internal static string RequiredSecurityTokenNotEncrypted {
              get { return SR.GetResourceString("RequiredSecurityTokenNotEncrypted", null); }
        }
        internal static string MessageBodyOperationNotValidInBodyState {
              get { return SR.GetResourceString("MessageBodyOperationNotValidInBodyState", null); }
        }
        internal static string EncryptedKeyWithReferenceListNotAllowed {
              get { return SR.GetResourceString("EncryptedKeyWithReferenceListNotAllowed", null); }
        }
        internal static string UnableToFindTokenAuthenticator {
              get { return SR.GetResourceString("UnableToFindTokenAuthenticator", null); }
        }
        internal static string NoPartsOfMessageMatchedPartsToSign {
              get { return SR.GetResourceString("NoPartsOfMessageMatchedPartsToSign", null); }
        }
        internal static string BasicTokenCannotBeWrittenWithoutEncryption {
              get { return SR.GetResourceString("BasicTokenCannotBeWrittenWithoutEncryption", null); }
        }
        internal static string DuplicateIdInMessageToBeVerified {
              get { return SR.GetResourceString("DuplicateIdInMessageToBeVerified", null); }
        }
        internal static string UnsupportedCanonicalizationAlgorithm {
              get { return SR.GetResourceString("UnsupportedCanonicalizationAlgorithm", null); }
        }
        internal static string NoKeyInfoInEncryptedItemToFindDecryptingToken {
              get { return SR.GetResourceString("NoKeyInfoInEncryptedItemToFindDecryptingToken", null); }
        }
        internal static string NoKeyInfoInSignatureToFindVerificationToken {
              get { return SR.GetResourceString("NoKeyInfoInSignatureToFindVerificationToken", null); }
        }
        internal static string SecurityHeaderIsEmpty {
              get { return SR.GetResourceString("SecurityHeaderIsEmpty", null); }
        }
        internal static string EncryptionMethodMissingInEncryptedData {
              get { return SR.GetResourceString("EncryptionMethodMissingInEncryptedData", null); }
        }
        internal static string EncryptedHeaderAttributeMismatch {
              get { return SR.GetResourceString("EncryptedHeaderAttributeMismatch", null); }
        }
        internal static string AtMostOneReferenceListIsSupportedWithDefaultPolicyCheck {
              get { return SR.GetResourceString("AtMostOneReferenceListIsSupportedWithDefaultPolicyCheck", null); }
        }
        internal static string AtMostOneSignatureIsSupportedWithDefaultPolicyCheck {
              get { return SR.GetResourceString("AtMostOneSignatureIsSupportedWithDefaultPolicyCheck", null); }
        }
        internal static string UnexpectedEncryptedElementInSecurityHeader {
              get { return SR.GetResourceString("UnexpectedEncryptedElementInSecurityHeader", null); }
        }
        internal static string MissingIdInEncryptedElement {
              get { return SR.GetResourceString("MissingIdInEncryptedElement", null); }
        }
        internal static string TokenManagerCannotCreateTokenReference {
              get { return SR.GetResourceString("TokenManagerCannotCreateTokenReference", null); }
        }
        internal static string TimestampToSignHasNoId {
              get { return SR.GetResourceString("TimestampToSignHasNoId", null); }
        }
        internal static string EncryptedHeaderXmlMustHaveId {
              get { return SR.GetResourceString("EncryptedHeaderXmlMustHaveId", null); }
        }
        internal static string UnableToResolveDataReference {
              get { return SR.GetResourceString("UnableToResolveDataReference", null); }
        }
        internal static string TimestampAlreadySetForSecurityHeader {
              get { return SR.GetResourceString("TimestampAlreadySetForSecurityHeader", null); }
        }
        internal static string DuplicateTimestampInSecurityHeader {
              get { return SR.GetResourceString("DuplicateTimestampInSecurityHeader", null); }
        }
        internal static string MismatchInSecurityOperationToken {
              get { return SR.GetResourceString("MismatchInSecurityOperationToken", null); }
        }
        internal static string UnableToCreateSymmetricAlgorithmFromToken {
              get { return SR.GetResourceString("UnableToCreateSymmetricAlgorithmFromToken", null); }
        }
        internal static string UnknownEncodingInBinarySecurityToken {
              get { return SR.GetResourceString("UnknownEncodingInBinarySecurityToken", null); }
        }
        internal static string UnableToResolveReferenceUriForSignature {
              get { return SR.GetResourceString("UnableToResolveReferenceUriForSignature", null); }
        }
        internal static string NoTimestampAvailableInSecurityHeaderToDoReplayDetection {
              get { return SR.GetResourceString("NoTimestampAvailableInSecurityHeaderToDoReplayDetection", null); }
        }
        internal static string NoSignatureAvailableInSecurityHeaderToDoReplayDetection {
              get { return SR.GetResourceString("NoSignatureAvailableInSecurityHeaderToDoReplayDetection", null); }
        }
        internal static string CouldNotFindNamespaceForPrefix {
              get { return SR.GetResourceString("CouldNotFindNamespaceForPrefix", null); }
        }
        internal static string DerivedKeyCannotDeriveFromSecret {
              get { return SR.GetResourceString("DerivedKeyCannotDeriveFromSecret", null); }
        }
        internal static string DerivedKeyPosAndGenBothSpecified {
              get { return SR.GetResourceString("DerivedKeyPosAndGenBothSpecified", null); }
        }
        internal static string DerivedKeyPosAndGenNotSpecified {
              get { return SR.GetResourceString("DerivedKeyPosAndGenNotSpecified", null); }
        }
        internal static string DerivedKeyTokenRequiresTokenReference {
              get { return SR.GetResourceString("DerivedKeyTokenRequiresTokenReference", null); }
        }
        internal static string DerivedKeyLengthTooLong {
              get { return SR.GetResourceString("DerivedKeyLengthTooLong", null); }
        }
        internal static string DerivedKeyLengthSpecifiedInImplicitDerivedKeyClauseTooLong {
              get { return SR.GetResourceString("DerivedKeyLengthSpecifiedInImplicitDerivedKeyClauseTooLong", null); }
        }
        internal static string DerivedKeyInvalidOffsetSpecified {
              get { return SR.GetResourceString("DerivedKeyInvalidOffsetSpecified", null); }
        }
        internal static string DerivedKeyInvalidGenerationSpecified {
              get { return SR.GetResourceString("DerivedKeyInvalidGenerationSpecified", null); }
        }
        internal static string ChildNodeTypeMissing {
              get { return SR.GetResourceString("ChildNodeTypeMissing", null); }
        }
        internal static string NoLicenseXml {
              get { return SR.GetResourceString("NoLicenseXml", null); }
        }
        internal static string UnsupportedBinaryEncoding {
              get { return SR.GetResourceString("UnsupportedBinaryEncoding", null); }
        }
        internal static string BadKeyEncryptionAlgorithm {
              get { return SR.GetResourceString("BadKeyEncryptionAlgorithm", null); }
        }
        internal static string SPS_InvalidAsyncResult {
              get { return SR.GetResourceString("SPS_InvalidAsyncResult", null); }
        }
        internal static string UnableToCreateTokenReference {
              get { return SR.GetResourceString("UnableToCreateTokenReference", null); }
        }
        internal static string NonceLengthTooShort {
              get { return SR.GetResourceString("NonceLengthTooShort", null); }
        }
        internal static string NoBinaryNegoToSend {
              get { return SR.GetResourceString("NoBinaryNegoToSend", null); }
        }
        internal static string BadSecurityNegotiationContext {
              get { return SR.GetResourceString("BadSecurityNegotiationContext", null); }
        }
        internal static string NoBinaryNegoToReceive {
              get { return SR.GetResourceString("NoBinaryNegoToReceive", null); }
        }
        internal static string ProofTokenWasNotWrappedCorrectly {
              get { return SR.GetResourceString("ProofTokenWasNotWrappedCorrectly", null); }
        }
        internal static string NoServiceTokenReceived {
              get { return SR.GetResourceString("NoServiceTokenReceived", null); }
        }
        internal static string InvalidSspiNegotiation {
              get { return SR.GetResourceString("InvalidSspiNegotiation", null); }
        }
        internal static string CannotAuthenticateServer {
              get { return SR.GetResourceString("CannotAuthenticateServer", null); }
        }
        internal static string IncorrectBinaryNegotiationValueType {
              get { return SR.GetResourceString("IncorrectBinaryNegotiationValueType", null); }
        }
        internal static string ChannelNotOpen {
              get { return SR.GetResourceString("ChannelNotOpen", null); }
        }
        internal static string FailToRecieveReplyFromNegotiation {
              get { return SR.GetResourceString("FailToRecieveReplyFromNegotiation", null); }
        }
        internal static string MessageSecurityVersionOutOfRange {
              get { return SR.GetResourceString("MessageSecurityVersionOutOfRange", null); }
        }
        internal static string CreationTimeUtcIsAfterExpiryTime {
              get { return SR.GetResourceString("CreationTimeUtcIsAfterExpiryTime", null); }
        }
        internal static string NegotiationStateAlreadyPresent {
              get { return SR.GetResourceString("NegotiationStateAlreadyPresent", null); }
        }
        internal static string CannotFindNegotiationState {
              get { return SR.GetResourceString("CannotFindNegotiationState", null); }
        }
        internal static string OutputNotExpected {
              get { return SR.GetResourceString("OutputNotExpected", null); }
        }
        internal static string SessionClosedBeforeDone {
              get { return SR.GetResourceString("SessionClosedBeforeDone", null); }
        }
        internal static string CacheQuotaReached {
              get { return SR.GetResourceString("CacheQuotaReached", null); }
        }
        internal static string NoServerX509TokenProvider {
              get { return SR.GetResourceString("NoServerX509TokenProvider", null); }
        }
        internal static string UnexpectedBinarySecretType {
              get { return SR.GetResourceString("UnexpectedBinarySecretType", null); }
        }
        internal static string UnsupportedPasswordType {
              get { return SR.GetResourceString("UnsupportedPasswordType", null); }
        }
        internal static string UnrecognizedIdentityPropertyType {
              get { return SR.GetResourceString("UnrecognizedIdentityPropertyType", null); }
        }
        internal static string UnableToDemuxChannel {
              get { return SR.GetResourceString("UnableToDemuxChannel", null); }
        }
        internal static string EndpointNotFound {
              get { return SR.GetResourceString("EndpointNotFound", null); }
        }
        internal static string MaxReceivedMessageSizeMustBeInIntegerRange {
              get { return SR.GetResourceString("MaxReceivedMessageSizeMustBeInIntegerRange", null); }
        }
        internal static string MaxBufferSizeMustMatchMaxReceivedMessageSize {
              get { return SR.GetResourceString("MaxBufferSizeMustMatchMaxReceivedMessageSize", null); }
        }
        internal static string MaxBufferSizeMustNotExceedMaxReceivedMessageSize {
              get { return SR.GetResourceString("MaxBufferSizeMustNotExceedMaxReceivedMessageSize", null); }
        }
        internal static string MessageSizeMustBeInIntegerRange {
              get { return SR.GetResourceString("MessageSizeMustBeInIntegerRange", null); }
        }
        internal static string UriLengthExceedsMaxSupportedSize {
              get { return SR.GetResourceString("UriLengthExceedsMaxSupportedSize", null); }
        }
        internal static string InValidateIdPrefix {
              get { return SR.GetResourceString("InValidateIdPrefix", null); }
        }
        internal static string InValidateId {
              get { return SR.GetResourceString("InValidateId", null); }
        }
        internal static string HttpRegistrationAlreadyExists {
              get { return SR.GetResourceString("HttpRegistrationAlreadyExists", null); }
        }
        internal static string HttpRegistrationAccessDenied {
              get { return SR.GetResourceString("HttpRegistrationAccessDenied", null); }
        }
        internal static string HttpRegistrationPortInUse {
              get { return SR.GetResourceString("HttpRegistrationPortInUse", null); }
        }
        internal static string HttpRegistrationLimitExceeded {
              get { return SR.GetResourceString("HttpRegistrationLimitExceeded", null); }
        }
        internal static string UnexpectedHttpResponseCode {
              get { return SR.GetResourceString("UnexpectedHttpResponseCode", null); }
        }
        internal static string HttpContentLengthIncorrect {
              get { return SR.GetResourceString("HttpContentLengthIncorrect", null); }
        }
        internal static string OneWayUnexpectedResponse {
              get { return SR.GetResourceString("OneWayUnexpectedResponse", null); }
        }
        internal static string MissingContentType {
              get { return SR.GetResourceString("MissingContentType", null); }
        }
        internal static string DuplexChannelAbortedDuringOpen {
              get { return SR.GetResourceString("DuplexChannelAbortedDuringOpen", null); }
        }
        internal static string OperationAbortedDuringConnectionEstablishment {
              get { return SR.GetResourceString("OperationAbortedDuringConnectionEstablishment", null); }
        }
        internal static string HttpAddressingNoneHeaderOnWire {
              get { return SR.GetResourceString("HttpAddressingNoneHeaderOnWire", null); }
        }
        internal static string MessageXmlProtocolError {
              get { return SR.GetResourceString("MessageXmlProtocolError", null); }
        }
        internal static string TcpV4AddressInvalid {
              get { return SR.GetResourceString("TcpV4AddressInvalid", null); }
        }
        internal static string TcpV6AddressInvalid {
              get { return SR.GetResourceString("TcpV6AddressInvalid", null); }
        }
        internal static string UniquePortNotAvailable {
              get { return SR.GetResourceString("UniquePortNotAvailable", null); }
        }
        internal static string TcpAddressInUse {
              get { return SR.GetResourceString("TcpAddressInUse", null); }
        }
        internal static string TcpConnectNoBufs {
              get { return SR.GetResourceString("TcpConnectNoBufs", null); }
        }
        internal static string InsufficentMemory {
              get { return SR.GetResourceString("InsufficentMemory", null); }
        }
        internal static string TcpConnectError {
              get { return SR.GetResourceString("TcpConnectError", null); }
        }
        internal static string TcpConnectErrorWithTimeSpan {
              get { return SR.GetResourceString("TcpConnectErrorWithTimeSpan", null); }
        }
        internal static string TcpListenError {
              get { return SR.GetResourceString("TcpListenError", null); }
        }
        internal static string TcpTransferError {
              get { return SR.GetResourceString("TcpTransferError", null); }
        }
        internal static string TcpTransferErrorWithIP {
              get { return SR.GetResourceString("TcpTransferErrorWithIP", null); }
        }
        internal static string TcpLocalConnectionAborted {
              get { return SR.GetResourceString("TcpLocalConnectionAborted", null); }
        }
        internal static string HttpResponseAborted {
              get { return SR.GetResourceString("HttpResponseAborted", null); }
        }
        internal static string TcpConnectionResetError {
              get { return SR.GetResourceString("TcpConnectionResetError", null); }
        }
        internal static string TcpConnectionResetErrorWithIP {
              get { return SR.GetResourceString("TcpConnectionResetErrorWithIP", null); }
        }
        internal static string TcpConnectionTimedOut {
              get { return SR.GetResourceString("TcpConnectionTimedOut", null); }
        }
        internal static string TcpConnectionTimedOutWithIP {
              get { return SR.GetResourceString("TcpConnectionTimedOutWithIP", null); }
        }
        internal static string SocketConnectionDisposed {
              get { return SR.GetResourceString("SocketConnectionDisposed", null); }
        }
        internal static string SocketListenerDisposed {
              get { return SR.GetResourceString("SocketListenerDisposed", null); }
        }
        internal static string SocketListenerNotListening {
              get { return SR.GetResourceString("SocketListenerNotListening", null); }
        }
        internal static string DuplexSessionListenerNotFound {
              get { return SR.GetResourceString("DuplexSessionListenerNotFound", null); }
        }
        internal static string HttpTargetNameDictionaryConflict {
              get { return SR.GetResourceString("HttpTargetNameDictionaryConflict", null); }
        }
        internal static string HttpContentTypeHeaderRequired {
              get { return SR.GetResourceString("HttpContentTypeHeaderRequired", null); }
        }
        internal static string ContentTypeMismatch {
              get { return SR.GetResourceString("ContentTypeMismatch", null); }
        }
        internal static string ResponseContentTypeMismatch {
              get { return SR.GetResourceString("ResponseContentTypeMismatch", null); }
        }
        internal static string ResponseContentTypeNotSupported {
              get { return SR.GetResourceString("ResponseContentTypeNotSupported", null); }
        }
        internal static string HttpToMustEqualVia {
              get { return SR.GetResourceString("HttpToMustEqualVia", null); }
        }
        internal static string NullReferenceOnHttpResponse {
              get { return SR.GetResourceString("NullReferenceOnHttpResponse", null); }
        }
        internal static string FramingContentTypeMismatch {
              get { return SR.GetResourceString("FramingContentTypeMismatch", null); }
        }
        internal static string FramingFaultUnrecognized {
              get { return SR.GetResourceString("FramingFaultUnrecognized", null); }
        }
        internal static string FramingContentTypeTooLongFault {
              get { return SR.GetResourceString("FramingContentTypeTooLongFault", null); }
        }
        internal static string FramingViaTooLongFault {
              get { return SR.GetResourceString("FramingViaTooLongFault", null); }
        }
        internal static string FramingModeNotSupportedFault {
              get { return SR.GetResourceString("FramingModeNotSupportedFault", null); }
        }
        internal static string FramingVersionNotSupportedFault {
              get { return SR.GetResourceString("FramingVersionNotSupportedFault", null); }
        }
        internal static string FramingUpgradeInvalid {
              get { return SR.GetResourceString("FramingUpgradeInvalid", null); }
        }
        internal static string SecurityServerTooBusy {
              get { return SR.GetResourceString("SecurityServerTooBusy", null); }
        }
        internal static string SecurityEndpointNotFound {
              get { return SR.GetResourceString("SecurityEndpointNotFound", null); }
        }
        internal static string ServerTooBusy {
              get { return SR.GetResourceString("ServerTooBusy", null); }
        }
        internal static string UpgradeProtocolNotSupported {
              get { return SR.GetResourceString("UpgradeProtocolNotSupported", null); }
        }
        internal static string UpgradeRequestToNonupgradableService {
              get { return SR.GetResourceString("UpgradeRequestToNonupgradableService", null); }
        }
        internal static string PreambleAckIncorrect {
              get { return SR.GetResourceString("PreambleAckIncorrect", null); }
        }
        internal static string PreambleAckIncorrectMaybeHttp {
              get { return SR.GetResourceString("PreambleAckIncorrectMaybeHttp", null); }
        }
        internal static string StreamError {
              get { return SR.GetResourceString("StreamError", null); }
        }
        internal static string ServerRejectedUpgradeRequest {
              get { return SR.GetResourceString("ServerRejectedUpgradeRequest", null); }
        }
        internal static string ServerRejectedSessionPreamble {
              get { return SR.GetResourceString("ServerRejectedSessionPreamble", null); }
        }
        internal static string UnableToResolveHost {
              get { return SR.GetResourceString("UnableToResolveHost", null); }
        }
        internal static string HttpRequiresSingleAuthScheme {
              get { return SR.GetResourceString("HttpRequiresSingleAuthScheme", null); }
        }
        internal static string HttpAuthSchemeCannotBeNone {
              get { return SR.GetResourceString("HttpAuthSchemeCannotBeNone", null); }
        }
        internal static string HttpProxyRequiresSingleAuthScheme {
              get { return SR.GetResourceString("HttpProxyRequiresSingleAuthScheme", null); }
        }
        internal static string HttpMutualAuthNotSatisfied {
              get { return SR.GetResourceString("HttpMutualAuthNotSatisfied", null); }
        }
        internal static string HttpAuthorizationFailed {
              get { return SR.GetResourceString("HttpAuthorizationFailed", null); }
        }
        internal static string HttpAuthenticationFailed {
              get { return SR.GetResourceString("HttpAuthenticationFailed", null); }
        }
        internal static string HttpAuthorizationForbidden {
              get { return SR.GetResourceString("HttpAuthorizationForbidden", null); }
        }
        internal static string InvalidUriScheme {
              get { return SR.GetResourceString("InvalidUriScheme", null); }
        }
        internal static string HttpAuthSchemeAndClientCert {
              get { return SR.GetResourceString("HttpAuthSchemeAndClientCert", null); }
        }
        internal static string NoTransportManagerForUri {
              get { return SR.GetResourceString("NoTransportManagerForUri", null); }
        }
        internal static string ListenerFactoryNotRegistered {
              get { return SR.GetResourceString("ListenerFactoryNotRegistered", null); }
        }
        internal static string HttpsExplicitIdentity {
              get { return SR.GetResourceString("HttpsExplicitIdentity", null); }
        }
        internal static string HttpsIdentityMultipleCerts {
              get { return SR.GetResourceString("HttpsIdentityMultipleCerts", null); }
        }
        internal static string HttpsServerCertThumbprintMismatch {
              get { return SR.GetResourceString("HttpsServerCertThumbprintMismatch", null); }
        }
        internal static string DuplicateRegistration {
              get { return SR.GetResourceString("DuplicateRegistration", null); }
        }
        internal static string SecureChannelFailure {
              get { return SR.GetResourceString("SecureChannelFailure", null); }
        }
        internal static string TrustFailure {
              get { return SR.GetResourceString("TrustFailure", null); }
        }
        internal static string NoCompatibleTransportManagerForUri {
              get { return SR.GetResourceString("NoCompatibleTransportManagerForUri", null); }
        }
        internal static string HttpSpnNotFound {
              get { return SR.GetResourceString("HttpSpnNotFound", null); }
        }
        internal static string StreamMutualAuthNotSatisfied {
              get { return SR.GetResourceString("StreamMutualAuthNotSatisfied", null); }
        }
        internal static string TransferModeNotSupported {
              get { return SR.GetResourceString("TransferModeNotSupported", null); }
        }
        internal static string InvalidTokenProvided {
              get { return SR.GetResourceString("InvalidTokenProvided", null); }
        }
        internal static string NoUserNameTokenProvided {
              get { return SR.GetResourceString("NoUserNameTokenProvided", null); }
        }
        internal static string RemoteIdentityFailedVerification {
              get { return SR.GetResourceString("RemoteIdentityFailedVerification", null); }
        }
        internal static string UseDefaultWebProxyCantBeUsedWithExplicitProxyAddress {
              get { return SR.GetResourceString("UseDefaultWebProxyCantBeUsedWithExplicitProxyAddress", null); }
        }
        internal static string ProxyImpersonationLevelMismatch {
              get { return SR.GetResourceString("ProxyImpersonationLevelMismatch", null); }
        }
        internal static string ProxyAuthenticationLevelMismatch {
              get { return SR.GetResourceString("ProxyAuthenticationLevelMismatch", null); }
        }
        internal static string CredentialDisallowsNtlm {
              get { return SR.GetResourceString("CredentialDisallowsNtlm", null); }
        }
        internal static string DigestExplicitCredsImpersonationLevel {
              get { return SR.GetResourceString("DigestExplicitCredsImpersonationLevel", null); }
        }
        internal static string UriGeneratorSchemeMustNotBeEmpty {
              get { return SR.GetResourceString("UriGeneratorSchemeMustNotBeEmpty", null); }
        }
        internal static string UnsupportedSslProtectionLevel {
              get { return SR.GetResourceString("UnsupportedSslProtectionLevel", null); }
        }
        internal static string HttpNoTrackingService {
              get { return SR.GetResourceString("HttpNoTrackingService", null); }
        }
        internal static string HttpNetnameDeleted {
              get { return SR.GetResourceString("HttpNetnameDeleted", null); }
        }
        internal static string TimeoutServiceChannelConcurrentOpen1 {
              get { return SR.GetResourceString("TimeoutServiceChannelConcurrentOpen1", null); }
        }
        internal static string TimeoutServiceChannelConcurrentOpen2 {
              get { return SR.GetResourceString("TimeoutServiceChannelConcurrentOpen2", null); }
        }
        internal static string TimeSpanMustbeGreaterThanTimeSpanZero {
              get { return SR.GetResourceString("TimeSpanMustbeGreaterThanTimeSpanZero", null); }
        }
        internal static string TimeSpanCannotBeLessThanTimeSpanZero {
              get { return SR.GetResourceString("TimeSpanCannotBeLessThanTimeSpanZero", null); }
        }
        internal static string ValueMustBeNonNegative {
              get { return SR.GetResourceString("ValueMustBeNonNegative", null); }
        }
        internal static string ValueMustBePositive {
              get { return SR.GetResourceString("ValueMustBePositive", null); }
        }
        internal static string ValueMustBeGreaterThanZero {
              get { return SR.GetResourceString("ValueMustBeGreaterThanZero", null); }
        }
        internal static string ValueMustBeInRange {
              get { return SR.GetResourceString("ValueMustBeInRange", null); }
        }
        internal static string OffsetExceedsBufferBound {
              get { return SR.GetResourceString("OffsetExceedsBufferBound", null); }
        }
        internal static string OffsetExceedsBufferSize {
              get { return SR.GetResourceString("OffsetExceedsBufferSize", null); }
        }
        internal static string SizeExceedsRemainingBufferSpace {
              get { return SR.GetResourceString("SizeExceedsRemainingBufferSpace", null); }
        }
        internal static string SpaceNeededExceedsMessageFrameOffset {
              get { return SR.GetResourceString("SpaceNeededExceedsMessageFrameOffset", null); }
        }
        internal static string FaultConverterDidNotCreateFaultMessage {
              get { return SR.GetResourceString("FaultConverterDidNotCreateFaultMessage", null); }
        }
        internal static string FaultConverterCreatedFaultMessage {
              get { return SR.GetResourceString("FaultConverterCreatedFaultMessage", null); }
        }
        internal static string FaultConverterDidNotCreateException {
              get { return SR.GetResourceString("FaultConverterDidNotCreateException", null); }
        }
        internal static string FaultConverterCreatedException {
              get { return SR.GetResourceString("FaultConverterCreatedException", null); }
        }
        internal static string InfoCardInvalidChain {
              get { return SR.GetResourceString("InfoCardInvalidChain", null); }
        }
        internal static string FullTrustOnlyBindingElementSecurityCheck1 {
              get { return SR.GetResourceString("FullTrustOnlyBindingElementSecurityCheck1", null); }
        }
        internal static string FullTrustOnlyBindingElementSecurityCheckWSHttpBinding1 {
              get { return SR.GetResourceString("FullTrustOnlyBindingElementSecurityCheckWSHttpBinding1", null); }
        }
        internal static string FullTrustOnlyBindingSecurityCheck1 {
              get { return SR.GetResourceString("FullTrustOnlyBindingSecurityCheck1", null); }
        }
        internal static string PartialTrustServiceCtorNotVisible {
              get { return SR.GetResourceString("PartialTrustServiceCtorNotVisible", null); }
        }
        internal static string PartialTrustServiceMethodNotVisible {
              get { return SR.GetResourceString("PartialTrustServiceMethodNotVisible", null); }
        }
        internal static string PartialTrustPerformanceCountersNotEnabled {
              get { return SR.GetResourceString("PartialTrustPerformanceCountersNotEnabled", null); }
        }
        internal static string PartialTrustWMINotEnabled {
              get { return SR.GetResourceString("PartialTrustWMINotEnabled", null); }
        }
        internal static string PartialTrustMessageLoggingNotEnabled {
              get { return SR.GetResourceString("PartialTrustMessageLoggingNotEnabled", null); }
        }
        internal static string ScopeNameMustBeSpecified {
              get { return SR.GetResourceString("ScopeNameMustBeSpecified", null); }
        }
        internal static string ProviderCannotBeEmptyString {
              get { return SR.GetResourceString("ProviderCannotBeEmptyString", null); }
        }
        internal static string CannotSetNameOnTheInvalidKey {
              get { return SR.GetResourceString("CannotSetNameOnTheInvalidKey", null); }
        }
        internal static string UnsupportedMessageQueryResultType {
              get { return SR.GetResourceString("UnsupportedMessageQueryResultType", null); }
        }
        internal static string CannotRepresentResultAsNodeset {
              get { return SR.GetResourceString("CannotRepresentResultAsNodeset", null); }
        }
        internal static string MessageNotInLockedState {
              get { return SR.GetResourceString("MessageNotInLockedState", null); }
        }
        internal static string MessageValidityExpired {
              get { return SR.GetResourceString("MessageValidityExpired", null); }
        }
        internal static string UnsupportedUpgradeInitiator {
              get { return SR.GetResourceString("UnsupportedUpgradeInitiator", null); }
        }
        internal static string UnsupportedUpgradeAcceptor {
              get { return SR.GetResourceString("UnsupportedUpgradeAcceptor", null); }
        }
        internal static string StreamUpgradeUnsupportedChannelBindingKind {
              get { return SR.GetResourceString("StreamUpgradeUnsupportedChannelBindingKind", null); }
        }
        internal static string ExtendedProtectionNotSupported {
              get { return SR.GetResourceString("ExtendedProtectionNotSupported", null); }
        }
        internal static string ExtendedProtectionPolicyBasicAuthNotSupported {
              get { return SR.GetResourceString("ExtendedProtectionPolicyBasicAuthNotSupported", null); }
        }
        internal static string ExtendedProtectionPolicyCustomChannelBindingNotSupported {
              get { return SR.GetResourceString("ExtendedProtectionPolicyCustomChannelBindingNotSupported", null); }
        }
        internal static string HttpClientCredentialTypeInvalid {
              get { return SR.GetResourceString("HttpClientCredentialTypeInvalid", null); }
        }
        internal static string SecurityTokenProviderIncludeWindowsGroupsInconsistent {
              get { return SR.GetResourceString("SecurityTokenProviderIncludeWindowsGroupsInconsistent", null); }
        }
        internal static string AuthenticationSchemesCannotBeInheritedFromHost {
              get { return SR.GetResourceString("AuthenticationSchemesCannotBeInheritedFromHost", null); }
        }
        internal static string AuthenticationSchemes_BindingAndHostConflict {
              get { return SR.GetResourceString("AuthenticationSchemes_BindingAndHostConflict", null); }
        }
        internal static string FlagEnumTypeExpected {
              get { return SR.GetResourceString("FlagEnumTypeExpected", null); }
        }
        internal static string InvalidFlagEnumType {
              get { return SR.GetResourceString("InvalidFlagEnumType", null); }
        }
        internal static string NoAsyncWritePending {
              get { return SR.GetResourceString("NoAsyncWritePending", null); }
        }
        internal static string FlushBufferAlreadyInUse {
              get { return SR.GetResourceString("FlushBufferAlreadyInUse", null); }
        }
        internal static string WriteAsyncWithoutFreeBuffer {
              get { return SR.GetResourceString("WriteAsyncWithoutFreeBuffer", null); }
        }
        internal static string TransportDoesNotSupportCompression {
              get { return SR.GetResourceString("TransportDoesNotSupportCompression", null); }
        }
        internal static string UnsupportedSecuritySetting {
              get { return SR.GetResourceString("UnsupportedSecuritySetting", null); }
        }
        internal static string UnsupportedBindingProperty {
              get { return SR.GetResourceString("UnsupportedBindingProperty", null); }
        }
        internal static string HttpMaxPendingAcceptsTooLargeError {
              get { return SR.GetResourceString("HttpMaxPendingAcceptsTooLargeError", null); }
        }
        internal static string RequestInitializationTimeoutReached {
              get { return SR.GetResourceString("RequestInitializationTimeoutReached", null); }
        }
        internal static string UnsupportedTokenImpersonationLevel {
              get { return SR.GetResourceString("UnsupportedTokenImpersonationLevel", null); }
        }
        internal static string AcksToMustBeSameAsRemoteAddress {
              get { return SR.GetResourceString("AcksToMustBeSameAsRemoteAddress", null); }
        }
        internal static string AcksToMustBeSameAsRemoteAddressReason {
              get { return SR.GetResourceString("AcksToMustBeSameAsRemoteAddressReason", null); }
        }
        internal static string AssertionNotSupported {
              get { return SR.GetResourceString("AssertionNotSupported", null); }
        }
        internal static string ConflictingOffer {
              get { return SR.GetResourceString("ConflictingOffer", null); }
        }
        internal static string CouldNotParseWithAction {
              get { return SR.GetResourceString("CouldNotParseWithAction", null); }
        }
        internal static string CSRefusedDuplexNoOffer {
              get { return SR.GetResourceString("CSRefusedDuplexNoOffer", null); }
        }
        internal static string CSRefusedInputOffer {
              get { return SR.GetResourceString("CSRefusedInputOffer", null); }
        }
        internal static string CSRefusedReplyNoOffer {
              get { return SR.GetResourceString("CSRefusedReplyNoOffer", null); }
        }
        internal static string CSRefusedUnexpectedElementAtEndOfCSMessage {
              get { return SR.GetResourceString("CSRefusedUnexpectedElementAtEndOfCSMessage", null); }
        }
        internal static string CSResponseOfferRejected {
              get { return SR.GetResourceString("CSResponseOfferRejected", null); }
        }
        internal static string CSResponseOfferRejectedReason {
              get { return SR.GetResourceString("CSResponseOfferRejectedReason", null); }
        }
        internal static string CSResponseWithOfferReason {
              get { return SR.GetResourceString("CSResponseWithOfferReason", null); }
        }
        internal static string CSResponseWithoutOfferReason {
              get { return SR.GetResourceString("CSResponseWithoutOfferReason", null); }
        }
        internal static string DeliveryAssuranceRequiredNothingFound {
              get { return SR.GetResourceString("DeliveryAssuranceRequiredNothingFound", null); }
        }
        internal static string DeliveryAssuranceRequired {
              get { return SR.GetResourceString("DeliveryAssuranceRequired", null); }
        }
        internal static string EarlyTerminateSequence {
              get { return SR.GetResourceString("EarlyTerminateSequence", null); }
        }
        internal static string ElementFound {
              get { return SR.GetResourceString("ElementFound", null); }
        }
        internal static string ElementRequired {
              get { return SR.GetResourceString("ElementRequired", null); }
        }
        internal static string InvalidAcknowledgementFaultReason {
              get { return SR.GetResourceString("InvalidAcknowledgementFaultReason", null); }
        }
        internal static string InvalidWsrmResponseChannelNotOpened {
              get { return SR.GetResourceString("InvalidWsrmResponseChannelNotOpened", null); }
        }
        internal static string InvalidWsrmResponseSessionFaultedExceptionString {
              get { return SR.GetResourceString("InvalidWsrmResponseSessionFaultedExceptionString", null); }
        }
        internal static string LastMessageNumberExceededFaultReason {
              get { return SR.GetResourceString("LastMessageNumberExceededFaultReason", null); }
        }
        internal static string ManualAddressingNotSupported {
              get { return SR.GetResourceString("ManualAddressingNotSupported", null); }
        }
        internal static string MessageExceptionOccurred {
              get { return SR.GetResourceString("MessageExceptionOccurred", null); }
        }
        internal static string MessageNumberRolloverFaultReason {
              get { return SR.GetResourceString("MessageNumberRolloverFaultReason", null); }
        }
        internal static string MissingMessageIdOnWsrmRequest {
              get { return SR.GetResourceString("MissingMessageIdOnWsrmRequest", null); }
        }
        internal static string MissingReplyToOnWsrmRequest {
              get { return SR.GetResourceString("MissingReplyToOnWsrmRequest", null); }
        }
        internal static string NonWsrmFeb2005ActionNotSupported {
              get { return SR.GetResourceString("NonWsrmFeb2005ActionNotSupported", null); }
        }
        internal static string ReceivedResponseBeforeRequestFaultString {
              get { return SR.GetResourceString("ReceivedResponseBeforeRequestFaultString", null); }
        }
        internal static string RMEndpointNotFoundReason {
              get { return SR.GetResourceString("RMEndpointNotFoundReason", null); }
        }
        internal static string SequenceClosedFaultString {
              get { return SR.GetResourceString("SequenceClosedFaultString", null); }
        }
        internal static string SequenceTerminatedAddLastToWindowTimedOut {
              get { return SR.GetResourceString("SequenceTerminatedAddLastToWindowTimedOut", null); }
        }
        internal static string SequenceTerminatedBeforeReplySequenceAcked {
              get { return SR.GetResourceString("SequenceTerminatedBeforeReplySequenceAcked", null); }
        }
        internal static string SequenceTerminatedEarlyTerminateSequence {
              get { return SR.GetResourceString("SequenceTerminatedEarlyTerminateSequence", null); }
        }
        internal static string SequenceTerminatedInactivityTimeoutExceeded {
              get { return SR.GetResourceString("SequenceTerminatedInactivityTimeoutExceeded", null); }
        }
        internal static string SequenceTerminatedMaximumRetryCountExceeded {
              get { return SR.GetResourceString("SequenceTerminatedMaximumRetryCountExceeded", null); }
        }
        internal static string SequenceTerminatedQuotaExceededException {
              get { return SR.GetResourceString("SequenceTerminatedQuotaExceededException", null); }
        }
        internal static string SequenceTerminatedReplyMissingAcknowledgement {
              get { return SR.GetResourceString("SequenceTerminatedReplyMissingAcknowledgement", null); }
        }
        internal static string SequenceTerminatedNotAllRepliesAcknowledged {
              get { return SR.GetResourceString("SequenceTerminatedNotAllRepliesAcknowledged", null); }
        }
        internal static string SequenceTerminatedSmallLastMsgNumber {
              get { return SR.GetResourceString("SequenceTerminatedSmallLastMsgNumber", null); }
        }
        internal static string SequenceTerminatedUnexpectedAcknowledgement {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedAcknowledgement", null); }
        }
        internal static string SequenceTerminatedUnexpectedAckRequested {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedAckRequested", null); }
        }
        internal static string SequenceTerminatedUnexpectedCloseSequence {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCloseSequence", null); }
        }
        internal static string SequenceTerminatedUnexpectedCloseSequenceResponse {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCloseSequenceResponse", null); }
        }
        internal static string SequenceTerminatedUnexpectedCS {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCS", null); }
        }
        internal static string SequenceTerminatedUnexpectedCSOfferId {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCSOfferId", null); }
        }
        internal static string SequenceTerminatedUnexpectedCSR {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCSR", null); }
        }
        internal static string SequenceTerminatedUnexpectedCSROfferId {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCSROfferId", null); }
        }
        internal static string SequenceTerminatedUnexpectedTerminateSequence {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedTerminateSequence", null); }
        }
        internal static string SequenceTerminatedUnexpectedTerminateSequenceResponse {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedTerminateSequenceResponse", null); }
        }
        internal static string SequenceTerminatedUnsupportedTerminateSequence {
              get { return SR.GetResourceString("SequenceTerminatedUnsupportedTerminateSequence", null); }
        }
        internal static string SequenceTerminatedUnknownAddToWindowError {
              get { return SR.GetResourceString("SequenceTerminatedUnknownAddToWindowError", null); }
        }
        internal static string TimeoutOnAddToWindow {
              get { return SR.GetResourceString("TimeoutOnAddToWindow", null); }
        }
        internal static string TimeoutOnClose {
              get { return SR.GetResourceString("TimeoutOnClose", null); }
        }
        internal static string TimeoutOnOpen {
              get { return SR.GetResourceString("TimeoutOnOpen", null); }
        }
        internal static string TimeoutOnOperation {
              get { return SR.GetResourceString("TimeoutOnOperation", null); }
        }
        internal static string TimeoutOnRequest {
              get { return SR.GetResourceString("TimeoutOnRequest", null); }
        }
        internal static string TimeoutOnSend {
              get { return SR.GetResourceString("TimeoutOnSend", null); }
        }
        internal static string UnexpectedAcknowledgement {
              get { return SR.GetResourceString("UnexpectedAcknowledgement", null); }
        }
        internal static string UnexpectedAckRequested {
              get { return SR.GetResourceString("UnexpectedAckRequested", null); }
        }
        internal static string UnexpectedCloseSequence {
              get { return SR.GetResourceString("UnexpectedCloseSequence", null); }
        }
        internal static string UnexpectedCloseSequenceResponse {
              get { return SR.GetResourceString("UnexpectedCloseSequenceResponse", null); }
        }
        internal static string UnexpectedCS {
              get { return SR.GetResourceString("UnexpectedCS", null); }
        }
        internal static string UnexpectedCSR {
              get { return SR.GetResourceString("UnexpectedCSR", null); }
        }
        internal static string UnexpectedCSOfferId {
              get { return SR.GetResourceString("UnexpectedCSOfferId", null); }
        }
        internal static string UnexpectedCSROfferId {
              get { return SR.GetResourceString("UnexpectedCSROfferId", null); }
        }
        internal static string UnexpectedTerminateSequence {
              get { return SR.GetResourceString("UnexpectedTerminateSequence", null); }
        }
        internal static string UnexpectedTerminateSequenceResponse {
              get { return SR.GetResourceString("UnexpectedTerminateSequenceResponse", null); }
        }
        internal static string UnparsableCSResponse {
              get { return SR.GetResourceString("UnparsableCSResponse", null); }
        }
        internal static string UnknownSequenceFaultReason {
              get { return SR.GetResourceString("UnknownSequenceFaultReason", null); }
        }
        internal static string UnknownSequenceMessageReceived {
              get { return SR.GetResourceString("UnknownSequenceMessageReceived", null); }
        }
        internal static string UnrecognizedFaultReceivedOnOpen {
              get { return SR.GetResourceString("UnrecognizedFaultReceivedOnOpen", null); }
        }
        internal static string WsrmFaultReceived {
              get { return SR.GetResourceString("WsrmFaultReceived", null); }
        }
        internal static string WsrmMessageProcessingError {
              get { return SR.GetResourceString("WsrmMessageProcessingError", null); }
        }
        internal static string WsrmMessageWithWrongRelatesToFaultString {
              get { return SR.GetResourceString("WsrmMessageWithWrongRelatesToFaultString", null); }
        }
        internal static string WsrmRequestIncorrectReplyToFaultString {
              get { return SR.GetResourceString("WsrmRequestIncorrectReplyToFaultString", null); }
        }
        internal static string WsrmRequiredFaultString {
              get { return SR.GetResourceString("WsrmRequiredFaultString", null); }
        }
        internal static string SFxActionDemuxerDuplicate {
              get { return SR.GetResourceString("SFxActionDemuxerDuplicate", null); }
        }
        internal static string SFxActionMismatch {
              get { return SR.GetResourceString("SFxActionMismatch", null); }
        }
        internal static string SFxAnonymousTypeNotSupported {
              get { return SR.GetResourceString("SFxAnonymousTypeNotSupported", null); }
        }
        internal static string SFxAsyncResultsDontMatch0 {
              get { return SR.GetResourceString("SFxAsyncResultsDontMatch0", null); }
        }
        internal static string SFXBindingNameCannotBeNullOrEmpty {
              get { return SR.GetResourceString("SFXBindingNameCannotBeNullOrEmpty", null); }
        }
        internal static string SFXUnvalidNamespaceValue {
              get { return SR.GetResourceString("SFXUnvalidNamespaceValue", null); }
        }
        internal static string SFXUnvalidNamespaceParam {
              get { return SR.GetResourceString("SFXUnvalidNamespaceParam", null); }
        }
        internal static string SFXHeaderNameCannotBeNullOrEmpty {
              get { return SR.GetResourceString("SFXHeaderNameCannotBeNullOrEmpty", null); }
        }
        internal static string SFxEndpointNoMatchingScheme {
              get { return SR.GetResourceString("SFxEndpointNoMatchingScheme", null); }
        }
        internal static string SFxBindingSchemeDoesNotMatch {
              get { return SR.GetResourceString("SFxBindingSchemeDoesNotMatch", null); }
        }
        internal static string SFxGetChannelDispatcherDoesNotSupportScheme {
              get { return SR.GetResourceString("SFxGetChannelDispatcherDoesNotSupportScheme", null); }
        }
        internal static string SFxIncorrectMessageVersion {
              get { return SR.GetResourceString("SFxIncorrectMessageVersion", null); }
        }
        internal static string SFxBindingNotSupportedForMetadataHttpGet {
              get { return SR.GetResourceString("SFxBindingNotSupportedForMetadataHttpGet", null); }
        }
        internal static string SFxBadByReferenceParameterMetadata {
              get { return SR.GetResourceString("SFxBadByReferenceParameterMetadata", null); }
        }
        internal static string SFxBadByValueParameterMetadata {
              get { return SR.GetResourceString("SFxBadByValueParameterMetadata", null); }
        }
        internal static string SFxBadMetadataMustBePolicy {
              get { return SR.GetResourceString("SFxBadMetadataMustBePolicy", null); }
        }
        internal static string SFxBadMetadataLocationUri {
              get { return SR.GetResourceString("SFxBadMetadataLocationUri", null); }
        }
        internal static string SFxBadMetadataLocationNoAppropriateBaseAddress {
              get { return SR.GetResourceString("SFxBadMetadataLocationNoAppropriateBaseAddress", null); }
        }
        internal static string SFxBadMetadataDialect {
              get { return SR.GetResourceString("SFxBadMetadataDialect", null); }
        }
        internal static string SFxBadMetadataReference {
              get { return SR.GetResourceString("SFxBadMetadataReference", null); }
        }
        internal static string SFxMaximumResolvedReferencesOutOfRange {
              get { return SR.GetResourceString("SFxMaximumResolvedReferencesOutOfRange", null); }
        }
        internal static string SFxMetadataExchangeClientNoMetadataAddress {
              get { return SR.GetResourceString("SFxMetadataExchangeClientNoMetadataAddress", null); }
        }
        internal static string SFxMetadataExchangeClientCouldNotCreateChannelFactory {
              get { return SR.GetResourceString("SFxMetadataExchangeClientCouldNotCreateChannelFactory", null); }
        }
        internal static string SFxMetadataExchangeClientCouldNotCreateWebRequest {
              get { return SR.GetResourceString("SFxMetadataExchangeClientCouldNotCreateWebRequest", null); }
        }
        internal static string SFxMetadataExchangeClientCouldNotCreateChannelFactoryBadScheme {
              get { return SR.GetResourceString("SFxMetadataExchangeClientCouldNotCreateChannelFactoryBadScheme", null); }
        }
        internal static string SFxBadTransactionProtocols {
              get { return SR.GetResourceString("SFxBadTransactionProtocols", null); }
        }
        internal static string SFxMetadataResolverKnownContractsArgumentCannotBeEmpty {
              get { return SR.GetResourceString("SFxMetadataResolverKnownContractsArgumentCannotBeEmpty", null); }
        }
        internal static string SFxMetadataResolverKnownContractsUniqueQNames {
              get { return SR.GetResourceString("SFxMetadataResolverKnownContractsUniqueQNames", null); }
        }
        internal static string SFxMetadataResolverKnownContractsCannotContainNull {
              get { return SR.GetResourceString("SFxMetadataResolverKnownContractsCannotContainNull", null); }
        }
        internal static string SFxBindingDoesNotHaveATransportBindingElement {
              get { return SR.GetResourceString("SFxBindingDoesNotHaveATransportBindingElement", null); }
        }
        internal static string SFxBindingMustContainTransport2 {
              get { return SR.GetResourceString("SFxBindingMustContainTransport2", null); }
        }
        internal static string SFxBodyCannotBeNull {
              get { return SR.GetResourceString("SFxBodyCannotBeNull", null); }
        }
        internal static string SFxBodyObjectTypeCannotBeInherited {
              get { return SR.GetResourceString("SFxBodyObjectTypeCannotBeInherited", null); }
        }
        internal static string SFxBodyObjectTypeCannotBeInterface {
              get { return SR.GetResourceString("SFxBodyObjectTypeCannotBeInterface", null); }
        }
        internal static string SFxCallbackBehaviorAttributeOnlyOnDuplex {
              get { return SR.GetResourceString("SFxCallbackBehaviorAttributeOnlyOnDuplex", null); }
        }
        internal static string SFxCallbackRequestReplyInOrder1 {
              get { return SR.GetResourceString("SFxCallbackRequestReplyInOrder1", null); }
        }
        internal static string SfxCallbackTypeCannotBeNull {
              get { return SR.GetResourceString("SfxCallbackTypeCannotBeNull", null); }
        }
        internal static string SFxCannotActivateCallbackInstace {
              get { return SR.GetResourceString("SFxCannotActivateCallbackInstace", null); }
        }
        internal static string SFxCannotCallAddBaseAddress {
              get { return SR.GetResourceString("SFxCannotCallAddBaseAddress", null); }
        }
        internal static string SFxCannotCallAutoOpenWhenExplicitOpenCalled {
              get { return SR.GetResourceString("SFxCannotCallAutoOpenWhenExplicitOpenCalled", null); }
        }
        internal static string SFxCannotGetMetadataFromRelativeAddress {
              get { return SR.GetResourceString("SFxCannotGetMetadataFromRelativeAddress", null); }
        }
        internal static string SFxCannotHttpGetMetadataFromAddress {
              get { return SR.GetResourceString("SFxCannotHttpGetMetadataFromAddress", null); }
        }
        internal static string SFxCannotGetMetadataFromLocation {
              get { return SR.GetResourceString("SFxCannotGetMetadataFromLocation", null); }
        }
        internal static string SFxCannotHaveDifferentTransactionProtocolsInOneBinding {
              get { return SR.GetResourceString("SFxCannotHaveDifferentTransactionProtocolsInOneBinding", null); }
        }
        internal static string SFxCannotImportAsParameters_Bare {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_Bare", null); }
        }
        internal static string SFxCannotImportAsParameters_DifferentWrapperNs {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_DifferentWrapperNs", null); }
        }
        internal static string SFxCannotImportAsParameters_DifferentWrapperName {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_DifferentWrapperName", null); }
        }
        internal static string SFxCannotImportAsParameters_ElementIsNotNillable {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_ElementIsNotNillable", null); }
        }
        internal static string SFxCannotImportAsParameters_MessageHasProtectionLevel {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_MessageHasProtectionLevel", null); }
        }
        internal static string SFxCannotImportAsParameters_HeadersAreIgnoredInEncoded {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_HeadersAreIgnoredInEncoded", null); }
        }
        internal static string SFxCannotImportAsParameters_HeadersAreUnsupported {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_HeadersAreUnsupported", null); }
        }
        internal static string SFxCannotImportAsParameters_Message {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_Message", null); }
        }
        internal static string SFxCannotImportAsParameters_NamespaceMismatch {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_NamespaceMismatch", null); }
        }
        internal static string SFxCannotRequireBothSessionAndDatagram3 {
              get { return SR.GetResourceString("SFxCannotRequireBothSessionAndDatagram3", null); }
        }
        internal static string SFxCannotSetExtensionsByIndex {
              get { return SR.GetResourceString("SFxCannotSetExtensionsByIndex", null); }
        }
        internal static string SFxChannelDispatcherDifferentHost0 {
              get { return SR.GetResourceString("SFxChannelDispatcherDifferentHost0", null); }
        }
        internal static string SFxChannelDispatcherMultipleHost0 {
              get { return SR.GetResourceString("SFxChannelDispatcherMultipleHost0", null); }
        }
        internal static string SFxChannelDispatcherNoHost0 {
              get { return SR.GetResourceString("SFxChannelDispatcherNoHost0", null); }
        }
        internal static string SFxChannelDispatcherNoMessageVersion {
              get { return SR.GetResourceString("SFxChannelDispatcherNoMessageVersion", null); }
        }
        internal static string SFxChannelDispatcherUnableToOpen1 {
              get { return SR.GetResourceString("SFxChannelDispatcherUnableToOpen1", null); }
        }
        internal static string SFxChannelDispatcherUnableToOpen2 {
              get { return SR.GetResourceString("SFxChannelDispatcherUnableToOpen2", null); }
        }
        internal static string SFxChannelFactoryTypeMustBeInterface {
              get { return SR.GetResourceString("SFxChannelFactoryTypeMustBeInterface", null); }
        }
        internal static string SFxChannelFactoryCannotApplyConfigurationWithoutEndpoint {
              get { return SR.GetResourceString("SFxChannelFactoryCannotApplyConfigurationWithoutEndpoint", null); }
        }
        internal static string SFxChannelFactoryCannotCreateFactoryWithoutDescription {
              get { return SR.GetResourceString("SFxChannelFactoryCannotCreateFactoryWithoutDescription", null); }
        }
        internal static string SFxClientOutputSessionAutoClosed {
              get { return SR.GetResourceString("SFxClientOutputSessionAutoClosed", null); }
        }
        internal static string SFxCodeGenArrayTypeIsNotSupported {
              get { return SR.GetResourceString("SFxCodeGenArrayTypeIsNotSupported", null); }
        }
        internal static string SFxCodeGenCanOnlyStoreIntoArgOrLocGot0 {
              get { return SR.GetResourceString("SFxCodeGenCanOnlyStoreIntoArgOrLocGot0", null); }
        }
        internal static string SFxCodeGenExpectingEnd {
              get { return SR.GetResourceString("SFxCodeGenExpectingEnd", null); }
        }
        internal static string SFxCodeGenIsNotAssignableFrom {
              get { return SR.GetResourceString("SFxCodeGenIsNotAssignableFrom", null); }
        }
        internal static string SFxCodeGenNoConversionPossibleTo {
              get { return SR.GetResourceString("SFxCodeGenNoConversionPossibleTo", null); }
        }
        internal static string SFxCodeGenWarning {
              get { return SR.GetResourceString("SFxCodeGenWarning", null); }
        }
        internal static string SFxCodeGenUnknownConstantType {
              get { return SR.GetResourceString("SFxCodeGenUnknownConstantType", null); }
        }
        internal static string SFxCollectionDoesNotSupportSet0 {
              get { return SR.GetResourceString("SFxCollectionDoesNotSupportSet0", null); }
        }
        internal static string SFxCollectionReadOnly {
              get { return SR.GetResourceString("SFxCollectionReadOnly", null); }
        }
        internal static string SFxCollectionWrongType2 {
              get { return SR.GetResourceString("SFxCollectionWrongType2", null); }
        }
        internal static string SFxConflictingGlobalElement {
              get { return SR.GetResourceString("SFxConflictingGlobalElement", null); }
        }
        internal static string SFxConflictingGlobalType {
              get { return SR.GetResourceString("SFxConflictingGlobalType", null); }
        }
        internal static string SFxContextModifiedInsideScope0 {
              get { return SR.GetResourceString("SFxContextModifiedInsideScope0", null); }
        }
        internal static string SFxContractDescriptionNameCannotBeEmpty {
              get { return SR.GetResourceString("SFxContractDescriptionNameCannotBeEmpty", null); }
        }
        internal static string SFxContractHasZeroOperations {
              get { return SR.GetResourceString("SFxContractHasZeroOperations", null); }
        }
        internal static string SFxContractHasZeroInitiatingOperations {
              get { return SR.GetResourceString("SFxContractHasZeroInitiatingOperations", null); }
        }
        internal static string SFxContractInheritanceRequiresInterfaces {
              get { return SR.GetResourceString("SFxContractInheritanceRequiresInterfaces", null); }
        }
        internal static string SFxContractInheritanceRequiresInterfaces2 {
              get { return SR.GetResourceString("SFxContractInheritanceRequiresInterfaces2", null); }
        }
        internal static string SFxCopyToRequiresICollection {
              get { return SR.GetResourceString("SFxCopyToRequiresICollection", null); }
        }
        internal static string SFxCreateDuplexChannel1 {
              get { return SR.GetResourceString("SFxCreateDuplexChannel1", null); }
        }
        internal static string SFxCreateDuplexChannelNoCallback {
              get { return SR.GetResourceString("SFxCreateDuplexChannelNoCallback", null); }
        }
        internal static string SFxCreateDuplexChannelNoCallback1 {
              get { return SR.GetResourceString("SFxCreateDuplexChannelNoCallback1", null); }
        }
        internal static string SFxCreateDuplexChannelNoCallbackUserObject {
              get { return SR.GetResourceString("SFxCreateDuplexChannelNoCallbackUserObject", null); }
        }
        internal static string SFxCreateDuplexChannelBadCallbackUserObject {
              get { return SR.GetResourceString("SFxCreateDuplexChannelBadCallbackUserObject", null); }
        }
        internal static string SFxCreateNonDuplexChannel1 {
              get { return SR.GetResourceString("SFxCreateNonDuplexChannel1", null); }
        }
        internal static string SFxCustomBindingNeedsTransport1 {
              get { return SR.GetResourceString("SFxCustomBindingNeedsTransport1", null); }
        }
        internal static string SFxCustomBindingWithoutTransport {
              get { return SR.GetResourceString("SFxCustomBindingWithoutTransport", null); }
        }
        internal static string SFxDeserializationFailed1 {
              get { return SR.GetResourceString("SFxDeserializationFailed1", null); }
        }
        internal static string SFxDictionaryIsEmpty {
              get { return SR.GetResourceString("SFxDictionaryIsEmpty", null); }
        }
        internal static string SFxDisallowedAttributeCombination {
              get { return SR.GetResourceString("SFxDisallowedAttributeCombination", null); }
        }
        internal static string SFxEndpointAddressNotSpecified {
              get { return SR.GetResourceString("SFxEndpointAddressNotSpecified", null); }
        }
        internal static string SFxEndpointContractNotSpecified {
              get { return SR.GetResourceString("SFxEndpointContractNotSpecified", null); }
        }
        internal static string SFxEndpointBindingNotSpecified {
              get { return SR.GetResourceString("SFxEndpointBindingNotSpecified", null); }
        }
        internal static string SFxInitializationUINotCalled {
              get { return SR.GetResourceString("SFxInitializationUINotCalled", null); }
        }
        internal static string SFxInitializationUIDisallowed {
              get { return SR.GetResourceString("SFxInitializationUIDisallowed", null); }
        }
        internal static string SFxDocExt_NoMetadataSection1 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataSection1", null); }
        }
        internal static string SFxDocExt_NoMetadataSection2 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataSection2", null); }
        }
        internal static string SFxDocExt_NoMetadataSection3 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataSection3", null); }
        }
        internal static string SFxDocExt_NoMetadataSection4 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataSection4", null); }
        }
        internal static string SFxDocExt_NoMetadataSection5 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataSection5", null); }
        }
        internal static string SFxDocExt_NoMetadataConfigComment1 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataConfigComment1", null); }
        }
        internal static string SFxDocExt_NoMetadataConfigComment2 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataConfigComment2", null); }
        }
        internal static string SFxDocExt_NoMetadataConfigComment3 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataConfigComment3", null); }
        }
        internal static string SFxDocExt_NoMetadataConfigComment4 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataConfigComment4", null); }
        }
        internal static string SFxDocExt_CS {
              get { return SR.GetResourceString("SFxDocExt_CS", null); }
        }
        internal static string SFxDocExt_VB {
              get { return SR.GetResourceString("SFxDocExt_VB", null); }
        }
        internal static string SFxDocExt_MainPageTitleNoServiceName {
              get { return SR.GetResourceString("SFxDocExt_MainPageTitleNoServiceName", null); }
        }
        internal static string SFxDocExt_MainPageTitle {
              get { return SR.GetResourceString("SFxDocExt_MainPageTitle", null); }
        }
        internal static string SFxDocExt_MainPageIntro1a {
              get { return SR.GetResourceString("SFxDocExt_MainPageIntro1a", null); }
        }
        internal static string SFxDocExt_MainPageIntro1b {
              get { return SR.GetResourceString("SFxDocExt_MainPageIntro1b", null); }
        }
        internal static string SFxDocExt_MainPageIntro2 {
              get { return SR.GetResourceString("SFxDocExt_MainPageIntro2", null); }
        }
        internal static string SFxDocExt_MainPageComment {
              get { return SR.GetResourceString("SFxDocExt_MainPageComment", null); }
        }
        internal static string SFxDocExt_MainPageComment2 {
              get { return SR.GetResourceString("SFxDocExt_MainPageComment2", null); }
        }
        internal static string SFxDocExt_Error {
              get { return SR.GetResourceString("SFxDocExt_Error", null); }
        }
        internal static string SFxDocEncodedNotSupported {
              get { return SR.GetResourceString("SFxDocEncodedNotSupported", null); }
        }
        internal static string SFxDocEncodedFaultNotSupported {
              get { return SR.GetResourceString("SFxDocEncodedFaultNotSupported", null); }
        }
        internal static string SFxDuplicateMessageParts {
              get { return SR.GetResourceString("SFxDuplicateMessageParts", null); }
        }
        internal static string SFxDuplicateInitiatingActionAtSameVia {
              get { return SR.GetResourceString("SFxDuplicateInitiatingActionAtSameVia", null); }
        }
        internal static string SFXEndpointBehaviorUsedOnWrongSide {
              get { return SR.GetResourceString("SFXEndpointBehaviorUsedOnWrongSide", null); }
        }
        internal static string SFxEndpointDispatcherMultipleChannelDispatcher0 {
              get { return SR.GetResourceString("SFxEndpointDispatcherMultipleChannelDispatcher0", null); }
        }
        internal static string SFxEndpointDispatcherDifferentChannelDispatcher0 {
              get { return SR.GetResourceString("SFxEndpointDispatcherDifferentChannelDispatcher0", null); }
        }
        internal static string SFxErrorCreatingMtomReader {
              get { return SR.GetResourceString("SFxErrorCreatingMtomReader", null); }
        }
        internal static string SFxErrorDeserializingRequestBody {
              get { return SR.GetResourceString("SFxErrorDeserializingRequestBody", null); }
        }
        internal static string SFxErrorDeserializingRequestBodyMore {
              get { return SR.GetResourceString("SFxErrorDeserializingRequestBodyMore", null); }
        }
        internal static string SFxErrorDeserializingReplyBody {
              get { return SR.GetResourceString("SFxErrorDeserializingReplyBody", null); }
        }
        internal static string SFxErrorDeserializingReplyBodyMore {
              get { return SR.GetResourceString("SFxErrorDeserializingReplyBodyMore", null); }
        }
        internal static string SFxErrorSerializingBody {
              get { return SR.GetResourceString("SFxErrorSerializingBody", null); }
        }
        internal static string SFxErrorDeserializingHeader {
              get { return SR.GetResourceString("SFxErrorDeserializingHeader", null); }
        }
        internal static string SFxErrorSerializingHeader {
              get { return SR.GetResourceString("SFxErrorSerializingHeader", null); }
        }
        internal static string SFxErrorDeserializingFault {
              get { return SR.GetResourceString("SFxErrorDeserializingFault", null); }
        }
        internal static string SFxErrorReflectingOnType2 {
              get { return SR.GetResourceString("SFxErrorReflectingOnType2", null); }
        }
        internal static string SFxErrorReflectingOnMethod3 {
              get { return SR.GetResourceString("SFxErrorReflectingOnMethod3", null); }
        }
        internal static string SFxErrorReflectingOnParameter4 {
              get { return SR.GetResourceString("SFxErrorReflectingOnParameter4", null); }
        }
        internal static string SFxErrorReflectionOnUnknown1 {
              get { return SR.GetResourceString("SFxErrorReflectionOnUnknown1", null); }
        }
        internal static string SFxExceptionDetailEndOfInner {
              get { return SR.GetResourceString("SFxExceptionDetailEndOfInner", null); }
        }
        internal static string SFxExceptionDetailFormat {
              get { return SR.GetResourceString("SFxExceptionDetailFormat", null); }
        }
        internal static string SFxExpectedIMethodCallMessage {
              get { return SR.GetResourceString("SFxExpectedIMethodCallMessage", null); }
        }
        internal static string SFxExportMustHaveType {
              get { return SR.GetResourceString("SFxExportMustHaveType", null); }
        }
        internal static string SFxFaultCannotBeImported {
              get { return SR.GetResourceString("SFxFaultCannotBeImported", null); }
        }
        internal static string SFxFaultContractDuplicateDetailType {
              get { return SR.GetResourceString("SFxFaultContractDuplicateDetailType", null); }
        }
        internal static string SFxFaultContractDuplicateElement {
              get { return SR.GetResourceString("SFxFaultContractDuplicateElement", null); }
        }
        internal static string SFxFaultExceptionToString3 {
              get { return SR.GetResourceString("SFxFaultExceptionToString3", null); }
        }
        internal static string SFxFaultReason {
              get { return SR.GetResourceString("SFxFaultReason", null); }
        }
        internal static string SFxFaultTypeAnonymous {
              get { return SR.GetResourceString("SFxFaultTypeAnonymous", null); }
        }
        internal static string SFxHeaderNameMismatchInMessageContract {
              get { return SR.GetResourceString("SFxHeaderNameMismatchInMessageContract", null); }
        }
        internal static string SFxHeaderNameMismatchInOperation {
              get { return SR.GetResourceString("SFxHeaderNameMismatchInOperation", null); }
        }
        internal static string SFxHeaderNamespaceMismatchInMessageContract {
              get { return SR.GetResourceString("SFxHeaderNamespaceMismatchInMessageContract", null); }
        }
        internal static string SFxHeaderNamespaceMismatchInOperation {
              get { return SR.GetResourceString("SFxHeaderNamespaceMismatchInOperation", null); }
        }
        internal static string SFxHeaderNotUnderstood {
              get { return SR.GetResourceString("SFxHeaderNotUnderstood", null); }
        }
        internal static string SFxHeadersAreNotSupportedInEncoded {
              get { return SR.GetResourceString("SFxHeadersAreNotSupportedInEncoded", null); }
        }
        internal static string SFxImmutableServiceHostBehavior0 {
              get { return SR.GetResourceString("SFxImmutableServiceHostBehavior0", null); }
        }
        internal static string SFxImmutableChannelFactoryBehavior0 {
              get { return SR.GetResourceString("SFxImmutableChannelFactoryBehavior0", null); }
        }
        internal static string SFxImmutableClientBaseCacheSetting {
              get { return SR.GetResourceString("SFxImmutableClientBaseCacheSetting", null); }
        }
        internal static string SFxImmutableThrottle1 {
              get { return SR.GetResourceString("SFxImmutableThrottle1", null); }
        }
        internal static string SFxInconsistentBindingBodyParts {
              get { return SR.GetResourceString("SFxInconsistentBindingBodyParts", null); }
        }
        internal static string SFxInconsistentWsdlOperationStyleInHeader {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationStyleInHeader", null); }
        }
        internal static string SFxInconsistentWsdlOperationStyleInMessageParts {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationStyleInMessageParts", null); }
        }
        internal static string SFxInconsistentWsdlOperationStyleInOperationMessages {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationStyleInOperationMessages", null); }
        }
        internal static string SFxInconsistentWsdlOperationUseAndStyleInBinding {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationUseAndStyleInBinding", null); }
        }
        internal static string SFxInconsistentWsdlOperationUseInBindingExtensions {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationUseInBindingExtensions", null); }
        }
        internal static string SFxInconsistentWsdlOperationUseInBindingMessages {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationUseInBindingMessages", null); }
        }
        internal static string SFxInconsistentWsdlOperationUseInBindingFaults {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationUseInBindingFaults", null); }
        }
        internal static string SFxInputParametersToServiceInvalid {
              get { return SR.GetResourceString("SFxInputParametersToServiceInvalid", null); }
        }
        internal static string SFxInputParametersToServiceNull {
              get { return SR.GetResourceString("SFxInputParametersToServiceNull", null); }
        }
        internal static string SFxInstanceNotInitialized {
              get { return SR.GetResourceString("SFxInstanceNotInitialized", null); }
        }
        internal static string SFxInterleavedContextScopes0 {
              get { return SR.GetResourceString("SFxInterleavedContextScopes0", null); }
        }
        internal static string SFxInternalServerError {
              get { return SR.GetResourceString("SFxInternalServerError", null); }
        }
        internal static string SFxInternalCallbackError {
              get { return SR.GetResourceString("SFxInternalCallbackError", null); }
        }
        internal static string SFxInvalidAsyncResultState0 {
              get { return SR.GetResourceString("SFxInvalidAsyncResultState0", null); }
        }
        internal static string SFxInvalidCallbackIAsyncResult {
              get { return SR.GetResourceString("SFxInvalidCallbackIAsyncResult", null); }
        }
        internal static string SFxInvalidCallbackContractType {
              get { return SR.GetResourceString("SFxInvalidCallbackContractType", null); }
        }
        internal static string SFxInvalidChannelToOperationContext {
              get { return SR.GetResourceString("SFxInvalidChannelToOperationContext", null); }
        }
        internal static string SFxInvalidContextScopeThread0 {
              get { return SR.GetResourceString("SFxInvalidContextScopeThread0", null); }
        }
        internal static string SFxInvalidMessageBody {
              get { return SR.GetResourceString("SFxInvalidMessageBody", null); }
        }
        internal static string SFxInvalidMessageBodyEmptyMessage {
              get { return SR.GetResourceString("SFxInvalidMessageBodyEmptyMessage", null); }
        }
        internal static string SFxInvalidMessageBodyErrorSerializingParameter {
              get { return SR.GetResourceString("SFxInvalidMessageBodyErrorSerializingParameter", null); }
        }
        internal static string SFxInvalidMessageBodyErrorDeserializingParameter {
              get { return SR.GetResourceString("SFxInvalidMessageBodyErrorDeserializingParameter", null); }
        }
        internal static string SFxInvalidMessageBodyErrorDeserializingParameterMore {
              get { return SR.GetResourceString("SFxInvalidMessageBodyErrorDeserializingParameterMore", null); }
        }
        internal static string SFxInvalidMessageContractSignature {
              get { return SR.GetResourceString("SFxInvalidMessageContractSignature", null); }
        }
        internal static string SFxInvalidMessageHeaderArrayType {
              get { return SR.GetResourceString("SFxInvalidMessageHeaderArrayType", null); }
        }
        internal static string SFxInvalidRequestAction {
              get { return SR.GetResourceString("SFxInvalidRequestAction", null); }
        }
        internal static string SFxInvalidReplyAction {
              get { return SR.GetResourceString("SFxInvalidReplyAction", null); }
        }
        internal static string SFxInvalidStreamInTypedMessage {
              get { return SR.GetResourceString("SFxInvalidStreamInTypedMessage", null); }
        }
        internal static string SFxInvalidStreamInRequest {
              get { return SR.GetResourceString("SFxInvalidStreamInRequest", null); }
        }
        internal static string SFxInvalidStreamInResponse {
              get { return SR.GetResourceString("SFxInvalidStreamInResponse", null); }
        }
        internal static string SFxInvalidStreamOffsetLength {
              get { return SR.GetResourceString("SFxInvalidStreamOffsetLength", null); }
        }
        internal static string SFxInvalidUseOfPrimitiveOperationFormatter {
              get { return SR.GetResourceString("SFxInvalidUseOfPrimitiveOperationFormatter", null); }
        }
        internal static string SFxInvalidStaticOverloadCalledForDuplexChannelFactory1 {
              get { return SR.GetResourceString("SFxInvalidStaticOverloadCalledForDuplexChannelFactory1", null); }
        }
        internal static string SFxInvalidSoapAttribute {
              get { return SR.GetResourceString("SFxInvalidSoapAttribute", null); }
        }
        internal static string SFxInvalidXmlAttributeInBare {
              get { return SR.GetResourceString("SFxInvalidXmlAttributeInBare", null); }
        }
        internal static string SFxInvalidXmlAttributeInWrapped {
              get { return SR.GetResourceString("SFxInvalidXmlAttributeInWrapped", null); }
        }
        internal static string SFxKnownTypeAttributeInvalid1 {
              get { return SR.GetResourceString("SFxKnownTypeAttributeInvalid1", null); }
        }
        internal static string SFxKnownTypeAttributeReturnType3 {
              get { return SR.GetResourceString("SFxKnownTypeAttributeReturnType3", null); }
        }
        internal static string SFxKnownTypeAttributeUnknownMethod3 {
              get { return SR.GetResourceString("SFxKnownTypeAttributeUnknownMethod3", null); }
        }
        internal static string SFxKnownTypeNull {
              get { return SR.GetResourceString("SFxKnownTypeNull", null); }
        }
        internal static string SFxMessageContractBaseTypeNotValid {
              get { return SR.GetResourceString("SFxMessageContractBaseTypeNotValid", null); }
        }
        internal static string SFxMessageContractRequiresDefaultConstructor {
              get { return SR.GetResourceString("SFxMessageContractRequiresDefaultConstructor", null); }
        }
        internal static string SFxMessageOperationFormatterCannotSerializeFault {
              get { return SR.GetResourceString("SFxMessageOperationFormatterCannotSerializeFault", null); }
        }
        internal static string SFxMetadataReferenceInvalidLocation {
              get { return SR.GetResourceString("SFxMetadataReferenceInvalidLocation", null); }
        }
        internal static string SFxMethodNotSupported1 {
              get { return SR.GetResourceString("SFxMethodNotSupported1", null); }
        }
        internal static string SFxMethodNotSupportedOnCallback1 {
              get { return SR.GetResourceString("SFxMethodNotSupportedOnCallback1", null); }
        }
        internal static string SFxMethodNotSupportedByType2 {
              get { return SR.GetResourceString("SFxMethodNotSupportedByType2", null); }
        }
        internal static string SFxMismatchedOperationParent {
              get { return SR.GetResourceString("SFxMismatchedOperationParent", null); }
        }
        internal static string SFxMissingActionHeader {
              get { return SR.GetResourceString("SFxMissingActionHeader", null); }
        }
        internal static string SFxMultipleCallbackFromSynchronizationContext {
              get { return SR.GetResourceString("SFxMultipleCallbackFromSynchronizationContext", null); }
        }
        internal static string SFxMultipleCallbackFromAsyncOperation {
              get { return SR.GetResourceString("SFxMultipleCallbackFromAsyncOperation", null); }
        }
        internal static string SFxMultipleUnknownHeaders {
              get { return SR.GetResourceString("SFxMultipleUnknownHeaders", null); }
        }
        internal static string SFxMultipleContractStarOperations0 {
              get { return SR.GetResourceString("SFxMultipleContractStarOperations0", null); }
        }
        internal static string SFxMultipleContractsWithSameName {
              get { return SR.GetResourceString("SFxMultipleContractsWithSameName", null); }
        }
        internal static string SFxMultiplePartsNotAllowedInEncoded {
              get { return SR.GetResourceString("SFxMultiplePartsNotAllowedInEncoded", null); }
        }
        internal static string SFxNameCannotBeEmpty {
              get { return SR.GetResourceString("SFxNameCannotBeEmpty", null); }
        }
        internal static string SFxConfigurationNameCannotBeEmpty {
              get { return SR.GetResourceString("SFxConfigurationNameCannotBeEmpty", null); }
        }
        internal static string SFxNeedProxyBehaviorOperationSelector2 {
              get { return SR.GetResourceString("SFxNeedProxyBehaviorOperationSelector2", null); }
        }
        internal static string SFxNoDefaultConstructor {
              get { return SR.GetResourceString("SFxNoDefaultConstructor", null); }
        }
        internal static string SFxNoMostDerivedContract {
              get { return SR.GetResourceString("SFxNoMostDerivedContract", null); }
        }
        internal static string SFxNullReplyFromExtension2 {
              get { return SR.GetResourceString("SFxNullReplyFromExtension2", null); }
        }
        internal static string SFxNullReplyFromFormatter2 {
              get { return SR.GetResourceString("SFxNullReplyFromFormatter2", null); }
        }
        internal static string SFxServiceChannelIdleAborted {
              get { return SR.GetResourceString("SFxServiceChannelIdleAborted", null); }
        }
        internal static string SFxServiceMetadataBehaviorUrlMustBeHttpOrRelative {
              get { return SR.GetResourceString("SFxServiceMetadataBehaviorUrlMustBeHttpOrRelative", null); }
        }
        internal static string SFxServiceMetadataBehaviorNoHttpBaseAddress {
              get { return SR.GetResourceString("SFxServiceMetadataBehaviorNoHttpBaseAddress", null); }
        }
        internal static string SFxServiceMetadataBehaviorNoHttpsBaseAddress {
              get { return SR.GetResourceString("SFxServiceMetadataBehaviorNoHttpsBaseAddress", null); }
        }
        internal static string SFxServiceMetadataBehaviorInstancingError {
              get { return SR.GetResourceString("SFxServiceMetadataBehaviorInstancingError", null); }
        }
        internal static string SFxServiceTypeNotCreatable {
              get { return SR.GetResourceString("SFxServiceTypeNotCreatable", null); }
        }
        internal static string SFxSetEnableFaultsOnChannelDispatcher0 {
              get { return SR.GetResourceString("SFxSetEnableFaultsOnChannelDispatcher0", null); }
        }
        internal static string SFxSetManualAddresssingOnChannelDispatcher0 {
              get { return SR.GetResourceString("SFxSetManualAddresssingOnChannelDispatcher0", null); }
        }
        internal static string SFxNoBatchingForSession {
              get { return SR.GetResourceString("SFxNoBatchingForSession", null); }
        }
        internal static string SFxNoBatchingForReleaseOnComplete {
              get { return SR.GetResourceString("SFxNoBatchingForReleaseOnComplete", null); }
        }
        internal static string SFxNoServiceObject {
              get { return SR.GetResourceString("SFxNoServiceObject", null); }
        }
        internal static string SFxNone2004 {
              get { return SR.GetResourceString("SFxNone2004", null); }
        }
        internal static string SFxNonExceptionThrown {
              get { return SR.GetResourceString("SFxNonExceptionThrown", null); }
        }
        internal static string SFxNonInitiatingOperation1 {
              get { return SR.GetResourceString("SFxNonInitiatingOperation1", null); }
        }
        internal static string SfxNoTypeSpecifiedForParameter {
              get { return SR.GetResourceString("SfxNoTypeSpecifiedForParameter", null); }
        }
        internal static string SFxOneWayAndTransactionsIncompatible {
              get { return SR.GetResourceString("SFxOneWayAndTransactionsIncompatible", null); }
        }
        internal static string SFxOneWayMessageToTwoWayMethod0 {
              get { return SR.GetResourceString("SFxOneWayMessageToTwoWayMethod0", null); }
        }
        internal static string SFxOperationBehaviorAttributeOnlyOnServiceClass {
              get { return SR.GetResourceString("SFxOperationBehaviorAttributeOnlyOnServiceClass", null); }
        }
        internal static string SFxOperationBehaviorAttributeReleaseInstanceModeDoesNotApplyToCallback {
              get { return SR.GetResourceString("SFxOperationBehaviorAttributeReleaseInstanceModeDoesNotApplyToCallback", null); }
        }
        internal static string SFxOperationContractOnNonServiceContract {
              get { return SR.GetResourceString("SFxOperationContractOnNonServiceContract", null); }
        }
        internal static string SFxOperationContractProviderOnNonServiceContract {
              get { return SR.GetResourceString("SFxOperationContractProviderOnNonServiceContract", null); }
        }
        internal static string SFxOperationDescriptionNameCannotBeEmpty {
              get { return SR.GetResourceString("SFxOperationDescriptionNameCannotBeEmpty", null); }
        }
        internal static string SFxParameterNameCannotBeNull {
              get { return SR.GetResourceString("SFxParameterNameCannotBeNull", null); }
        }
        internal static string SFxOperationMustHaveOneOrTwoMessages {
              get { return SR.GetResourceString("SFxOperationMustHaveOneOrTwoMessages", null); }
        }
        internal static string SFxParameterCountMismatch {
              get { return SR.GetResourceString("SFxParameterCountMismatch", null); }
        }
        internal static string SFxParameterMustBeMessage {
              get { return SR.GetResourceString("SFxParameterMustBeMessage", null); }
        }
        internal static string SFxParametersMustBeEmpty {
              get { return SR.GetResourceString("SFxParametersMustBeEmpty", null); }
        }
        internal static string SFxParameterMustBeArrayOfOneElement {
              get { return SR.GetResourceString("SFxParameterMustBeArrayOfOneElement", null); }
        }
        internal static string SFxPartNameMustBeUniqueInRpc {
              get { return SR.GetResourceString("SFxPartNameMustBeUniqueInRpc", null); }
        }
        internal static string SFxReceiveContextSettingsPropertyMissing {
              get { return SR.GetResourceString("SFxReceiveContextSettingsPropertyMissing", null); }
        }
        internal static string SFxReceiveContextPropertyMissing {
              get { return SR.GetResourceString("SFxReceiveContextPropertyMissing", null); }
        }
        internal static string SFxRequestHasInvalidReplyToOnClient {
              get { return SR.GetResourceString("SFxRequestHasInvalidReplyToOnClient", null); }
        }
        internal static string SFxRequestHasInvalidFaultToOnClient {
              get { return SR.GetResourceString("SFxRequestHasInvalidFaultToOnClient", null); }
        }
        internal static string SFxRequestHasInvalidFromOnClient {
              get { return SR.GetResourceString("SFxRequestHasInvalidFromOnClient", null); }
        }
        internal static string SFxRequestHasInvalidReplyToOnServer {
              get { return SR.GetResourceString("SFxRequestHasInvalidReplyToOnServer", null); }
        }
        internal static string SFxRequestHasInvalidFaultToOnServer {
              get { return SR.GetResourceString("SFxRequestHasInvalidFaultToOnServer", null); }
        }
        internal static string SFxRequestHasInvalidFromOnServer {
              get { return SR.GetResourceString("SFxRequestHasInvalidFromOnServer", null); }
        }
        internal static string SFxRequestReplyNone {
              get { return SR.GetResourceString("SFxRequestReplyNone", null); }
        }
        internal static string SFxRequestTimedOut1 {
              get { return SR.GetResourceString("SFxRequestTimedOut1", null); }
        }
        internal static string SFxRequestTimedOut2 {
              get { return SR.GetResourceString("SFxRequestTimedOut2", null); }
        }
        internal static string SFxReplyActionMismatch3 {
              get { return SR.GetResourceString("SFxReplyActionMismatch3", null); }
        }
        internal static string SFxRequiredRuntimePropertyMissing {
              get { return SR.GetResourceString("SFxRequiredRuntimePropertyMissing", null); }
        }
        internal static string SFxResolvedMaxResolvedReferences {
              get { return SR.GetResourceString("SFxResolvedMaxResolvedReferences", null); }
        }
        internal static string SFxResultMustBeMessage {
              get { return SR.GetResourceString("SFxResultMustBeMessage", null); }
        }
        internal static string SFxRevertImpersonationFailed0 {
              get { return SR.GetResourceString("SFxRevertImpersonationFailed0", null); }
        }
        internal static string SFxRpcMessageBodyPartNameInvalid {
              get { return SR.GetResourceString("SFxRpcMessageBodyPartNameInvalid", null); }
        }
        internal static string SFxRpcMessageMustHaveASingleBody {
              get { return SR.GetResourceString("SFxRpcMessageMustHaveASingleBody", null); }
        }
        internal static string SFxSchemaDoesNotContainElement {
              get { return SR.GetResourceString("SFxSchemaDoesNotContainElement", null); }
        }
        internal static string SFxSchemaDoesNotContainType {
              get { return SR.GetResourceString("SFxSchemaDoesNotContainType", null); }
        }
        internal static string SFxWsdlMessageDoesNotContainPart3 {
              get { return SR.GetResourceString("SFxWsdlMessageDoesNotContainPart3", null); }
        }
        internal static string SFxSchemaNotFound {
              get { return SR.GetResourceString("SFxSchemaNotFound", null); }
        }
        internal static string SFxSecurityContextPropertyMissingFromRequestMessage {
              get { return SR.GetResourceString("SFxSecurityContextPropertyMissingFromRequestMessage", null); }
        }
        internal static string SFxServerDidNotReply {
              get { return SR.GetResourceString("SFxServerDidNotReply", null); }
        }
        internal static string SFxServiceHostBaseCannotAddEndpointAfterOpen {
              get { return SR.GetResourceString("SFxServiceHostBaseCannotAddEndpointAfterOpen", null); }
        }
        internal static string SFxServiceHostBaseCannotAddEndpointWithoutDescription {
              get { return SR.GetResourceString("SFxServiceHostBaseCannotAddEndpointWithoutDescription", null); }
        }
        internal static string SFxServiceHostBaseCannotApplyConfigurationWithoutDescription {
              get { return SR.GetResourceString("SFxServiceHostBaseCannotApplyConfigurationWithoutDescription", null); }
        }
        internal static string SFxServiceHostBaseCannotLoadConfigurationSectionWithoutDescription {
              get { return SR.GetResourceString("SFxServiceHostBaseCannotLoadConfigurationSectionWithoutDescription", null); }
        }
        internal static string SFxServiceHostBaseCannotInitializeRuntimeWithoutDescription {
              get { return SR.GetResourceString("SFxServiceHostBaseCannotInitializeRuntimeWithoutDescription", null); }
        }
        internal static string SFxServiceHostCannotCreateDescriptionWithoutServiceType {
              get { return SR.GetResourceString("SFxServiceHostCannotCreateDescriptionWithoutServiceType", null); }
        }
        internal static string SFxStaticMessageHeaderPropertiesNotAllowed {
              get { return SR.GetResourceString("SFxStaticMessageHeaderPropertiesNotAllowed", null); }
        }
        internal static string SFxStreamIOException {
              get { return SR.GetResourceString("SFxStreamIOException", null); }
        }
        internal static string SFxStreamRequestMessageClosed {
              get { return SR.GetResourceString("SFxStreamRequestMessageClosed", null); }
        }
        internal static string SFxStreamResponseMessageClosed {
              get { return SR.GetResourceString("SFxStreamResponseMessageClosed", null); }
        }
        internal static string SFxThrottleLimitMustBeGreaterThanZero0 {
              get { return SR.GetResourceString("SFxThrottleLimitMustBeGreaterThanZero0", null); }
        }
        internal static string SFxTimeoutInvalidStringFormat {
              get { return SR.GetResourceString("SFxTimeoutInvalidStringFormat", null); }
        }
        internal static string SFxTimeoutOutOfRange0 {
              get { return SR.GetResourceString("SFxTimeoutOutOfRange0", null); }
        }
        internal static string SFxTimeoutOutOfRangeTooBig {
              get { return SR.GetResourceString("SFxTimeoutOutOfRangeTooBig", null); }
        }
        internal static string SFxTooManyPartsWithSameName {
              get { return SR.GetResourceString("SFxTooManyPartsWithSameName", null); }
        }
        internal static string SFxTraceCodeElementIgnored {
              get { return SR.GetResourceString("SFxTraceCodeElementIgnored", null); }
        }
        internal static string SfxTransactedBindingNeeded {
              get { return SR.GetResourceString("SfxTransactedBindingNeeded", null); }
        }
        internal static string SFxTransactionNonConcurrentOrAutoComplete2 {
              get { return SR.GetResourceString("SFxTransactionNonConcurrentOrAutoComplete2", null); }
        }
        internal static string SFxTransactionNonConcurrentOrReleaseServiceInstanceOnTxComplete {
              get { return SR.GetResourceString("SFxTransactionNonConcurrentOrReleaseServiceInstanceOnTxComplete", null); }
        }
        internal static string SFxNonConcurrentOrEnsureOrderedDispatch {
              get { return SR.GetResourceString("SFxNonConcurrentOrEnsureOrderedDispatch", null); }
        }
        internal static string SfxDispatchRuntimeNonConcurrentOrEnsureOrderedDispatch {
              get { return SR.GetResourceString("SfxDispatchRuntimeNonConcurrentOrEnsureOrderedDispatch", null); }
        }
        internal static string SFxTransactionsNotSupported {
              get { return SR.GetResourceString("SFxTransactionsNotSupported", null); }
        }
        internal static string SFxTransactionAsyncAborted {
              get { return SR.GetResourceString("SFxTransactionAsyncAborted", null); }
        }
        internal static string SFxTransactionInvalidSetTransactionComplete {
              get { return SR.GetResourceString("SFxTransactionInvalidSetTransactionComplete", null); }
        }
        internal static string SFxMultiSetTransactionComplete {
              get { return SR.GetResourceString("SFxMultiSetTransactionComplete", null); }
        }
        internal static string SFxTransactionFlowAndMSMQ {
              get { return SR.GetResourceString("SFxTransactionFlowAndMSMQ", null); }
        }
        internal static string SFxTransactionAutoCompleteFalseAndInstanceContextMode {
              get { return SR.GetResourceString("SFxTransactionAutoCompleteFalseAndInstanceContextMode", null); }
        }
        internal static string SFxTransactionAutoCompleteFalseOnCallbackContract {
              get { return SR.GetResourceString("SFxTransactionAutoCompleteFalseOnCallbackContract", null); }
        }
        internal static string SFxTransactionAutoCompleteFalseAndSupportsSession {
              get { return SR.GetResourceString("SFxTransactionAutoCompleteFalseAndSupportsSession", null); }
        }
        internal static string SFxTransactionAutoCompleteOnSessionCloseNoSession {
              get { return SR.GetResourceString("SFxTransactionAutoCompleteOnSessionCloseNoSession", null); }
        }
        internal static string SFxTransactionTransactionTimeoutNeedsScope {
              get { return SR.GetResourceString("SFxTransactionTransactionTimeoutNeedsScope", null); }
        }
        internal static string SFxTransactionIsolationLevelNeedsScope {
              get { return SR.GetResourceString("SFxTransactionIsolationLevelNeedsScope", null); }
        }
        internal static string SFxTransactionReleaseServiceInstanceOnTransactionCompleteNeedsScope {
              get { return SR.GetResourceString("SFxTransactionReleaseServiceInstanceOnTransactionCompleteNeedsScope", null); }
        }
        internal static string SFxTransactionTransactionAutoCompleteOnSessionCloseNeedsScope {
              get { return SR.GetResourceString("SFxTransactionTransactionAutoCompleteOnSessionCloseNeedsScope", null); }
        }
        internal static string SFxTransactionFlowRequired {
              get { return SR.GetResourceString("SFxTransactionFlowRequired", null); }
        }
        internal static string SFxTransactionUnmarshalFailed {
              get { return SR.GetResourceString("SFxTransactionUnmarshalFailed", null); }
        }
        internal static string SFxTransactionDeserializationFailed {
              get { return SR.GetResourceString("SFxTransactionDeserializationFailed", null); }
        }
        internal static string SFxTransactionHeaderNotUnderstood {
              get { return SR.GetResourceString("SFxTransactionHeaderNotUnderstood", null); }
        }
        internal static string SFxTryAddMultipleTransactionsOnMessage {
              get { return SR.GetResourceString("SFxTryAddMultipleTransactionsOnMessage", null); }
        }
        internal static string SFxTypedMessageCannotBeNull {
              get { return SR.GetResourceString("SFxTypedMessageCannotBeNull", null); }
        }
        internal static string SFxTypedMessageCannotBeRpcLiteral {
              get { return SR.GetResourceString("SFxTypedMessageCannotBeRpcLiteral", null); }
        }
        internal static string SFxTypedOrUntypedMessageCannotBeMixedWithParameters {
              get { return SR.GetResourceString("SFxTypedOrUntypedMessageCannotBeMixedWithParameters", null); }
        }
        internal static string SFxTypedOrUntypedMessageCannotBeMixedWithVoidInRpc {
              get { return SR.GetResourceString("SFxTypedOrUntypedMessageCannotBeMixedWithVoidInRpc", null); }
        }
        internal static string SFxUnknownFaultNoMatchingTranslation1 {
              get { return SR.GetResourceString("SFxUnknownFaultNoMatchingTranslation1", null); }
        }
        internal static string SFxUnknownFaultNullReason0 {
              get { return SR.GetResourceString("SFxUnknownFaultNullReason0", null); }
        }
        internal static string SFxUnknownFaultZeroReasons0 {
              get { return SR.GetResourceString("SFxUnknownFaultZeroReasons0", null); }
        }
        internal static string SFxUserCodeThrewException {
              get { return SR.GetResourceString("SFxUserCodeThrewException", null); }
        }
        internal static string SfxUseTypedMessageForCustomAttributes {
              get { return SR.GetResourceString("SfxUseTypedMessageForCustomAttributes", null); }
        }
        internal static string SFxWellKnownNonSingleton0 {
              get { return SR.GetResourceString("SFxWellKnownNonSingleton0", null); }
        }
        internal static string SFxVersionMismatchInOperationContextAndMessage2 {
              get { return SR.GetResourceString("SFxVersionMismatchInOperationContextAndMessage2", null); }
        }
        internal static string SFxWhenMultipleEndpointsShareAListenUriTheyMustHaveSameIdentity {
              get { return SR.GetResourceString("SFxWhenMultipleEndpointsShareAListenUriTheyMustHaveSameIdentity", null); }
        }
        internal static string SFxWrapperNameCannotBeEmpty {
              get { return SR.GetResourceString("SFxWrapperNameCannotBeEmpty", null); }
        }
        internal static string SFxWrapperTypeHasMultipleNamespaces {
              get { return SR.GetResourceString("SFxWrapperTypeHasMultipleNamespaces", null); }
        }
        internal static string SFxWsdlPartMustHaveElementOrType {
              get { return SR.GetResourceString("SFxWsdlPartMustHaveElementOrType", null); }
        }
        internal static string SFxDataContractSerializerDoesNotSupportBareArray {
              get { return SR.GetResourceString("SFxDataContractSerializerDoesNotSupportBareArray", null); }
        }
        internal static string SFxDataContractSerializerDoesNotSupportEncoded {
              get { return SR.GetResourceString("SFxDataContractSerializerDoesNotSupportEncoded", null); }
        }
        internal static string SFxXmlArrayNotAllowedForMultiple {
              get { return SR.GetResourceString("SFxXmlArrayNotAllowedForMultiple", null); }
        }
        internal static string SFxXmlSerializerIsNotFound {
              get { return SR.GetResourceString("SFxXmlSerializerIsNotFound", null); }
        }
        internal static string SFxConfigContractNotFound {
              get { return SR.GetResourceString("SFxConfigContractNotFound", null); }
        }
        internal static string SFxConfigChannelConfigurationNotFound {
              get { return SR.GetResourceString("SFxConfigChannelConfigurationNotFound", null); }
        }
        internal static string SFxChannelFactoryEndpointAddressUri {
              get { return SR.GetResourceString("SFxChannelFactoryEndpointAddressUri", null); }
        }
        internal static string SFxServiceContractGeneratorConfigRequired {
              get { return SR.GetResourceString("SFxServiceContractGeneratorConfigRequired", null); }
        }
        internal static string SFxCloseTimedOut1 {
              get { return SR.GetResourceString("SFxCloseTimedOut1", null); }
        }
        internal static string SfxCloseTimedOutWaitingForDispatchToComplete {
              get { return SR.GetResourceString("SfxCloseTimedOutWaitingForDispatchToComplete", null); }
        }
        internal static string SFxInvalidWsdlBindingOpMismatch2 {
              get { return SR.GetResourceString("SFxInvalidWsdlBindingOpMismatch2", null); }
        }
        internal static string SFxInvalidWsdlBindingOpNoName {
              get { return SR.GetResourceString("SFxInvalidWsdlBindingOpNoName", null); }
        }
        internal static string SFxChannelFactoryNoBindingFoundInConfig1 {
              get { return SR.GetResourceString("SFxChannelFactoryNoBindingFoundInConfig1", null); }
        }
        internal static string SFxChannelFactoryNoBindingFoundInConfigOrCode {
              get { return SR.GetResourceString("SFxChannelFactoryNoBindingFoundInConfigOrCode", null); }
        }
        internal static string SFxConfigLoaderMultipleEndpointMatchesSpecified2 {
              get { return SR.GetResourceString("SFxConfigLoaderMultipleEndpointMatchesSpecified2", null); }
        }
        internal static string SFxConfigLoaderMultipleEndpointMatchesWildcard1 {
              get { return SR.GetResourceString("SFxConfigLoaderMultipleEndpointMatchesWildcard1", null); }
        }
        internal static string SFxProxyRuntimeMessageCannotBeNull {
              get { return SR.GetResourceString("SFxProxyRuntimeMessageCannotBeNull", null); }
        }
        internal static string SFxDispatchRuntimeMessageCannotBeNull {
              get { return SR.GetResourceString("SFxDispatchRuntimeMessageCannotBeNull", null); }
        }
        internal static string SFxServiceHostNeedsClass {
              get { return SR.GetResourceString("SFxServiceHostNeedsClass", null); }
        }
        internal static string SfxReflectedContractKeyNotFound2 {
              get { return SR.GetResourceString("SfxReflectedContractKeyNotFound2", null); }
        }
        internal static string SfxReflectedContractKeyNotFoundEmpty {
              get { return SR.GetResourceString("SfxReflectedContractKeyNotFoundEmpty", null); }
        }
        internal static string SfxReflectedContractKeyNotFoundIMetadataExchange {
              get { return SR.GetResourceString("SfxReflectedContractKeyNotFoundIMetadataExchange", null); }
        }
        internal static string SfxServiceContractAttributeNotFound {
              get { return SR.GetResourceString("SfxServiceContractAttributeNotFound", null); }
        }
        internal static string SfxReflectedContractsNotInitialized1 {
              get { return SR.GetResourceString("SfxReflectedContractsNotInitialized1", null); }
        }
        internal static string SFxMessagePartDescriptionMissingType {
              get { return SR.GetResourceString("SFxMessagePartDescriptionMissingType", null); }
        }
        internal static string SFxWsdlOperationInputNeedsMessageAttribute2 {
              get { return SR.GetResourceString("SFxWsdlOperationInputNeedsMessageAttribute2", null); }
        }
        internal static string SFxWsdlOperationOutputNeedsMessageAttribute2 {
              get { return SR.GetResourceString("SFxWsdlOperationOutputNeedsMessageAttribute2", null); }
        }
        internal static string SFxWsdlOperationFaultNeedsMessageAttribute2 {
              get { return SR.GetResourceString("SFxWsdlOperationFaultNeedsMessageAttribute2", null); }
        }
        internal static string SFxMessageContractAttributeRequired {
              get { return SR.GetResourceString("SFxMessageContractAttributeRequired", null); }
        }
        internal static string AChannelServiceEndpointIsNull0 {
              get { return SR.GetResourceString("AChannelServiceEndpointIsNull0", null); }
        }
        internal static string AChannelServiceEndpointSBindingIsNull0 {
              get { return SR.GetResourceString("AChannelServiceEndpointSBindingIsNull0", null); }
        }
        internal static string AChannelServiceEndpointSContractIsNull0 {
              get { return SR.GetResourceString("AChannelServiceEndpointSContractIsNull0", null); }
        }
        internal static string AChannelServiceEndpointSContractSNameIsNull0 {
              get { return SR.GetResourceString("AChannelServiceEndpointSContractSNameIsNull0", null); }
        }
        internal static string AChannelServiceEndpointSContractSNamespace0 {
              get { return SR.GetResourceString("AChannelServiceEndpointSContractSNamespace0", null); }
        }
        internal static string ServiceHasZeroAppEndpoints {
              get { return SR.GetResourceString("ServiceHasZeroAppEndpoints", null); }
        }
        internal static string BindingRequirementsAttributeRequiresQueuedDelivery1 {
              get { return SR.GetResourceString("BindingRequirementsAttributeRequiresQueuedDelivery1", null); }
        }
        internal static string BindingRequirementsAttributeDisallowsQueuedDelivery1 {
              get { return SR.GetResourceString("BindingRequirementsAttributeDisallowsQueuedDelivery1", null); }
        }
        internal static string SinceTheBindingForDoesnTSupportIBindingCapabilities1_1 {
              get { return SR.GetResourceString("SinceTheBindingForDoesnTSupportIBindingCapabilities1_1", null); }
        }
        internal static string SinceTheBindingForDoesnTSupportIBindingCapabilities2_1 {
              get { return SR.GetResourceString("SinceTheBindingForDoesnTSupportIBindingCapabilities2_1", null); }
        }
        internal static string TheBindingForDoesnTSupportOrderedDelivery1 {
              get { return SR.GetResourceString("TheBindingForDoesnTSupportOrderedDelivery1", null); }
        }
        internal static string ChannelHasAtLeastOneOperationWithTransactionFlowEnabled {
              get { return SR.GetResourceString("ChannelHasAtLeastOneOperationWithTransactionFlowEnabled", null); }
        }
        internal static string ServiceHasAtLeastOneOperationWithTransactionFlowEnabled {
              get { return SR.GetResourceString("ServiceHasAtLeastOneOperationWithTransactionFlowEnabled", null); }
        }
        internal static string SFxNoEndpointMatchingContract {
              get { return SR.GetResourceString("SFxNoEndpointMatchingContract", null); }
        }
        internal static string SFxNoEndpointMatchingAddress {
              get { return SR.GetResourceString("SFxNoEndpointMatchingAddress", null); }
        }
        internal static string SFxNoEndpointMatchingAddressForConnectionOpeningMessage {
              get { return SR.GetResourceString("SFxNoEndpointMatchingAddressForConnectionOpeningMessage", null); }
        }
        internal static string SFxServiceChannelCannotBeCalledBecauseIsSessionOpenNotificationEnabled {
              get { return SR.GetResourceString("SFxServiceChannelCannotBeCalledBecauseIsSessionOpenNotificationEnabled", null); }
        }
        internal static string EndMethodsCannotBeDecoratedWithOperationContractAttribute {
              get { return SR.GetResourceString("EndMethodsCannotBeDecoratedWithOperationContractAttribute", null); }
        }
        internal static string WsatMessagingInitializationFailed {
              get { return SR.GetResourceString("WsatMessagingInitializationFailed", null); }
        }
        internal static string WsatProxyCreationFailed {
              get { return SR.GetResourceString("WsatProxyCreationFailed", null); }
        }
        internal static string DispatchRuntimeRequiresFormatter0 {
              get { return SR.GetResourceString("DispatchRuntimeRequiresFormatter0", null); }
        }
        internal static string ClientRuntimeRequiresFormatter0 {
              get { return SR.GetResourceString("ClientRuntimeRequiresFormatter0", null); }
        }
        internal static string RuntimeRequiresInvoker0 {
              get { return SR.GetResourceString("RuntimeRequiresInvoker0", null); }
        }
        internal static string CouldnTCreateChannelForType2 {
              get { return SR.GetResourceString("CouldnTCreateChannelForType2", null); }
        }
        internal static string CouldnTCreateChannelForChannelType2 {
              get { return SR.GetResourceString("CouldnTCreateChannelForChannelType2", null); }
        }
        internal static string EndpointListenerRequirementsCannotBeMetBy3 {
              get { return SR.GetResourceString("EndpointListenerRequirementsCannotBeMetBy3", null); }
        }
        internal static string UnknownListenerType1 {
              get { return SR.GetResourceString("UnknownListenerType1", null); }
        }
        internal static string BindingDoesnTSupportSessionButContractRequires1 {
              get { return SR.GetResourceString("BindingDoesnTSupportSessionButContractRequires1", null); }
        }
        internal static string BindingDoesntSupportDatagramButContractRequires {
              get { return SR.GetResourceString("BindingDoesntSupportDatagramButContractRequires", null); }
        }
        internal static string BindingDoesnTSupportOneWayButContractRequires1 {
              get { return SR.GetResourceString("BindingDoesnTSupportOneWayButContractRequires1", null); }
        }
        internal static string BindingDoesnTSupportTwoWayButContractRequires1 {
              get { return SR.GetResourceString("BindingDoesnTSupportTwoWayButContractRequires1", null); }
        }
        internal static string BindingDoesnTSupportRequestReplyButContract1 {
              get { return SR.GetResourceString("BindingDoesnTSupportRequestReplyButContract1", null); }
        }
        internal static string BindingDoesnTSupportDuplexButContractRequires1 {
              get { return SR.GetResourceString("BindingDoesnTSupportDuplexButContractRequires1", null); }
        }
        internal static string BindingDoesnTSupportAnyChannelTypes1 {
              get { return SR.GetResourceString("BindingDoesnTSupportAnyChannelTypes1", null); }
        }
        internal static string ContractIsNotSelfConsistentItHasOneOrMore2 {
              get { return SR.GetResourceString("ContractIsNotSelfConsistentItHasOneOrMore2", null); }
        }
        internal static string ContractIsNotSelfConsistentWhenIsSessionOpenNotificationEnabled {
              get { return SR.GetResourceString("ContractIsNotSelfConsistentWhenIsSessionOpenNotificationEnabled", null); }
        }
        internal static string InstanceSettingsMustHaveTypeOrWellKnownObject0 {
              get { return SR.GetResourceString("InstanceSettingsMustHaveTypeOrWellKnownObject0", null); }
        }
        internal static string TheServiceMetadataExtensionInstanceCouldNot2_0 {
              get { return SR.GetResourceString("TheServiceMetadataExtensionInstanceCouldNot2_0", null); }
        }
        internal static string TheServiceMetadataExtensionInstanceCouldNot3_0 {
              get { return SR.GetResourceString("TheServiceMetadataExtensionInstanceCouldNot3_0", null); }
        }
        internal static string TheServiceMetadataExtensionInstanceCouldNot4_0 {
              get { return SR.GetResourceString("TheServiceMetadataExtensionInstanceCouldNot4_0", null); }
        }
        internal static string SynchronizedCollectionWrongType1 {
              get { return SR.GetResourceString("SynchronizedCollectionWrongType1", null); }
        }
        internal static string SynchronizedCollectionWrongTypeNull {
              get { return SR.GetResourceString("SynchronizedCollectionWrongTypeNull", null); }
        }
        internal static string CannotAddTwoItemsWithTheSameKeyToSynchronizedKeyedCollection0 {
              get { return SR.GetResourceString("CannotAddTwoItemsWithTheSameKeyToSynchronizedKeyedCollection0", null); }
        }
        internal static string ItemDoesNotExistInSynchronizedKeyedCollection0 {
              get { return SR.GetResourceString("ItemDoesNotExistInSynchronizedKeyedCollection0", null); }
        }
        internal static string SuppliedMessageIsNotAReplyItHasNoRelatesTo0 {
              get { return SR.GetResourceString("SuppliedMessageIsNotAReplyItHasNoRelatesTo0", null); }
        }
        internal static string channelIsNotAvailable0 {
              get { return SR.GetResourceString("channelIsNotAvailable0", null); }
        }
        internal static string channelDoesNotHaveADuplexSession0 {
              get { return SR.GetResourceString("channelDoesNotHaveADuplexSession0", null); }
        }
        internal static string EndpointsMustHaveAValidBinding1 {
              get { return SR.GetResourceString("EndpointsMustHaveAValidBinding1", null); }
        }
        internal static string ABindingInstanceHasAlreadyBeenAssociatedTo1 {
              get { return SR.GetResourceString("ABindingInstanceHasAlreadyBeenAssociatedTo1", null); }
        }
        internal static string UnabletoImportPolicy {
              get { return SR.GetResourceString("UnabletoImportPolicy", null); }
        }
        internal static string UnImportedAssertionList {
              get { return SR.GetResourceString("UnImportedAssertionList", null); }
        }
        internal static string XPathUnavailable {
              get { return SR.GetResourceString("XPathUnavailable", null); }
        }
        internal static string DuplicatePolicyInWsdlSkipped {
              get { return SR.GetResourceString("DuplicatePolicyInWsdlSkipped", null); }
        }
        internal static string DuplicatePolicyDocumentSkipped {
              get { return SR.GetResourceString("DuplicatePolicyDocumentSkipped", null); }
        }
        internal static string PolicyDocumentMustHaveIdentifier {
              get { return SR.GetResourceString("PolicyDocumentMustHaveIdentifier", null); }
        }
        internal static string XPathPointer {
              get { return SR.GetResourceString("XPathPointer", null); }
        }
        internal static string UnableToFindPolicyWithId {
              get { return SR.GetResourceString("UnableToFindPolicyWithId", null); }
        }
        internal static string PolicyReferenceInvalidId {
              get { return SR.GetResourceString("PolicyReferenceInvalidId", null); }
        }
        internal static string PolicyReferenceMissingURI {
              get { return SR.GetResourceString("PolicyReferenceMissingURI", null); }
        }
        internal static string ExceededMaxPolicyComplexity {
              get { return SR.GetResourceString("ExceededMaxPolicyComplexity", null); }
        }
        internal static string ExceededMaxPolicySize {
              get { return SR.GetResourceString("ExceededMaxPolicySize", null); }
        }
        internal static string UnrecognizedPolicyElementInNamespace {
              get { return SR.GetResourceString("UnrecognizedPolicyElementInNamespace", null); }
        }
        internal static string UnsupportedPolicyDocumentRoot {
              get { return SR.GetResourceString("UnsupportedPolicyDocumentRoot", null); }
        }
        internal static string UnrecognizedPolicyDocumentNamespace {
              get { return SR.GetResourceString("UnrecognizedPolicyDocumentNamespace", null); }
        }
        internal static string NoUsablePolicyAssertions {
              get { return SR.GetResourceString("NoUsablePolicyAssertions", null); }
        }
        internal static string PolicyInWsdlMustHaveFragmentId {
              get { return SR.GetResourceString("PolicyInWsdlMustHaveFragmentId", null); }
        }
        internal static string FailedImportOfWsdl {
              get { return SR.GetResourceString("FailedImportOfWsdl", null); }
        }
        internal static string OptionalWSDLExtensionIgnored {
              get { return SR.GetResourceString("OptionalWSDLExtensionIgnored", null); }
        }
        internal static string RequiredWSDLExtensionIgnored {
              get { return SR.GetResourceString("RequiredWSDLExtensionIgnored", null); }
        }
        internal static string UnknownWSDLExtensionIgnored {
              get { return SR.GetResourceString("UnknownWSDLExtensionIgnored", null); }
        }
        internal static string WsdlExporterIsFaulted {
              get { return SR.GetResourceString("WsdlExporterIsFaulted", null); }
        }
        internal static string WsdlImporterIsFaulted {
              get { return SR.GetResourceString("WsdlImporterIsFaulted", null); }
        }
        internal static string WsdlImporterContractMustBeInKnownContracts {
              get { return SR.GetResourceString("WsdlImporterContractMustBeInKnownContracts", null); }
        }
        internal static string WsdlItemAlreadyFaulted {
              get { return SR.GetResourceString("WsdlItemAlreadyFaulted", null); }
        }
        internal static string InvalidPolicyExtensionTypeInConfig {
              get { return SR.GetResourceString("InvalidPolicyExtensionTypeInConfig", null); }
        }
        internal static string PolicyExtensionTypeRequiresDefaultConstructor {
              get { return SR.GetResourceString("PolicyExtensionTypeRequiresDefaultConstructor", null); }
        }
        internal static string PolicyExtensionImportError {
              get { return SR.GetResourceString("PolicyExtensionImportError", null); }
        }
        internal static string PolicyExtensionExportError {
              get { return SR.GetResourceString("PolicyExtensionExportError", null); }
        }
        internal static string MultipleCallsToExportContractWithSameContract {
              get { return SR.GetResourceString("MultipleCallsToExportContractWithSameContract", null); }
        }
        internal static string DuplicateContractQNameNameOnExport {
              get { return SR.GetResourceString("DuplicateContractQNameNameOnExport", null); }
        }
        internal static string WarnDuplicateBindingQNameNameOnExport {
              get { return SR.GetResourceString("WarnDuplicateBindingQNameNameOnExport", null); }
        }
        internal static string WarnSkippingOpertationWithWildcardAction {
              get { return SR.GetResourceString("WarnSkippingOpertationWithWildcardAction", null); }
        }
        internal static string WarnSkippingOpertationWithSessionOpenNotificationEnabled {
              get { return SR.GetResourceString("WarnSkippingOpertationWithSessionOpenNotificationEnabled", null); }
        }
        internal static string InvalidWsdlExtensionTypeInConfig {
              get { return SR.GetResourceString("InvalidWsdlExtensionTypeInConfig", null); }
        }
        internal static string WsdlExtensionTypeRequiresDefaultConstructor {
              get { return SR.GetResourceString("WsdlExtensionTypeRequiresDefaultConstructor", null); }
        }
        internal static string WsdlExtensionContractExportError {
              get { return SR.GetResourceString("WsdlExtensionContractExportError", null); }
        }
        internal static string WsdlExtensionEndpointExportError {
              get { return SR.GetResourceString("WsdlExtensionEndpointExportError", null); }
        }
        internal static string WsdlExtensionBeforeImportError {
              get { return SR.GetResourceString("WsdlExtensionBeforeImportError", null); }
        }
        internal static string WsdlExtensionImportError {
              get { return SR.GetResourceString("WsdlExtensionImportError", null); }
        }
        internal static string WsdlImportErrorMessageDetail {
              get { return SR.GetResourceString("WsdlImportErrorMessageDetail", null); }
        }
        internal static string WsdlImportErrorDependencyDetail {
              get { return SR.GetResourceString("WsdlImportErrorDependencyDetail", null); }
        }
        internal static string UnsupportedEnvelopeVersion {
              get { return SR.GetResourceString("UnsupportedEnvelopeVersion", null); }
        }
        internal static string NoValue0 {
              get { return SR.GetResourceString("NoValue0", null); }
        }
        internal static string UnsupportedBindingElementClone {
              get { return SR.GetResourceString("UnsupportedBindingElementClone", null); }
        }
        internal static string UnrecognizedBindingAssertions1 {
              get { return SR.GetResourceString("UnrecognizedBindingAssertions1", null); }
        }
        internal static string ServicesWithoutAServiceContractAttributeCan2 {
              get { return SR.GetResourceString("ServicesWithoutAServiceContractAttributeCan2", null); }
        }
        internal static string tooManyAttributesOfTypeOn2 {
              get { return SR.GetResourceString("tooManyAttributesOfTypeOn2", null); }
        }
        internal static string couldnTFindRequiredAttributeOfTypeOn2 {
              get { return SR.GetResourceString("couldnTFindRequiredAttributeOfTypeOn2", null); }
        }
        internal static string AttemptedToGetContractTypeForButThatTypeIs1 {
              get { return SR.GetResourceString("AttemptedToGetContractTypeForButThatTypeIs1", null); }
        }
        internal static string NoEndMethodFoundForAsyncBeginMethod3 {
              get { return SR.GetResourceString("NoEndMethodFoundForAsyncBeginMethod3", null); }
        }
        internal static string MoreThanOneEndMethodFoundForAsyncBeginMethod3 {
              get { return SR.GetResourceString("MoreThanOneEndMethodFoundForAsyncBeginMethod3", null); }
        }
        internal static string InvalidAsyncEndMethodSignatureForMethod2 {
              get { return SR.GetResourceString("InvalidAsyncEndMethodSignatureForMethod2", null); }
        }
        internal static string InvalidAsyncBeginMethodSignatureForMethod2 {
              get { return SR.GetResourceString("InvalidAsyncBeginMethodSignatureForMethod2", null); }
        }
        internal static string InAContractInheritanceHierarchyIfParentHasCallbackChildMustToo {
              get { return SR.GetResourceString("InAContractInheritanceHierarchyIfParentHasCallbackChildMustToo", null); }
        }
        internal static string InAContractInheritanceHierarchyTheServiceContract3_2 {
              get { return SR.GetResourceString("InAContractInheritanceHierarchyTheServiceContract3_2", null); }
        }
        internal static string CannotHaveTwoOperationsWithTheSameName3 {
              get { return SR.GetResourceString("CannotHaveTwoOperationsWithTheSameName3", null); }
        }
        internal static string CannotHaveTwoOperationsWithTheSameElement5 {
              get { return SR.GetResourceString("CannotHaveTwoOperationsWithTheSameElement5", null); }
        }
        internal static string CannotInheritTwoOperationsWithTheSameName3 {
              get { return SR.GetResourceString("CannotInheritTwoOperationsWithTheSameName3", null); }
        }
        internal static string SyncAsyncMatchConsistency_Parameters5 {
              get { return SR.GetResourceString("SyncAsyncMatchConsistency_Parameters5", null); }
        }
        internal static string SyncTaskMatchConsistency_Parameters5 {
              get { return SR.GetResourceString("SyncTaskMatchConsistency_Parameters5", null); }
        }
        internal static string TaskAsyncMatchConsistency_Parameters5 {
              get { return SR.GetResourceString("TaskAsyncMatchConsistency_Parameters5", null); }
        }
        internal static string SyncAsyncMatchConsistency_ReturnType5 {
              get { return SR.GetResourceString("SyncAsyncMatchConsistency_ReturnType5", null); }
        }
        internal static string SyncTaskMatchConsistency_ReturnType5 {
              get { return SR.GetResourceString("SyncTaskMatchConsistency_ReturnType5", null); }
        }
        internal static string TaskAsyncMatchConsistency_ReturnType5 {
              get { return SR.GetResourceString("TaskAsyncMatchConsistency_ReturnType5", null); }
        }
        internal static string SyncAsyncMatchConsistency_Attributes6 {
              get { return SR.GetResourceString("SyncAsyncMatchConsistency_Attributes6", null); }
        }
        internal static string SyncTaskMatchConsistency_Attributes6 {
              get { return SR.GetResourceString("SyncTaskMatchConsistency_Attributes6", null); }
        }
        internal static string TaskAsyncMatchConsistency_Attributes6 {
              get { return SR.GetResourceString("TaskAsyncMatchConsistency_Attributes6", null); }
        }
        internal static string SyncAsyncMatchConsistency_Property6 {
              get { return SR.GetResourceString("SyncAsyncMatchConsistency_Property6", null); }
        }
        internal static string SyncTaskMatchConsistency_Property6 {
              get { return SR.GetResourceString("SyncTaskMatchConsistency_Property6", null); }
        }
        internal static string TaskAsyncMatchConsistency_Property6 {
              get { return SR.GetResourceString("TaskAsyncMatchConsistency_Property6", null); }
        }
        internal static string ServiceOperationsMarkedWithIsOneWayTrueMust0 {
              get { return SR.GetResourceString("ServiceOperationsMarkedWithIsOneWayTrueMust0", null); }
        }
        internal static string OneWayOperationShouldNotSpecifyAReplyAction1 {
              get { return SR.GetResourceString("OneWayOperationShouldNotSpecifyAReplyAction1", null); }
        }
        internal static string OneWayAndFaultsIncompatible2 {
              get { return SR.GetResourceString("OneWayAndFaultsIncompatible2", null); }
        }
        internal static string OnlyMalformedMessagesAreSupported {
              get { return SR.GetResourceString("OnlyMalformedMessagesAreSupported", null); }
        }
        internal static string UnableToLocateOperation2 {
              get { return SR.GetResourceString("UnableToLocateOperation2", null); }
        }
        internal static string UnsupportedWSDLOnlyOneMessage {
              get { return SR.GetResourceString("UnsupportedWSDLOnlyOneMessage", null); }
        }
        internal static string UnsupportedWSDLTheFault {
              get { return SR.GetResourceString("UnsupportedWSDLTheFault", null); }
        }
        internal static string AsyncEndCalledOnWrongChannel {
              get { return SR.GetResourceString("AsyncEndCalledOnWrongChannel", null); }
        }
        internal static string AsyncEndCalledWithAnIAsyncResult {
              get { return SR.GetResourceString("AsyncEndCalledWithAnIAsyncResult", null); }
        }
        internal static string IsolationLevelMismatch2 {
              get { return SR.GetResourceString("IsolationLevelMismatch2", null); }
        }
        internal static string MessageHeaderIsNull0 {
              get { return SR.GetResourceString("MessageHeaderIsNull0", null); }
        }
        internal static string MessagePropertiesArraySize0 {
              get { return SR.GetResourceString("MessagePropertiesArraySize0", null); }
        }
        internal static string DuplicateBehavior1 {
              get { return SR.GetResourceString("DuplicateBehavior1", null); }
        }
        internal static string CantCreateChannelWithManualAddressing {
              get { return SR.GetResourceString("CantCreateChannelWithManualAddressing", null); }
        }
        internal static string XsdMissingRequiredAttribute1 {
              get { return SR.GetResourceString("XsdMissingRequiredAttribute1", null); }
        }
        internal static string IgnoreSoapHeaderBinding3 {
              get { return SR.GetResourceString("IgnoreSoapHeaderBinding3", null); }
        }
        internal static string IgnoreSoapFaultBinding3 {
              get { return SR.GetResourceString("IgnoreSoapFaultBinding3", null); }
        }
        internal static string IgnoreMessagePart3 {
              get { return SR.GetResourceString("IgnoreMessagePart3", null); }
        }
        internal static string CannotImportPrivacyNoticeElementWithoutVersionAttribute {
              get { return SR.GetResourceString("CannotImportPrivacyNoticeElementWithoutVersionAttribute", null); }
        }
        internal static string PrivacyNoticeElementVersionAttributeInvalid {
              get { return SR.GetResourceString("PrivacyNoticeElementVersionAttributeInvalid", null); }
        }
        internal static string XDCannotFindValueInDictionaryString {
              get { return SR.GetResourceString("XDCannotFindValueInDictionaryString", null); }
        }
        internal static string WmiGetObject {
              get { return SR.GetResourceString("WmiGetObject", null); }
        }
        internal static string WmiPutInstance {
              get { return SR.GetResourceString("WmiPutInstance", null); }
        }
        internal static string ObjectMustBeOpenedToDequeue {
              get { return SR.GetResourceString("ObjectMustBeOpenedToDequeue", null); }
        }
        internal static string NoChannelBuilderAvailable {
              get { return SR.GetResourceString("NoChannelBuilderAvailable", null); }
        }
        internal static string InvalidBindingScheme {
              get { return SR.GetResourceString("InvalidBindingScheme", null); }
        }
        internal static string CustomBindingRequiresTransport {
              get { return SR.GetResourceString("CustomBindingRequiresTransport", null); }
        }
        internal static string TransportBindingElementMustBeLast {
              get { return SR.GetResourceString("TransportBindingElementMustBeLast", null); }
        }
        internal static string MessageVersionMissingFromBinding {
              get { return SR.GetResourceString("MessageVersionMissingFromBinding", null); }
        }
        internal static string NotAllBindingElementsBuilt {
              get { return SR.GetResourceString("NotAllBindingElementsBuilt", null); }
        }
        internal static string MultipleMebesInParameters {
              get { return SR.GetResourceString("MultipleMebesInParameters", null); }
        }
        internal static string MultipleStreamUpgradeProvidersInParameters {
              get { return SR.GetResourceString("MultipleStreamUpgradeProvidersInParameters", null); }
        }
        internal static string SecurityCapabilitiesMismatched {
              get { return SR.GetResourceString("SecurityCapabilitiesMismatched", null); }
        }
        internal static string BaseAddressMustBeAbsolute {
              get { return SR.GetResourceString("BaseAddressMustBeAbsolute", null); }
        }
        internal static string BaseAddressDuplicateScheme {
              get { return SR.GetResourceString("BaseAddressDuplicateScheme", null); }
        }
        internal static string BaseAddressCannotHaveUserInfo {
              get { return SR.GetResourceString("BaseAddressCannotHaveUserInfo", null); }
        }
        internal static string TransportBindingElementNotFound {
              get { return SR.GetResourceString("TransportBindingElementNotFound", null); }
        }
        internal static string ChannelDemuxerBindingElementNotFound {
              get { return SR.GetResourceString("ChannelDemuxerBindingElementNotFound", null); }
        }
        internal static string BaseAddressCannotHaveQuery {
              get { return SR.GetResourceString("BaseAddressCannotHaveQuery", null); }
        }
        internal static string BaseAddressCannotHaveFragment {
              get { return SR.GetResourceString("BaseAddressCannotHaveFragment", null); }
        }
        internal static string UriMustBeAbsolute {
              get { return SR.GetResourceString("UriMustBeAbsolute", null); }
        }
        internal static string BindingProtocolMappingNotDefined {
              get { return SR.GetResourceString("BindingProtocolMappingNotDefined", null); }
        }
        internal static string Default {
              get { return SR.GetResourceString("Default", null); }
        }
        internal static string AdminMTAWorkerThreadException {
              get { return SR.GetResourceString("AdminMTAWorkerThreadException", null); }
        }
        internal static string InternalError {
              get { return SR.GetResourceString("InternalError", null); }
        }
        internal static string ClsidNotInApplication {
              get { return SR.GetResourceString("ClsidNotInApplication", null); }
        }
        internal static string ClsidNotInConfiguration {
              get { return SR.GetResourceString("ClsidNotInConfiguration", null); }
        }
        internal static string EndpointNotAnIID {
              get { return SR.GetResourceString("EndpointNotAnIID", null); }
        }
        internal static string ServiceStringFormatError {
              get { return SR.GetResourceString("ServiceStringFormatError", null); }
        }
        internal static string ContractTypeNotAnIID {
              get { return SR.GetResourceString("ContractTypeNotAnIID", null); }
        }
        internal static string ApplicationNotFound {
              get { return SR.GetResourceString("ApplicationNotFound", null); }
        }
        internal static string NoVoteIssued {
              get { return SR.GetResourceString("NoVoteIssued", null); }
        }
        internal static string FailedToConvertTypelibraryToAssembly {
              get { return SR.GetResourceString("FailedToConvertTypelibraryToAssembly", null); }
        }
        internal static string BadInterfaceVersion {
              get { return SR.GetResourceString("BadInterfaceVersion", null); }
        }
        internal static string FailedToLoadTypeLibrary {
              get { return SR.GetResourceString("FailedToLoadTypeLibrary", null); }
        }
        internal static string NativeTypeLibraryNotAllowed {
              get { return SR.GetResourceString("NativeTypeLibraryNotAllowed", null); }
        }
        internal static string InterfaceNotFoundInAssembly {
              get { return SR.GetResourceString("InterfaceNotFoundInAssembly", null); }
        }
        internal static string UdtNotFoundInAssembly {
              get { return SR.GetResourceString("UdtNotFoundInAssembly", null); }
        }
        internal static string UnknownMonikerKeyword {
              get { return SR.GetResourceString("UnknownMonikerKeyword", null); }
        }
        internal static string MonikerIncorectSerializer {
              get { return SR.GetResourceString("MonikerIncorectSerializer", null); }
        }
        internal static string NoEqualSignFound {
              get { return SR.GetResourceString("NoEqualSignFound", null); }
        }
        internal static string KewordMissingValue {
              get { return SR.GetResourceString("KewordMissingValue", null); }
        }
        internal static string BadlyTerminatedValue {
              get { return SR.GetResourceString("BadlyTerminatedValue", null); }
        }
        internal static string MissingQuote {
              get { return SR.GetResourceString("MissingQuote", null); }
        }
        internal static string RepeatedKeyword {
              get { return SR.GetResourceString("RepeatedKeyword", null); }
        }
        internal static string InterfaceNotFoundInConfig {
              get { return SR.GetResourceString("InterfaceNotFoundInConfig", null); }
        }
        internal static string CannotHaveNullOrEmptyNameOrNamespaceForIID {
              get { return SR.GetResourceString("CannotHaveNullOrEmptyNameOrNamespaceForIID", null); }
        }
        internal static string MethodGivenInConfigNotFoundOnInterface {
              get { return SR.GetResourceString("MethodGivenInConfigNotFoundOnInterface", null); }
        }
        internal static string MonikerIncorrectServerIdentityForMex {
              get { return SR.GetResourceString("MonikerIncorrectServerIdentityForMex", null); }
        }
        internal static string MonikerAddressNotSpecified {
              get { return SR.GetResourceString("MonikerAddressNotSpecified", null); }
        }
        internal static string MonikerMexBindingSectionNameNotSpecified {
              get { return SR.GetResourceString("MonikerMexBindingSectionNameNotSpecified", null); }
        }
        internal static string MonikerMexAddressNotSpecified {
              get { return SR.GetResourceString("MonikerMexAddressNotSpecified", null); }
        }
        internal static string MonikerContractNotSpecified {
              get { return SR.GetResourceString("MonikerContractNotSpecified", null); }
        }
        internal static string MonikerBindingNotSpecified {
              get { return SR.GetResourceString("MonikerBindingNotSpecified", null); }
        }
        internal static string MonikerBindingNamespacetNotSpecified {
              get { return SR.GetResourceString("MonikerBindingNamespacetNotSpecified", null); }
        }
        internal static string MonikerFailedToDoMexRetrieve {
              get { return SR.GetResourceString("MonikerFailedToDoMexRetrieve", null); }
        }
        internal static string MonikerContractNotFoundInRetreivedMex {
              get { return SR.GetResourceString("MonikerContractNotFoundInRetreivedMex", null); }
        }
        internal static string MonikerNoneOfTheBindingMatchedTheSpecifiedBinding {
              get { return SR.GetResourceString("MonikerNoneOfTheBindingMatchedTheSpecifiedBinding", null); }
        }
        internal static string MonikerMissingColon {
              get { return SR.GetResourceString("MonikerMissingColon", null); }
        }
        internal static string MonikerIncorrectServerIdentity {
              get { return SR.GetResourceString("MonikerIncorrectServerIdentity", null); }
        }
        internal static string NoInterface {
              get { return SR.GetResourceString("NoInterface", null); }
        }
        internal static string DuplicateTokenExFailed {
              get { return SR.GetResourceString("DuplicateTokenExFailed", null); }
        }
        internal static string AccessCheckFailed {
              get { return SR.GetResourceString("AccessCheckFailed", null); }
        }
        internal static string ImpersonateAnonymousTokenFailed {
              get { return SR.GetResourceString("ImpersonateAnonymousTokenFailed", null); }
        }
        internal static string OnlyByRefVariantSafeArraysAllowed {
              get { return SR.GetResourceString("OnlyByRefVariantSafeArraysAllowed", null); }
        }
        internal static string OnlyOneDimensionalSafeArraysAllowed {
              get { return SR.GetResourceString("OnlyOneDimensionalSafeArraysAllowed", null); }
        }
        internal static string OnlyVariantTypeElementsAllowed {
              get { return SR.GetResourceString("OnlyVariantTypeElementsAllowed", null); }
        }
        internal static string OnlyZeroLBoundAllowed {
              get { return SR.GetResourceString("OnlyZeroLBoundAllowed", null); }
        }
        internal static string OpenThreadTokenFailed {
              get { return SR.GetResourceString("OpenThreadTokenFailed", null); }
        }
        internal static string OpenProcessTokenFailed {
              get { return SR.GetResourceString("OpenProcessTokenFailed", null); }
        }
        internal static string InvalidIsolationLevelValue {
              get { return SR.GetResourceString("InvalidIsolationLevelValue", null); }
        }
        internal static string UnsupportedConversion {
              get { return SR.GetResourceString("UnsupportedConversion", null); }
        }
        internal static string FailedProxyProviderCreation {
              get { return SR.GetResourceString("FailedProxyProviderCreation", null); }
        }
        internal static string UnableToLoadDll {
              get { return SR.GetResourceString("UnableToLoadDll", null); }
        }
        internal static string InterfaceNotRegistered {
              get { return SR.GetResourceString("InterfaceNotRegistered", null); }
        }
        internal static string BadInterfaceRegistration {
              get { return SR.GetResourceString("BadInterfaceRegistration", null); }
        }
        internal static string NoTypeLibraryFoundForInterface {
              get { return SR.GetResourceString("NoTypeLibraryFoundForInterface", null); }
        }
        internal static string VariantArrayNull {
              get { return SR.GetResourceString("VariantArrayNull", null); }
        }
        internal static string UnableToRetrievepUnk {
              get { return SR.GetResourceString("UnableToRetrievepUnk", null); }
        }
        internal static string PersistWrapperIsNull {
              get { return SR.GetResourceString("PersistWrapperIsNull", null); }
        }
        internal static string UnexpectedThreadingModel {
              get { return SR.GetResourceString("UnexpectedThreadingModel", null); }
        }
        internal static string NoneOfTheMethodsForInterfaceFoundInConfig {
              get { return SR.GetResourceString("NoneOfTheMethodsForInterfaceFoundInConfig", null); }
        }
        internal static string InvalidWebServiceInterface {
              get { return SR.GetResourceString("InvalidWebServiceInterface", null); }
        }
        internal static string InvalidWebServiceParameter {
              get { return SR.GetResourceString("InvalidWebServiceParameter", null); }
        }
        internal static string InvalidWebServiceReturnValue {
              get { return SR.GetResourceString("InvalidWebServiceReturnValue", null); }
        }
        internal static string OperationNotFound {
              get { return SR.GetResourceString("OperationNotFound", null); }
        }
        internal static string BadDispID {
              get { return SR.GetResourceString("BadDispID", null); }
        }
        internal static string BadParamCount {
              get { return SR.GetResourceString("BadParamCount", null); }
        }
        internal static string BindingNotFoundInConfig {
              get { return SR.GetResourceString("BindingNotFoundInConfig", null); }
        }
        internal static string AddressNotSpecified {
              get { return SR.GetResourceString("AddressNotSpecified", null); }
        }
        internal static string BindingNotSpecified {
              get { return SR.GetResourceString("BindingNotSpecified", null); }
        }
        internal static string OnlyVariantAllowedByRef {
              get { return SR.GetResourceString("OnlyVariantAllowedByRef", null); }
        }
        internal static string CannotResolveTypeForParamInMessageDescription {
              get { return SR.GetResourceString("CannotResolveTypeForParamInMessageDescription", null); }
        }
        internal static string TooLate {
              get { return SR.GetResourceString("TooLate", null); }
        }
        internal static string RequireConfiguredMethods {
              get { return SR.GetResourceString("RequireConfiguredMethods", null); }
        }
        internal static string RequireConfiguredInterfaces {
              get { return SR.GetResourceString("RequireConfiguredInterfaces", null); }
        }
        internal static string CannotCreateChannelOption {
              get { return SR.GetResourceString("CannotCreateChannelOption", null); }
        }
        internal static string NoTransactionInContext {
              get { return SR.GetResourceString("NoTransactionInContext", null); }
        }
        internal static string IssuedTokenFlowNotAllowed {
              get { return SR.GetResourceString("IssuedTokenFlowNotAllowed", null); }
        }
        internal static string GeneralSchemaValidationError {
              get { return SR.GetResourceString("GeneralSchemaValidationError", null); }
        }
        internal static string SchemaValidationError {
              get { return SR.GetResourceString("SchemaValidationError", null); }
        }
        internal static string ContractBindingAddressCannotBeNull {
              get { return SR.GetResourceString("ContractBindingAddressCannotBeNull", null); }
        }
        internal static string TypeLoadForContractTypeIIDFailedWith {
              get { return SR.GetResourceString("TypeLoadForContractTypeIIDFailedWith", null); }
        }
        internal static string BindingLoadFromConfigFailedWith {
              get { return SR.GetResourceString("BindingLoadFromConfigFailedWith", null); }
        }
        internal static string PooledApplicationNotSupportedForComplusHostedScenarios {
              get { return SR.GetResourceString("PooledApplicationNotSupportedForComplusHostedScenarios", null); }
        }
        internal static string RecycledApplicationNotSupportedForComplusHostedScenarios {
              get { return SR.GetResourceString("RecycledApplicationNotSupportedForComplusHostedScenarios", null); }
        }
        internal static string BadImpersonationLevelForOutOfProcWas {
              get { return SR.GetResourceString("BadImpersonationLevelForOutOfProcWas", null); }
        }
        internal static string ComPlusInstanceProviderRequiresMessage0 {
              get { return SR.GetResourceString("ComPlusInstanceProviderRequiresMessage0", null); }
        }
        internal static string ComPlusInstanceCreationRequestSchema {
              get { return SR.GetResourceString("ComPlusInstanceCreationRequestSchema", null); }
        }
        internal static string ComPlusMethodCallSchema {
              get { return SR.GetResourceString("ComPlusMethodCallSchema", null); }
        }
        internal static string ComPlusServiceSchema {
              get { return SR.GetResourceString("ComPlusServiceSchema", null); }
        }
        internal static string ComPlusServiceSchemaDllHost {
              get { return SR.GetResourceString("ComPlusServiceSchemaDllHost", null); }
        }
        internal static string ComPlusTLBImportSchema {
              get { return SR.GetResourceString("ComPlusTLBImportSchema", null); }
        }
        internal static string ComPlusServiceHostStartingServiceErrorNoQFE {
              get { return SR.GetResourceString("ComPlusServiceHostStartingServiceErrorNoQFE", null); }
        }
        internal static string ComIntegrationManifestCreationFailed {
              get { return SR.GetResourceString("ComIntegrationManifestCreationFailed", null); }
        }
        internal static string TempDirectoryNotFound {
              get { return SR.GetResourceString("TempDirectoryNotFound", null); }
        }
        internal static string CannotAccessDirectory {
              get { return SR.GetResourceString("CannotAccessDirectory", null); }
        }
        internal static string CLSIDDoesNotSupportIPersistStream {
              get { return SR.GetResourceString("CLSIDDoesNotSupportIPersistStream", null); }
        }
        internal static string CLSIDOfTypeDoesNotMatch {
              get { return SR.GetResourceString("CLSIDOfTypeDoesNotMatch", null); }
        }
        internal static string TargetObjectDoesNotSupportIPersistStream {
              get { return SR.GetResourceString("TargetObjectDoesNotSupportIPersistStream", null); }
        }
        internal static string TargetTypeIsAnIntefaceButCorrespoindingTypeIsNotPersistStreamTypeWrapper {
              get { return SR.GetResourceString("TargetTypeIsAnIntefaceButCorrespoindingTypeIsNotPersistStreamTypeWrapper", null); }
        }
        internal static string NotAllowedPersistableCLSID {
              get { return SR.GetResourceString("NotAllowedPersistableCLSID", null); }
        }
        internal static string TransferringToComplus {
              get { return SR.GetResourceString("TransferringToComplus", null); }
        }
        internal static string NamedArgsNotSupported {
              get { return SR.GetResourceString("NamedArgsNotSupported", null); }
        }
        internal static string MexBindingNotFoundInConfig {
              get { return SR.GetResourceString("MexBindingNotFoundInConfig", null); }
        }
        internal static string ClaimTypeCannotBeEmpty {
              get { return SR.GetResourceString("ClaimTypeCannotBeEmpty", null); }
        }
        internal static string X509ChainIsEmpty {
              get { return SR.GetResourceString("X509ChainIsEmpty", null); }
        }
        internal static string MissingCustomCertificateValidator {
              get { return SR.GetResourceString("MissingCustomCertificateValidator", null); }
        }
        internal static string MissingMembershipProvider {
              get { return SR.GetResourceString("MissingMembershipProvider", null); }
        }
        internal static string MissingCustomUserNamePasswordValidator {
              get { return SR.GetResourceString("MissingCustomUserNamePasswordValidator", null); }
        }
        internal static string SpnegoImpersonationLevelCannotBeSetToNone {
              get { return SR.GetResourceString("SpnegoImpersonationLevelCannotBeSetToNone", null); }
        }
        internal static string PublicKeyNotRSA {
              get { return SR.GetResourceString("PublicKeyNotRSA", null); }
        }
        internal static string SecurityAuditFailToLoadDll {
              get { return SR.GetResourceString("SecurityAuditFailToLoadDll", null); }
        }
        internal static string SecurityAuditPlatformNotSupported {
              get { return SR.GetResourceString("SecurityAuditPlatformNotSupported", null); }
        }
        internal static string NoPrincipalSpecifiedInAuthorizationContext {
              get { return SR.GetResourceString("NoPrincipalSpecifiedInAuthorizationContext", null); }
        }
        internal static string AccessDenied {
              get { return SR.GetResourceString("AccessDenied", null); }
        }
        internal static string SecurityAuditNotSupportedOnChannelFactory {
              get { return SR.GetResourceString("SecurityAuditNotSupportedOnChannelFactory", null); }
        }
        internal static string ExpiredTokenInChannelParameters {
              get { return SR.GetResourceString("ExpiredTokenInChannelParameters", null); }
        }
        internal static string NoTokenInChannelParameters {
              get { return SR.GetResourceString("NoTokenInChannelParameters", null); }
        }
        internal static string ArgumentOutOfRange {
              get { return SR.GetResourceString("ArgumentOutOfRange", null); }
        }
        internal static string InsufficientCryptoSupport {
              get { return SR.GetResourceString("InsufficientCryptoSupport", null); }
        }
        internal static string InsufficientCredentials {
              get { return SR.GetResourceString("InsufficientCredentials", null); }
        }
        internal static string UnexpectedSecurityTokensDuringHandshake {
              get { return SR.GetResourceString("UnexpectedSecurityTokensDuringHandshake", null); }
        }
        internal static string InsufficientResolverSettings {
              get { return SR.GetResourceString("InsufficientResolverSettings", null); }
        }
        internal static string InvalidResolverMode {
              get { return SR.GetResourceString("InvalidResolverMode", null); }
        }
        internal static string MustOverrideInitialize {
              get { return SR.GetResourceString("MustOverrideInitialize", null); }
        }
        internal static string NotValidWhenOpen {
              get { return SR.GetResourceString("NotValidWhenOpen", null); }
        }
        internal static string NotValidWhenClosed {
              get { return SR.GetResourceString("NotValidWhenClosed", null); }
        }
        internal static string DuplicatePeerRegistration {
              get { return SR.GetResourceString("DuplicatePeerRegistration", null); }
        }
        internal static string MessagePropagationException {
              get { return SR.GetResourceString("MessagePropagationException", null); }
        }
        internal static string NotificationException {
              get { return SR.GetResourceString("NotificationException", null); }
        }
        internal static string ResolverException {
              get { return SR.GetResourceString("ResolverException", null); }
        }
        internal static string RefreshIntervalMustBeGreaterThanZero {
              get { return SR.GetResourceString("RefreshIntervalMustBeGreaterThanZero", null); }
        }
        internal static string CleanupIntervalMustBeGreaterThanZero {
              get { return SR.GetResourceString("CleanupIntervalMustBeGreaterThanZero", null); }
        }
        internal static string AmbiguousConnectivitySpec {
              get { return SR.GetResourceString("AmbiguousConnectivitySpec", null); }
        }
        internal static string MustRegisterMoreThanZeroAddresses {
              get { return SR.GetResourceString("MustRegisterMoreThanZeroAddresses", null); }
        }
        internal static string BasicHttpContextBindingRequiresAllowCookie {
              get { return SR.GetResourceString("BasicHttpContextBindingRequiresAllowCookie", null); }
        }
        internal static string CallbackContextOnlySupportedInWSAddressing10 {
              get { return SR.GetResourceString("CallbackContextOnlySupportedInWSAddressing10", null); }
        }
        internal static string ListenAddressAlreadyContainsContext {
              get { return SR.GetResourceString("ListenAddressAlreadyContainsContext", null); }
        }
        internal static string MultipleContextHeadersFoundInCallbackAddress {
              get { return SR.GetResourceString("MultipleContextHeadersFoundInCallbackAddress", null); }
        }
        internal static string CallbackContextNotExpectedOnIncomingMessageAtClient {
              get { return SR.GetResourceString("CallbackContextNotExpectedOnIncomingMessageAtClient", null); }
        }
        internal static string CallbackContextOnlySupportedInSoap {
              get { return SR.GetResourceString("CallbackContextOnlySupportedInSoap", null); }
        }
        internal static string ContextBindingElementCannotProvideChannelFactory {
              get { return SR.GetResourceString("ContextBindingElementCannotProvideChannelFactory", null); }
        }
        internal static string ContextBindingElementCannotProvideChannelListener {
              get { return SR.GetResourceString("ContextBindingElementCannotProvideChannelListener", null); }
        }
        internal static string InvalidCookieContent {
              get { return SR.GetResourceString("InvalidCookieContent", null); }
        }
        internal static string SchemaViolationInsideContextHeader {
              get { return SR.GetResourceString("SchemaViolationInsideContextHeader", null); }
        }
        internal static string CallbackContextNotExpectedOnOutgoingMessageAtServer {
              get { return SR.GetResourceString("CallbackContextNotExpectedOnOutgoingMessageAtServer", null); }
        }
        internal static string ChannelIsOpen {
              get { return SR.GetResourceString("ChannelIsOpen", null); }
        }
        internal static string ContextManagementNotEnabled {
              get { return SR.GetResourceString("ContextManagementNotEnabled", null); }
        }
        internal static string CachedContextIsImmutable {
              get { return SR.GetResourceString("CachedContextIsImmutable", null); }
        }
        internal static string InvalidMessageContext {
              get { return SR.GetResourceString("InvalidMessageContext", null); }
        }
        internal static string InvalidContextReceived {
              get { return SR.GetResourceString("InvalidContextReceived", null); }
        }
        internal static string BehaviorRequiresContextProtocolSupportInBinding {
              get { return SR.GetResourceString("BehaviorRequiresContextProtocolSupportInBinding", null); }
        }
        internal static string HttpCookieContextExchangeMechanismNotCompatibleWithTransportType {
              get { return SR.GetResourceString("HttpCookieContextExchangeMechanismNotCompatibleWithTransportType", null); }
        }
        internal static string HttpCookieContextExchangeMechanismNotCompatibleWithTransportCookieSetting {
              get { return SR.GetResourceString("HttpCookieContextExchangeMechanismNotCompatibleWithTransportCookieSetting", null); }
        }
        internal static string PolicyImportContextBindingElementCollectionIsNull {
              get { return SR.GetResourceString("PolicyImportContextBindingElementCollectionIsNull", null); }
        }
        internal static string ContextChannelFactoryChannelCreatedDetail {
              get { return SR.GetResourceString("ContextChannelFactoryChannelCreatedDetail", null); }
        }
        internal static string XmlFormatViolationInContextHeader {
              get { return SR.GetResourceString("XmlFormatViolationInContextHeader", null); }
        }
        internal static string XmlFormatViolationInCallbackContextHeader {
              get { return SR.GetResourceString("XmlFormatViolationInCallbackContextHeader", null); }
        }
        internal static string OleTxHeaderCorrupt {
              get { return SR.GetResourceString("OleTxHeaderCorrupt", null); }
        }
        internal static string WsatHeaderCorrupt {
              get { return SR.GetResourceString("WsatHeaderCorrupt", null); }
        }
        internal static string FailedToDeserializeIssuedToken {
              get { return SR.GetResourceString("FailedToDeserializeIssuedToken", null); }
        }
        internal static string InvalidPropagationToken {
              get { return SR.GetResourceString("InvalidPropagationToken", null); }
        }
        internal static string InvalidWsatExtendedInfo {
              get { return SR.GetResourceString("InvalidWsatExtendedInfo", null); }
        }
        internal static string TMCommunicationError {
              get { return SR.GetResourceString("TMCommunicationError", null); }
        }
        internal static string UnmarshalTransactionFaulted {
              get { return SR.GetResourceString("UnmarshalTransactionFaulted", null); }
        }
        internal static string InvalidRegistrationHeaderTransactionId {
              get { return SR.GetResourceString("InvalidRegistrationHeaderTransactionId", null); }
        }
        internal static string InvalidRegistrationHeaderIdentifier {
              get { return SR.GetResourceString("InvalidRegistrationHeaderIdentifier", null); }
        }
        internal static string InvalidRegistrationHeaderTokenId {
              get { return SR.GetResourceString("InvalidRegistrationHeaderTokenId", null); }
        }
        internal static string InvalidCoordinationContextTransactionId {
              get { return SR.GetResourceString("InvalidCoordinationContextTransactionId", null); }
        }
        internal static string WsatRegistryValueReadError {
              get { return SR.GetResourceString("WsatRegistryValueReadError", null); }
        }
        internal static string WsatProtocolServiceDisabled {
              get { return SR.GetResourceString("WsatProtocolServiceDisabled", null); }
        }
        internal static string InboundTransactionsDisabled {
              get { return SR.GetResourceString("InboundTransactionsDisabled", null); }
        }
        internal static string SourceTransactionsDisabled {
              get { return SR.GetResourceString("SourceTransactionsDisabled", null); }
        }
        internal static string WsatUriCreationFailed {
              get { return SR.GetResourceString("WsatUriCreationFailed", null); }
        }
        internal static string InvalidWsatProtocolVersion {
              get { return SR.GetResourceString("InvalidWsatProtocolVersion", null); }
        }
        internal static string ParameterCannotBeEmpty {
              get { return SR.GetResourceString("ParameterCannotBeEmpty", null); }
        }
        internal static string RedirectCache {
              get { return SR.GetResourceString("RedirectCache", null); }
        }
        internal static string RedirectResource {
              get { return SR.GetResourceString("RedirectResource", null); }
        }
        internal static string RedirectUseIntermediary {
              get { return SR.GetResourceString("RedirectUseIntermediary", null); }
        }
        internal static string RedirectGenericMessage {
              get { return SR.GetResourceString("RedirectGenericMessage", null); }
        }
        internal static string RedirectMustProvideLocation {
              get { return SR.GetResourceString("RedirectMustProvideLocation", null); }
        }
        internal static string RedirectCacheNoLocationAllowed {
              get { return SR.GetResourceString("RedirectCacheNoLocationAllowed", null); }
        }
        internal static string RedirectionInfoStringFormatWithNamespace {
              get { return SR.GetResourceString("RedirectionInfoStringFormatWithNamespace", null); }
        }
        internal static string RedirectionInfoStringFormatNoNamespace {
              get { return SR.GetResourceString("RedirectionInfoStringFormatNoNamespace", null); }
        }
        internal static string RetryGenericMessage {
              get { return SR.GetResourceString("RetryGenericMessage", null); }
        }
        internal static string ActivityCallback {
              get { return SR.GetResourceString("ActivityCallback", null); }
        }
        internal static string ActivityClose {
              get { return SR.GetResourceString("ActivityClose", null); }
        }
        internal static string ActivityConstructChannelFactory {
              get { return SR.GetResourceString("ActivityConstructChannelFactory", null); }
        }
        internal static string ActivityConstructServiceHost {
              get { return SR.GetResourceString("ActivityConstructServiceHost", null); }
        }
        internal static string ActivityExecuteMethod {
              get { return SR.GetResourceString("ActivityExecuteMethod", null); }
        }
        internal static string ActivityExecuteAsyncMethod {
              get { return SR.GetResourceString("ActivityExecuteAsyncMethod", null); }
        }
        internal static string ActivityCloseChannelFactory {
              get { return SR.GetResourceString("ActivityCloseChannelFactory", null); }
        }
        internal static string ActivityCloseClientBase {
              get { return SR.GetResourceString("ActivityCloseClientBase", null); }
        }
        internal static string ActivityCloseServiceHost {
              get { return SR.GetResourceString("ActivityCloseServiceHost", null); }
        }
        internal static string ActivityListenAt {
              get { return SR.GetResourceString("ActivityListenAt", null); }
        }
        internal static string ActivityOpen {
              get { return SR.GetResourceString("ActivityOpen", null); }
        }
        internal static string ActivityOpenServiceHost {
              get { return SR.GetResourceString("ActivityOpenServiceHost", null); }
        }
        internal static string ActivityOpenChannelFactory {
              get { return SR.GetResourceString("ActivityOpenChannelFactory", null); }
        }
        internal static string ActivityOpenClientBase {
              get { return SR.GetResourceString("ActivityOpenClientBase", null); }
        }
        internal static string ActivityProcessAction {
              get { return SR.GetResourceString("ActivityProcessAction", null); }
        }
        internal static string ActivityProcessingMessage {
              get { return SR.GetResourceString("ActivityProcessingMessage", null); }
        }
        internal static string ActivityReceiveBytes {
              get { return SR.GetResourceString("ActivityReceiveBytes", null); }
        }
        internal static string ActivitySecuritySetup {
              get { return SR.GetResourceString("ActivitySecuritySetup", null); }
        }
        internal static string ActivitySecurityRenew {
              get { return SR.GetResourceString("ActivitySecurityRenew", null); }
        }
        internal static string ActivitySecurityClose {
              get { return SR.GetResourceString("ActivitySecurityClose", null); }
        }
        internal static string ActivitySharedListenerConnection {
              get { return SR.GetResourceString("ActivitySharedListenerConnection", null); }
        }
        internal static string ActivitySocketConnection {
              get { return SR.GetResourceString("ActivitySocketConnection", null); }
        }
        internal static string ActivityReadOnConnection {
              get { return SR.GetResourceString("ActivityReadOnConnection", null); }
        }
        internal static string ActivityReceiveAtVia {
              get { return SR.GetResourceString("ActivityReceiveAtVia", null); }
        }
        internal static string TraceCodeBeginExecuteMethod {
              get { return SR.GetResourceString("TraceCodeBeginExecuteMethod", null); }
        }
        internal static string TraceCodeChannelCreated {
              get { return SR.GetResourceString("TraceCodeChannelCreated", null); }
        }
        internal static string TraceCodeChannelDisposed {
              get { return SR.GetResourceString("TraceCodeChannelDisposed", null); }
        }
        internal static string TraceCodeChannelMessageSent {
              get { return SR.GetResourceString("TraceCodeChannelMessageSent", null); }
        }
        internal static string TraceCodeChannelPreparedMessage {
              get { return SR.GetResourceString("TraceCodeChannelPreparedMessage", null); }
        }
        internal static string TraceCodeCommunicationObjectAborted {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectAborted", null); }
        }
        internal static string TraceCodeCommunicationObjectAbortFailed {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectAbortFailed", null); }
        }
        internal static string TraceCodeCommunicationObjectCloseFailed {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectCloseFailed", null); }
        }
        internal static string TraceCodeCommunicationObjectClosed {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectClosed", null); }
        }
        internal static string TraceCodeCommunicationObjectCreated {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectCreated", null); }
        }
        internal static string TraceCodeCommunicationObjectClosing {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectClosing", null); }
        }
        internal static string TraceCodeCommunicationObjectDisposing {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectDisposing", null); }
        }
        internal static string TraceCodeCommunicationObjectFaultReason {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectFaultReason", null); }
        }
        internal static string TraceCodeCommunicationObjectFaulted {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectFaulted", null); }
        }
        internal static string TraceCodeCommunicationObjectOpenFailed {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectOpenFailed", null); }
        }
        internal static string TraceCodeCommunicationObjectOpened {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectOpened", null); }
        }
        internal static string TraceCodeCommunicationObjectOpening {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectOpening", null); }
        }
        internal static string TraceCodeConfigurationIsReadOnly {
              get { return SR.GetResourceString("TraceCodeConfigurationIsReadOnly", null); }
        }
        internal static string TraceCodeConfiguredExtensionTypeNotFound {
              get { return SR.GetResourceString("TraceCodeConfiguredExtensionTypeNotFound", null); }
        }
        internal static string TraceCodeConnectionAbandoned {
              get { return SR.GetResourceString("TraceCodeConnectionAbandoned", null); }
        }
        internal static string TraceCodeConnectToIPEndpoint {
              get { return SR.GetResourceString("TraceCodeConnectToIPEndpoint", null); }
        }
        internal static string TraceCodeConnectionPoolCloseException {
              get { return SR.GetResourceString("TraceCodeConnectionPoolCloseException", null); }
        }
        internal static string TraceCodeConnectionPoolIdleTimeoutReached {
              get { return SR.GetResourceString("TraceCodeConnectionPoolIdleTimeoutReached", null); }
        }
        internal static string TraceCodeConnectionPoolLeaseTimeoutReached {
              get { return SR.GetResourceString("TraceCodeConnectionPoolLeaseTimeoutReached", null); }
        }
        internal static string TraceCodeConnectionPoolMaxOutboundConnectionsPerEndpointQuotaReached {
              get { return SR.GetResourceString("TraceCodeConnectionPoolMaxOutboundConnectionsPerEndpointQuotaReached", null); }
        }
        internal static string TraceCodeServerMaxPooledConnectionsQuotaReached {
              get { return SR.GetResourceString("TraceCodeServerMaxPooledConnectionsQuotaReached", null); }
        }
        internal static string TraceCodeDefaultEndpointsAdded {
              get { return SR.GetResourceString("TraceCodeDefaultEndpointsAdded", null); }
        }
        internal static string TraceCodeDiagnosticsFailedMessageTrace {
              get { return SR.GetResourceString("TraceCodeDiagnosticsFailedMessageTrace", null); }
        }
        internal static string TraceCodeDidNotUnderstandMessageHeader {
              get { return SR.GetResourceString("TraceCodeDidNotUnderstandMessageHeader", null); }
        }
        internal static string TraceCodeDroppedAMessage {
              get { return SR.GetResourceString("TraceCodeDroppedAMessage", null); }
        }
        internal static string TraceCodeCannotBeImportedInCurrentFormat {
              get { return SR.GetResourceString("TraceCodeCannotBeImportedInCurrentFormat", null); }
        }
        internal static string TraceCodeElementTypeDoesntMatchConfiguredType {
              get { return SR.GetResourceString("TraceCodeElementTypeDoesntMatchConfiguredType", null); }
        }
        internal static string TraceCodeEndExecuteMethod {
              get { return SR.GetResourceString("TraceCodeEndExecuteMethod", null); }
        }
        internal static string TraceCodeEndpointListenerClose {
              get { return SR.GetResourceString("TraceCodeEndpointListenerClose", null); }
        }
        internal static string TraceCodeEndpointListenerOpen {
              get { return SR.GetResourceString("TraceCodeEndpointListenerOpen", null); }
        }
        internal static string TraceCodeErrorInvokingUserCode {
              get { return SR.GetResourceString("TraceCodeErrorInvokingUserCode", null); }
        }
        internal static string TraceCodeEvaluationContextNotFound {
              get { return SR.GetResourceString("TraceCodeEvaluationContextNotFound", null); }
        }
        internal static string TraceCodeExportSecurityChannelBindingEntry {
              get { return SR.GetResourceString("TraceCodeExportSecurityChannelBindingEntry", null); }
        }
        internal static string TraceCodeExportSecurityChannelBindingExit {
              get { return SR.GetResourceString("TraceCodeExportSecurityChannelBindingExit", null); }
        }
        internal static string TraceCodeExtensionCollectionDoesNotExist {
              get { return SR.GetResourceString("TraceCodeExtensionCollectionDoesNotExist", null); }
        }
        internal static string TraceCodeExtensionCollectionIsEmpty {
              get { return SR.GetResourceString("TraceCodeExtensionCollectionIsEmpty", null); }
        }
        internal static string TraceCodeExtensionCollectionNameNotFound {
              get { return SR.GetResourceString("TraceCodeExtensionCollectionNameNotFound", null); }
        }
        internal static string TraceCodeExtensionElementAlreadyExistsInCollection {
              get { return SR.GetResourceString("TraceCodeExtensionElementAlreadyExistsInCollection", null); }
        }
        internal static string TraceCodeExtensionTypeNotFound {
              get { return SR.GetResourceString("TraceCodeExtensionTypeNotFound", null); }
        }
        internal static string TraceCodeFailedToAddAnActivityIdHeader {
              get { return SR.GetResourceString("TraceCodeFailedToAddAnActivityIdHeader", null); }
        }
        internal static string TraceCodeFailedToReadAnActivityIdHeader {
              get { return SR.GetResourceString("TraceCodeFailedToReadAnActivityIdHeader", null); }
        }
        internal static string TraceCodeFilterNotMatchedNodeQuotaExceeded {
              get { return SR.GetResourceString("TraceCodeFilterNotMatchedNodeQuotaExceeded", null); }
        }
        internal static string TraceCodeGetBehaviorElement {
              get { return SR.GetResourceString("TraceCodeGetBehaviorElement", null); }
        }
        internal static string TraceCodeGetChannelEndpointElement {
              get { return SR.GetResourceString("TraceCodeGetChannelEndpointElement", null); }
        }
        internal static string TraceCodeGetCommonBehaviors {
              get { return SR.GetResourceString("TraceCodeGetCommonBehaviors", null); }
        }
        internal static string TraceCodeGetConfigurationSection {
              get { return SR.GetResourceString("TraceCodeGetConfigurationSection", null); }
        }
        internal static string TraceCodeGetConfiguredBinding {
              get { return SR.GetResourceString("TraceCodeGetConfiguredBinding", null); }
        }
        internal static string TraceCodeGetDefaultConfiguredBinding {
              get { return SR.GetResourceString("TraceCodeGetDefaultConfiguredBinding", null); }
        }
        internal static string TraceCodeGetConfiguredEndpoint {
              get { return SR.GetResourceString("TraceCodeGetConfiguredEndpoint", null); }
        }
        internal static string TraceCodeGetDefaultConfiguredEndpoint {
              get { return SR.GetResourceString("TraceCodeGetDefaultConfiguredEndpoint", null); }
        }
        internal static string TraceCodeGetServiceElement {
              get { return SR.GetResourceString("TraceCodeGetServiceElement", null); }
        }
        internal static string TraceCodeHttpAuthFailed {
              get { return SR.GetResourceString("TraceCodeHttpAuthFailed", null); }
        }
        internal static string TraceCodeHttpActionMismatch {
              get { return SR.GetResourceString("TraceCodeHttpActionMismatch", null); }
        }
        internal static string TraceCodeHttpChannelMessageReceiveFailed {
              get { return SR.GetResourceString("TraceCodeHttpChannelMessageReceiveFailed", null); }
        }
        internal static string TraceCodeHttpChannelRequestAborted {
              get { return SR.GetResourceString("TraceCodeHttpChannelRequestAborted", null); }
        }
        internal static string TraceCodeHttpChannelResponseAborted {
              get { return SR.GetResourceString("TraceCodeHttpChannelResponseAborted", null); }
        }
        internal static string TraceCodeHttpChannelUnexpectedResponse {
              get { return SR.GetResourceString("TraceCodeHttpChannelUnexpectedResponse", null); }
        }
        internal static string TraceCodeHttpResponseReceived {
              get { return SR.GetResourceString("TraceCodeHttpResponseReceived", null); }
        }
        internal static string TraceCodeHttpChannelConcurrentReceiveQuotaReached {
              get { return SR.GetResourceString("TraceCodeHttpChannelConcurrentReceiveQuotaReached", null); }
        }
        internal static string TraceCodeHttpsClientCertificateInvalid {
              get { return SR.GetResourceString("TraceCodeHttpsClientCertificateInvalid", null); }
        }
        internal static string TraceCodeHttpsClientCertificateInvalid1 {
              get { return SR.GetResourceString("TraceCodeHttpsClientCertificateInvalid1", null); }
        }
        internal static string TraceCodeHttpsClientCertificateNotPresent {
              get { return SR.GetResourceString("TraceCodeHttpsClientCertificateNotPresent", null); }
        }
        internal static string TraceCodeImportSecurityChannelBindingEntry {
              get { return SR.GetResourceString("TraceCodeImportSecurityChannelBindingEntry", null); }
        }
        internal static string TraceCodeImportSecurityChannelBindingExit {
              get { return SR.GetResourceString("TraceCodeImportSecurityChannelBindingExit", null); }
        }
        internal static string TraceCodeIncompatibleExistingTransportManager {
              get { return SR.GetResourceString("TraceCodeIncompatibleExistingTransportManager", null); }
        }
        internal static string TraceCodeInitiatingNamedPipeConnection {
              get { return SR.GetResourceString("TraceCodeInitiatingNamedPipeConnection", null); }
        }
        internal static string TraceCodeInitiatingTcpConnection {
              get { return SR.GetResourceString("TraceCodeInitiatingTcpConnection", null); }
        }
        internal static string TraceCodeIssuanceTokenProviderBeginSecurityNegotiation {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderBeginSecurityNegotiation", null); }
        }
        internal static string TraceCodeIssuanceTokenProviderEndSecurityNegotiation {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderEndSecurityNegotiation", null); }
        }
        internal static string TraceCodeIssuanceTokenProviderRedirectApplied {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderRedirectApplied", null); }
        }
        internal static string TraceCodeIssuanceTokenProviderRemovedCachedToken {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderRemovedCachedToken", null); }
        }
        internal static string TraceCodeIssuanceTokenProviderServiceTokenCacheFull {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderServiceTokenCacheFull", null); }
        }
        internal static string TraceCodeIssuanceTokenProviderUsingCachedToken {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderUsingCachedToken", null); }
        }
        internal static string TraceCodeListenerCreated {
              get { return SR.GetResourceString("TraceCodeListenerCreated", null); }
        }
        internal static string TraceCodeListenerDisposed {
              get { return SR.GetResourceString("TraceCodeListenerDisposed", null); }
        }
        internal static string TraceCodeMaxPendingConnectionsReached {
              get { return SR.GetResourceString("TraceCodeMaxPendingConnectionsReached", null); }
        }
        internal static string TraceCodeMaxAcceptedChannelsReached {
              get { return SR.GetResourceString("TraceCodeMaxAcceptedChannelsReached", null); }
        }
        internal static string TraceCodeMessageClosed {
              get { return SR.GetResourceString("TraceCodeMessageClosed", null); }
        }
        internal static string TraceCodeMessageClosedAgain {
              get { return SR.GetResourceString("TraceCodeMessageClosedAgain", null); }
        }
        internal static string TraceCodeMessageCopied {
              get { return SR.GetResourceString("TraceCodeMessageCopied", null); }
        }
        internal static string TraceCodeMessageCountLimitExceeded {
              get { return SR.GetResourceString("TraceCodeMessageCountLimitExceeded", null); }
        }
        internal static string TraceCodeMessageNotLoggedQuotaExceeded {
              get { return SR.GetResourceString("TraceCodeMessageNotLoggedQuotaExceeded", null); }
        }
        internal static string TraceCodeMessageRead {
              get { return SR.GetResourceString("TraceCodeMessageRead", null); }
        }
        internal static string TraceCodeMessageSent {
              get { return SR.GetResourceString("TraceCodeMessageSent", null); }
        }
        internal static string TraceCodeMessageReceived {
              get { return SR.GetResourceString("TraceCodeMessageReceived", null); }
        }
        internal static string TraceCodeMessageWritten {
              get { return SR.GetResourceString("TraceCodeMessageWritten", null); }
        }
        internal static string TraceCodeMessageProcessingPaused {
              get { return SR.GetResourceString("TraceCodeMessageProcessingPaused", null); }
        }
        internal static string TraceCodeNegotiationAuthenticatorAttached {
              get { return SR.GetResourceString("TraceCodeNegotiationAuthenticatorAttached", null); }
        }
        internal static string TraceCodeNegotiationTokenProviderAttached {
              get { return SR.GetResourceString("TraceCodeNegotiationTokenProviderAttached", null); }
        }
        internal static string TraceCodeNoExistingTransportManager {
              get { return SR.GetResourceString("TraceCodeNoExistingTransportManager", null); }
        }
        internal static string TraceCodeOpenedListener {
              get { return SR.GetResourceString("TraceCodeOpenedListener", null); }
        }
        internal static string TraceCodeOverridingDuplicateConfigurationKey {
              get { return SR.GetResourceString("TraceCodeOverridingDuplicateConfigurationKey", null); }
        }
        internal static string TraceCodePerformanceCounterFailedToLoad {
              get { return SR.GetResourceString("TraceCodePerformanceCounterFailedToLoad", null); }
        }
        internal static string TraceCodePerformanceCountersFailed {
              get { return SR.GetResourceString("TraceCodePerformanceCountersFailed", null); }
        }
        internal static string TraceCodePerformanceCountersFailedDuringUpdate {
              get { return SR.GetResourceString("TraceCodePerformanceCountersFailedDuringUpdate", null); }
        }
        internal static string TraceCodePerformanceCountersFailedForService {
              get { return SR.GetResourceString("TraceCodePerformanceCountersFailedForService", null); }
        }
        internal static string TraceCodePerformanceCountersFailedOnRelease {
              get { return SR.GetResourceString("TraceCodePerformanceCountersFailedOnRelease", null); }
        }
        internal static string TraceCodePrematureDatagramEof {
              get { return SR.GetResourceString("TraceCodePrematureDatagramEof", null); }
        }
        internal static string TraceCodeRemoveBehavior {
              get { return SR.GetResourceString("TraceCodeRemoveBehavior", null); }
        }
        internal static string TraceCodeRequestChannelReplyReceived {
              get { return SR.GetResourceString("TraceCodeRequestChannelReplyReceived", null); }
        }
        internal static string TraceCodeSecurity {
              get { return SR.GetResourceString("TraceCodeSecurity", null); }
        }
        internal static string TraceCodeSecurityActiveServerSessionRemoved {
              get { return SR.GetResourceString("TraceCodeSecurityActiveServerSessionRemoved", null); }
        }
        internal static string TraceCodeSecurityAuditWrittenFailure {
              get { return SR.GetResourceString("TraceCodeSecurityAuditWrittenFailure", null); }
        }
        internal static string TraceCodeSecurityAuditWrittenSuccess {
              get { return SR.GetResourceString("TraceCodeSecurityAuditWrittenSuccess", null); }
        }
        internal static string TraceCodeSecurityBindingIncomingMessageVerified {
              get { return SR.GetResourceString("TraceCodeSecurityBindingIncomingMessageVerified", null); }
        }
        internal static string TraceCodeSecurityBindingOutgoingMessageSecured {
              get { return SR.GetResourceString("TraceCodeSecurityBindingOutgoingMessageSecured", null); }
        }
        internal static string TraceCodeSecurityBindingSecureOutgoingMessageFailure {
              get { return SR.GetResourceString("TraceCodeSecurityBindingSecureOutgoingMessageFailure", null); }
        }
        internal static string TraceCodeSecurityBindingVerifyIncomingMessageFailure {
              get { return SR.GetResourceString("TraceCodeSecurityBindingVerifyIncomingMessageFailure", null); }
        }
        internal static string TraceCodeSecurityClientSessionKeyRenewed {
              get { return SR.GetResourceString("TraceCodeSecurityClientSessionKeyRenewed", null); }
        }
        internal static string TraceCodeSecurityClientSessionCloseSent {
              get { return SR.GetResourceString("TraceCodeSecurityClientSessionCloseSent", null); }
        }
        internal static string TraceCodeSecurityClientSessionCloseResponseSent {
              get { return SR.GetResourceString("TraceCodeSecurityClientSessionCloseResponseSent", null); }
        }
        internal static string TraceCodeSecurityClientSessionCloseMessageReceived {
              get { return SR.GetResourceString("TraceCodeSecurityClientSessionCloseMessageReceived", null); }
        }
        internal static string TraceCodeSecurityClientSessionPreviousKeyDiscarded {
              get { return SR.GetResourceString("TraceCodeSecurityClientSessionPreviousKeyDiscarded", null); }
        }
        internal static string TraceCodeSecurityContextTokenCacheFull {
              get { return SR.GetResourceString("TraceCodeSecurityContextTokenCacheFull", null); }
        }
        internal static string TraceCodeSecurityIdentityDeterminationFailure {
              get { return SR.GetResourceString("TraceCodeSecurityIdentityDeterminationFailure", null); }
        }
        internal static string TraceCodeSecurityIdentityDeterminationSuccess {
              get { return SR.GetResourceString("TraceCodeSecurityIdentityDeterminationSuccess", null); }
        }
        internal static string TraceCodeSecurityIdentityHostNameNormalizationFailure {
              get { return SR.GetResourceString("TraceCodeSecurityIdentityHostNameNormalizationFailure", null); }
        }
        internal static string TraceCodeSecurityIdentityVerificationFailure {
              get { return SR.GetResourceString("TraceCodeSecurityIdentityVerificationFailure", null); }
        }
        internal static string TraceCodeSecurityIdentityVerificationSuccess {
              get { return SR.GetResourceString("TraceCodeSecurityIdentityVerificationSuccess", null); }
        }
        internal static string TraceCodeSecurityImpersonationFailure {
              get { return SR.GetResourceString("TraceCodeSecurityImpersonationFailure", null); }
        }
        internal static string TraceCodeSecurityImpersonationSuccess {
              get { return SR.GetResourceString("TraceCodeSecurityImpersonationSuccess", null); }
        }
        internal static string TraceCodeSecurityInactiveSessionFaulted {
              get { return SR.GetResourceString("TraceCodeSecurityInactiveSessionFaulted", null); }
        }
        internal static string TraceCodeSecurityNegotiationProcessingFailure {
              get { return SR.GetResourceString("TraceCodeSecurityNegotiationProcessingFailure", null); }
        }
        internal static string TraceCodeSecurityNewServerSessionKeyIssued {
              get { return SR.GetResourceString("TraceCodeSecurityNewServerSessionKeyIssued", null); }
        }
        internal static string TraceCodeSecurityPendingServerSessionAdded {
              get { return SR.GetResourceString("TraceCodeSecurityPendingServerSessionAdded", null); }
        }
        internal static string TraceCodeSecurityPendingServerSessionClosed {
              get { return SR.GetResourceString("TraceCodeSecurityPendingServerSessionClosed", null); }
        }
        internal static string TraceCodeSecurityPendingServerSessionActivated {
              get { return SR.GetResourceString("TraceCodeSecurityPendingServerSessionActivated", null); }
        }
        internal static string TraceCodeSecurityServerSessionCloseReceived {
              get { return SR.GetResourceString("TraceCodeSecurityServerSessionCloseReceived", null); }
        }
        internal static string TraceCodeSecurityServerSessionCloseResponseReceived {
              get { return SR.GetResourceString("TraceCodeSecurityServerSessionCloseResponseReceived", null); }
        }
        internal static string TraceCodeSecurityServerSessionAbortedFaultSent {
              get { return SR.GetResourceString("TraceCodeSecurityServerSessionAbortedFaultSent", null); }
        }
        internal static string TraceCodeSecurityServerSessionKeyUpdated {
              get { return SR.GetResourceString("TraceCodeSecurityServerSessionKeyUpdated", null); }
        }
        internal static string TraceCodeSecurityServerSessionRenewalFaultSent {
              get { return SR.GetResourceString("TraceCodeSecurityServerSessionRenewalFaultSent", null); }
        }
        internal static string TraceCodeSecuritySessionCloseResponseSent {
              get { return SR.GetResourceString("TraceCodeSecuritySessionCloseResponseSent", null); }
        }
        internal static string TraceCodeSecuritySessionServerCloseSent {
              get { return SR.GetResourceString("TraceCodeSecuritySessionServerCloseSent", null); }
        }
        internal static string TraceCodeSecuritySessionAbortedFaultReceived {
              get { return SR.GetResourceString("TraceCodeSecuritySessionAbortedFaultReceived", null); }
        }
        internal static string TraceCodeSecuritySessionAbortedFaultSendFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionAbortedFaultSendFailure", null); }
        }
        internal static string TraceCodeSecuritySessionClosedResponseReceived {
              get { return SR.GetResourceString("TraceCodeSecuritySessionClosedResponseReceived", null); }
        }
        internal static string TraceCodeSecuritySessionClosedResponseSendFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionClosedResponseSendFailure", null); }
        }
        internal static string TraceCodeSecuritySessionServerCloseSendFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionServerCloseSendFailure", null); }
        }
        internal static string TraceCodeSecuritySessionKeyRenewalFaultReceived {
              get { return SR.GetResourceString("TraceCodeSecuritySessionKeyRenewalFaultReceived", null); }
        }
        internal static string TraceCodeSecuritySessionRedirectApplied {
              get { return SR.GetResourceString("TraceCodeSecuritySessionRedirectApplied", null); }
        }
        internal static string TraceCodeSecuritySessionRenewFaultSendFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionRenewFaultSendFailure", null); }
        }
        internal static string TraceCodeSecuritySessionRequestorOperationFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionRequestorOperationFailure", null); }
        }
        internal static string TraceCodeSecuritySessionRequestorOperationSuccess {
              get { return SR.GetResourceString("TraceCodeSecuritySessionRequestorOperationSuccess", null); }
        }
        internal static string TraceCodeSecuritySessionRequestorStartOperation {
              get { return SR.GetResourceString("TraceCodeSecuritySessionRequestorStartOperation", null); }
        }
        internal static string TraceCodeSecuritySessionResponderOperationFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionResponderOperationFailure", null); }
        }
        internal static string TraceCodeSecuritySpnToSidMappingFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySpnToSidMappingFailure", null); }
        }
        internal static string TraceCodeSecurityTokenAuthenticatorClosed {
              get { return SR.GetResourceString("TraceCodeSecurityTokenAuthenticatorClosed", null); }
        }
        internal static string TraceCodeSecurityTokenAuthenticatorOpened {
              get { return SR.GetResourceString("TraceCodeSecurityTokenAuthenticatorOpened", null); }
        }
        internal static string TraceCodeSecurityTokenProviderClosed {
              get { return SR.GetResourceString("TraceCodeSecurityTokenProviderClosed", null); }
        }
        internal static string TraceCodeSecurityTokenProviderOpened {
              get { return SR.GetResourceString("TraceCodeSecurityTokenProviderOpened", null); }
        }
        internal static string TraceCodeServiceChannelLifetime {
              get { return SR.GetResourceString("TraceCodeServiceChannelLifetime", null); }
        }
        internal static string TraceCodeServiceHostBaseAddresses {
              get { return SR.GetResourceString("TraceCodeServiceHostBaseAddresses", null); }
        }
        internal static string TraceCodeServiceHostTimeoutOnClose {
              get { return SR.GetResourceString("TraceCodeServiceHostTimeoutOnClose", null); }
        }
        internal static string TraceCodeServiceHostFaulted {
              get { return SR.GetResourceString("TraceCodeServiceHostFaulted", null); }
        }
        internal static string TraceCodeServiceHostErrorOnReleasePerformanceCounter {
              get { return SR.GetResourceString("TraceCodeServiceHostErrorOnReleasePerformanceCounter", null); }
        }
        internal static string TraceCodeServiceThrottleLimitReached {
              get { return SR.GetResourceString("TraceCodeServiceThrottleLimitReached", null); }
        }
        internal static string TraceCodeServiceThrottleLimitReachedInternal {
              get { return SR.GetResourceString("TraceCodeServiceThrottleLimitReachedInternal", null); }
        }
        internal static string TraceCodeManualFlowThrottleLimitReached {
              get { return SR.GetResourceString("TraceCodeManualFlowThrottleLimitReached", null); }
        }
        internal static string TraceCodeProcessMessage2Paused {
              get { return SR.GetResourceString("TraceCodeProcessMessage2Paused", null); }
        }
        internal static string TraceCodeProcessMessage3Paused {
              get { return SR.GetResourceString("TraceCodeProcessMessage3Paused", null); }
        }
        internal static string TraceCodeProcessMessage31Paused {
              get { return SR.GetResourceString("TraceCodeProcessMessage31Paused", null); }
        }
        internal static string TraceCodeProcessMessage4Paused {
              get { return SR.GetResourceString("TraceCodeProcessMessage4Paused", null); }
        }
        internal static string TraceCodeServiceOperationExceptionOnReply {
              get { return SR.GetResourceString("TraceCodeServiceOperationExceptionOnReply", null); }
        }
        internal static string TraceCodeServiceOperationMissingReply {
              get { return SR.GetResourceString("TraceCodeServiceOperationMissingReply", null); }
        }
        internal static string TraceCodeServiceOperationMissingReplyContext {
              get { return SR.GetResourceString("TraceCodeServiceOperationMissingReplyContext", null); }
        }
        internal static string TraceCodeServiceSecurityNegotiationCompleted {
              get { return SR.GetResourceString("TraceCodeServiceSecurityNegotiationCompleted", null); }
        }
        internal static string TraceCodeSecuritySessionDemuxFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionDemuxFailure", null); }
        }
        internal static string TraceCodeServiceHostCreation {
              get { return SR.GetResourceString("TraceCodeServiceHostCreation", null); }
        }
        internal static string TraceCodeSkipBehavior {
              get { return SR.GetResourceString("TraceCodeSkipBehavior", null); }
        }
        internal static string TraceCodeFailedAcceptFromPool {
              get { return SR.GetResourceString("TraceCodeFailedAcceptFromPool", null); }
        }
        internal static string TraceCodeSystemTimeResolution {
              get { return SR.GetResourceString("TraceCodeSystemTimeResolution", null); }
        }
        internal static string TraceCodeRequestContextAbort {
              get { return SR.GetResourceString("TraceCodeRequestContextAbort", null); }
        }
        internal static string TraceCodeSharedManagerServiceEndpointNotExist {
              get { return SR.GetResourceString("TraceCodeSharedManagerServiceEndpointNotExist", null); }
        }
        internal static string TraceCodeSocketConnectionAbort {
              get { return SR.GetResourceString("TraceCodeSocketConnectionAbort", null); }
        }
        internal static string TraceCodeSocketConnectionAbortClose {
              get { return SR.GetResourceString("TraceCodeSocketConnectionAbortClose", null); }
        }
        internal static string TraceCodeSocketConnectionClose {
              get { return SR.GetResourceString("TraceCodeSocketConnectionClose", null); }
        }
        internal static string TraceCodeSocketConnectionCreate {
              get { return SR.GetResourceString("TraceCodeSocketConnectionCreate", null); }
        }
        internal static string TraceCodeSpnegoClientNegotiationCompleted {
              get { return SR.GetResourceString("TraceCodeSpnegoClientNegotiationCompleted", null); }
        }
        internal static string TraceCodeSpnegoServiceNegotiationCompleted {
              get { return SR.GetResourceString("TraceCodeSpnegoServiceNegotiationCompleted", null); }
        }
        internal static string TraceCodeSpnegoClientNegotiation {
              get { return SR.GetResourceString("TraceCodeSpnegoClientNegotiation", null); }
        }
        internal static string TraceCodeSpnegoServiceNegotiation {
              get { return SR.GetResourceString("TraceCodeSpnegoServiceNegotiation", null); }
        }
        internal static string TraceCodeSslClientCertMissing {
              get { return SR.GetResourceString("TraceCodeSslClientCertMissing", null); }
        }
        internal static string TraceCodeStreamSecurityUpgradeAccepted {
              get { return SR.GetResourceString("TraceCodeStreamSecurityUpgradeAccepted", null); }
        }
        internal static string TraceCodeTcpChannelMessageReceiveFailed {
              get { return SR.GetResourceString("TraceCodeTcpChannelMessageReceiveFailed", null); }
        }
        internal static string TraceCodeTcpChannelMessageReceived {
              get { return SR.GetResourceString("TraceCodeTcpChannelMessageReceived", null); }
        }
        internal static string TraceCodeUnderstoodMessageHeader {
              get { return SR.GetResourceString("TraceCodeUnderstoodMessageHeader", null); }
        }
        internal static string TraceCodeUnhandledAction {
              get { return SR.GetResourceString("TraceCodeUnhandledAction", null); }
        }
        internal static string TraceCodeUnhandledExceptionInUserOperation {
              get { return SR.GetResourceString("TraceCodeUnhandledExceptionInUserOperation", null); }
        }
        internal static string TraceCodeWebHostFailedToActivateService {
              get { return SR.GetResourceString("TraceCodeWebHostFailedToActivateService", null); }
        }
        internal static string TraceCodeWebHostFailedToCompile {
              get { return SR.GetResourceString("TraceCodeWebHostFailedToCompile", null); }
        }
        internal static string TraceCodeWmiPut {
              get { return SR.GetResourceString("TraceCodeWmiPut", null); }
        }
        internal static string TraceCodeWsmexNonCriticalWsdlExportError {
              get { return SR.GetResourceString("TraceCodeWsmexNonCriticalWsdlExportError", null); }
        }
        internal static string TraceCodeWsmexNonCriticalWsdlImportError {
              get { return SR.GetResourceString("TraceCodeWsmexNonCriticalWsdlImportError", null); }
        }
        internal static string TraceCodeFailedToOpenIncomingChannel {
              get { return SR.GetResourceString("TraceCodeFailedToOpenIncomingChannel", null); }
        }
        internal static string TraceCodeTransportListen {
              get { return SR.GetResourceString("TraceCodeTransportListen", null); }
        }
        internal static string TraceCodeWsrmInvalidCreateSequence {
              get { return SR.GetResourceString("TraceCodeWsrmInvalidCreateSequence", null); }
        }
        internal static string TraceCodeWsrmInvalidMessage {
              get { return SR.GetResourceString("TraceCodeWsrmInvalidMessage", null); }
        }
        internal static string TraceCodeWsrmMaxPendingChannelsReached {
              get { return SR.GetResourceString("TraceCodeWsrmMaxPendingChannelsReached", null); }
        }
        internal static string TraceCodeWsrmMessageDropped {
              get { return SR.GetResourceString("TraceCodeWsrmMessageDropped", null); }
        }
        internal static string TraceCodeWsrmReceiveAcknowledgement {
              get { return SR.GetResourceString("TraceCodeWsrmReceiveAcknowledgement", null); }
        }
        internal static string TraceCodeWsrmReceiveLastSequenceMessage {
              get { return SR.GetResourceString("TraceCodeWsrmReceiveLastSequenceMessage", null); }
        }
        internal static string TraceCodeWsrmReceiveSequenceMessage {
              get { return SR.GetResourceString("TraceCodeWsrmReceiveSequenceMessage", null); }
        }
        internal static string TraceCodeWsrmSendAcknowledgement {
              get { return SR.GetResourceString("TraceCodeWsrmSendAcknowledgement", null); }
        }
        internal static string TraceCodeWsrmSendLastSequenceMessage {
              get { return SR.GetResourceString("TraceCodeWsrmSendLastSequenceMessage", null); }
        }
        internal static string TraceCodeWsrmSendSequenceMessage {
              get { return SR.GetResourceString("TraceCodeWsrmSendSequenceMessage", null); }
        }
        internal static string TraceCodeWsrmSequenceFaulted {
              get { return SR.GetResourceString("TraceCodeWsrmSequenceFaulted", null); }
        }
        internal static string TraceCodeChannelConnectionDropped {
              get { return SR.GetResourceString("TraceCodeChannelConnectionDropped", null); }
        }
        internal static string TraceCodeAsyncCallbackThrewException {
              get { return SR.GetResourceString("TraceCodeAsyncCallbackThrewException", null); }
        }
        internal static string TraceCodeMetadataExchangeClientSendRequest {
              get { return SR.GetResourceString("TraceCodeMetadataExchangeClientSendRequest", null); }
        }
        internal static string TraceCodeMetadataExchangeClientReceiveReply {
              get { return SR.GetResourceString("TraceCodeMetadataExchangeClientReceiveReply", null); }
        }
        internal static string TraceCodeWarnHelpPageEnabledNoBaseAddress {
              get { return SR.GetResourceString("TraceCodeWarnHelpPageEnabledNoBaseAddress", null); }
        }
        internal static string TraceCodeTcpConnectError {
              get { return SR.GetResourceString("TraceCodeTcpConnectError", null); }
        }
        internal static string TraceCodeTxSourceTxScopeRequiredIsTransactedTransport {
              get { return SR.GetResourceString("TraceCodeTxSourceTxScopeRequiredIsTransactedTransport", null); }
        }
        internal static string TraceCodeTxSourceTxScopeRequiredIsTransactionFlow {
              get { return SR.GetResourceString("TraceCodeTxSourceTxScopeRequiredIsTransactionFlow", null); }
        }
        internal static string TraceCodeTxSourceTxScopeRequiredIsAttachedTransaction {
              get { return SR.GetResourceString("TraceCodeTxSourceTxScopeRequiredIsAttachedTransaction", null); }
        }
        internal static string TraceCodeTxSourceTxScopeRequiredUsingExistingTransaction {
              get { return SR.GetResourceString("TraceCodeTxSourceTxScopeRequiredUsingExistingTransaction", null); }
        }
        internal static string TraceCodeTxCompletionStatusCompletedForAutocomplete {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusCompletedForAutocomplete", null); }
        }
        internal static string TraceCodeTxCompletionStatusCompletedForError {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusCompletedForError", null); }
        }
        internal static string TraceCodeTxCompletionStatusCompletedForSetComplete {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusCompletedForSetComplete", null); }
        }
        internal static string TraceCodeTxCompletionStatusCompletedForTACOSC {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusCompletedForTACOSC", null); }
        }
        internal static string TraceCodeTxCompletionStatusCompletedForAsyncAbort {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusCompletedForAsyncAbort", null); }
        }
        internal static string TraceCodeTxCompletionStatusRemainsAttached {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusRemainsAttached", null); }
        }
        internal static string TraceCodeTxCompletionStatusAbortedOnSessionClose {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusAbortedOnSessionClose", null); }
        }
        internal static string TraceCodeTxReleaseServiceInstanceOnCompletion {
              get { return SR.GetResourceString("TraceCodeTxReleaseServiceInstanceOnCompletion", null); }
        }
        internal static string TraceCodeTxAsyncAbort {
              get { return SR.GetResourceString("TraceCodeTxAsyncAbort", null); }
        }
        internal static string TraceCodeTxFailedToNegotiateOleTx {
              get { return SR.GetResourceString("TraceCodeTxFailedToNegotiateOleTx", null); }
        }
        internal static string TraceCodeTxSourceTxScopeRequiredIsCreateNewTransaction {
              get { return SR.GetResourceString("TraceCodeTxSourceTxScopeRequiredIsCreateNewTransaction", null); }
        }
        internal static string TraceCodeActivatingMessageReceived {
              get { return SR.GetResourceString("TraceCodeActivatingMessageReceived", null); }
        }
        internal static string TraceCodeDICPInstanceContextCached {
              get { return SR.GetResourceString("TraceCodeDICPInstanceContextCached", null); }
        }
        internal static string TraceCodeDICPInstanceContextRemovedFromCache {
              get { return SR.GetResourceString("TraceCodeDICPInstanceContextRemovedFromCache", null); }
        }
        internal static string TraceCodeInstanceContextBoundToDurableInstance {
              get { return SR.GetResourceString("TraceCodeInstanceContextBoundToDurableInstance", null); }
        }
        internal static string TraceCodeInstanceContextDetachedFromDurableInstance {
              get { return SR.GetResourceString("TraceCodeInstanceContextDetachedFromDurableInstance", null); }
        }
        internal static string TraceCodeContextChannelFactoryChannelCreated {
              get { return SR.GetResourceString("TraceCodeContextChannelFactoryChannelCreated", null); }
        }
        internal static string TraceCodeContextChannelListenerChannelAccepted {
              get { return SR.GetResourceString("TraceCodeContextChannelListenerChannelAccepted", null); }
        }
        internal static string TraceCodeContextProtocolContextAddedToMessage {
              get { return SR.GetResourceString("TraceCodeContextProtocolContextAddedToMessage", null); }
        }
        internal static string TraceCodeContextProtocolContextRetrievedFromMessage {
              get { return SR.GetResourceString("TraceCodeContextProtocolContextRetrievedFromMessage", null); }
        }
        internal static string TraceCodeWorkflowServiceHostCreated {
              get { return SR.GetResourceString("TraceCodeWorkflowServiceHostCreated", null); }
        }
        internal static string TraceCodeServiceDurableInstanceDeleted {
              get { return SR.GetResourceString("TraceCodeServiceDurableInstanceDeleted", null); }
        }
        internal static string TraceCodeServiceDurableInstanceDisposed {
              get { return SR.GetResourceString("TraceCodeServiceDurableInstanceDisposed", null); }
        }
        internal static string TraceCodeServiceDurableInstanceLoaded {
              get { return SR.GetResourceString("TraceCodeServiceDurableInstanceLoaded", null); }
        }
        internal static string TraceCodeServiceDurableInstanceSaved {
              get { return SR.GetResourceString("TraceCodeServiceDurableInstanceSaved", null); }
        }
        internal static string TraceCodeWorkflowDurableInstanceLoaded {
              get { return SR.GetResourceString("TraceCodeWorkflowDurableInstanceLoaded", null); }
        }
        internal static string TraceCodeWorkflowDurableInstanceActivated {
              get { return SR.GetResourceString("TraceCodeWorkflowDurableInstanceActivated", null); }
        }
        internal static string TraceCodeWorkflowDurableInstanceAborted {
              get { return SR.GetResourceString("TraceCodeWorkflowDurableInstanceAborted", null); }
        }
        internal static string TraceCodeWorkflowOperationInvokerItemQueued {
              get { return SR.GetResourceString("TraceCodeWorkflowOperationInvokerItemQueued", null); }
        }
        internal static string TraceCodeWorkflowRequestContextReplySent {
              get { return SR.GetResourceString("TraceCodeWorkflowRequestContextReplySent", null); }
        }
        internal static string TraceCodeWorkflowRequestContextFaultSent {
              get { return SR.GetResourceString("TraceCodeWorkflowRequestContextFaultSent", null); }
        }
        internal static string TraceCodeSqlPersistenceProviderSQLCallStart {
              get { return SR.GetResourceString("TraceCodeSqlPersistenceProviderSQLCallStart", null); }
        }
        internal static string TraceCodeSqlPersistenceProviderSQLCallEnd {
              get { return SR.GetResourceString("TraceCodeSqlPersistenceProviderSQLCallEnd", null); }
        }
        internal static string TraceCodeSqlPersistenceProviderOpenParameters {
              get { return SR.GetResourceString("TraceCodeSqlPersistenceProviderOpenParameters", null); }
        }
        internal static string TraceCodeSyncContextSchedulerServiceTimerCancelled {
              get { return SR.GetResourceString("TraceCodeSyncContextSchedulerServiceTimerCancelled", null); }
        }
        internal static string TraceCodeSyncContextSchedulerServiceTimerCreated {
              get { return SR.GetResourceString("TraceCodeSyncContextSchedulerServiceTimerCreated", null); }
        }
        internal static string TraceCodeSyndicationReadFeedBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationReadFeedBegin", null); }
        }
        internal static string TraceCodeSyndicationReadFeedEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationReadFeedEnd", null); }
        }
        internal static string TraceCodeSyndicationReadItemBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationReadItemBegin", null); }
        }
        internal static string TraceCodeSyndicationReadItemEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationReadItemEnd", null); }
        }
        internal static string TraceCodeSyndicationWriteFeedBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteFeedBegin", null); }
        }
        internal static string TraceCodeSyndicationWriteFeedEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteFeedEnd", null); }
        }
        internal static string TraceCodeSyndicationWriteItemBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteItemBegin", null); }
        }
        internal static string TraceCodeSyndicationWriteItemEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteItemEnd", null); }
        }
        internal static string TraceCodeSyndicationProtocolElementIgnoredOnWrite {
              get { return SR.GetResourceString("TraceCodeSyndicationProtocolElementIgnoredOnWrite", null); }
        }
        internal static string TraceCodeSyndicationProtocolElementInvalid {
              get { return SR.GetResourceString("TraceCodeSyndicationProtocolElementInvalid", null); }
        }
        internal static string TraceCodeWebUnknownQueryParameterIgnored {
              get { return SR.GetResourceString("TraceCodeWebUnknownQueryParameterIgnored", null); }
        }
        internal static string TraceCodeWebRequestMatchesOperation {
              get { return SR.GetResourceString("TraceCodeWebRequestMatchesOperation", null); }
        }
        internal static string TraceCodeWebRequestDoesNotMatchOperations {
              get { return SR.GetResourceString("TraceCodeWebRequestDoesNotMatchOperations", null); }
        }
        internal static string UTTMustBeAbsolute {
              get { return SR.GetResourceString("UTTMustBeAbsolute", null); }
        }
        internal static string UTTBaseAddressMustBeAbsolute {
              get { return SR.GetResourceString("UTTBaseAddressMustBeAbsolute", null); }
        }
        internal static string UTTCannotChangeBaseAddress {
              get { return SR.GetResourceString("UTTCannotChangeBaseAddress", null); }
        }
        internal static string UTTMultipleMatches {
              get { return SR.GetResourceString("UTTMultipleMatches", null); }
        }
        internal static string UTTBaseAddressNotSet {
              get { return SR.GetResourceString("UTTBaseAddressNotSet", null); }
        }
        internal static string UTTEmptyKeyValuePairs {
              get { return SR.GetResourceString("UTTEmptyKeyValuePairs", null); }
        }
        internal static string UTBindByPositionWrongCount {
              get { return SR.GetResourceString("UTBindByPositionWrongCount", null); }
        }
        internal static string UTBadBaseAddress {
              get { return SR.GetResourceString("UTBadBaseAddress", null); }
        }
        internal static string UTQueryNamesMustBeUnique {
              get { return SR.GetResourceString("UTQueryNamesMustBeUnique", null); }
        }
        internal static string UTQueryCannotEndInAmpersand {
              get { return SR.GetResourceString("UTQueryCannotEndInAmpersand", null); }
        }
        internal static string UTQueryCannotHaveEmptyName {
              get { return SR.GetResourceString("UTQueryCannotHaveEmptyName", null); }
        }
        internal static string UTVarNamesMustBeUnique {
              get { return SR.GetResourceString("UTVarNamesMustBeUnique", null); }
        }
        internal static string UTTAmbiguousQueries {
              get { return SR.GetResourceString("UTTAmbiguousQueries", null); }
        }
        internal static string UTTOtherAmbiguousQueries {
              get { return SR.GetResourceString("UTTOtherAmbiguousQueries", null); }
        }
        internal static string UTTDuplicate {
              get { return SR.GetResourceString("UTTDuplicate", null); }
        }
        internal static string UTInvalidFormatSegmentOrQueryPart {
              get { return SR.GetResourceString("UTInvalidFormatSegmentOrQueryPart", null); }
        }
        internal static string BindUriTemplateToNullOrEmptyPathParam {
              get { return SR.GetResourceString("BindUriTemplateToNullOrEmptyPathParam", null); }
        }
        internal static string UTBindByPositionNoVariables {
              get { return SR.GetResourceString("UTBindByPositionNoVariables", null); }
        }
        internal static string UTCSRLookupBeforeMatch {
              get { return SR.GetResourceString("UTCSRLookupBeforeMatch", null); }
        }
        internal static string UTDoesNotSupportAdjacentVarsInCompoundSegment {
              get { return SR.GetResourceString("UTDoesNotSupportAdjacentVarsInCompoundSegment", null); }
        }
        internal static string UTQueryCannotHaveCompoundValue {
              get { return SR.GetResourceString("UTQueryCannotHaveCompoundValue", null); }
        }
        internal static string UTQueryMustHaveLiteralNames {
              get { return SR.GetResourceString("UTQueryMustHaveLiteralNames", null); }
        }
        internal static string UTAdditionalDefaultIsInvalid {
              get { return SR.GetResourceString("UTAdditionalDefaultIsInvalid", null); }
        }
        internal static string UTDefaultValuesAreImmutable {
              get { return SR.GetResourceString("UTDefaultValuesAreImmutable", null); }
        }
        internal static string UTDefaultValueToCompoundSegmentVar {
              get { return SR.GetResourceString("UTDefaultValueToCompoundSegmentVar", null); }
        }
        internal static string UTDefaultValueToQueryVar {
              get { return SR.GetResourceString("UTDefaultValueToQueryVar", null); }
        }
        internal static string UTInvalidDefaultPathValue {
              get { return SR.GetResourceString("UTInvalidDefaultPathValue", null); }
        }
        internal static string UTInvalidVarDeclaration {
              get { return SR.GetResourceString("UTInvalidVarDeclaration", null); }
        }
        internal static string UTInvalidWildcardInVariableOrLiteral {
              get { return SR.GetResourceString("UTInvalidWildcardInVariableOrLiteral", null); }
        }
        internal static string UTStarVariableWithDefaults {
              get { return SR.GetResourceString("UTStarVariableWithDefaults", null); }
        }
        internal static string UTDefaultValueToCompoundSegmentVarFromAdditionalDefaults {
              get { return SR.GetResourceString("UTDefaultValueToCompoundSegmentVarFromAdditionalDefaults", null); }
        }
        internal static string UTDefaultValueToQueryVarFromAdditionalDefaults {
              get { return SR.GetResourceString("UTDefaultValueToQueryVarFromAdditionalDefaults", null); }
        }
        internal static string UTNullableDefaultAtAdditionalDefaults {
              get { return SR.GetResourceString("UTNullableDefaultAtAdditionalDefaults", null); }
        }
        internal static string UTNullableDefaultMustBeFollowedWithNullables {
              get { return SR.GetResourceString("UTNullableDefaultMustBeFollowedWithNullables", null); }
        }
        internal static string UTNullableDefaultMustNotBeFollowedWithLiteral {
              get { return SR.GetResourceString("UTNullableDefaultMustNotBeFollowedWithLiteral", null); }
        }
        internal static string UTNullableDefaultMustNotBeFollowedWithWildcard {
              get { return SR.GetResourceString("UTNullableDefaultMustNotBeFollowedWithWildcard", null); }
        }
        internal static string UTStarVariableWithDefaultsFromAdditionalDefaults {
              get { return SR.GetResourceString("UTStarVariableWithDefaultsFromAdditionalDefaults", null); }
        }
        internal static string UTTInvalidTemplateKey {
              get { return SR.GetResourceString("UTTInvalidTemplateKey", null); }
        }
        internal static string UTTNullTemplateKey {
              get { return SR.GetResourceString("UTTNullTemplateKey", null); }
        }
        internal static string UTBindByNameCalledWithEmptyKey {
              get { return SR.GetResourceString("UTBindByNameCalledWithEmptyKey", null); }
        }
        internal static string UTBothLiteralAndNameValueCollectionKey {
              get { return SR.GetResourceString("UTBothLiteralAndNameValueCollectionKey", null); }
        }
        internal static string ExtensionNameNotSpecified {
              get { return SR.GetResourceString("ExtensionNameNotSpecified", null); }
        }
        internal static string UnsupportedRssVersion {
              get { return SR.GetResourceString("UnsupportedRssVersion", null); }
        }
        internal static string Atom10SpecRequiresTextConstruct {
              get { return SR.GetResourceString("Atom10SpecRequiresTextConstruct", null); }
        }
        internal static string ErrorInLine {
              get { return SR.GetResourceString("ErrorInLine", null); }
        }
        internal static string ErrorParsingFeed {
              get { return SR.GetResourceString("ErrorParsingFeed", null); }
        }
        internal static string ErrorParsingDocument {
              get { return SR.GetResourceString("ErrorParsingDocument", null); }
        }
        internal static string ErrorParsingItem {
              get { return SR.GetResourceString("ErrorParsingItem", null); }
        }
        internal static string ErrorParsingDateTime {
              get { return SR.GetResourceString("ErrorParsingDateTime", null); }
        }
        internal static string OuterElementNameNotSpecified {
              get { return SR.GetResourceString("OuterElementNameNotSpecified", null); }
        }
        internal static string UnknownFeedXml {
              get { return SR.GetResourceString("UnknownFeedXml", null); }
        }
        internal static string UnknownDocumentXml {
              get { return SR.GetResourceString("UnknownDocumentXml", null); }
        }
        internal static string UnknownItemXml {
              get { return SR.GetResourceString("UnknownItemXml", null); }
        }
        internal static string FeedFormatterDoesNotHaveFeed {
              get { return SR.GetResourceString("FeedFormatterDoesNotHaveFeed", null); }
        }
        internal static string DocumentFormatterDoesNotHaveDocument {
              get { return SR.GetResourceString("DocumentFormatterDoesNotHaveDocument", null); }
        }
        internal static string ItemFormatterDoesNotHaveItem {
              get { return SR.GetResourceString("ItemFormatterDoesNotHaveItem", null); }
        }
        internal static string UnbufferedItemsCannotBeCloned {
              get { return SR.GetResourceString("UnbufferedItemsCannotBeCloned", null); }
        }
        internal static string FeedHasNonContiguousItems {
              get { return SR.GetResourceString("FeedHasNonContiguousItems", null); }
        }
        internal static string FeedCreatedNullCategory {
              get { return SR.GetResourceString("FeedCreatedNullCategory", null); }
        }
        internal static string ItemCreatedNullCategory {
              get { return SR.GetResourceString("ItemCreatedNullCategory", null); }
        }
        internal static string FeedCreatedNullPerson {
              get { return SR.GetResourceString("FeedCreatedNullPerson", null); }
        }
        internal static string ItemCreatedNullPerson {
              get { return SR.GetResourceString("ItemCreatedNullPerson", null); }
        }
        internal static string FeedCreatedNullItem {
              get { return SR.GetResourceString("FeedCreatedNullItem", null); }
        }
        internal static string TraceCodeSyndicationFeedReadBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationFeedReadBegin", null); }
        }
        internal static string TraceCodeSyndicationFeedReadEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationFeedReadEnd", null); }
        }
        internal static string TraceCodeSyndicationItemReadBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationItemReadBegin", null); }
        }
        internal static string TraceCodeSyndicationItemReadEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationItemReadEnd", null); }
        }
        internal static string TraceCodeSyndicationFeedWriteBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationFeedWriteBegin", null); }
        }
        internal static string TraceCodeSyndicationFeedWriteEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationFeedWriteEnd", null); }
        }
        internal static string TraceCodeSyndicationItemWriteBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationItemWriteBegin", null); }
        }
        internal static string TraceCodeSyndicationItemWriteEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationItemWriteEnd", null); }
        }
        internal static string TraceCodeSyndicationProtocolElementIgnoredOnRead {
              get { return SR.GetResourceString("TraceCodeSyndicationProtocolElementIgnoredOnRead", null); }
        }
        internal static string TraceCodeSyndicationReadServiceDocumentBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationReadServiceDocumentBegin", null); }
        }
        internal static string TraceCodeSyndicationReadServiceDocumentEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationReadServiceDocumentEnd", null); }
        }
        internal static string TraceCodeSyndicationWriteServiceDocumentBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteServiceDocumentBegin", null); }
        }
        internal static string TraceCodeSyndicationWriteServiceDocumentEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteServiceDocumentEnd", null); }
        }
        internal static string TraceCodeSyndicationReadCategoriesDocumentBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationReadCategoriesDocumentBegin", null); }
        }
        internal static string TraceCodeSyndicationReadCategoriesDocumentEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationReadCategoriesDocumentEnd", null); }
        }
        internal static string TraceCodeSyndicationWriteCategoriesDocumentBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteCategoriesDocumentBegin", null); }
        }
        internal static string TraceCodeSyndicationWriteCategoriesDocumentEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteCategoriesDocumentEnd", null); }
        }
        internal static string FeedAuthorsIgnoredOnWrite {
              get { return SR.GetResourceString("FeedAuthorsIgnoredOnWrite", null); }
        }
        internal static string FeedContributorsIgnoredOnWrite {
              get { return SR.GetResourceString("FeedContributorsIgnoredOnWrite", null); }
        }
        internal static string FeedIdIgnoredOnWrite {
              get { return SR.GetResourceString("FeedIdIgnoredOnWrite", null); }
        }
        internal static string FeedLinksIgnoredOnWrite {
              get { return SR.GetResourceString("FeedLinksIgnoredOnWrite", null); }
        }
        internal static string ItemAuthorsIgnoredOnWrite {
              get { return SR.GetResourceString("ItemAuthorsIgnoredOnWrite", null); }
        }
        internal static string ItemContributorsIgnoredOnWrite {
              get { return SR.GetResourceString("ItemContributorsIgnoredOnWrite", null); }
        }
        internal static string ItemLinksIgnoredOnWrite {
              get { return SR.GetResourceString("ItemLinksIgnoredOnWrite", null); }
        }
        internal static string ItemCopyrightIgnoredOnWrite {
              get { return SR.GetResourceString("ItemCopyrightIgnoredOnWrite", null); }
        }
        internal static string ItemContentIgnoredOnWrite {
              get { return SR.GetResourceString("ItemContentIgnoredOnWrite", null); }
        }
        internal static string ItemLastUpdatedTimeIgnoredOnWrite {
              get { return SR.GetResourceString("ItemLastUpdatedTimeIgnoredOnWrite", null); }
        }
        internal static string OuterNameOfElementExtensionEmpty {
              get { return SR.GetResourceString("OuterNameOfElementExtensionEmpty", null); }
        }
        internal static string InvalidObjectTypePassed {
              get { return SR.GetResourceString("InvalidObjectTypePassed", null); }
        }
        internal static string UnableToImpersonateWhileSerializingReponse {
              get { return SR.GetResourceString("UnableToImpersonateWhileSerializingReponse", null); }
        }
        internal static string XmlLineInfo {
              get { return SR.GetResourceString("XmlLineInfo", null); }
        }
        internal static string XmlFoundEndOfFile {
              get { return SR.GetResourceString("XmlFoundEndOfFile", null); }
        }
        internal static string XmlFoundElement {
              get { return SR.GetResourceString("XmlFoundElement", null); }
        }
        internal static string XmlFoundEndElement {
              get { return SR.GetResourceString("XmlFoundEndElement", null); }
        }
        internal static string XmlFoundText {
              get { return SR.GetResourceString("XmlFoundText", null); }
        }
        internal static string XmlFoundCData {
              get { return SR.GetResourceString("XmlFoundCData", null); }
        }
        internal static string XmlFoundComment {
              get { return SR.GetResourceString("XmlFoundComment", null); }
        }
        internal static string XmlFoundNodeType {
              get { return SR.GetResourceString("XmlFoundNodeType", null); }
        }
        internal static string XmlStartElementExpected {
              get { return SR.GetResourceString("XmlStartElementExpected", null); }
        }
        internal static string SingleWsdlNotGenerated {
              get { return SR.GetResourceString("SingleWsdlNotGenerated", null); }
        }
        internal static string SFxDocExt_MainPageIntroSingleWsdl {
              get { return SR.GetResourceString("SFxDocExt_MainPageIntroSingleWsdl", null); }
        }
        internal static string TaskMethodParameterNotSupported {
              get { return SR.GetResourceString("TaskMethodParameterNotSupported", null); }
        }
        internal static string TaskMethodMustNotHaveOutParameter {
              get { return SR.GetResourceString("TaskMethodMustNotHaveOutParameter", null); }
        }
        internal static string SFxCannotImportAsParameters_OutputParameterAndTask {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_OutputParameterAndTask", null); }
        }
        internal static string ID0020 {
              get { return SR.GetResourceString("ID0020", null); }
        }
        internal static string ID0023 {
              get { return SR.GetResourceString("ID0023", null); }
        }
        internal static string ID2004 {
              get { return SR.GetResourceString("ID2004", null); }
        }
        internal static string ID3002 {
              get { return SR.GetResourceString("ID3002", null); }
        }
        internal static string ID3004 {
              get { return SR.GetResourceString("ID3004", null); }
        }
        internal static string ID3022 {
              get { return SR.GetResourceString("ID3022", null); }
        }
        internal static string ID3023 {
              get { return SR.GetResourceString("ID3023", null); }
        }
        internal static string ID3097 {
              get { return SR.GetResourceString("ID3097", null); }
        }
        internal static string ID3112 {
              get { return SR.GetResourceString("ID3112", null); }
        }
        internal static string ID3113 {
              get { return SR.GetResourceString("ID3113", null); }
        }
        internal static string ID3114 {
              get { return SR.GetResourceString("ID3114", null); }
        }
        internal static string ID3137 {
              get { return SR.GetResourceString("ID3137", null); }
        }
        internal static string ID3138 {
              get { return SR.GetResourceString("ID3138", null); }
        }
        internal static string ID3139 {
              get { return SR.GetResourceString("ID3139", null); }
        }
        internal static string ID3140 {
              get { return SR.GetResourceString("ID3140", null); }
        }
        internal static string ID3141 {
              get { return SR.GetResourceString("ID3141", null); }
        }
        internal static string ID3144 {
              get { return SR.GetResourceString("ID3144", null); }
        }
        internal static string ID3146 {
              get { return SR.GetResourceString("ID3146", null); }
        }
        internal static string ID3147 {
              get { return SR.GetResourceString("ID3147", null); }
        }
        internal static string ID3148 {
              get { return SR.GetResourceString("ID3148", null); }
        }
        internal static string ID3149 {
              get { return SR.GetResourceString("ID3149", null); }
        }
        internal static string ID3150 {
              get { return SR.GetResourceString("ID3150", null); }
        }
        internal static string ID3190 {
              get { return SR.GetResourceString("ID3190", null); }
        }
        internal static string ID3191 {
              get { return SR.GetResourceString("ID3191", null); }
        }
        internal static string ID3192 {
              get { return SR.GetResourceString("ID3192", null); }
        }
        internal static string ID3193 {
              get { return SR.GetResourceString("ID3193", null); }
        }
        internal static string ID3194 {
              get { return SR.GetResourceString("ID3194", null); }
        }
        internal static string ID3269 {
              get { return SR.GetResourceString("ID3269", null); }
        }
        internal static string ID3270 {
              get { return SR.GetResourceString("ID3270", null); }
        }
        internal static string ID3285 {
              get { return SR.GetResourceString("ID3285", null); }
        }
        internal static string ID3286 {
              get { return SR.GetResourceString("ID3286", null); }
        }
        internal static string ID3287 {
              get { return SR.GetResourceString("ID3287", null); }
        }
        internal static string ID4008 {
              get { return SR.GetResourceString("ID4008", null); }
        }
        internal static string ID4039 {
              get { return SR.GetResourceString("ID4039", null); }
        }
        internal static string ID4041 {
              get { return SR.GetResourceString("ID4041", null); }
        }
        internal static string ID4053 {
              get { return SR.GetResourceString("ID4053", null); }
        }
        internal static string ID4072 {
              get { return SR.GetResourceString("ID4072", null); }
        }
        internal static string ID4101 {
              get { return SR.GetResourceString("ID4101", null); }
        }
        internal static string ID4192 {
              get { return SR.GetResourceString("ID4192", null); }
        }
        internal static string ID4240 {
              get { return SR.GetResourceString("ID4240", null); }
        }
        internal static string ID4244 {
              get { return SR.GetResourceString("ID4244", null); }
        }
        internal static string ID4245 {
              get { return SR.GetResourceString("ID4245", null); }
        }
        internal static string ID4268 {
              get { return SR.GetResourceString("ID4268", null); }
        }
        internal static string ID4271 {
              get { return SR.GetResourceString("ID4271", null); }
        }
        internal static string ID4274 {
              get { return SR.GetResourceString("ID4274", null); }
        }
        internal static string ID4285 {
              get { return SR.GetResourceString("ID4285", null); }
        }
        internal static string ID4287 {
              get { return SR.GetResourceString("ID4287", null); }
        }
        internal static string ID5004 {
              get { return SR.GetResourceString("ID5004", null); }
        }
        internal static string TraceAuthorize {
              get { return SR.GetResourceString("TraceAuthorize", null); }
        }
        internal static string TraceOnAuthorizeRequestFailed {
              get { return SR.GetResourceString("TraceOnAuthorizeRequestFailed", null); }
        }
        internal static string TraceOnAuthorizeRequestSucceed {
              get { return SR.GetResourceString("TraceOnAuthorizeRequestSucceed", null); }
        }
        internal static string AuthFailed {
              get { return SR.GetResourceString("AuthFailed", null); }
        }
        internal static string DuplicateFederatedClientCredentialsParameters {
              get { return SR.GetResourceString("DuplicateFederatedClientCredentialsParameters", null); }
        }
        internal static string UnsupportedTrustVersion {
              get { return SR.GetResourceString("UnsupportedTrustVersion", null); }
        }
        internal static string InputMustBeDelegatingHandlerElementError {
              get { return SR.GetResourceString("InputMustBeDelegatingHandlerElementError", null); }
        }
        internal static string InputTypeListEmptyError {
              get { return SR.GetResourceString("InputTypeListEmptyError", null); }
        }
        internal static string DelegatingHandlerArrayHasNonNullInnerHandler {
              get { return SR.GetResourceString("DelegatingHandlerArrayHasNonNullInnerHandler", null); }
        }
        internal static string DelegatingHandlerArrayFromFuncContainsNullItem {
              get { return SR.GetResourceString("DelegatingHandlerArrayFromFuncContainsNullItem", null); }
        }
        internal static string HttpMessageHandlerFactoryConfigInvalid_WithBothTypeAndHandlerList {
              get { return SR.GetResourceString("HttpMessageHandlerFactoryConfigInvalid_WithBothTypeAndHandlerList", null); }
        }
        internal static string HttpMessageHandlerFactoryWithFuncCannotGenerateConfig {
              get { return SR.GetResourceString("HttpMessageHandlerFactoryWithFuncCannotGenerateConfig", null); }
        }
        internal static string HttpMessageHandlerTypeNotSupported {
              get { return SR.GetResourceString("HttpMessageHandlerTypeNotSupported", null); }
        }
        internal static string HttpMessageHandlerChannelFactoryNullPipeline {
              get { return SR.GetResourceString("HttpMessageHandlerChannelFactoryNullPipeline", null); }
        }
        internal static string HttpPipelineOperationCanceledError {
              get { return SR.GetResourceString("HttpPipelineOperationCanceledError", null); }
        }
        internal static string HttpPipelineMessagePropertyMissingError {
              get { return SR.GetResourceString("HttpPipelineMessagePropertyMissingError", null); }
        }
        internal static string HttpPipelineMessagePropertyTypeError {
              get { return SR.GetResourceString("HttpPipelineMessagePropertyTypeError", null); }
        }
        internal static string InvalidContentTypeError {
              get { return SR.GetResourceString("InvalidContentTypeError", null); }
        }
        internal static string HttpPipelineNotSupportedOnClientSide {
              get { return SR.GetResourceString("HttpPipelineNotSupportedOnClientSide", null); }
        }
        internal static string CanNotLoadTypeGotFromConfig {
              get { return SR.GetResourceString("CanNotLoadTypeGotFromConfig", null); }
        }
        internal static string HttpPipelineNotSupportNullResponseMessage {
              get { return SR.GetResourceString("HttpPipelineNotSupportNullResponseMessage", null); }
        }
        internal static string WebSocketInvalidProtocolNoHeader {
              get { return SR.GetResourceString("WebSocketInvalidProtocolNoHeader", null); }
        }
        internal static string WebSocketInvalidProtocolNotInClientList {
              get { return SR.GetResourceString("WebSocketInvalidProtocolNotInClientList", null); }
        }
        internal static string WebSocketInvalidProtocolInvalidCharInProtocolString {
              get { return SR.GetResourceString("WebSocketInvalidProtocolInvalidCharInProtocolString", null); }
        }
        internal static string WebSocketInvalidProtocolContainsMultipleSubProtocolString {
              get { return SR.GetResourceString("WebSocketInvalidProtocolContainsMultipleSubProtocolString", null); }
        }
        internal static string WebSocketInvalidProtocolEmptySubprotocolString {
              get { return SR.GetResourceString("WebSocketInvalidProtocolEmptySubprotocolString", null); }
        }
        internal static string WebSocketOpaqueStreamContentNotSupportError {
              get { return SR.GetResourceString("WebSocketOpaqueStreamContentNotSupportError", null); }
        }
        internal static string WebSocketElementConfigInvalidHttpMessageHandlerFactoryType {
              get { return SR.GetResourceString("WebSocketElementConfigInvalidHttpMessageHandlerFactoryType", null); }
        }
        internal static string WebSocketEndpointOnlySupportWebSocketError {
              get { return SR.GetResourceString("WebSocketEndpointOnlySupportWebSocketError", null); }
        }
        internal static string WebSocketEndpointDoesNotSupportWebSocketError {
              get { return SR.GetResourceString("WebSocketEndpointDoesNotSupportWebSocketError", null); }
        }
        internal static string WebSocketUpgradeFailedError {
              get { return SR.GetResourceString("WebSocketUpgradeFailedError", null); }
        }
        internal static string WebSocketUpgradeFailedHeaderMissingError {
              get { return SR.GetResourceString("WebSocketUpgradeFailedHeaderMissingError", null); }
        }
        internal static string WebSocketUpgradeFailedWrongHeaderError {
              get { return SR.GetResourceString("WebSocketUpgradeFailedWrongHeaderError", null); }
        }
        internal static string WebSocketUpgradeFailedInvalidProtocolError {
              get { return SR.GetResourceString("WebSocketUpgradeFailedInvalidProtocolError", null); }
        }
        internal static string WebSocketContextWebSocketCannotBeAccessedError {
              get { return SR.GetResourceString("WebSocketContextWebSocketCannotBeAccessedError", null); }
        }
        internal static string WebSocketTransportError {
              get { return SR.GetResourceString("WebSocketTransportError", null); }
        }
        internal static string WebSocketUnexpectedCloseMessageError {
              get { return SR.GetResourceString("WebSocketUnexpectedCloseMessageError", null); }
        }
        internal static string WebSocketStreamWriteCalledAfterEOMSent {
              get { return SR.GetResourceString("WebSocketStreamWriteCalledAfterEOMSent", null); }
        }
        internal static string WebSocketCannotCreateRequestClientChannelWithCertainWebSocketTransportUsage {
              get { return SR.GetResourceString("WebSocketCannotCreateRequestClientChannelWithCertainWebSocketTransportUsage", null); }
        }
        internal static string WebSocketMaxPendingConnectionsReached {
              get { return SR.GetResourceString("WebSocketMaxPendingConnectionsReached", null); }
        }
        internal static string WebSocketOpeningHandshakePropertiesNotAvailable {
              get { return SR.GetResourceString("WebSocketOpeningHandshakePropertiesNotAvailable", null); }
        }
        internal static string AcceptWebSocketTimedOutError {
              get { return SR.GetResourceString("AcceptWebSocketTimedOutError", null); }
        }
        internal static string TaskCancelledError {
              get { return SR.GetResourceString("TaskCancelledError", null); }
        }
        internal static string ClientWebSocketFactory_GetWebSocketVersionFailed {
              get { return SR.GetResourceString("ClientWebSocketFactory_GetWebSocketVersionFailed", null); }
        }
        internal static string ClientWebSocketFactory_InvalidWebSocketVersion {
              get { return SR.GetResourceString("ClientWebSocketFactory_InvalidWebSocketVersion", null); }
        }
        internal static string ClientWebSocketFactory_CreateWebSocketFailed {
              get { return SR.GetResourceString("ClientWebSocketFactory_CreateWebSocketFailed", null); }
        }
        internal static string ClientWebSocketFactory_InvalidWebSocket {
              get { return SR.GetResourceString("ClientWebSocketFactory_InvalidWebSocket", null); }
        }
        internal static string ClientWebSocketFactory_InvalidSubProtocol {
              get { return SR.GetResourceString("ClientWebSocketFactory_InvalidSubProtocol", null); }
        }
        internal static string MultipleClientWebSocketFactoriesSpecified {
              get { return SR.GetResourceString("MultipleClientWebSocketFactoriesSpecified", null); }
        }
        internal static string WebSocketSendTimedOut {
              get { return SR.GetResourceString("WebSocketSendTimedOut", null); }
        }
        internal static string WebSocketReceiveTimedOut {
              get { return SR.GetResourceString("WebSocketReceiveTimedOut", null); }
        }
        internal static string WebSocketOperationTimedOut {
              get { return SR.GetResourceString("WebSocketOperationTimedOut", null); }
        }
        internal static string WebSocketsServerSideNotSupported {
              get { return SR.GetResourceString("WebSocketsServerSideNotSupported", null); }
        }
        internal static string WebSocketsClientSideNotSupported {
              get { return SR.GetResourceString("WebSocketsClientSideNotSupported", null); }
        }
        internal static string WebSocketsNotSupportedInClassicPipeline {
              get { return SR.GetResourceString("WebSocketsNotSupportedInClassicPipeline", null); }
        }
        internal static string WebSocketModuleNotLoaded {
              get { return SR.GetResourceString("WebSocketModuleNotLoaded", null); }
        }
        internal static string WebSocketTransportPolicyAssertionInvalid {
              get { return SR.GetResourceString("WebSocketTransportPolicyAssertionInvalid", null); }
        }
        internal static string WebSocketVersionMismatchFromServer {
              get { return SR.GetResourceString("WebSocketVersionMismatchFromServer", null); }
        }
        internal static string WebSocketSubProtocolMismatchFromServer {
              get { return SR.GetResourceString("WebSocketSubProtocolMismatchFromServer", null); }
        }
        internal static string WebSocketContentTypeMismatchFromServer {
              get { return SR.GetResourceString("WebSocketContentTypeMismatchFromServer", null); }
        }
        internal static string WebSocketContentTypeAndTransferModeMismatchFromServer {
              get { return SR.GetResourceString("WebSocketContentTypeAndTransferModeMismatchFromServer", null); }
        }
        internal static string ResponseHeaderWithRequestHeadersCollection {
              get { return SR.GetResourceString("ResponseHeaderWithRequestHeadersCollection", null); }
        }
        internal static string RequestHeaderWithResponseHeadersCollection {
              get { return SR.GetResourceString("RequestHeaderWithResponseHeadersCollection", null); }
        }
        internal static string MessageVersionNoneRequiredForHttpMessageSupport {
              get { return SR.GetResourceString("MessageVersionNoneRequiredForHttpMessageSupport", null); }
        }
        internal static string WebHeaderEnumOperationCantHappen {
              get { return SR.GetResourceString("WebHeaderEnumOperationCantHappen", null); }
        }
        internal static string WebHeaderEmptyStringCall {
              get { return SR.GetResourceString("WebHeaderEmptyStringCall", null); }
        }
        internal static string WebHeaderInvalidControlChars {
              get { return SR.GetResourceString("WebHeaderInvalidControlChars", null); }
        }
        internal static string WebHeaderInvalidCRLFChars {
              get { return SR.GetResourceString("WebHeaderInvalidCRLFChars", null); }
        }
        internal static string WebHeaderInvalidHeaderChars {
              get { return SR.GetResourceString("WebHeaderInvalidHeaderChars", null); }
        }
        internal static string WebHeaderInvalidNonAsciiChars {
              get { return SR.GetResourceString("WebHeaderInvalidNonAsciiChars", null); }
        }
        internal static string WebHeaderArgumentOutOfRange {
              get { return SR.GetResourceString("WebHeaderArgumentOutOfRange", null); }
        }
        internal static string CopyHttpHeaderFailed {
              get { return SR.GetResourceString("CopyHttpHeaderFailed", null); }
        }
        internal static string XmlInvalidConversion {
              get { return SR.GetResourceString("XmlInvalidConversion", null); }
        }
        internal static string XmlInvalidStream {
              get { return SR.GetResourceString("XmlInvalidStream", null); }
        }
        internal static string LockTimeoutExceptionMessage {
              get { return SR.GetResourceString("LockTimeoutExceptionMessage", null); }
        }
        internal static string InvalidEnumArgument {
              get { return SR.GetResourceString("InvalidEnumArgument", null); }
        }
        internal static string InvalidTypedProxyMethodHandle {
              get { return SR.GetResourceString("InvalidTypedProxyMethodHandle", null); }
        }
        internal static string FailedToCreateTypedProxy {
              get { return SR.GetResourceString("FailedToCreateTypedProxy", null); }
        }
        internal static string Arg_SystemException {
              get { return SR.GetResourceString("Arg_SystemException", null); }
        }
        internal static string SecurityTokenRequirementDoesNotContainProperty {
              get { return SR.GetResourceString("SecurityTokenRequirementDoesNotContainProperty", null); }
        }
        internal static string SecurityTokenRequirementHasInvalidTypeForProperty {
              get { return SR.GetResourceString("SecurityTokenRequirementHasInvalidTypeForProperty", null); }
        }
        internal static string TokenCancellationNotSupported {
              get { return SR.GetResourceString("TokenCancellationNotSupported", null); }
        }
        internal static string TokenProviderUnableToGetToken {
              get { return SR.GetResourceString("TokenProviderUnableToGetToken", null); }
        }
        internal static string TokenProviderUnableToRenewToken {
              get { return SR.GetResourceString("TokenProviderUnableToRenewToken", null); }
        }
        internal static string TokenRenewalNotSupported {
              get { return SR.GetResourceString("TokenRenewalNotSupported", null); }
        }
        internal static string UserNameCannotBeEmpty {
              get { return SR.GetResourceString("UserNameCannotBeEmpty", null); }
        }
        internal static string ActivityBoundary {
              get { return SR.GetResourceString("ActivityBoundary", null); }
        }
        internal static string StringNullOrEmpty {
              get { return SR.GetResourceString("StringNullOrEmpty", null); }
        }
        internal static string GenericCallbackException {
              get { return SR.GetResourceString("GenericCallbackException", null); }
        }
        internal static string ArgumentCannotBeEmptyString {
              get { return SR.GetResourceString("ArgumentCannotBeEmptyString", null); }
        }
        internal static string KeyIdentifierClauseDoesNotSupportKeyCreation {
              get { return SR.GetResourceString("KeyIdentifierClauseDoesNotSupportKeyCreation", null); }
        }
        internal static string SymmetricKeyLengthTooShort {
              get { return SR.GetResourceString("SymmetricKeyLengthTooShort", null); }
        }
        internal static string KeyIdentifierCannotCreateKey {
              get { return SR.GetResourceString("KeyIdentifierCannotCreateKey", null); }
        }
        internal static string NoKeyIdentifierClauseFound {
              get { return SR.GetResourceString("NoKeyIdentifierClauseFound", null); }
        }
        internal static string LocalIdCannotBeEmpty {
              get { return SR.GetResourceString("LocalIdCannotBeEmpty", null); }
        }
        internal static string UnableToResolveKeyReference {
              get { return SR.GetResourceString("UnableToResolveKeyReference", null); }
        }
        internal static string CannotValidateSecurityTokenType {
              get { return SR.GetResourceString("CannotValidateSecurityTokenType", null); }
        }
        internal static string UnableToResolveTokenReference {
              get { return SR.GetResourceString("UnableToResolveTokenReference", null); }
        }
        internal static string UnauthorizedAccess_MemStreamBuffer {
              get { return SR.GetResourceString("UnauthorizedAccess_MemStreamBuffer", null); }
        }
        internal static string ConfigurationFilesNotSupported {
              get { return SR.GetResourceString("ConfigurationFilesNotSupported", null); }
        }
        internal static string X509ChainBuildFail {
              get { return SR.GetResourceString("X509ChainBuildFail", null); }
        }
        internal static string ImpersonationLevelNotSupported {
            get { return SR.GetResourceString("ImpersonationLevelNotSupported", null); }
        }
        internal static string ProvidedNetworkCredentialsForKerberosHasInvalidUserName {
            get { return SR.GetResourceString("ProvidedNetworkCredentialsForKerberosHasInvalidUserName", null); }
        }
#else
        internal static string NoIPEndpointsFoundForHost {
              get { return SR.GetResourceString("NoIPEndpointsFoundForHost", @"No IPEndpoints were found for host {0}."); }
        }
        internal static string DnsResolveFailed {
              get { return SR.GetResourceString("DnsResolveFailed", @"No DNS entries exist for host {0}."); }
        }
        internal static string RequiredAttributeMissing {
              get { return SR.GetResourceString("RequiredAttributeMissing", @"Attribute '{0}' is required on element '{1}'."); }
        }
        internal static string UnsupportedCryptoAlgorithm {
              get { return SR.GetResourceString("UnsupportedCryptoAlgorithm", @"Crypto algorithm {0} not supported in this context."); }
        }
        internal static string CustomCryptoAlgorithmIsNotValidHashAlgorithm {
              get { return SR.GetResourceString("CustomCryptoAlgorithmIsNotValidHashAlgorithm", @"The custom crypto algorithm '{0}' obtained using CryptoConfig is not a valid or supported hash algorithm."); }
        }
        internal static string InvalidClientCredentials {
              get { return SR.GetResourceString("InvalidClientCredentials", @"The client credential entered was invalid."); }
        }
        internal static string SspiErrorOrInvalidClientCredentials {
              get { return SR.GetResourceString("SspiErrorOrInvalidClientCredentials", @"Either the client credential was invalid or there was an error collecting the client credentials by the SSPI."); }
        }
        internal static string CustomCryptoAlgorithmIsNotValidAsymmetricSignature {
              get { return SR.GetResourceString("CustomCryptoAlgorithmIsNotValidAsymmetricSignature", @"The custom crypto algorithm '{0}' obtained using CryptoConfig is not a valid or supported asymmetric signature algorithm."); }
        }
        internal static string TokenSerializerNotSetonFederationProvider {
              get { return SR.GetResourceString("TokenSerializerNotSetonFederationProvider", @"The security token serializer must be specified on the security token provider."); }
        }
        internal static string IssuerBindingNotPresentInTokenRequirement {
              get { return SR.GetResourceString("IssuerBindingNotPresentInTokenRequirement", @"The key length '{0}' is not a multiple of 8 for symmetric keys."); }
        }
        internal static string IssuerChannelBehaviorsCannotContainSecurityCredentialsManager {
              get { return SR.GetResourceString("IssuerChannelBehaviorsCannotContainSecurityCredentialsManager", @"The channel behaviors configured for the issuer address '{0}' cannot contain a behavior of type '{1}'."); }
        }
        internal static string ServiceBusyCountTrace {
              get { return SR.GetResourceString("ServiceBusyCountTrace", @"Operation Action={0}"); }
        }
        internal static string SecurityTokenManagerCannotCreateProviderForRequirement {
              get { return SR.GetResourceString("SecurityTokenManagerCannotCreateProviderForRequirement", @"The security token manager cannot create a token provider for requirement '{0}'."); }
        }
        internal static string SecurityTokenManagerCannotCreateAuthenticatorForRequirement {
              get { return SR.GetResourceString("SecurityTokenManagerCannotCreateAuthenticatorForRequirement", @"The security token manager cannot create a token authenticator for requirement '{0}'."); }
        }
        internal static string FailedSignatureVerification {
              get { return SR.GetResourceString("FailedSignatureVerification", @"The signature verification failed. Please see inner exception for fault details."); }
        }
        internal static string SecurityTokenManagerCannotCreateSerializerForVersion {
              get { return SR.GetResourceString("SecurityTokenManagerCannotCreateSerializerForVersion", @"The security token manager cannot create a token serializer for security token version '{0}'."); }
        }
        internal static string SupportingSignatureIsNotDerivedFrom {
              get { return SR.GetResourceString("SupportingSignatureIsNotDerivedFrom", @"The supporting signature is not signed with a derived key. The binding's supporting token parameter '{0}' requires key derivation."); }
        }
        internal static string PrimarySignatureWasNotSignedByDerivedKey {
              get { return SR.GetResourceString("PrimarySignatureWasNotSignedByDerivedKey", @"The primary signature is not signed with a derived key. The binding's primary token parameter '{0}' requires key derivation."); }
        }
        internal static string PrimarySignatureWasNotSignedByDerivedWrappedKey {
              get { return SR.GetResourceString("PrimarySignatureWasNotSignedByDerivedWrappedKey", @"The primary signature is not signed with a key derived from the encrypted key. The binding's token parameter '{0}' requires key derivation."); }
        }
        internal static string MessageWasNotEncryptedByDerivedWrappedKey {
              get { return SR.GetResourceString("MessageWasNotEncryptedByDerivedWrappedKey", @"The message is not encrypted with a key derived from the encrypted key. The binding's token parameter '{0}' requires key derivation."); }
        }
        internal static string SecurityStateEncoderDecodingFailure {
              get { return SR.GetResourceString("SecurityStateEncoderDecodingFailure", @"The DataProtectionSecurityStateEncoder is unable to decode the byte array. Ensure that a 'UserProfile' is loaded, if this is a 'web farm scenario' ensure all servers are running as the same user with the roaming profiles or provide a custom SecurityStateEncoder'."); }
        }
        internal static string SecurityStateEncoderEncodingFailure {
              get { return SR.GetResourceString("SecurityStateEncoderEncodingFailure", @"The DataProtectionSecurityStateEncoder is unable to encode the byte array. Ensure that a 'UserProfile' is loaded, if this is a 'web farm scenario' ensure all servers are running as the same user with the roaming profiles or provide a custom SecurityStateEncoder'."); }
        }
        internal static string MessageWasNotEncryptedByDerivedEncryptionToken {
              get { return SR.GetResourceString("MessageWasNotEncryptedByDerivedEncryptionToken", @"The message is not encrypted with a key derived from the encryption token. The binding's token parameter '{0}' requires key derivation."); }
        }
        internal static string TokenAuthenticatorRequiresSecurityBindingElement {
              get { return SR.GetResourceString("TokenAuthenticatorRequiresSecurityBindingElement", @"The security token manager requires the security binding element to be specified in order to create a token authenticator for requirement '{0}'."); }
        }
        internal static string TokenProviderRequiresSecurityBindingElement {
              get { return SR.GetResourceString("TokenProviderRequiresSecurityBindingElement", @"The security token manager requires the security binding element to be specified in order to create a token provider for requirement '{0}'."); }
        }
        internal static string UnexpectedSecuritySessionCloseResponse {
              get { return SR.GetResourceString("UnexpectedSecuritySessionCloseResponse", @"The security session received an unexpected close response from the other party."); }
        }
        internal static string UnexpectedSecuritySessionClose {
              get { return SR.GetResourceString("UnexpectedSecuritySessionClose", @"The security session received an unexpected close from the other party."); }
        }
        internal static string CannotObtainSslConnectionInfo {
              get { return SR.GetResourceString("CannotObtainSslConnectionInfo", @"The service was unable to verify the cipher strengths negotiated as part of the SSL handshake."); }
        }
        internal static string HeaderEncryptionNotSupportedInWsSecurityJan2004 {
              get { return SR.GetResourceString("HeaderEncryptionNotSupportedInWsSecurityJan2004", @"SecurityVersion.WSSecurityJan2004 does not support header encryption. Header with name '{0}' and namespace '{1}' is configured for encryption. Consider using SecurityVersion.WsSecurity11 and above or use transport security to encrypt the full message."); }
        }
        internal static string EncryptedHeaderNotSigned {
              get { return SR.GetResourceString("EncryptedHeaderNotSigned", @"The Header ('{0}', '{1}') was encrypted but not signed. All encrypted headers outside the security header should be signed."); }
        }
        internal static string EncodingBindingElementDoesNotHandleReaderQuotas {
              get { return SR.GetResourceString("EncodingBindingElementDoesNotHandleReaderQuotas", @"Unable to obtain XmlDictionaryReaderQuotas from the Binding. If you have specified a custom EncodingBindingElement, verify that the EncodingBindingElement can handle XmlDictionaryReaderQuotas in its GetProperty<T>() method."); }
        }
        internal static string HeaderDecryptionNotSupportedInWsSecurityJan2004 {
              get { return SR.GetResourceString("HeaderDecryptionNotSupportedInWsSecurityJan2004", @"SecurityVersion.WSSecurityJan2004 does not support header decryption. Use SecurityVersion.WsSecurity11 and above or use transport security to encrypt the full message."); }
        }
        internal static string DecryptionFailed {
              get { return SR.GetResourceString("DecryptionFailed", @"Unable to decrypt an encrypted data block. Please verify that the encryption algorithm and keys used by the sender and receiver match."); }
        }
        internal static string AuthenticationManagerShouldNotReturnNull {
              get { return SR.GetResourceString("AuthenticationManagerShouldNotReturnNull", @"The authenticate method in the ServiceAuthenticationManager returned null. If you do not want to return any authorization policies in the collection then return an empty ReadOnlyCollection instead. "); }
        }
        internal static string ErrorSerializingSecurityToken {
              get { return SR.GetResourceString("ErrorSerializingSecurityToken", @"There was an error serializing the security token. Please see the inner exception for more details."); }
        }
        internal static string ErrorDeserializingKeyIdentifierClauseFromTokenXml {
              get { return SR.GetResourceString("ErrorDeserializingKeyIdentifierClauseFromTokenXml", @"There was an error creating the security key identifier clause from the security token XML. Please see the inner exception for more details."); }
        }
        internal static string ErrorDeserializingTokenXml {
              get { return SR.GetResourceString("ErrorDeserializingTokenXml", @"There was an error deserializing the security token XML. Please see the inner exception for more details."); }
        }
        internal static string TokenRequirementDoesNotSpecifyTargetAddress {
              get { return SR.GetResourceString("TokenRequirementDoesNotSpecifyTargetAddress", @"The token requirement '{0}' does not specify the target address. This is required by the token manager for creating the corresponding security token provider."); }
        }
        internal static string DerivedKeyNotInitialized {
              get { return SR.GetResourceString("DerivedKeyNotInitialized", @"The derived key has not been computed for the security token."); }
        }
        internal static string IssuedKeySizeNotCompatibleWithAlgorithmSuite {
              get { return SR.GetResourceString("IssuedKeySizeNotCompatibleWithAlgorithmSuite", @"The binding ('{0}', '{1}') has been configured with a security algorithm suite '{2}' that is incompatible with the issued token key size '{3}' specified on the binding."); }
        }
        internal static string IssuedTokenAuthenticationModeRequiresSymmetricIssuedKey {
              get { return SR.GetResourceString("IssuedTokenAuthenticationModeRequiresSymmetricIssuedKey", @"The IssuedToken security authentication mode requires the issued token to contain a symmetric key."); }
        }
        internal static string InvalidBearerKeyUsage {
              get { return SR.GetResourceString("InvalidBearerKeyUsage", @"The binding ('{0}', '{1}') uses an Issued Token with Bearer Key Type in a invalid context. The Issued Token with a Bearer Key Type can only be used as a Signed Supporting token or a Signed Encrypted Supporting token. See the SecurityBindingElement.EndpointSupportingTokenParameters property."); }
        }
        internal static string MultipleIssuerEndpointsFound {
              get { return SR.GetResourceString("MultipleIssuerEndpointsFound", @"Policy for multiple issuer endpoints was retrieved from '{0}' but the relying party's policy does not specify which issuer endpoint to use. One of the endpoints was selected as the issuer endpoint to use. If you are using svcutil, the other endpoints will be available in commented form in the configuration as <alternativeIssuedTokenParameters>. Check the configuration to ensure that the right issuer endpoint was selected."); }
        }
        internal static string MultipleAuthenticationManagersInServiceBindingParameters {
              get { return SR.GetResourceString("MultipleAuthenticationManagersInServiceBindingParameters", @"The AuthenticationManager cannot be added to the binding parameters because the binding parameters already contains a AuthenticationManager '{0}'. If you are configuring a custom AuthenticationManager for the service, please first remove any existing AuthenticationManagers from the behaviors collection before adding the custom AuthenticationManager."); }
        }
        internal static string MultipleAuthenticationSchemesInServiceBindingParameters {
              get { return SR.GetResourceString("MultipleAuthenticationSchemesInServiceBindingParameters", @"The AuthenticationSchemes cannot be added to the binding parameters because the binding parameters already contains AuthenticationSchemes '{0}'. If you are configuring custom AuthenticationSchemes for the service, please first remove any existing AuthenticationSchemes from the behaviors collection before adding custom AuthenticationSchemes."); }
        }
        internal static string NoSecurityBindingElementFound {
              get { return SR.GetResourceString("NoSecurityBindingElementFound", @"Unable to find a SecurityBindingElement."); }
        }
        internal static string MultipleSecurityCredentialsManagersInServiceBindingParameters {
              get { return SR.GetResourceString("MultipleSecurityCredentialsManagersInServiceBindingParameters", @"The ServiceCredentials cannot be added to the binding parameters because the binding parameters already contains a SecurityCredentialsManager '{0}'. If you are configuring custom credentials for the service, please first remove any existing ServiceCredentials from the behaviors collection before adding the custom credential."); }
        }
        internal static string MultipleSecurityCredentialsManagersInChannelBindingParameters {
              get { return SR.GetResourceString("MultipleSecurityCredentialsManagersInChannelBindingParameters", @"The ClientCredentials cannot be added to the binding parameters because the binding parameters already contains a SecurityCredentialsManager '{0}'. If you are configuring custom credentials for the channel, please first remove any existing ClientCredentials from the behaviors collection before adding the custom credential."); }
        }
        internal static string NoClientCertificate {
              get { return SR.GetResourceString("NoClientCertificate", @"The binding ('{0}', '{1}') has been configured with a MutualCertificateDuplexBindingElement that requires a client certificate. The client certificate is currently missing."); }
        }
        internal static string SecurityTokenParametersHasIncompatibleInclusionMode {
              get { return SR.GetResourceString("SecurityTokenParametersHasIncompatibleInclusionMode", @"The binding ('{0}', '{1}') is configured with a security token parameter '{2}' that has an incompatible security token inclusion mode '{3}'. Specify an alternate security token inclusion mode (for example, '{4}')."); }
        }
        internal static string CannotCreateTwoWayListenerForNegotiation {
              get { return SR.GetResourceString("CannotCreateTwoWayListenerForNegotiation", @"Unable to create a bi-directional (request-reply or duplex) channel for security negotiation. Please ensure that the binding is capable of creating a bi-directional channel."); }
        }
        internal static string NegotiationQuotasExceededFaultReason {
              get { return SR.GetResourceString("NegotiationQuotasExceededFaultReason", @"There are too many active security negotiations or secure conversations at the service. Please retry later."); }
        }
        internal static string PendingSessionsExceededFaultReason {
              get { return SR.GetResourceString("PendingSessionsExceededFaultReason", @"There are too many pending secure conversations on the server. Please retry later."); }
        }
        internal static string RequestSecurityTokenDoesNotMatchEndpointFilters {
              get { return SR.GetResourceString("RequestSecurityTokenDoesNotMatchEndpointFilters", @"The RequestSecurityToken message does not match the endpoint filters the service '{0}' is expecting incoming messages to match. This may be because the RequestSecurityToken was intended to be sent to a different service."); }
        }
        internal static string SecuritySessionRequiresIssuanceAuthenticator {
              get { return SR.GetResourceString("SecuritySessionRequiresIssuanceAuthenticator", @"The security session requires a security token authenticator that implements '{0}'. '{1}' does not implement '{0}'."); }
        }
        internal static string SecuritySessionRequiresSecurityContextTokenCache {
              get { return SR.GetResourceString("SecuritySessionRequiresSecurityContextTokenCache", @"The security session requires a security token resolver that implements '{1}'. The security token resolver '{0}' does not implement '{1}'."); }
        }
        internal static string SessionTokenIsNotSecurityContextToken {
              get { return SR.GetResourceString("SessionTokenIsNotSecurityContextToken", @"The session security token authenticator returned a token of type '{0}'. The token type expected is '{1}'."); }
        }
        internal static string SessionTokenIsNotGenericXmlToken {
              get { return SR.GetResourceString("SessionTokenIsNotGenericXmlToken", @"The session security token provider returned a token of type '{0}'. The token type expected is '{1}'."); }
        }
        internal static string SecurityStandardsManagerNotSet {
              get { return SR.GetResourceString("SecurityStandardsManagerNotSet", @"The security standards manager was not specified on  '{0}'."); }
        }
        internal static string SecurityNegotiationMessageTooLarge {
              get { return SR.GetResourceString("SecurityNegotiationMessageTooLarge", @"The security negotiation message with action '{0}' is larger than the maximum allowed buffer size '{1}'. If you are using a streamed transport consider increasing the maximum buffer size on the transport."); }
        }
        internal static string PreviousChannelDemuxerOpenFailed {
              get { return SR.GetResourceString("PreviousChannelDemuxerOpenFailed", @"The channel demuxer Open failed previously with exception '{0}'."); }
        }
        internal static string SecurityChannelListenerNotSet {
              get { return SR.GetResourceString("SecurityChannelListenerNotSet", @"The security channel listener was not specified on  '{0}'."); }
        }
        internal static string SecurityChannelListenerChannelExtendedProtectionNotSupported {
              get { return SR.GetResourceString("SecurityChannelListenerChannelExtendedProtectionNotSupported", @"ExtendedProtectionPolicy specified a PolicyEnforcement of 'Always' which is not supported for the authentication mode requested.  This prevents the ExtendedProtectionPolicy from being enforced. For StandardBindings use a SecurityMode of TransportWithMessageCredential and a ClientCredential type of Windows. For CustomBindings use SspiNegotiationOverTransport or KerberosOverTransport.  Alternatively, specify a PolicyEnforcement of 'Never'."); }
        }
        internal static string SecurityChannelBindingMissing {
              get { return SR.GetResourceString("SecurityChannelBindingMissing", @"ExtendedProtectionPolicy specified a PolicyEnforcement of 'Always' and a ChannelBinding was not found.  This prevents the ExtendedProtectionPolicy from being enforced. Change the binding to make a ChannelBinding available, for StandardBindings use a SecurityMode of TransportWithMessageCredential and a ClientCredential type of Windows. For CustomBindings use SspiNegotiationOverTransport or KerberosOverTransport.  Alternatively, specify a PolicyEnforcement of 'Never'."); }
        }
        internal static string SecuritySettingsLifetimeManagerNotSet {
              get { return SR.GetResourceString("SecuritySettingsLifetimeManagerNotSet", @"The security settings lifetime manager was not specified on  '{0}'."); }
        }
        internal static string SecurityListenerClosing {
              get { return SR.GetResourceString("SecurityListenerClosing", @"The listener is not accepting new secure conversations because it is closing."); }
        }
        internal static string SecurityListenerClosingFaultReason {
              get { return SR.GetResourceString("SecurityListenerClosingFaultReason", @"The server is not accepting new secure conversations currently because it is closing. Please retry later."); }
        }
        internal static string SslCipherKeyTooSmall {
              get { return SR.GetResourceString("SslCipherKeyTooSmall", @"The cipher key negotiated by SSL is too small ('{0}' bits). Keys of such lengths are not allowed as they may result in information disclosure. Please configure the initiator machine to negotiate SSL cipher keys that are '{1}' bits or longer."); }
        }
        internal static string DerivedKeyTokenNonceTooLong {
              get { return SR.GetResourceString("DerivedKeyTokenNonceTooLong", @"The length ('{0}' bytes) of the derived key's Nonce exceeds the maximum length ('{1}' bytes) allowed."); }
        }
        internal static string DerivedKeyTokenLabelTooLong {
              get { return SR.GetResourceString("DerivedKeyTokenLabelTooLong", @"The length ('{0}' bytes) of the derived key's Label exceeds the maximum length ('{1}' bytes) allowed."); }
        }
        internal static string DerivedKeyTokenOffsetTooHigh {
              get { return SR.GetResourceString("DerivedKeyTokenOffsetTooHigh", @"The derived key's Offset ('{0}' bytes) exceeds the maximum offset ('{1}' bytes) allowed."); }
        }
        internal static string DerivedKeyTokenGenerationAndLengthTooHigh {
              get { return SR.GetResourceString("DerivedKeyTokenGenerationAndLengthTooHigh", @"The derived key's generation ('{0}') and length ('{1}' bytes) result in a key derivation offset that is greater than the maximum offset ('{2}' bytes) allowed."); }
        }
        internal static string DerivedKeyLimitExceeded {
              get { return SR.GetResourceString("DerivedKeyLimitExceeded", @"The number of derived keys in the message has exceeded the maximum allowed number '{0}'."); }
        }
        internal static string WrappedKeyLimitExceeded {
              get { return SR.GetResourceString("WrappedKeyLimitExceeded", @"The number of encrypted keys in the message has exceeded the maximum allowed number '{0}'."); }
        }
        internal static string BufferQuotaExceededReadingBase64 {
              get { return SR.GetResourceString("BufferQuotaExceededReadingBase64", @"Unable to finish reading Base64 data as the given buffer quota has been exceeded. Buffer quota: {0}. Consider increasing the MaxReceivedMessageSize quota on the TransportBindingElement. Please note that a very high value for MaxReceivedMessageSize will result in buffering a large message and might open the system to DOS attacks."); }
        }
        internal static string MessageSecurityDoesNotWorkWithManualAddressing {
              get { return SR.GetResourceString("MessageSecurityDoesNotWorkWithManualAddressing", @"Manual addressing is not supported with message level security. Configure the binding ('{0}', '{1}') to use transport security or to not do manual addressing."); }
        }
        internal static string TargetAddressIsNotSet {
              get { return SR.GetResourceString("TargetAddressIsNotSet", @"The target service address was not specified on '{0}'."); }
        }
        internal static string IssuedTokenCacheNotSet {
              get { return SR.GetResourceString("IssuedTokenCacheNotSet", @"The issued token cache was not specified on '{0}'."); }
        }
        internal static string SecurityAlgorithmSuiteNotSet {
              get { return SR.GetResourceString("SecurityAlgorithmSuiteNotSet", @"The security algorithm suite was not specified on '{0}'."); }
        }
        internal static string SecurityTokenFoundOutsideSecurityHeader {
              get { return SR.GetResourceString("SecurityTokenFoundOutsideSecurityHeader", @"A security token ('{0}', '{1}') was found outside the security header. The message may have been altered in transit."); }
        }
        internal static string SecurityTokenNotResolved {
              get { return SR.GetResourceString("SecurityTokenNotResolved", @"The SecurityTokenProvider '{0}' could not resolve the token."); }
        }
        internal static string SecureConversationCancelNotAllowedFaultReason {
              get { return SR.GetResourceString("SecureConversationCancelNotAllowedFaultReason", @"A secure conversation cancellation is not allowed by the binding."); }
        }
        internal static string BootstrapSecurityBindingElementNotSet {
              get { return SR.GetResourceString("BootstrapSecurityBindingElementNotSet", @"The security binding element for bootstrap security was not specified on '{0}'."); }
        }
        internal static string IssuerBuildContextNotSet {
              get { return SR.GetResourceString("IssuerBuildContextNotSet", @"The context for building the issuer channel was  not specified on '{0}'."); }
        }
        internal static string StsBindingNotSet {
              get { return SR.GetResourceString("StsBindingNotSet", @"The binding to use to communicate to the federation service at '{0}' is not specified."); }
        }
        internal static string SslCertMayNotDoKeyExchange {
              get { return SR.GetResourceString("SslCertMayNotDoKeyExchange", @"It is likely that certificate '{0}' may not have a private key that is capable of key exchange or the process may not have access rights for the private key. Please see inner exception for detail."); }
        }
        internal static string SslCertMustHavePrivateKey {
              get { return SR.GetResourceString("SslCertMustHavePrivateKey", @"The certificate '{0}' must have a private key. The process must have access rights for the private key."); }
        }
        internal static string NoOutgoingEndpointAddressAvailableForDoingIdentityCheck {
              get { return SR.GetResourceString("NoOutgoingEndpointAddressAvailableForDoingIdentityCheck", @"No outgoing EndpointAddress is available to check the identity on a message to be sent."); }
        }
        internal static string NoOutgoingEndpointAddressAvailableForDoingIdentityCheckOnReply {
              get { return SR.GetResourceString("NoOutgoingEndpointAddressAvailableForDoingIdentityCheckOnReply", @"No outgoing EndpointAddress is available to check the identity on a received reply."); }
        }
        internal static string NoSigningTokenAvailableToDoIncomingIdentityCheck {
              get { return SR.GetResourceString("NoSigningTokenAvailableToDoIncomingIdentityCheck", @"No signing token is available to do an incoming identity check."); }
        }
        internal static string Psha1KeyLengthInvalid {
              get { return SR.GetResourceString("Psha1KeyLengthInvalid", @"The PSHA1 key length '{0}' is invalid."); }
        }
        internal static string CloneNotImplementedCorrectly {
              get { return SR.GetResourceString("CloneNotImplementedCorrectly", @"Clone() was not implemented properly by '{0}'. The cloned object was '{1}'."); }
        }
        internal static string BadIssuedTokenType {
              get { return SR.GetResourceString("BadIssuedTokenType", @"The issued token is of unexpected type '{0}'. Expected token type '{1}'."); }
        }
        internal static string OperationDoesNotAllowImpersonation {
              get { return SR.GetResourceString("OperationDoesNotAllowImpersonation", @"The service operation '{0}' that belongs to the contract with the '{1}' name and the '{2}' namespace does not allow impersonation."); }
        }
        internal static string RstrHasMultipleIssuedTokens {
              get { return SR.GetResourceString("RstrHasMultipleIssuedTokens", @"The RequestSecurityTokenResponse has multiple RequestedSecurityToken elements."); }
        }
        internal static string RstrHasMultipleProofTokens {
              get { return SR.GetResourceString("RstrHasMultipleProofTokens", @"The RequestSecurityTokenResponse has multiple RequestedProofToken elements."); }
        }
        internal static string ProofTokenXmlUnexpectedInRstr {
              get { return SR.GetResourceString("ProofTokenXmlUnexpectedInRstr", @"The proof token XML element is not expected in the response."); }
        }
        internal static string InvalidKeyLengthRequested {
              get { return SR.GetResourceString("InvalidKeyLengthRequested", @"The key length '{0}' requested is invalid."); }
        }
        internal static string IssuedSecurityTokenParametersNotSet {
              get { return SR.GetResourceString("IssuedSecurityTokenParametersNotSet", @"The security token parameters to use for the issued token are not set on '{0}'."); }
        }
        internal static string InvalidOrUnrecognizedAction {
              get { return SR.GetResourceString("InvalidOrUnrecognizedAction", @"The message could not be processed because the action '{0}' is invalid or unrecognized."); }
        }
        internal static string UnsupportedTokenInclusionMode {
              get { return SR.GetResourceString("UnsupportedTokenInclusionMode", @"Token inclusion mode '{0}' is not supported."); }
        }
        internal static string CannotImportProtectionLevelForContract {
              get { return SR.GetResourceString("CannotImportProtectionLevelForContract", @"The policy to import a process cannot import a binding for contract ({0},{1}). The protection requirements for the binding are not compatible with a binding already imported for the contract. You must reconfigure the binding."); }
        }
        internal static string OnlyOneOfEncryptedKeyOrSymmetricBindingCanBeSelected {
              get { return SR.GetResourceString("OnlyOneOfEncryptedKeyOrSymmetricBindingCanBeSelected", @"The symmetric security protocol can either be configured with a symmetric token provider and a symmetric token authenticator or an asymmetric token provider. It cannot be configured with both."); }
        }
        internal static string ClientCredentialTypeMustBeSpecifiedForMixedMode {
              get { return SR.GetResourceString("ClientCredentialTypeMustBeSpecifiedForMixedMode", @"ClientCredentialType.None is not valid for the TransportWithMessageCredential security mode. Specify a message credential type or use a different security mode."); }
        }
        internal static string SecuritySessionIdAlreadyPresentInFilterTable {
              get { return SR.GetResourceString("SecuritySessionIdAlreadyPresentInFilterTable", @"The security session id '{0}' is already present in the filter table."); }
        }
        internal static string SupportingTokenNotProvided {
              get { return SR.GetResourceString("SupportingTokenNotProvided", @"A supporting token that satisfies parameters '{0}' and attachment mode '{1}' was not provided."); }
        }
        internal static string SupportingTokenIsNotEndorsing {
              get { return SR.GetResourceString("SupportingTokenIsNotEndorsing", @"The supporting token provided for parameters '{0}' did not endorse the primary signature."); }
        }
        internal static string SupportingTokenIsNotSigned {
              get { return SR.GetResourceString("SupportingTokenIsNotSigned", @"The supporting token provided for parameters '{0}' was not signed as part of the primary signature."); }
        }
        internal static string SupportingTokenIsNotEncrypted {
              get { return SR.GetResourceString("SupportingTokenIsNotEncrypted", @"The supporting token provided for parameters '{0}' was not encrypted."); }
        }
        internal static string BasicTokenNotExpected {
              get { return SR.GetResourceString("BasicTokenNotExpected", @"A basic token is not expected in the security header in this context."); }
        }
        internal static string FailedAuthenticationTrustFaultCode {
              get { return SR.GetResourceString("FailedAuthenticationTrustFaultCode", @"The request for security token could not be satisfied because authentication failed."); }
        }
        internal static string AuthenticationOfClientFailed {
              get { return SR.GetResourceString("AuthenticationOfClientFailed", @"The caller was not authenticated by the service."); }
        }
        internal static string InvalidRequestTrustFaultCode {
              get { return SR.GetResourceString("InvalidRequestTrustFaultCode", @"The request for security token has invalid or malformed elements."); }
        }
        internal static string SignedSupportingTokenNotExpected {
              get { return SR.GetResourceString("SignedSupportingTokenNotExpected", @"A signed supporting token is not expected in the security header in this context."); }
        }
        internal static string SenderSideSupportingTokensMustSpecifySecurityTokenParameters {
              get { return SR.GetResourceString("SenderSideSupportingTokensMustSpecifySecurityTokenParameters", @"Security token parameters must be specified with supporting tokens for each message."); }
        }
        internal static string SignatureAndEncryptionTokenMismatch {
              get { return SR.GetResourceString("SignatureAndEncryptionTokenMismatch", @"The signature token '{0}' is not the same token as the encryption token '{1}'."); }
        }
        internal static string RevertingPrivilegeFailed {
              get { return SR.GetResourceString("RevertingPrivilegeFailed", @"The reverting operation failed with the exception '{0}'."); }
        }
        internal static string UnknownSupportingToken {
              get { return SR.GetResourceString("UnknownSupportingToken", @"Unrecognized supporting token '{0}' was encountered."); }
        }
        internal static string MoreThanOneSupportingSignature {
              get { return SR.GetResourceString("MoreThanOneSupportingSignature", @"More than one supporting signature was encountered using the same supporting token '{0}'."); }
        }
        internal static string UnsecuredMessageFaultReceived {
              get { return SR.GetResourceString("UnsecuredMessageFaultReceived", @"An unsecured or incorrectly secured fault was received from the other party. See the inner FaultException for the fault code and detail."); }
        }
        internal static string FailedAuthenticationFaultReason {
              get { return SR.GetResourceString("FailedAuthenticationFaultReason", @"At least one security token in the message could not be validated."); }
        }
        internal static string BadContextTokenOrActionFaultReason {
              get { return SR.GetResourceString("BadContextTokenOrActionFaultReason", @"The message could not be processed. This is most likely because the action '{0}' is incorrect or because the message contains an invalid or expired security context token or because there is a mismatch between bindings. The security context token would be invalid if the service aborted the channel due to inactivity. To prevent the service from aborting idle sessions prematurely increase the Receive timeout on the service endpoint's binding."); }
        }
        internal static string BadContextTokenFaultReason {
              get { return SR.GetResourceString("BadContextTokenFaultReason", @"The security context token is expired or is not valid. The message was not processed."); }
        }
        internal static string NegotiationFailedIO {
              get { return SR.GetResourceString("NegotiationFailedIO", @"Transport security negotiation failed due to an underlying IO error: {0}."); }
        }
        internal static string SecurityNegotiationCannotProtectConfidentialEndpointHeader {
              get { return SR.GetResourceString("SecurityNegotiationCannotProtectConfidentialEndpointHeader", @"The security negotiation with '{0}' cannot be initiated because the confidential endpoint address header ('{1}', '{2}') cannot be encrypted during the course of the negotiation."); }
        }
        internal static string InvalidSecurityTokenFaultReason {
              get { return SR.GetResourceString("InvalidSecurityTokenFaultReason", @"An error occurred when processing the security tokens in the message."); }
        }
        internal static string InvalidSecurityFaultReason {
              get { return SR.GetResourceString("InvalidSecurityFaultReason", @"An error occurred when verifying security for the message."); }
        }
        internal static string AnonymousLogonsAreNotAllowed {
              get { return SR.GetResourceString("AnonymousLogonsAreNotAllowed", @"The service does not allow you to log on anonymously."); }
        }
        internal static string UnableToObtainIssuerMetadata {
              get { return SR.GetResourceString("UnableToObtainIssuerMetadata", @"Obtaining metadata from issuer '{0}' failed with error '{1}'."); }
        }
        internal static string ErrorImportingIssuerMetadata {
              get { return SR.GetResourceString("ErrorImportingIssuerMetadata", @"Importing metadata from issuer '{0}' failed with error '{1}'."); }
        }
        internal static string MultipleCorrelationTokensFound {
              get { return SR.GetResourceString("MultipleCorrelationTokensFound", @"Multiple correlation tokens were found in the security correlation state."); }
        }
        internal static string NoCorrelationTokenFound {
              get { return SR.GetResourceString("NoCorrelationTokenFound", @"No correlation token was found in the security correlation state."); }
        }
        internal static string MultipleSupportingAuthenticatorsOfSameType {
              get { return SR.GetResourceString("MultipleSupportingAuthenticatorsOfSameType", @"Multiple supporting token authenticators with the token parameter type equal to '{0}' cannot be specified. If more than one Supporting Token of the same type is expected in the response, then configure the supporting token collection with just one entry for that SecurityTokenParameters. The SecurityTokenAuthenticator that gets created from the SecurityTokenParameters will be used to authenticate multiple tokens. It is not possible to add SecurityTokenParameters of the same type in the SupportingTokenParameters collection or repeat it across EndpointSupportingTokenParameters and OperationSupportingTokenParameters."); }
        }
        internal static string TooManyIssuedSecurityTokenParameters {
              get { return SR.GetResourceString("TooManyIssuedSecurityTokenParameters", @"A leg of the federated security chain contains multiple IssuedSecurityTokenParameters. The InfoCard system only supports one IssuedSecurityTokenParameters for each leg."); }
        }
        internal static string UnknownTokenAuthenticatorUsedInTokenProcessing {
              get { return SR.GetResourceString("UnknownTokenAuthenticatorUsedInTokenProcessing", @"An unrecognized token authenticator '{0}' was used for token processing."); }
        }
        internal static string TokenMustBeNullWhenTokenParametersAre {
              get { return SR.GetResourceString("TokenMustBeNullWhenTokenParametersAre", @"The SecurityTokenParameters and SecurityToken tuple specified for use in the security header must both be null or must both be non-null."); }
        }
        internal static string SecurityTokenParametersCloneInvalidResult {
              get { return SR.GetResourceString("SecurityTokenParametersCloneInvalidResult", @"The CloneCore method of {0} type returned an invalid result. "); }
        }
        internal static string CertificateUnsupportedForHttpTransportCredentialOnly {
              get { return SR.GetResourceString("CertificateUnsupportedForHttpTransportCredentialOnly", @"Certificate-based client authentication is not supported in TransportCredentialOnly security mode. Select the Transport security mode."); }
        }
        internal static string BasicHttpMessageSecurityRequiresCertificate {
              get { return SR.GetResourceString("BasicHttpMessageSecurityRequiresCertificate", @"BasicHttp binding requires that BasicHttpBinding.Security.Message.ClientCredentialType be equivalent to the BasicHttpMessageCredentialType.Certificate credential type for secure messages. Select Transport or TransportWithMessageCredential security for UserName credentials."); }
        }
        internal static string EntropyModeRequiresRequestorEntropy {
              get { return SR.GetResourceString("EntropyModeRequiresRequestorEntropy", @"The client must provide key entropy in key entropy mode '{0}'."); }
        }
        internal static string BearerKeyTypeCannotHaveProofKey {
              get { return SR.GetResourceString("BearerKeyTypeCannotHaveProofKey", @"A Proof Token was found in the response that was returned by the Security Token Service for a Bearer Key Type token request. Note that Proof Tokens should not be generated when a Bearer Key Type request is made."); }
        }
        internal static string BearerKeyIncompatibleWithWSFederationHttpBinding {
              get { return SR.GetResourceString("BearerKeyIncompatibleWithWSFederationHttpBinding", @"Bearer Key Type is not supported with WSFederationHttpBinding. Please use WS2007FederationHttpBinding."); }
        }
        internal static string UnableToCreateKeyTypeElementForUnknownKeyType {
              get { return SR.GetResourceString("UnableToCreateKeyTypeElementForUnknownKeyType", @"Unable to create Key Type element for the Key Type '{0}'. This might be due to a wrong version of MessageSecurityVersion set on the SecurityBindingElement."); }
        }
        internal static string EntropyModeCannotHaveProofTokenOrIssuerEntropy {
              get { return SR.GetResourceString("EntropyModeCannotHaveProofTokenOrIssuerEntropy", @"The issuer cannot provide key entropy or a proof token in key entropy mode '{0}'."); }
        }
        internal static string EntropyModeCannotHaveRequestorEntropy {
              get { return SR.GetResourceString("EntropyModeCannotHaveRequestorEntropy", @"The client cannot provide key entropy in key entropy mode '{0}'."); }
        }
        internal static string EntropyModeRequiresProofToken {
              get { return SR.GetResourceString("EntropyModeRequiresProofToken", @"The issuer must provide a proof token in key entropy mode '{0}'."); }
        }
        internal static string EntropyModeRequiresComputedKey {
              get { return SR.GetResourceString("EntropyModeRequiresComputedKey", @"The issuer must provide a computed key in key entropy mode '{0}'."); }
        }
        internal static string EntropyModeRequiresIssuerEntropy {
              get { return SR.GetResourceString("EntropyModeRequiresIssuerEntropy", @"The issuer must provide key entropy in key entropy mode '{0}'."); }
        }
        internal static string EntropyModeCannotHaveComputedKey {
              get { return SR.GetResourceString("EntropyModeCannotHaveComputedKey", @"The issuer cannot provide a computed key in key entropy mode '{0}'."); }
        }
        internal static string UnknownComputedKeyAlgorithm {
              get { return SR.GetResourceString("UnknownComputedKeyAlgorithm", @"The computed key algorithm '{0}' is not supported."); }
        }
        internal static string NoncesCachedInfinitely {
              get { return SR.GetResourceString("NoncesCachedInfinitely", @"The ReplayWindow and ClockSkew cannot be the maximum possible value when replay detection is enabled."); }
        }
        internal static string ChannelMustBeOpenedToGetSessionId {
              get { return SR.GetResourceString("ChannelMustBeOpenedToGetSessionId", @"The session channel must be opened before the session ID can be accessed."); }
        }
        internal static string SecurityVersionDoesNotSupportEncryptedKeyBinding {
              get { return SR.GetResourceString("SecurityVersionDoesNotSupportEncryptedKeyBinding", @"The binding ('{0}','{1}') for contract ('{2}','{3}') has been configured with an incompatible security version that does not support unattached references to EncryptedKeys. Use '{4}' or higher as the security version for the binding."); }
        }
        internal static string SecurityVersionDoesNotSupportThumbprintX509KeyIdentifierClause {
              get { return SR.GetResourceString("SecurityVersionDoesNotSupportThumbprintX509KeyIdentifierClause", @"The '{0}','{1}' binding for the '{2}','{3}' contract is configured with a security version that does not support external references to X.509 tokens using the certificate's thumbprint value. Use '{4}' or higher as the security version for the binding."); }
        }
        internal static string SecurityBindingSupportsOneWayOnly {
              get { return SR.GetResourceString("SecurityBindingSupportsOneWayOnly", @"The SecurityBinding for the ('{0}','{1}') binding for the ('{2}','{3}') contract only supports the OneWay operation."); }
        }
        internal static string DownlevelNameCannotMapToUpn {
              get { return SR.GetResourceString("DownlevelNameCannotMapToUpn", @"Cannot map Windows user '{0}' to a UserPrincipalName that can be used for S4U impersonation."); }
        }
        internal static string ResolvingExternalTokensRequireSecurityTokenParameters {
              get { return SR.GetResourceString("ResolvingExternalTokensRequireSecurityTokenParameters", @"Resolving an External reference token requires appropriate SecurityTokenParameters to be specified."); }
        }
        internal static string SecurityRenewFaultReason {
              get { return SR.GetResourceString("SecurityRenewFaultReason", @"The SecurityContextSecurityToken's key needs to be renewed."); }
        }
        internal static string ClientSecurityOutputSessionCloseTimeout {
              get { return SR.GetResourceString("ClientSecurityOutputSessionCloseTimeout", @"The client's security session was not able to close its output session within the configured timeout ({0})."); }
        }
        internal static string ClientSecurityNegotiationTimeout {
              get { return SR.GetResourceString("ClientSecurityNegotiationTimeout", @"Client is unable to finish the security negotiation within the configured timeout ({0}).  The current negotiation leg is {1} ({2}).  "); }
        }
        internal static string ClientSecuritySessionRequestTimeout {
              get { return SR.GetResourceString("ClientSecuritySessionRequestTimeout", @"Client is unable to request the security session within the configured timeout ({0})."); }
        }
        internal static string ServiceSecurityCloseOutputSessionTimeout {
              get { return SR.GetResourceString("ServiceSecurityCloseOutputSessionTimeout", @"The service's security session was not able to close its output session within the configured timeout ({0})."); }
        }
        internal static string ServiceSecurityCloseTimeout {
              get { return SR.GetResourceString("ServiceSecurityCloseTimeout", @"The service's security session did not receive a 'close' message from the client within the configured timeout ({0})."); }
        }
        internal static string ClientSecurityCloseTimeout {
              get { return SR.GetResourceString("ClientSecurityCloseTimeout", @"The client's security session did not receive a 'close response' message from the service within the configured timeout ({0})."); }
        }
        internal static string UnableToRenewSessionKey {
              get { return SR.GetResourceString("UnableToRenewSessionKey", @"Cannot renew the security session key."); }
        }
        internal static string SessionKeyRenewalNotSupported {
              get { return SR.GetResourceString("SessionKeyRenewalNotSupported", @"Cannot renew the security session key. Session Key Renewal is not supported."); }
        }
        internal static string SctCookieXmlParseError {
              get { return SR.GetResourceString("SctCookieXmlParseError", @"Error parsing SecurityContextSecurityToken Cookie XML."); }
        }
        internal static string SctCookieValueMissingOrIncorrect {
              get { return SR.GetResourceString("SctCookieValueMissingOrIncorrect", @"The SecurityContextSecurityToken's Cookie element either does not contain '{0}' or has a wrong value for it."); }
        }
        internal static string SctCookieBlobDecodeFailure {
              get { return SR.GetResourceString("SctCookieBlobDecodeFailure", @"Error decoding the Cookie element of SecurityContextSecurityToken."); }
        }
        internal static string SctCookieNotSupported {
              get { return SR.GetResourceString("SctCookieNotSupported", @"Issuing cookie SecurityContextSecurityToken is not supported."); }
        }
        internal static string CannotImportSupportingTokensForOperationWithoutRequestAction {
              get { return SR.GetResourceString("CannotImportSupportingTokensForOperationWithoutRequestAction", @"Security policy import failed. The security policy contains supporting token requirements at the operation scope. The contract description does not specify the action for the request message associated with this operation."); }
        }
        internal static string SignatureConfirmationsNotExpected {
              get { return SR.GetResourceString("SignatureConfirmationsNotExpected", @"Signature confirmation is not expected in the security header."); }
        }
        internal static string SignatureConfirmationsOccursAfterPrimarySignature {
              get { return SR.GetResourceString("SignatureConfirmationsOccursAfterPrimarySignature", @"The signature confirmation elements cannot occur after the primary signature."); }
        }
        internal static string SignatureConfirmationWasExpected {
              get { return SR.GetResourceString("SignatureConfirmationWasExpected", @"Signature confirmation was expected to be present in the security header."); }
        }
        internal static string SecurityVersionDoesNotSupportSignatureConfirmation {
              get { return SR.GetResourceString("SecurityVersionDoesNotSupportSignatureConfirmation", @"The SecurityVersion '{0}' does not support signature confirmation. Use a later SecurityVersion."); }
        }
        internal static string SignatureConfirmationRequiresRequestReply {
              get { return SR.GetResourceString("SignatureConfirmationRequiresRequestReply", @"The protocol factory must support Request/Reply security in order to offer signature confirmation."); }
        }
        internal static string NotAllSignaturesConfirmed {
              get { return SR.GetResourceString("NotAllSignaturesConfirmed", @"Not all the signatures in the request message were confirmed in the reply message."); }
        }
        internal static string FoundUnexpectedSignatureConfirmations {
              get { return SR.GetResourceString("FoundUnexpectedSignatureConfirmations", @"The request did not have any signatures but the reply has signature confirmations."); }
        }
        internal static string TooManyPendingSessionKeys {
              get { return SR.GetResourceString("TooManyPendingSessionKeys", @"There are too many renewed session keys that have not been used."); }
        }
        internal static string SecuritySessionKeyIsStale {
              get { return SR.GetResourceString("SecuritySessionKeyIsStale", @"The session key must be renewed before it can secure application messages."); }
        }
        internal static string MultipleMatchingCryptosFound {
              get { return SR.GetResourceString("MultipleMatchingCryptosFound", @"The token's crypto collection has multiple objects of type '{0}'."); }
        }
        internal static string CannotFindMatchingCrypto {
              get { return SR.GetResourceString("CannotFindMatchingCrypto", @"The token's crypto collection does not support algorithm '{0}'."); }
        }
        internal static string SymmetricSecurityBindingElementNeedsProtectionTokenParameters {
              get { return SR.GetResourceString("SymmetricSecurityBindingElementNeedsProtectionTokenParameters", @"SymmetricSecurityBindingElement cannot build a channel or listener factory. The ProtectionTokenParameters property is required but not set. Binding element configuration: {0}"); }
        }
        internal static string AsymmetricSecurityBindingElementNeedsInitiatorTokenParameters {
              get { return SR.GetResourceString("AsymmetricSecurityBindingElementNeedsInitiatorTokenParameters", @"AsymmetricSecurityBindingElement cannot build a channel or listener factory. The InitiatorTokenParameters property is required but not set. Binding element configuration: {0}"); }
        }
        internal static string AsymmetricSecurityBindingElementNeedsRecipientTokenParameters {
              get { return SR.GetResourceString("AsymmetricSecurityBindingElementNeedsRecipientTokenParameters", @"AsymmetricSecurityBindingElement cannot build a channel or listener factory. The RecipientTokenParameters property is required but not set. Binding element configuration: {0}"); }
        }
        internal static string CachedNegotiationStateQuotaReached {
              get { return SR.GetResourceString("CachedNegotiationStateQuotaReached", @"The service cannot cache the negotiation state as the capacity '{0}' has been reached. Retry the request."); }
        }
        internal static string LsaAuthorityNotContacted {
              get { return SR.GetResourceString("LsaAuthorityNotContacted", @"Internal SSL error (refer to Win32 status code for details). Check the server certificate to determine if it is capable of key exchange."); }
        }
        internal static string KeyRolloverGreaterThanKeyRenewal {
              get { return SR.GetResourceString("KeyRolloverGreaterThanKeyRenewal", @"The key rollover interval cannot be greater than the key renewal interval."); }
        }
        internal static string AtLeastOneContractOperationRequestRequiresProtectionLevelNotSupportedByBinding {
              get { return SR.GetResourceString("AtLeastOneContractOperationRequestRequiresProtectionLevelNotSupportedByBinding", @"The request message must be protected. This is required by an operation of the contract ('{0}','{1}'). The protection must be provided by the binding ('{2}','{3}')."); }
        }
        internal static string AtLeastOneContractOperationResponseRequiresProtectionLevelNotSupportedByBinding {
              get { return SR.GetResourceString("AtLeastOneContractOperationResponseRequiresProtectionLevelNotSupportedByBinding", @"The response message must be protected. This is required by an operation of the contract ('{0}', '{1}'). The protection must be provided by the binding ('{2}', '{3}')."); }
        }
        internal static string UnknownHeaderCannotProtected {
              get { return SR.GetResourceString("UnknownHeaderCannotProtected", @"The contract ('{0}','{1}') contains some unknown header ('{2}','{3}') which cannot be secured. Please choose ProtectionLevel.None for this header.   "); }
        }
        internal static string NoStreamingWithSecurity {
              get { return SR.GetResourceString("NoStreamingWithSecurity", @"The binding ('{0}','{1}') supports streaming which cannot be configured together with message level security.  Consider choosing a different transfer mode or choosing the transport level security."); }
        }
        internal static string CurrentSessionTokenNotRenewed {
              get { return SR.GetResourceString("CurrentSessionTokenNotRenewed", @"The supporting token in the renew message has a different generation '{0}' than the current session token's generation '{1}'."); }
        }
        internal static string IncorrectSpnOrUpnSpecified {
              get { return SR.GetResourceString("IncorrectSpnOrUpnSpecified", @"Security Support Provider Interface (SSPI) authentication failed. The server may not be running in an account with identity '{0}'. If the server is running in a service account (Network Service for example), specify the account's ServicePrincipalName as the identity in the EndpointAddress for the server. If the server is running in a user account, specify the account's UserPrincipalName as the identity in the EndpointAddress for the server."); }
        }
        internal static string IncomingSigningTokenMustBeAnEncryptedKey {
              get { return SR.GetResourceString("IncomingSigningTokenMustBeAnEncryptedKey", @"For this security protocol, the incoming signing token must be an EncryptedKey."); }
        }
        internal static string SecuritySessionAbortedFaultReason {
              get { return SR.GetResourceString("SecuritySessionAbortedFaultReason", @"The security session was terminated This may be because no messages were received on the session for too long."); }
        }
        internal static string NoAppliesToPresent {
              get { return SR.GetResourceString("NoAppliesToPresent", @"No AppliesTo element is present in the deserialized RequestSecurityToken/RequestSecurityTokenResponse."); }
        }
        internal static string UnsupportedKeyLength {
              get { return SR.GetResourceString("UnsupportedKeyLength", @"Symmetric Key length {0} is not supported by the algorithm suite '{1}'."); }
        }
        internal static string ForReplayDetectionToBeDoneRequireIntegrityMustBeSet {
              get { return SR.GetResourceString("ForReplayDetectionToBeDoneRequireIntegrityMustBeSet", @"For replay detection to be done ProtectionLevel must be Sign or EncryptAndSign."); }
        }
        internal static string CantInferReferenceForToken {
              get { return SR.GetResourceString("CantInferReferenceForToken", @"Can't infer an external reference for '{0}' token type."); }
        }
        internal static string TrustDriverIsUnableToCreatedNecessaryAttachedOrUnattachedReferences {
              get { return SR.GetResourceString("TrustDriverIsUnableToCreatedNecessaryAttachedOrUnattachedReferences", @"Unable to create Attached or Unattached reference for '{0}'."); }
        }
        internal static string TrustDriverVersionDoesNotSupportSession {
              get { return SR.GetResourceString("TrustDriverVersionDoesNotSupportSession", @"The configured Trust version does not support sessions. Use WSTrustFeb2005 or above."); }
        }
        internal static string TrustDriverVersionDoesNotSupportIssuedTokens {
              get { return SR.GetResourceString("TrustDriverVersionDoesNotSupportIssuedTokens", @"The configured WS-Trust version does not support issued tokens. WS-Trust February 2005 or later is required."); }
        }
        internal static string CannotPerformS4UImpersonationOnPlatform {
              get { return SR.GetResourceString("CannotPerformS4UImpersonationOnPlatform", @"The binding ('{0}','{1}') for contract ('{2}','{3}') supports impersonation only on Windows 2003 Server and newer version of Windows. Use SspiNegotiated authentication and a binding with Secure Conversation with cancellation enabled."); }
        }
        internal static string CannotPerformImpersonationOnUsernameToken {
              get { return SR.GetResourceString("CannotPerformImpersonationOnUsernameToken", @"Impersonation using the client token is not possible. The binding ('{0}', '{1}') for contract ('{2}', '{3}') uses the Username Security Token for client authentication with a Membership Provider registered. Use a different type of security token for the client."); }
        }
        internal static string RevertImpersonationFailure {
              get { return SR.GetResourceString("RevertImpersonationFailure", @"Failed to revert impersonation. {0}"); }
        }
        internal static string TransactionFlowRequiredIssuedTokens {
              get { return SR.GetResourceString("TransactionFlowRequiredIssuedTokens", @"In order to flow a transaction, flowing issued tokens must also be supported."); }
        }
        internal static string SignatureConfirmationNotSupported {
              get { return SR.GetResourceString("SignatureConfirmationNotSupported", @"The configured SecurityVersion does not support signature confirmation. Use WsSecurity11 or above."); }
        }
        internal static string SecureConversationDriverVersionDoesNotSupportSession {
              get { return SR.GetResourceString("SecureConversationDriverVersionDoesNotSupportSession", @"The configured SecureConversation version does not support sessions. Use WSSecureConversationFeb2005 or above."); }
        }
        internal static string SoapSecurityNegotiationFailed {
              get { return SR.GetResourceString("SoapSecurityNegotiationFailed", @"SOAP security negotiation failed. See inner exception for more details."); }
        }
        internal static string SoapSecurityNegotiationFailedForIssuerAndTarget {
              get { return SR.GetResourceString("SoapSecurityNegotiationFailedForIssuerAndTarget", @"SOAP security negotiation with '{0}' for target '{1}' failed. See inner exception for more details."); }
        }
        internal static string OneWayOperationReturnedFault {
              get { return SR.GetResourceString("OneWayOperationReturnedFault", @"The one-way operation returned a fault message.  The reason for the fault was '{0}'."); }
        }
        internal static string OneWayOperationReturnedLargeFault {
              get { return SR.GetResourceString("OneWayOperationReturnedLargeFault", @"The one-way operation returned a fault message with Action='{0}'."); }
        }
        internal static string OneWayOperationReturnedMessage {
              get { return SR.GetResourceString("OneWayOperationReturnedMessage", @"The one-way operation returned a non-null message with Action='{0}'."); }
        }
        internal static string CannotFindSecuritySession {
              get { return SR.GetResourceString("CannotFindSecuritySession", @"Cannot find the security session with the ID '{0}'."); }
        }
        internal static string SecurityContextKeyExpired {
              get { return SR.GetResourceString("SecurityContextKeyExpired", @"The SecurityContextSecurityToken with Context-id={0} (generation-id={1}) has expired."); }
        }
        internal static string SecurityContextKeyExpiredNoKeyGeneration {
              get { return SR.GetResourceString("SecurityContextKeyExpiredNoKeyGeneration", @"The SecurityContextSecurityToken with Context-id={0} (no key generation-id) has expired."); }
        }
        internal static string SecuritySessionRequiresMessageIntegrity {
              get { return SR.GetResourceString("SecuritySessionRequiresMessageIntegrity", @"Security sessions require all messages to be signed."); }
        }
        internal static string RequiredTimestampMissingInSecurityHeader {
              get { return SR.GetResourceString("RequiredTimestampMissingInSecurityHeader", @"Required timestamp missing in security header."); }
        }
        internal static string ReceivedMessageInRequestContextNull {
              get { return SR.GetResourceString("ReceivedMessageInRequestContextNull", @"The request message in the request context received from channel '{0}' is null."); }
        }
        internal static string KeyLifetimeNotWithinTokenLifetime {
              get { return SR.GetResourceString("KeyLifetimeNotWithinTokenLifetime", @"The key effective and expiration times must be bounded by the token effective and expiration times."); }
        }
        internal static string EffectiveGreaterThanExpiration {
              get { return SR.GetResourceString("EffectiveGreaterThanExpiration", @"The valid from time is greater than the valid to time."); }
        }
        internal static string NoSessionTokenPresentInMessage {
              get { return SR.GetResourceString("NoSessionTokenPresentInMessage", @"No session token was present in the message."); }
        }
        internal static string LengthMustBeGreaterThanZero {
              get { return SR.GetResourceString("LengthMustBeGreaterThanZero", @"The length of this argument must be greater than 0."); }
        }
        internal static string KeyLengthMustBeMultipleOfEight {
              get { return SR.GetResourceString("KeyLengthMustBeMultipleOfEight", @"Key length '{0}' is not a multiple of 8 for symmetric keys."); }
        }
        internal static string InvalidX509RawData {
              get { return SR.GetResourceString("InvalidX509RawData", @"Invalid binary representation of an X.509 certificate."); }
        }
        internal static string ExportOfBindingWithTransportSecurityBindingElementAndNoTransportSecurityNotSupported {
              get { return SR.GetResourceString("ExportOfBindingWithTransportSecurityBindingElementAndNoTransportSecurityNotSupported", @"Security policy export failed. The binding contains a TransportSecurityBindingElement but no transport binding element that implements ITransportTokenAssertionProvider. Policy export for such a binding is not supported. Make sure the transport binding element in the binding implements the ITransportTokenAssertionProvider interface."); }
        }
        internal static string UnsupportedSecureConversationBootstrapProtectionRequirements {
              get { return SR.GetResourceString("UnsupportedSecureConversationBootstrapProtectionRequirements", @"Cannot import the security policy. The protection requirements for the secure conversation bootstrap binding are not supported. Protection requirements for the secure conversation bootstrap must require both the request and the response to be signed and encrypted."); }
        }
        internal static string UnsupportedBooleanAttribute {
              get { return SR.GetResourceString("UnsupportedBooleanAttribute", @"Cannot import the policy. The value of the attribute '{0}' must be either 'true', 'false', '1' or '0'. The following error occurred: '{1}'."); }
        }
        internal static string NoTransportTokenAssertionProvided {
              get { return SR.GetResourceString("NoTransportTokenAssertionProvided", @"The security policy expert failed. The provided transport token assertion of type '{0}' did not create a transport token assertion to include the sp:TransportBinding security policy assertion."); }
        }
        internal static string PolicyRequiresConfidentialityWithoutIntegrity {
              get { return SR.GetResourceString("PolicyRequiresConfidentialityWithoutIntegrity", @"Message security policy for the '{0}' action requires confidentiality without integrity. Confidentiality without integrity is not supported."); }
        }
        internal static string PrimarySignatureIsRequiredToBeEncrypted {
              get { return SR.GetResourceString("PrimarySignatureIsRequiredToBeEncrypted", @"The primary signature must be encrypted."); }
        }
        internal static string TokenCannotCreateSymmetricCrypto {
              get { return SR.GetResourceString("TokenCannotCreateSymmetricCrypto", @"A symmetric crypto could not be created from token '{0}'."); }
        }
        internal static string TokenDoesNotMeetKeySizeRequirements {
              get { return SR.GetResourceString("TokenDoesNotMeetKeySizeRequirements", @"The key size requirements for the '{0}' algorithm suite are not met by the '{1}' token which has key size of '{2}'."); }
        }
        internal static string MessageProtectionOrderMismatch {
              get { return SR.GetResourceString("MessageProtectionOrderMismatch", @"The received message does not meet the required message protection order '{0}'."); }
        }
        internal static string PrimarySignatureMustBeComputedBeforeSupportingTokenSignatures {
              get { return SR.GetResourceString("PrimarySignatureMustBeComputedBeforeSupportingTokenSignatures", @"Primary signature must be computed before supporting token signatures."); }
        }
        internal static string ElementToSignMustHaveId {
              get { return SR.GetResourceString("ElementToSignMustHaveId", @"Element to sign must have id."); }
        }
        internal static string StandardsManagerCannotWriteObject {
              get { return SR.GetResourceString("StandardsManagerCannotWriteObject", @"The token Serializer cannot serialize '{0}'.  If this is a custom type you must supply a custom serializer."); }
        }
        internal static string SigningWithoutPrimarySignatureRequiresTimestamp {
              get { return SR.GetResourceString("SigningWithoutPrimarySignatureRequiresTimestamp", @"Signing without primary signature requires timestamp."); }
        }
        internal static string OperationCannotBeDoneAfterProcessingIsStarted {
              get { return SR.GetResourceString("OperationCannotBeDoneAfterProcessingIsStarted", @"This operation cannot be done after processing is started."); }
        }
        internal static string MaximumPolicyRedirectionsExceeded {
              get { return SR.GetResourceString("MaximumPolicyRedirectionsExceeded", @"The recursive policy fetching limit has been reached. Check to determine if there is a loop in the federation service chain."); }
        }
        internal static string InvalidAttributeInSignedHeader {
              get { return SR.GetResourceString("InvalidAttributeInSignedHeader", @"The ('{0}', '{1}') signed header contains the ('{2}', '{3}') attribute. The expected attribute is ('{4}', '{5}')."); }
        }
        internal static string StsAddressNotSet {
              get { return SR.GetResourceString("StsAddressNotSet", @"The address of the security token issuer is not specified. An explicit issuer address must be specified in the binding for target '{0}' or the local issuer address must be configured in the credentials."); }
        }
        internal static string MoreThanOneSecurityBindingElementInTheBinding {
              get { return SR.GetResourceString("MoreThanOneSecurityBindingElementInTheBinding", @"More than one SecurityBindingElement found in the binding ('{0}', '{1}) for contract ('{2}', '{3}'). Only one SecurityBindingElement is allowed. "); }
        }
        internal static string ClientCredentialsUnableToCreateLocalTokenProvider {
              get { return SR.GetResourceString("ClientCredentialsUnableToCreateLocalTokenProvider", @"ClientCredentials cannot create a local token provider for token requirement {0}."); }
        }
        internal static string SecurityBindingElementCannotBeExpressedInConfig {
              get { return SR.GetResourceString("SecurityBindingElementCannotBeExpressedInConfig", @"A security policy was imported for the endpoint. The security policy contains requirements that cannot be represented in a Windows Communication Foundation configuration. Look for a comment about the SecurityBindingElement parameters that are required in the configuration file that was generated. Create the correct binding element with code. The binding configuration that is in the configuration file is not secure."); }
        }
        internal static string SecurityProtocolCannotDoReplayDetection {
              get { return SR.GetResourceString("SecurityProtocolCannotDoReplayDetection", @"The security protocol '{0}' cannot do replay detection."); }
        }
        internal static string UnableToFindSecurityHeaderInMessage {
              get { return SR.GetResourceString("UnableToFindSecurityHeaderInMessage", @"Security processor was unable to find a security header with actor '{0}' in the message. This might be because the message is an unsecured fault or because there is a binding mismatch between the communicating parties.  This can occur if the service is configured for security and the client is not using security."); }
        }
        internal static string UnableToFindSecurityHeaderInMessageNoActor {
              get { return SR.GetResourceString("UnableToFindSecurityHeaderInMessageNoActor", @"Security processor was unable to find a security header in the message. This might be because the message is an unsecured fault or because there is a binding mismatch between the communicating parties.   This can occur if the service is configured for security and the client is not using security."); }
        }
        internal static string NoPrimarySignatureAvailableForSupportingTokenSignatureVerification {
              get { return SR.GetResourceString("NoPrimarySignatureAvailableForSupportingTokenSignatureVerification", @"No primary signature available for supporting token signature verification."); }
        }
        internal static string SupportingTokenSignaturesNotExpected {
              get { return SR.GetResourceString("SupportingTokenSignaturesNotExpected", @"Supporting token signatures not expected."); }
        }
        internal static string CannotReadToken {
              get { return SR.GetResourceString("CannotReadToken", @"Cannot read the token from the '{0}' element with the '{1}' namespace for BinarySecretSecurityToken, with a '{2}' ValueType. If this element is expected to be valid, ensure that security is configured to consume tokens with the name, namespace and value type specified."); }
        }
        internal static string ExpectedElementMissing {
              get { return SR.GetResourceString("ExpectedElementMissing", @"Element '{0}' with namespace '{1}' not found."); }
        }
        internal static string ExpectedOneOfTwoElementsFromNamespace {
              get { return SR.GetResourceString("ExpectedOneOfTwoElementsFromNamespace", @"Expected element '{0}' or element '{1}' (from namespace '{2}')."); }
        }
        internal static string RstDirectDoesNotExpectRstr {
              get { return SR.GetResourceString("RstDirectDoesNotExpectRstr", @"AcceleratedTokenAuthenticator does not expect RequestSecurityTokenResponse from the client."); }
        }
        internal static string RequireNonCookieMode {
              get { return SR.GetResourceString("RequireNonCookieMode", @"The '{0}' binding with the '{1}' namespace is configured to issue cookie security context tokens. COM+ Integration services does not support cookie security context tokens."); }
        }
        internal static string RequiredSignatureMissing {
              get { return SR.GetResourceString("RequiredSignatureMissing", @"The signature must be in the security header."); }
        }
        internal static string RequiredMessagePartNotSigned {
              get { return SR.GetResourceString("RequiredMessagePartNotSigned", @"The '{0}' required message part was not signed."); }
        }
        internal static string RequiredMessagePartNotSignedNs {
              get { return SR.GetResourceString("RequiredMessagePartNotSignedNs", @"The '{0}', '{1}' required message part  was not signed."); }
        }
        internal static string RequiredMessagePartNotEncrypted {
              get { return SR.GetResourceString("RequiredMessagePartNotEncrypted", @"The '{0}' required message part was not encrypted."); }
        }
        internal static string RequiredMessagePartNotEncryptedNs {
              get { return SR.GetResourceString("RequiredMessagePartNotEncryptedNs", @"The '{0}', '{1}' required message part  was not encrypted."); }
        }
        internal static string SignatureVerificationFailed {
              get { return SR.GetResourceString("SignatureVerificationFailed", @"Signature verification failed."); }
        }
        internal static string CannotIssueRstTokenType {
              get { return SR.GetResourceString("CannotIssueRstTokenType", @"Cannot issue the token type '{0}'."); }
        }
        internal static string NoNegotiationMessageToSend {
              get { return SR.GetResourceString("NoNegotiationMessageToSend", @"There is no negotiation message to send."); }
        }
        internal static string InvalidIssuedTokenKeySize {
              get { return SR.GetResourceString("InvalidIssuedTokenKeySize", @"The issued token has an invalid key size '{0}'."); }
        }
        internal static string CannotObtainIssuedTokenKeySize {
              get { return SR.GetResourceString("CannotObtainIssuedTokenKeySize", @"Cannot determine the key size of the issued token."); }
        }
        internal static string NegotiationIsNotCompleted {
              get { return SR.GetResourceString("NegotiationIsNotCompleted", @"The negotiation has not yet completed."); }
        }
        internal static string NegotiationIsCompleted {
              get { return SR.GetResourceString("NegotiationIsCompleted", @"The negotiation has already completed."); }
        }
        internal static string MissingMessageID {
              get { return SR.GetResourceString("MissingMessageID", @"Request Message is missing a MessageID header. One is required to correlate a reply."); }
        }
        internal static string SecuritySessionLimitReached {
              get { return SR.GetResourceString("SecuritySessionLimitReached", @"Cannot create a security session. Retry later."); }
        }
        internal static string SecuritySessionAlreadyPending {
              get { return SR.GetResourceString("SecuritySessionAlreadyPending", @"The security session with id '{0}' is already pending."); }
        }
        internal static string SecuritySessionNotPending {
              get { return SR.GetResourceString("SecuritySessionNotPending", @"No security session with id '{0}' is pending."); }
        }
        internal static string SecuritySessionListenerNotFound {
              get { return SR.GetResourceString("SecuritySessionListenerNotFound", @"No security session listener was found for message with action '{0}'."); }
        }
        internal static string SessionTokenWasNotClosed {
              get { return SR.GetResourceString("SessionTokenWasNotClosed", @"The session token was not closed by the server."); }
        }
        internal static string ProtocolMustBeInitiator {
              get { return SR.GetResourceString("ProtocolMustBeInitiator", @"'{0}' protocol can only be used by the Initiator."); }
        }
        internal static string ProtocolMustBeRecipient {
              get { return SR.GetResourceString("ProtocolMustBeRecipient", @"'{0}' protocol can only be used at the Recipient."); }
        }
        internal static string SendingOutgoingmessageOnRecipient {
              get { return SR.GetResourceString("SendingOutgoingmessageOnRecipient", @"Unexpected code path for server security application, sending outgoing message on Recipient."); }
        }
        internal static string OnlyBodyReturnValuesSupported {
              get { return SR.GetResourceString("OnlyBodyReturnValuesSupported", @"Only body return values are supported currently for protection, MessagePartDescription was specified."); }
        }
        internal static string UnknownTokenAttachmentMode {
              get { return SR.GetResourceString("UnknownTokenAttachmentMode", @"Unknown token attachment mode: {0}."); }
        }
        internal static string ProtocolMisMatch {
              get { return SR.GetResourceString("ProtocolMisMatch", @"Security protocol must be '{0}', type is: '{1}'.;"); }
        }
        internal static string AttemptToCreateMultipleRequestContext {
              get { return SR.GetResourceString("AttemptToCreateMultipleRequestContext", @"The initial request context was already specified.  Can not create two for same message."); }
        }
        internal static string ServerReceivedCloseMessageStateIsCreated {
              get { return SR.GetResourceString("ServerReceivedCloseMessageStateIsCreated", @"{0}.OnCloseMessageReceived when state == Created."); }
        }
        internal static string ShutdownRequestWasNotReceived {
              get { return SR.GetResourceString("ShutdownRequestWasNotReceived", @"Shutdown request was not received."); }
        }
        internal static string UnknownFilterType {
              get { return SR.GetResourceString("UnknownFilterType", @"Unknown filter type: '{0}'."); }
        }
        internal static string StandardsManagerDoesNotMatch {
              get { return SR.GetResourceString("StandardsManagerDoesNotMatch", @"Standards manager of filter does not match that of filter table.  Can not have two different filters."); }
        }
        internal static string FilterStrictModeDifferent {
              get { return SR.GetResourceString("FilterStrictModeDifferent", @"Session filter's isStrictMode differs from filter table's isStrictMode."); }
        }
        internal static string SSSSCreateAcceptor {
              get { return SR.GetResourceString("SSSSCreateAcceptor", @"SecuritySessionServerSettings.CreateAcceptor, channelAcceptor must be null, can not create twice."); }
        }
        internal static string TransactionFlowBadOption {
              get { return SR.GetResourceString("TransactionFlowBadOption", @"Invalid TransactionFlowOption value."); }
        }
        internal static string TokenManagerCouldNotReadToken {
              get { return SR.GetResourceString("TokenManagerCouldNotReadToken", @"Security token manager could not parse token with name '{0}', namespace '{1}', valueType '{2}'."); }
        }
        internal static string InvalidActionForNegotiationMessage {
              get { return SR.GetResourceString("InvalidActionForNegotiationMessage", @"Security negotiation message has incorrect action '{0}'."); }
        }
        internal static string InvalidKeySizeSpecifiedInNegotiation {
              get { return SR.GetResourceString("InvalidKeySizeSpecifiedInNegotiation", @"The specified key size {0} is invalid. The key size must be between {1} and {2}."); }
        }
        internal static string GetTokenInfoFailed {
              get { return SR.GetResourceString("GetTokenInfoFailed", @"Could not get token information (error=0x{0:X})."); }
        }
        internal static string UnexpectedEndOfFile {
              get { return SR.GetResourceString("UnexpectedEndOfFile", @"Unexpected end of file."); }
        }
        internal static string TimeStampHasCreationAheadOfExpiry {
              get { return SR.GetResourceString("TimeStampHasCreationAheadOfExpiry", @"The security timestamp is invalid because its creation time ('{0}') is greater than or equal to its expiration time ('{1}')."); }
        }
        internal static string TimeStampHasExpiryTimeInPast {
              get { return SR.GetResourceString("TimeStampHasExpiryTimeInPast", @"The security timestamp is stale because its expiration time ('{0}') is in the past. Current time is '{1}' and allowed clock skew is '{2}'."); }
        }
        internal static string TimeStampHasCreationTimeInFuture {
              get { return SR.GetResourceString("TimeStampHasCreationTimeInFuture", @"The security timestamp is invalid because its creation time ('{0}') is in the future. Current time is '{1}' and allowed clock skew is '{2}'."); }
        }
        internal static string TimeStampWasCreatedTooLongAgo {
              get { return SR.GetResourceString("TimeStampWasCreatedTooLongAgo", @"The security timestamp is stale because its creation time ('{0}') is too far back in the past. Current time is '{1}', maximum timestamp lifetime is '{2}' and allowed clock skew is '{3}'."); }
        }
        internal static string InvalidOrReplayedNonce {
              get { return SR.GetResourceString("InvalidOrReplayedNonce", @"The nonce is invalid or replayed."); }
        }
        internal static string MessagePartSpecificationMustBeImmutable {
              get { return SR.GetResourceString("MessagePartSpecificationMustBeImmutable", @"Message part specification must be made constant before being set."); }
        }
        internal static string UnsupportedIssuerEntropyType {
              get { return SR.GetResourceString("UnsupportedIssuerEntropyType", @"Issuer entropy is not BinarySecretSecurityToken or WrappedKeySecurityToken."); }
        }
        internal static string NoRequestSecurityTokenResponseElements {
              get { return SR.GetResourceString("NoRequestSecurityTokenResponseElements", @"No RequestSecurityTokenResponse elements were found."); }
        }
        internal static string NoCookieInSct {
              get { return SR.GetResourceString("NoCookieInSct", @"The SecurityContextSecurityToken does not have a cookie."); }
        }
        internal static string TokenProviderReturnedBadToken {
              get { return SR.GetResourceString("TokenProviderReturnedBadToken", @"TokenProvider returned token of incorrect type '{0}'."); }
        }
        internal static string ItemNotAvailableInDeserializedRST {
              get { return SR.GetResourceString("ItemNotAvailableInDeserializedRST", @"{0} is not available in deserialized RequestSecurityToken."); }
        }
        internal static string ItemAvailableInDeserializedRSTOnly {
              get { return SR.GetResourceString("ItemAvailableInDeserializedRSTOnly", @"{0} is only available in a deserialized RequestSecurityToken."); }
        }
        internal static string ItemNotAvailableInDeserializedRSTR {
              get { return SR.GetResourceString("ItemNotAvailableInDeserializedRSTR", @"{0} is not available in deserialized RequestSecurityTokenResponse."); }
        }
        internal static string ItemAvailableInDeserializedRSTROnly {
              get { return SR.GetResourceString("ItemAvailableInDeserializedRSTROnly", @"{0} is only available in a deserialized RequestSecurityTokenResponse."); }
        }
        internal static string MoreThanOneRSTRInRSTRC {
              get { return SR.GetResourceString("MoreThanOneRSTRInRSTRC", @"The RequestSecurityTokenResponseCollection received has more than one RequestSecurityTokenResponse element. Only one RequestSecurityTokenResponse element was expected."); }
        }
        internal static string Hosting_VirtualPathExtenstionCanNotBeDetached {
              get { return SR.GetResourceString("Hosting_VirtualPathExtenstionCanNotBeDetached", @"VirtualPathExtension is not allowed to be removed."); }
        }
        internal static string Hosting_NotSupportedProtocol {
              get { return SR.GetResourceString("Hosting_NotSupportedProtocol", @"The protocol '{0}' is not supported."); }
        }
        internal static string Hosting_BaseUriDeserializedNotValid {
              get { return SR.GetResourceString("Hosting_BaseUriDeserializedNotValid", @"The BaseUriWithWildcard object has invalid fields after deserialization."); }
        }
        internal static string Hosting_RelativeAddressFormatError {
              get { return SR.GetResourceString("Hosting_RelativeAddressFormatError", @"Registered relativeAddress '{0}' in configuration file is not a valid one. Possible causes could be : You specified an empty addreess or an absolute address (i.e., starting with '/' or '\\'), or the address contains invalid character[s]. The supported relativeAddress formats are \""[folder/]filename\"" or \""~/[folder/]filename\"".  "); }
        }
        internal static string Hosting_NoAbsoluteRelativeAddress {
              get { return SR.GetResourceString("Hosting_NoAbsoluteRelativeAddress", @" '{0}' is an absolute address. The supported relativeAddress formats are \""[subfolder/]filename\"" or \""~/[subfolder/]filename\"".  "); }
        }
        internal static string SecureConversationNeedsBootstrapSecurity {
              get { return SR.GetResourceString("SecureConversationNeedsBootstrapSecurity", @"Cannot create security binding element based on the configuration data. When secure conversation authentication mode is selected, the secure conversation bootstrap binding element must also be specified. "); }
        }
        internal static string Hosting_MemoryGatesCheckFailedUnderPartialTrust {
              get { return SR.GetResourceString("Hosting_MemoryGatesCheckFailedUnderPartialTrust", @"Setting minFreeMemoryPercentageToActivateService requires full trust privilege. Please change the application's trust level or remove this setting from the configuration file."); }
        }
        internal static string Hosting_CompatibilityServiceNotHosted {
              get { return SR.GetResourceString("Hosting_CompatibilityServiceNotHosted", @"This service requires ASP.NET compatibility and must be hosted in IIS.  Either host the service in IIS with ASP.NET compatibility turned on in web.config or set the AspNetCompatibilityRequirementsAttribute.AspNetCompatibilityRequirementsMode property to a value other than Required."); }
        }
        internal static string Hosting_MisformattedPort {
              get { return SR.GetResourceString("Hosting_MisformattedPort", @"The '{0}' protocol binding '{1}' specifies an invalid port number '{2}'."); }
        }
        internal static string Hosting_MisformattedBinding {
              get { return SR.GetResourceString("Hosting_MisformattedBinding", @"The protocol binding '{0}' does not conform to the syntax for '{1}'. The following is an example of valid '{1}' protocol bindings: '{2}'."); }
        }
        internal static string Hosting_MisformattedBindingData {
              get { return SR.GetResourceString("Hosting_MisformattedBindingData", @"The protocol binding '{0}' is not valid for '{1}'.  This might be because the port number is out of range."); }
        }
        internal static string Hosting_NoHttpTransportManagerForUri {
              get { return SR.GetResourceString("Hosting_NoHttpTransportManagerForUri", @"There is no compatible TransportManager found for URI '{0}'. This may be because you have used an absolute address that points outside of the virtual application. Please use a relative address instead."); }
        }
        internal static string Hosting_NoTcpPipeTransportManagerForUri {
              get { return SR.GetResourceString("Hosting_NoTcpPipeTransportManagerForUri", @"There is no compatible TransportManager found for URI '{0}'. This may be because you have used an absolute address that points outside of the virtual application, or the binding settings of the endpoint do not match those that have been set by other services or endpoints. Note that all bindings for the same protocol should have the same settings in the same application."); }
        }
        internal static string Hosting_ProcessNotExecutingUnderHostedContext {
              get { return SR.GetResourceString("Hosting_ProcessNotExecutingUnderHostedContext", @"'{0}' cannot be invoked within the current hosting environment. This API requires that the calling application be hosted in IIS or WAS."); }
        }
        internal static string Hosting_ServiceActivationFailed {
              get { return SR.GetResourceString("Hosting_ServiceActivationFailed", @"The requested service, '{0}' could not be activated. See the server's diagnostic trace logs for more information."); }
        }
        internal static string Hosting_ServiceTypeNotProvided {
              get { return SR.GetResourceString("Hosting_ServiceTypeNotProvided", @"The value for the Service attribute was not provided in the ServiceHost directive."); }
        }
        internal static string SharedEndpointReadDenied {
              get { return SR.GetResourceString("SharedEndpointReadDenied", @"The service endpoint failed to listen on the URI '{0}' because access was denied.  Verify that the current user is granted access in the appropriate allowAccounts section of SMSvcHost.exe.config."); }
        }
        internal static string SharedEndpointReadNotFound {
              get { return SR.GetResourceString("SharedEndpointReadNotFound", @"The service endpoint failed to listen on the URI '{0}' because the shared memory section was not found.  Verify that the '{1}' service is running."); }
        }
        internal static string SharedManagerBase {
              get { return SR.GetResourceString("SharedManagerBase", @"The TransportManager failed to listen on the supplied URI using the {0} service: {1}."); }
        }
        internal static string SharedManagerServiceStartFailure {
              get { return SR.GetResourceString("SharedManagerServiceStartFailure", @"failed to start the service ({0}). Refer to the Event Log for more details"); }
        }
        internal static string SharedManagerServiceStartFailureDisabled {
              get { return SR.GetResourceString("SharedManagerServiceStartFailureDisabled", @"failed to start the service because it is disabled. An administrator can enable it by running 'sc.exe config {0} start= demand'."); }
        }
        internal static string SharedManagerServiceStartFailureNoError {
              get { return SR.GetResourceString("SharedManagerServiceStartFailureNoError", @"failed to start the service. Refer to the Event Log for more details"); }
        }
        internal static string SharedManagerServiceLookupFailure {
              get { return SR.GetResourceString("SharedManagerServiceLookupFailure", @"failed to look up the service process in the SCM ({0})"); }
        }
        internal static string SharedManagerServiceSidLookupFailure {
              get { return SR.GetResourceString("SharedManagerServiceSidLookupFailure", @"failed to look up the service SID in the SCM ({0})"); }
        }
        internal static string SharedManagerServiceEndpointReadFailure {
              get { return SR.GetResourceString("SharedManagerServiceEndpointReadFailure", @"failed to read the service's endpoint with native error code {0}.  See inner exception for details"); }
        }
        internal static string SharedManagerServiceSecurityFailed {
              get { return SR.GetResourceString("SharedManagerServiceSecurityFailed", @"the service failed the security checks"); }
        }
        internal static string SharedManagerUserSidLookupFailure {
              get { return SR.GetResourceString("SharedManagerUserSidLookupFailure", @"failed to retrieve the UserSid of the service process ({0})"); }
        }
        internal static string SharedManagerCurrentUserSidLookupFailure {
              get { return SR.GetResourceString("SharedManagerCurrentUserSidLookupFailure", @"failed to retrieve the UserSid of the current process"); }
        }
        internal static string SharedManagerLogonSidLookupFailure {
              get { return SR.GetResourceString("SharedManagerLogonSidLookupFailure", @"failed to retrieve the LogonSid of the service process ({0})"); }
        }
        internal static string SharedManagerDataConnectionFailure {
              get { return SR.GetResourceString("SharedManagerDataConnectionFailure", @"failed to establish a data connection to the service"); }
        }
        internal static string SharedManagerDataConnectionCreateFailure {
              get { return SR.GetResourceString("SharedManagerDataConnectionCreateFailure", @"failed to create a data connection to the service"); }
        }
        internal static string SharedManagerDataConnectionPipeFailed {
              get { return SR.GetResourceString("SharedManagerDataConnectionPipeFailed", @"failed to establish the data connection because of an I/O error"); }
        }
        internal static string SharedManagerVersionUnsupported {
              get { return SR.GetResourceString("SharedManagerVersionUnsupported", @"the version is not supported by the service"); }
        }
        internal static string SharedManagerAllowDupHandleFailed {
              get { return SR.GetResourceString("SharedManagerAllowDupHandleFailed", @"failed to grant the PROCESS_DUP_HANDLE access right to the target service's account SID '{0}'."); }
        }
        internal static string SharedManagerPathTooLong {
              get { return SR.GetResourceString("SharedManagerPathTooLong", @"the URI is too long"); }
        }
        internal static string SharedManagerRegistrationQuotaExceeded {
              get { return SR.GetResourceString("SharedManagerRegistrationQuotaExceeded", @"the quota was exceeded"); }
        }
        internal static string SharedManagerProtocolUnsupported {
              get { return SR.GetResourceString("SharedManagerProtocolUnsupported", @"the protocol is not supported"); }
        }
        internal static string SharedManagerConflictingRegistration {
              get { return SR.GetResourceString("SharedManagerConflictingRegistration", @"the URI is already registered with the service"); }
        }
        internal static string SharedManagerFailedToListen {
              get { return SR.GetResourceString("SharedManagerFailedToListen", @"the service failed to listen"); }
        }
        internal static string Sharing_ConnectionDispatchFailed {
              get { return SR.GetResourceString("Sharing_ConnectionDispatchFailed", @"The message could not be dispatched to the service at address '{0}'. Refer to the server Event Log for more details"); }
        }
        internal static string Sharing_EndpointUnavailable {
              get { return SR.GetResourceString("Sharing_EndpointUnavailable", @"The message could not be dispatched because the service at the endpoint address '{0}' is unavailable for the protocol of the address."); }
        }
        internal static string Sharing_EmptyListenerEndpoint {
              get { return SR.GetResourceString("Sharing_EmptyListenerEndpoint", @"The endpoint address for the NT service '{0}' read from shared memory is empty."); }
        }
        internal static string Sharing_ListenerProxyStopped {
              get { return SR.GetResourceString("Sharing_ListenerProxyStopped", @"The message could not be dispatched because the transport manager has been stopped.  This can happen if the application is being recycled or disabled."); }
        }
        internal static string UnexpectedEmptyElementExpectingClaim {
              get { return SR.GetResourceString("UnexpectedEmptyElementExpectingClaim", @"The '{0}' from the '{1}' namespace is empty and does not specify a valid identity claim. "); }
        }
        internal static string UnexpectedElementExpectingElement {
              get { return SR.GetResourceString("UnexpectedElementExpectingElement", @"'{0}' from namespace '{1}' is not expected. Expecting element '{2}' from namespace '{3}'"); }
        }
        internal static string UnexpectedDuplicateElement {
              get { return SR.GetResourceString("UnexpectedDuplicateElement", @"'{0}' from namespace '{1}' is not expected to appear more than once"); }
        }
        internal static string UnsupportedSecurityPolicyAssertion {
              get { return SR.GetResourceString("UnsupportedSecurityPolicyAssertion", @"An unsupported security policy assertion was detected during the security policy import: {0}"); }
        }
        internal static string MultipleIdentities {
              get { return SR.GetResourceString("MultipleIdentities", @"The extensions cannot contain an Identity if one is supplied as a constructor argument."); }
        }
        internal static string InvalidUriValue {
              get { return SR.GetResourceString("InvalidUriValue", @"Value '{0}' provided for '{1}' from namespace '{2}' is an invalid absolute URI."); }
        }
        internal static string BindingDoesNotSupportProtectionForRst {
              get { return SR.GetResourceString("BindingDoesNotSupportProtectionForRst", @"The binding ('{0}','{1}') for contract ('{2}','{3}') is configured with SecureConversation, but the authentication mode is not able to provide the request/reply-based integrity and confidentiality required for the negotiation."); }
        }
        internal static string TransportDoesNotProtectMessage {
              get { return SR.GetResourceString("TransportDoesNotProtectMessage", @"The '{0}'.'{1}' binding for the '{2}'.'{3}' contract is configured with an authentication mode that requires transport level integrity and confidentiality. However the transport cannot provide integrity and confidentiality."); }
        }
        internal static string BindingDoesNotSupportWindowsIdenityForImpersonation {
              get { return SR.GetResourceString("BindingDoesNotSupportWindowsIdenityForImpersonation", @"The contract operation '{0}' requires Windows identity for automatic impersonation. A Windows identity that represents the caller is not provided by binding ('{1}','{2}') for contract ('{3}','{4}'."); }
        }
        internal static string ListenUriNotSet {
              get { return SR.GetResourceString("ListenUriNotSet", @"A listen URI must be specified in order to open this {0}."); }
        }
        internal static string UnsupportedChannelInterfaceType {
              get { return SR.GetResourceString("UnsupportedChannelInterfaceType", @"Channel interface type '{0}' is not supported."); }
        }
        internal static string TransportManagerOpen {
              get { return SR.GetResourceString("TransportManagerOpen", @"This property cannot be changed after the transport manager has been opened."); }
        }
        internal static string TransportManagerNotOpen {
              get { return SR.GetResourceString("TransportManagerNotOpen", @"This operation is only valid after the transport manager has been opened."); }
        }
        internal static string UnrecognizedIdentityType {
              get { return SR.GetResourceString("UnrecognizedIdentityType", @"Unrecognized identity type Name='{0}', Namespace='{1}'."); }
        }
        internal static string InvalidIdentityElement {
              get { return SR.GetResourceString("InvalidIdentityElement", @"Cannot read the Identity element. The Identity type is not supported or the Identity element is empty."); }
        }
        internal static string UnableToLoadCertificateIdentity {
              get { return SR.GetResourceString("UnableToLoadCertificateIdentity", @"Cannot load the X.509 certificate identity specified in the configuration."); }
        }
        internal static string UnrecognizedClaimTypeForIdentity {
              get { return SR.GetResourceString("UnrecognizedClaimTypeForIdentity", @"The ClaimType '{0}' is not recognized. Expected ClaimType '{1}'."); }
        }
        internal static string AsyncCallbackException {
              get { return SR.GetResourceString("AsyncCallbackException", @"An AsyncCallback threw an exception."); }
        }
        internal static string SendCannotBeCalledAfterCloseOutputSession {
              get { return SR.GetResourceString("SendCannotBeCalledAfterCloseOutputSession", @"You cannot Send messages on a channel after CloseOutputSession has been called."); }
        }
        internal static string CommunicationObjectCannotBeModifiedInState {
              get { return SR.GetResourceString("CommunicationObjectCannotBeModifiedInState", @"The communication object, {0}, cannot be modified while it is in the {1} state."); }
        }
        internal static string CommunicationObjectCannotBeModified {
              get { return SR.GetResourceString("CommunicationObjectCannotBeModified", @"The communication object, {0}, cannot be modified unless it is in the Created state."); }
        }
        internal static string CommunicationObjectCannotBeUsed {
              get { return SR.GetResourceString("CommunicationObjectCannotBeUsed", @"The communication object, {0}, is in the {1} state.  Communication objects cannot be used for communication unless they are in the Opened state."); }
        }
        internal static string CommunicationObjectFaulted1 {
              get { return SR.GetResourceString("CommunicationObjectFaulted1", @"The communication object, {0}, cannot be used for communication because it is in the Faulted state."); }
        }
        internal static string CommunicationObjectFaultedStack2 {
              get { return SR.GetResourceString("CommunicationObjectFaultedStack2", @"The communication object, {0}, cannot be used for communication because it is in the Faulted state: {1}"); }
        }
        internal static string CommunicationObjectAborted1 {
              get { return SR.GetResourceString("CommunicationObjectAborted1", @"The communication object, {0}, cannot be used for communication because it has been Aborted."); }
        }
        internal static string CommunicationObjectAbortedStack2 {
              get { return SR.GetResourceString("CommunicationObjectAbortedStack2", @"The communication object, {0}, cannot be used for communication because it has been Aborted: {1}"); }
        }
        internal static string CommunicationObjectBaseClassMethodNotCalled {
              get { return SR.GetResourceString("CommunicationObjectBaseClassMethodNotCalled", @"The communication object, {0}, has overridden the virtual function {1} but it does not call version defined in the base class."); }
        }
        internal static string CommunicationObjectInInvalidState {
              get { return SR.GetResourceString("CommunicationObjectInInvalidState", @"The communication object, {0}, is not part of WCF and is in an unsupported state '{1}'.  This indicates an internal error in the implementation of that communication object."); }
        }
        internal static string CommunicationObjectCloseInterrupted1 {
              get { return SR.GetResourceString("CommunicationObjectCloseInterrupted1", @"The communication object, {0}, cannot be used due to an error that occurred during close."); }
        }
        internal static string ChannelFactoryCannotBeUsedToCreateChannels {
              get { return SR.GetResourceString("ChannelFactoryCannotBeUsedToCreateChannels", @"A call to IChannelFactory.CreateChannel made on an object of type {0} failed because Open has not been called on this object."); }
        }
        internal static string ChannelParametersCannotBeModified {
              get { return SR.GetResourceString("ChannelParametersCannotBeModified", @"Cannot modify channel parameters because the {0} is in the {1} state.  This operation is only supported in the Created state."); }
        }
        internal static string ChannelParametersCannotBePropagated {
              get { return SR.GetResourceString("ChannelParametersCannotBePropagated", @"Cannot propagate channel parameters because the {0} is in the {1} state.  This operation is only supported in the Opening or Opened state when the collection is locked."); }
        }
        internal static string OneWayInternalTypeNotSupported {
              get { return SR.GetResourceString("OneWayInternalTypeNotSupported", @"Binding '{0}' is not configured properly. OneWayBindingElement requires an inner binding element that supports IRequestChannel/IReplyChannel or IDuplexSessionChannel. "); }
        }
        internal static string ChannelTypeNotSupported {
              get { return SR.GetResourceString("ChannelTypeNotSupported", @"The specified channel type {0} is not supported by this channel manager."); }
        }
        internal static string SecurityContextMissing {
              get { return SR.GetResourceString("SecurityContextMissing", @"SecurityContext for the UltimateReceiver role is missing from the SecurityContextProperty of the request message with action '{0}'."); }
        }
        internal static string SecurityContextDoesNotAllowImpersonation {
              get { return SR.GetResourceString("SecurityContextDoesNotAllowImpersonation", @"Cannot start impersonation because the SecurityContext for the UltimateReceiver role from the request message with the '{0}' action is not mapped to a Windows identity."); }
        }
        internal static string InvalidEnumValue {
              get { return SR.GetResourceString("InvalidEnumValue", @"Unexpected internal enum value: {0}."); }
        }
        internal static string InvalidDecoderStateMachine {
              get { return SR.GetResourceString("InvalidDecoderStateMachine", @"Invalid decoder state machine."); }
        }
        internal static string OperationPropertyIsRequiredForAttributeGeneration {
              get { return SR.GetResourceString("OperationPropertyIsRequiredForAttributeGeneration", @"Operation property of OperationAttributeGenerationContext is required to generate an attribute based on settings. "); }
        }
        internal static string InvalidMembershipProviderSpecifiedInConfig {
              get { return SR.GetResourceString("InvalidMembershipProviderSpecifiedInConfig", @"The username/password Membership provider {0} specified in the configuration is invalid. No such provider was found registered under system.web/membership/providers."); }
        }
        internal static string InvalidRoleProviderSpecifiedInConfig {
              get { return SR.GetResourceString("InvalidRoleProviderSpecifiedInConfig", @"The RoleProvider {0} specified in the configuration is invalid. No such provider was found registered under system.web/roleManager/providers."); }
        }
        internal static string ObjectDisposed {
              get { return SR.GetResourceString("ObjectDisposed", @"The {0} object has been disposed."); }
        }
        internal static string InvalidReaderPositionOnCreateMessage {
              get { return SR.GetResourceString("InvalidReaderPositionOnCreateMessage", @"The XmlReader used for the body of the message must be positioned on an element."); }
        }
        internal static string DuplicateMessageProperty {
              get { return SR.GetResourceString("DuplicateMessageProperty", @"A property with the name '{0}' already exists."); }
        }
        internal static string MessagePropertyNotFound {
              get { return SR.GetResourceString("MessagePropertyNotFound", @"A property with the name '{0}' is not present."); }
        }
        internal static string HeaderAlreadyUnderstood {
              get { return SR.GetResourceString("HeaderAlreadyUnderstood", @"The message header with name '{0}' and namespace '{1}' is already present in the set of understood headers."); }
        }
        internal static string HeaderAlreadyNotUnderstood {
              get { return SR.GetResourceString("HeaderAlreadyNotUnderstood", @"The message header with name '{0}' and namespace '{1}' is not present in the set of understood headers."); }
        }
        internal static string MultipleMessageHeaders {
              get { return SR.GetResourceString("MultipleMessageHeaders", @"Multiple headers with name '{0}' and namespace '{1}' found."); }
        }
        internal static string MultipleMessageHeadersWithActor {
              get { return SR.GetResourceString("MultipleMessageHeadersWithActor", @"Multiple headers with name '{0}' and namespace '{1}' and role '{2}' found."); }
        }
        internal static string MultipleRelatesToHeaders {
              get { return SR.GetResourceString("MultipleRelatesToHeaders", @" Multiple RelatesTo headers with relationship '{0}' found.  Only one is allowed per relationship."); }
        }
        internal static string ExtraContentIsPresentInFaultDetail {
              get { return SR.GetResourceString("ExtraContentIsPresentInFaultDetail", @"Additional XML content is present in the fault detail element. Only a single element is allowed."); }
        }
        internal static string MessageIsEmpty {
              get { return SR.GetResourceString("MessageIsEmpty", @"The body of the message cannot be read because it is empty."); }
        }
        internal static string MessageClosed {
              get { return SR.GetResourceString("MessageClosed", @"Message is closed."); }
        }
        internal static string StreamClosed {
              get { return SR.GetResourceString("StreamClosed", @"The operation cannot be completed because the stream is closed."); }
        }
        internal static string BodyWriterReturnedIsNotBuffered {
              get { return SR.GetResourceString("BodyWriterReturnedIsNotBuffered", @"The body writer returned from OnCreateBufferedCopy was not buffered."); }
        }
        internal static string BodyWriterCanOnlyBeWrittenOnce {
              get { return SR.GetResourceString("BodyWriterCanOnlyBeWrittenOnce", @"The body writer does not support writing more than once because it is not buffered."); }
        }
        internal static string RstrKeySizeNotProvided {
              get { return SR.GetResourceString("RstrKeySizeNotProvided", @"KeySize element not present in RequestSecurityTokenResponse."); }
        }
        internal static string RequestMessageDoesNotHaveAMessageID {
              get { return SR.GetResourceString("RequestMessageDoesNotHaveAMessageID", @"A reply message cannot be created because the request message does not have a MessageID."); }
        }
        internal static string HeaderNotFound {
              get { return SR.GetResourceString("HeaderNotFound", @"There is not a header with name {0} and namespace {1} in the message."); }
        }
        internal static string MessageBufferIsClosed {
              get { return SR.GetResourceString("MessageBufferIsClosed", @"MessageBuffer is closed."); }
        }
        internal static string MessageTextEncodingNotSupported {
              get { return SR.GetResourceString("MessageTextEncodingNotSupported", @"The text encoding '{0}' used in the text message format is not supported."); }
        }
        internal static string AtLeastOneFaultReasonMustBeSpecified {
              get { return SR.GetResourceString("AtLeastOneFaultReasonMustBeSpecified", @"At least one fault reason must be specified."); }
        }
        internal static string NoNullTranslations {
              get { return SR.GetResourceString("NoNullTranslations", @"The translation set cannot contain nulls."); }
        }
        internal static string FaultDoesNotHaveAnyDetail {
              get { return SR.GetResourceString("FaultDoesNotHaveAnyDetail", @"The fault does not have detail information."); }
        }
        internal static string InvalidXmlQualifiedName {
              get { return SR.GetResourceString("InvalidXmlQualifiedName", @"Expected XML qualified name, found '{0}'."); }
        }
        internal static string UnboundPrefixInQName {
              get { return SR.GetResourceString("UnboundPrefixInQName", @"Unbound prefix used in qualified name '{0}'."); }
        }
        internal static string MessageBodyIsUnknown {
              get { return SR.GetResourceString("MessageBodyIsUnknown", @"..."); }
        }
        internal static string MessageBodyIsStream {
              get { return SR.GetResourceString("MessageBodyIsStream", @"... stream ..."); }
        }
        internal static string MessageBodyToStringError {
              get { return SR.GetResourceString("MessageBodyToStringError", @"... Error reading body: {0}: {1} ..."); }
        }
        internal static string NoMatchingTranslationFoundForFaultText {
              get { return SR.GetResourceString("NoMatchingTranslationFoundForFaultText", @"The fault reason does not contain any text translations."); }
        }
        internal static string CannotDetermineSPNBasedOnAddress {
              get { return SR.GetResourceString("CannotDetermineSPNBasedOnAddress", @"Client cannot determine the Service Principal Name based on the identity in the target address '{0}' for the purpose of SspiNegotiation/Kerberos. The target address identity must be a UPN identity (like acmedomain\\alice) or SPN identity (like host/bobs-machine)."); }
        }
        internal static string XmlLangAttributeMissing {
              get { return SR.GetResourceString("XmlLangAttributeMissing", @"Required xml:lang attribute value is missing."); }
        }
        internal static string EncoderUnrecognizedCharSet {
              get { return SR.GetResourceString("EncoderUnrecognizedCharSet", @"Unrecognized charSet '{0}' in contentType."); }
        }
        internal static string EncoderUnrecognizedContentType {
              get { return SR.GetResourceString("EncoderUnrecognizedContentType", @"Unrecognized contentType ({0}). Expected: {1}."); }
        }
        internal static string EncoderBadContentType {
              get { return SR.GetResourceString("EncoderBadContentType", @"Cannot process contentType."); }
        }
        internal static string EncoderEnvelopeVersionMismatch {
              get { return SR.GetResourceString("EncoderEnvelopeVersionMismatch", @"The envelope version of the incoming message ({0}) does not match that of the encoder ({1}). Make sure the binding is configured with the same version as the expected messages."); }
        }
        internal static string EncoderMessageVersionMismatch {
              get { return SR.GetResourceString("EncoderMessageVersionMismatch", @"The message version of the outgoing message ({0}) does not match that of the encoder ({1}). Make sure the binding is configured with the same version as the message."); }
        }
        internal static string MtomEncoderBadMessageVersion {
              get { return SR.GetResourceString("MtomEncoderBadMessageVersion", @"MessageVersion '{0}' not supported by MTOM encoder."); }
        }
        internal static string SPS_ReadNotSupported {
              get { return SR.GetResourceString("SPS_ReadNotSupported", @"Read is not supported on this stream."); }
        }
        internal static string SPS_SeekNotSupported {
              get { return SR.GetResourceString("SPS_SeekNotSupported", @"Seek is not supported on this stream."); }
        }
        internal static string WriterAsyncWritePending {
              get { return SR.GetResourceString("WriterAsyncWritePending", @"An asynchronous write is pending on the stream. Ensure that there are no uncompleted asynchronous writes before attempting the next write. "); }
        }
        internal static string ChannelInitializationTimeout {
              get { return SR.GetResourceString("ChannelInitializationTimeout", @"A newly accepted connection did not receive initialization data from the sender within the configured ChannelInitializationTimeout ({0}).  As a result, the connection will be aborted.  If you are on a highly congested network, or your sending machine is heavily loaded, consider increasing this value or load-balancing your server."); }
        }
        internal static string SocketCloseReadTimeout {
              get { return SR.GetResourceString("SocketCloseReadTimeout", @"The remote endpoint of the socket ({0}) did not respond to a close request within the allotted timeout ({1}). It is likely that the remote endpoint is not calling Close after receiving the EOF signal (null) from Receive. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string SocketCloseReadReceivedData {
              get { return SR.GetResourceString("SocketCloseReadReceivedData", @"A graceful close was attempted on the socket, but the other side ({0}) is still sending data."); }
        }
        internal static string SessionValueInvalid {
              get { return SR.GetResourceString("SessionValueInvalid", @"The Session value '{0}' is invalid. Please specify 'CurrentSession','ServiceSession' or a valid non-negative Windows Session Id."); }
        }
        internal static string PackageFullNameInvalid {
              get { return SR.GetResourceString("PackageFullNameInvalid", @"The package full name '{0}' is invalid."); }
        }
        internal static string SocketAbortedReceiveTimedOut {
              get { return SR.GetResourceString("SocketAbortedReceiveTimedOut", @"The socket was aborted because an asynchronous receive from the socket did not complete within the allotted timeout of {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string SocketAbortedSendTimedOut {
              get { return SR.GetResourceString("SocketAbortedSendTimedOut", @"The socket connection was aborted because an asynchronous send to the socket did not complete within the allotted timeout of {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string OperationInvalidBeforeSecurityNegotiation {
              get { return SR.GetResourceString("OperationInvalidBeforeSecurityNegotiation", @"This operation is not valid until security negotiation is complete."); }
        }
        internal static string FramingError {
              get { return SR.GetResourceString("FramingError", @"Error while reading message framing format at position {0} of stream (state: {1})"); }
        }
        internal static string FramingPrematureEOF {
              get { return SR.GetResourceString("FramingPrematureEOF", @"More data was expected, but EOF was reached."); }
        }
        internal static string FramingRecordTypeMismatch {
              get { return SR.GetResourceString("FramingRecordTypeMismatch", @"Expected record type '{0}', found '{1}'."); }
        }
        internal static string FramingVersionNotSupported {
              get { return SR.GetResourceString("FramingVersionNotSupported", @"Framing major version {0} is not supported."); }
        }
        internal static string FramingModeNotSupported {
              get { return SR.GetResourceString("FramingModeNotSupported", @"Framing mode {0} is not supported."); }
        }
        internal static string FramingSizeTooLarge {
              get { return SR.GetResourceString("FramingSizeTooLarge", @"Specified size is too large for this implementation."); }
        }
        internal static string FramingViaTooLong {
              get { return SR.GetResourceString("FramingViaTooLong", @"The framing via size ({0}) exceeds the quota."); }
        }
        internal static string FramingViaNotUri {
              get { return SR.GetResourceString("FramingViaNotUri", @"The framing via ({0}) is not a valid URI."); }
        }
        internal static string FramingFaultTooLong {
              get { return SR.GetResourceString("FramingFaultTooLong", @"The framing fault size ({0}) exceeds the quota."); }
        }
        internal static string FramingContentTypeTooLong {
              get { return SR.GetResourceString("FramingContentTypeTooLong", @"The framing content type size ({0}) exceeds the quota."); }
        }
        internal static string FramingValueNotAvailable {
              get { return SR.GetResourceString("FramingValueNotAvailable", @"The value cannot be accessed because it has not yet been fully decoded."); }
        }
        internal static string FramingAtEnd {
              get { return SR.GetResourceString("FramingAtEnd", @"An attempt was made to decode a value after the framing stream was ended."); }
        }
        internal static string RemoteSecurityNotNegotiatedOnStreamUpgrade {
              get { return SR.GetResourceString("RemoteSecurityNotNegotiatedOnStreamUpgrade", @"Stream Security is required at {0}, but no security context was negotiated. This is likely caused by the remote endpoint missing a StreamSecurityBindingElement from its binding."); }
        }
        internal static string BinaryEncoderSessionTooLarge {
              get { return SR.GetResourceString("BinaryEncoderSessionTooLarge", @"The binary encoder session information exceeded the maximum size quota ({0}). To increase this quota, use the MaxSessionSize property on the BinaryMessageEncodingBindingElement."); }
        }
        internal static string BinaryEncoderSessionInvalid {
              get { return SR.GetResourceString("BinaryEncoderSessionInvalid", @"The binary encoder session is not valid. There was an error decoding a previous message."); }
        }
        internal static string BinaryEncoderSessionMalformed {
              get { return SR.GetResourceString("BinaryEncoderSessionMalformed", @"The binary encoder session information is not properly formed."); }
        }
        internal static string ReceiveShutdownReturnedFault {
              get { return SR.GetResourceString("ReceiveShutdownReturnedFault", @"The channel received an unexpected fault input message while closing. The fault reason given is: '{0}'"); }
        }
        internal static string ReceiveShutdownReturnedLargeFault {
              get { return SR.GetResourceString("ReceiveShutdownReturnedLargeFault", @"The channel received an unexpected fault input message with Action = '{0}' while closing. You should only close your channel when you are not expecting any more input messages."); }
        }
        internal static string ReceiveShutdownReturnedMessage {
              get { return SR.GetResourceString("ReceiveShutdownReturnedMessage", @"The channel received an unexpected input message with Action '{0}' while closing. You should only close your channel when you are not expecting any more input messages."); }
        }
        internal static string MaxReceivedMessageSizeExceeded {
              get { return SR.GetResourceString("MaxReceivedMessageSizeExceeded", @"The maximum message size quota for incoming messages ({0}) has been exceeded. To increase the quota, use the MaxReceivedMessageSize property on the appropriate binding element."); }
        }
        internal static string MaxSentMessageSizeExceeded {
              get { return SR.GetResourceString("MaxSentMessageSizeExceeded", @"The maximum message size quota for outgoing messages ({0}) has been exceeded."); }
        }
        internal static string FramingMaxMessageSizeExceeded {
              get { return SR.GetResourceString("FramingMaxMessageSizeExceeded", @"The maximum message size quota for incoming messages has been exceeded for the remote channel. See the server logs for more details."); }
        }
        internal static string StreamDoesNotSupportTimeout {
              get { return SR.GetResourceString("StreamDoesNotSupportTimeout", @"TimeoutStream requires an inner Stream that supports timeouts; its CanTimeout property must be true."); }
        }
        internal static string FilterExists {
              get { return SR.GetResourceString("FilterExists", @"The filter already exists in the filter table."); }
        }
        internal static string FilterUnexpectedError {
              get { return SR.GetResourceString("FilterUnexpectedError", @"An internal error has occurred. Unexpected error modifying filter table."); }
        }
        internal static string FilterNodeQuotaExceeded {
              get { return SR.GetResourceString("FilterNodeQuotaExceeded", @"The number of XML infoset nodes inspected by the navigator has exceeded the quota ({0})."); }
        }
        internal static string FilterCapacityNegative {
              get { return SR.GetResourceString("FilterCapacityNegative", @"Value cannot be negative."); }
        }
        internal static string ActionFilterEmptyList {
              get { return SR.GetResourceString("ActionFilterEmptyList", @"The set of actions cannot be empty."); }
        }
        internal static string FilterUndefinedPrefix {
              get { return SR.GetResourceString("FilterUndefinedPrefix", @"The prefix '{0}' is not defined."); }
        }
        internal static string FilterMultipleMatches {
              get { return SR.GetResourceString("FilterMultipleMatches", @"Multiple filters matched."); }
        }
        internal static string FilterTableTypeMismatch {
              get { return SR.GetResourceString("FilterTableTypeMismatch", @"The type of IMessageFilterTable created for a particular Filter type must always be the same."); }
        }
        internal static string FilterTableInvalidForLookup {
              get { return SR.GetResourceString("FilterTableInvalidForLookup", @"The MessageFilterTable state is corrupt. The requested lookup cannot be performed."); }
        }
        internal static string FilterBadTableType {
              get { return SR.GetResourceString("FilterBadTableType", @"The IMessageFilterTable created for a Filter cannot be a MessageFilterTable or a subclass of MessageFilterTable."); }
        }
        internal static string FilterQuotaRange {
              get { return SR.GetResourceString("FilterQuotaRange", @"NodeQuota must be greater than 0."); }
        }
        internal static string FilterEmptyString {
              get { return SR.GetResourceString("FilterEmptyString", @"Parameter value cannot be an empty string."); }
        }
        internal static string FilterInvalidInner {
              get { return SR.GetResourceString("FilterInvalidInner", @"Required inner element '{0}' was not found."); }
        }
        internal static string FilterInvalidAttribute {
              get { return SR.GetResourceString("FilterInvalidAttribute", @"Invalid attribute on the XPath."); }
        }
        internal static string FilterInvalidDialect {
              get { return SR.GetResourceString("FilterInvalidDialect", @"When present, the dialect attribute must have the value '{0}'."); }
        }
        internal static string FilterCouldNotCompile {
              get { return SR.GetResourceString("FilterCouldNotCompile", @"Could not compile the XPath expression '{0}' with the given XsltContext."); }
        }
        internal static string FilterReaderNotStartElem {
              get { return SR.GetResourceString("FilterReaderNotStartElem", @"XmlReader not positioned at a start element."); }
        }
        internal static string SeekableMessageNavInvalidPosition {
              get { return SR.GetResourceString("SeekableMessageNavInvalidPosition", @"The position is not valid for this navigator."); }
        }
        internal static string SeekableMessageNavNonAtomized {
              get { return SR.GetResourceString("SeekableMessageNavNonAtomized", @"Cannot call '{0}' on a non-atomized navigator."); }
        }
        internal static string SeekableMessageNavIDNotSupported {
              get { return SR.GetResourceString("SeekableMessageNavIDNotSupported", @"XML unique ID not supported."); }
        }
        internal static string SeekableMessageNavBodyForbidden {
              get { return SR.GetResourceString("SeekableMessageNavBodyForbidden", @"A filter has attempted to access the body of a Message. Use a MessageBuffer instead if body filtering is required."); }
        }
        internal static string SeekableMessageNavOverrideForbidden {
              get { return SR.GetResourceString("SeekableMessageNavOverrideForbidden", @"Not allowed to override prefix '{0}'."); }
        }
        internal static string QueryNotImplemented {
              get { return SR.GetResourceString("QueryNotImplemented", @"The function '{0}' is not implemented."); }
        }
        internal static string QueryNotSortable {
              get { return SR.GetResourceString("QueryNotSortable", @"XPathNavigator positions cannot be compared."); }
        }
        internal static string QueryMustBeSeekable {
              get { return SR.GetResourceString("QueryMustBeSeekable", @"XPathNavigator must be a SeekableXPathNavigator."); }
        }
        internal static string QueryContextNotSupportedInSequences {
              get { return SR.GetResourceString("QueryContextNotSupportedInSequences", @"Context node is not supported in node sequences."); }
        }
        internal static string QueryFunctionTypeNotSupported {
              get { return SR.GetResourceString("QueryFunctionTypeNotSupported", @"IXsltContextFunction return type '{0}' not supported."); }
        }
        internal static string QueryVariableTypeNotSupported {
              get { return SR.GetResourceString("QueryVariableTypeNotSupported", @"IXsltContextVariable type '{0}' not supported."); }
        }
        internal static string QueryVariableNull {
              get { return SR.GetResourceString("QueryVariableNull", @"IXsltContextVariables cannot return null."); }
        }
        internal static string QueryFunctionStringArg {
              get { return SR.GetResourceString("QueryFunctionStringArg", @"The argument to an IXsltContextFunction could not be converted to a string."); }
        }
        internal static string QueryItemAlreadyExists {
              get { return SR.GetResourceString("QueryItemAlreadyExists", @"An internal error has occurred. Item already exists."); }
        }
        internal static string QueryBeforeNodes {
              get { return SR.GetResourceString("QueryBeforeNodes", @"Positioned before first element."); }
        }
        internal static string QueryAfterNodes {
              get { return SR.GetResourceString("QueryAfterNodes", @"Positioned after last element."); }
        }
        internal static string QueryIteratorOutOfScope {
              get { return SR.GetResourceString("QueryIteratorOutOfScope", @"The XPathNodeIterator has been invalidated. XPathNodeIterators passed as arguments to IXsltContextFunctions are only valid within the function. They cannot be cached for later use or returned as the result of the function."); }
        }
        internal static string QueryCantGetStringForMovedIterator {
              get { return SR.GetResourceString("QueryCantGetStringForMovedIterator", @"The string value can't be determined because the XPathNodeIterator has been moved past the first node."); }
        }
        internal static string AddressingVersionNotSupported {
              get { return SR.GetResourceString("AddressingVersionNotSupported", @"Addressing Version '{0}' is not supported."); }
        }
        internal static string SupportedAddressingModeNotSupported {
              get { return SR.GetResourceString("SupportedAddressingModeNotSupported", @"The '{0}' addressing mode is not supported."); }
        }
        internal static string MessagePropertyReturnedNullCopy {
              get { return SR.GetResourceString("MessagePropertyReturnedNullCopy", @"The IMessageProperty could not be copied. CreateCopy returned null."); }
        }
        internal static string MessageVersionUnknown {
              get { return SR.GetResourceString("MessageVersionUnknown", @"Unrecognized message version."); }
        }
        internal static string EnvelopeVersionUnknown {
              get { return SR.GetResourceString("EnvelopeVersionUnknown", @"Unrecognized envelope version: {0}."); }
        }
        internal static string EnvelopeVersionNotSupported {
              get { return SR.GetResourceString("EnvelopeVersionNotSupported", @"Envelope Version '{0}' is not supported."); }
        }
        internal static string CannotDetectAddressingVersion {
              get { return SR.GetResourceString("CannotDetectAddressingVersion", @"Cannot detect WS-Addressing version. EndpointReference does not start with an Element."); }
        }
        internal static string HeadersCannotBeAddedToEnvelopeVersion {
              get { return SR.GetResourceString("HeadersCannotBeAddedToEnvelopeVersion", @"Envelope Version '{0}' does not support adding Message Headers."); }
        }
        internal static string AddressingHeadersCannotBeAddedToAddressingVersion {
              get { return SR.GetResourceString("AddressingHeadersCannotBeAddedToAddressingVersion", @"Addressing Version '{0}' does not support adding WS-Addressing headers."); }
        }
        internal static string AddressingExtensionInBadNS {
              get { return SR.GetResourceString("AddressingExtensionInBadNS", @"The element '{0}' in namespace '{1}' is not valid. This either means that element '{0}' is a duplicate element, or that it is not a legal extension because extension elements cannot be in the addressing namespace."); }
        }
        internal static string MessageHeaderVersionNotSupported {
              get { return SR.GetResourceString("MessageHeaderVersionNotSupported", @"The '{0}' header cannot be added because it does not support the specified message version '{1}'."); }
        }
        internal static string MessageHasBeenCopied {
              get { return SR.GetResourceString("MessageHasBeenCopied", @"This message cannot support the operation because it has been copied."); }
        }
        internal static string MessageHasBeenWritten {
              get { return SR.GetResourceString("MessageHasBeenWritten", @"This message cannot support the operation because it has been written."); }
        }
        internal static string MessageHasBeenRead {
              get { return SR.GetResourceString("MessageHasBeenRead", @"This message cannot support the operation because it has been read."); }
        }
        internal static string InvalidMessageState {
              get { return SR.GetResourceString("InvalidMessageState", @"An internal error has occurred. Invalid MessageState."); }
        }
        internal static string MessageBodyReaderInvalidReadState {
              get { return SR.GetResourceString("MessageBodyReaderInvalidReadState", @"The body reader is in ReadState '{0}' and cannot be consumed."); }
        }
        internal static string XmlBufferQuotaExceeded {
              get { return SR.GetResourceString("XmlBufferQuotaExceeded", @"The size necessary to buffer the XML content exceeded the buffer quota."); }
        }
        internal static string XmlBufferInInvalidState {
              get { return SR.GetResourceString("XmlBufferInInvalidState", @"An internal error has occurred. The XML buffer is not in the correct state to perform the operation."); }
        }
        internal static string MessageBodyMissing {
              get { return SR.GetResourceString("MessageBodyMissing", @"A body element was not found inside the message envelope."); }
        }
        internal static string MessageHeaderVersionMismatch {
              get { return SR.GetResourceString("MessageHeaderVersionMismatch", @"The version of the header(s) ({0}) differs from the version of the message ({1})."); }
        }
        internal static string ManualAddressingRequiresAddressedMessages {
              get { return SR.GetResourceString("ManualAddressingRequiresAddressedMessages", @"Manual addressing is enabled on this factory, so all messages sent must be pre-addressed."); }
        }
        internal static string OneWayHeaderNotFound {
              get { return SR.GetResourceString("OneWayHeaderNotFound", @"A one-way header was expected on this message and none was found. It is possible that your bindings are mismatched."); }
        }
        internal static string ReceiveTimedOut {
              get { return SR.GetResourceString("ReceiveTimedOut", @"Receive on local address {0} timed out after {1}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string ReceiveTimedOut2 {
              get { return SR.GetResourceString("ReceiveTimedOut2", @"Receive timed out after {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string WaitForMessageTimedOut {
              get { return SR.GetResourceString("WaitForMessageTimedOut", @"WaitForMessage timed out after {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string ReceiveTimedOutNoLocalAddress {
              get { return SR.GetResourceString("ReceiveTimedOutNoLocalAddress", @"Receive timed out after {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string ReceiveRequestTimedOutNoLocalAddress {
              get { return SR.GetResourceString("ReceiveRequestTimedOutNoLocalAddress", @"Receive request timed out after {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string ReceiveRequestTimedOut {
              get { return SR.GetResourceString("ReceiveRequestTimedOut", @"Receive request on local address {0} timed out after {1}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string SendToViaTimedOut {
              get { return SR.GetResourceString("SendToViaTimedOut", @"Sending to via {0} timed out after {1}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string CloseTimedOut {
              get { return SR.GetResourceString("CloseTimedOut", @"Close timed out after {0}.  Increase the timeout value passed to the call to Close or increase the CloseTimeout value on the Binding. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string OpenTimedOutEstablishingTransportSession {
              get { return SR.GetResourceString("OpenTimedOutEstablishingTransportSession", @"Open timed out after {0} while establishing a transport session to {1}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string RequestTimedOutEstablishingTransportSession {
              get { return SR.GetResourceString("RequestTimedOutEstablishingTransportSession", @"Request timed out after {0} while establishing a transport connection to {1}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string TcpConnectingToViaTimedOut {
              get { return SR.GetResourceString("TcpConnectingToViaTimedOut", @"Connecting to via {0} timed out after {1}. Connection attempts were made to {2} of {3} available addresses ({4}). Check the RemoteAddress of your channel and verify that the DNS records for this endpoint correspond to valid IP Addresses. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string RequestChannelSendTimedOut {
              get { return SR.GetResourceString("RequestChannelSendTimedOut", @"The request channel timed out attempting to send after {0}. Increase the timeout value passed to the call to Request or increase the SendTimeout value on the Binding. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string RequestChannelWaitForReplyTimedOut {
              get { return SR.GetResourceString("RequestChannelWaitForReplyTimedOut", @"The request channel timed out while waiting for a reply after {0}. Increase the timeout value passed to the call to Request or increase the SendTimeout value on the Binding. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string HttpTransportCannotHaveMultipleAuthenticationSchemes {
              get { return SR.GetResourceString("HttpTransportCannotHaveMultipleAuthenticationSchemes", @"The policy being imported for contract '{0}:{1}' contains multiple HTTP authentication scheme assertions.  Since at most one such assertion is allowed, policy import has failed.  This may be resolved by updating the policy to contain no more than one HTTP authentication scheme assertion."); }
        }
        internal static string MultipleCCbesInParameters {
              get { return SR.GetResourceString("MultipleCCbesInParameters", @"More than one '{0}' objects were found in the BindingParameters of the BindingContext.  This is usually caused by having multiple '{0}' objects in a CustomBinding. Remove all but one of these elements."); }
        }
        internal static string CookieContainerBindingElementNeedsHttp {
              get { return SR.GetResourceString("CookieContainerBindingElementNeedsHttp", @"The '{0}' can only be used with HTTP (or HTTPS) transport."); }
        }
        internal static string HttpIfModifiedSinceParseError {
              get { return SR.GetResourceString("HttpIfModifiedSinceParseError", @"The value specified, '{0}', for the If-Modified-Since header does not parse into a valid date. Check the property value and ensure that it is of the proper format."); }
        }
        internal static string HttpSoapActionMismatch {
              get { return SR.GetResourceString("HttpSoapActionMismatch", @"The SOAP action specified on the message, '{0}', does not match the action specified on the HttpRequestMessageProperty, '{1}'."); }
        }
        internal static string HttpSoapActionMismatchContentType {
              get { return SR.GetResourceString("HttpSoapActionMismatchContentType", @"The SOAP action specified on the message, '{0}', does not match the action specified in the content-type of the HttpRequestMessageProperty, '{1}'."); }
        }
        internal static string HttpSoapActionMismatchFault {
              get { return SR.GetResourceString("HttpSoapActionMismatchFault", @"The SOAP action specified on the message, '{0}', does not match the HTTP SOAP Action, '{1}'. "); }
        }
        internal static string HttpContentTypeFormatException {
              get { return SR.GetResourceString("HttpContentTypeFormatException", @"An error ({0}) occurred while parsing the content type of the HTTP request. The content type was: {1}."); }
        }
        internal static string HttpServerTooBusy {
              get { return SR.GetResourceString("HttpServerTooBusy", @"The HTTP service located at {0} is unavailable.  This could be because the service is too busy or because no endpoint was found listening at the specified address. Please ensure that the address is correct and try accessing the service again later."); }
        }
        internal static string HttpRequestAborted {
              get { return SR.GetResourceString("HttpRequestAborted", @"The HTTP request to '{0}' was aborted.  This may be due to the local channel being closed while the request was still in progress.  If this behavior is not desired, then update your code so that it does not close the channel while request operations are still in progress."); }
        }
        internal static string HttpRequestTimedOut {
              get { return SR.GetResourceString("HttpRequestTimedOut", @"The HTTP request to '{0}' has exceeded the allotted timeout of {1}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string HttpResponseTimedOut {
              get { return SR.GetResourceString("HttpResponseTimedOut", @"The HTTP request to '{0}' has exceeded the allotted timeout of {1} while reading the response. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string HttpTransferError {
              get { return SR.GetResourceString("HttpTransferError", @"An error ({0}) occurred while transmitting data over the HTTP channel."); }
        }
        internal static string HttpReceiveFailure {
              get { return SR.GetResourceString("HttpReceiveFailure", @"An error occurred while receiving the HTTP response to {0}. This could be due to the service endpoint binding not using the HTTP protocol. This could also be due to an HTTP request context being aborted by the server (possibly due to the service shutting down). See server logs for more details."); }
        }
        internal static string HttpSendFailure {
              get { return SR.GetResourceString("HttpSendFailure", @"An error occurred while making the HTTP request to {0}. This could be due to the fact that the server certificate is not configured properly with HTTP.SYS in the HTTPS case. This could also be caused by a mismatch of the security binding between the client and the server."); }
        }
        internal static string HttpAuthDoesNotSupportRequestStreaming {
              get { return SR.GetResourceString("HttpAuthDoesNotSupportRequestStreaming", @"HTTP request streaming cannot be used in conjunction with HTTP authentication.  Either disable request streaming or specify anonymous HTTP authentication."); }
        }
        internal static string ReplyAlreadySent {
              get { return SR.GetResourceString("ReplyAlreadySent", @"A reply has already been sent from this RequestContext."); }
        }
        internal static string HttpInvalidListenURI {
              get { return SR.GetResourceString("HttpInvalidListenURI", @"Unable to start the HTTP listener. The URI provided, '{0}', is invalid for listening. Check the base address of your service and verify that it is a valid URI."); }
        }
        internal static string RequestContextAborted {
              get { return SR.GetResourceString("RequestContextAborted", @"The requestContext has been aborted."); }
        }
        internal static string ReceiveContextCannotBeUsed {
              get { return SR.GetResourceString("ReceiveContextCannotBeUsed", @"The receive context, {0}, is in the {1} state.  Receive contexts cannot be used for sending delayed acks unless they are in the Received state."); }
        }
        internal static string ReceiveContextInInvalidState {
              get { return SR.GetResourceString("ReceiveContextInInvalidState", @"The receive context, {0}, is in an unsupported state '{1}'.  This indicates an internal error in the implementation of that receive context."); }
        }
        internal static string ReceiveContextFaulted {
              get { return SR.GetResourceString("ReceiveContextFaulted", @"The receive context, {0}, cannot be used for sending delayed acks because it is in the Faulted state."); }
        }
        internal static string UnrecognizedHostNameComparisonMode {
              get { return SR.GetResourceString("UnrecognizedHostNameComparisonMode", @"Invalid HostNameComparisonMode value: {0}."); }
        }
        internal static string BadData {
              get { return SR.GetResourceString("BadData", @"Invalid data buffer."); }
        }
        internal static string InvalidRenewResponseAction {
              get { return SR.GetResourceString("InvalidRenewResponseAction", @"A security session renew response was received with an invalid action '{0}'."); }
        }
        internal static string InvalidCloseResponseAction {
              get { return SR.GetResourceString("InvalidCloseResponseAction", @"A security session close response was received with an invalid action '{0}',"); }
        }
        internal static string IncompatibleBehaviors {
              get { return SR.GetResourceString("IncompatibleBehaviors", @"TransactedBatchingBehavior cannot be used when ReceiveContext is being used."); }
        }
        internal static string NullSessionRequestMessage {
              get { return SR.GetResourceString("NullSessionRequestMessage", @"Could not formulate request message for security session operation '{0}'."); }
        }
        internal static string IssueSessionTokenHandlerNotSet {
              get { return SR.GetResourceString("IssueSessionTokenHandlerNotSet", @"There is no handler registered for session token issuance event."); }
        }
        internal static string RenewSessionTokenHandlerNotSet {
              get { return SR.GetResourceString("RenewSessionTokenHandlerNotSet", @"There is no handler registered for session token renew event."); }
        }
        internal static string WrongIdentityRenewingToken {
              get { return SR.GetResourceString("WrongIdentityRenewingToken", @"The identity of the security session renew message does not match the identity of the session token."); }
        }
        internal static string InvalidRstRequestType {
              get { return SR.GetResourceString("InvalidRstRequestType", @"The RequestSecurityToken has an invalid or unspecified RequestType '{0}'."); }
        }
        internal static string NoCloseTargetSpecified {
              get { return SR.GetResourceString("NoCloseTargetSpecified", @"The RequestSecurityToken must specify a CloseTarget."); }
        }
        internal static string FailedSspiNegotiation {
              get { return SR.GetResourceString("FailedSspiNegotiation", @"Secure channel cannot be opened because security negotiation with the remote endpoint has failed. This may be due to absent or incorrectly specified EndpointIdentity in the EndpointAddress used to create the channel. Please verify the EndpointIdentity specified or implied by the EndpointAddress correctly identifies the remote endpoint. "); }
        }
        internal static string BadCloseTarget {
              get { return SR.GetResourceString("BadCloseTarget", @"The CloseTarget specified '{0}' does not identify the security token that signed the message."); }
        }
        internal static string RenewSessionMissingSupportingToken {
              get { return SR.GetResourceString("RenewSessionMissingSupportingToken", @"The renew security session message does not have the session token as a supporting token."); }
        }
        internal static string NoRenewTargetSpecified {
              get { return SR.GetResourceString("NoRenewTargetSpecified", @"The RequestSecurityToken must specify a RenewTarget."); }
        }
        internal static string BadRenewTarget {
              get { return SR.GetResourceString("BadRenewTarget", @"There is no endorsing session token that matches the specified RenewTarget '{0}'."); }
        }
        internal static string BadEncryptedBody {
              get { return SR.GetResourceString("BadEncryptedBody", @"Invalid format for encrypted body."); }
        }
        internal static string BadEncryptionState {
              get { return SR.GetResourceString("BadEncryptionState", @"The EncryptedData or EncryptedKey is in an invalid state for this operation."); }
        }
        internal static string NoSignaturePartsSpecified {
              get { return SR.GetResourceString("NoSignaturePartsSpecified", @"No signature message parts were specified for messages with the '{0}' action."); }
        }
        internal static string NoEncryptionPartsSpecified {
              get { return SR.GetResourceString("NoEncryptionPartsSpecified", @"No encryption message parts were specified for messages with the '{0}' action."); }
        }
        internal static string SecuritySessionFaultReplyWasSent {
              get { return SR.GetResourceString("SecuritySessionFaultReplyWasSent", @"The receiver sent back a security session fault message. Retry the request."); }
        }
        internal static string InnerListenerFactoryNotSet {
              get { return SR.GetResourceString("InnerListenerFactoryNotSet", @"The Inner listener factory of {0} must be set before this operation."); }
        }
        internal static string SecureConversationBootstrapCannotUseSecureConversation {
              get { return SR.GetResourceString("SecureConversationBootstrapCannotUseSecureConversation", @"Cannot create security binding element based on configuration data. The secure conversation bootstrap requires another secure conversation which is not supported. "); }
        }
        internal static string InnerChannelFactoryWasNotSet {
              get { return SR.GetResourceString("InnerChannelFactoryWasNotSet", @"Cannot open ChannelFactory as the inner channel factory was not set during the initialization process."); }
        }
        internal static string SecurityProtocolFactoryDoesNotSupportDuplex {
              get { return SR.GetResourceString("SecurityProtocolFactoryDoesNotSupportDuplex", @"Duplex security is not supported by the security protocol factory '{0}'."); }
        }
        internal static string SecurityProtocolFactoryDoesNotSupportRequestReply {
              get { return SR.GetResourceString("SecurityProtocolFactoryDoesNotSupportRequestReply", @"Request-reply security is not supported by the security protocol factory '{0}'."); }
        }
        internal static string SecurityProtocolFactoryShouldBeSetBeforeThisOperation {
              get { return SR.GetResourceString("SecurityProtocolFactoryShouldBeSetBeforeThisOperation", @"The security protocol factory must be set before this operation is performed."); }
        }
        internal static string SecuritySessionProtocolFactoryShouldBeSetBeforeThisOperation {
              get { return SR.GetResourceString("SecuritySessionProtocolFactoryShouldBeSetBeforeThisOperation", @"Security session protocol factory must be set before this operation is performed."); }
        }
        internal static string SecureConversationSecurityTokenParametersRequireBootstrapBinding {
              get { return SR.GetResourceString("SecureConversationSecurityTokenParametersRequireBootstrapBinding", @"Security channel or listener factory creation failed. Secure conversation security token parameters do not specify the bootstrap security binding element."); }
        }
        internal static string PropertySettingErrorOnProtocolFactory {
              get { return SR.GetResourceString("PropertySettingErrorOnProtocolFactory", @"The required '{0}' property on the '{1}' security protocol factory is not set or has an invalid value."); }
        }
        internal static string ProtocolFactoryCouldNotCreateProtocol {
              get { return SR.GetResourceString("ProtocolFactoryCouldNotCreateProtocol", @"The protocol factory cannot create a protocol."); }
        }
        internal static string IdentityCheckFailedForOutgoingMessage {
              get { return SR.GetResourceString("IdentityCheckFailedForOutgoingMessage", @"The identity check failed for the outgoing message. The expected identity is '{0}' for the '{1}' target endpoint."); }
        }
        internal static string IdentityCheckFailedForIncomingMessage {
              get { return SR.GetResourceString("IdentityCheckFailedForIncomingMessage", @"The identity check failed for the incoming message. The expected identity is '{0}' for the '{1}' target endpoint."); }
        }
        internal static string DnsIdentityCheckFailedForIncomingMessageLackOfDnsClaim {
              get { return SR.GetResourceString("DnsIdentityCheckFailedForIncomingMessageLackOfDnsClaim", @"The Identity check failed for the incoming message. The remote endpoint did not provide a domain name system (DNS) claim and therefore did not satisfied DNS identity '{0}'. This may be caused by lack of DNS or CN name in the remote endpoint X.509 certificate's distinguished name."); }
        }
        internal static string DnsIdentityCheckFailedForOutgoingMessageLackOfDnsClaim {
              get { return SR.GetResourceString("DnsIdentityCheckFailedForOutgoingMessageLackOfDnsClaim", @"The Identity check failed for the outgoing message. The remote endpoint did not provide a domain name system (DNS) claim and therefore did not satisfied DNS identity '{0}'. This may be caused by lack of DNS or CN name in the remote endpoint X.509 certificate's distinguished name."); }
        }
        internal static string DnsIdentityCheckFailedForIncomingMessage {
              get { return SR.GetResourceString("DnsIdentityCheckFailedForIncomingMessage", @"Identity check failed for incoming message. The expected DNS identity of the remote endpoint was '{0}' but the remote endpoint provided DNS claim '{1}'. If this is a legitimate remote endpoint, you can fix the problem by explicitly specifying DNS identity '{1}' as the Identity property of EndpointAddress when creating channel proxy. "); }
        }
        internal static string DnsIdentityCheckFailedForOutgoingMessage {
              get { return SR.GetResourceString("DnsIdentityCheckFailedForOutgoingMessage", @"Identity check failed for outgoing message. The expected DNS identity of the remote endpoint was '{0}' but the remote endpoint provided DNS claim '{1}'. If this is a legitimate remote endpoint, you can fix the problem by explicitly specifying DNS identity '{1}' as the Identity property of EndpointAddress when creating channel proxy. "); }
        }
        internal static string SerializedTokenVersionUnsupported {
              get { return SR.GetResourceString("SerializedTokenVersionUnsupported", @"The serialized token version {0} is unsupported."); }
        }
        internal static string AuthenticatorNotPresentInRSTRCollection {
              get { return SR.GetResourceString("AuthenticatorNotPresentInRSTRCollection", @"The RequestSecurityTokenResponseCollection does not contain an authenticator."); }
        }
        internal static string RSTRAuthenticatorHasBadContext {
              get { return SR.GetResourceString("RSTRAuthenticatorHasBadContext", @"The negotiation RequestSecurityTokenResponse has a different context from the authenticator RequestSecurityTokenResponse."); }
        }
        internal static string ServerCertificateNotProvided {
              get { return SR.GetResourceString("ServerCertificateNotProvided", @"The recipient did not provide its certificate.  This certificate is required by the TLS protocol.  Both parties must have access to their certificates."); }
        }
        internal static string RSTRAuthenticatorNotPresent {
              get { return SR.GetResourceString("RSTRAuthenticatorNotPresent", @"The authenticator was not included in the final leg of negotiation."); }
        }
        internal static string RSTRAuthenticatorIncorrect {
              get { return SR.GetResourceString("RSTRAuthenticatorIncorrect", @"The RequestSecurityTokenResponse CombinedHash is incorrect."); }
        }
        internal static string ClientCertificateNotProvided {
              get { return SR.GetResourceString("ClientCertificateNotProvided", @"The certificate for the client has not been provided.  The certificate can be set on the ClientCredentials or ServiceCredentials."); }
        }
        internal static string ClientCertificateNotProvidedOnServiceCredentials {
              get { return SR.GetResourceString("ClientCertificateNotProvidedOnServiceCredentials", @"The client certificate is not provided. Specify a client certificate in ServiceCredentials. "); }
        }
        internal static string ClientCertificateNotProvidedOnClientCredentials {
              get { return SR.GetResourceString("ClientCertificateNotProvidedOnClientCredentials", @"The client certificate is not provided. Specify a client certificate in ClientCredentials. "); }
        }
        internal static string ServiceCertificateNotProvidedOnServiceCredentials {
              get { return SR.GetResourceString("ServiceCertificateNotProvidedOnServiceCredentials", @"The service certificate is not provided. Specify a service certificate in ServiceCredentials. "); }
        }
        internal static string ServiceCertificateNotProvidedOnClientCredentials {
              get { return SR.GetResourceString("ServiceCertificateNotProvidedOnClientCredentials", @"The service certificate is not provided for target '{0}'. Specify a service certificate in ClientCredentials. "); }
        }
        internal static string UserNamePasswordNotProvidedOnClientCredentials {
              get { return SR.GetResourceString("UserNamePasswordNotProvidedOnClientCredentials", @"The username is not provided. Specify username in ClientCredentials."); }
        }
        internal static string ObjectIsReadOnly {
              get { return SR.GetResourceString("ObjectIsReadOnly", @"Object is read-only."); }
        }
        internal static string EmptyXmlElementError {
              get { return SR.GetResourceString("EmptyXmlElementError", @"Element {0} cannot be empty."); }
        }
        internal static string UnexpectedXmlChildNode {
              get { return SR.GetResourceString("UnexpectedXmlChildNode", @"XML child node {0} of type {1} is unexpected for element {2}."); }
        }
        internal static string ContextAlreadyRegistered {
              get { return SR.GetResourceString("ContextAlreadyRegistered", @"The context-id={0} (generation-id={1}) is already registered with SecurityContextSecurityTokenAuthenticator."); }
        }
        internal static string ContextAlreadyRegisteredNoKeyGeneration {
              get { return SR.GetResourceString("ContextAlreadyRegisteredNoKeyGeneration", @"The context-id={0} (no key generation-id) is already registered with SecurityContextSecurityTokenAuthenticator."); }
        }
        internal static string ContextNotPresent {
              get { return SR.GetResourceString("ContextNotPresent", @"There is no SecurityContextSecurityToken with context-id={0} (generation-id={1}) registered with SecurityContextSecurityTokenAuthenticator."); }
        }
        internal static string ContextNotPresentNoKeyGeneration {
              get { return SR.GetResourceString("ContextNotPresentNoKeyGeneration", @"There is no SecurityContextSecurityToken with context-id={0} (no key generation-id) registered with SecurityContextSecurityTokenAuthenticator."); }
        }
        internal static string InvalidSecurityContextCookie {
              get { return SR.GetResourceString("InvalidSecurityContextCookie", @"The SecurityContextSecurityToken has an invalid Cookie. The following error occurred when processing the Cookie: '{0}'."); }
        }
        internal static string SecurityContextNotRegistered {
              get { return SR.GetResourceString("SecurityContextNotRegistered", @"The SecurityContextSecurityToken with context-id={0} (key generation-id={1}) is not registered."); }
        }
        internal static string SecurityContextExpired {
              get { return SR.GetResourceString("SecurityContextExpired", @"The SecurityContextSecurityToken with context-id={0} (key generation-id={1}) has expired."); }
        }
        internal static string SecurityContextExpiredNoKeyGeneration {
              get { return SR.GetResourceString("SecurityContextExpiredNoKeyGeneration", @"The SecurityContextSecurityToken with context-id={0} (no key generation-id) has expired."); }
        }
        internal static string NoSecurityContextIdentifier {
              get { return SR.GetResourceString("NoSecurityContextIdentifier", @"The SecurityContextSecurityToken does not have a context-id."); }
        }
        internal static string MessageMustHaveViaOrToSetForSendingOnServerSideCompositeDuplexChannels {
              get { return SR.GetResourceString("MessageMustHaveViaOrToSetForSendingOnServerSideCompositeDuplexChannels", @"For sending a message on server side composite duplex channels, the message must have either the 'Via' property or the 'To' header set."); }
        }
        internal static string MessageViaCannotBeAddressedToAnonymousOnServerSideCompositeDuplexChannels {
              get { return SR.GetResourceString("MessageViaCannotBeAddressedToAnonymousOnServerSideCompositeDuplexChannels", @"The 'Via' property on the message is set to Anonymous Uri '{0}'. Please set the 'Via' property to a non-anonymous address as message cannot be addressed to anonymous Uri on server side composite duplex channels."); }
        }
        internal static string MessageToCannotBeAddressedToAnonymousOnServerSideCompositeDuplexChannels {
              get { return SR.GetResourceString("MessageToCannotBeAddressedToAnonymousOnServerSideCompositeDuplexChannels", @"The 'To' header on the message is set to Anonymous Uri '{0}'. Please set the 'To' header to a non-anonymous address as message cannot be addressed to anonymous Uri on server side composite duplex channels."); }
        }
        internal static string SecurityBindingNotSetUpToProcessOutgoingMessages {
              get { return SR.GetResourceString("SecurityBindingNotSetUpToProcessOutgoingMessages", @"This SecurityProtocol instance was not set up to process outgoing messages."); }
        }
        internal static string SecurityBindingNotSetUpToProcessIncomingMessages {
              get { return SR.GetResourceString("SecurityBindingNotSetUpToProcessIncomingMessages", @"This SecurityProtocol instance was not set up to process incoming messages."); }
        }
        internal static string TokenProviderCannotGetTokensForTarget {
              get { return SR.GetResourceString("TokenProviderCannotGetTokensForTarget", @"The token provider cannot get tokens for target '{0}'."); }
        }
        internal static string UnsupportedKeyDerivationAlgorithm {
              get { return SR.GetResourceString("UnsupportedKeyDerivationAlgorithm", @"Key derivation algorithm '{0}' is not supported."); }
        }
        internal static string CannotFindCorrelationStateForApplyingSecurity {
              get { return SR.GetResourceString("CannotFindCorrelationStateForApplyingSecurity", @"Cannot find the correlation state for applying security to reply at the responder."); }
        }
        internal static string ReplyWasNotSignedWithRequiredSigningToken {
              get { return SR.GetResourceString("ReplyWasNotSignedWithRequiredSigningToken", @"The reply was not signed with the required signing token."); }
        }
        internal static string EncryptionNotExpected {
              get { return SR.GetResourceString("EncryptionNotExpected", @"Encryption not expected for this message."); }
        }
        internal static string SignatureNotExpected {
              get { return SR.GetResourceString("SignatureNotExpected", @"A signature is not expected for this message."); }
        }
        internal static string InvalidQName {
              get { return SR.GetResourceString("InvalidQName", @"The QName is invalid."); }
        }
        internal static string UnknownICryptoType {
              get { return SR.GetResourceString("UnknownICryptoType", @"The ICrypto implementation '{0}' is not supported."); }
        }
        internal static string SameProtocolFactoryCannotBeSetForBothDuplexDirections {
              get { return SR.GetResourceString("SameProtocolFactoryCannotBeSetForBothDuplexDirections", @"On DuplexSecurityProtocolFactory, the same protocol factory cannot be set for the forward and reverse directions."); }
        }
        internal static string SuiteDoesNotAcceptAlgorithm {
              get { return SR.GetResourceString("SuiteDoesNotAcceptAlgorithm", @"The algorithm '{0}' is not accepted for operation '{1}' by algorithm suite {2}."); }
        }
        internal static string TokenDoesNotSupportKeyIdentifierClauseCreation {
              get { return SR.GetResourceString("TokenDoesNotSupportKeyIdentifierClauseCreation", @"'{0}' does not support '{1}' creation."); }
        }
        internal static string UnableToCreateICryptoFromTokenForSignatureVerification {
              get { return SR.GetResourceString("UnableToCreateICryptoFromTokenForSignatureVerification", @"Cannot create an ICrypto interface from the '{0}' token for signature verification."); }
        }
        internal static string MessageSecurityVerificationFailed {
              get { return SR.GetResourceString("MessageSecurityVerificationFailed", @"Message security verification failed."); }
        }
        internal static string TransportSecurityRequireToHeader {
              get { return SR.GetResourceString("TransportSecurityRequireToHeader", @"Transport secured messages should have the 'To' header specified."); }
        }
        internal static string TransportSecuredMessageMissingToHeader {
              get { return SR.GetResourceString("TransportSecuredMessageMissingToHeader", @"The message received over Transport security was missing the 'To' header."); }
        }
        internal static string UnsignedToHeaderInTransportSecuredMessage {
              get { return SR.GetResourceString("UnsignedToHeaderInTransportSecuredMessage", @"The message received over Transport security has unsigned 'To' header."); }
        }
        internal static string TransportSecuredMessageHasMoreThanOneToHeader {
              get { return SR.GetResourceString("TransportSecuredMessageHasMoreThanOneToHeader", @"More than one 'To' header specified in a message secured by Transport Security."); }
        }
        internal static string TokenNotExpectedInSecurityHeader {
              get { return SR.GetResourceString("TokenNotExpectedInSecurityHeader", @"Received security header contains unexpected token '{0}'."); }
        }
        internal static string CannotFindCert {
              get { return SR.GetResourceString("CannotFindCert", @"Cannot find the X.509 certificate using the following search criteria: StoreName '{0}', StoreLocation '{1}', FindType '{2}', FindValue '{3}'."); }
        }
        internal static string CannotFindCertForTarget {
              get { return SR.GetResourceString("CannotFindCertForTarget", @"Cannot find The X.509 certificate using the following search criteria: StoreName '{0}', StoreLocation '{1}', FindType '{2}', FindValue '{3}' for target '{4}'."); }
        }
        internal static string FoundMultipleCerts {
              get { return SR.GetResourceString("FoundMultipleCerts", @"Found multiple X.509 certificates using the following search criteria: StoreName '{0}', StoreLocation '{1}', FindType '{2}', FindValue '{3}'. Provide a more specific find value."); }
        }
        internal static string FoundMultipleCertsForTarget {
              get { return SR.GetResourceString("FoundMultipleCertsForTarget", @"Found multiple X.509 certificates using the following search criteria: StoreName '{0}', StoreLocation '{1}', FindType '{2}', FindValue '{3}' for target '{4}'. Provide a more specific find value."); }
        }
        internal static string MissingKeyInfoInEncryptedKey {
              get { return SR.GetResourceString("MissingKeyInfoInEncryptedKey", @"The KeyInfo clause is missing or empty in EncryptedKey."); }
        }
        internal static string EncryptedKeyWasNotEncryptedWithTheRequiredEncryptingToken {
              get { return SR.GetResourceString("EncryptedKeyWasNotEncryptedWithTheRequiredEncryptingToken", @"The EncryptedKey clause was not wrapped with the required encryption token '{0}'."); }
        }
        internal static string MessageWasNotEncryptedWithTheRequiredEncryptingToken {
              get { return SR.GetResourceString("MessageWasNotEncryptedWithTheRequiredEncryptingToken", @"The message was not encrypted with the required encryption token."); }
        }
        internal static string TimestampMustOccurFirstInSecurityHeaderLayout {
              get { return SR.GetResourceString("TimestampMustOccurFirstInSecurityHeaderLayout", @"The timestamp must occur first in this security header layout."); }
        }
        internal static string TimestampMustOccurLastInSecurityHeaderLayout {
              get { return SR.GetResourceString("TimestampMustOccurLastInSecurityHeaderLayout", @"The timestamp must occur last in this security header layout."); }
        }
        internal static string AtMostOnePrimarySignatureInReceiveSecurityHeader {
              get { return SR.GetResourceString("AtMostOnePrimarySignatureInReceiveSecurityHeader", @"Only one primary signature is allowed in a security header."); }
        }
        internal static string SigningTokenHasNoKeys {
              get { return SR.GetResourceString("SigningTokenHasNoKeys", @"The signing token {0} has no keys. The security token is used in a context that requires it to perform cryptographic operations, but the token contains no cryptographic keys. Either the token type does not support cryptographic operations, or the particular token instance does not contain cryptographic keys. Check your configuration to ensure that cryptographically disabled token types (for example, UserNameSecurityToken) are not specified in a context that requires cryptographic operations (for example, an endorsing supporting token)."); }
        }
        internal static string SigningTokenHasNoKeysSupportingTheAlgorithmSuite {
              get { return SR.GetResourceString("SigningTokenHasNoKeysSupportingTheAlgorithmSuite", @"The signing token {0} has no key that supports the algorithm suite {1}."); }
        }
        internal static string DelayedSecurityApplicationAlreadyCompleted {
              get { return SR.GetResourceString("DelayedSecurityApplicationAlreadyCompleted", @"Delayed security application has already been completed."); }
        }
        internal static string UnableToResolveKeyInfoClauseInDerivedKeyToken {
              get { return SR.GetResourceString("UnableToResolveKeyInfoClauseInDerivedKeyToken", @"Cannot resolve KeyInfo in derived key token for resolving source token: KeyInfoClause '{0}'."); }
        }
        internal static string UnableToDeriveKeyFromKeyInfoClause {
              get { return SR.GetResourceString("UnableToDeriveKeyFromKeyInfoClause", @"KeyInfo clause '{0}' resolved to token '{1}', which does not contain a Symmetric key that can be used for derivation."); }
        }
        internal static string UnableToResolveKeyInfoForVerifyingSignature {
              get { return SR.GetResourceString("UnableToResolveKeyInfoForVerifyingSignature", @"Cannot resolve KeyInfo for verifying signature: KeyInfo '{0}', available tokens '{1}'."); }
        }
        internal static string UnableToResolveKeyInfoForUnwrappingToken {
              get { return SR.GetResourceString("UnableToResolveKeyInfoForUnwrappingToken", @"Cannot resolve KeyInfo for unwrapping key: KeyInfo '{0}', available tokens '{1}'."); }
        }
        internal static string UnableToResolveKeyInfoForDecryption {
              get { return SR.GetResourceString("UnableToResolveKeyInfoForDecryption", @"Cannot resolve KeyInfo for decryption: KeyInfo '{0}', available tokens '{1}'."); }
        }
        internal static string EmptyBase64Attribute {
              get { return SR.GetResourceString("EmptyBase64Attribute", @"An empty value was found for the required base-64 attribute name '{0}', namespace '{1}'."); }
        }
        internal static string RequiredSecurityHeaderElementNotSigned {
              get { return SR.GetResourceString("RequiredSecurityHeaderElementNotSigned", @"The security header element '{0}' with the '{1}' id must be signed."); }
        }
        internal static string RequiredSecurityTokenNotSigned {
              get { return SR.GetResourceString("RequiredSecurityTokenNotSigned", @"The '{0}' security token with the '{1}' attachment mode must be signed."); }
        }
        internal static string RequiredSecurityTokenNotEncrypted {
              get { return SR.GetResourceString("RequiredSecurityTokenNotEncrypted", @"The '{0}' security token with the '{1}' attachment mode must be encrypted."); }
        }
        internal static string MessageBodyOperationNotValidInBodyState {
              get { return SR.GetResourceString("MessageBodyOperationNotValidInBodyState", @"Operation '{0}' is not valid in message body state '{1}'."); }
        }
        internal static string EncryptedKeyWithReferenceListNotAllowed {
              get { return SR.GetResourceString("EncryptedKeyWithReferenceListNotAllowed", @"EncryptedKey with ReferenceList is not allowed according to the current settings."); }
        }
        internal static string UnableToFindTokenAuthenticator {
              get { return SR.GetResourceString("UnableToFindTokenAuthenticator", @"Cannot find a token authenticator for the '{0}' token type. Tokens of that type cannot be accepted according to current security settings."); }
        }
        internal static string NoPartsOfMessageMatchedPartsToSign {
              get { return SR.GetResourceString("NoPartsOfMessageMatchedPartsToSign", @"No signature was created because not part of the message matched the supplied message part specification."); }
        }
        internal static string BasicTokenCannotBeWrittenWithoutEncryption {
              get { return SR.GetResourceString("BasicTokenCannotBeWrittenWithoutEncryption", @"Supporting SecurityToken cannot be written without encryption."); }
        }
        internal static string DuplicateIdInMessageToBeVerified {
              get { return SR.GetResourceString("DuplicateIdInMessageToBeVerified", @"The '{0}' id occurred twice in the message that is supplied for verification."); }
        }
        internal static string UnsupportedCanonicalizationAlgorithm {
              get { return SR.GetResourceString("UnsupportedCanonicalizationAlgorithm", @"Canonicalization algorithm '{0}' is not supported."); }
        }
        internal static string NoKeyInfoInEncryptedItemToFindDecryptingToken {
              get { return SR.GetResourceString("NoKeyInfoInEncryptedItemToFindDecryptingToken", @"The KeyInfo value was not found in the encrypted item to find the decrypting token."); }
        }
        internal static string NoKeyInfoInSignatureToFindVerificationToken {
              get { return SR.GetResourceString("NoKeyInfoInSignatureToFindVerificationToken", @"No KeyInfo in signature to find verification token."); }
        }
        internal static string SecurityHeaderIsEmpty {
              get { return SR.GetResourceString("SecurityHeaderIsEmpty", @"Security header is empty."); }
        }
        internal static string EncryptionMethodMissingInEncryptedData {
              get { return SR.GetResourceString("EncryptionMethodMissingInEncryptedData", @"The encryption method is missing in encrypted data."); }
        }
        internal static string EncryptedHeaderAttributeMismatch {
              get { return SR.GetResourceString("EncryptedHeaderAttributeMismatch", @"The Encrypted Header and the Security Header '{0}' attribute did not match. Encrypted Header: {1}. Security Header: {2}."); }
        }
        internal static string AtMostOneReferenceListIsSupportedWithDefaultPolicyCheck {
              get { return SR.GetResourceString("AtMostOneReferenceListIsSupportedWithDefaultPolicyCheck", @"At most one reference list is supported with default policy check."); }
        }
        internal static string AtMostOneSignatureIsSupportedWithDefaultPolicyCheck {
              get { return SR.GetResourceString("AtMostOneSignatureIsSupportedWithDefaultPolicyCheck", @"At most one signature is supported with default policy check."); }
        }
        internal static string UnexpectedEncryptedElementInSecurityHeader {
              get { return SR.GetResourceString("UnexpectedEncryptedElementInSecurityHeader", @"Unexpected encrypted element in security header."); }
        }
        internal static string MissingIdInEncryptedElement {
              get { return SR.GetResourceString("MissingIdInEncryptedElement", @"Id is missing in encrypted item in security header."); }
        }
        internal static string TokenManagerCannotCreateTokenReference {
              get { return SR.GetResourceString("TokenManagerCannotCreateTokenReference", @"The supplied token manager cannot create a token reference."); }
        }
        internal static string TimestampToSignHasNoId {
              get { return SR.GetResourceString("TimestampToSignHasNoId", @"The timestamp element added to security header to sign has no id."); }
        }
        internal static string EncryptedHeaderXmlMustHaveId {
              get { return SR.GetResourceString("EncryptedHeaderXmlMustHaveId", @"An encrypted header must have an id."); }
        }
        internal static string UnableToResolveDataReference {
              get { return SR.GetResourceString("UnableToResolveDataReference", @"The data reference '{0}' could not be resolved in the received message."); }
        }
        internal static string TimestampAlreadySetForSecurityHeader {
              get { return SR.GetResourceString("TimestampAlreadySetForSecurityHeader", @"A timestamp element has already been set for this security header."); }
        }
        internal static string DuplicateTimestampInSecurityHeader {
              get { return SR.GetResourceString("DuplicateTimestampInSecurityHeader", @"More than one Timestamp element was present in security header."); }
        }
        internal static string MismatchInSecurityOperationToken {
              get { return SR.GetResourceString("MismatchInSecurityOperationToken", @"The incoming message was signed with a token which was different from what used to encrypt the body.  This was not expected."); }
        }
        internal static string UnableToCreateSymmetricAlgorithmFromToken {
              get { return SR.GetResourceString("UnableToCreateSymmetricAlgorithmFromToken", @"Cannot create the '{0}' symmetric algorithm from the token."); }
        }
        internal static string UnknownEncodingInBinarySecurityToken {
              get { return SR.GetResourceString("UnknownEncodingInBinarySecurityToken", @"Unrecognized encoding occurred while reading the binary security token."); }
        }
        internal static string UnableToResolveReferenceUriForSignature {
              get { return SR.GetResourceString("UnableToResolveReferenceUriForSignature", @"Cannot resolve reference URI '{0}' in signature to compute digest."); }
        }
        internal static string NoTimestampAvailableInSecurityHeaderToDoReplayDetection {
              get { return SR.GetResourceString("NoTimestampAvailableInSecurityHeaderToDoReplayDetection", @"No timestamp is available in the security header to do replay detection."); }
        }
        internal static string NoSignatureAvailableInSecurityHeaderToDoReplayDetection {
              get { return SR.GetResourceString("NoSignatureAvailableInSecurityHeaderToDoReplayDetection", @"No signature is available in the security header to provide the nonce for replay detection."); }
        }
        internal static string CouldNotFindNamespaceForPrefix {
              get { return SR.GetResourceString("CouldNotFindNamespaceForPrefix", @"There is no namespace binding for prefix '{0}' in scope."); }
        }
        internal static string DerivedKeyCannotDeriveFromSecret {
              get { return SR.GetResourceString("DerivedKeyCannotDeriveFromSecret", @"Derived Key Token cannot derive key from the secret."); }
        }
        internal static string DerivedKeyPosAndGenBothSpecified {
              get { return SR.GetResourceString("DerivedKeyPosAndGenBothSpecified", @"Both offset and generation cannot be specified for Derived Key Token."); }
        }
        internal static string DerivedKeyPosAndGenNotSpecified {
              get { return SR.GetResourceString("DerivedKeyPosAndGenNotSpecified", @"Either offset or generation must be specified for Derived Key Token."); }
        }
        internal static string DerivedKeyTokenRequiresTokenReference {
              get { return SR.GetResourceString("DerivedKeyTokenRequiresTokenReference", @"DerivedKeyToken requires a reference to a token."); }
        }
        internal static string DerivedKeyLengthTooLong {
              get { return SR.GetResourceString("DerivedKeyLengthTooLong", @"DerivedKey length ({0}) exceeds the allowed settings ({1})."); }
        }
        internal static string DerivedKeyLengthSpecifiedInImplicitDerivedKeyClauseTooLong {
              get { return SR.GetResourceString("DerivedKeyLengthSpecifiedInImplicitDerivedKeyClauseTooLong", @"The Implicit derived key clause '{0}' specifies a derivation key length ({1}) which exceeds the allowed maximum length ({2})."); }
        }
        internal static string DerivedKeyInvalidOffsetSpecified {
              get { return SR.GetResourceString("DerivedKeyInvalidOffsetSpecified", @"The received derived key token has a invalid offset value specified. Value: {0}. The value should be greater than or equal to zero."); }
        }
        internal static string DerivedKeyInvalidGenerationSpecified {
              get { return SR.GetResourceString("DerivedKeyInvalidGenerationSpecified", @"The received derived key token has a invalid generation value specified. Value: {0}. The value should be greater than or equal to zero."); }
        }
        internal static string ChildNodeTypeMissing {
              get { return SR.GetResourceString("ChildNodeTypeMissing", @"The XML element {0} does not have a child of type {1}."); }
        }
        internal static string NoLicenseXml {
              get { return SR.GetResourceString("NoLicenseXml", @"RequestedSecurityToken not specified in RequestSecurityTokenResponse."); }
        }
        internal static string UnsupportedBinaryEncoding {
              get { return SR.GetResourceString("UnsupportedBinaryEncoding", @"Binary encoding {0} is not supported."); }
        }
        internal static string BadKeyEncryptionAlgorithm {
              get { return SR.GetResourceString("BadKeyEncryptionAlgorithm", @"Invalid key encryption algorithm {0}."); }
        }
        internal static string SPS_InvalidAsyncResult {
              get { return SR.GetResourceString("SPS_InvalidAsyncResult", @"The asynchronous result object used to end this operation was not the object that was returned when the operation was initiated."); }
        }
        internal static string UnableToCreateTokenReference {
              get { return SR.GetResourceString("UnableToCreateTokenReference", @"Unable to create token reference."); }
        }
        internal static string NonceLengthTooShort {
              get { return SR.GetResourceString("NonceLengthTooShort", @"The specified nonce is too short. The minimum required nonce length is 4 bytes."); }
        }
        internal static string NoBinaryNegoToSend {
              get { return SR.GetResourceString("NoBinaryNegoToSend", @"There is no binary negotiation to send to the other party."); }
        }
        internal static string BadSecurityNegotiationContext {
              get { return SR.GetResourceString("BadSecurityNegotiationContext", @"Security negotiation failure because an incorrect Context attribute specified in RequestSecurityToken/RequestSecurityTokenResponse from the other party."); }
        }
        internal static string NoBinaryNegoToReceive {
              get { return SR.GetResourceString("NoBinaryNegoToReceive", @"No binary negotiation was received from the other party."); }
        }
        internal static string ProofTokenWasNotWrappedCorrectly {
              get { return SR.GetResourceString("ProofTokenWasNotWrappedCorrectly", @"The proof token was not wrapped correctly in the RequestSecurityTokenResponse."); }
        }
        internal static string NoServiceTokenReceived {
              get { return SR.GetResourceString("NoServiceTokenReceived", @"Final RSTR from other party does not contain a service token."); }
        }
        internal static string InvalidSspiNegotiation {
              get { return SR.GetResourceString("InvalidSspiNegotiation", @"The Security Support Provider Interface (SSPI) negotiation failed."); }
        }
        internal static string CannotAuthenticateServer {
              get { return SR.GetResourceString("CannotAuthenticateServer", @"Cannot authenticate the other party."); }
        }
        internal static string IncorrectBinaryNegotiationValueType {
              get { return SR.GetResourceString("IncorrectBinaryNegotiationValueType", @"Incoming binary negotiation has invalid ValueType {0}."); }
        }
        internal static string ChannelNotOpen {
              get { return SR.GetResourceString("ChannelNotOpen", @"The channel is not open."); }
        }
        internal static string FailToRecieveReplyFromNegotiation {
              get { return SR.GetResourceString("FailToRecieveReplyFromNegotiation", @"Security negotiation failed because the remote party did not send back a reply in a timely manner. This may be because the underlying transport connection was aborted."); }
        }
        internal static string MessageSecurityVersionOutOfRange {
              get { return SR.GetResourceString("MessageSecurityVersionOutOfRange", @"SecurityVersion must be WsSecurity10 or WsSecurity11."); }
        }
        internal static string CreationTimeUtcIsAfterExpiryTime {
              get { return SR.GetResourceString("CreationTimeUtcIsAfterExpiryTime", @"Creation time must be before expiration time."); }
        }
        internal static string NegotiationStateAlreadyPresent {
              get { return SR.GetResourceString("NegotiationStateAlreadyPresent", @"Negotiation state already exists for context '{0}'."); }
        }
        internal static string CannotFindNegotiationState {
              get { return SR.GetResourceString("CannotFindNegotiationState", @"Cannot find the negotiation state for the context '{0}'."); }
        }
        internal static string OutputNotExpected {
              get { return SR.GetResourceString("OutputNotExpected", @"Send cannot be called when the session does not expect output."); }
        }
        internal static string SessionClosedBeforeDone {
              get { return SR.GetResourceString("SessionClosedBeforeDone", @"The session was closed before message transfer was complete."); }
        }
        internal static string CacheQuotaReached {
              get { return SR.GetResourceString("CacheQuotaReached", @"The item cannot be added. The maximum cache size is ({0} items)."); }
        }
        internal static string NoServerX509TokenProvider {
              get { return SR.GetResourceString("NoServerX509TokenProvider", @"The server's X509SecurityTokenProvider cannot be null."); }
        }
        internal static string UnexpectedBinarySecretType {
              get { return SR.GetResourceString("UnexpectedBinarySecretType", @"Expected binary secret of type {0} but got secret of type {1}."); }
        }
        internal static string UnsupportedPasswordType {
              get { return SR.GetResourceString("UnsupportedPasswordType", @"The '{0}' username token has an unsupported password type."); }
        }
        internal static string UnrecognizedIdentityPropertyType {
              get { return SR.GetResourceString("UnrecognizedIdentityPropertyType", @"Unrecognized identity property type: '{0}'."); }
        }
        internal static string UnableToDemuxChannel {
              get { return SR.GetResourceString("UnableToDemuxChannel", @"There was no channel that could accept the message with action '{0}'."); }
        }
        internal static string EndpointNotFound {
              get { return SR.GetResourceString("EndpointNotFound", @"There was no endpoint listening at {0} that could accept the message. This is often caused by an incorrect address or SOAP action. See InnerException, if present, for more details."); }
        }
        internal static string MaxReceivedMessageSizeMustBeInIntegerRange {
              get { return SR.GetResourceString("MaxReceivedMessageSizeMustBeInIntegerRange", @"This factory buffers messages, so the message sizes must be in the range of an integer value."); }
        }
        internal static string MaxBufferSizeMustMatchMaxReceivedMessageSize {
              get { return SR.GetResourceString("MaxBufferSizeMustMatchMaxReceivedMessageSize", @"For TransferMode.Buffered, MaxReceivedMessageSize and MaxBufferSize must be the same value."); }
        }
        internal static string MaxBufferSizeMustNotExceedMaxReceivedMessageSize {
              get { return SR.GetResourceString("MaxBufferSizeMustNotExceedMaxReceivedMessageSize", @"MaxBufferSize must not exceed MaxReceivedMessageSize."); }
        }
        internal static string MessageSizeMustBeInIntegerRange {
              get { return SR.GetResourceString("MessageSizeMustBeInIntegerRange", @"This Factory buffers messages, so the message sizes must be in the range of a int value."); }
        }
        internal static string UriLengthExceedsMaxSupportedSize {
              get { return SR.GetResourceString("UriLengthExceedsMaxSupportedSize", @"URI {0} could not be set because its size ({1}) exceeds the max supported size ({2})."); }
        }
        internal static string InValidateIdPrefix {
              get { return SR.GetResourceString("InValidateIdPrefix", @"Expecting first char - c - to be in set [Char.IsLetter(c) && c == '_', found '{0}'."); }
        }
        internal static string InValidateId {
              get { return SR.GetResourceString("InValidateId", @"Expecting all chars - c - of id to be in set [Char.IsLetter(c), Char.IsNumber(c), '.', '_', '-'], found '{0}'."); }
        }
        internal static string HttpRegistrationAlreadyExists {
              get { return SR.GetResourceString("HttpRegistrationAlreadyExists", @"HTTP could not register URL {0}. Another application has already registered this URL with HTTP.SYS."); }
        }
        internal static string HttpRegistrationAccessDenied {
              get { return SR.GetResourceString("HttpRegistrationAccessDenied", @"HTTP could not register URL {0}. Your process does not have access rights to this namespace (see http://go.microsoft.com/fwlink/?LinkId=70353 for details)."); }
        }
        internal static string HttpRegistrationPortInUse {
              get { return SR.GetResourceString("HttpRegistrationPortInUse", @"HTTP could not register URL {0} because TCP port {1} is being used by another application."); }
        }
        internal static string HttpRegistrationLimitExceeded {
              get { return SR.GetResourceString("HttpRegistrationLimitExceeded", @"HTTP could not register URL {0} because the MaxEndpoints quota has been exceeded. To correct this, either close other HTTP-based services, or increase your MaxEndpoints registry key setting (see http://go.microsoft.com/fwlink/?LinkId=70352 for details)."); }
        }
        internal static string UnexpectedHttpResponseCode {
              get { return SR.GetResourceString("UnexpectedHttpResponseCode", @"The remote server returned an unexpected response: ({0}) {1}."); }
        }
        internal static string HttpContentLengthIncorrect {
              get { return SR.GetResourceString("HttpContentLengthIncorrect", @"The number of bytes available is inconsistent with the HTTP Content-Length header.  There may have been a network error or the client may be sending invalid requests."); }
        }
        internal static string OneWayUnexpectedResponse {
              get { return SR.GetResourceString("OneWayUnexpectedResponse", @"A response was received from a one-way send over the underlying IRequestChannel. Make sure the remote endpoint has a compatible binding at its endpoint (one that contains OneWayBindingElement)."); }
        }
        internal static string MissingContentType {
              get { return SR.GetResourceString("MissingContentType", @"The receiver returned an error indicating that the content type was missing on the request to {0}.  See the inner exception for more information."); }
        }
        internal static string DuplexChannelAbortedDuringOpen {
              get { return SR.GetResourceString("DuplexChannelAbortedDuringOpen", @"Duplex channel to {0} was aborted during the open process."); }
        }
        internal static string OperationAbortedDuringConnectionEstablishment {
              get { return SR.GetResourceString("OperationAbortedDuringConnectionEstablishment", @"Operation was aborted while establishing a connection to {0}."); }
        }
        internal static string HttpAddressingNoneHeaderOnWire {
              get { return SR.GetResourceString("HttpAddressingNoneHeaderOnWire", @"The incoming message contains a SOAP header representing the WS-Addressing '{0}', yet the HTTP transport is configured with AddressingVersion.None.  As a result, the message is being dropped.  If this is not desired, then update your HTTP binding to support a different AddressingVersion."); }
        }
        internal static string MessageXmlProtocolError {
              get { return SR.GetResourceString("MessageXmlProtocolError", @"There is a problem with the XML that was received from the network. See inner exception for more details."); }
        }
        internal static string TcpV4AddressInvalid {
              get { return SR.GetResourceString("TcpV4AddressInvalid", @"An IPv4 address was specified ({0}), but IPv4 is not enabled on this machine. "); }
        }
        internal static string TcpV6AddressInvalid {
              get { return SR.GetResourceString("TcpV6AddressInvalid", @"An IPv6 address was specified ({0}), but IPv6 is not enabled on this machine. "); }
        }
        internal static string UniquePortNotAvailable {
              get { return SR.GetResourceString("UniquePortNotAvailable", @"Cannot find a unique port number that is available for both IPv4 and IPv6."); }
        }
        internal static string TcpAddressInUse {
              get { return SR.GetResourceString("TcpAddressInUse", @"There is already a listener on IP endpoint {0}. This could happen if there is another application already listening on this endpoint or if you have multiple service endpoints in your service host with the same IP endpoint but with incompatible binding configurations."); }
        }
        internal static string TcpConnectNoBufs {
              get { return SR.GetResourceString("TcpConnectNoBufs", @"Insufficient winsock resources available to complete socket connection initiation."); }
        }
        internal static string InsufficentMemory {
              get { return SR.GetResourceString("InsufficentMemory", @"Insufficient memory avaliable to complete the operation."); }
        }
        internal static string TcpConnectError {
              get { return SR.GetResourceString("TcpConnectError", @"Could not connect to {0}. TCP error code {1}: {2}. "); }
        }
        internal static string TcpConnectErrorWithTimeSpan {
              get { return SR.GetResourceString("TcpConnectErrorWithTimeSpan", @"Could not connect to {0}. The connection attempt lasted for a time span of {3}. TCP error code {1}: {2}. "); }
        }
        internal static string TcpListenError {
              get { return SR.GetResourceString("TcpListenError", @"A TCP error ({0}: {1}) occurred while listening on IP Endpoint={2}."); }
        }
        internal static string TcpTransferError {
              get { return SR.GetResourceString("TcpTransferError", @"A TCP error ({0}: {1}) occurred while transmitting data."); }
        }
        internal static string TcpTransferErrorWithIP {
              get { return SR.GetResourceString("TcpTransferErrorWithIP", @"A TCP error ({0}: {1}) occurred while transmitting data. The local IP address and port is {2}. The remote IP address and port is {3}."); }
        }
        internal static string TcpLocalConnectionAborted {
              get { return SR.GetResourceString("TcpLocalConnectionAborted", @"The socket connection was aborted by your local machine. This could be caused by a channel Abort(), or a transmission error from another thread using this socket."); }
        }
        internal static string HttpResponseAborted {
              get { return SR.GetResourceString("HttpResponseAborted", @"The HTTP request context was aborted while writing the response.  As a result, the response may not have been completely written to the network.  This can be remedied by gracefully closing the request context rather than aborting it."); }
        }
        internal static string TcpConnectionResetError {
              get { return SR.GetResourceString("TcpConnectionResetError", @"The socket connection was aborted. This could be caused by an error processing your message or a receive timeout being exceeded by the remote host, or an underlying network resource issue. Local socket timeout was '{0}'."); }
        }
        internal static string TcpConnectionResetErrorWithIP {
              get { return SR.GetResourceString("TcpConnectionResetErrorWithIP", @"The socket connection was aborted. This could be caused by an error processing your message or a receive timeout being exceeded by the remote host, or an underlying network resource issue. Local socket timeout was '{0}'. The local IP address and port is {1}. The remote IP address and port is {2}."); }
        }
        internal static string TcpConnectionTimedOut {
              get { return SR.GetResourceString("TcpConnectionTimedOut", @"The socket transfer timed out after {0}. You have exceeded the timeout set on your binding. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string TcpConnectionTimedOutWithIP {
              get { return SR.GetResourceString("TcpConnectionTimedOutWithIP", @"The socket transfer timed out after {0}. You have exceeded the timeout set on your binding. The time allotted to this operation may have been a portion of a longer timeout. The local IP address and port is {1}. The remote IP address and port is {2}."); }
        }
        internal static string SocketConnectionDisposed {
              get { return SR.GetResourceString("SocketConnectionDisposed", @"The socket connection has been disposed."); }
        }
        internal static string SocketListenerDisposed {
              get { return SR.GetResourceString("SocketListenerDisposed", @"The socket listener has been disposed."); }
        }
        internal static string SocketListenerNotListening {
              get { return SR.GetResourceString("SocketListenerNotListening", @"The socket listener is not listening."); }
        }
        internal static string DuplexSessionListenerNotFound {
              get { return SR.GetResourceString("DuplexSessionListenerNotFound", @"No duplex session listener was listening at {0}. This could be due to an incorrect via set on the client or a binding mismatch."); }
        }
        internal static string HttpTargetNameDictionaryConflict {
              get { return SR.GetResourceString("HttpTargetNameDictionaryConflict", @"The entry found in AuthenticationManager's CustomTargetNameDictionary for {0} does not match the requested identity of {1}."); }
        }
        internal static string HttpContentTypeHeaderRequired {
              get { return SR.GetResourceString("HttpContentTypeHeaderRequired", @"An HTTP Content-Type header is required for SOAP messaging and none was found."); }
        }
        internal static string ContentTypeMismatch {
              get { return SR.GetResourceString("ContentTypeMismatch", @"Content Type {0} was sent to a service expecting {1}.  The client and service bindings may be mismatched."); }
        }
        internal static string ResponseContentTypeMismatch {
              get { return SR.GetResourceString("ResponseContentTypeMismatch", @"The content type {0} of the response message does not match the content type of the binding ({1}). If using a custom encoder, be sure that the IsContentTypeSupported method is implemented properly. The first {2} bytes of the response were: '{3}'."); }
        }
        internal static string ResponseContentTypeNotSupported {
              get { return SR.GetResourceString("ResponseContentTypeNotSupported", @"The content type {0} of the message is not supported by the encoder."); }
        }
        internal static string HttpToMustEqualVia {
              get { return SR.GetResourceString("HttpToMustEqualVia", @"The binding specified requires that the to and via URIs must match because the Addressing Version is set to None. The to URI specified was '{0}'. The via URI specified was '{1}'."); }
        }
        internal static string NullReferenceOnHttpResponse {
              get { return SR.GetResourceString("NullReferenceOnHttpResponse", @"The server challenged this request and streamed requests cannot be resubmitted. To enable HTTP server challenges, set your TransferMode to Buffered or StreamedResponse."); }
        }
        internal static string FramingContentTypeMismatch {
              get { return SR.GetResourceString("FramingContentTypeMismatch", @"Content Type {0} was not supported by service {1}.  The client and service bindings may be mismatched."); }
        }
        internal static string FramingFaultUnrecognized {
              get { return SR.GetResourceString("FramingFaultUnrecognized", @"Server faulted with code '{0}'."); }
        }
        internal static string FramingContentTypeTooLongFault {
              get { return SR.GetResourceString("FramingContentTypeTooLongFault", @"Content type '{0}' is too long to be processed by the remote host. See the server logs for more details."); }
        }
        internal static string FramingViaTooLongFault {
              get { return SR.GetResourceString("FramingViaTooLongFault", @"Via '{0}' is too long to be processed by the remote host. See the server logs for more details."); }
        }
        internal static string FramingModeNotSupportedFault {
              get { return SR.GetResourceString("FramingModeNotSupportedFault", @"The .Net Framing mode being used is not supported by '{0}'. See the server logs for more details."); }
        }
        internal static string FramingVersionNotSupportedFault {
              get { return SR.GetResourceString("FramingVersionNotSupportedFault", @"The .Net Framing version being used is not supported by '{0}'. See the server logs for more details."); }
        }
        internal static string FramingUpgradeInvalid {
              get { return SR.GetResourceString("FramingUpgradeInvalid", @"The requested upgrade is not supported by '{0}'. This could be due to mismatched bindings (for example security enabled on the client and not on the server)."); }
        }
        internal static string SecurityServerTooBusy {
              get { return SR.GetResourceString("SecurityServerTooBusy", @"Server '{0}' sent back a fault indicating it is too busy to process the request. Please retry later. Please see the inner exception for fault details."); }
        }
        internal static string SecurityEndpointNotFound {
              get { return SR.GetResourceString("SecurityEndpointNotFound", @"Server '{0}' sent back a fault indicating it is in the process of shutting down. Please see the inner exception for fault details."); }
        }
        internal static string ServerTooBusy {
              get { return SR.GetResourceString("ServerTooBusy", @"Server '{0}' is too busy to process this request. Try again later."); }
        }
        internal static string UpgradeProtocolNotSupported {
              get { return SR.GetResourceString("UpgradeProtocolNotSupported", @"Protocol Type {0} was sent to a service that does not support that type of upgrade."); }
        }
        internal static string UpgradeRequestToNonupgradableService {
              get { return SR.GetResourceString("UpgradeRequestToNonupgradableService", @".Net Framing upgrade request for {0} was sent to a service that is not setup to receive upgrades."); }
        }
        internal static string PreambleAckIncorrect {
              get { return SR.GetResourceString("PreambleAckIncorrect", @"You have tried to create a channel to a service that does not support .Net Framing. "); }
        }
        internal static string PreambleAckIncorrectMaybeHttp {
              get { return SR.GetResourceString("PreambleAckIncorrectMaybeHttp", @"You have tried to create a channel to a service that does not support .Net Framing. It is possible that you are encountering an HTTP endpoint."); }
        }
        internal static string StreamError {
              get { return SR.GetResourceString("StreamError", @"An error occurred while transmitting data."); }
        }
        internal static string ServerRejectedUpgradeRequest {
              get { return SR.GetResourceString("ServerRejectedUpgradeRequest", @"The server rejected the upgrade request."); }
        }
        internal static string ServerRejectedSessionPreamble {
              get { return SR.GetResourceString("ServerRejectedSessionPreamble", @"The server at {0} rejected the session-establishment request."); }
        }
        internal static string UnableToResolveHost {
              get { return SR.GetResourceString("UnableToResolveHost", @"Cannot resolve the host name of URI \""{0}\"" using DNS."); }
        }
        internal static string HttpRequiresSingleAuthScheme {
              get { return SR.GetResourceString("HttpRequiresSingleAuthScheme", @"The '{0}' authentication scheme has been specified on the HTTP factory. However, the factory only supports specification of exactly one authentication scheme. Valid authentication schemes are Digest, Negotiate, NTLM, Basic, or Anonymous."); }
        }
        internal static string HttpAuthSchemeCannotBeNone {
              get { return SR.GetResourceString("HttpAuthSchemeCannotBeNone", @"The value specified for the AuthenticationScheme property on the HttpTransportBindingElement ('{0}') is not allowed when building a ChannelFactory. If you used a standard binding, ensure the ClientCredentialType is not set to HttpClientCredentialType.InheritedFromHost, a value which is invalid on a client. If you set the value to '{0}' directly on the HttpTransportBindingElement, please set it to Digest, Negotiate, NTLM, Basic, or Anonymous."); }
        }
        internal static string HttpProxyRequiresSingleAuthScheme {
              get { return SR.GetResourceString("HttpProxyRequiresSingleAuthScheme", @"The '{0}' authentication scheme has been specified for the proxy on the HTTP factory. However, the factory only supports specification of exactly one authentication scheme. Valid authentication schemes are Digest, Negotiate, NTLM, Basic, or Anonymous."); }
        }
        internal static string HttpMutualAuthNotSatisfied {
              get { return SR.GetResourceString("HttpMutualAuthNotSatisfied", @"The remote HTTP server did not satisfy the mutual authentication requirement."); }
        }
        internal static string HttpAuthorizationFailed {
              get { return SR.GetResourceString("HttpAuthorizationFailed", @"The HTTP request is unauthorized with client authentication scheme '{0}'. The authentication header received from the server was '{1}'."); }
        }
        internal static string HttpAuthenticationFailed {
              get { return SR.GetResourceString("HttpAuthenticationFailed", @"The HTTP request with client authentication scheme '{0}' failed with '{1}' status."); }
        }
        internal static string HttpAuthorizationForbidden {
              get { return SR.GetResourceString("HttpAuthorizationForbidden", @"The HTTP request was forbidden with client authentication scheme '{0}'."); }
        }
        internal static string InvalidUriScheme {
              get { return SR.GetResourceString("InvalidUriScheme", @"The provided URI scheme '{0}' is invalid; expected '{1}'."); }
        }
        internal static string HttpAuthSchemeAndClientCert {
              get { return SR.GetResourceString("HttpAuthSchemeAndClientCert", @"The HTTPS listener factory was configured to require a client certificate and the '{0}' authentication scheme. However, only one form of client authentication can be required at once."); }
        }
        internal static string NoTransportManagerForUri {
              get { return SR.GetResourceString("NoTransportManagerForUri", @"Could not find an appropriate transport manager for listen URI '{0}'."); }
        }
        internal static string ListenerFactoryNotRegistered {
              get { return SR.GetResourceString("ListenerFactoryNotRegistered", @"The specified channel listener at '{0}' is not registered with this transport manager."); }
        }
        internal static string HttpsExplicitIdentity {
              get { return SR.GetResourceString("HttpsExplicitIdentity", @"The HTTPS channel factory does not support explicit specification of an identity in the EndpointAddress unless the authentication scheme is NTLM or Negotiate."); }
        }
        internal static string HttpsIdentityMultipleCerts {
              get { return SR.GetResourceString("HttpsIdentityMultipleCerts", @"The endpoint identity specified when creating the HTTPS channel to '{0}' contains multiple server certificates.  However, the HTTPS transport only supports the specification of a single server certificate.  In order to create an HTTPS channel, please specify no more than one server certificate in the endpoint identity."); }
        }
        internal static string HttpsServerCertThumbprintMismatch {
              get { return SR.GetResourceString("HttpsServerCertThumbprintMismatch", @"The server certificate with name '{0}' failed identity verification because its thumbprint ('{1}') does not match the one specified in the endpoint identity ('{2}').  As a result, the current HTTPS request has failed.  Please update the endpoint identity used on the client or the certificate used by the server."); }
        }
        internal static string DuplicateRegistration {
              get { return SR.GetResourceString("DuplicateRegistration", @"A registration already exists for URI '{0}'."); }
        }
        internal static string SecureChannelFailure {
              get { return SR.GetResourceString("SecureChannelFailure", @"Could not establish secure channel for SSL/TLS with authority '{0}'."); }
        }
        internal static string TrustFailure {
              get { return SR.GetResourceString("TrustFailure", @"Could not establish trust relationship for the SSL/TLS secure channel with authority '{0}'."); }
        }
        internal static string NoCompatibleTransportManagerForUri {
              get { return SR.GetResourceString("NoCompatibleTransportManagerForUri", @"Could not find a compatible transport manager for URI '{0}'."); }
        }
        internal static string HttpSpnNotFound {
              get { return SR.GetResourceString("HttpSpnNotFound", @"The SPN for the responding server at URI '{0}' could not be determined."); }
        }
        internal static string StreamMutualAuthNotSatisfied {
              get { return SR.GetResourceString("StreamMutualAuthNotSatisfied", @"The remote server did not satisfy the mutual authentication requirement."); }
        }
        internal static string TransferModeNotSupported {
              get { return SR.GetResourceString("TransferModeNotSupported", @"Transfer mode {0} is not supported by {1}."); }
        }
        internal static string InvalidTokenProvided {
              get { return SR.GetResourceString("InvalidTokenProvided", @"The token provider of type '{0}' did not return a token of type '{1}'. Check the credential configuration."); }
        }
        internal static string NoUserNameTokenProvided {
              get { return SR.GetResourceString("NoUserNameTokenProvided", @"The required UserNameSecurityToken was not provided."); }
        }
        internal static string RemoteIdentityFailedVerification {
              get { return SR.GetResourceString("RemoteIdentityFailedVerification", @"The following remote identity failed verification: '{0}'."); }
        }
        internal static string UseDefaultWebProxyCantBeUsedWithExplicitProxyAddress {
              get { return SR.GetResourceString("UseDefaultWebProxyCantBeUsedWithExplicitProxyAddress", @"You cannot specify an explicit Proxy Address as well as UseDefaultWebProxy=true in your HTTP Transport Binding Element."); }
        }
        internal static string ProxyImpersonationLevelMismatch {
              get { return SR.GetResourceString("ProxyImpersonationLevelMismatch", @"The HTTP proxy authentication credential specified an impersonation level restriction ({0}) that is stricter than the restriction for target server authentication ({1})."); }
        }
        internal static string ProxyAuthenticationLevelMismatch {
              get { return SR.GetResourceString("ProxyAuthenticationLevelMismatch", @"The HTTP proxy authentication credential specified an mutual authentication requirement ({0}) that is stricter than the requirement for target server authentication ({1})."); }
        }
        internal static string CredentialDisallowsNtlm {
              get { return SR.GetResourceString("CredentialDisallowsNtlm", @"The NTLM authentication scheme was specified, but the target credential does not allow NTLM."); }
        }
        internal static string DigestExplicitCredsImpersonationLevel {
              get { return SR.GetResourceString("DigestExplicitCredsImpersonationLevel", @"The impersonation level '{0}' was specified, yet HTTP Digest authentication can only support 'Impersonation' level when used with an explicit credential."); }
        }
        internal static string UriGeneratorSchemeMustNotBeEmpty {
              get { return SR.GetResourceString("UriGeneratorSchemeMustNotBeEmpty", @"The scheme parameter must not be empty."); }
        }
        internal static string UnsupportedSslProtectionLevel {
              get { return SR.GetResourceString("UnsupportedSslProtectionLevel", @"The protection level '{0}' was specified, yet SSL transport security only supports EncryptAndSign."); }
        }
        internal static string HttpNoTrackingService {
              get { return SR.GetResourceString("HttpNoTrackingService", @"{0}. This often indicates that a service that HTTP.SYS depends upon (such as httpfilter) is not started."); }
        }
        internal static string HttpNetnameDeleted {
              get { return SR.GetResourceString("HttpNetnameDeleted", @"{0}. This often indicates that the HTTP client has prematurely closed the underlying TCP connection."); }
        }
        internal static string TimeoutServiceChannelConcurrentOpen1 {
              get { return SR.GetResourceString("TimeoutServiceChannelConcurrentOpen1", @"Opening the channel timed out after {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string TimeoutServiceChannelConcurrentOpen2 {
              get { return SR.GetResourceString("TimeoutServiceChannelConcurrentOpen2", @"Opening the {0} channel timed out after {1}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string TimeSpanMustbeGreaterThanTimeSpanZero {
              get { return SR.GetResourceString("TimeSpanMustbeGreaterThanTimeSpanZero", @"TimeSpan must be greater than TimeSpan.Zero."); }
        }
        internal static string TimeSpanCannotBeLessThanTimeSpanZero {
              get { return SR.GetResourceString("TimeSpanCannotBeLessThanTimeSpanZero", @"TimeSpan cannot be less than TimeSpan.Zero."); }
        }
        internal static string ValueMustBeNonNegative {
              get { return SR.GetResourceString("ValueMustBeNonNegative", @"The value of this argument must be non-negative."); }
        }
        internal static string ValueMustBePositive {
              get { return SR.GetResourceString("ValueMustBePositive", @"The value of this argument must be positive."); }
        }
        internal static string ValueMustBeGreaterThanZero {
              get { return SR.GetResourceString("ValueMustBeGreaterThanZero", @"The value of this argument must be greater than 0."); }
        }
        internal static string ValueMustBeInRange {
              get { return SR.GetResourceString("ValueMustBeInRange", @"The value of this argument must fall within the range {0} to {1}."); }
        }
        internal static string OffsetExceedsBufferBound {
              get { return SR.GetResourceString("OffsetExceedsBufferBound", @"The specified offset exceeds the upper bound of the buffer ({0})."); }
        }
        internal static string OffsetExceedsBufferSize {
              get { return SR.GetResourceString("OffsetExceedsBufferSize", @"The specified offset exceeds the buffer size ({0} bytes)."); }
        }
        internal static string SizeExceedsRemainingBufferSpace {
              get { return SR.GetResourceString("SizeExceedsRemainingBufferSpace", @"The specified size exceeds the remaining buffer space ({0} bytes)."); }
        }
        internal static string SpaceNeededExceedsMessageFrameOffset {
              get { return SR.GetResourceString("SpaceNeededExceedsMessageFrameOffset", @"The space needed for encoding ({0} bytes) exceeds the message frame offset."); }
        }
        internal static string FaultConverterDidNotCreateFaultMessage {
              get { return SR.GetResourceString("FaultConverterDidNotCreateFaultMessage", @"{0} returned true from OnTryCreateFaultMessage, but did not return a fault message."); }
        }
        internal static string FaultConverterCreatedFaultMessage {
              get { return SR.GetResourceString("FaultConverterCreatedFaultMessage", @"{0} returned false from OnTryCreateFaultMessage, but returned a non-null fault message."); }
        }
        internal static string FaultConverterDidNotCreateException {
              get { return SR.GetResourceString("FaultConverterDidNotCreateException", @"{0} returned true from OnTryCreateException, but did not return an Exception."); }
        }
        internal static string FaultConverterCreatedException {
              get { return SR.GetResourceString("FaultConverterCreatedException", @"{0} returned false from OnTryCreateException, but returned a non-null Exception (See InnerException for details)."); }
        }
        internal static string InfoCardInvalidChain {
              get { return SR.GetResourceString("InfoCardInvalidChain", @"Policy chain contains self issued URI or a managed issuer in the wrong position."); }
        }
        internal static string FullTrustOnlyBindingElementSecurityCheck1 {
              get { return SR.GetResourceString("FullTrustOnlyBindingElementSecurityCheck1", @"The Binding with name {0} failed validation because it contains a BindingElement with type {1} which is not supported in partial trust. Consider using BasicHttpBinding or WSHttpBinding, or hosting your application in a full-trust environment."); }
        }
        internal static string FullTrustOnlyBindingElementSecurityCheckWSHttpBinding1 {
              get { return SR.GetResourceString("FullTrustOnlyBindingElementSecurityCheckWSHttpBinding1", @"The WSHttpBinding with name {0} failed validation because it contains a BindingElement with type {1} which is not supported in partial trust. Consider disabling the message security and reliable session options, using BasicHttpBinding, or hosting your application in a full-trust environment."); }
        }
        internal static string FullTrustOnlyBindingSecurityCheck1 {
              get { return SR.GetResourceString("FullTrustOnlyBindingSecurityCheck1", @"The Binding with name {0} failed validation because the Binding type {1} is not supported in partial trust. Consider using BasicHttpBinding or WSHttpBinding, or hosting your application in a full-trust environment."); }
        }
        internal static string PartialTrustServiceCtorNotVisible {
              get { return SR.GetResourceString("PartialTrustServiceCtorNotVisible", @"The Service with name '{0}' could not be constructed because the application does not have permission to construct the type: both the Type and its default parameter-less constructor must be public."); }
        }
        internal static string PartialTrustServiceMethodNotVisible {
              get { return SR.GetResourceString("PartialTrustServiceMethodNotVisible", @"The Method with name '{1}' in Type '{0}' could not be invoked because the application does not have permission to invoke the method: both the Method and its containing Type must be public."); }
        }
        internal static string PartialTrustPerformanceCountersNotEnabled {
              get { return SR.GetResourceString("PartialTrustPerformanceCountersNotEnabled", @"Access to performance counters is denied. Application may be running in partial trust. Either disable performance counters or configure the application to run in full trust."); }
        }
        internal static string PartialTrustWMINotEnabled {
              get { return SR.GetResourceString("PartialTrustWMINotEnabled", @"Access to windows management instrumentation (WMI) is denied. Application may be running in partial trust. Either disable WMI or configure the application to run in full trust."); }
        }
        internal static string PartialTrustMessageLoggingNotEnabled {
              get { return SR.GetResourceString("PartialTrustMessageLoggingNotEnabled", @"Unable to log messages. Application may be running in partial trust. Either disable message logging or configure the application to run in full trust."); }
        }
        internal static string ScopeNameMustBeSpecified {
              get { return SR.GetResourceString("ScopeNameMustBeSpecified", @"The 'scopeName' argument to the InstanceKey constructor must be a non-empty string which indicates the scope of uniqueness for the key. Durable services use the service namespace and name as the scope of uniqueness."); }
        }
        internal static string ProviderCannotBeEmptyString {
              get { return SR.GetResourceString("ProviderCannotBeEmptyString", @"The 'provider' argument to the InstanceKey constructor must be a non-empty string which identifies the source of the key data. The 'provider' argument can be null, in which case the default correlation provider name is used."); }
        }
        internal static string CannotSetNameOnTheInvalidKey {
              get { return SR.GetResourceString("CannotSetNameOnTheInvalidKey", @"The 'Name' property cannot be set on an invalid InstanceKey."); }
        }
        internal static string UnsupportedMessageQueryResultType {
              get { return SR.GetResourceString("UnsupportedMessageQueryResultType", @"The type {0} is not a supported result type."); }
        }
        internal static string CannotRepresentResultAsNodeset {
              get { return SR.GetResourceString("CannotRepresentResultAsNodeset", @"The result cannot be represented as a nodeset. Only results of type XPathResultType.NodeSet can be represented as nodesets."); }
        }
        internal static string MessageNotInLockedState {
              get { return SR.GetResourceString("MessageNotInLockedState", @"Message with id {0} was not in a locked state."); }
        }
        internal static string MessageValidityExpired {
              get { return SR.GetResourceString("MessageValidityExpired", @"Validity of message with id {0} has expired."); }
        }
        internal static string UnsupportedUpgradeInitiator {
              get { return SR.GetResourceString("UnsupportedUpgradeInitiator", @"The StreamUpgradeInitiator specified ({0}) is not supported by this IStreamUpgradeChannelBindingProvider  implementation.  The most likely cause of this is passing a StreamUpgradeInitiator that was not created by the StreamUpgradeProvider associated with the current IStreamUpgradeChannelBindingProvider  implementation."); }
        }
        internal static string UnsupportedUpgradeAcceptor {
              get { return SR.GetResourceString("UnsupportedUpgradeAcceptor", @"The StreamUpgradeAcceptor specified ({0}) is not supported by this IStreamUpgradeChannelBindingProvider  implementation.  The most likely cause of this is passing a StreamUpgradeAcceptor that was not created by the StreamUpgradeProvider associated with this IStreamUpgradeChannelBindingProvider  implementation."); }
        }
        internal static string StreamUpgradeUnsupportedChannelBindingKind {
              get { return SR.GetResourceString("StreamUpgradeUnsupportedChannelBindingKind", @"The StreamUpgradeProvider {0} does not support the specified ChannelBindingKind ({1}). "); }
        }
        internal static string ExtendedProtectionNotSupported {
              get { return SR.GetResourceString("ExtendedProtectionNotSupported", @"Extended protection is not supported on this platform.  Please install the appropriate patch or change the ExtendedProtectionPolicy on the Binding or BindingElement to a value with a PolicyEnforcement value of \""Never\"" or \""WhenSupported\""."); }
        }
        internal static string ExtendedProtectionPolicyBasicAuthNotSupported {
              get { return SR.GetResourceString("ExtendedProtectionPolicyBasicAuthNotSupported", @"The Authentication Scheme \""Basic\"" does not support Extended Protection.  Please use a different authentication scheme or disable the ExtendedProtectionPolicy on the Binding or BindingElement by creating a new ExtendedProtectionPolicy with a PolicyEnforcement value of \""Never\""."); }
        }
        internal static string ExtendedProtectionPolicyCustomChannelBindingNotSupported {
              get { return SR.GetResourceString("ExtendedProtectionPolicyCustomChannelBindingNotSupported", @"CustomChannelBindings are not supported.  Please remove the CustomChannelBinding from the ExtendedProtectionPolicy\""."); }
        }
        internal static string HttpClientCredentialTypeInvalid {
              get { return SR.GetResourceString("HttpClientCredentialTypeInvalid", @"ClientCredentialType '{0}' can only be used on the server side, not the client side. Please use one of the following values instead 'None, Basic, Client, Digest, Ntlm, Windows'."); }
        }
        internal static string SecurityTokenProviderIncludeWindowsGroupsInconsistent {
              get { return SR.GetResourceString("SecurityTokenProviderIncludeWindowsGroupsInconsistent", @"When authentication schemes 'Basic' and also '{0}' are enabled, the value of IncludeWindowsGroups for Windows ('{1}') and UserName authentication ('{2}') must match. Please consider using the same value in both places."); }
        }
        internal static string AuthenticationSchemesCannotBeInheritedFromHost {
              get { return SR.GetResourceString("AuthenticationSchemesCannotBeInheritedFromHost", @"The authentication schemes cannot be inherited from the host for binding '{0}'. No AuthenticationScheme was specified on the ServiceHost or in the virtual application in IIS. This may be resolved by enabling at least one authentication scheme for this virtual application in IIS, through the ServiceHost.Authentication.AuthenticationSchemes property or in the configuration at the <serviceAuthenticationManager> element."); }
        }
        internal static string AuthenticationSchemes_BindingAndHostConflict {
              get { return SR.GetResourceString("AuthenticationSchemes_BindingAndHostConflict", @"The authentication schemes configured on the host ('{0}') do not allow those configured on the binding '{1}' ('{2}').  Please ensure that the SecurityMode is set to Transport or TransportCredentialOnly.  Additionally, this may be resolved by changing the authentication schemes for this application through the IIS management tool, through the ServiceHost.Authentication.AuthenticationSchemes property, in the application configuration file at the <serviceAuthenticationManager> element, by updating the ClientCredentialType property on the binding, or by adjusting the AuthenticationScheme property on the HttpTransportBindingElement."); }
        }
        internal static string FlagEnumTypeExpected {
              get { return SR.GetResourceString("FlagEnumTypeExpected", @"Object type must be an enum with the flag attribute. '{0}' is not an enum - or the flag attribute is not set. Please use an enum type with the flag attribute instead."); }
        }
        internal static string InvalidFlagEnumType {
              get { return SR.GetResourceString("InvalidFlagEnumType", @"Object type must be an enum with the flag attribute and may only contain powers of two for the flags enum values or a combination of such values. Please use an enum type according to these rules."); }
        }
        internal static string NoAsyncWritePending {
              get { return SR.GetResourceString("NoAsyncWritePending", @"There is no pending asynchronous write on this stream. Ensure that there is pending write on the stream or verify that the implementation does not try to complete the same operation multiple times."); }
        }
        internal static string FlushBufferAlreadyInUse {
              get { return SR.GetResourceString("FlushBufferAlreadyInUse", @"Cannot write to a buffer which is currently being flushed. "); }
        }
        internal static string WriteAsyncWithoutFreeBuffer {
              get { return SR.GetResourceString("WriteAsyncWithoutFreeBuffer", @"An asynchronous write was called on the stream without a free buffer."); }
        }
        internal static string TransportDoesNotSupportCompression {
              get { return SR.GetResourceString("TransportDoesNotSupportCompression", @"The transport configured on this binding does not appear to support the CompressionFormat specified ({0}) on the message encoder.  To resolve this issue, set the CompressionFormat on the {1} to '{2}' or use a different transport."); }
        }
        internal static string UnsupportedSecuritySetting {
              get { return SR.GetResourceString("UnsupportedSecuritySetting", @"The value '{1}' is not supported in this context for the binding security property '{0}'."); }
        }
        internal static string UnsupportedBindingProperty {
              get { return SR.GetResourceString("UnsupportedBindingProperty", @"The value '{1}' is not supported in this context for the binding property '{0}'."); }
        }
        internal static string HttpMaxPendingAcceptsTooLargeError {
              get { return SR.GetResourceString("HttpMaxPendingAcceptsTooLargeError", @"The value of MaxPendingAccepts should not be larger than {0}."); }
        }
        internal static string RequestInitializationTimeoutReached {
              get { return SR.GetResourceString("RequestInitializationTimeoutReached", @"The initialization process of the request message timed out after {0}. To increase this quota, use the '{1}' property on the '{2}'."); }
        }
        internal static string UnsupportedTokenImpersonationLevel {
              get { return SR.GetResourceString("UnsupportedTokenImpersonationLevel", @"The value '{1}' for the '{0}' property is not supported in Windows Store apps."); }
        }
        internal static string AcksToMustBeSameAsRemoteAddress {
              get { return SR.GetResourceString("AcksToMustBeSameAsRemoteAddress", @"The remote endpoint requested an address for acknowledgements that is not the same as the address for application messages. The channel could not be opened because this is not supported. Ensure the endpoint address used to create the channel is identical to the one the remote endpoint was set up with."); }
        }
        internal static string AcksToMustBeSameAsRemoteAddressReason {
              get { return SR.GetResourceString("AcksToMustBeSameAsRemoteAddressReason", @"The address for acknowledgements must be the same as the address for application messages. Verify that your endpoint is configured to use the same URI for these two addresses."); }
        }
        internal static string AssertionNotSupported {
              get { return SR.GetResourceString("AssertionNotSupported", @"The {0}:{1} assertion is not supported."); }
        }
        internal static string ConflictingOffer {
              get { return SR.GetResourceString("ConflictingOffer", @"The remote endpoint sent conflicting requests to create a reliable session. The remote endpoint requested both a one way and a two way session. The reliable session has been faulted."); }
        }
        internal static string CouldNotParseWithAction {
              get { return SR.GetResourceString("CouldNotParseWithAction", @"A message with action {0} could not be parsed."); }
        }
        internal static string CSRefusedDuplexNoOffer {
              get { return SR.GetResourceString("CSRefusedDuplexNoOffer", @"The endpoint at {0} processes duplex sessions. The create sequence request must contain an offer for a return sequence. This is likely caused by a binding mismatch."); }
        }
        internal static string CSRefusedInputOffer {
              get { return SR.GetResourceString("CSRefusedInputOffer", @"The endpoint at {0} processes input sessions. The create sequence request must not contain an offer for a return sequence. This is likely caused by a binding mismatch."); }
        }
        internal static string CSRefusedReplyNoOffer {
              get { return SR.GetResourceString("CSRefusedReplyNoOffer", @"The endpoint at {0} processes reply sessions. The create sequence request must contain an offer for a return sequence. This is likely caused by a binding mismatch."); }
        }
        internal static string CSRefusedUnexpectedElementAtEndOfCSMessage {
              get { return SR.GetResourceString("CSRefusedUnexpectedElementAtEndOfCSMessage", @"The message is not a valid SOAP message. The body contains more than 1 root element."); }
        }
        internal static string CSResponseOfferRejected {
              get { return SR.GetResourceString("CSResponseOfferRejected", @"The remote endpoint replied to a request for a two way session with an offer for a one way session. This is likely caused by a binding mismatch. The channel could not be opened."); }
        }
        internal static string CSResponseOfferRejectedReason {
              get { return SR.GetResourceString("CSResponseOfferRejectedReason", @"The client requested creation of a two way session. A one way session was created. The session cannot continue without as a one way session. This is likely caused by a binding mismatch."); }
        }
        internal static string CSResponseWithOfferReason {
              get { return SR.GetResourceString("CSResponseWithOfferReason", @"A return sequence was not offered by the create sequence request. The create sequence response cannot accept a return sequence."); }
        }
        internal static string CSResponseWithoutOfferReason {
              get { return SR.GetResourceString("CSResponseWithoutOfferReason", @"A return sequence was offered by the create sequence request but the create sequence response did not accept this sequence."); }
        }
        internal static string DeliveryAssuranceRequiredNothingFound {
              get { return SR.GetResourceString("DeliveryAssuranceRequiredNothingFound", @"The WS-RM policy under the namespace {0} requires the wsrmp:ExactlyOnce, wsrmp:AtLeastOnce, or wsrmp:AtMostOnce assertion. Nothing was found."); }
        }
        internal static string DeliveryAssuranceRequired {
              get { return SR.GetResourceString("DeliveryAssuranceRequired", @"The WS-RM policy under the namespace {0} requires the wsrmp:ExactlyOnce, wsrmp:AtLeastOnce, or wsrmp:AtMostOnce assertion. The {1} element under the {2} namespace was found."); }
        }
        internal static string EarlyTerminateSequence {
              get { return SR.GetResourceString("EarlyTerminateSequence", @"The remote endpoint has errantly sent a TerminateSequence protocol message before the sequence finished."); }
        }
        internal static string ElementFound {
              get { return SR.GetResourceString("ElementFound", @"The {0}:{1} element requires a {2}:{3} child element but has the {4} child element under the {5} namespace."); }
        }
        internal static string ElementRequired {
              get { return SR.GetResourceString("ElementRequired", @"The {0}:{1} element requires a {2}:{3} child element but has no child elements."); }
        }
        internal static string InvalidAcknowledgementFaultReason {
              get { return SR.GetResourceString("InvalidAcknowledgementFaultReason", @"The SequenceAcknowledgement violates the cumulative acknowledgement invariant."); }
        }
        internal static string InvalidWsrmResponseChannelNotOpened {
              get { return SR.GetResourceString("InvalidWsrmResponseChannelNotOpened", @"The remote endpoint responded to the {0} request with a response with action {1}. The response must be a {0}Response with action {2}. The channel could not be opened."); }
        }
        internal static string InvalidWsrmResponseSessionFaultedExceptionString {
              get { return SR.GetResourceString("InvalidWsrmResponseSessionFaultedExceptionString", @"The remote endpoint responded to the {0} request with a response with action {1}. The response must be a {0}Response with action {2}. The channel was faulted."); }
        }
        internal static string LastMessageNumberExceededFaultReason {
              get { return SR.GetResourceString("LastMessageNumberExceededFaultReason", @"The value for wsrm:MessageNumber exceeds the value of the MessageNumber accompanying a LastMessage element in this Sequence."); }
        }
        internal static string ManualAddressingNotSupported {
              get { return SR.GetResourceString("ManualAddressingNotSupported", @"Binding validation failed because the TransportBindingElement's ManualAddressing property was set to true on a binding that is configured to create reliable sessions. This combination is not supported and the channel factory or service host was not opened."); }
        }
        internal static string MessageExceptionOccurred {
              get { return SR.GetResourceString("MessageExceptionOccurred", @"A problem occurred while reading a message. See inner exception for details."); }
        }
        internal static string MessageNumberRolloverFaultReason {
              get { return SR.GetResourceString("MessageNumberRolloverFaultReason", @"The maximum value for wsrm:MessageNumber has been exceeded."); }
        }
        internal static string MissingMessageIdOnWsrmRequest {
              get { return SR.GetResourceString("MissingMessageIdOnWsrmRequest", @"The wsa:MessageId header must be present on a wsrm:{0} message."); }
        }
        internal static string MissingReplyToOnWsrmRequest {
              get { return SR.GetResourceString("MissingReplyToOnWsrmRequest", @"The wsa:ReplyTo header must be present on a wsrm:{0} message."); }
        }
        internal static string NonWsrmFeb2005ActionNotSupported {
              get { return SR.GetResourceString("NonWsrmFeb2005ActionNotSupported", @"The action {0} is not supported by this endpoint. Only WS-ReliableMessaging February 2005 messages are processed by this endpoint."); }
        }
        internal static string ReceivedResponseBeforeRequestFaultString {
              get { return SR.GetResourceString("ReceivedResponseBeforeRequestFaultString", @"The {0}Response was received when the {0} request had not been sent. This is a WS-ReliableMessaging protocol violation. The reliable session cannot continue."); }
        }
        internal static string RMEndpointNotFoundReason {
              get { return SR.GetResourceString("RMEndpointNotFoundReason", @"The endpoint at {0} has stopped accepting wsrm sessions."); }
        }
        internal static string SequenceClosedFaultString {
              get { return SR.GetResourceString("SequenceClosedFaultString", @"The Sequence is closed and cannot accept new messages."); }
        }
        internal static string SequenceTerminatedAddLastToWindowTimedOut {
              get { return SR.GetResourceString("SequenceTerminatedAddLastToWindowTimedOut", @"The RM Source could not transfer the last message within the timeout the user specified."); }
        }
        internal static string SequenceTerminatedBeforeReplySequenceAcked {
              get { return SR.GetResourceString("SequenceTerminatedBeforeReplySequenceAcked", @"The server received a TerminateSequence message before all reply sequence messages were acknowledged. This is a violation of the reply sequence acknowledgement protocol."); }
        }
        internal static string SequenceTerminatedEarlyTerminateSequence {
              get { return SR.GetResourceString("SequenceTerminatedEarlyTerminateSequence", @"The wsrm:TerminateSequence protocol message was transmitted before the sequence was successfully completed."); }
        }
        internal static string SequenceTerminatedInactivityTimeoutExceeded {
              get { return SR.GetResourceString("SequenceTerminatedInactivityTimeoutExceeded", @"The inactivity timeout of ({0}) has been exceeded."); }
        }
        internal static string SequenceTerminatedMaximumRetryCountExceeded {
              get { return SR.GetResourceString("SequenceTerminatedMaximumRetryCountExceeded", @"The user specified maximum retry count for a particular message has been exceeded. Because of this the reliable session cannot continue."); }
        }
        internal static string SequenceTerminatedQuotaExceededException {
              get { return SR.GetResourceString("SequenceTerminatedQuotaExceededException", @"The necessary size to buffer a sequence message has exceeded the configured buffer quota. Because of this the reliable session cannot continue."); }
        }
        internal static string SequenceTerminatedReplyMissingAcknowledgement {
              get { return SR.GetResourceString("SequenceTerminatedReplyMissingAcknowledgement", @"A reply message was received with no acknowledgement."); }
        }
        internal static string SequenceTerminatedNotAllRepliesAcknowledged {
              get { return SR.GetResourceString("SequenceTerminatedNotAllRepliesAcknowledged", @"All of the reply sequence's messages must be acknowledged prior to closing the request sequence. This is a violation of the reply sequence's delivery guarantee. The session cannot continue."); }
        }
        internal static string SequenceTerminatedSmallLastMsgNumber {
              get { return SR.GetResourceString("SequenceTerminatedSmallLastMsgNumber", @"The wsrm:LastMsgNumber value is too small. A message with a larger sequence number has already been received."); }
        }
        internal static string SequenceTerminatedUnexpectedAcknowledgement {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedAcknowledgement", @"The RM destination received an acknowledgement message. The RM destination does not process acknowledgement messages."); }
        }
        internal static string SequenceTerminatedUnexpectedAckRequested {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedAckRequested", @"The RM source received an AckRequested message. The RM source does not process AckRequested messages."); }
        }
        internal static string SequenceTerminatedUnexpectedCloseSequence {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCloseSequence", @"The RM source received an CloseSequence message. The RM source does not process CloseSequence messages."); }
        }
        internal static string SequenceTerminatedUnexpectedCloseSequenceResponse {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCloseSequenceResponse", @"The RM destination received an CloseSequenceResponse message. The RM destination does not process CloseSequenceResponse messages."); }
        }
        internal static string SequenceTerminatedUnexpectedCS {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCS", @"The RM source received a CreateSequence request. The RM source does not process CreateSequence requests."); }
        }
        internal static string SequenceTerminatedUnexpectedCSOfferId {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCSOfferId", @"The RM destination received multiple CreateSequence requests with different OfferId values over the same session."); }
        }
        internal static string SequenceTerminatedUnexpectedCSR {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCSR", @"The RM destination received a CreateSequenceResponse message. The RM destination does not process CreateSequenceResponse messages."); }
        }
        internal static string SequenceTerminatedUnexpectedCSROfferId {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedCSROfferId", @"The RM source received multiple CreateSequenceResponse messages with different sequence identifiers over the same session."); }
        }
        internal static string SequenceTerminatedUnexpectedTerminateSequence {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedTerminateSequence", @"The RM source received a TerminateSequence message. The RM source does not process TerminateSequence messages."); }
        }
        internal static string SequenceTerminatedUnexpectedTerminateSequenceResponse {
              get { return SR.GetResourceString("SequenceTerminatedUnexpectedTerminateSequenceResponse", @"The RM destination received a TerminateSequenceResponse message. The RM destination does not process TerminateSequenceResponse messages."); }
        }
        internal static string SequenceTerminatedUnsupportedTerminateSequence {
              get { return SR.GetResourceString("SequenceTerminatedUnsupportedTerminateSequence", @"The RM source does not support an RM destination initiated termination since messages can be lost. The reliable session cannot continue."); }
        }
        internal static string SequenceTerminatedUnknownAddToWindowError {
              get { return SR.GetResourceString("SequenceTerminatedUnknownAddToWindowError", @"An unknown error occurred while trying to add a sequence message to the window."); }
        }
        internal static string TimeoutOnAddToWindow {
              get { return SR.GetResourceString("TimeoutOnAddToWindow", @"The message could not be transferred within the allotted timeout of {0}. There was no space available in the reliable channel's transfer window. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string TimeoutOnClose {
              get { return SR.GetResourceString("TimeoutOnClose", @"The close operation did not complete within the allotted timeout of {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string TimeoutOnOpen {
              get { return SR.GetResourceString("TimeoutOnOpen", @"The open operation did not complete within the allotted timeout of {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string TimeoutOnOperation {
              get { return SR.GetResourceString("TimeoutOnOperation", @"The operation did not complete within the allotted timeout of {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string TimeoutOnRequest {
              get { return SR.GetResourceString("TimeoutOnRequest", @"The request operation did not complete within the allotted timeout of {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string TimeoutOnSend {
              get { return SR.GetResourceString("TimeoutOnSend", @"The send operation did not complete within the allotted timeout of {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string UnexpectedAcknowledgement {
              get { return SR.GetResourceString("UnexpectedAcknowledgement", @"The remote endpoint sent an unexpected ack. Simplex servers do not process acks."); }
        }
        internal static string UnexpectedAckRequested {
              get { return SR.GetResourceString("UnexpectedAckRequested", @"The remote endpoint sent an unexpected request for an ack. Simplex clients do not send acks and do not process requests for acks."); }
        }
        internal static string UnexpectedCloseSequence {
              get { return SR.GetResourceString("UnexpectedCloseSequence", @"The remote endpoint sent an unexpected close sequence message. Simplex clients do not process this message."); }
        }
        internal static string UnexpectedCloseSequenceResponse {
              get { return SR.GetResourceString("UnexpectedCloseSequenceResponse", @"The remote endpoint sent an unexpected close sequence response message. Simplex servers do not process this message."); }
        }
        internal static string UnexpectedCS {
              get { return SR.GetResourceString("UnexpectedCS", @"The remote endpoint sent an unexpected request to create a sequence. Clients do not process requests for a sequence."); }
        }
        internal static string UnexpectedCSR {
              get { return SR.GetResourceString("UnexpectedCSR", @"The remote endpoint sent an unexpected create sequence response. Servers do not process this message."); }
        }
        internal static string UnexpectedCSOfferId {
              get { return SR.GetResourceString("UnexpectedCSOfferId", @"The remote endpoint sent inconsistent requests to create the same sequence. The OfferId values are not identical."); }
        }
        internal static string UnexpectedCSROfferId {
              get { return SR.GetResourceString("UnexpectedCSROfferId", @"The remote endpoint sent inconsistent responses to the same create sequence request. The sequence identifiers are not identical."); }
        }
        internal static string UnexpectedTerminateSequence {
              get { return SR.GetResourceString("UnexpectedTerminateSequence", @"The remote endpoint sent an unexpected terminate sequence message. Simplex clients do not process this message."); }
        }
        internal static string UnexpectedTerminateSequenceResponse {
              get { return SR.GetResourceString("UnexpectedTerminateSequenceResponse", @"The remote endpoint sent an unexpected terminate sequence response message. Simplex servers do not process this message."); }
        }
        internal static string UnparsableCSResponse {
              get { return SR.GetResourceString("UnparsableCSResponse", @"The remote endpoint replied to the request for a sequence with a response that could not be parsed. See inner exception for details. The channel could not be opened."); }
        }
        internal static string UnknownSequenceFaultReason {
              get { return SR.GetResourceString("UnknownSequenceFaultReason", @"The value of wsrm:Identifier is not a known Sequence identifier."); }
        }
        internal static string UnknownSequenceMessageReceived {
              get { return SR.GetResourceString("UnknownSequenceMessageReceived", @"The remote endpoint has sent a message containing an unrecognized sequence identifier. The reliable session was faulted."); }
        }
        internal static string UnrecognizedFaultReceivedOnOpen {
              get { return SR.GetResourceString("UnrecognizedFaultReceivedOnOpen", @"The remote endpoint has sent an unrecognized fault with namespace, {0}, name {1}, and reason {2}. The channel could not be opened."); }
        }
        internal static string WsrmFaultReceived {
              get { return SR.GetResourceString("WsrmFaultReceived", @"The sequence has been terminated by the remote endpoint. {0} The reliable session was faulted."); }
        }
        internal static string WsrmMessageProcessingError {
              get { return SR.GetResourceString("WsrmMessageProcessingError", @"An error occurred while processing a message. {0}"); }
        }
        internal static string WsrmMessageWithWrongRelatesToFaultString {
              get { return SR.GetResourceString("WsrmMessageWithWrongRelatesToFaultString", @"The remote endpoint has responded to a {0} request message with an invalid reply. The reply has a wsa:RelatesTo header with an unexpected identifier. The reliable session cannot continue."); }
        }
        internal static string WsrmRequestIncorrectReplyToFaultString {
              get { return SR.GetResourceString("WsrmRequestIncorrectReplyToFaultString", @"The wsrm:{0} request message's wsa:ReplyTo address containing a URI which is not equivalent to the remote address. This is not supported. The reliable session was faulted."); }
        }
        internal static string WsrmRequiredFaultString {
              get { return SR.GetResourceString("WsrmRequiredFaultString", @"The RM server requires the use of WS-ReliableMessaging 1.1 protocol. This is likely caused by a binding mismatch."); }
        }
        internal static string SFxActionDemuxerDuplicate {
              get { return SR.GetResourceString("SFxActionDemuxerDuplicate", @"The operations {0} and {1} have the same action ({2}).  Every operation must have a unique action value."); }
        }
        internal static string SFxActionMismatch {
              get { return SR.GetResourceString("SFxActionMismatch", @"Cannot create a typed message due to action mismatch, expecting {0} encountered {1}"); }
        }
        internal static string SFxAnonymousTypeNotSupported {
              get { return SR.GetResourceString("SFxAnonymousTypeNotSupported", @"Part {1} in message {0} cannot be exported with RPC or encoded since its type is anonymous."); }
        }
        internal static string SFxAsyncResultsDontMatch0 {
              get { return SR.GetResourceString("SFxAsyncResultsDontMatch0", @"The IAsyncResult returned from Begin and the IAsyncResult supplied to the Callback are on different objects. These are required to be the same object."); }
        }
        internal static string SFXBindingNameCannotBeNullOrEmpty {
              get { return SR.GetResourceString("SFXBindingNameCannotBeNullOrEmpty", @"Binding name cannot be null or empty."); }
        }
        internal static string SFXUnvalidNamespaceValue {
              get { return SR.GetResourceString("SFXUnvalidNamespaceValue", @"Value '{0}' provided for {1} property is an invalid URI."); }
        }
        internal static string SFXUnvalidNamespaceParam {
              get { return SR.GetResourceString("SFXUnvalidNamespaceParam", @"Parameter value '{0}' is an invalid URI."); }
        }
        internal static string SFXHeaderNameCannotBeNullOrEmpty {
              get { return SR.GetResourceString("SFXHeaderNameCannotBeNullOrEmpty", @"Header name cannot be null or empty."); }
        }
        internal static string SFxEndpointNoMatchingScheme {
              get { return SR.GetResourceString("SFxEndpointNoMatchingScheme", @"Could not find a base address that matches scheme {0} for the endpoint with binding {1}. Registered base address schemes are [{2}]."); }
        }
        internal static string SFxBindingSchemeDoesNotMatch {
              get { return SR.GetResourceString("SFxBindingSchemeDoesNotMatch", @"The scheme '{0}' used by binding {1} does not match the required scheme '{2}'."); }
        }
        internal static string SFxGetChannelDispatcherDoesNotSupportScheme {
              get { return SR.GetResourceString("SFxGetChannelDispatcherDoesNotSupportScheme", @"Only a '{0}' using '{1}' or '{2}' is supported in this scenario."); }
        }
        internal static string SFxIncorrectMessageVersion {
              get { return SR.GetResourceString("SFxIncorrectMessageVersion", @"MessageVersion '{0}' is not supported in this scenario.  Only MessageVersion '{1}' is supported."); }
        }
        internal static string SFxBindingNotSupportedForMetadataHttpGet {
              get { return SR.GetResourceString("SFxBindingNotSupportedForMetadataHttpGet", @"The binding associated with ServiceMetadataBehavior or ServiceDebugBehavior is not supported.  The inner binding elements used by this binding must support IReplyChannel. Verify that HttpGetBinding/HttpsGetBinding (on ServiceMetadataBehavior) and HttpHelpPageBinding/HttpsHelpPageBinding (on ServiceDebugBehavior) are supported."); }
        }
        internal static string SFxBadByReferenceParameterMetadata {
              get { return SR.GetResourceString("SFxBadByReferenceParameterMetadata", @"Method '{0}' in class '{1}' has bad parameter metadata: a pass-by-reference parameter is marked with the 'in' but not the 'out' parameter mode."); }
        }
        internal static string SFxBadByValueParameterMetadata {
              get { return SR.GetResourceString("SFxBadByValueParameterMetadata", @"Method '{0}' in class '{1}' has bad parameter metadata: a pass-by-value parameter is marked with the 'out' parameter mode."); }
        }
        internal static string SFxBadMetadataMustBePolicy {
              get { return SR.GetResourceString("SFxBadMetadataMustBePolicy", @"When calling the CreateFromPolicy method, the policy argument must be an XmlElement instance with LocalName '{1}' and NamespaceUri '{0}'. This XmlElement has LocalName '{3}' and NamespaceUri '{2}'. "); }
        }
        internal static string SFxBadMetadataLocationUri {
              get { return SR.GetResourceString("SFxBadMetadataLocationUri", @"The URI supplied to ServiceMetadataBehavior via the ExternalMetadataLocation property or the externalMetadataLocation attribute in the serviceMetadata section in config must be a relative URI or an absolute URI with an http or https scheme. '{0}' was specified, which is a absolute URI with {1} scheme."); }
        }
        internal static string SFxBadMetadataLocationNoAppropriateBaseAddress {
              get { return SR.GetResourceString("SFxBadMetadataLocationNoAppropriateBaseAddress", @"The URL supplied to ServiceMetadataBehavior via the ExternalMetadataLocation property or the externalMetadataLocation attribute in the serviceMetadata section in config was a relative URL and there is no base address with which to resolve it. '{0}' was specified."); }
        }
        internal static string SFxBadMetadataDialect {
              get { return SR.GetResourceString("SFxBadMetadataDialect", @"There was a problem reading the MetadataSet argument: a MetadataSection instance with identifier '{0}' and dialect '{1}' has a Metadata property whose type does not match the dialect. The expected Metadata type for this dialect is '{2}' but was found to be '{3}'."); }
        }
        internal static string SFxBadMetadataReference {
              get { return SR.GetResourceString("SFxBadMetadataReference", @"Metadata contains a reference that cannot be resolved: '{0}'."); }
        }
        internal static string SFxMaximumResolvedReferencesOutOfRange {
              get { return SR.GetResourceString("SFxMaximumResolvedReferencesOutOfRange", @"The MaximumResolvedReferences property of MetadataExchangeClient must be greater than or equal to one.  '{0}' was specified."); }
        }
        internal static string SFxMetadataExchangeClientNoMetadataAddress {
              get { return SR.GetResourceString("SFxMetadataExchangeClientNoMetadataAddress", @"The MetadataExchangeClient was not supplied with a MetadataReference or MetadataLocation from which to get metadata.  You must supply one to the constructor, to the GetMetadata method, or to the BeginGetMetadata method."); }
        }
        internal static string SFxMetadataExchangeClientCouldNotCreateChannelFactory {
              get { return SR.GetResourceString("SFxMetadataExchangeClientCouldNotCreateChannelFactory", @"The MetadataExchangeClient could not create an IChannelFactory for: address='{0}', dialect='{1}', and  identifier='{2}'. "); }
        }
        internal static string SFxMetadataExchangeClientCouldNotCreateWebRequest {
              get { return SR.GetResourceString("SFxMetadataExchangeClientCouldNotCreateWebRequest", @"The MetadataExchangeClient could not create an HttpWebRequest for: address='{0}', dialect='{1}', and  identifier='{2}'. "); }
        }
        internal static string SFxMetadataExchangeClientCouldNotCreateChannelFactoryBadScheme {
              get { return SR.GetResourceString("SFxMetadataExchangeClientCouldNotCreateChannelFactoryBadScheme", @"The MetadataExchangeClient instance could not be initialized because no Binding is available for scheme '{0}'. You can supply a Binding in the constructor, or specify a configurationName."); }
        }
        internal static string SFxBadTransactionProtocols {
              get { return SR.GetResourceString("SFxBadTransactionProtocols", @"The TransactionProtocol setting was not understood. A supported protocol must be specified."); }
        }
        internal static string SFxMetadataResolverKnownContractsArgumentCannotBeEmpty {
              get { return SR.GetResourceString("SFxMetadataResolverKnownContractsArgumentCannotBeEmpty", @"The MetadataResolver cannot recieve an empty contracts argument to the Resolve or BeginResolve methods.  You must supply at least one ContractDescription."); }
        }
        internal static string SFxMetadataResolverKnownContractsUniqueQNames {
              get { return SR.GetResourceString("SFxMetadataResolverKnownContractsUniqueQNames", @"The ContractDescriptions in contracts must all have unique Name and Namespace pairs.  More than one ContractDescription had the pair Name='{0}' and Namespace='{1}'. "); }
        }
        internal static string SFxMetadataResolverKnownContractsCannotContainNull {
              get { return SR.GetResourceString("SFxMetadataResolverKnownContractsCannotContainNull", @"The contracts argument to the Resolve or BeginResolve methods cannot contain a null ContractDescription."); }
        }
        internal static string SFxBindingDoesNotHaveATransportBindingElement {
              get { return SR.GetResourceString("SFxBindingDoesNotHaveATransportBindingElement", @"The binding specified to do metadata exchange does not contain a TransportBindingElement."); }
        }
        internal static string SFxBindingMustContainTransport2 {
              get { return SR.GetResourceString("SFxBindingMustContainTransport2", @"The binding (Name={0}, Namespace={1}) does not contain a TransportBindingElement."); }
        }
        internal static string SFxBodyCannotBeNull {
              get { return SR.GetResourceString("SFxBodyCannotBeNull", @"Body object cannot be null in message {0}"); }
        }
        internal static string SFxBodyObjectTypeCannotBeInherited {
              get { return SR.GetResourceString("SFxBodyObjectTypeCannotBeInherited", @"Type {0} cannot inherit from any class other than object to be used as body object in RPC style."); }
        }
        internal static string SFxBodyObjectTypeCannotBeInterface {
              get { return SR.GetResourceString("SFxBodyObjectTypeCannotBeInterface", @"Type {0} implements interface {1} which is not supported for body object in RPC style."); }
        }
        internal static string SFxCallbackBehaviorAttributeOnlyOnDuplex {
              get { return SR.GetResourceString("SFxCallbackBehaviorAttributeOnlyOnDuplex", @"CallbackBehaviorAttribute can only be run as a behavior on an endpoint with a duplex contract. Contract '{0}' is not duplex, as it contains no callback operations."); }
        }
        internal static string SFxCallbackRequestReplyInOrder1 {
              get { return SR.GetResourceString("SFxCallbackRequestReplyInOrder1", @"This operation would deadlock because the reply cannot be received until the current Message completes processing. If you want to allow out-of-order message processing, specify ConcurrencyMode of Reentrant or Multiple on {0}."); }
        }
        internal static string SfxCallbackTypeCannotBeNull {
              get { return SR.GetResourceString("SfxCallbackTypeCannotBeNull", @"In order to use the contract '{0}' with DuplexChannelFactory, the contract must specify a valid callback contract.  If your contract does not have a callback contract, consider using ChannelFactory instead of DuplexChannelFactory."); }
        }
        internal static string SFxCannotActivateCallbackInstace {
              get { return SR.GetResourceString("SFxCannotActivateCallbackInstace", @"The dispatch instance for duplex callbacks cannot be activated - you must provide an instance."); }
        }
        internal static string SFxCannotCallAddBaseAddress {
              get { return SR.GetResourceString("SFxCannotCallAddBaseAddress", @"ServiceHostBase's AddBaseAddress method cannot be called after the InitializeDescription method has completed."); }
        }
        internal static string SFxCannotCallAutoOpenWhenExplicitOpenCalled {
              get { return SR.GetResourceString("SFxCannotCallAutoOpenWhenExplicitOpenCalled", @"Cannot make a call on this channel because a call to Open() is in progress."); }
        }
        internal static string SFxCannotGetMetadataFromRelativeAddress {
              get { return SR.GetResourceString("SFxCannotGetMetadataFromRelativeAddress", @"The MetadataExchangeClient can only get metadata from absolute addresses.  It cannot get metadata from '{0}'."); }
        }
        internal static string SFxCannotHttpGetMetadataFromAddress {
              get { return SR.GetResourceString("SFxCannotHttpGetMetadataFromAddress", @"The MetadataExchangeClient can only get metadata from http or https addresses when using MetadataExchangeClientMode HttpGet. It cannot get metadata from '{0}'."); }
        }
        internal static string SFxCannotGetMetadataFromLocation {
              get { return SR.GetResourceString("SFxCannotGetMetadataFromLocation", @"The MetadataExchangeClient can only get metadata from http and https MetadataLocations.  It cannot get metadata from '{0}'."); }
        }
        internal static string SFxCannotHaveDifferentTransactionProtocolsInOneBinding {
              get { return SR.GetResourceString("SFxCannotHaveDifferentTransactionProtocolsInOneBinding", @"The configured policy specifies more than one TransactionProtocol across the operations. A single TransactionProtocol for each endpoint must be specified."); }
        }
        internal static string SFxCannotImportAsParameters_Bare {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_Bare", @"Generating message contract since the operation {0} is neither RPC nor document wrapped."); }
        }
        internal static string SFxCannotImportAsParameters_DifferentWrapperNs {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_DifferentWrapperNs", @"Generating message contract since the wrapper namespace ({1}) of message {0} does not match the default value ({2})"); }
        }
        internal static string SFxCannotImportAsParameters_DifferentWrapperName {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_DifferentWrapperName", @"Generating message contract since the wrapper name ({1}) of message {0} does not match the default value ({2})"); }
        }
        internal static string SFxCannotImportAsParameters_ElementIsNotNillable {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_ElementIsNotNillable", @"Generating message contract since element name {0} from namespace {1} is not marked nillable"); }
        }
        internal static string SFxCannotImportAsParameters_MessageHasProtectionLevel {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_MessageHasProtectionLevel", @"Generating message contract since message {0} requires protection."); }
        }
        internal static string SFxCannotImportAsParameters_HeadersAreIgnoredInEncoded {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_HeadersAreIgnoredInEncoded", @"Headers are not supported in RPC encoded format. Headers are ignored in message {0}."); }
        }
        internal static string SFxCannotImportAsParameters_HeadersAreUnsupported {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_HeadersAreUnsupported", @"Generating message contract since message {0} has headers"); }
        }
        internal static string SFxCannotImportAsParameters_Message {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_Message", @"Generating message contract since the operation {0} has untyped Message as argument or return type"); }
        }
        internal static string SFxCannotImportAsParameters_NamespaceMismatch {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_NamespaceMismatch", @"Generating message contract since message part namespace ({0}) does not match the default value ({1})"); }
        }
        internal static string SFxCannotRequireBothSessionAndDatagram3 {
              get { return SR.GetResourceString("SFxCannotRequireBothSessionAndDatagram3", @"There are two contracts listening on the same binding ({2}) and address with conflicting settings.  Specifically, the contract '{0}' specifies SessionMode.NotAllowed while the contract '{1}' specifies SessionMode.Required.  You should either change one of the SessionMode values or specify a different address (or ListenUri) for each endpoint."); }
        }
        internal static string SFxCannotSetExtensionsByIndex {
              get { return SR.GetResourceString("SFxCannotSetExtensionsByIndex", @"This collection does not support setting extensions by index.  Please consider using the InsertItem or RemoveItem methods."); }
        }
        internal static string SFxChannelDispatcherDifferentHost0 {
              get { return SR.GetResourceString("SFxChannelDispatcherDifferentHost0", @"This ChannelDispatcher is not currently attached to the provided ServiceHost."); }
        }
        internal static string SFxChannelDispatcherMultipleHost0 {
              get { return SR.GetResourceString("SFxChannelDispatcherMultipleHost0", @"Cannot add a ChannelDispatcher to more than one ServiceHost."); }
        }
        internal static string SFxChannelDispatcherNoHost0 {
              get { return SR.GetResourceString("SFxChannelDispatcherNoHost0", @"Cannot open ChannelDispatcher because it is not attached to a ServiceHost."); }
        }
        internal static string SFxChannelDispatcherNoMessageVersion {
              get { return SR.GetResourceString("SFxChannelDispatcherNoMessageVersion", @"Cannot open ChannelDispatcher because it is does not have a MessageVersion set."); }
        }
        internal static string SFxChannelDispatcherUnableToOpen1 {
              get { return SR.GetResourceString("SFxChannelDispatcherUnableToOpen1", @"The ChannelDispatcher at '{0}' is unable to open its IChannelListener as there are no endpoints for the ChannelDispatcher."); }
        }
        internal static string SFxChannelDispatcherUnableToOpen2 {
              get { return SR.GetResourceString("SFxChannelDispatcherUnableToOpen2", @"The ChannelDispatcher at '{0}' with contract(s) '{1}' is unable to open its IChannelListener."); }
        }
        internal static string SFxChannelFactoryTypeMustBeInterface {
              get { return SR.GetResourceString("SFxChannelFactoryTypeMustBeInterface", @"The type argument passed to the generic ChannelFactory class must be an interface type."); }
        }
        internal static string SFxChannelFactoryCannotApplyConfigurationWithoutEndpoint {
              get { return SR.GetResourceString("SFxChannelFactoryCannotApplyConfigurationWithoutEndpoint", @"ApplyConfiguration requires that the Endpoint property be initialized. Either provide a valid ServiceEndpoint in the CreateDescription method or override the ApplyConfiguration method to provide an alternative implementation."); }
        }
        internal static string SFxChannelFactoryCannotCreateFactoryWithoutDescription {
              get { return SR.GetResourceString("SFxChannelFactoryCannotCreateFactoryWithoutDescription", @"CreateFactory requires that the Endpoint property be initialized. Either provide a valid ServiceEndpoint in the CreateDescription method or override the CreateFactory method to provide an alternative implementation."); }
        }
        internal static string SFxClientOutputSessionAutoClosed {
              get { return SR.GetResourceString("SFxClientOutputSessionAutoClosed", @"This channel can no longer be used to send messages as the output session was auto-closed due to a server-initiated shutdown. Either disable auto-close by setting the DispatchRuntime.AutomaticInputSessionShutdown to false, or consider modifying the shutdown protocol with the remote server."); }
        }
        internal static string SFxCodeGenArrayTypeIsNotSupported {
              get { return SR.GetResourceString("SFxCodeGenArrayTypeIsNotSupported", @"Array of type {0} is not supported."); }
        }
        internal static string SFxCodeGenCanOnlyStoreIntoArgOrLocGot0 {
              get { return SR.GetResourceString("SFxCodeGenCanOnlyStoreIntoArgOrLocGot0", @"Can only store into ArgBuilder or LocalBuilder. Got: {0}."); }
        }
        internal static string SFxCodeGenExpectingEnd {
              get { return SR.GetResourceString("SFxCodeGenExpectingEnd", @"Expecting End {0}."); }
        }
        internal static string SFxCodeGenIsNotAssignableFrom {
              get { return SR.GetResourceString("SFxCodeGenIsNotAssignableFrom", @"{0} is not assignable from {1}."); }
        }
        internal static string SFxCodeGenNoConversionPossibleTo {
              get { return SR.GetResourceString("SFxCodeGenNoConversionPossibleTo", @"No conversion possible to {0}."); }
        }
        internal static string SFxCodeGenWarning {
              get { return SR.GetResourceString("SFxCodeGenWarning", @"CODEGEN: {0}"); }
        }
        internal static string SFxCodeGenUnknownConstantType {
              get { return SR.GetResourceString("SFxCodeGenUnknownConstantType", @"Internal Error: Unrecognized constant type {0}."); }
        }
        internal static string SFxCollectionDoesNotSupportSet0 {
              get { return SR.GetResourceString("SFxCollectionDoesNotSupportSet0", @"This collection does not support setting items by index."); }
        }
        internal static string SFxCollectionReadOnly {
              get { return SR.GetResourceString("SFxCollectionReadOnly", @"This operation is not supported because the collection is read-only."); }
        }
        internal static string SFxCollectionWrongType2 {
              get { return SR.GetResourceString("SFxCollectionWrongType2", @"The collection of type {0} does not support values of type {1}."); }
        }
        internal static string SFxConflictingGlobalElement {
              get { return SR.GetResourceString("SFxConflictingGlobalElement", @"Top level XML element with name {0} in namespace {1} cannot reference {2} type because it already references a different type ({3}). Use a different operation name or MessageBodyMemberAttribute to specify a different name for the Message or Message parts."); }
        }
        internal static string SFxConflictingGlobalType {
              get { return SR.GetResourceString("SFxConflictingGlobalType", @"Duplicate top level XML Schema type with name {0} in namespace {1}."); }
        }
        internal static string SFxContextModifiedInsideScope0 {
              get { return SR.GetResourceString("SFxContextModifiedInsideScope0", @"The value of OperationContext.Current is not the OperationContext value installed by this OperationContextScope."); }
        }
        internal static string SFxContractDescriptionNameCannotBeEmpty {
              get { return SR.GetResourceString("SFxContractDescriptionNameCannotBeEmpty", @"ContractDescription's Name must be a non-empty string."); }
        }
        internal static string SFxContractHasZeroOperations {
              get { return SR.GetResourceString("SFxContractHasZeroOperations", @"ContractDescription '{0}' has zero operations; a contract must have at least one operation."); }
        }
        internal static string SFxContractHasZeroInitiatingOperations {
              get { return SR.GetResourceString("SFxContractHasZeroInitiatingOperations", @"ContractDescription '{0}' has zero IsInitiating=true operations; a contract must have at least one IsInitiating=true operation."); }
        }
        internal static string SFxContractInheritanceRequiresInterfaces {
              get { return SR.GetResourceString("SFxContractInheritanceRequiresInterfaces", @"The service class of type {0} both defines a ServiceContract and inherits a ServiceContract from type {1}. Contract inheritance can only be used among interface types.  If a class is marked with ServiceContractAttribute, it must be the only type in the hierarchy with ServiceContractAttribute.  Consider moving the ServiceContractAttribute on type {1} to a separate interface that type {1} implements."); }
        }
        internal static string SFxContractInheritanceRequiresInterfaces2 {
              get { return SR.GetResourceString("SFxContractInheritanceRequiresInterfaces2", @"The service class of type {0} both defines a ServiceContract and inherits a ServiceContract from type {1}. Contract inheritance can only be used among interface types.  If a class is marked with ServiceContractAttribute, then another service class cannot derive from it."); }
        }
        internal static string SFxCopyToRequiresICollection {
              get { return SR.GetResourceString("SFxCopyToRequiresICollection", @"SynchronizedReadOnlyCollection's CopyTo only works if the underlying list implements ICollection."); }
        }
        internal static string SFxCreateDuplexChannel1 {
              get { return SR.GetResourceString("SFxCreateDuplexChannel1", @"The callback contract of contract {0} either does not exist or does not define any operations.  If this is not a duplex contract, consider using ChannelFactory instead of DuplexChannelFactory."); }
        }
        internal static string SFxCreateDuplexChannelNoCallback {
              get { return SR.GetResourceString("SFxCreateDuplexChannelNoCallback", @"This CreateChannel overload cannot be called on this instance of DuplexChannelFactory, as the DuplexChannelFactory was not initialized with an InstanceContext.  Please call the CreateChannel overload that takes an InstanceContext."); }
        }
        internal static string SFxCreateDuplexChannelNoCallback1 {
              get { return SR.GetResourceString("SFxCreateDuplexChannelNoCallback1", @"This CreateChannel overload cannot be called on this instance of DuplexChannelFactory, as the DuplexChannelFactory was initialized with a Type and no valid InstanceContext was provided.  Please call the CreateChannel overload that takes an InstanceContext."); }
        }
        internal static string SFxCreateDuplexChannelNoCallbackUserObject {
              get { return SR.GetResourceString("SFxCreateDuplexChannelNoCallbackUserObject", @"This CreateChannel overload cannot be called on this instance of DuplexChannelFactory, as the InstanceContext provided to the DuplexChannelFactory does not contain a valid UserObject."); }
        }
        internal static string SFxCreateDuplexChannelBadCallbackUserObject {
              get { return SR.GetResourceString("SFxCreateDuplexChannelBadCallbackUserObject", @"The InstanceContext provided to the ChannelFactory contains a UserObject that does not implement the CallbackContractType '{0}'."); }
        }
        internal static string SFxCreateNonDuplexChannel1 {
              get { return SR.GetResourceString("SFxCreateNonDuplexChannel1", @"ChannelFactory does not support the contract {0} as it defines a callback contract with one or more operations.  Please consider using DuplexChannelFactory instead of ChannelFactory."); }
        }
        internal static string SFxCustomBindingNeedsTransport1 {
              get { return SR.GetResourceString("SFxCustomBindingNeedsTransport1", @"The CustomBinding on the ServiceEndpoint with contract '{0}' lacks a TransportBindingElement.  Every binding must have at least one binding element that derives from TransportBindingElement."); }
        }
        internal static string SFxCustomBindingWithoutTransport {
              get { return SR.GetResourceString("SFxCustomBindingWithoutTransport", @"The Scheme cannot be computed for this binding because this CustomBinding lacks a TransportBindingElement.  Every binding must have at least one binding element that derives from TransportBindingElement."); }
        }
        internal static string SFxDeserializationFailed1 {
              get { return SR.GetResourceString("SFxDeserializationFailed1", @"The formatter threw an exception while trying to deserialize the message: {0}"); }
        }
        internal static string SFxDictionaryIsEmpty {
              get { return SR.GetResourceString("SFxDictionaryIsEmpty", @"This operation is not possible since the dictionary is empty."); }
        }
        internal static string SFxDisallowedAttributeCombination {
              get { return SR.GetResourceString("SFxDisallowedAttributeCombination", @"The type or member named '{0}' could not be loaded because it has two incompatible attributes: '{1}' and '{2}'. To fix the problem, remove one of the attributes from the type or member."); }
        }
        internal static string SFxEndpointAddressNotSpecified {
              get { return SR.GetResourceString("SFxEndpointAddressNotSpecified", @"The endpoint's address is not specified. "); }
        }
        internal static string SFxEndpointContractNotSpecified {
              get { return SR.GetResourceString("SFxEndpointContractNotSpecified", @"The endpoint's contract is not specified."); }
        }
        internal static string SFxEndpointBindingNotSpecified {
              get { return SR.GetResourceString("SFxEndpointBindingNotSpecified", @"The endpoint's binding is not specified."); }
        }
        internal static string SFxInitializationUINotCalled {
              get { return SR.GetResourceString("SFxInitializationUINotCalled", @"The channel is configured to use interactive initializer '{0}', but the channel was Opened without calling DisplayInitializationUI.  Call DisplayInitializationUI before calling Open or other methods on this channel."); }
        }
        internal static string SFxInitializationUIDisallowed {
              get { return SR.GetResourceString("SFxInitializationUIDisallowed", @"AllowInitializationUI was set to false for this channel, but the channel is configured to use the '{0}' as an interactive initializer."); }
        }
        internal static string SFxDocExt_NoMetadataSection1 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataSection1", @"This is a Windows&#169; Communication Foundation service.<BR/><BR/><B>Metadata publishing for this service is currently disabled.</B><BR/><BR/>If you have access to the service, you can enable metadata publishing by completing the following steps to modify your web or application configuration file:<BR/><BR/>1. Create the following service behavior configuration, or add the &lt;serviceMetadata&gt; element to an existing service behavior configuration:"); }
        }
        internal static string SFxDocExt_NoMetadataSection2 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataSection2", @"2. Add the behavior configuration to the service:"); }
        }
        internal static string SFxDocExt_NoMetadataSection3 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataSection3", @"Note: the service name must match the configuration name for the service implementation.<BR/><BR/>3. Add the following endpoint to your service configuration:"); }
        }
        internal static string SFxDocExt_NoMetadataSection4 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataSection4", @"Note: your service must have an http base address to add this endpoint.<BR/><BR/>The following is an example service configuration file with metadata publishing enabled:"); }
        }
        internal static string SFxDocExt_NoMetadataSection5 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataSection5", @"For more information on publishing metadata please see the following documentation: <a href=\""http://go.microsoft.com/fwlink/?LinkId=65455\"">http://go.microsoft.com/fwlink/?LinkId=65455</a>."); }
        }
        internal static string SFxDocExt_NoMetadataConfigComment1 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataConfigComment1", @"Note: the service name must match the configuration name for the service implementation."); }
        }
        internal static string SFxDocExt_NoMetadataConfigComment2 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataConfigComment2", @"Add the following endpoint. "); }
        }
        internal static string SFxDocExt_NoMetadataConfigComment3 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataConfigComment3", @"Note: your service must have an http base address to add this endpoint."); }
        }
        internal static string SFxDocExt_NoMetadataConfigComment4 {
              get { return SR.GetResourceString("SFxDocExt_NoMetadataConfigComment4", @"Add the following element to your service behavior configuration."); }
        }
        internal static string SFxDocExt_CS {
              get { return SR.GetResourceString("SFxDocExt_CS", @"<P class='intro'><B>C#</B></P>"); }
        }
        internal static string SFxDocExt_VB {
              get { return SR.GetResourceString("SFxDocExt_VB", @"<P class='intro'><B>Visual Basic</B></P>"); }
        }
        internal static string SFxDocExt_MainPageTitleNoServiceName {
              get { return SR.GetResourceString("SFxDocExt_MainPageTitleNoServiceName", @"Service"); }
        }
        internal static string SFxDocExt_MainPageTitle {
              get { return SR.GetResourceString("SFxDocExt_MainPageTitle", @"{0} Service"); }
        }
        internal static string SFxDocExt_MainPageIntro1a {
              get { return SR.GetResourceString("SFxDocExt_MainPageIntro1a", @"You have created a service.<P class='intro'>To test this service, you will need to create a client and use it to call the service. You can do this using the svcutil.exe tool from the command line with the following syntax:</P> "); }
        }
        internal static string SFxDocExt_MainPageIntro1b {
              get { return SR.GetResourceString("SFxDocExt_MainPageIntro1b", @"You have created a service.<P class='intro'>To test this service, you will need to create a client and use it to call the service; however, metadata publishing via ?WSDL is currently disabled. This can be enabled via the service's configuration file. </P>"); }
        }
        internal static string SFxDocExt_MainPageIntro2 {
              get { return SR.GetResourceString("SFxDocExt_MainPageIntro2", @"This will generate a configuration file and a code file that contains the client class. Add the two files to your client application and use the generated client class to call the Service. For example:<BR/>"); }
        }
        internal static string SFxDocExt_MainPageComment {
              get { return SR.GetResourceString("SFxDocExt_MainPageComment", @"Use the 'client' variable to call operations on the service."); }
        }
        internal static string SFxDocExt_MainPageComment2 {
              get { return SR.GetResourceString("SFxDocExt_MainPageComment2", @"Always close the client."); }
        }
        internal static string SFxDocExt_Error {
              get { return SR.GetResourceString("SFxDocExt_Error", @"The service encountered an error."); }
        }
        internal static string SFxDocEncodedNotSupported {
              get { return SR.GetResourceString("SFxDocEncodedNotSupported", @"Operation '{0}' could not be loaded as it uses an unsupported combination of Use and Style settings: Document with Encoded. To fix the problem, change the Use setting to Literal or change the Style setting to Rpc."); }
        }
        internal static string SFxDocEncodedFaultNotSupported {
              get { return SR.GetResourceString("SFxDocEncodedFaultNotSupported", @"Fault could not be loaded as the Use setting is Encoded and it references a schema definition using Element attribute. To fix the problem, change the Use setting to Literal."); }
        }
        internal static string SFxDuplicateMessageParts {
              get { return SR.GetResourceString("SFxDuplicateMessageParts", @"Message part {0} in namespace {1} appears more than once in Message."); }
        }
        internal static string SFxDuplicateInitiatingActionAtSameVia {
              get { return SR.GetResourceString("SFxDuplicateInitiatingActionAtSameVia", @"This service has multiple endpoints listening at '{0}' which share the same initiating action '{1}'.  As a result, messages with this action would be dropped since the dispatcher would not be able to determine the correct endpoint for handling the message.  Please consider hosting these Endpoints at separate ListenUris."); }
        }
        internal static string SFXEndpointBehaviorUsedOnWrongSide {
              get { return SR.GetResourceString("SFXEndpointBehaviorUsedOnWrongSide", @"The IEndpointBehavior '{0}' cannot be used on the server side; this behavior can only be applied to clients."); }
        }
        internal static string SFxEndpointDispatcherMultipleChannelDispatcher0 {
              get { return SR.GetResourceString("SFxEndpointDispatcherMultipleChannelDispatcher0", @"Cannot add EndpointDispatcher to more than one ChannelDispatcher."); }
        }
        internal static string SFxEndpointDispatcherDifferentChannelDispatcher0 {
              get { return SR.GetResourceString("SFxEndpointDispatcherDifferentChannelDispatcher0", @"This EndpointDispatcher is not currently attached to the provided ChannelDispatcher."); }
        }
        internal static string SFxErrorCreatingMtomReader {
              get { return SR.GetResourceString("SFxErrorCreatingMtomReader", @"Error creating a reader for the MTOM message"); }
        }
        internal static string SFxErrorDeserializingRequestBody {
              get { return SR.GetResourceString("SFxErrorDeserializingRequestBody", @"Error in deserializing body of request message for operation '{0}'."); }
        }
        internal static string SFxErrorDeserializingRequestBodyMore {
              get { return SR.GetResourceString("SFxErrorDeserializingRequestBodyMore", @"Error in deserializing body of request message for operation '{0}'. {1}"); }
        }
        internal static string SFxErrorDeserializingReplyBody {
              get { return SR.GetResourceString("SFxErrorDeserializingReplyBody", @"Error in deserializing body of reply message for operation '{0}'."); }
        }
        internal static string SFxErrorDeserializingReplyBodyMore {
              get { return SR.GetResourceString("SFxErrorDeserializingReplyBodyMore", @"Error in deserializing body of reply message for operation '{0}'. {1}"); }
        }
        internal static string SFxErrorSerializingBody {
              get { return SR.GetResourceString("SFxErrorSerializingBody", @"There was an error in serializing body of message {0}: '{1}'.  Please see InnerException for more details."); }
        }
        internal static string SFxErrorDeserializingHeader {
              get { return SR.GetResourceString("SFxErrorDeserializingHeader", @"There was an error in deserializing one of the headers in message {0}.  Please see InnerException for more details."); }
        }
        internal static string SFxErrorSerializingHeader {
              get { return SR.GetResourceString("SFxErrorSerializingHeader", @"There was an error in serializing one of the headers in message {0}: '{1}'.  Please see InnerException for more details."); }
        }
        internal static string SFxErrorDeserializingFault {
              get { return SR.GetResourceString("SFxErrorDeserializingFault", @"Server returned an invalid SOAP Fault.  Please see InnerException for more details."); }
        }
        internal static string SFxErrorReflectingOnType2 {
              get { return SR.GetResourceString("SFxErrorReflectingOnType2", @"An error occurred while loading attribute '{0}' on type '{1}'.  Please see InnerException for more details."); }
        }
        internal static string SFxErrorReflectingOnMethod3 {
              get { return SR.GetResourceString("SFxErrorReflectingOnMethod3", @"An error occurred while loading attribute '{0}' on method '{1}' in type '{2}'.  Please see InnerException for more details."); }
        }
        internal static string SFxErrorReflectingOnParameter4 {
              get { return SR.GetResourceString("SFxErrorReflectingOnParameter4", @"An error occurred while loading attribute '{0}' on parameter {1} of method '{2}' in type '{3}'.  Please see InnerException for more details."); }
        }
        internal static string SFxErrorReflectionOnUnknown1 {
              get { return SR.GetResourceString("SFxErrorReflectionOnUnknown1", @"An error occurred while loading attribute '{0}'.  Please see InnerException for more details."); }
        }
        internal static string SFxExceptionDetailEndOfInner {
              get { return SR.GetResourceString("SFxExceptionDetailEndOfInner", @"--- End of inner ExceptionDetail stack trace ---"); }
        }
        internal static string SFxExceptionDetailFormat {
              get { return SR.GetResourceString("SFxExceptionDetailFormat", @"An ExceptionDetail, likely created by IncludeExceptionDetailInFaults=true, whose value is:"); }
        }
        internal static string SFxExpectedIMethodCallMessage {
              get { return SR.GetResourceString("SFxExpectedIMethodCallMessage", @"Internal Error: Message must be a valid IMethodCallMessage."); }
        }
        internal static string SFxExportMustHaveType {
              get { return SR.GetResourceString("SFxExportMustHaveType", @"The specified ContractDescription could not be exported to WSDL because the Type property of the MessagePartDescription with name '{1}' in the OperationDescription with name '{0}' is not set.  The Type property must be set in order to create WSDL."); }
        }
        internal static string SFxFaultCannotBeImported {
              get { return SR.GetResourceString("SFxFaultCannotBeImported", @"Fault named {0} in operation {1} cannot be imported. {2}"); }
        }
        internal static string SFxFaultContractDuplicateDetailType {
              get { return SR.GetResourceString("SFxFaultContractDuplicateDetailType", @"In operation {0}, more than one fault is declared with detail type {1}"); }
        }
        internal static string SFxFaultContractDuplicateElement {
              get { return SR.GetResourceString("SFxFaultContractDuplicateElement", @"In operation {0}, more than one fault is declared with element name {1} in namespace {2}"); }
        }
        internal static string SFxFaultExceptionToString3 {
              get { return SR.GetResourceString("SFxFaultExceptionToString3", @"{0}: {1} (Fault Detail is equal to {2})."); }
        }
        internal static string SFxFaultReason {
              get { return SR.GetResourceString("SFxFaultReason", @"The creator of this fault did not specify a Reason."); }
        }
        internal static string SFxFaultTypeAnonymous {
              get { return SR.GetResourceString("SFxFaultTypeAnonymous", @"In operation {0}, the schema type corresponding to the fault detail type {1} is anonymous. Please set Fault name explicitly to export anonymous types."); }
        }
        internal static string SFxHeaderNameMismatchInMessageContract {
              get { return SR.GetResourceString("SFxHeaderNameMismatchInMessageContract", @"Header name mismatch in member {1} of type {0}. The header name found in the description is {2}. The element name deduced by the formatter is {3}. This mismatch can happen if the ElementName specified in XmlElementAttribute or XmlArrayAttribute does not match the name specified in the MessageHeaderAttribute or MessageHeaderArrayAttribute or the member name."); }
        }
        internal static string SFxHeaderNameMismatchInOperation {
              get { return SR.GetResourceString("SFxHeaderNameMismatchInOperation", @"Header name mismatch in operation {0} from contract {1}:{2}. The header name found in the description is {3}. The element name deduced by the formatter is {4}. This mismatch can happen if the ElementName specified in XmlElementAttribute or XmlArrayAttribute does not match the name specified in the MessageHeaderAttribute or MessageHeaderArrayAttribute or the member name."); }
        }
        internal static string SFxHeaderNamespaceMismatchInMessageContract {
              get { return SR.GetResourceString("SFxHeaderNamespaceMismatchInMessageContract", @"Header namespace mismatch in member {1} of type {0}. The header namespace found in the description is {2}. The element namespace deduced by the formatter is {3}. This mismatch can happen if the Namespace specified in XmlElementAttribute or XmlArrayAttribute does not match the namespace specified in the MessageHeaderAttribute or MessageHeaderArrayAttribute or the contract namespace."); }
        }
        internal static string SFxHeaderNamespaceMismatchInOperation {
              get { return SR.GetResourceString("SFxHeaderNamespaceMismatchInOperation", @"Header namespace mismatch in operation {0} from contract {1}:{2}. The header namespace found in the description is {3}. The element namespace deduced by the formatter is {4}. This mismatch can happen if the Namespace specified in XmlElementAttribute or XmlArrayAttribute does not match the namespace specified in the MessageHeaderAttribute or MessageHeaderArrayAttribute or the contract namespace."); }
        }
        internal static string SFxHeaderNotUnderstood {
              get { return SR.GetResourceString("SFxHeaderNotUnderstood", @"The header '{0}' from the namespace '{1}' was not understood by the recipient of this message, causing the message to not be processed.  This error typically indicates that the sender of this message has enabled a communication protocol that the receiver cannot process.  Please ensure that the configuration of the client's binding is consistent with the service's binding. "); }
        }
        internal static string SFxHeadersAreNotSupportedInEncoded {
              get { return SR.GetResourceString("SFxHeadersAreNotSupportedInEncoded", @"Message {0} must not have headers to be used in RPC encoded style."); }
        }
        internal static string SFxImmutableServiceHostBehavior0 {
              get { return SR.GetResourceString("SFxImmutableServiceHostBehavior0", @"This value cannot be changed after the ServiceHost has opened."); }
        }
        internal static string SFxImmutableChannelFactoryBehavior0 {
              get { return SR.GetResourceString("SFxImmutableChannelFactoryBehavior0", @"This value cannot be changed after the ChannelFactory has opened."); }
        }
        internal static string SFxImmutableClientBaseCacheSetting {
              get { return SR.GetResourceString("SFxImmutableClientBaseCacheSetting", @"This value cannot be changed after the first ClientBase of type '{0}' has been created."); }
        }
        internal static string SFxImmutableThrottle1 {
              get { return SR.GetResourceString("SFxImmutableThrottle1", @"{0} cannot be changed after the ServiceHost has opened."); }
        }
        internal static string SFxInconsistentBindingBodyParts {
              get { return SR.GetResourceString("SFxInconsistentBindingBodyParts", @"Operation {0} binding {1} has extra part {2} that is not present in other bindings"); }
        }
        internal static string SFxInconsistentWsdlOperationStyleInHeader {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationStyleInHeader", @"Style {1} on header {0} does not match expected style {2}."); }
        }
        internal static string SFxInconsistentWsdlOperationStyleInMessageParts {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationStyleInMessageParts", @"All parts of message in operation {0} must either contain type or element. "); }
        }
        internal static string SFxInconsistentWsdlOperationStyleInOperationMessages {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationStyleInOperationMessages", @"Style {1} inferred from messages in operation {0} does not match expected style {2} specified via bindings."); }
        }
        internal static string SFxInconsistentWsdlOperationUseAndStyleInBinding {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationUseAndStyleInBinding", @"Bindings for operation {0} cannot specify different use and style values. Binding {1} specifies use {2} and style {3} while binding {4} specifies use {5} and style {6}."); }
        }
        internal static string SFxInconsistentWsdlOperationUseInBindingExtensions {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationUseInBindingExtensions", @"Extensions for operation {0} in binding {1} cannot specify different use values."); }
        }
        internal static string SFxInconsistentWsdlOperationUseInBindingMessages {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationUseInBindingMessages", @"Message bindings for operation {0} in binding {1} cannot specify different use values."); }
        }
        internal static string SFxInconsistentWsdlOperationUseInBindingFaults {
              get { return SR.GetResourceString("SFxInconsistentWsdlOperationUseInBindingFaults", @"Fault bindings for operation {0} in binding {1} cannot specify different use values."); }
        }
        internal static string SFxInputParametersToServiceInvalid {
              get { return SR.GetResourceString("SFxInputParametersToServiceInvalid", @"Service implementation object invoked with wrong number of input parameters, operation expects {0} parameters but was called with {1} parameters."); }
        }
        internal static string SFxInputParametersToServiceNull {
              get { return SR.GetResourceString("SFxInputParametersToServiceNull", @"Service implementation object invoked with null input parameters, but operation expects {0} parameters."); }
        }
        internal static string SFxInstanceNotInitialized {
              get { return SR.GetResourceString("SFxInstanceNotInitialized", @"The InstanceContext has no provider for creating Service implementation objects."); }
        }
        internal static string SFxInterleavedContextScopes0 {
              get { return SR.GetResourceString("SFxInterleavedContextScopes0", @"This OperationContextScope is being disposed out of order."); }
        }
        internal static string SFxInternalServerError {
              get { return SR.GetResourceString("SFxInternalServerError", @"The server was unable to process the request due to an internal error.  For more information about the error, either turn on IncludeExceptionDetailInFaults (either from ServiceBehaviorAttribute or from the <serviceDebug> configuration behavior) on the server in order to send the exception information back to the client, or turn on tracing as per the Microsoft .NET Framework SDK documentation and inspect the server trace logs."); }
        }
        internal static string SFxInternalCallbackError {
              get { return SR.GetResourceString("SFxInternalCallbackError", @"The client was unable to process the callback request due to an internal error.  For more information about the error, either turn on IncludeExceptionDetailInFaults (either from CallbackBehaviorAttribute or from the <clientDebug> configuration behavior) on the client in order to send the exception information back to the server, or turn on tracing as per the Microsoft .NET Framework SDK documentation and inspect the client trace logs."); }
        }
        internal static string SFxInvalidAsyncResultState0 {
              get { return SR.GetResourceString("SFxInvalidAsyncResultState0", @"IAsyncResult's State must be the state argument passed to your Begin call."); }
        }
        internal static string SFxInvalidCallbackIAsyncResult {
              get { return SR.GetResourceString("SFxInvalidCallbackIAsyncResult", @"IAsyncResult not provided or of wrong type."); }
        }
        internal static string SFxInvalidCallbackContractType {
              get { return SR.GetResourceString("SFxInvalidCallbackContractType", @"The CallbackContract {0} is invalid because it is not an interface type."); }
        }
        internal static string SFxInvalidChannelToOperationContext {
              get { return SR.GetResourceString("SFxInvalidChannelToOperationContext", @"Invalid IContextChannel passed to OperationContext. Must be either a server dispatching channel or a client proxy channel."); }
        }
        internal static string SFxInvalidContextScopeThread0 {
              get { return SR.GetResourceString("SFxInvalidContextScopeThread0", @"This OperationContextScope is being disposed on a different thread than it was created."); }
        }
        internal static string SFxInvalidMessageBody {
              get { return SR.GetResourceString("SFxInvalidMessageBody", @"OperationFormatter encountered an invalid Message body. Expected to find node type 'Element' with name '{0}' and namespace '{1}'. Found node type '{2}' with name '{3}' and namespace '{4}'"); }
        }
        internal static string SFxInvalidMessageBodyEmptyMessage {
              get { return SR.GetResourceString("SFxInvalidMessageBodyEmptyMessage", @"The OperationFormatter could not deserialize any information from the Message because the Message is empty (IsEmpty = true)."); }
        }
        internal static string SFxInvalidMessageBodyErrorSerializingParameter {
              get { return SR.GetResourceString("SFxInvalidMessageBodyErrorSerializingParameter", @"There was an error while trying to serialize parameter {0}:{1}. The InnerException message was '{2}'.  Please see InnerException for more details."); }
        }
        internal static string SFxInvalidMessageBodyErrorDeserializingParameter {
              get { return SR.GetResourceString("SFxInvalidMessageBodyErrorDeserializingParameter", @"There was an error while trying to deserialize parameter {0}:{1}.  Please see InnerException for more details."); }
        }
        internal static string SFxInvalidMessageBodyErrorDeserializingParameterMore {
              get { return SR.GetResourceString("SFxInvalidMessageBodyErrorDeserializingParameterMore", @"There was an error while trying to deserialize parameter {0}:{1}. The InnerException message was '{2}'.  Please see InnerException for more details."); }
        }
        internal static string SFxInvalidMessageContractSignature {
              get { return SR.GetResourceString("SFxInvalidMessageContractSignature", @"The operation {0} either has a parameter or a return type that is attributed with MessageContractAttribute.  In order to represent the request message using a Message Contract, the operation must have a single parameter attributed with MessageContractAttribute.  In order to represent the response message using a Message Contract, the operation's return value must be a type that is attributed with MessageContractAttribute and the operation may not have any out or ref parameters."); }
        }
        internal static string SFxInvalidMessageHeaderArrayType {
              get { return SR.GetResourceString("SFxInvalidMessageHeaderArrayType", @"MessageHeaderArrayAttribute found on member {0} is not a single dimensional array."); }
        }
        internal static string SFxInvalidRequestAction {
              get { return SR.GetResourceString("SFxInvalidRequestAction", @"Outgoing request message for operation '{0}' specified Action='{1}', but contract for that operation specifies Action='{2}'.  The Action specified in the Message must match the Action in the contract, or the operation contract must specify Action='*'."); }
        }
        internal static string SFxInvalidReplyAction {
              get { return SR.GetResourceString("SFxInvalidReplyAction", @"Outgoing reply message for operation '{0}' specified Action='{1}', but contract for that operation specifies ReplyAction='{2}'.    The Action specified in the Message must match the ReplyAction in the contract, or the operation contract must specify ReplyAction='*'."); }
        }
        internal static string SFxInvalidStreamInTypedMessage {
              get { return SR.GetResourceString("SFxInvalidStreamInTypedMessage", @"In order to use Streams with the MessageContract programming model, the type {0} must have a single member with MessageBodyMember attribute and the member type must be Stream."); }
        }
        internal static string SFxInvalidStreamInRequest {
              get { return SR.GetResourceString("SFxInvalidStreamInRequest", @"For request in operation {0} to be a stream the operation must have a single parameter whose type is Stream."); }
        }
        internal static string SFxInvalidStreamInResponse {
              get { return SR.GetResourceString("SFxInvalidStreamInResponse", @"For response in operation {0} to be a stream the operation must have a single out parameter or return value whose type is Stream."); }
        }
        internal static string SFxInvalidStreamOffsetLength {
              get { return SR.GetResourceString("SFxInvalidStreamOffsetLength", @"Buffer size must be at least {0} bytes."); }
        }
        internal static string SFxInvalidUseOfPrimitiveOperationFormatter {
              get { return SR.GetResourceString("SFxInvalidUseOfPrimitiveOperationFormatter", @"The PrimitiveOperationFormatter was given a parameter or return type which it does not support."); }
        }
        internal static string SFxInvalidStaticOverloadCalledForDuplexChannelFactory1 {
              get { return SR.GetResourceString("SFxInvalidStaticOverloadCalledForDuplexChannelFactory1", @"The static CreateChannel method cannot be used with the contract {0} because that contract defines a callback contract.  Please try using one of the static CreateChannel overloads on DuplexChannelFactory<TChannel>."); }
        }
        internal static string SFxInvalidSoapAttribute {
              get { return SR.GetResourceString("SFxInvalidSoapAttribute", @"XmlSerializer attribute {0} is not valid in {1}. Only SoapElement attribute is supported."); }
        }
        internal static string SFxInvalidXmlAttributeInBare {
              get { return SR.GetResourceString("SFxInvalidXmlAttributeInBare", @"XmlSerializer attribute {0} is not valid in {1}. Only XmlElement, XmlArray, XmlArrayItem and XmlAnyElement attributes are supported in MessageContract when IsWrapped is false."); }
        }
        internal static string SFxInvalidXmlAttributeInWrapped {
              get { return SR.GetResourceString("SFxInvalidXmlAttributeInWrapped", @"XmlSerializer attribute {0} is not valid in {1}. Only XmlElement, XmlArray, XmlArrayItem, XmlAnyAttribute and XmlAnyElement attributes are supported when IsWrapped is true."); }
        }
        internal static string SFxKnownTypeAttributeInvalid1 {
              get { return SR.GetResourceString("SFxKnownTypeAttributeInvalid1", @"{0} must contain either a single ServiceKnownTypeAttribute that refers to a method or a set of ServiceKnownTypeAttributes, each specifying a valid type"); }
        }
        internal static string SFxKnownTypeAttributeReturnType3 {
              get { return SR.GetResourceString("SFxKnownTypeAttributeReturnType3", @"The return type of method {1} in type {2} must be IEnumerable<Type> to be used by ServiceKnownTypeAttribute in {0}"); }
        }
        internal static string SFxKnownTypeAttributeUnknownMethod3 {
              get { return SR.GetResourceString("SFxKnownTypeAttributeUnknownMethod3", @"ServiceKnownTypeAttribute in {0} refers to a method {1} that does not exist in type {2}"); }
        }
        internal static string SFxKnownTypeNull {
              get { return SR.GetResourceString("SFxKnownTypeNull", @"KnownType cannot be null in operation {0}"); }
        }
        internal static string SFxMessageContractBaseTypeNotValid {
              get { return SR.GetResourceString("SFxMessageContractBaseTypeNotValid", @"The type {1} defines a MessageContract but also derives from a type {0} that does not define a MessageContract.  All of the objects in the inheritance hierarchy of {1} must defines a MessageContract."); }
        }
        internal static string SFxMessageContractRequiresDefaultConstructor {
              get { return SR.GetResourceString("SFxMessageContractRequiresDefaultConstructor", @"The message cannot be deserialized into MessageContract type {0} since it does not have a default (parameterless) constructor."); }
        }
        internal static string SFxMessageOperationFormatterCannotSerializeFault {
              get { return SR.GetResourceString("SFxMessageOperationFormatterCannotSerializeFault", @"MessageOperationFormatter cannot serialize faults."); }
        }
        internal static string SFxMetadataReferenceInvalidLocation {
              get { return SR.GetResourceString("SFxMetadataReferenceInvalidLocation", @"The value '{0}' is not valid for the Location property. The Location property must be a valid absolute or relative URI."); }
        }
        internal static string SFxMethodNotSupported1 {
              get { return SR.GetResourceString("SFxMethodNotSupported1", @"Method {0} is not supported on this proxy, this can happen if the method is not marked with OperationContractAttribute or if the interface type is not marked with ServiceContractAttribute."); }
        }
        internal static string SFxMethodNotSupportedOnCallback1 {
              get { return SR.GetResourceString("SFxMethodNotSupportedOnCallback1", @"Callback method {0} is not supported, this can happen if the method is not marked with OperationContractAttribute or if its interface type is not the target of the ServiceContractAttribute's CallbackContract."); }
        }
        internal static string SFxMethodNotSupportedByType2 {
              get { return SR.GetResourceString("SFxMethodNotSupportedByType2", @"ServiceHost implementation type {0} does not implement ServiceContract {1}."); }
        }
        internal static string SFxMismatchedOperationParent {
              get { return SR.GetResourceString("SFxMismatchedOperationParent", @"A DispatchOperation (or ClientOperation) can only be added to its parent DispatchRuntime (or ClientRuntime)."); }
        }
        internal static string SFxMissingActionHeader {
              get { return SR.GetResourceString("SFxMissingActionHeader", @"No Action header was found with namespace '{0}' for the given message."); }
        }
        internal static string SFxMultipleCallbackFromSynchronizationContext {
              get { return SR.GetResourceString("SFxMultipleCallbackFromSynchronizationContext", @"Calling Post() on '{0}' resulted in multiple callbacks.  This indicates a problem in '{0}'."); }
        }
        internal static string SFxMultipleCallbackFromAsyncOperation {
              get { return SR.GetResourceString("SFxMultipleCallbackFromAsyncOperation", @"The callback passed to operation '{0}' was called more than once.  This indicates an internal error in the implementation of that operation."); }
        }
        internal static string SFxMultipleUnknownHeaders {
              get { return SR.GetResourceString("SFxMultipleUnknownHeaders", @"Method {0} in type {1} has more than one header part of type array of XmlElement."); }
        }
        internal static string SFxMultipleContractStarOperations0 {
              get { return SR.GetResourceString("SFxMultipleContractStarOperations0", @"A ServiceContract has more the one operation with an Action of \""*\"".  A ServiceContract can have at most one operation an Action = \""*\""."); }
        }
        internal static string SFxMultipleContractsWithSameName {
              get { return SR.GetResourceString("SFxMultipleContractsWithSameName", @"The Service contains multiple ServiceEndpoints with different ContractDescriptions which each have Name='{0}' and Namespace='{1}'.  Either provide ContractDescriptions with unique Name and Namespaces, or ensure the ServiceEndpoints have the same ContractDescription instance."); }
        }
        internal static string SFxMultiplePartsNotAllowedInEncoded {
              get { return SR.GetResourceString("SFxMultiplePartsNotAllowedInEncoded", @"Part {1}:{0} is repeating and is not supported in Soap Encoding."); }
        }
        internal static string SFxNameCannotBeEmpty {
              get { return SR.GetResourceString("SFxNameCannotBeEmpty", @"The Name property must be a non-empty string."); }
        }
        internal static string SFxConfigurationNameCannotBeEmpty {
              get { return SR.GetResourceString("SFxConfigurationNameCannotBeEmpty", @"The ConfigurationName property must be a non-empty string."); }
        }
        internal static string SFxNeedProxyBehaviorOperationSelector2 {
              get { return SR.GetResourceString("SFxNeedProxyBehaviorOperationSelector2", @"Cannot handle invocation of {0} on interface {1} because the OperationSelector on ClientRuntime is null."); }
        }
        internal static string SFxNoDefaultConstructor {
              get { return SR.GetResourceString("SFxNoDefaultConstructor", @"The service type provided could not be loaded as a service because it does not have a default (parameter-less) constructor. To fix the problem, add a default constructor to the type, or pass an instance of the type to the host."); }
        }
        internal static string SFxNoMostDerivedContract {
              get { return SR.GetResourceString("SFxNoMostDerivedContract", @"The contract specified by type '{0}' is ambiguous.  The type derives from at least two different types that each define its own service contract.  For this type to be used as a contract type, exactly one of its inherited contracts must be more derived than any of the others."); }
        }
        internal static string SFxNullReplyFromExtension2 {
              get { return SR.GetResourceString("SFxNullReplyFromExtension2", @"Extension {0} prevented call to operation '{1}' from replying by setting the reply to null."); }
        }
        internal static string SFxNullReplyFromFormatter2 {
              get { return SR.GetResourceString("SFxNullReplyFromFormatter2", @"Formatter {0} returned a null reply message for call to operation '{1}'."); }
        }
        internal static string SFxServiceChannelIdleAborted {
              get { return SR.GetResourceString("SFxServiceChannelIdleAborted", @"The operation '{0}' could not be completed because the sessionful channel timed out waiting to receive a message.  To increase the timeout, either set the receiveTimeout property on the binding in your configuration file, or set the ReceiveTimeout property on the Binding directly."); }
        }
        internal static string SFxServiceMetadataBehaviorUrlMustBeHttpOrRelative {
              get { return SR.GetResourceString("SFxServiceMetadataBehaviorUrlMustBeHttpOrRelative", @"{0} must be a relative URI or an absolute URI with scheme '{1}'.  '{2}' is an absolute URI with scheme '{3}'. "); }
        }
        internal static string SFxServiceMetadataBehaviorNoHttpBaseAddress {
              get { return SR.GetResourceString("SFxServiceMetadataBehaviorNoHttpBaseAddress", @"The HttpGetEnabled property of ServiceMetadataBehavior is set to true and the HttpGetUrl property is a relative address, but there is no http base address.  Either supply an http base address or set HttpGetUrl to an absolute address."); }
        }
        internal static string SFxServiceMetadataBehaviorNoHttpsBaseAddress {
              get { return SR.GetResourceString("SFxServiceMetadataBehaviorNoHttpsBaseAddress", @"The HttpsGetEnabled property of ServiceMetadataBehavior is set to true and the HttpsGetUrl property is a relative address, but there is no https base address.  Either supply an https base address or set HttpsGetUrl to an absolute address."); }
        }
        internal static string SFxServiceMetadataBehaviorInstancingError {
              get { return SR.GetResourceString("SFxServiceMetadataBehaviorInstancingError", @"The ChannelDispatcher with ListenUri '{0}' has endpoints with the following contracts: {1}. Metadata endpoints cannot share ListenUris. The conflicting endpoints were either specified in AddServiceEndpoint() calls, in a config file, or a combination of AddServiceEndpoint() and config."); }
        }
        internal static string SFxServiceTypeNotCreatable {
              get { return SR.GetResourceString("SFxServiceTypeNotCreatable", @"Service implementation type is an interface or abstract class and no implementation object was provided."); }
        }
        internal static string SFxSetEnableFaultsOnChannelDispatcher0 {
              get { return SR.GetResourceString("SFxSetEnableFaultsOnChannelDispatcher0", @"This property sets EnableFaults on the client. To set EnableFaults on the server, use ChannelDispatcher's EnableFaults."); }
        }
        internal static string SFxSetManualAddresssingOnChannelDispatcher0 {
              get { return SR.GetResourceString("SFxSetManualAddresssingOnChannelDispatcher0", @"This property sets ManualAddressing on the client. To set ManualAddressing on the server, use ChannelDispatcher's ManualAddressing."); }
        }
        internal static string SFxNoBatchingForSession {
              get { return SR.GetResourceString("SFxNoBatchingForSession", @"TransactedBatchingBehavior validation failed. Service or client cannot be started. Transacted batching is not supported for session contracts. Remove transacted batching behavior from the endpoint or define a non-sessionful contract."); }
        }
        internal static string SFxNoBatchingForReleaseOnComplete {
              get { return SR.GetResourceString("SFxNoBatchingForReleaseOnComplete", @"TransactedBatchingBehavior validation failed. Service cannot be started. Transacted batching requires ServiceBehavior.ReleaseServiceInstanceOnTransactionComplete to be false."); }
        }
        internal static string SFxNoServiceObject {
              get { return SR.GetResourceString("SFxNoServiceObject", @"The service implementation object was not initialized or is not available."); }
        }
        internal static string SFxNone2004 {
              get { return SR.GetResourceString("SFxNone2004", @"The WS-Addressing \""none\"" value is not valid for the August 2004 version of WS-Addressing."); }
        }
        internal static string SFxNonExceptionThrown {
              get { return SR.GetResourceString("SFxNonExceptionThrown", @"An object that is not an exception was thrown."); }
        }
        internal static string SFxNonInitiatingOperation1 {
              get { return SR.GetResourceString("SFxNonInitiatingOperation1", @"The operation '{0}' cannot be the first operation to be called because IsInitiating is false."); }
        }
        internal static string SfxNoTypeSpecifiedForParameter {
              get { return SR.GetResourceString("SfxNoTypeSpecifiedForParameter", @"There was no CLR type specified for parameter {0}, preventing the operation from being generated."); }
        }
        internal static string SFxOneWayAndTransactionsIncompatible {
              get { return SR.GetResourceString("SFxOneWayAndTransactionsIncompatible", @"The one-way operation '{1}' on ServiceContract '{0}' is configured for transaction flow. Transactions cannot be flowed over one-way operations."); }
        }
        internal static string SFxOneWayMessageToTwoWayMethod0 {
              get { return SR.GetResourceString("SFxOneWayMessageToTwoWayMethod0", @"The incoming message with action could not be processed because it is targeted at a request-reply operation, but cannot be replied to as the MessageId property is not set."); }
        }
        internal static string SFxOperationBehaviorAttributeOnlyOnServiceClass {
              get { return SR.GetResourceString("SFxOperationBehaviorAttributeOnlyOnServiceClass", @"OperationBehaviorAttribute can only go on the service class, it cannot be put on the ServiceContract interface. Method '{0}' on type '{1}' violates this."); }
        }
        internal static string SFxOperationBehaviorAttributeReleaseInstanceModeDoesNotApplyToCallback {
              get { return SR.GetResourceString("SFxOperationBehaviorAttributeReleaseInstanceModeDoesNotApplyToCallback", @"The ReleaseInstanceMode property on OperationBehaviorAttribute can only be set on non-callback operations. Method '{0}' violates this."); }
        }
        internal static string SFxOperationContractOnNonServiceContract {
              get { return SR.GetResourceString("SFxOperationContractOnNonServiceContract", @"Method '{0}' has OperationContractAttribute, but enclosing type '{1}' does not have ServiceContractAttribute. OperationContractAttribute can only be used on methods in ServiceContractAttribute types or on their CallbackContract types."); }
        }
        internal static string SFxOperationContractProviderOnNonServiceContract {
              get { return SR.GetResourceString("SFxOperationContractProviderOnNonServiceContract", @"Method '{1}' has {0}, but enclosing type '{2}' does not have ServiceContractAttribute. {0} can only be used on methods in ServiceContractAttribute types."); }
        }
        internal static string SFxOperationDescriptionNameCannotBeEmpty {
              get { return SR.GetResourceString("SFxOperationDescriptionNameCannotBeEmpty", @"OperationDescription's Name must be a non-empty string."); }
        }
        internal static string SFxParameterNameCannotBeNull {
              get { return SR.GetResourceString("SFxParameterNameCannotBeNull", @"All parameter names used in operations that make up a service contract must not be null."); }
        }
        internal static string SFxOperationMustHaveOneOrTwoMessages {
              get { return SR.GetResourceString("SFxOperationMustHaveOneOrTwoMessages", @"OperationDescription '{0}' is invalid because its Messages property contains an invalid number of MessageDescription instances. Each OperationDescription must have one or two messages."); }
        }
        internal static string SFxParameterCountMismatch {
              get { return SR.GetResourceString("SFxParameterCountMismatch", @"There was a mismatch between the number of supplied arguments and the number of expected arguments.  Specifically, the argument '{0}' has '{1}' elements while the argument '{2}' has '{3}' elements."); }
        }
        internal static string SFxParameterMustBeMessage {
              get { return SR.GetResourceString("SFxParameterMustBeMessage", @"The 'parameters' argument must be an array that contains a single Message object."); }
        }
        internal static string SFxParametersMustBeEmpty {
              get { return SR.GetResourceString("SFxParametersMustBeEmpty", @"The 'parameters' argument must be either null or an empty array."); }
        }
        internal static string SFxParameterMustBeArrayOfOneElement {
              get { return SR.GetResourceString("SFxParameterMustBeArrayOfOneElement", @"The 'parameters' argument must be an array of one element."); }
        }
        internal static string SFxPartNameMustBeUniqueInRpc {
              get { return SR.GetResourceString("SFxPartNameMustBeUniqueInRpc", @"Message part name {0} is not unique in an RPC Message."); }
        }
        internal static string SFxReceiveContextSettingsPropertyMissing {
              get { return SR.GetResourceString("SFxReceiveContextSettingsPropertyMissing", @"The contract '{0}' has at least one operation annotated with '{1}', but the binding used for the contract endpoint at address '{2}' does not support required binding property '{3}'. Please ensure that the binding used for the contract supports the ReceiveContext capability."); }
        }
        internal static string SFxReceiveContextPropertyMissing {
              get { return SR.GetResourceString("SFxReceiveContextPropertyMissing", @"Required message property '{0}' is missing from the IncomingProperties collections of the received message. Ensure that when the receive context is enabled on the binding, the created channel ensures that '{0}' is present on all received messages."); }
        }
        internal static string SFxRequestHasInvalidReplyToOnClient {
              get { return SR.GetResourceString("SFxRequestHasInvalidReplyToOnClient", @"The request message has ReplyTo='{0}' but IContextChannel.LocalAddress is '{1}'.  When ManualAddressing is false, these values must be the same, null, or EndpointAddress.AnonymousAddress.  Enable ManualAddressing or avoid setting ReplyTo on the message."); }
        }
        internal static string SFxRequestHasInvalidFaultToOnClient {
              get { return SR.GetResourceString("SFxRequestHasInvalidFaultToOnClient", @"The request message has FaultTo='{0}' but IContextChannel.LocalAddress is '{1}'.  When ManualAddressing is false, these values must be the same, null, or EndpointAddress.AnonymousAddress.  Enable ManualAddressing or avoid setting FaultTo on the message."); }
        }
        internal static string SFxRequestHasInvalidFromOnClient {
              get { return SR.GetResourceString("SFxRequestHasInvalidFromOnClient", @"The request message has From='{0}' but IContextChannel.LocalAddress is '{1}'.  When ManualAddressing is false, these values must be the same, null, or EndpointAddress.AnonymousAddress.  Enable ManualAddressing or avoid setting From on the message."); }
        }
        internal static string SFxRequestHasInvalidReplyToOnServer {
              get { return SR.GetResourceString("SFxRequestHasInvalidReplyToOnServer", @"The request message has ReplyTo='{0}' but IContextChannel.RemoteAddress is '{1}'.  When ManualAddressing is false, these values must be the same, null, or EndpointAddress.AnonymousAddress because sending a reply to a different address than the original sender can create a security risk.  If you want to process such messages, enable ManualAddressing."); }
        }
        internal static string SFxRequestHasInvalidFaultToOnServer {
              get { return SR.GetResourceString("SFxRequestHasInvalidFaultToOnServer", @"The request message has FaultTo='{0}' but IContextChannel.RemoteAddress is '{1}'.  When ManualAddressing is false, these values must be the same, null, or EndpointAddress.AnonymousAddress because sending a reply to a different address than the original sender can create a security risk.  If you want to process such messages, enable ManualAddressing."); }
        }
        internal static string SFxRequestHasInvalidFromOnServer {
              get { return SR.GetResourceString("SFxRequestHasInvalidFromOnServer", @"The request message has From='{0}' but IContextChannel.RemoteAddress is '{1}'.  When ManualAddressing is false, these values must be the same, null, or EndpointAddress.AnonymousAddress because sending a reply to a different address than the original sender can create a security risk.  If you want to process such messages, enable ManualAddressing."); }
        }
        internal static string SFxRequestReplyNone {
              get { return SR.GetResourceString("SFxRequestReplyNone", @"A message was received with a WS-Addressing ReplyTo or FaultTo header targeted at the \""None\"" address.  These values are not valid for request-reply operations.  Please consider using a one-way operation or enabling ManualAddressing if you need to support ReplyTo or FaultTo values of \""None.\"""); }
        }
        internal static string SFxRequestTimedOut1 {
              get { return SR.GetResourceString("SFxRequestTimedOut1", @"This request operation did not receive a reply within the configured timeout ({0}).  The time allotted to this operation may have been a portion of a longer timeout.  This may be because the service is still processing the operation or because the service was unable to send a reply message.  Please consider increasing the operation timeout (by casting the channel/proxy to IContextChannel and setting the OperationTimeout property) and ensure that the service is able to connect to the client."); }
        }
        internal static string SFxRequestTimedOut2 {
              get { return SR.GetResourceString("SFxRequestTimedOut2", @"This request operation sent to {0} did not receive a reply within the configured timeout ({1}).  The time allotted to this operation may have been a portion of a longer timeout.  This may be because the service is still processing the operation or because the service was unable to send a reply message.  Please consider increasing the operation timeout (by casting the channel/proxy to IContextChannel and setting the OperationTimeout property) and ensure that the service is able to connect to the client."); }
        }
        internal static string SFxReplyActionMismatch3 {
              get { return SR.GetResourceString("SFxReplyActionMismatch3", @"A reply message was received for operation '{0}' with action '{1}'. However, your client code requires action '{2}'."); }
        }
        internal static string SFxRequiredRuntimePropertyMissing {
              get { return SR.GetResourceString("SFxRequiredRuntimePropertyMissing", @"Required runtime property '{0}' is not initialized on DispatchRuntime. Do not remove ServiceBehaviorAttribute from ServiceDescription.Behaviors or ensure that you include a third-party service behavior that supplies this value."); }
        }
        internal static string SFxResolvedMaxResolvedReferences {
              get { return SR.GetResourceString("SFxResolvedMaxResolvedReferences", @"The MetadataExchangeClient has resolved more than MaximumResolvedReferences."); }
        }
        internal static string SFxResultMustBeMessage {
              get { return SR.GetResourceString("SFxResultMustBeMessage", @"The 'result' argument must be of type Message."); }
        }
        internal static string SFxRevertImpersonationFailed0 {
              get { return SR.GetResourceString("SFxRevertImpersonationFailed0", @"Could not revert impersonation on current thread. Continuing would compromise system security. Terminating process."); }
        }
        internal static string SFxRpcMessageBodyPartNameInvalid {
              get { return SR.GetResourceString("SFxRpcMessageBodyPartNameInvalid", @"RPC Message {1} in operation {0} has an invalid body name {2}. It must be {3}"); }
        }
        internal static string SFxRpcMessageMustHaveASingleBody {
              get { return SR.GetResourceString("SFxRpcMessageMustHaveASingleBody", @"RPC Message {1} in operation {0} must have a single MessageBodyMember."); }
        }
        internal static string SFxSchemaDoesNotContainElement {
              get { return SR.GetResourceString("SFxSchemaDoesNotContainElement", @"There was a problem loading the XSD documents provided: a reference to a schema element with name '{0}' and namespace '{1}' could not be resolved because the element definition could not be found in the schema for targetNamespace '{1}'. Please check the XSD documents provided and try again."); }
        }
        internal static string SFxSchemaDoesNotContainType {
              get { return SR.GetResourceString("SFxSchemaDoesNotContainType", @"There was a problem loading the XSD documents provided: a reference to a schema type with name '{0}' and namespace '{1}' could not be resolved because the type definition could not be found in the schema for targetNamespace '{1}'. Please check the XSD documents provided and try again."); }
        }
        internal static string SFxWsdlMessageDoesNotContainPart3 {
              get { return SR.GetResourceString("SFxWsdlMessageDoesNotContainPart3", @"Service description message '{1}' from target namespace '{2}' does not contain part named '{0}'."); }
        }
        internal static string SFxSchemaNotFound {
              get { return SR.GetResourceString("SFxSchemaNotFound", @"Schema with target namespace '{0}' could not be found."); }
        }
        internal static string SFxSecurityContextPropertyMissingFromRequestMessage {
              get { return SR.GetResourceString("SFxSecurityContextPropertyMissingFromRequestMessage", @"SecurityContextProperty is missing from the request Message, this may indicate security is configured incorrectly."); }
        }
        internal static string SFxServerDidNotReply {
              get { return SR.GetResourceString("SFxServerDidNotReply", @"The server did not provide a meaningful reply; this might be caused by a contract mismatch, a premature session shutdown or an internal server error."); }
        }
        internal static string SFxServiceHostBaseCannotAddEndpointAfterOpen {
              get { return SR.GetResourceString("SFxServiceHostBaseCannotAddEndpointAfterOpen", @"Endpoints cannot be added after the ServiceHost has been opened/faulted/aborted/closed."); }
        }
        internal static string SFxServiceHostBaseCannotAddEndpointWithoutDescription {
              get { return SR.GetResourceString("SFxServiceHostBaseCannotAddEndpointWithoutDescription", @"Endpoints cannot be added before the Description property has been initialized."); }
        }
        internal static string SFxServiceHostBaseCannotApplyConfigurationWithoutDescription {
              get { return SR.GetResourceString("SFxServiceHostBaseCannotApplyConfigurationWithoutDescription", @"ApplyConfiguration requires that the Description property be initialized. Either provide a valid ServiceDescription in the CreateDescription method or override the ApplyConfiguration method to provide an alternative implementation."); }
        }
        internal static string SFxServiceHostBaseCannotLoadConfigurationSectionWithoutDescription {
              get { return SR.GetResourceString("SFxServiceHostBaseCannotLoadConfigurationSectionWithoutDescription", @"LoadConfigurationSection requires that the Description property be initialized. Provide a valid ServiceDescription in the CreateDescription method."); }
        }
        internal static string SFxServiceHostBaseCannotInitializeRuntimeWithoutDescription {
              get { return SR.GetResourceString("SFxServiceHostBaseCannotInitializeRuntimeWithoutDescription", @"InitializeRuntime requires that the Description property be initialized. Either provide a valid ServiceDescription in the CreateDescription method or override the InitializeRuntime method to provide an alternative implementation."); }
        }
        internal static string SFxServiceHostCannotCreateDescriptionWithoutServiceType {
              get { return SR.GetResourceString("SFxServiceHostCannotCreateDescriptionWithoutServiceType", @"InitializeDescription must be called with a serviceType or singletonInstance parameter."); }
        }
        internal static string SFxStaticMessageHeaderPropertiesNotAllowed {
              get { return SR.GetResourceString("SFxStaticMessageHeaderPropertiesNotAllowed", @"Header properties cannot be set in MessageHeaderAttribute of {0} as its type is MessageHeader<T>."); }
        }
        internal static string SFxStreamIOException {
              get { return SR.GetResourceString("SFxStreamIOException", @"An exception has been thrown when reading the stream."); }
        }
        internal static string SFxStreamRequestMessageClosed {
              get { return SR.GetResourceString("SFxStreamRequestMessageClosed", @"The message containing this stream has been closed. Note that request streams cannot be accessed after the service operation returns."); }
        }
        internal static string SFxStreamResponseMessageClosed {
              get { return SR.GetResourceString("SFxStreamResponseMessageClosed", @"The message containing this stream has been closed. "); }
        }
        internal static string SFxThrottleLimitMustBeGreaterThanZero0 {
              get { return SR.GetResourceString("SFxThrottleLimitMustBeGreaterThanZero0", @"Throttle limit must be greater than zero. To disable, set to Int32.MaxValue."); }
        }
        internal static string SFxTimeoutInvalidStringFormat {
              get { return SR.GetResourceString("SFxTimeoutInvalidStringFormat", @"The timeout value provided was not of a recognized format.  Please see InnerException for more details."); }
        }
        internal static string SFxTimeoutOutOfRange0 {
              get { return SR.GetResourceString("SFxTimeoutOutOfRange0", @"Timeout must be greater than or equal to TimeSpan.Zero. To disable timeout, specify TimeSpan.MaxValue."); }
        }
        internal static string SFxTimeoutOutOfRangeTooBig {
              get { return SR.GetResourceString("SFxTimeoutOutOfRangeTooBig", @"Timeouts larger than Int32.MaxValue TotalMilliseconds (approximately 24 days) cannot be honored. To disable timeout, specify TimeSpan.MaxValue."); }
        }
        internal static string SFxTooManyPartsWithSameName {
              get { return SR.GetResourceString("SFxTooManyPartsWithSameName", @"Cannot create a unique part name for {0}."); }
        }
        internal static string SFxTraceCodeElementIgnored {
              get { return SR.GetResourceString("SFxTraceCodeElementIgnored", @"An unrecognized element was encountered in the XML during deserialization which was ignored."); }
        }
        internal static string SfxTransactedBindingNeeded {
              get { return SR.GetResourceString("SfxTransactedBindingNeeded", @"TransactedBatchingBehavior validation failed. The service endpoint cannot be started. TransactedBatchingBehavior requires a binding that contains a binding element ITransactedBindingElement that returns true for ITransactedBindingElement.TransactedReceiveEnabled. If you are using NetMsmqBinding or MsmqIntegrationBinding make sure that ExactlyOnce is set to true."); }
        }
        internal static string SFxTransactionNonConcurrentOrAutoComplete2 {
              get { return SR.GetResourceString("SFxTransactionNonConcurrentOrAutoComplete2", @"TThe operation '{1}' on contract '{0}' is configured with TransactionAutoComplete set to false and with ConcurrencyMode not set to Single. TransactionAutoComplete set to false requires ConcurrencyMode.Single."); }
        }
        internal static string SFxTransactionNonConcurrentOrReleaseServiceInstanceOnTxComplete {
              get { return SR.GetResourceString("SFxTransactionNonConcurrentOrReleaseServiceInstanceOnTxComplete", @"The '{0}' service is configured with ReleaseServiceInstanceOnTransactionComplete set to true, but the ConcurrencyMode is not set to Single. The ReleaseServiceInstanceOnTransactionComplete requires the use of ConcurrencyMode.Single."); }
        }
        internal static string SFxNonConcurrentOrEnsureOrderedDispatch {
              get { return SR.GetResourceString("SFxNonConcurrentOrEnsureOrderedDispatch", @"The '{0}' service is configured with EnsureOrderedDispatch set to true, but the ConcurrencyMode is not set to Single. EnsureOrderedDispatch requires the use of ConcurrencyMode.Single."); }
        }
        internal static string SfxDispatchRuntimeNonConcurrentOrEnsureOrderedDispatch {
              get { return SR.GetResourceString("SfxDispatchRuntimeNonConcurrentOrEnsureOrderedDispatch", @"The DispatchRuntime.EnsureOrderedDispatch property is set to true, but the DispatchRuntime.ConcurrencyMode is not set to Single. EnsureOrderedDispatch requires the use of ConcurrencyMode.Single."); }
        }
        internal static string SFxTransactionsNotSupported {
              get { return SR.GetResourceString("SFxTransactionsNotSupported", @"The service does not support concurrent transactions."); }
        }
        internal static string SFxTransactionAsyncAborted {
              get { return SR.GetResourceString("SFxTransactionAsyncAborted", @"The transaction under which this method call was executing was asynchronously aborted."); }
        }
        internal static string SFxTransactionInvalidSetTransactionComplete {
              get { return SR.GetResourceString("SFxTransactionInvalidSetTransactionComplete", @"The SetTransactionComplete method was called in the operation '{0}' on contract '{1}' when TransactionAutoComplete was set to true. The SetTransactionComplete method can only be called when TransactionAutoComplete is set to false. This is an invalid scenario and the current transaction was aborted."); }
        }
        internal static string SFxMultiSetTransactionComplete {
              get { return SR.GetResourceString("SFxMultiSetTransactionComplete", @"The SetTransactionComplete method was wrongly called more than once in the operation '{0}' on contract '{1}'. The SetTransactionComplete method can only be called once. This is an invalid scenario and the current transaction was aborted."); }
        }
        internal static string SFxTransactionFlowAndMSMQ {
              get { return SR.GetResourceString("SFxTransactionFlowAndMSMQ", @"The binding for the endpoint at address '{0}' is configured with both the MsmqTransportBindingElement and the TransactionFlowBindingElement. These two elements cannot be used together."); }
        }
        internal static string SFxTransactionAutoCompleteFalseAndInstanceContextMode {
              get { return SR.GetResourceString("SFxTransactionAutoCompleteFalseAndInstanceContextMode", @"The operation '{1}' on contract '{0}' is configured with TransactionAutoComplete set to false and the InstanceContextMode is not set to PerSession. TransactionAutoComplete set to false requires the use of InstanceContextMode.PerSession."); }
        }
        internal static string SFxTransactionAutoCompleteFalseOnCallbackContract {
              get { return SR.GetResourceString("SFxTransactionAutoCompleteFalseOnCallbackContract", @"The operation '{0}' on callback contract '{1}' is configured with TransactionAutoComplete set to false. TransactionAutoComplete set to false cannot be used with operations on callback contracts."); }
        }
        internal static string SFxTransactionAutoCompleteFalseAndSupportsSession {
              get { return SR.GetResourceString("SFxTransactionAutoCompleteFalseAndSupportsSession", @"The operation '{1}' on contract '{0}' is configured with TransactionAutoComplete set to false but SessionMode is not set to Required. TransactionAutoComplete set to false requires SessionMode.Required."); }
        }
        internal static string SFxTransactionAutoCompleteOnSessionCloseNoSession {
              get { return SR.GetResourceString("SFxTransactionAutoCompleteOnSessionCloseNoSession", @"The service '{0}' is configured with TransactionAutoCompleteOnSessionClose set to true and with an InstanceContextMode not set to PerSession. TransactionAutoCompleteOnSessionClose set to true requires an instancing mode that uses sessions."); }
        }
        internal static string SFxTransactionTransactionTimeoutNeedsScope {
              get { return SR.GetResourceString("SFxTransactionTransactionTimeoutNeedsScope", @"The service '{0}' is configured with a TransactionTimeout but no operations are configured with TransactionScopeRequired set to true. TransactionTimeout requires at least one operation with TransactionScopeRequired set to true."); }
        }
        internal static string SFxTransactionIsolationLevelNeedsScope {
              get { return SR.GetResourceString("SFxTransactionIsolationLevelNeedsScope", @"The service '{0}' is configured with a TransactionIsolationLevel but no operations are configured with TransactionScopeRequired set to true. TransactionIsolationLevel requires at least one operation with TransactionScopeRequired set to true."); }
        }
        internal static string SFxTransactionReleaseServiceInstanceOnTransactionCompleteNeedsScope {
              get { return SR.GetResourceString("SFxTransactionReleaseServiceInstanceOnTransactionCompleteNeedsScope", @"The service '{0}' is configured with ReleaseServiceInstanceOnTransactionComplete but no operations are configured with TransactionScopeRequired set to true. The ReleaseServiceInstanceOnTransactionComplete property requires at least one operation with TransactionScopeRequired set to true. Remove the ReleaseServiceInstanceOnTransactionComplete property from the service if this is the case."); }
        }
        internal static string SFxTransactionTransactionAutoCompleteOnSessionCloseNeedsScope {
              get { return SR.GetResourceString("SFxTransactionTransactionAutoCompleteOnSessionCloseNeedsScope", @"The service '{0}' is configured with TransactionAutoCompleteOnSessionClose, but no operations are configured with TransactionScopeRequired set to true. The TransactionAutoCompleteOnSessionClose property requires at least one operation with TransactionScopeRequired set to true. Remove the TransactionAutoCompleteOnSessionClose property from the service if this is the case."); }
        }
        internal static string SFxTransactionFlowRequired {
              get { return SR.GetResourceString("SFxTransactionFlowRequired", @"The service operation requires a transaction to be flowed."); }
        }
        internal static string SFxTransactionUnmarshalFailed {
              get { return SR.GetResourceString("SFxTransactionUnmarshalFailed", @"The flowed transaction could not be unmarshaled. The following exception occurred: {0}"); }
        }
        internal static string SFxTransactionDeserializationFailed {
              get { return SR.GetResourceString("SFxTransactionDeserializationFailed", @"The incoming transaction cannot be deserialized. The transaction header in the message was either malformed or in an unrecognized format. The client and the service must be configured to use the same protocol and protocol version. The following exception occurred: {0}"); }
        }
        internal static string SFxTransactionHeaderNotUnderstood {
              get { return SR.GetResourceString("SFxTransactionHeaderNotUnderstood", @"The transaction header '{0}' within the namespace '{1}' was not understood by the service. The client and the service must be configured to use the same protocol and protocol version ('{2}')."); }
        }
        internal static string SFxTryAddMultipleTransactionsOnMessage {
              get { return SR.GetResourceString("SFxTryAddMultipleTransactionsOnMessage", @"An attempt was made to add more than one transaction to a message. At most one transaction can be added."); }
        }
        internal static string SFxTypedMessageCannotBeNull {
              get { return SR.GetResourceString("SFxTypedMessageCannotBeNull", @"Internal Error: The instance of the MessageContract cannot be null in {0}."); }
        }
        internal static string SFxTypedMessageCannotBeRpcLiteral {
              get { return SR.GetResourceString("SFxTypedMessageCannotBeRpcLiteral", @"The operation '{0}' could not be loaded because it specifies \""rpc-style\"" in \""literal\"" mode, but uses message contract types or the System.ServiceModel.Channels.Message. This combination is disallowed -- specify a different value for style or use parameters other than message contract types or System.ServiceModel.Channels.Message."); }
        }
        internal static string SFxTypedOrUntypedMessageCannotBeMixedWithParameters {
              get { return SR.GetResourceString("SFxTypedOrUntypedMessageCannotBeMixedWithParameters", @"The operation '{0}' could not be loaded because it has a parameter or return type of type System.ServiceModel.Channels.Message or a type that has MessageContractAttribute and other parameters of different types. When using System.ServiceModel.Channels.Message or types with MessageContractAttribute, the method must not use any other types of parameters."); }
        }
        internal static string SFxTypedOrUntypedMessageCannotBeMixedWithVoidInRpc {
              get { return SR.GetResourceString("SFxTypedOrUntypedMessageCannotBeMixedWithVoidInRpc", @"When using the rpc-encoded style, message contract types or the System.ServiceModel.Channels.Message type cannot be used if the operation has no parameters or has a void return value. Add a blank message contract type as a parameter or return type to operation '{0}'."); }
        }
        internal static string SFxUnknownFaultNoMatchingTranslation1 {
              get { return SR.GetResourceString("SFxUnknownFaultNoMatchingTranslation1", @"This fault did not provide a matching translation: {0}"); }
        }
        internal static string SFxUnknownFaultNullReason0 {
              get { return SR.GetResourceString("SFxUnknownFaultNullReason0", @"This fault did not provide a reason (MessageFault.Reason was null)."); }
        }
        internal static string SFxUnknownFaultZeroReasons0 {
              get { return SR.GetResourceString("SFxUnknownFaultZeroReasons0", @"This fault did not provide a reason (MessageFault.Reason.Translations.Count was 0)."); }
        }
        internal static string SFxUserCodeThrewException {
              get { return SR.GetResourceString("SFxUserCodeThrewException", @"User operation '{0}.{1}' threw an exception that is unhandled in user code. This exception will be rethrown. If this is a recurring problem, it may indicate an error in the implementation of the '{0}.{1}' method."); }
        }
        internal static string SfxUseTypedMessageForCustomAttributes {
              get { return SR.GetResourceString("SfxUseTypedMessageForCustomAttributes", @"Parameter '{0}' requires additional schema information that cannot be captured using the parameter mode. The specific attribute is '{1}'."); }
        }
        internal static string SFxWellKnownNonSingleton0 {
              get { return SR.GetResourceString("SFxWellKnownNonSingleton0", @"In order to use one of the ServiceHost constructors that takes a service instance, the InstanceContextMode of the service must be set to InstanceContextMode.Single.  This can be configured via the ServiceBehaviorAttribute.  Otherwise, please consider using the ServiceHost constructors that take a Type argument."); }
        }
        internal static string SFxVersionMismatchInOperationContextAndMessage2 {
              get { return SR.GetResourceString("SFxVersionMismatchInOperationContextAndMessage2", @"Cannot add outgoing headers to message as MessageVersion in OperationContext.Current '{0}' does not match with the header version of message being processed '{1}'."); }
        }
        internal static string SFxWhenMultipleEndpointsShareAListenUriTheyMustHaveSameIdentity {
              get { return SR.GetResourceString("SFxWhenMultipleEndpointsShareAListenUriTheyMustHaveSameIdentity", @"When multiple endpoints on a service share the same ListenUri, those endpoints must all have the same Identity in their EndpointAddress. The endpoints at ListenUri '{0}' do not meet this criteria."); }
        }
        internal static string SFxWrapperNameCannotBeEmpty {
              get { return SR.GetResourceString("SFxWrapperNameCannotBeEmpty", @"Wrapper element name cannot be empty."); }
        }
        internal static string SFxWrapperTypeHasMultipleNamespaces {
              get { return SR.GetResourceString("SFxWrapperTypeHasMultipleNamespaces", @"Wrapper type for message {0} cannot be projected as a data contract type since it has multiple namespaces. Consider using the XmlSerializer"); }
        }
        internal static string SFxWsdlPartMustHaveElementOrType {
              get { return SR.GetResourceString("SFxWsdlPartMustHaveElementOrType", @"WSDL part {0} in message {1} from namespace {2} must have either an element or a type name"); }
        }
        internal static string SFxDataContractSerializerDoesNotSupportBareArray {
              get { return SR.GetResourceString("SFxDataContractSerializerDoesNotSupportBareArray", @"DataContractSerializer does not support collection specified on element '{0}' "); }
        }
        internal static string SFxDataContractSerializerDoesNotSupportEncoded {
              get { return SR.GetResourceString("SFxDataContractSerializerDoesNotSupportEncoded", @"Invalid OperationFormatUse specified in the OperationFormatStyle of operation {0}, DataContractSerializer supports only Literal."); }
        }
        internal static string SFxXmlArrayNotAllowedForMultiple {
              get { return SR.GetResourceString("SFxXmlArrayNotAllowedForMultiple", @"XmlArrayAttribute cannot be used in repeating part {1}:{0}."); }
        }
        internal static string SFxXmlSerializerIsNotFound {
              get { return SR.GetResourceString("SFxXmlSerializerIsNotFound", @"Could not find XmlSerializer for type {0}."); }
        }
        internal static string SFxConfigContractNotFound {
              get { return SR.GetResourceString("SFxConfigContractNotFound", @"Could not find default endpoint element that references contract '{0}' in the ServiceModel client configuration section. This might be because no configuration file was found for your application, or because no endpoint element matching this contract could be found in the client element."); }
        }
        internal static string SFxConfigChannelConfigurationNotFound {
              get { return SR.GetResourceString("SFxConfigChannelConfigurationNotFound", @"Could not find endpoint element with name '{0}' and contract '{1}' in the ServiceModel client configuration section. This might be because no configuration file was found for your application, or because no endpoint element matching this name could be found in the client element."); }
        }
        internal static string SFxChannelFactoryEndpointAddressUri {
              get { return SR.GetResourceString("SFxChannelFactoryEndpointAddressUri", @"The Address property on ChannelFactory.Endpoint was null.  The ChannelFactory's Endpoint must have a valid Address specified."); }
        }
        internal static string SFxServiceContractGeneratorConfigRequired {
              get { return SR.GetResourceString("SFxServiceContractGeneratorConfigRequired", @"In order to generate configuration information using the GenerateServiceEndpoint method, the ServiceContractGenerator instance must have been initialized with a valid Configuration object."); }
        }
        internal static string SFxCloseTimedOut1 {
              get { return SR.GetResourceString("SFxCloseTimedOut1", @"The ServiceHost close operation timed out after {0}.  This could be because a client failed to close a sessionful channel within the required time.  The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string SfxCloseTimedOutWaitingForDispatchToComplete {
              get { return SR.GetResourceString("SfxCloseTimedOutWaitingForDispatchToComplete", @"Close process timed out waiting for service dispatch to complete."); }
        }
        internal static string SFxInvalidWsdlBindingOpMismatch2 {
              get { return SR.GetResourceString("SFxInvalidWsdlBindingOpMismatch2", @"The WSDL binding named {0} is not valid because no match for operation {1} was found in the corresponding portType definition."); }
        }
        internal static string SFxInvalidWsdlBindingOpNoName {
              get { return SR.GetResourceString("SFxInvalidWsdlBindingOpNoName", @"The WSDL binding named {0} is not valid because an operation binding doesn't have a name specified."); }
        }
        internal static string SFxChannelFactoryNoBindingFoundInConfig1 {
              get { return SR.GetResourceString("SFxChannelFactoryNoBindingFoundInConfig1", @"The underlying channel factory could not be created because no binding information was found in the configuration file for endpoint with name '{0}'.  Please check the endpoint configuration section with name '{0}' to ensure that binding information is present and correct."); }
        }
        internal static string SFxChannelFactoryNoBindingFoundInConfigOrCode {
              get { return SR.GetResourceString("SFxChannelFactoryNoBindingFoundInConfigOrCode", @"The underlying channel factory could not be created because no Binding was passed to the ChannelFactory. Please supply a valid Binding instance via the ChannelFactory constructor."); }
        }
        internal static string SFxConfigLoaderMultipleEndpointMatchesSpecified2 {
              get { return SR.GetResourceString("SFxConfigLoaderMultipleEndpointMatchesSpecified2", @"The endpoint configuration section for contract '{0}' with name '{1}' could not be loaded because more than one endpoint configuration with the same name and contract were found. Please check your config and try again."); }
        }
        internal static string SFxConfigLoaderMultipleEndpointMatchesWildcard1 {
              get { return SR.GetResourceString("SFxConfigLoaderMultipleEndpointMatchesWildcard1", @"An endpoint configuration section for contract '{0}' could not be loaded because more than one endpoint configuration for that contract was found. Please indicate the preferred endpoint configuration section by name."); }
        }
        internal static string SFxProxyRuntimeMessageCannotBeNull {
              get { return SR.GetResourceString("SFxProxyRuntimeMessageCannotBeNull", @"In operation '{0}', cannot pass null to methods that take Message as input parameter."); }
        }
        internal static string SFxDispatchRuntimeMessageCannotBeNull {
              get { return SR.GetResourceString("SFxDispatchRuntimeMessageCannotBeNull", @"In operation '{0}', cannot return null from methods that return Message."); }
        }
        internal static string SFxServiceHostNeedsClass {
              get { return SR.GetResourceString("SFxServiceHostNeedsClass", @"ServiceHost only supports class service types."); }
        }
        internal static string SfxReflectedContractKeyNotFound2 {
              get { return SR.GetResourceString("SfxReflectedContractKeyNotFound2", @"The contract name '{0}' could not be found in the list of contracts implemented by the service '{1}'."); }
        }
        internal static string SfxReflectedContractKeyNotFoundEmpty {
              get { return SR.GetResourceString("SfxReflectedContractKeyNotFoundEmpty", @"In order to add an endpoint to the service '{0}', a non-empty contract name must be specified."); }
        }
        internal static string SfxReflectedContractKeyNotFoundIMetadataExchange {
              get { return SR.GetResourceString("SfxReflectedContractKeyNotFoundIMetadataExchange", @"The contract name 'IMetadataExchange' could not be found in the list of contracts implemented by the service {0}.  Add a ServiceMetadataBehavior to the configuration file or to the ServiceHost directly to enable support for this contract."); }
        }
        internal static string SfxServiceContractAttributeNotFound {
              get { return SR.GetResourceString("SfxServiceContractAttributeNotFound", @"The contract type {0} is not attributed with ServiceContractAttribute.  In order to define a valid contract, the specified type (either contract interface or service class) must be attributed with ServiceContractAttribute."); }
        }
        internal static string SfxReflectedContractsNotInitialized1 {
              get { return SR.GetResourceString("SfxReflectedContractsNotInitialized1", @"An endpoint for type '{0}' could not be added because the ServiceHost instance was not initialized properly.  In order to add endpoints by Type, the CreateDescription method must be called.  If you are using a class derived from ServiceHost, ensure that the class is properly calling base.CreateDescription."); }
        }
        internal static string SFxMessagePartDescriptionMissingType {
              get { return SR.GetResourceString("SFxMessagePartDescriptionMissingType", @"Instance of MessagePartDescription Name='{0}' Namespace='{1}' cannot be used in this context: required 'Type' property was not set."); }
        }
        internal static string SFxWsdlOperationInputNeedsMessageAttribute2 {
              get { return SR.GetResourceString("SFxWsdlOperationInputNeedsMessageAttribute2", @"The wsdl operation input {0} in portType {1} does not reference a message. This is either because the message attribute is missing or empty."); }
        }
        internal static string SFxWsdlOperationOutputNeedsMessageAttribute2 {
              get { return SR.GetResourceString("SFxWsdlOperationOutputNeedsMessageAttribute2", @"The wsdl operation output {0} in portType {1} does not reference a message. This is either because the message attribute is missing or empty."); }
        }
        internal static string SFxWsdlOperationFaultNeedsMessageAttribute2 {
              get { return SR.GetResourceString("SFxWsdlOperationFaultNeedsMessageAttribute2", @"The wsdl operation {0} in portType {1} contains a fault that does not reference a message. This is either because the message attribute is missing or empty."); }
        }
        internal static string SFxMessageContractAttributeRequired {
              get { return SR.GetResourceString("SFxMessageContractAttributeRequired", @"Cannot create a typed message from type '{0}'.  The functionality only valid for types decorated with MessageContractAttribute."); }
        }
        internal static string AChannelServiceEndpointIsNull0 {
              get { return SR.GetResourceString("AChannelServiceEndpointIsNull0", @"A Channel/Service Endpoint is null."); }
        }
        internal static string AChannelServiceEndpointSBindingIsNull0 {
              get { return SR.GetResourceString("AChannelServiceEndpointSBindingIsNull0", @"A Channel/Service endpoint's Binding is null."); }
        }
        internal static string AChannelServiceEndpointSContractIsNull0 {
              get { return SR.GetResourceString("AChannelServiceEndpointSContractIsNull0", @"A Channel/Service endpoint's Contract is null."); }
        }
        internal static string AChannelServiceEndpointSContractSNameIsNull0 {
              get { return SR.GetResourceString("AChannelServiceEndpointSContractSNameIsNull0", @"A Channel/Service endpoint's Contract's name is null or empty."); }
        }
        internal static string AChannelServiceEndpointSContractSNamespace0 {
              get { return SR.GetResourceString("AChannelServiceEndpointSContractSNamespace0", @"A Channel/Service endpoint's Contract's namespace is null."); }
        }
        internal static string ServiceHasZeroAppEndpoints {
              get { return SR.GetResourceString("ServiceHasZeroAppEndpoints", @"Service '{0}' has zero application (non-infrastructure) endpoints. This might be because no configuration file was found for your application, or because no service element matching the service name could be found in the configuration file, or because no endpoints were defined in the service element."); }
        }
        internal static string BindingRequirementsAttributeRequiresQueuedDelivery1 {
              get { return SR.GetResourceString("BindingRequirementsAttributeRequiresQueuedDelivery1", @"DeliveryRequirementsAttribute requires QueuedDelivery, but binding for the endpoint with contract '{0}' doesn't support it or isn't configured properly to support it."); }
        }
        internal static string BindingRequirementsAttributeDisallowsQueuedDelivery1 {
              get { return SR.GetResourceString("BindingRequirementsAttributeDisallowsQueuedDelivery1", @"DeliveryRequirementsAttribute disallows QueuedDelivery, but binding for the endpoint with contract '{0}' supports it."); }
        }
        internal static string SinceTheBindingForDoesnTSupportIBindingCapabilities1_1 {
              get { return SR.GetResourceString("SinceTheBindingForDoesnTSupportIBindingCapabilities1_1", @"The DeliveryRequirementsAttribute on contract '{0}' specifies that the binding must support ordered delivery (RequireOrderedDelivery).  This condition could not be verified because the configured binding does not implement IBindingDeliveryCapabilities.  The DeliveryRequirementsAttribute may only be used with bindings that implement the IBindingDeliveryCapabilities interface."); }
        }
        internal static string SinceTheBindingForDoesnTSupportIBindingCapabilities2_1 {
              get { return SR.GetResourceString("SinceTheBindingForDoesnTSupportIBindingCapabilities2_1", @"The DeliveryRequirementsAttribute on contract '{0}' specifies a QueuedDeliveryRequirements constraint.  This condition could not be verified because the configured binding does not implement IBindingDeliveryCapabilities.  The DeliveryRequirementsAttribute may only be used with bindings that implement the IBindingDeliveryCapabilities interface."); }
        }
        internal static string TheBindingForDoesnTSupportOrderedDelivery1 {
              get { return SR.GetResourceString("TheBindingForDoesnTSupportOrderedDelivery1", @"The DeliveryRequirementsAttribute on contract '{0}' specifies a QueuedDeliveryRequirements value of NotAllowed.  However, the configured binding for this contract specifies that it does support queued delivery.  A queued binding may not be used with this contract."); }
        }
        internal static string ChannelHasAtLeastOneOperationWithTransactionFlowEnabled {
              get { return SR.GetResourceString("ChannelHasAtLeastOneOperationWithTransactionFlowEnabled", @"At least one operation on the '{0}' contract is configured with the TransactionFlowAttribute attribute set to Mandatory but the channel's binding '{1}' is not configured with a TransactionFlowBindingElement. The TransactionFlowAttribute attribute set to Mandatory cannot be used without a TransactionFlowBindingElement."); }
        }
        internal static string ServiceHasAtLeastOneOperationWithTransactionFlowEnabled {
              get { return SR.GetResourceString("ServiceHasAtLeastOneOperationWithTransactionFlowEnabled", @"At least one operation on the '{0}' contract is configured with the TransactionFlowAttribute attribute set to Mandatory but the channel's binding '{1}' is not configured with a TransactionFlowBindingElement. The TransactionFlowAttribute attribute set to Mandatory cannot be used without a TransactionFlowBindingElement."); }
        }
        internal static string SFxNoEndpointMatchingContract {
              get { return SR.GetResourceString("SFxNoEndpointMatchingContract", @"The message with Action '{0}' cannot be processed at the receiver, due to a ContractFilter mismatch at the EndpointDispatcher. This may be because of either a contract mismatch (mismatched Actions between sender and receiver) or a binding/security mismatch between the sender and the receiver.  Check that sender and receiver have the same contract and the same binding (including security requirements, e.g. Message, Transport, None)."); }
        }
        internal static string SFxNoEndpointMatchingAddress {
              get { return SR.GetResourceString("SFxNoEndpointMatchingAddress", @"The message with To '{0}' cannot be processed at the receiver, due to an AddressFilter mismatch at the EndpointDispatcher.  Check that the sender and receiver's EndpointAddresses agree."); }
        }
        internal static string SFxNoEndpointMatchingAddressForConnectionOpeningMessage {
              get { return SR.GetResourceString("SFxNoEndpointMatchingAddressForConnectionOpeningMessage", @"The message with Action '{0}' cannot be processed at the receiver because this Action is reserved for the connection opening messages only and cannot be sent from client to server. To invoke this operation on the server, call the '{1}' method on the client proxy instead."); }
        }
        internal static string SFxServiceChannelCannotBeCalledBecauseIsSessionOpenNotificationEnabled {
              get { return SR.GetResourceString("SFxServiceChannelCannotBeCalledBecauseIsSessionOpenNotificationEnabled", @"The operation '{0}' could not be invoked because the property '{1}' on the OperationContract is set to '{2}'. To invoke this operation on the server, call the '{3}' method on the client proxy instead."); }
        }
        internal static string EndMethodsCannotBeDecoratedWithOperationContractAttribute {
              get { return SR.GetResourceString("EndMethodsCannotBeDecoratedWithOperationContractAttribute", @"When using the IAsyncResult design pattern, the End method cannot be decorated with OperationContractAttribute. Only the corresponding Begin method can be decorated with OperationContractAttribute; that attribute will apply to the Begin-End pair of methods. Method '{0}' in type '{1}' violates this."); }
        }
        internal static string WsatMessagingInitializationFailed {
              get { return SR.GetResourceString("WsatMessagingInitializationFailed", @"The WS-AT messaging library failed to initialize."); }
        }
        internal static string WsatProxyCreationFailed {
              get { return SR.GetResourceString("WsatProxyCreationFailed", @"A client-side channel to the WS-AT protocol service could not be created."); }
        }
        internal static string DispatchRuntimeRequiresFormatter0 {
              get { return SR.GetResourceString("DispatchRuntimeRequiresFormatter0", @"The DispatchOperation '{0}' requires Formatter, since DeserializeRequest and SerializeReply are not both false."); }
        }
        internal static string ClientRuntimeRequiresFormatter0 {
              get { return SR.GetResourceString("ClientRuntimeRequiresFormatter0", @"The ClientOperation '{0}' requires Formatter, since SerializeRequest and DeserializeReply are not both false."); }
        }
        internal static string RuntimeRequiresInvoker0 {
              get { return SR.GetResourceString("RuntimeRequiresInvoker0", @"DispatchOperation requires Invoker."); }
        }
        internal static string CouldnTCreateChannelForType2 {
              get { return SR.GetResourceString("CouldnTCreateChannelForType2", @"Channel requirements cannot be met by the ChannelFactory for Binding '{0}' since the contract requires support for one of these channel types '{1}' but the binding doesn't support any of them."); }
        }
        internal static string CouldnTCreateChannelForChannelType2 {
              get { return SR.GetResourceString("CouldnTCreateChannelForChannelType2", @"Channel type '{1}' was requested, but Binding '{0}' doesn't support it or isn't configured properly to support it."); }
        }
        internal static string EndpointListenerRequirementsCannotBeMetBy3 {
              get { return SR.GetResourceString("EndpointListenerRequirementsCannotBeMetBy3", @"ChannelDispatcher requirements cannot be met by the IChannelListener for Binding '{0}' since the contract requires support for one of these channel types '{1}' but the binding only supports these channel types '{2}'."); }
        }
        internal static string UnknownListenerType1 {
              get { return SR.GetResourceString("UnknownListenerType1", @"The listener at Uri '{0}' could not be initialized because it was created for an unrecognized channel type."); }
        }
        internal static string BindingDoesnTSupportSessionButContractRequires1 {
              get { return SR.GetResourceString("BindingDoesnTSupportSessionButContractRequires1", @"Contract requires Session, but Binding '{0}' doesn't support it or isn't configured properly to support it."); }
        }
        internal static string BindingDoesntSupportDatagramButContractRequires {
              get { return SR.GetResourceString("BindingDoesntSupportDatagramButContractRequires", @"Contract does not allow Session, but Binding '{0}' does not support Datagram or is not configured properly to support it."); }
        }
        internal static string BindingDoesnTSupportOneWayButContractRequires1 {
              get { return SR.GetResourceString("BindingDoesnTSupportOneWayButContractRequires1", @"Contract requires OneWay, but Binding '{0}' doesn't support it or isn't configured properly to support it."); }
        }
        internal static string BindingDoesnTSupportTwoWayButContractRequires1 {
              get { return SR.GetResourceString("BindingDoesnTSupportTwoWayButContractRequires1", @"Contract requires TwoWay (either request-reply or duplex), but Binding '{0}' doesn't support it or isn't configured properly to support it."); }
        }
        internal static string BindingDoesnTSupportRequestReplyButContract1 {
              get { return SR.GetResourceString("BindingDoesnTSupportRequestReplyButContract1", @"Contract requires Request/Reply, but Binding '{0}' doesn't support it or isn't configured properly to support it."); }
        }
        internal static string BindingDoesnTSupportDuplexButContractRequires1 {
              get { return SR.GetResourceString("BindingDoesnTSupportDuplexButContractRequires1", @"Contract requires Duplex, but Binding '{0}' doesn't support it or isn't configured properly to support it."); }
        }
        internal static string BindingDoesnTSupportAnyChannelTypes1 {
              get { return SR.GetResourceString("BindingDoesnTSupportAnyChannelTypes1", @"Binding '{0}' doesn't support creating any channel types. This often indicates that the BindingElements in a CustomBinding have been stacked incorrectly or in the wrong order. A Transport is required at the bottom of the stack. The recommended order for BindingElements is: TransactionFlow, ReliableSession, Security, CompositeDuplex, OneWay, StreamSecurity, MessageEncoding, Transport. "); }
        }
        internal static string ContractIsNotSelfConsistentItHasOneOrMore2 {
              get { return SR.GetResourceString("ContractIsNotSelfConsistentItHasOneOrMore2", @"The contract '{0}' is not self-consistent -- it has one or more IsTerminating or non-IsInitiating operations, but it does not have the SessionMode property set to SessionMode.Required.  The IsInitiating and IsTerminating attributes can only be used in the context of a session."); }
        }
        internal static string ContractIsNotSelfConsistentWhenIsSessionOpenNotificationEnabled {
              get { return SR.GetResourceString("ContractIsNotSelfConsistentWhenIsSessionOpenNotificationEnabled", @"The operation contract '{0}' is not self-consistent. When the '{1}' is set to '{2}', both '{3}' and '{4}' properties must be true, and the operation must not have any input parameters."); }
        }
        internal static string InstanceSettingsMustHaveTypeOrWellKnownObject0 {
              get { return SR.GetResourceString("InstanceSettingsMustHaveTypeOrWellKnownObject0", @"The ServiceHost must be configured with either a serviceType or a serviceInstance.  Both of these values are currently null."); }
        }
        internal static string TheServiceMetadataExtensionInstanceCouldNot2_0 {
              get { return SR.GetResourceString("TheServiceMetadataExtensionInstanceCouldNot2_0", @"The ServiceMetadataExtension instance could not be added to the ServiceHost instance because it has already been added to another ServiceHost instance."); }
        }
        internal static string TheServiceMetadataExtensionInstanceCouldNot3_0 {
              get { return SR.GetResourceString("TheServiceMetadataExtensionInstanceCouldNot3_0", @"The ServiceMetadataExtension instance could not be removed from the ServiceHost instance because it has not been added to any ServiceHost instance."); }
        }
        internal static string TheServiceMetadataExtensionInstanceCouldNot4_0 {
              get { return SR.GetResourceString("TheServiceMetadataExtensionInstanceCouldNot4_0", @"The ServiceMetadataExtension instance could not be removed from the ServiceHost instance because it has already been added to a different ServiceHost instance."); }
        }
        internal static string SynchronizedCollectionWrongType1 {
              get { return SR.GetResourceString("SynchronizedCollectionWrongType1", @"A value of type '{0}' cannot be added to the generic collection, because the collection has been parameterized with a different type."); }
        }
        internal static string SynchronizedCollectionWrongTypeNull {
              get { return SR.GetResourceString("SynchronizedCollectionWrongTypeNull", @"A null value cannot be added to the generic collection, because the collection has been parameterized with a value type."); }
        }
        internal static string CannotAddTwoItemsWithTheSameKeyToSynchronizedKeyedCollection0 {
              get { return SR.GetResourceString("CannotAddTwoItemsWithTheSameKeyToSynchronizedKeyedCollection0", @"Cannot add two items with the same key to SynchronizedKeyedCollection."); }
        }
        internal static string ItemDoesNotExistInSynchronizedKeyedCollection0 {
              get { return SR.GetResourceString("ItemDoesNotExistInSynchronizedKeyedCollection0", @"Item does not exist in SynchronizedKeyedCollection."); }
        }
        internal static string SuppliedMessageIsNotAReplyItHasNoRelatesTo0 {
              get { return SR.GetResourceString("SuppliedMessageIsNotAReplyItHasNoRelatesTo0", @"A reply message was received without a valid RelatesTo header.  This may have been caused by a missing RelatesTo header or a RelatesTo header with an invalid WS-Addressing Relationship type."); }
        }
        internal static string channelIsNotAvailable0 {
              get { return SR.GetResourceString("channelIsNotAvailable0", @"Internal Error: The InnerChannel property is null."); }
        }
        internal static string channelDoesNotHaveADuplexSession0 {
              get { return SR.GetResourceString("channelDoesNotHaveADuplexSession0", @"The current channel does not support closing the output session as this channel does not implement ISessionChannel<IDuplexSession>."); }
        }
        internal static string EndpointsMustHaveAValidBinding1 {
              get { return SR.GetResourceString("EndpointsMustHaveAValidBinding1", @"The ServiceEndpoint with name '{0}' could not be exported to WSDL because the Binding property is null. To fix this, set the Binding property to a valid Binding instance."); }
        }
        internal static string ABindingInstanceHasAlreadyBeenAssociatedTo1 {
              get { return SR.GetResourceString("ABindingInstanceHasAlreadyBeenAssociatedTo1", @"A binding instance has already been associated to listen URI '{0}'. If two endpoints want to share the same ListenUri, they must also share the same binding object instance. The two conflicting endpoints were either specified in AddServiceEndpoint() calls, in a config file, or a combination of AddServiceEndpoint() and config. "); }
        }
        internal static string UnabletoImportPolicy {
              get { return SR.GetResourceString("UnabletoImportPolicy", @"The following Policy Assertions were not Imported:\r\n"); }
        }
        internal static string UnImportedAssertionList {
              get { return SR.GetResourceString("UnImportedAssertionList", @"   XPath:{0}\r\n  Assertions:"); }
        }
        internal static string XPathUnavailable {
              get { return SR.GetResourceString("XPathUnavailable", @"\""XPath Unavailable\"""); }
        }
        internal static string DuplicatePolicyInWsdlSkipped {
              get { return SR.GetResourceString("DuplicatePolicyInWsdlSkipped", @"A policy expression was ignored because another policy expression with that ID has already been read in this document.\r\nXPath:{0}"); }
        }
        internal static string DuplicatePolicyDocumentSkipped {
              get { return SR.GetResourceString("DuplicatePolicyDocumentSkipped", @"A policy document was ignored because a policy expression with that ID has already been imported.\r\nPolicy ID:{0}"); }
        }
        internal static string PolicyDocumentMustHaveIdentifier {
              get { return SR.GetResourceString("PolicyDocumentMustHaveIdentifier", @"A metadata section containing policy did not have an identifier so it cannot be referenced. "); }
        }
        internal static string XPathPointer {
              get { return SR.GetResourceString("XPathPointer", @"XPath:{0}"); }
        }
        internal static string UnableToFindPolicyWithId {
              get { return SR.GetResourceString("UnableToFindPolicyWithId", @"A policy reference was ignored because the policy with ID '{0}' could not be found."); }
        }
        internal static string PolicyReferenceInvalidId {
              get { return SR.GetResourceString("PolicyReferenceInvalidId", @"A policy reference was ignored because the URI of the reference was empty."); }
        }
        internal static string PolicyReferenceMissingURI {
              get { return SR.GetResourceString("PolicyReferenceMissingURI", @"A policy reference was ignored because the required {0} attribute was missing."); }
        }
        internal static string ExceededMaxPolicyComplexity {
              get { return SR.GetResourceString("ExceededMaxPolicyComplexity", @"The policy expression was not fully imported because it exceeded the maximum allowable complexity. The import stopped at element '{0}' '{1}'."); }
        }
        internal static string ExceededMaxPolicySize {
              get { return SR.GetResourceString("ExceededMaxPolicySize", @"The policy expression was not fully imported because its normalized form was too large."); }
        }
        internal static string UnrecognizedPolicyElementInNamespace {
              get { return SR.GetResourceString("UnrecognizedPolicyElementInNamespace", @"Unrecognized policy element {0} in namespace {1}."); }
        }
        internal static string UnsupportedPolicyDocumentRoot {
              get { return SR.GetResourceString("UnsupportedPolicyDocumentRoot", @"\""{0}\"" is not a supported WS-Policy document root element."); }
        }
        internal static string UnrecognizedPolicyDocumentNamespace {
              get { return SR.GetResourceString("UnrecognizedPolicyDocumentNamespace", @"The \""{0}\"" namespace is not a recognized WS-Policy namespace."); }
        }
        internal static string NoUsablePolicyAssertions {
              get { return SR.GetResourceString("NoUsablePolicyAssertions", @"Cannot find usable policy alternatives."); }
        }
        internal static string PolicyInWsdlMustHaveFragmentId {
              get { return SR.GetResourceString("PolicyInWsdlMustHaveFragmentId", @"Unreachable policy detected.\r\nA WS-Policy element embedded in WSDL is missing a fragment identifier. This policy cannot be referenced by any WS-PolicyAttachment mechanisms.\r\nXPath:{0}"); }
        }
        internal static string FailedImportOfWsdl {
              get { return SR.GetResourceString("FailedImportOfWsdl", @"The processing of the WSDL parameter failed. Error: {0}"); }
        }
        internal static string OptionalWSDLExtensionIgnored {
              get { return SR.GetResourceString("OptionalWSDLExtensionIgnored", @"The optional WSDL extension element '{0}' from namespace '{1}' was not handled.\r\nXPath: {2}"); }
        }
        internal static string RequiredWSDLExtensionIgnored {
              get { return SR.GetResourceString("RequiredWSDLExtensionIgnored", @"The required WSDL extension element '{0}' from namespace '{1}' was not handled."); }
        }
        internal static string UnknownWSDLExtensionIgnored {
              get { return SR.GetResourceString("UnknownWSDLExtensionIgnored", @"An unrecognized WSDL extension of Type '{0}' was not handled."); }
        }
        internal static string WsdlExporterIsFaulted {
              get { return SR.GetResourceString("WsdlExporterIsFaulted", @"A previous call to this WsdlExporter left it in a faulted state. It is no longer usable."); }
        }
        internal static string WsdlImporterIsFaulted {
              get { return SR.GetResourceString("WsdlImporterIsFaulted", @"A previous call to this WsdlImporter left it in a faulted state. It is no longer usable."); }
        }
        internal static string WsdlImporterContractMustBeInKnownContracts {
              get { return SR.GetResourceString("WsdlImporterContractMustBeInKnownContracts", @"The ContractDescription argument to ImportEndpoints must be contained in the KnownContracts collection."); }
        }
        internal static string WsdlItemAlreadyFaulted {
              get { return SR.GetResourceString("WsdlItemAlreadyFaulted", @"A previous attempt to import this {0} already failed."); }
        }
        internal static string InvalidPolicyExtensionTypeInConfig {
              get { return SR.GetResourceString("InvalidPolicyExtensionTypeInConfig", @"The type {0} registered as a policy extension does not implement IPolicyImportExtension"); }
        }
        internal static string PolicyExtensionTypeRequiresDefaultConstructor {
              get { return SR.GetResourceString("PolicyExtensionTypeRequiresDefaultConstructor", @"The type {0} registered as a policy extension does not have a public default constructor. Policy extensions must have a public default constructor"); }
        }
        internal static string PolicyExtensionImportError {
              get { return SR.GetResourceString("PolicyExtensionImportError", @"An exception was thrown in a call to a policy import extension.\r\nExtension: {0}\r\nError: {1}"); }
        }
        internal static string PolicyExtensionExportError {
              get { return SR.GetResourceString("PolicyExtensionExportError", @"An exception was thrown in a call to a policy export extension.\r\nExtension: {0}\r\nError: {1}"); }
        }
        internal static string MultipleCallsToExportContractWithSameContract {
              get { return SR.GetResourceString("MultipleCallsToExportContractWithSameContract", @"Calling IWsdlExportExtension.ExportContract twice with the same ContractDescription is not supported."); }
        }
        internal static string DuplicateContractQNameNameOnExport {
              get { return SR.GetResourceString("DuplicateContractQNameNameOnExport", @"Duplicate contract XmlQualifiedNames are not supported.\r\nAnother ContractDescription with the Name: {0} and Namespace: {1} has already been exported."); }
        }
        internal static string WarnDuplicateBindingQNameNameOnExport {
              get { return SR.GetResourceString("WarnDuplicateBindingQNameNameOnExport", @"Similar ServiceEndpoints were exported. The WSDL export process was forced to suffix wsdl:binding names to avoid naming conflicts.\r\n Similar ServiceEndpoints means different binding instances having the Name: {0} and Namespace: {1} and either the same ContractDescription or at least the same contract Name: {2}."); }
        }
        internal static string WarnSkippingOpertationWithWildcardAction {
              get { return SR.GetResourceString("WarnSkippingOpertationWithWildcardAction", @"An operation was skipped during export because it has a wildcard action. This is not supported in WSDL.\r\nContract Name:{0}\r\nContract Namespace:{1}\r\nOperation Name:{2}"); }
        }
        internal static string WarnSkippingOpertationWithSessionOpenNotificationEnabled {
              get { return SR.GetResourceString("WarnSkippingOpertationWithSessionOpenNotificationEnabled", @"An operation was skipped during export because the property '{0}' is set to '{1}'. This operation should be used for server only and should not be exposed from WSDL. \r\nContract Name:{2}\r\nContract Namespace:{3}\r\nOperation Name:{4}"); }
        }
        internal static string InvalidWsdlExtensionTypeInConfig {
              get { return SR.GetResourceString("InvalidWsdlExtensionTypeInConfig", @"The type {0} registered as a WSDL extension does not implement IWsdlImportExtension."); }
        }
        internal static string WsdlExtensionTypeRequiresDefaultConstructor {
              get { return SR.GetResourceString("WsdlExtensionTypeRequiresDefaultConstructor", @"The type {0} registered as a WSDL extension does not have a public default constructor. WSDL extensions must have a public default constructor."); }
        }
        internal static string WsdlExtensionContractExportError {
              get { return SR.GetResourceString("WsdlExtensionContractExportError", @"An exception was thrown in a call to a WSDL export extension: {0}\r\n contract: {1}"); }
        }
        internal static string WsdlExtensionEndpointExportError {
              get { return SR.GetResourceString("WsdlExtensionEndpointExportError", @"An exception was thrown in a call to a WSDL export extension: {0}\r\n Endpoint: {1}"); }
        }
        internal static string WsdlExtensionBeforeImportError {
              get { return SR.GetResourceString("WsdlExtensionBeforeImportError", @"A WSDL import extension threw an exception during the BeforeImport call: {0}\r\nError: {1}"); }
        }
        internal static string WsdlExtensionImportError {
              get { return SR.GetResourceString("WsdlExtensionImportError", @"An exception was thrown while running a WSDL import extension: {0}\r\nError: {1}"); }
        }
        internal static string WsdlImportErrorMessageDetail {
              get { return SR.GetResourceString("WsdlImportErrorMessageDetail", @"Cannot import {0}\r\nDetail: {2}\r\nXPath to Error Source: {1}"); }
        }
        internal static string WsdlImportErrorDependencyDetail {
              get { return SR.GetResourceString("WsdlImportErrorDependencyDetail", @"There was an error importing a {0} that the {1} is dependent on.\r\nXPath to {0}: {2}"); }
        }
        internal static string UnsupportedEnvelopeVersion {
              get { return SR.GetResourceString("UnsupportedEnvelopeVersion", @"The {0} binding element requires envelope version '{1}' It doesn't support '{2}'."); }
        }
        internal static string NoValue0 {
              get { return SR.GetResourceString("NoValue0", @"No value."); }
        }
        internal static string UnsupportedBindingElementClone {
              get { return SR.GetResourceString("UnsupportedBindingElementClone", @"The '{0}' binding element does not support cloning."); }
        }
        internal static string UnrecognizedBindingAssertions1 {
              get { return SR.GetResourceString("UnrecognizedBindingAssertions1", @"WsdlImporter encountered unrecognized policy assertions in ServiceDescription '{0}':"); }
        }
        internal static string ServicesWithoutAServiceContractAttributeCan2 {
              get { return SR.GetResourceString("ServicesWithoutAServiceContractAttributeCan2", @"The {0} declared on method '{1}' in type '{2}' is invalid. {0}s are only valid on methods that are declared in a type that has ServiceContractAttribute. Either add ServiceContractAttribute to type '{2}' or remove {0} from method '{1}'."); }
        }
        internal static string tooManyAttributesOfTypeOn2 {
              get { return SR.GetResourceString("tooManyAttributesOfTypeOn2", @"Too many attributes of type {0} on {1}."); }
        }
        internal static string couldnTFindRequiredAttributeOfTypeOn2 {
              get { return SR.GetResourceString("couldnTFindRequiredAttributeOfTypeOn2", @"Couldn't find required attribute of type {0} on {1}."); }
        }
        internal static string AttemptedToGetContractTypeForButThatTypeIs1 {
              get { return SR.GetResourceString("AttemptedToGetContractTypeForButThatTypeIs1", @"Attempted to get contract type for {0}, but that type is not a ServiceContract, nor does it inherit a ServiceContract."); }
        }
        internal static string NoEndMethodFoundForAsyncBeginMethod3 {
              get { return SR.GetResourceString("NoEndMethodFoundForAsyncBeginMethod3", @"OperationContract method '{0}' in type '{1}' does not properly implement the async pattern, as no corresponding method '{2}' could be found. Either provide a method called '{2}' or set the AsyncPattern property on method '{0}' to false."); }
        }
        internal static string MoreThanOneEndMethodFoundForAsyncBeginMethod3 {
              get { return SR.GetResourceString("MoreThanOneEndMethodFoundForAsyncBeginMethod3", @"OperationContract method '{0}' in type '{1}' does not properly implement the async pattern, as more than one corresponding method '{2}' was found. When using the async pattern, exactly one end method must be provided. Either remove or rename one or more of the '{2}' methods such that there is just one, or set the AsyncPattern property on method '{0}' to false."); }
        }
        internal static string InvalidAsyncEndMethodSignatureForMethod2 {
              get { return SR.GetResourceString("InvalidAsyncEndMethodSignatureForMethod2", @"Invalid async End method signature for method {0} in ServiceContract type {1}. Your end method must take an IAsyncResult as the last argument."); }
        }
        internal static string InvalidAsyncBeginMethodSignatureForMethod2 {
              get { return SR.GetResourceString("InvalidAsyncBeginMethodSignatureForMethod2", @"Invalid async Begin method signature for method {0} in ServiceContract type {1}. Your begin method must take an AsyncCallback and an object as the last two arguments and return an IAsyncResult."); }
        }
        internal static string InAContractInheritanceHierarchyIfParentHasCallbackChildMustToo {
              get { return SR.GetResourceString("InAContractInheritanceHierarchyIfParentHasCallbackChildMustToo", @"Because base ServiceContract '{0}' has a CallbackContract '{1}', derived ServiceContract '{2}' must also specify either '{1}' or a derived type as its CallbackContract."); }
        }
        internal static string InAContractInheritanceHierarchyTheServiceContract3_2 {
              get { return SR.GetResourceString("InAContractInheritanceHierarchyTheServiceContract3_2", @"In a contract inheritance hierarchy, the ServiceContract's CallbackContract must be a subtype of the CallbackContracts of all of the CallbackContracts of the ServiceContracts inherited by the original ServiceContract, Types {0} and {1} violate this rule."); }
        }
        internal static string CannotHaveTwoOperationsWithTheSameName3 {
              get { return SR.GetResourceString("CannotHaveTwoOperationsWithTheSameName3", @"Cannot have two operations in the same contract with the same name, methods {0} and {1} in type {2} violate this rule. You can change the name of one of the operations by changing the method name or by using the Name property of OperationContractAttribute."); }
        }
        internal static string CannotHaveTwoOperationsWithTheSameElement5 {
              get { return SR.GetResourceString("CannotHaveTwoOperationsWithTheSameElement5", @"The {0}.{1} operation references a message element [{2}] that has already been exported from the {3}.{4} operation. You can change the name of one of the operations by changing the method name or using the Name property of OperationContractAttribute. Alternatively, you can control the element name in greater detail using the MessageContract programming model."); }
        }
        internal static string CannotInheritTwoOperationsWithTheSameName3 {
              get { return SR.GetResourceString("CannotInheritTwoOperationsWithTheSameName3", @"Cannot inherit two different operations with the same name, operation '{0}' from contracts '{1}' and '{2}' violate this rule. You can change the name of one of the operations by changing the method name or by using the Name property of OperationContractAttribute."); }
        }
        internal static string SyncAsyncMatchConsistency_Parameters5 {
              get { return SR.GetResourceString("SyncAsyncMatchConsistency_Parameters5", @"The synchronous OperationContract method '{0}' in type '{1}' was matched with the asynchronous OperationContract methods '{2}' and '{3}' because they have the same operation name '{4}'. When a synchronous OperationContract method is matched to a pair of asynchronous OperationContract methods, the two OperationContracts must define the same number and types of parameters. In this case, some of the arguments are different. To fix it, ensure that the OperationContracts define the same number and types of arguments, in the same order. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string SyncTaskMatchConsistency_Parameters5 {
              get { return SR.GetResourceString("SyncTaskMatchConsistency_Parameters5", @"The synchronous OperationContract method '{0}' in type '{1}' was matched with the task-based asynchronous OperationContract method '{2}' because they have the same operation name '{3}'. When a synchronous OperationContract method is matched to a task-based asynchronous OperationContract method, the two OperationContracts must define the same number and types of parameters. In this case, some of the arguments are different. To fix it, ensure that the OperationContracts define the same number and types of arguments, in the same order. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string TaskAsyncMatchConsistency_Parameters5 {
              get { return SR.GetResourceString("TaskAsyncMatchConsistency_Parameters5", @"The task-based asynchronous OperationContract method '{0}' in type '{1}' was matched with the asynchronous OperationContract methods '{2}' and '{3}' because they have the same operation name '{4}'. When a task-based asynchronous OperationContract method is matched to a pair of asynchronous OperationContract methods, the two OperationContracts must define the same number and types of parameters. In this case, some of the arguments are different. To fix it, ensure that the OperationContracts define the same number and types of arguments, in the same order. Alternatively, changing the name of one of the methods will prevent matching."); }
        }
        internal static string SyncAsyncMatchConsistency_ReturnType5 {
              get { return SR.GetResourceString("SyncAsyncMatchConsistency_ReturnType5", @"The synchronous OperationContract method '{0}' in type '{1}' was matched with the asynchronous OperationContract methods '{2}' and '{3}' because they have the same operation name '{4}'. When a synchronous OperationContract method is matched to a pair of asynchronous OperationContract methods, the two OperationContracts must define the same return type. In this case, the return types are different. To fix it, ensure that method '{0}' and method '{3}' have the same return type. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string SyncTaskMatchConsistency_ReturnType5 {
              get { return SR.GetResourceString("SyncTaskMatchConsistency_ReturnType5", @"The synchronous OperationContract method '{0}' in type '{1}' was matched with the task-based asynchronous OperationContract method '{2}' because they have the same operation name '{3}'. When a synchronous OperationContract method is matched to a task-based asynchronous OperationContract method, the two OperationContracts must define the same return type. In this case, the return types are different. To fix it, ensure that method '{0}' and method '{2}' have the same return type. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string TaskAsyncMatchConsistency_ReturnType5 {
              get { return SR.GetResourceString("TaskAsyncMatchConsistency_ReturnType5", @"The task-based asynchronous OperationContract method '{0}' in type '{1}' was matched with the asynchronous OperationContract methods '{2}' and '{3}' because they have the same operation name '{4}'. When a synchronous OperationContract method is matched to a pair of asynchronous OperationContract methods, the two OperationContracts must define the same return type. In this case, the return types are different. To fix it, ensure that method '{0}' and method '{3}' have the same return type. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string SyncAsyncMatchConsistency_Attributes6 {
              get { return SR.GetResourceString("SyncAsyncMatchConsistency_Attributes6", @"The synchronous OperationContract method '{0}' in type '{1}' was matched with the asynchronous OperationContract methods '{2}' and '{3}' because they have the same operation name '{4}'. When a synchronous OperationContract method is matched to a pair of asynchronous OperationContract methods, any additional attributes must be declared on the synchronous OperationContract method. In this case, the asynchronous OperationContract method '{2}' has one or more attributes of type '{5}'. To fix it, remove the '{5}' attribute or attributes from method '{2}'. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string SyncTaskMatchConsistency_Attributes6 {
              get { return SR.GetResourceString("SyncTaskMatchConsistency_Attributes6", @"The synchronous OperationContract method '{0}' in type '{1}' was matched with the task-based asynchronous OperationContract method '{2}' because they have the same operation name '{3}'. When a synchronous OperationContract method is matched to a task-based asynchronous OperationContract method, any additional attributes must be declared on the synchronous OperationContract method. In this case, the task-based asynchronous OperationContract method '{2}' has one or more attributes of type '{4}'. To fix it, remove the '{4}' attribute or attributes from method '{2}'. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string TaskAsyncMatchConsistency_Attributes6 {
              get { return SR.GetResourceString("TaskAsyncMatchConsistency_Attributes6", @"The task-based asynchronous OperationContract method '{0}' in type '{1}' was matched with the asynchronous OperationContract methods '{2}' and '{3}' because they have the same operation name '{4}'. When a task-based asynchronous OperationContract method is matched to a pair of asynchronous OperationContract methods, any additional attributes must be declared on the task-based asynchronous OperationContract method. In this case, the asynchronous OperationContract method '{2}' has one or more attributes of type '{5}'. To fix it, remove the '{5}' attribute or attributes from method '{2}'. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string SyncAsyncMatchConsistency_Property6 {
              get { return SR.GetResourceString("SyncAsyncMatchConsistency_Property6", @"The synchronous OperationContract method '{0}' in type '{1}' was matched with the asynchronous OperationContract  methods '{2}' and '{3}' because they have the same operation name '{4}'. When a synchronous OperationContract method is matched to a pair of asynchronous OperationContract methods, the two OperationContracts must have the same value for the '{5}' property. In this case, the values are different. To fix it, change the '{5} property of one of the OperationContracts to match the other. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string SyncTaskMatchConsistency_Property6 {
              get { return SR.GetResourceString("SyncTaskMatchConsistency_Property6", @"The synchronous OperationContract method '{0}' in type '{1}' was matched with the task-based asynchronous OperationContract  method '{2}' because they have the same operation name '{3}'. When a synchronous OperationContract method is matched to a task-based asynchronous OperationContract method, the two OperationContracts must have the same value for the '{4}' property. In this case, the values are different. To fix it, change the '{4} property of one of the OperationContracts to match the other. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string TaskAsyncMatchConsistency_Property6 {
              get { return SR.GetResourceString("TaskAsyncMatchConsistency_Property6", @"The task-based asynchronous OperationContract method '{0}' in type '{1}' was matched with the asynchronous OperationContract  methods '{2}' and '{3}' because they have the same operation name '{4}'. When a task-based asynchronous OperationContract method is matched to a pair of asynchronous OperationContract methods, the two OperationContracts must have the same value for the '{5}' property. In this case, the values are different. To fix it, change the '{5} property of one of the OperationContracts to match the other. Alternatively, changing the name of one of the methods will prevent matching. "); }
        }
        internal static string ServiceOperationsMarkedWithIsOneWayTrueMust0 {
              get { return SR.GetResourceString("ServiceOperationsMarkedWithIsOneWayTrueMust0", @"Operations marked with IsOneWay=true must not declare output parameters, by-reference parameters or return values."); }
        }
        internal static string OneWayOperationShouldNotSpecifyAReplyAction1 {
              get { return SR.GetResourceString("OneWayOperationShouldNotSpecifyAReplyAction1", @"One way operation {0} cannot not specify a reply action."); }
        }
        internal static string OneWayAndFaultsIncompatible2 {
              get { return SR.GetResourceString("OneWayAndFaultsIncompatible2", @"The method '{1}' in type '{0}' is marked IsOneWay=true and declares one or more FaultContractAttributes. One-way methods cannot declare FaultContractAttributes. To fix it, change IsOneWay to false or remove the FaultContractAttributes."); }
        }
        internal static string OnlyMalformedMessagesAreSupported {
              get { return SR.GetResourceString("OnlyMalformedMessagesAreSupported", @"Only malformed Messages are supported."); }
        }
        internal static string UnableToLocateOperation2 {
              get { return SR.GetResourceString("UnableToLocateOperation2", @"Cannot locate operation {0} in Contract {1}."); }
        }
        internal static string UnsupportedWSDLOnlyOneMessage {
              get { return SR.GetResourceString("UnsupportedWSDLOnlyOneMessage", @"Unsupported WSDL, only one message part is supported for fault messages. This fault message references zero or more than one message part. If you have edit access to the WSDL file, you can fix the problem by removing the extra message parts such that fault message references just one part."); }
        }
        internal static string UnsupportedWSDLTheFault {
              get { return SR.GetResourceString("UnsupportedWSDLTheFault", @"Unsupported WSDL, the fault message part must reference an element. This fault message does not reference an element. If you have edit access to the WSDL document, you can fix the problem by referencing a schema element using the 'element' attribute."); }
        }
        internal static string AsyncEndCalledOnWrongChannel {
              get { return SR.GetResourceString("AsyncEndCalledOnWrongChannel", @"Async End called on wrong channel."); }
        }
        internal static string AsyncEndCalledWithAnIAsyncResult {
              get { return SR.GetResourceString("AsyncEndCalledWithAnIAsyncResult", @"Async End called with an IAsyncResult from a different Begin method."); }
        }
        internal static string IsolationLevelMismatch2 {
              get { return SR.GetResourceString("IsolationLevelMismatch2", @"The received transaction has an isolation level of '{0}' but the service is configured with a TransactionIsolationLevel of '{1}'. The isolation level for received transactions and the service must be the same."); }
        }
        internal static string MessageHeaderIsNull0 {
              get { return SR.GetResourceString("MessageHeaderIsNull0", @"The value of the addressHeaders argument is invalid because the collection contains null values. Null is not a valid value for the AddressHeaderCollection."); }
        }
        internal static string MessagePropertiesArraySize0 {
              get { return SR.GetResourceString("MessagePropertiesArraySize0", @"The array passed does not have enough space to hold all the properties contained by this collection."); }
        }
        internal static string DuplicateBehavior1 {
              get { return SR.GetResourceString("DuplicateBehavior1", @"The value could not be added to the collection, as the collection already contains an item of the same type: '{0}'. This collection only supports one instance of each type."); }
        }
        internal static string CantCreateChannelWithManualAddressing {
              get { return SR.GetResourceString("CantCreateChannelWithManualAddressing", @"Cannot create channel for a contract that requires request/reply and a binding that requires manual addressing but only supports duplex communication."); }
        }
        internal static string XsdMissingRequiredAttribute1 {
              get { return SR.GetResourceString("XsdMissingRequiredAttribute1", @"Missing required '{0}' attribute."); }
        }
        internal static string IgnoreSoapHeaderBinding3 {
              get { return SR.GetResourceString("IgnoreSoapHeaderBinding3", @"Ignoring invalid SOAP header extension in wsdl:operation name='{0}' from targetNamespace='{1}'. Reason: {2}"); }
        }
        internal static string IgnoreSoapFaultBinding3 {
              get { return SR.GetResourceString("IgnoreSoapFaultBinding3", @"Ignoring invalid SOAP fault extension in wsdl:operation name='{0}' from targetNamespace='{1}'. Reason: {2}"); }
        }
        internal static string IgnoreMessagePart3 {
              get { return SR.GetResourceString("IgnoreMessagePart3", @"Ignoring invalid part in wsdl:message name='{0}' from targetNamespace='{1}'. Reason: {2}"); }
        }
        internal static string CannotImportPrivacyNoticeElementWithoutVersionAttribute {
              get { return SR.GetResourceString("CannotImportPrivacyNoticeElementWithoutVersionAttribute", @"PrivacyNotice element must have a Version attribute."); }
        }
        internal static string PrivacyNoticeElementVersionAttributeInvalid {
              get { return SR.GetResourceString("PrivacyNoticeElementVersionAttributeInvalid", @"PrivacyNotice element Version attribute must have an integer value."); }
        }
        internal static string XDCannotFindValueInDictionaryString {
              get { return SR.GetResourceString("XDCannotFindValueInDictionaryString", @"Cannot find '{0}' value in dictionary string."); }
        }
        internal static string WmiGetObject {
              get { return SR.GetResourceString("WmiGetObject", @"WMI GetObject Query: {0}"); }
        }
        internal static string WmiPutInstance {
              get { return SR.GetResourceString("WmiPutInstance", @"WMI PutInstance Class: {0}"); }
        }
        internal static string ObjectMustBeOpenedToDequeue {
              get { return SR.GetResourceString("ObjectMustBeOpenedToDequeue", @"Cannot dequeue a '{0}' object while in the Created state."); }
        }
        internal static string NoChannelBuilderAvailable {
              get { return SR.GetResourceString("NoChannelBuilderAvailable", @"The binding (Name={0}, Namespace={1}) cannot be used to create a ChannelFactory or a ChannelListener because it appears to be missing a TransportBindingElement.  Every binding must have at least one binding element that derives from TransportBindingElement."); }
        }
        internal static string InvalidBindingScheme {
              get { return SR.GetResourceString("InvalidBindingScheme", @"The TransportBindingElement of type '{0}' in this CustomBinding returned a null or empty string for the Scheme. TransportBindingElement's Scheme must be a non-empty string."); }
        }
        internal static string CustomBindingRequiresTransport {
              get { return SR.GetResourceString("CustomBindingRequiresTransport", @"Binding '{0}' lacks a TransportBindingElement.  Every binding must have a binding element that derives from TransportBindingElement. This binding element must appear last in the BindingElementCollection."); }
        }
        internal static string TransportBindingElementMustBeLast {
              get { return SR.GetResourceString("TransportBindingElementMustBeLast", @"In Binding '{0}', TransportBindingElement '{1}' does not appear last in the BindingElementCollection.  Please change the order of elements such that the TransportBindingElement is last."); }
        }
        internal static string MessageVersionMissingFromBinding {
              get { return SR.GetResourceString("MessageVersionMissingFromBinding", @"None of the binding elements in binding '{0}' define a message version. At least one binding element must define a message version and return it from the GetProperty<MessageVersion> method."); }
        }
        internal static string NotAllBindingElementsBuilt {
              get { return SR.GetResourceString("NotAllBindingElementsBuilt", @"Some of the binding elements in this binding were not used when building the ChannelFactory / ChannelListener.  This may be have been caused by the binding elements being misordered.  The recommended order for binding elements is: TransactionFlow, ReliableSession, Security, CompositeDuplex, OneWay, StreamSecurity, MessageEncoding, Transport.  Note that the TransportBindingElement must be last.  The following binding elements were not built: {0}."); }
        }
        internal static string MultipleMebesInParameters {
              get { return SR.GetResourceString("MultipleMebesInParameters", @"More than one MessageEncodingBindingElement was found in the BindingParameters of the BindingContext.  This usually is caused by having multiple MessageEncodingBindingElements in a CustomBinding. Remove all but one of these elements."); }
        }
        internal static string MultipleStreamUpgradeProvidersInParameters {
              get { return SR.GetResourceString("MultipleStreamUpgradeProvidersInParameters", @"More than one IStreamUpgradeProviderElement was found in the BindingParameters of the BindingContext.  This usually is caused by having multiple IStreamUpgradeProviderElements in a CustomBinding. Remove all but one of these elements."); }
        }
        internal static string SecurityCapabilitiesMismatched {
              get { return SR.GetResourceString("SecurityCapabilitiesMismatched", @"The security capabilities of binding '{0}' do not match those of the generated runtime object. Most likely this means the binding contains a StreamSecurityBindingElement, but lacks a TransportBindingElement that supports Stream Security (such as TCP or Named Pipes). Either remove the unused StreamSecurityBindingElement or use a transport that supports this element."); }
        }
        internal static string BaseAddressMustBeAbsolute {
              get { return SR.GetResourceString("BaseAddressMustBeAbsolute", @"Only an absolute Uri can be used as a base address."); }
        }
        internal static string BaseAddressDuplicateScheme {
              get { return SR.GetResourceString("BaseAddressDuplicateScheme", @"This collection already contains an address with scheme {0}.  There can be at most one address per scheme in this collection. If your service is being hosted in IIS you can fix the problem by setting 'system.serviceModel/serviceHostingEnvironment/multipleSiteBindingsEnabled' to true or specifying 'system.serviceModel/serviceHostingEnvironment/baseAddressPrefixFilters'."); }
        }
        internal static string BaseAddressCannotHaveUserInfo {
              get { return SR.GetResourceString("BaseAddressCannotHaveUserInfo", @"A base address cannot contain a Uri user info section."); }
        }
        internal static string TransportBindingElementNotFound {
              get { return SR.GetResourceString("TransportBindingElementNotFound", @"The binding does not contain a TransportBindingElement."); }
        }
        internal static string ChannelDemuxerBindingElementNotFound {
              get { return SR.GetResourceString("ChannelDemuxerBindingElementNotFound", @"The binding does not contain a ChannelDemuxerBindingElement."); }
        }
        internal static string BaseAddressCannotHaveQuery {
              get { return SR.GetResourceString("BaseAddressCannotHaveQuery", @"A base address cannot contain a Uri query string."); }
        }
        internal static string BaseAddressCannotHaveFragment {
              get { return SR.GetResourceString("BaseAddressCannotHaveFragment", @"A base address cannot contain a Uri fragment."); }
        }
        internal static string UriMustBeAbsolute {
              get { return SR.GetResourceString("UriMustBeAbsolute", @"The given URI must be absolute."); }
        }
        internal static string BindingProtocolMappingNotDefined {
              get { return SR.GetResourceString("BindingProtocolMappingNotDefined", @"The binding for scheme '{0}' specified in the protocol mapping does not exist and must be created."); }
        }
        internal static string Default {
              get { return SR.GetResourceString("Default", @"(Default)"); }
        }
        internal static string AdminMTAWorkerThreadException {
              get { return SR.GetResourceString("AdminMTAWorkerThreadException", @"MTAWorkerThread exception"); }
        }
        internal static string InternalError {
              get { return SR.GetResourceString("InternalError", @"An unexpected error has occurred."); }
        }
        internal static string ClsidNotInApplication {
              get { return SR.GetResourceString("ClsidNotInApplication", @"The CLSID specified in the service file is not configured in the specified application. (The CLSID is {0}, the AppID is {1}.)"); }
        }
        internal static string ClsidNotInConfiguration {
              get { return SR.GetResourceString("ClsidNotInConfiguration", @"The CLSID specified in the service file does not have a service element in a configuration file. (The CLSID is {0}.)"); }
        }
        internal static string EndpointNotAnIID {
              get { return SR.GetResourceString("EndpointNotAnIID", @"An endpoint configured for the COM+ CLSID {0} is not a configured interface on the class. (The contract type is {1}.)"); }
        }
        internal static string ServiceStringFormatError {
              get { return SR.GetResourceString("ServiceStringFormatError", @"The COM+ string in the .svc file was formatted incorrectly. (The string is \""{0}\"".)"); }
        }
        internal static string ContractTypeNotAnIID {
              get { return SR.GetResourceString("ContractTypeNotAnIID", @"The contract type name in the configuration file was not in the form of an interface identifier. (The string is \""{0}\"".)"); }
        }
        internal static string ApplicationNotFound {
              get { return SR.GetResourceString("ApplicationNotFound", @"The configured application was not found. (The Application ID was {0}.)"); }
        }
        internal static string NoVoteIssued {
              get { return SR.GetResourceString("NoVoteIssued", @" A transaction vote request was completed, but there was no outstanding vote request."); }
        }
        internal static string FailedToConvertTypelibraryToAssembly {
              get { return SR.GetResourceString("FailedToConvertTypelibraryToAssembly", @"Failed to convert type library to assembly"); }
        }
        internal static string BadInterfaceVersion {
              get { return SR.GetResourceString("BadInterfaceVersion", @"Incorrect Interface version in registry"); }
        }
        internal static string FailedToLoadTypeLibrary {
              get { return SR.GetResourceString("FailedToLoadTypeLibrary", @"Failed to load type library"); }
        }
        internal static string NativeTypeLibraryNotAllowed {
              get { return SR.GetResourceString("NativeTypeLibraryNotAllowed", @" An attempt to load the native type library '{0}' was made. Native type libraries cannot be loaded."); }
        }
        internal static string InterfaceNotFoundInAssembly {
              get { return SR.GetResourceString("InterfaceNotFoundInAssembly", @"Could not find interface in the Assembly"); }
        }
        internal static string UdtNotFoundInAssembly {
              get { return SR.GetResourceString("UdtNotFoundInAssembly", @"The '{0}' user-defined type could not be found. Ensure that the correct type and type library are registered and specified."); }
        }
        internal static string UnknownMonikerKeyword {
              get { return SR.GetResourceString("UnknownMonikerKeyword", @"Could not find keyword {0}."); }
        }
        internal static string MonikerIncorectSerializer {
              get { return SR.GetResourceString("MonikerIncorectSerializer", @"Invalid serializer specified. The only valid values are 'xml' and 'datacontract'."); }
        }
        internal static string NoEqualSignFound {
              get { return SR.GetResourceString("NoEqualSignFound", @"The keyword '{0}' has no equal sign following it. Ensure that each keyword is followed by an equal sign and a value. "); }
        }
        internal static string KewordMissingValue {
              get { return SR.GetResourceString("KewordMissingValue", @"No value found for a keyword."); }
        }
        internal static string BadlyTerminatedValue {
              get { return SR.GetResourceString("BadlyTerminatedValue", @"Badly terminated value {0}."); }
        }
        internal static string MissingQuote {
              get { return SR.GetResourceString("MissingQuote", @"Missing Quote in value {0}."); }
        }
        internal static string RepeatedKeyword {
              get { return SR.GetResourceString("RepeatedKeyword", @"Repeated moniker keyword."); }
        }
        internal static string InterfaceNotFoundInConfig {
              get { return SR.GetResourceString("InterfaceNotFoundInConfig", @"Interface {0} not found in configuration."); }
        }
        internal static string CannotHaveNullOrEmptyNameOrNamespaceForIID {
              get { return SR.GetResourceString("CannotHaveNullOrEmptyNameOrNamespaceForIID", @"Interface {0} has a null namespace or name."); }
        }
        internal static string MethodGivenInConfigNotFoundOnInterface {
              get { return SR.GetResourceString("MethodGivenInConfigNotFoundOnInterface", @"Method {0} given in config was not found on interface {1}."); }
        }
        internal static string MonikerIncorrectServerIdentityForMex {
              get { return SR.GetResourceString("MonikerIncorrectServerIdentityForMex", @"Only one type of server identity can be specified."); }
        }
        internal static string MonikerAddressNotSpecified {
              get { return SR.GetResourceString("MonikerAddressNotSpecified", @"Address not specified."); }
        }
        internal static string MonikerMexBindingSectionNameNotSpecified {
              get { return SR.GetResourceString("MonikerMexBindingSectionNameNotSpecified", @"Mex binding section name attribute not specified."); }
        }
        internal static string MonikerMexAddressNotSpecified {
              get { return SR.GetResourceString("MonikerMexAddressNotSpecified", @"Mex address not specified."); }
        }
        internal static string MonikerContractNotSpecified {
              get { return SR.GetResourceString("MonikerContractNotSpecified", @"Contract not specified."); }
        }
        internal static string MonikerBindingNotSpecified {
              get { return SR.GetResourceString("MonikerBindingNotSpecified", @"Binding not specified."); }
        }
        internal static string MonikerBindingNamespacetNotSpecified {
              get { return SR.GetResourceString("MonikerBindingNamespacetNotSpecified", @"Binding namespace not specified."); }
        }
        internal static string MonikerFailedToDoMexRetrieve {
              get { return SR.GetResourceString("MonikerFailedToDoMexRetrieve", @"Failed to do mex retrieval:{0}."); }
        }
        internal static string MonikerContractNotFoundInRetreivedMex {
              get { return SR.GetResourceString("MonikerContractNotFoundInRetreivedMex", @"None of the contract in metadata matched the contract specified."); }
        }
        internal static string MonikerNoneOfTheBindingMatchedTheSpecifiedBinding {
              get { return SR.GetResourceString("MonikerNoneOfTheBindingMatchedTheSpecifiedBinding", @"The contract does not have an endpoint supporting the binding specified."); }
        }
        internal static string MonikerMissingColon {
              get { return SR.GetResourceString("MonikerMissingColon", @"Moniker Missing Colon"); }
        }
        internal static string MonikerIncorrectServerIdentity {
              get { return SR.GetResourceString("MonikerIncorrectServerIdentity", @"Multiple server identity keywords were specified. Ensure that at most one identity keyword is specified."); }
        }
        internal static string NoInterface {
              get { return SR.GetResourceString("NoInterface", @"The object does not support the interface '{0}'."); }
        }
        internal static string DuplicateTokenExFailed {
              get { return SR.GetResourceString("DuplicateTokenExFailed", @"Could not duplicate the token (error=0x{0:X})."); }
        }
        internal static string AccessCheckFailed {
              get { return SR.GetResourceString("AccessCheckFailed", @"Could not perform an AccessCheck (error=0x{0:X})."); }
        }
        internal static string ImpersonateAnonymousTokenFailed {
              get { return SR.GetResourceString("ImpersonateAnonymousTokenFailed", @"Could not impersonate the anonymous user (error=0x{0:X})."); }
        }
        internal static string OnlyByRefVariantSafeArraysAllowed {
              get { return SR.GetResourceString("OnlyByRefVariantSafeArraysAllowed", @"The provided SafeArray parameter was passed by value. SafeArray parameters must be passed by reference."); }
        }
        internal static string OnlyOneDimensionalSafeArraysAllowed {
              get { return SR.GetResourceString("OnlyOneDimensionalSafeArraysAllowed", @" Multi-dimensional SafeArray parameters cannot be used."); }
        }
        internal static string OnlyVariantTypeElementsAllowed {
              get { return SR.GetResourceString("OnlyVariantTypeElementsAllowed", @"The elements of the SafeArray must be of the type VARIANT."); }
        }
        internal static string OnlyZeroLBoundAllowed {
              get { return SR.GetResourceString("OnlyZeroLBoundAllowed", @"The lower bound of the SafeArray was not zero. SafeArrays with a lower bound other than zero cannot be used."); }
        }
        internal static string OpenThreadTokenFailed {
              get { return SR.GetResourceString("OpenThreadTokenFailed", @"Could not open the thread token (error=0x{0:X})."); }
        }
        internal static string OpenProcessTokenFailed {
              get { return SR.GetResourceString("OpenProcessTokenFailed", @"Could not open the process token (error=0x{0:X})."); }
        }
        internal static string InvalidIsolationLevelValue {
              get { return SR.GetResourceString("InvalidIsolationLevelValue", @"The isolation level for component {0} is invalid. (The value was {1}.)"); }
        }
        internal static string UnsupportedConversion {
              get { return SR.GetResourceString("UnsupportedConversion", @"The conversion between the client parameter type '{0}' to the required server parameter type '{1}' cannot be performed."); }
        }
        internal static string FailedProxyProviderCreation {
              get { return SR.GetResourceString("FailedProxyProviderCreation", @"The required outer proxy could not be created. Ensure that the service moniker is correctly installed and registered."); }
        }
        internal static string UnableToLoadDll {
              get { return SR.GetResourceString("UnableToLoadDll", @"Cannot load library {0}. Ensure that WCF is properly installed."); }
        }
        internal static string InterfaceNotRegistered {
              get { return SR.GetResourceString("InterfaceNotRegistered", @"Interface Not Registered"); }
        }
        internal static string BadInterfaceRegistration {
              get { return SR.GetResourceString("BadInterfaceRegistration", @"Bad Interface Registration"); }
        }
        internal static string NoTypeLibraryFoundForInterface {
              get { return SR.GetResourceString("NoTypeLibraryFoundForInterface", @"No type library available for interface"); }
        }
        internal static string VariantArrayNull {
              get { return SR.GetResourceString("VariantArrayNull", @"Parameter at index {0} is null."); }
        }
        internal static string UnableToRetrievepUnk {
              get { return SR.GetResourceString("UnableToRetrievepUnk", @"Unable to retrieve IUnknown for object."); }
        }
        internal static string PersistWrapperIsNull {
              get { return SR.GetResourceString("PersistWrapperIsNull", @"QueryInterface succeeded but the persistable type wrapper was null."); }
        }
        internal static string UnexpectedThreadingModel {
              get { return SR.GetResourceString("UnexpectedThreadingModel", @"Unexpected threading model. WCF/COM+ integration only supports STA and MTA threading models."); }
        }
        internal static string NoneOfTheMethodsForInterfaceFoundInConfig {
              get { return SR.GetResourceString("NoneOfTheMethodsForInterfaceFoundInConfig", @"None of the methods were found for interface {0}."); }
        }
        internal static string InvalidWebServiceInterface {
              get { return SR.GetResourceString("InvalidWebServiceInterface", @"The interface with IID {0} cannot be exposed as a web service"); }
        }
        internal static string InvalidWebServiceParameter {
              get { return SR.GetResourceString("InvalidWebServiceParameter", @"The parameter named {0} of type {1} on method {2} of interface {3} cannot be serialized."); }
        }
        internal static string InvalidWebServiceReturnValue {
              get { return SR.GetResourceString("InvalidWebServiceReturnValue", @"The return value of type {0} on method {1} of interface {2} cannot be serialized."); }
        }
        internal static string OperationNotFound {
              get { return SR.GetResourceString("OperationNotFound", @"The method '{0}' could not be found. Ensure that the correct method name is specified."); }
        }
        internal static string BadDispID {
              get { return SR.GetResourceString("BadDispID", @"The Dispatch ID '{0}' could not be found or is invalid."); }
        }
        internal static string BadParamCount {
              get { return SR.GetResourceString("BadParamCount", @"The number of parameters in the request did not match the number supported by the method. Ensure that the correct number of parameters are specified."); }
        }
        internal static string BindingNotFoundInConfig {
              get { return SR.GetResourceString("BindingNotFoundInConfig", @"Binding type {0} instance {1} not found in config."); }
        }
        internal static string AddressNotSpecified {
              get { return SR.GetResourceString("AddressNotSpecified", @"The required address keyword was not specified."); }
        }
        internal static string BindingNotSpecified {
              get { return SR.GetResourceString("BindingNotSpecified", @"The required binding keyword was not specified or is not valid."); }
        }
        internal static string OnlyVariantAllowedByRef {
              get { return SR.GetResourceString("OnlyVariantAllowedByRef", @"A VARIANT parameter was passed by value. VARIANT parameters must be passed by reference."); }
        }
        internal static string CannotResolveTypeForParamInMessageDescription {
              get { return SR.GetResourceString("CannotResolveTypeForParamInMessageDescription", @"The type for the '{0}' parameter in '{1}' within the namespace '{2}' cannot not be resolved."); }
        }
        internal static string TooLate {
              get { return SR.GetResourceString("TooLate", @"The operation cannot be performed after the communications channel has been created."); }
        }
        internal static string RequireConfiguredMethods {
              get { return SR.GetResourceString("RequireConfiguredMethods", @"The interface with IID {0} has no methods configured in the COM+ catalog and cannot be exposed as a web service."); }
        }
        internal static string RequireConfiguredInterfaces {
              get { return SR.GetResourceString("RequireConfiguredInterfaces", @"The interface with IID {0} is not configured in the COM+ catalog and cannot be exposed as a web service."); }
        }
        internal static string CannotCreateChannelOption {
              get { return SR.GetResourceString("CannotCreateChannelOption", @"The channeloption intrinsic object cannot be created because the channel builder is not initialized."); }
        }
        internal static string NoTransactionInContext {
              get { return SR.GetResourceString("NoTransactionInContext", @"There is no transaction in the context of the operation."); }
        }
        internal static string IssuedTokenFlowNotAllowed {
              get { return SR.GetResourceString("IssuedTokenFlowNotAllowed", @"The service does not accept issued tokens."); }
        }
        internal static string GeneralSchemaValidationError {
              get { return SR.GetResourceString("GeneralSchemaValidationError", @"There was an error verifying some XML Schemas generated during export:\r\n{0}"); }
        }
        internal static string SchemaValidationError {
              get { return SR.GetResourceString("SchemaValidationError", @"There was a validation error on a schema generated during export:\r\n    Source: {0}\r\n    Line: {1} Column: {2}\r\n   Validation Error: {3}"); }
        }
        internal static string ContractBindingAddressCannotBeNull {
              get { return SR.GetResourceString("ContractBindingAddressCannotBeNull", @"The Address, Binding and Contract keywords are required."); }
        }
        internal static string TypeLoadForContractTypeIIDFailedWith {
              get { return SR.GetResourceString("TypeLoadForContractTypeIIDFailedWith", @"Type load for contract interface ID {0} failed with Error:{1}."); }
        }
        internal static string BindingLoadFromConfigFailedWith {
              get { return SR.GetResourceString("BindingLoadFromConfigFailedWith", @"Fail to load binding {0} from config. Error:{1}."); }
        }
        internal static string PooledApplicationNotSupportedForComplusHostedScenarios {
              get { return SR.GetResourceString("PooledApplicationNotSupportedForComplusHostedScenarios", @"Application {0} is marked Pooled. Pooled applications are not supported under COM+ hosting."); }
        }
        internal static string RecycledApplicationNotSupportedForComplusHostedScenarios {
              get { return SR.GetResourceString("RecycledApplicationNotSupportedForComplusHostedScenarios", @"Application {0} has recycling enabled. Recycling of applications is not supported under COM+ hosting."); }
        }
        internal static string BadImpersonationLevelForOutOfProcWas {
              get { return SR.GetResourceString("BadImpersonationLevelForOutOfProcWas", @"The client token at least needs to have the SecurityImpersonationLevel of at least Impersonation for Out of process Webhost activations."); }
        }
        internal static string ComPlusInstanceProviderRequiresMessage0 {
              get { return SR.GetResourceString("ComPlusInstanceProviderRequiresMessage0", @"This InstanceContext requires a valid Message to obtain the instance."); }
        }
        internal static string ComPlusInstanceCreationRequestSchema {
              get { return SR.GetResourceString("ComPlusInstanceCreationRequestSchema", @"From: {0}\nAppId: {1}\nClsId: {2}\nIncoming TransactionId: {3}\nRequesting Identity: {4}"); }
        }
        internal static string ComPlusMethodCallSchema {
              get { return SR.GetResourceString("ComPlusMethodCallSchema", @"From: {0}\nAppId: {1}\nClsId: {2}\nIid: {3}\nAction: {4}\nInstance Id: {5}\nManaged Thread Id: {6}\nUnmanaged Thread Id: {7}\nRequesting Identity: {8}"); }
        }
        internal static string ComPlusServiceSchema {
              get { return SR.GetResourceString("ComPlusServiceSchema", @"AppId: {0}\nClsId: {1}\n"); }
        }
        internal static string ComPlusServiceSchemaDllHost {
              get { return SR.GetResourceString("ComPlusServiceSchemaDllHost", @"AppId: {0}"); }
        }
        internal static string ComPlusTLBImportSchema {
              get { return SR.GetResourceString("ComPlusTLBImportSchema", @"Iid: {0}\nType Library ID: {1}"); }
        }
        internal static string ComPlusServiceHostStartingServiceErrorNoQFE {
              get { return SR.GetResourceString("ComPlusServiceHostStartingServiceErrorNoQFE", @"A Windows hotfix or later service pack is required on Windows XP and Windows Server 2003 to use WS-AtomicTransaction and COM+ Integration Web service transaction functionality. See the Microsoft .NET Framework release notes for instructions on installing the required hotfix."); }
        }
        internal static string ComIntegrationManifestCreationFailed {
              get { return SR.GetResourceString("ComIntegrationManifestCreationFailed", @"Generating manifest file {0} failed with {1}."); }
        }
        internal static string TempDirectoryNotFound {
              get { return SR.GetResourceString("TempDirectoryNotFound", @"Directory {0} not found."); }
        }
        internal static string CannotAccessDirectory {
              get { return SR.GetResourceString("CannotAccessDirectory", @"Cannot access directory {0}."); }
        }
        internal static string CLSIDDoesNotSupportIPersistStream {
              get { return SR.GetResourceString("CLSIDDoesNotSupportIPersistStream", @"The object with CLSID '{0}' does not support the required IPersistStream interface."); }
        }
        internal static string CLSIDOfTypeDoesNotMatch {
              get { return SR.GetResourceString("CLSIDOfTypeDoesNotMatch", @"CLSID of type {0} does not match the CLSID on PersistStreamTypeWrapper which is {1}."); }
        }
        internal static string TargetObjectDoesNotSupportIPersistStream {
              get { return SR.GetResourceString("TargetObjectDoesNotSupportIPersistStream", @"Target object does not support IPersistStream."); }
        }
        internal static string TargetTypeIsAnIntefaceButCorrespoindingTypeIsNotPersistStreamTypeWrapper {
              get { return SR.GetResourceString("TargetTypeIsAnIntefaceButCorrespoindingTypeIsNotPersistStreamTypeWrapper", @"Target type is an interface but corresponding type is not PersistStreamTypeWrapper."); }
        }
        internal static string NotAllowedPersistableCLSID {
              get { return SR.GetResourceString("NotAllowedPersistableCLSID", @"CLSID {0} is not allowed."); }
        }
        internal static string TransferringToComplus {
              get { return SR.GetResourceString("TransferringToComplus", @"Transferring to ComPlus logical thread {0}."); }
        }
        internal static string NamedArgsNotSupported {
              get { return SR.GetResourceString("NamedArgsNotSupported", @"The cNamedArgs parameter is not supported and must be 0."); }
        }
        internal static string MexBindingNotFoundInConfig {
              get { return SR.GetResourceString("MexBindingNotFoundInConfig", @"Binding '{0}' was not found in config. The config file must be present and contain a binding matching the one specified in the moniker."); }
        }
        internal static string ClaimTypeCannotBeEmpty {
              get { return SR.GetResourceString("ClaimTypeCannotBeEmpty", @"The claimType cannot be an empty string."); }
        }
        internal static string X509ChainIsEmpty {
              get { return SR.GetResourceString("X509ChainIsEmpty", @"X509Chain does not have any valid certificates."); }
        }
        internal static string MissingCustomCertificateValidator {
              get { return SR.GetResourceString("MissingCustomCertificateValidator", @"X509CertificateValidationMode.Custom requires a CustomCertificateValidator. Specify the CustomCertificateValidator property."); }
        }
        internal static string MissingMembershipProvider {
              get { return SR.GetResourceString("MissingMembershipProvider", @"UserNamePasswordValidationMode.MembershipProvider requires a MembershipProvider. Specify the MembershipProvider property."); }
        }
        internal static string MissingCustomUserNamePasswordValidator {
              get { return SR.GetResourceString("MissingCustomUserNamePasswordValidator", @"UserNamePasswordValidationMode.Custom requires a CustomUserNamePasswordValidator. Specify the CustomUserNamePasswordValidator property."); }
        }
        internal static string SpnegoImpersonationLevelCannotBeSetToNone {
              get { return SR.GetResourceString("SpnegoImpersonationLevelCannotBeSetToNone", @"The Security Support Provider Interface does not support Impersonation level 'None'. Specify Identification, Impersonation or Delegation level."); }
        }
        internal static string PublicKeyNotRSA {
              get { return SR.GetResourceString("PublicKeyNotRSA", @"The public key is not an RSA key."); }
        }
        internal static string SecurityAuditFailToLoadDll {
              get { return SR.GetResourceString("SecurityAuditFailToLoadDll", @"The '{0}' dynamic link library (dll) failed to load."); }
        }
        internal static string SecurityAuditPlatformNotSupported {
              get { return SR.GetResourceString("SecurityAuditPlatformNotSupported", @"Writing audit messages to the Security log is not supported by the current platform. You must write audit messages to the Application log."); }
        }
        internal static string NoPrincipalSpecifiedInAuthorizationContext {
              get { return SR.GetResourceString("NoPrincipalSpecifiedInAuthorizationContext", @"No custom principal is specified in the authorization context."); }
        }
        internal static string AccessDenied {
              get { return SR.GetResourceString("AccessDenied", @"Access is denied."); }
        }
        internal static string SecurityAuditNotSupportedOnChannelFactory {
              get { return SR.GetResourceString("SecurityAuditNotSupportedOnChannelFactory", @"SecurityAuditBehavior is not supported on the channel factory."); }
        }
        internal static string ExpiredTokenInChannelParameters {
              get { return SR.GetResourceString("ExpiredTokenInChannelParameters", @"The Infocard token created during channel intialization has expired. Please create a new channel to reacquire token. "); }
        }
        internal static string NoTokenInChannelParameters {
              get { return SR.GetResourceString("NoTokenInChannelParameters", @"No Infocard token was found in the ChannelParameters. Infocard requires that the security token be created during channel intialization."); }
        }
        internal static string ArgumentOutOfRange {
              get { return SR.GetResourceString("ArgumentOutOfRange", @"value must be >= {0} and <= {1}."); }
        }
        internal static string InsufficientCryptoSupport {
              get { return SR.GetResourceString("InsufficientCryptoSupport", @"The binding's PeerTransportSecuritySettings can not be supported under the current system security configuration."); }
        }
        internal static string InsufficientCredentials {
              get { return SR.GetResourceString("InsufficientCredentials", @"Credentials specified are not sufficient to carry requested operation. Please specify a valid value for {0}. "); }
        }
        internal static string UnexpectedSecurityTokensDuringHandshake {
              get { return SR.GetResourceString("UnexpectedSecurityTokensDuringHandshake", @"Connection was not accepted because the SecurityContext contained tokens that do not match the current security settings."); }
        }
        internal static string InsufficientResolverSettings {
              get { return SR.GetResourceString("InsufficientResolverSettings", @"Provided information is Insufficient to create a valid connection to the resolver service."); }
        }
        internal static string InvalidResolverMode {
              get { return SR.GetResourceString("InvalidResolverMode", @"Specified PeerResolverMode value {0} is invalid. Please specify either PeerResolveMode.Auto, Default, or Pnrp."); }
        }
        internal static string MustOverrideInitialize {
              get { return SR.GetResourceString("MustOverrideInitialize", @"concrete PeerResolver implementation must override Initialize to accept metadata about resolver service."); }
        }
        internal static string NotValidWhenOpen {
              get { return SR.GetResourceString("NotValidWhenOpen", @"The operation: {0} is not valid while the object is in open state."); }
        }
        internal static string NotValidWhenClosed {
              get { return SR.GetResourceString("NotValidWhenClosed", @"The operation: {0} is not valid while the object is in closed state."); }
        }
        internal static string DuplicatePeerRegistration {
              get { return SR.GetResourceString("DuplicatePeerRegistration", @"A peer registration with the service address {0} already exists."); }
        }
        internal static string MessagePropagationException {
              get { return SR.GetResourceString("MessagePropagationException", @"The MessagePropagationFilter threw an exception. Please refer to InnerException."); }
        }
        internal static string NotificationException {
              get { return SR.GetResourceString("NotificationException", @"An event notification threw an exception. Please refer to InnerException."); }
        }
        internal static string ResolverException {
              get { return SR.GetResourceString("ResolverException", @"The Peer resolver threw an exception.  Please refer to InnerException."); }
        }
        internal static string RefreshIntervalMustBeGreaterThanZero {
              get { return SR.GetResourceString("RefreshIntervalMustBeGreaterThanZero", @"Invalid RefreshInterval value of {0}; it must be greater than zero"); }
        }
        internal static string CleanupIntervalMustBeGreaterThanZero {
              get { return SR.GetResourceString("CleanupIntervalMustBeGreaterThanZero", @"Invalid CleanupInterval value of {0}; it must be greater than zero"); }
        }
        internal static string AmbiguousConnectivitySpec {
              get { return SR.GetResourceString("AmbiguousConnectivitySpec", @"Multiple link-local only interfaces detected.  Please specifiy the interface you require by using the ListenIpAddress attribute in the PeerTransportBindingElement"); }
        }
        internal static string MustRegisterMoreThanZeroAddresses {
              get { return SR.GetResourceString("MustRegisterMoreThanZeroAddresses", @"Registration with zero addresses detected.   Please call Register with more than zero addresses."); }
        }
        internal static string BasicHttpContextBindingRequiresAllowCookie {
              get { return SR.GetResourceString("BasicHttpContextBindingRequiresAllowCookie", @"BasicHttpContextBinding {0}:{1} requires that AllowCookies property is set to true."); }
        }
        internal static string CallbackContextOnlySupportedInWSAddressing10 {
              get { return SR.GetResourceString("CallbackContextOnlySupportedInWSAddressing10", @"The message contains a callback context header with an endpoint reference for AddressingVersion '{0}'. Callback context can only be transmitted when the AddressingVersion is configured with 'WSAddressing10'."); }
        }
        internal static string ListenAddressAlreadyContainsContext {
              get { return SR.GetResourceString("ListenAddressAlreadyContainsContext", @"The callback address already has a context header in it."); }
        }
        internal static string MultipleContextHeadersFoundInCallbackAddress {
              get { return SR.GetResourceString("MultipleContextHeadersFoundInCallbackAddress", @"The callback address contains multiple context headers. There can be at most one context header in a callback address."); }
        }
        internal static string CallbackContextNotExpectedOnIncomingMessageAtClient {
              get { return SR.GetResourceString("CallbackContextNotExpectedOnIncomingMessageAtClient", @"The incoming message with action '{0}' contains a callback context header with name '{1}' and namespace '{2}'. Callback context headers are not expected in incoming messages at the client."); }
        }
        internal static string CallbackContextOnlySupportedInSoap {
              get { return SR.GetResourceString("CallbackContextOnlySupportedInSoap", @"The message contains a callback context message property. Callback context can be transmitted only when the ContextBindingElement is configured with ContextExchangeMechanism of ContextSoapHeader."); }
        }
        internal static string ContextBindingElementCannotProvideChannelFactory {
              get { return SR.GetResourceString("ContextBindingElementCannotProvideChannelFactory", @"ContextBindingElement cannot provide channel factory for the requested channel shape {0}."); }
        }
        internal static string ContextBindingElementCannotProvideChannelListener {
              get { return SR.GetResourceString("ContextBindingElementCannotProvideChannelListener", @"ContextBindingElement cannot provide channel listener for the requested channel shape {0}."); }
        }
        internal static string InvalidCookieContent {
              get { return SR.GetResourceString("InvalidCookieContent", @"Value '{0}' specified for 'name' attribute of ContextMessageProperty is either null or has invalid character(s). Please ensure value of 'name' is within the allowed value space."); }
        }
        internal static string SchemaViolationInsideContextHeader {
              get { return SR.GetResourceString("SchemaViolationInsideContextHeader", @"Context protocol was unable to parse the context header. Nodes disallowed by the context header schema were found inside the context header."); }
        }
        internal static string CallbackContextNotExpectedOnOutgoingMessageAtServer {
              get { return SR.GetResourceString("CallbackContextNotExpectedOnOutgoingMessageAtServer", @"The outgoing message with action '{0}' contains a callback context message property. Callback context cannot be transmitted in outgoing messages at the server."); }
        }
        internal static string ChannelIsOpen {
              get { return SR.GetResourceString("ChannelIsOpen", @"Channel context management cannot be enabled or disabled after the channel is opened."); }
        }
        internal static string ContextManagementNotEnabled {
              get { return SR.GetResourceString("ContextManagementNotEnabled", @"Context cached at the channel cannot be set or retrieved when the context management is disabled at the channel layer. Ensure context channel property 'IContextManager.Enabled' is set to true."); }
        }
        internal static string CachedContextIsImmutable {
              get { return SR.GetResourceString("CachedContextIsImmutable", @"Context cached at the channel layer cannot be changed after the channel is opened."); }
        }
        internal static string InvalidMessageContext {
              get { return SR.GetResourceString("InvalidMessageContext", @"Cannot specify 'ContextMessageProperty' in message when using context channel with context management enabled. Ensure the message does not have 'ContextMessageProperty' or disable context management by setting channel property 'IContextManager.Enabled' to false."); }
        }
        internal static string InvalidContextReceived {
              get { return SR.GetResourceString("InvalidContextReceived", @"Context channel received a message with context which does not match the current context cached at the channel. Ensure service does not change context after it was originally set or disable context management by setting channel property 'IContextManager.Enabled' to false."); }
        }
        internal static string BehaviorRequiresContextProtocolSupportInBinding {
              get { return SR.GetResourceString("BehaviorRequiresContextProtocolSupportInBinding", @"Service behavior {0} requires that the binding associated with endpoint {1} listening on {2} supports the context protocol, because the contract associated with this endpoint may require a session. Currently configured binding for this endpoint does not support the context protocol. Please modify the binding to add support for the context protocol or modify the SessionMode on the contract to NotAllowed."); }
        }
        internal static string HttpCookieContextExchangeMechanismNotCompatibleWithTransportType {
              get { return SR.GetResourceString("HttpCookieContextExchangeMechanismNotCompatibleWithTransportType", @"Binding {1}:{2} is configured with ContextExchangeMechanism.HttpCookie which is not compatible with the transport type {0}. Please modify the ContextExchangeMechanism or use HTTP or HTTPS transport."); }
        }
        internal static string HttpCookieContextExchangeMechanismNotCompatibleWithTransportCookieSetting {
              get { return SR.GetResourceString("HttpCookieContextExchangeMechanismNotCompatibleWithTransportCookieSetting", @"ContextBindingElement of binding {0}:{1} is configured with ContextExchangeMode.HttpCookie but the configuration of this binding's HttpTransportBindingElement prevents upper channel layers from managing cookies. Please set the HttpTransportBindingElement.AllowCookies property to false or change the ContextExchangeMechanism of ContextBindingElement to SoapHeader."); }
        }
        internal static string PolicyImportContextBindingElementCollectionIsNull {
              get { return SR.GetResourceString("PolicyImportContextBindingElementCollectionIsNull", @"ContextBindingElementImporter cannot import policy because PolicyImportContext.BindingElements collection is null."); }
        }
        internal static string ContextChannelFactoryChannelCreatedDetail {
              get { return SR.GetResourceString("ContextChannelFactoryChannelCreatedDetail", @"EndpointAddress: {0}, Via:{1}"); }
        }
        internal static string XmlFormatViolationInContextHeader {
              get { return SR.GetResourceString("XmlFormatViolationInContextHeader", @"Context protocol was unable to parse the context header."); }
        }
        internal static string XmlFormatViolationInCallbackContextHeader {
              get { return SR.GetResourceString("XmlFormatViolationInCallbackContextHeader", @"Context protocol was unable to parse the callback context header."); }
        }
        internal static string OleTxHeaderCorrupt {
              get { return SR.GetResourceString("OleTxHeaderCorrupt", @"The OLE Transactions header was invalid or corrupt."); }
        }
        internal static string WsatHeaderCorrupt {
              get { return SR.GetResourceString("WsatHeaderCorrupt", @"The WS-AtomicTransaction header was invalid or corrupt."); }
        }
        internal static string FailedToDeserializeIssuedToken {
              get { return SR.GetResourceString("FailedToDeserializeIssuedToken", @"The issued token accompanying the WS-AtomicTransaction coordination context was invalid or corrupt."); }
        }
        internal static string InvalidPropagationToken {
              get { return SR.GetResourceString("InvalidPropagationToken", @"The OLE Transactions propagation token received in the message could not be used to unmarshal a transaction. It may be invalid or corrupt."); }
        }
        internal static string InvalidWsatExtendedInfo {
              get { return SR.GetResourceString("InvalidWsatExtendedInfo", @"The WS-AtomicTransaction extended information included in the OLE Transactions propagation token was invalid or corrupt."); }
        }
        internal static string TMCommunicationError {
              get { return SR.GetResourceString("TMCommunicationError", @"An error occurred communicating with the distributed transaction manager."); }
        }
        internal static string UnmarshalTransactionFaulted {
              get { return SR.GetResourceString("UnmarshalTransactionFaulted", @"The WS-AtomicTransaction protocol service could not unmarshal the flowed transaction. The following exception occured: {0}"); }
        }
        internal static string InvalidRegistrationHeaderTransactionId {
              get { return SR.GetResourceString("InvalidRegistrationHeaderTransactionId", @"The transaction identifier element in the registration header is invalid"); }
        }
        internal static string InvalidRegistrationHeaderIdentifier {
              get { return SR.GetResourceString("InvalidRegistrationHeaderIdentifier", @"The context identifier element in the registration header is invalid."); }
        }
        internal static string InvalidRegistrationHeaderTokenId {
              get { return SR.GetResourceString("InvalidRegistrationHeaderTokenId", @"The token identifier element in the registration header is invalid."); }
        }
        internal static string InvalidCoordinationContextTransactionId {
              get { return SR.GetResourceString("InvalidCoordinationContextTransactionId", @"The transaction identifier element in the coordination context is invalid."); }
        }
        internal static string WsatRegistryValueReadError {
              get { return SR.GetResourceString("WsatRegistryValueReadError", @"The WS-AtomicTransaction transaction formatter could not read the registry value '{0}'."); }
        }
        internal static string WsatProtocolServiceDisabled {
              get { return SR.GetResourceString("WsatProtocolServiceDisabled", @"The MSDTC transaction manager's WS-AtomicTransaction protocol service '{0}' is disabled and cannot unmarshal incoming transactions."); }
        }
        internal static string InboundTransactionsDisabled {
              get { return SR.GetResourceString("InboundTransactionsDisabled", @"The MSDTC transaction manager has disabled incoming transactions."); }
        }
        internal static string SourceTransactionsDisabled {
              get { return SR.GetResourceString("SourceTransactionsDisabled", @"The incoming transaction cannot be unmarshaled because the source MSDTC transaction manager has either disabled outbound transactions or disabled its WS-AtomicTransaction protocol service."); }
        }
        internal static string WsatUriCreationFailed {
              get { return SR.GetResourceString("WsatUriCreationFailed", @"A registration service address could not be created from MSDTC whereabouts information."); }
        }
        internal static string InvalidWsatProtocolVersion {
              get { return SR.GetResourceString("InvalidWsatProtocolVersion", @"The specified WSAT protocol version is invalid."); }
        }
        internal static string ParameterCannotBeEmpty {
              get { return SR.GetResourceString("ParameterCannotBeEmpty", @"The parameter cannot be empty."); }
        }
        internal static string RedirectCache {
              get { return SR.GetResourceString("RedirectCache", @"The requested resouce has not changed and should be taken from cache."); }
        }
        internal static string RedirectResource {
              get { return SR.GetResourceString("RedirectResource", @"The requested resource has moved to one of the following locations:\n{0}"); }
        }
        internal static string RedirectUseIntermediary {
              get { return SR.GetResourceString("RedirectUseIntermediary", @"The requested resource must be accessed through one of the following intermediary service locations:\n{0}"); }
        }
        internal static string RedirectGenericMessage {
              get { return SR.GetResourceString("RedirectGenericMessage", @"The requested resource has been moved."); }
        }
        internal static string RedirectMustProvideLocation {
              get { return SR.GetResourceString("RedirectMustProvideLocation", @"At least one RedirectionLocation must be provided for this RedirectionType."); }
        }
        internal static string RedirectCacheNoLocationAllowed {
              get { return SR.GetResourceString("RedirectCacheNoLocationAllowed", @"RedirectionType 'Cache' does not allow any RedirectionLocation objects be passed into the constructor."); }
        }
        internal static string RedirectionInfoStringFormatWithNamespace {
              get { return SR.GetResourceString("RedirectionInfoStringFormatWithNamespace", @"{0} ({1})"); }
        }
        internal static string RedirectionInfoStringFormatNoNamespace {
              get { return SR.GetResourceString("RedirectionInfoStringFormatNoNamespace", @"{0}"); }
        }
        internal static string RetryGenericMessage {
              get { return SR.GetResourceString("RetryGenericMessage", @"The requested resource is available."); }
        }
        internal static string ActivityCallback {
              get { return SR.GetResourceString("ActivityCallback", @"Executing user callback."); }
        }
        internal static string ActivityClose {
              get { return SR.GetResourceString("ActivityClose", @"Close '{0}'."); }
        }
        internal static string ActivityConstructChannelFactory {
              get { return SR.GetResourceString("ActivityConstructChannelFactory", @"Construct ChannelFactory. Contract type: '{0}'."); }
        }
        internal static string ActivityConstructServiceHost {
              get { return SR.GetResourceString("ActivityConstructServiceHost", @"Construct ServiceHost '{0}'."); }
        }
        internal static string ActivityExecuteMethod {
              get { return SR.GetResourceString("ActivityExecuteMethod", @"Execute '{0}.{1}'."); }
        }
        internal static string ActivityExecuteAsyncMethod {
              get { return SR.GetResourceString("ActivityExecuteAsyncMethod", @"Execute Async: Begin: '{0}.{1}'; End: '{2}.{3}'."); }
        }
        internal static string ActivityCloseChannelFactory {
              get { return SR.GetResourceString("ActivityCloseChannelFactory", @"Close ChannelFactory. Contract type: '{0}'."); }
        }
        internal static string ActivityCloseClientBase {
              get { return SR.GetResourceString("ActivityCloseClientBase", @"Close ClientBase. Contract type: '{0}'."); }
        }
        internal static string ActivityCloseServiceHost {
              get { return SR.GetResourceString("ActivityCloseServiceHost", @"Close ServiceHost '{0}'."); }
        }
        internal static string ActivityListenAt {
              get { return SR.GetResourceString("ActivityListenAt", @"Listen at '{0}'."); }
        }
        internal static string ActivityOpen {
              get { return SR.GetResourceString("ActivityOpen", @"Open '{0}'."); }
        }
        internal static string ActivityOpenServiceHost {
              get { return SR.GetResourceString("ActivityOpenServiceHost", @"Open ServiceHost '{0}'."); }
        }
        internal static string ActivityOpenChannelFactory {
              get { return SR.GetResourceString("ActivityOpenChannelFactory", @"Open ChannelFactory. Contract type: '{0}'."); }
        }
        internal static string ActivityOpenClientBase {
              get { return SR.GetResourceString("ActivityOpenClientBase", @"Open ClientBase. Contract type: '{0}'."); }
        }
        internal static string ActivityProcessAction {
              get { return SR.GetResourceString("ActivityProcessAction", @"Process action '{0}'."); }
        }
        internal static string ActivityProcessingMessage {
              get { return SR.GetResourceString("ActivityProcessingMessage", @"Processing message {0}."); }
        }
        internal static string ActivityReceiveBytes {
              get { return SR.GetResourceString("ActivityReceiveBytes", @"Receive bytes on connection '{0}'."); }
        }
        internal static string ActivitySecuritySetup {
              get { return SR.GetResourceString("ActivitySecuritySetup", @"Set up Secure Session."); }
        }
        internal static string ActivitySecurityRenew {
              get { return SR.GetResourceString("ActivitySecurityRenew", @"Renew Secure Session."); }
        }
        internal static string ActivitySecurityClose {
              get { return SR.GetResourceString("ActivitySecurityClose", @"Close Security Session."); }
        }
        internal static string ActivitySharedListenerConnection {
              get { return SR.GetResourceString("ActivitySharedListenerConnection", @"Shared listener connection: '{0}'."); }
        }
        internal static string ActivitySocketConnection {
              get { return SR.GetResourceString("ActivitySocketConnection", @"Socket connection: '{0}'."); }
        }
        internal static string ActivityReadOnConnection {
              get { return SR.GetResourceString("ActivityReadOnConnection", @"Reading data from connection on '{0}'."); }
        }
        internal static string ActivityReceiveAtVia {
              get { return SR.GetResourceString("ActivityReceiveAtVia", @"Receiving data at via '{0}'."); }
        }
        internal static string TraceCodeBeginExecuteMethod {
              get { return SR.GetResourceString("TraceCodeBeginExecuteMethod", @"Begin method execution."); }
        }
        internal static string TraceCodeChannelCreated {
              get { return SR.GetResourceString("TraceCodeChannelCreated", @"Created: {0}"); }
        }
        internal static string TraceCodeChannelDisposed {
              get { return SR.GetResourceString("TraceCodeChannelDisposed", @"Disposed: {0}"); }
        }
        internal static string TraceCodeChannelMessageSent {
              get { return SR.GetResourceString("TraceCodeChannelMessageSent", @"Sent a message over a channel"); }
        }
        internal static string TraceCodeChannelPreparedMessage {
              get { return SR.GetResourceString("TraceCodeChannelPreparedMessage", @"Prepared message for sending over a channel"); }
        }
        internal static string TraceCodeCommunicationObjectAborted {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectAborted", @"Aborted '{0}'."); }
        }
        internal static string TraceCodeCommunicationObjectAbortFailed {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectAbortFailed", @"Failed to abort {0}"); }
        }
        internal static string TraceCodeCommunicationObjectCloseFailed {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectCloseFailed", @"Failed to close {0}"); }
        }
        internal static string TraceCodeCommunicationObjectClosed {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectClosed", @"Closed {0}"); }
        }
        internal static string TraceCodeCommunicationObjectCreated {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectCreated", @"Created {0}"); }
        }
        internal static string TraceCodeCommunicationObjectClosing {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectClosing", @"Closing {0}"); }
        }
        internal static string TraceCodeCommunicationObjectDisposing {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectDisposing", @"Disposing {0}"); }
        }
        internal static string TraceCodeCommunicationObjectFaultReason {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectFaultReason", @"CommunicationObject faulted due to exception."); }
        }
        internal static string TraceCodeCommunicationObjectFaulted {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectFaulted", @"Faulted {0}"); }
        }
        internal static string TraceCodeCommunicationObjectOpenFailed {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectOpenFailed", @"Failed to open {0}"); }
        }
        internal static string TraceCodeCommunicationObjectOpened {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectOpened", @"Opened {0}"); }
        }
        internal static string TraceCodeCommunicationObjectOpening {
              get { return SR.GetResourceString("TraceCodeCommunicationObjectOpening", @"Opening {0}"); }
        }
        internal static string TraceCodeConfigurationIsReadOnly {
              get { return SR.GetResourceString("TraceCodeConfigurationIsReadOnly", @"The configuration is read-only."); }
        }
        internal static string TraceCodeConfiguredExtensionTypeNotFound {
              get { return SR.GetResourceString("TraceCodeConfiguredExtensionTypeNotFound", @"Extension type is not configured."); }
        }
        internal static string TraceCodeConnectionAbandoned {
              get { return SR.GetResourceString("TraceCodeConnectionAbandoned", @"The connection has been abandoned."); }
        }
        internal static string TraceCodeConnectToIPEndpoint {
              get { return SR.GetResourceString("TraceCodeConnectToIPEndpoint", @"Connection information."); }
        }
        internal static string TraceCodeConnectionPoolCloseException {
              get { return SR.GetResourceString("TraceCodeConnectionPoolCloseException", @"An exception occurred while closing the connections in this connection pool."); }
        }
        internal static string TraceCodeConnectionPoolIdleTimeoutReached {
              get { return SR.GetResourceString("TraceCodeConnectionPoolIdleTimeoutReached", @"A connection has exceeded the idle timeout of this connection pool ({0}) and been closed."); }
        }
        internal static string TraceCodeConnectionPoolLeaseTimeoutReached {
              get { return SR.GetResourceString("TraceCodeConnectionPoolLeaseTimeoutReached", @"A connection has exceeded the connection lease timeout of this connection pool ({0}) and been closed."); }
        }
        internal static string TraceCodeConnectionPoolMaxOutboundConnectionsPerEndpointQuotaReached {
              get { return SR.GetResourceString("TraceCodeConnectionPoolMaxOutboundConnectionsPerEndpointQuotaReached", @"MaxOutboundConnectionsPerEndpoint quota ({0}) has been reached, so connection was closed and not stored in this connection pool."); }
        }
        internal static string TraceCodeServerMaxPooledConnectionsQuotaReached {
              get { return SR.GetResourceString("TraceCodeServerMaxPooledConnectionsQuotaReached", @"MaxOutboundConnectionsPerEndpoint quota ({0}) has been reached, so the connection was closed and not reused by the listener."); }
        }
        internal static string TraceCodeDefaultEndpointsAdded {
              get { return SR.GetResourceString("TraceCodeDefaultEndpointsAdded", @"No matching <service> tag was found. Default endpoints added."); }
        }
        internal static string TraceCodeDiagnosticsFailedMessageTrace {
              get { return SR.GetResourceString("TraceCodeDiagnosticsFailedMessageTrace", @"Failed to trace a message"); }
        }
        internal static string TraceCodeDidNotUnderstandMessageHeader {
              get { return SR.GetResourceString("TraceCodeDidNotUnderstandMessageHeader", @"Did not understand message header."); }
        }
        internal static string TraceCodeDroppedAMessage {
              get { return SR.GetResourceString("TraceCodeDroppedAMessage", @"A response message was received, but there are no outstanding requests waiting for this message. The message is being dropped."); }
        }
        internal static string TraceCodeCannotBeImportedInCurrentFormat {
              get { return SR.GetResourceString("TraceCodeCannotBeImportedInCurrentFormat", @"The given schema cannot be imported in this format."); }
        }
        internal static string TraceCodeElementTypeDoesntMatchConfiguredType {
              get { return SR.GetResourceString("TraceCodeElementTypeDoesntMatchConfiguredType", @"The type of the element does not match the configuration type."); }
        }
        internal static string TraceCodeEndExecuteMethod {
              get { return SR.GetResourceString("TraceCodeEndExecuteMethod", @"End method execution."); }
        }
        internal static string TraceCodeEndpointListenerClose {
              get { return SR.GetResourceString("TraceCodeEndpointListenerClose", @"Endpoint listener closed."); }
        }
        internal static string TraceCodeEndpointListenerOpen {
              get { return SR.GetResourceString("TraceCodeEndpointListenerOpen", @"Endpoint listener opened."); }
        }
        internal static string TraceCodeErrorInvokingUserCode {
              get { return SR.GetResourceString("TraceCodeErrorInvokingUserCode", @"Error invoking user code"); }
        }
        internal static string TraceCodeEvaluationContextNotFound {
              get { return SR.GetResourceString("TraceCodeEvaluationContextNotFound", @"Configuration evaluation context not found."); }
        }
        internal static string TraceCodeExportSecurityChannelBindingEntry {
              get { return SR.GetResourceString("TraceCodeExportSecurityChannelBindingEntry", @"Starting Security ExportChannelBinding"); }
        }
        internal static string TraceCodeExportSecurityChannelBindingExit {
              get { return SR.GetResourceString("TraceCodeExportSecurityChannelBindingExit", @"Finished Security ExportChannelBinding"); }
        }
        internal static string TraceCodeExtensionCollectionDoesNotExist {
              get { return SR.GetResourceString("TraceCodeExtensionCollectionDoesNotExist", @"The extension collection does not exist."); }
        }
        internal static string TraceCodeExtensionCollectionIsEmpty {
              get { return SR.GetResourceString("TraceCodeExtensionCollectionIsEmpty", @"The extension collection is empty."); }
        }
        internal static string TraceCodeExtensionCollectionNameNotFound {
              get { return SR.GetResourceString("TraceCodeExtensionCollectionNameNotFound", @"Extension element not associated with an extension collection."); }
        }
        internal static string TraceCodeExtensionElementAlreadyExistsInCollection {
              get { return SR.GetResourceString("TraceCodeExtensionElementAlreadyExistsInCollection", @"The extension element already exists in the collection."); }
        }
        internal static string TraceCodeExtensionTypeNotFound {
              get { return SR.GetResourceString("TraceCodeExtensionTypeNotFound", @"Extension type not found."); }
        }
        internal static string TraceCodeFailedToAddAnActivityIdHeader {
              get { return SR.GetResourceString("TraceCodeFailedToAddAnActivityIdHeader", @"Failed to set an activity id header on an outgoing message"); }
        }
        internal static string TraceCodeFailedToReadAnActivityIdHeader {
              get { return SR.GetResourceString("TraceCodeFailedToReadAnActivityIdHeader", @"Failed to read an activity id header on a message"); }
        }
        internal static string TraceCodeFilterNotMatchedNodeQuotaExceeded {
              get { return SR.GetResourceString("TraceCodeFilterNotMatchedNodeQuotaExceeded", @"Evaluating message logging filter against the message exceeded the node quota set on the filter."); }
        }
        internal static string TraceCodeGetBehaviorElement {
              get { return SR.GetResourceString("TraceCodeGetBehaviorElement", @"Get BehaviorElement."); }
        }
        internal static string TraceCodeGetChannelEndpointElement {
              get { return SR.GetResourceString("TraceCodeGetChannelEndpointElement", @"Get ChannelEndpointElement."); }
        }
        internal static string TraceCodeGetCommonBehaviors {
              get { return SR.GetResourceString("TraceCodeGetCommonBehaviors", @"Get machine.config common behaviors."); }
        }
        internal static string TraceCodeGetConfigurationSection {
              get { return SR.GetResourceString("TraceCodeGetConfigurationSection", @"Get configuration section."); }
        }
        internal static string TraceCodeGetConfiguredBinding {
              get { return SR.GetResourceString("TraceCodeGetConfiguredBinding", @"Get configured binding."); }
        }
        internal static string TraceCodeGetDefaultConfiguredBinding {
              get { return SR.GetResourceString("TraceCodeGetDefaultConfiguredBinding", @"Get default configured binding."); }
        }
        internal static string TraceCodeGetConfiguredEndpoint {
              get { return SR.GetResourceString("TraceCodeGetConfiguredEndpoint", @"Get configured endpoint."); }
        }
        internal static string TraceCodeGetDefaultConfiguredEndpoint {
              get { return SR.GetResourceString("TraceCodeGetDefaultConfiguredEndpoint", @"Get default configured endpoint."); }
        }
        internal static string TraceCodeGetServiceElement {
              get { return SR.GetResourceString("TraceCodeGetServiceElement", @"Get ServiceElement."); }
        }
        internal static string TraceCodeHttpAuthFailed {
              get { return SR.GetResourceString("TraceCodeHttpAuthFailed", @"Authentication failed for HTTP(S) connection"); }
        }
        internal static string TraceCodeHttpActionMismatch {
              get { return SR.GetResourceString("TraceCodeHttpActionMismatch", @"The HTTP SOAPAction header and the wsa:Action SOAP header did not match. "); }
        }
        internal static string TraceCodeHttpChannelMessageReceiveFailed {
              get { return SR.GetResourceString("TraceCodeHttpChannelMessageReceiveFailed", @"Failed to lookup a channel to receive an incoming message. Either the endpoint or the SOAP action was not found."); }
        }
        internal static string TraceCodeHttpChannelRequestAborted {
              get { return SR.GetResourceString("TraceCodeHttpChannelRequestAborted", @"Failed to send request message over HTTP"); }
        }
        internal static string TraceCodeHttpChannelResponseAborted {
              get { return SR.GetResourceString("TraceCodeHttpChannelResponseAborted", @"Failed to send response message over HTTP"); }
        }
        internal static string TraceCodeHttpChannelUnexpectedResponse {
              get { return SR.GetResourceString("TraceCodeHttpChannelUnexpectedResponse", @"Received bad HTTP response"); }
        }
        internal static string TraceCodeHttpResponseReceived {
              get { return SR.GetResourceString("TraceCodeHttpResponseReceived", @"HTTP response was received"); }
        }
        internal static string TraceCodeHttpChannelConcurrentReceiveQuotaReached {
              get { return SR.GetResourceString("TraceCodeHttpChannelConcurrentReceiveQuotaReached", @"The HTTP concurrent receive quota was reached."); }
        }
        internal static string TraceCodeHttpsClientCertificateInvalid {
              get { return SR.GetResourceString("TraceCodeHttpsClientCertificateInvalid", @"Client certificate is invalid."); }
        }
        internal static string TraceCodeHttpsClientCertificateInvalid1 {
              get { return SR.GetResourceString("TraceCodeHttpsClientCertificateInvalid1", @"Client certificate is invalid with native error code {0} (see http://go.microsoft.com/fwlink/?LinkId=187517 for details)."); }
        }
        internal static string TraceCodeHttpsClientCertificateNotPresent {
              get { return SR.GetResourceString("TraceCodeHttpsClientCertificateNotPresent", @"Client certificate is required.  No certificate was found in the request.  This might be because the client certificate could not be successfully validated by the operating system or IIS.  For information on how to bypass those validations and use a custom X509CertificateValidator in WCF please see http://go.microsoft.com/fwlink/?LinkId=208540."); }
        }
        internal static string TraceCodeImportSecurityChannelBindingEntry {
              get { return SR.GetResourceString("TraceCodeImportSecurityChannelBindingEntry", @"Starting Security ImportChannelBinding"); }
        }
        internal static string TraceCodeImportSecurityChannelBindingExit {
              get { return SR.GetResourceString("TraceCodeImportSecurityChannelBindingExit", @"Finished Security ImportChannelBinding"); }
        }
        internal static string TraceCodeIncompatibleExistingTransportManager {
              get { return SR.GetResourceString("TraceCodeIncompatibleExistingTransportManager", @"An existing incompatible transport manager was found for the specified URI."); }
        }
        internal static string TraceCodeInitiatingNamedPipeConnection {
              get { return SR.GetResourceString("TraceCodeInitiatingNamedPipeConnection", @"Initiating Named Pipe connection."); }
        }
        internal static string TraceCodeInitiatingTcpConnection {
              get { return SR.GetResourceString("TraceCodeInitiatingTcpConnection", @"Initiating TCP connection."); }
        }
        internal static string TraceCodeIssuanceTokenProviderBeginSecurityNegotiation {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderBeginSecurityNegotiation", @"The IssuanceTokenProvider has started a new security negotiation."); }
        }
        internal static string TraceCodeIssuanceTokenProviderEndSecurityNegotiation {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderEndSecurityNegotiation", @"The IssuanceTokenProvider has completed the security negotiation."); }
        }
        internal static string TraceCodeIssuanceTokenProviderRedirectApplied {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderRedirectApplied", @"The IssuanceTokenProvider applied a redirection header."); }
        }
        internal static string TraceCodeIssuanceTokenProviderRemovedCachedToken {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderRemovedCachedToken", @"The IssuanceTokenProvider removed the expired service token."); }
        }
        internal static string TraceCodeIssuanceTokenProviderServiceTokenCacheFull {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderServiceTokenCacheFull", @"IssuanceTokenProvider pruned service token cache."); }
        }
        internal static string TraceCodeIssuanceTokenProviderUsingCachedToken {
              get { return SR.GetResourceString("TraceCodeIssuanceTokenProviderUsingCachedToken", @"The IssuanceTokenProvider used the cached service token."); }
        }
        internal static string TraceCodeListenerCreated {
              get { return SR.GetResourceString("TraceCodeListenerCreated", @"Listener created"); }
        }
        internal static string TraceCodeListenerDisposed {
              get { return SR.GetResourceString("TraceCodeListenerDisposed", @"Listener disposed"); }
        }
        internal static string TraceCodeMaxPendingConnectionsReached {
              get { return SR.GetResourceString("TraceCodeMaxPendingConnectionsReached", @"Maximum number of pending connections has been reached. "); }
        }
        internal static string TraceCodeMaxAcceptedChannelsReached {
              get { return SR.GetResourceString("TraceCodeMaxAcceptedChannelsReached", @"Maximum number of inbound session channel has been reached. "); }
        }
        internal static string TraceCodeMessageClosed {
              get { return SR.GetResourceString("TraceCodeMessageClosed", @"A message was closed"); }
        }
        internal static string TraceCodeMessageClosedAgain {
              get { return SR.GetResourceString("TraceCodeMessageClosedAgain", @"A message was closed again"); }
        }
        internal static string TraceCodeMessageCopied {
              get { return SR.GetResourceString("TraceCodeMessageCopied", @"A message was copied"); }
        }
        internal static string TraceCodeMessageCountLimitExceeded {
              get { return SR.GetResourceString("TraceCodeMessageCountLimitExceeded", @"Reached the limit of messages to log. Message logging is stopping. "); }
        }
        internal static string TraceCodeMessageNotLoggedQuotaExceeded {
              get { return SR.GetResourceString("TraceCodeMessageNotLoggedQuotaExceeded", @"Message not logged because its size exceeds configured quota"); }
        }
        internal static string TraceCodeMessageRead {
              get { return SR.GetResourceString("TraceCodeMessageRead", @"A message was read"); }
        }
        internal static string TraceCodeMessageSent {
              get { return SR.GetResourceString("TraceCodeMessageSent", @"Sent a message over a channel."); }
        }
        internal static string TraceCodeMessageReceived {
              get { return SR.GetResourceString("TraceCodeMessageReceived", @"Received a message over a channel."); }
        }
        internal static string TraceCodeMessageWritten {
              get { return SR.GetResourceString("TraceCodeMessageWritten", @"A message was written"); }
        }
        internal static string TraceCodeMessageProcessingPaused {
              get { return SR.GetResourceString("TraceCodeMessageProcessingPaused", @"Switched threads while processing a message."); }
        }
        internal static string TraceCodeNegotiationAuthenticatorAttached {
              get { return SR.GetResourceString("TraceCodeNegotiationAuthenticatorAttached", @"NegotiationTokenAuthenticator was attached."); }
        }
        internal static string TraceCodeNegotiationTokenProviderAttached {
              get { return SR.GetResourceString("TraceCodeNegotiationTokenProviderAttached", @"NegotiationTokenProvider was attached."); }
        }
        internal static string TraceCodeNoExistingTransportManager {
              get { return SR.GetResourceString("TraceCodeNoExistingTransportManager", @"No existing transport manager was found for the specified URI."); }
        }
        internal static string TraceCodeOpenedListener {
              get { return SR.GetResourceString("TraceCodeOpenedListener", @"Transport is listening at base URI."); }
        }
        internal static string TraceCodeOverridingDuplicateConfigurationKey {
              get { return SR.GetResourceString("TraceCodeOverridingDuplicateConfigurationKey", @"The configuration system has detected a duplicate key in a different configuration scope and is overriding with the more recent value."); }
        }
        internal static string TraceCodePerformanceCounterFailedToLoad {
              get { return SR.GetResourceString("TraceCodePerformanceCounterFailedToLoad", @"A performance counter failed to load. Some performance counters will not be available."); }
        }
        internal static string TraceCodePerformanceCountersFailed {
              get { return SR.GetResourceString("TraceCodePerformanceCountersFailed", @"Failed to load the performance counter '{0}'. Some performance counters will not be available"); }
        }
        internal static string TraceCodePerformanceCountersFailedDuringUpdate {
              get { return SR.GetResourceString("TraceCodePerformanceCountersFailedDuringUpdate", @"There was an error while updating the performance counter '{0}'. This performance counter will be disabled."); }
        }
        internal static string TraceCodePerformanceCountersFailedForService {
              get { return SR.GetResourceString("TraceCodePerformanceCountersFailedForService", @"Loading performance counters for the service failed. Performance counters will not be available for this service."); }
        }
        internal static string TraceCodePerformanceCountersFailedOnRelease {
              get { return SR.GetResourceString("TraceCodePerformanceCountersFailedOnRelease", @"Unloading the performance counters failed."); }
        }
        internal static string TraceCodePrematureDatagramEof {
              get { return SR.GetResourceString("TraceCodePrematureDatagramEof", @"A null Message (signalling end of channel) was received from a datagram channel, but the channel is still in the Opened state. This indicates a bug in the datagram channel, and the demuxer receive loop has been prematurely stalled. "); }
        }
        internal static string TraceCodeRemoveBehavior {
              get { return SR.GetResourceString("TraceCodeRemoveBehavior", @"Behavior type already exists in the collection"); }
        }
        internal static string TraceCodeRequestChannelReplyReceived {
              get { return SR.GetResourceString("TraceCodeRequestChannelReplyReceived", @"Received reply over request channel"); }
        }
        internal static string TraceCodeSecurity {
              get { return SR.GetResourceString("TraceCodeSecurity", @"A failure occured while performing a security related operation."); }
        }
        internal static string TraceCodeSecurityActiveServerSessionRemoved {
              get { return SR.GetResourceString("TraceCodeSecurityActiveServerSessionRemoved", @"An active security session was removed by the server."); }
        }
        internal static string TraceCodeSecurityAuditWrittenFailure {
              get { return SR.GetResourceString("TraceCodeSecurityAuditWrittenFailure", @"A failure occurred while writing to the security audit log."); }
        }
        internal static string TraceCodeSecurityAuditWrittenSuccess {
              get { return SR.GetResourceString("TraceCodeSecurityAuditWrittenSuccess", @"The security audit log is written successfully."); }
        }
        internal static string TraceCodeSecurityBindingIncomingMessageVerified {
              get { return SR.GetResourceString("TraceCodeSecurityBindingIncomingMessageVerified", @"The security protocol verified the incoming message."); }
        }
        internal static string TraceCodeSecurityBindingOutgoingMessageSecured {
              get { return SR.GetResourceString("TraceCodeSecurityBindingOutgoingMessageSecured", @"The security protocol secured the outgoing message."); }
        }
        internal static string TraceCodeSecurityBindingSecureOutgoingMessageFailure {
              get { return SR.GetResourceString("TraceCodeSecurityBindingSecureOutgoingMessageFailure", @"The security protocol cannot secure the outgoing message."); }
        }
        internal static string TraceCodeSecurityBindingVerifyIncomingMessageFailure {
              get { return SR.GetResourceString("TraceCodeSecurityBindingVerifyIncomingMessageFailure", @"The security protocol cannot verify the incoming message."); }
        }
        internal static string TraceCodeSecurityClientSessionKeyRenewed {
              get { return SR.GetResourceString("TraceCodeSecurityClientSessionKeyRenewed", @"The client security session renewed the session key."); }
        }
        internal static string TraceCodeSecurityClientSessionCloseSent {
              get { return SR.GetResourceString("TraceCodeSecurityClientSessionCloseSent", @"A Close message was sent by the client security session."); }
        }
        internal static string TraceCodeSecurityClientSessionCloseResponseSent {
              get { return SR.GetResourceString("TraceCodeSecurityClientSessionCloseResponseSent", @"Close response message was sent by client security session."); }
        }
        internal static string TraceCodeSecurityClientSessionCloseMessageReceived {
              get { return SR.GetResourceString("TraceCodeSecurityClientSessionCloseMessageReceived", @"Close message was received by client security session.TraceCodeSecurityClientSessionKeyRenewed=Client security session renewed session key."); }
        }
        internal static string TraceCodeSecurityClientSessionPreviousKeyDiscarded {
              get { return SR.GetResourceString("TraceCodeSecurityClientSessionPreviousKeyDiscarded", @"The client security session discarded the previous session key."); }
        }
        internal static string TraceCodeSecurityContextTokenCacheFull {
              get { return SR.GetResourceString("TraceCodeSecurityContextTokenCacheFull", @"The SecurityContextSecurityToken cache is full."); }
        }
        internal static string TraceCodeSecurityIdentityDeterminationFailure {
              get { return SR.GetResourceString("TraceCodeSecurityIdentityDeterminationFailure", @"Identity cannot be determined for an EndpointReference."); }
        }
        internal static string TraceCodeSecurityIdentityDeterminationSuccess {
              get { return SR.GetResourceString("TraceCodeSecurityIdentityDeterminationSuccess", @"Identity was determined for an EndpointReference."); }
        }
        internal static string TraceCodeSecurityIdentityHostNameNormalizationFailure {
              get { return SR.GetResourceString("TraceCodeSecurityIdentityHostNameNormalizationFailure", @"The HostName portion of an endpoint address cannot be normalized."); }
        }
        internal static string TraceCodeSecurityIdentityVerificationFailure {
              get { return SR.GetResourceString("TraceCodeSecurityIdentityVerificationFailure", @"Identity verification failed."); }
        }
        internal static string TraceCodeSecurityIdentityVerificationSuccess {
              get { return SR.GetResourceString("TraceCodeSecurityIdentityVerificationSuccess", @"Identity verification succeeded."); }
        }
        internal static string TraceCodeSecurityImpersonationFailure {
              get { return SR.GetResourceString("TraceCodeSecurityImpersonationFailure", @"Security impersonation failed at the server."); }
        }
        internal static string TraceCodeSecurityImpersonationSuccess {
              get { return SR.GetResourceString("TraceCodeSecurityImpersonationSuccess", @"Security Impersonation succeeded at the server."); }
        }
        internal static string TraceCodeSecurityInactiveSessionFaulted {
              get { return SR.GetResourceString("TraceCodeSecurityInactiveSessionFaulted", @"An inactive security session was faulted by the server."); }
        }
        internal static string TraceCodeSecurityNegotiationProcessingFailure {
              get { return SR.GetResourceString("TraceCodeSecurityNegotiationProcessingFailure", @"Service security negotiation processing failure."); }
        }
        internal static string TraceCodeSecurityNewServerSessionKeyIssued {
              get { return SR.GetResourceString("TraceCodeSecurityNewServerSessionKeyIssued", @"A new security session key was issued by the server."); }
        }
        internal static string TraceCodeSecurityPendingServerSessionAdded {
              get { return SR.GetResourceString("TraceCodeSecurityPendingServerSessionAdded", @"A pending security session was added to the server."); }
        }
        internal static string TraceCodeSecurityPendingServerSessionClosed {
              get { return SR.GetResourceString("TraceCodeSecurityPendingServerSessionClosed", @"The pending security session was closed by the server."); }
        }
        internal static string TraceCodeSecurityPendingServerSessionActivated {
              get { return SR.GetResourceString("TraceCodeSecurityPendingServerSessionActivated", @"A pending security session was activated by the server."); }
        }
        internal static string TraceCodeSecurityServerSessionCloseReceived {
              get { return SR.GetResourceString("TraceCodeSecurityServerSessionCloseReceived", @"The server security session received a close message from the client."); }
        }
        internal static string TraceCodeSecurityServerSessionCloseResponseReceived {
              get { return SR.GetResourceString("TraceCodeSecurityServerSessionCloseResponseReceived", @"Server security session received Close response message from client."); }
        }
        internal static string TraceCodeSecurityServerSessionAbortedFaultSent {
              get { return SR.GetResourceString("TraceCodeSecurityServerSessionAbortedFaultSent", @"Server security session sent session aborted fault to client."); }
        }
        internal static string TraceCodeSecurityServerSessionKeyUpdated {
              get { return SR.GetResourceString("TraceCodeSecurityServerSessionKeyUpdated", @"The security session key was updated by the server."); }
        }
        internal static string TraceCodeSecurityServerSessionRenewalFaultSent {
              get { return SR.GetResourceString("TraceCodeSecurityServerSessionRenewalFaultSent", @"The server security session sent a key renewal fault to the client."); }
        }
        internal static string TraceCodeSecuritySessionCloseResponseSent {
              get { return SR.GetResourceString("TraceCodeSecuritySessionCloseResponseSent", @"The server security session sent a close response to the client."); }
        }
        internal static string TraceCodeSecuritySessionServerCloseSent {
              get { return SR.GetResourceString("TraceCodeSecuritySessionServerCloseSent", @"Server security session sent Close to client."); }
        }
        internal static string TraceCodeSecuritySessionAbortedFaultReceived {
              get { return SR.GetResourceString("TraceCodeSecuritySessionAbortedFaultReceived", @"Client security session received session aborted fault from server."); }
        }
        internal static string TraceCodeSecuritySessionAbortedFaultSendFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionAbortedFaultSendFailure", @"Failure sending security session aborted fault to client."); }
        }
        internal static string TraceCodeSecuritySessionClosedResponseReceived {
              get { return SR.GetResourceString("TraceCodeSecuritySessionClosedResponseReceived", @"The client security session received a closed reponse from the server."); }
        }
        internal static string TraceCodeSecuritySessionClosedResponseSendFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionClosedResponseSendFailure", @"A failure occurred when sending a security session Close response to the client."); }
        }
        internal static string TraceCodeSecuritySessionServerCloseSendFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionServerCloseSendFailure", @"Failure sending security session Close to client."); }
        }
        internal static string TraceCodeSecuritySessionKeyRenewalFaultReceived {
              get { return SR.GetResourceString("TraceCodeSecuritySessionKeyRenewalFaultReceived", @"The client security session received a key renewal fault from the server."); }
        }
        internal static string TraceCodeSecuritySessionRedirectApplied {
              get { return SR.GetResourceString("TraceCodeSecuritySessionRedirectApplied", @"The client security session was redirected."); }
        }
        internal static string TraceCodeSecuritySessionRenewFaultSendFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionRenewFaultSendFailure", @"A failure occurred when sending a renewal fault on the security session key to the client."); }
        }
        internal static string TraceCodeSecuritySessionRequestorOperationFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionRequestorOperationFailure", @"The client security session operation failed."); }
        }
        internal static string TraceCodeSecuritySessionRequestorOperationSuccess {
              get { return SR.GetResourceString("TraceCodeSecuritySessionRequestorOperationSuccess", @"The security session operation completed successfully at the client."); }
        }
        internal static string TraceCodeSecuritySessionRequestorStartOperation {
              get { return SR.GetResourceString("TraceCodeSecuritySessionRequestorStartOperation", @"A security session operation was started at the client."); }
        }
        internal static string TraceCodeSecuritySessionResponderOperationFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionResponderOperationFailure", @"The security session operation failed at the server."); }
        }
        internal static string TraceCodeSecuritySpnToSidMappingFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySpnToSidMappingFailure", @"The ServicePrincipalName could not be mapped to a SecurityIdentifier."); }
        }
        internal static string TraceCodeSecurityTokenAuthenticatorClosed {
              get { return SR.GetResourceString("TraceCodeSecurityTokenAuthenticatorClosed", @"Security Token Authenticator was closed."); }
        }
        internal static string TraceCodeSecurityTokenAuthenticatorOpened {
              get { return SR.GetResourceString("TraceCodeSecurityTokenAuthenticatorOpened", @"Security Token Authenticator was opened."); }
        }
        internal static string TraceCodeSecurityTokenProviderClosed {
              get { return SR.GetResourceString("TraceCodeSecurityTokenProviderClosed", @"Security Token Provider was closed."); }
        }
        internal static string TraceCodeSecurityTokenProviderOpened {
              get { return SR.GetResourceString("TraceCodeSecurityTokenProviderOpened", @"Security Token Provider was opened."); }
        }
        internal static string TraceCodeServiceChannelLifetime {
              get { return SR.GetResourceString("TraceCodeServiceChannelLifetime", @"ServiceChannel information."); }
        }
        internal static string TraceCodeServiceHostBaseAddresses {
              get { return SR.GetResourceString("TraceCodeServiceHostBaseAddresses", @"ServiceHost base addresses."); }
        }
        internal static string TraceCodeServiceHostTimeoutOnClose {
              get { return SR.GetResourceString("TraceCodeServiceHostTimeoutOnClose", @"ServiceHost close operation timedout."); }
        }
        internal static string TraceCodeServiceHostFaulted {
              get { return SR.GetResourceString("TraceCodeServiceHostFaulted", @"ServiceHost faulted."); }
        }
        internal static string TraceCodeServiceHostErrorOnReleasePerformanceCounter {
              get { return SR.GetResourceString("TraceCodeServiceHostErrorOnReleasePerformanceCounter", @"ServiceHost error on calling ReleasePerformanceCounters."); }
        }
        internal static string TraceCodeServiceThrottleLimitReached {
              get { return SR.GetResourceString("TraceCodeServiceThrottleLimitReached", @"The system hit the limit set for throttle '{0}'. Limit for this throttle was set to {1}. Throttle value can be changed by modifying attribute '{2}' in serviceThrottle element or by modifying '{0}' property on behavior ServiceThrottlingBehavior."); }
        }
        internal static string TraceCodeServiceThrottleLimitReachedInternal {
              get { return SR.GetResourceString("TraceCodeServiceThrottleLimitReachedInternal", @"The system hit an internal throttle limit. Limit for this throttle was set to {0}. This throttle cannot be configured."); }
        }
        internal static string TraceCodeManualFlowThrottleLimitReached {
              get { return SR.GetResourceString("TraceCodeManualFlowThrottleLimitReached", @"The system hit the limit set for the '{0}' throttle. Throttle value can be changed by modifying {0} property on {1}."); }
        }
        internal static string TraceCodeProcessMessage2Paused {
              get { return SR.GetResourceString("TraceCodeProcessMessage2Paused", @"Switched threads while processing a message for Contract '{0}' at Address '{1}'. ConcurrencyMode for service is set to Single/Reentrant and the service is currently processing another message."); }
        }
        internal static string TraceCodeProcessMessage3Paused {
              get { return SR.GetResourceString("TraceCodeProcessMessage3Paused", @"Switched threads while processing a message for Contract '{0}' at Address '{1}'. Cannot process more than one transaction at a time and the transaction associated with the previous message is not yet complete. Ensure that the caller has committed the transaction."); }
        }
        internal static string TraceCodeProcessMessage31Paused {
              get { return SR.GetResourceString("TraceCodeProcessMessage31Paused", @"Switched threads while processing a message for Contract '{0}' at Address '{1}'. Waiting for the completion of ReceiveContext acknowledgement. If your service seems to be not processing the message ensure that the channel implementation of receive context completes the operation."); }
        }
        internal static string TraceCodeProcessMessage4Paused {
              get { return SR.GetResourceString("TraceCodeProcessMessage4Paused", @"Switched threads while processing a message for Contract '{0}' at Address '{1}'. UseSynchronizationContext property on ServiceBehaviorAttribute is set to true, and SynchronizationContext.Current was non-null when opening ServiceHost.  If your service seems to be not processing messages, consider setting UseSynchronizationContext to false."); }
        }
        internal static string TraceCodeServiceOperationExceptionOnReply {
              get { return SR.GetResourceString("TraceCodeServiceOperationExceptionOnReply", @"Replying to an operation threw a exception."); }
        }
        internal static string TraceCodeServiceOperationMissingReply {
              get { return SR.GetResourceString("TraceCodeServiceOperationMissingReply", @"The Request/Reply operation {0} has no Reply Message."); }
        }
        internal static string TraceCodeServiceOperationMissingReplyContext {
              get { return SR.GetResourceString("TraceCodeServiceOperationMissingReplyContext", @"The Request/Reply operation {0} has no IRequestContext to use for the reply."); }
        }
        internal static string TraceCodeServiceSecurityNegotiationCompleted {
              get { return SR.GetResourceString("TraceCodeServiceSecurityNegotiationCompleted", @"Service security negotiation completed."); }
        }
        internal static string TraceCodeSecuritySessionDemuxFailure {
              get { return SR.GetResourceString("TraceCodeSecuritySessionDemuxFailure", @"The incoming message is not part of an existing security session."); }
        }
        internal static string TraceCodeServiceHostCreation {
              get { return SR.GetResourceString("TraceCodeServiceHostCreation", @"Create ServiceHost."); }
        }
        internal static string TraceCodeSkipBehavior {
              get { return SR.GetResourceString("TraceCodeSkipBehavior", @"Behavior type is not of expected type"); }
        }
        internal static string TraceCodeFailedAcceptFromPool {
              get { return SR.GetResourceString("TraceCodeFailedAcceptFromPool", @"An attempt to reuse a pooled connection failed. Another attempt will be made with {0} remaining in the overall timeout."); }
        }
        internal static string TraceCodeSystemTimeResolution {
              get { return SR.GetResourceString("TraceCodeSystemTimeResolution", @"The operating system's timer resolution was detected as {0} ticks, which is about {1} milliseconds."); }
        }
        internal static string TraceCodeRequestContextAbort {
              get { return SR.GetResourceString("TraceCodeRequestContextAbort", @"RequestContext aborted"); }
        }
        internal static string TraceCodeSharedManagerServiceEndpointNotExist {
              get { return SR.GetResourceString("TraceCodeSharedManagerServiceEndpointNotExist", @"The shared memory for the endpoint of the service '{0}' does not exist. The service may not be started."); }
        }
        internal static string TraceCodeSocketConnectionAbort {
              get { return SR.GetResourceString("TraceCodeSocketConnectionAbort", @"SocketConnection aborted"); }
        }
        internal static string TraceCodeSocketConnectionAbortClose {
              get { return SR.GetResourceString("TraceCodeSocketConnectionAbortClose", @"SocketConnection aborted under Close"); }
        }
        internal static string TraceCodeSocketConnectionClose {
              get { return SR.GetResourceString("TraceCodeSocketConnectionClose", @"SocketConnection close"); }
        }
        internal static string TraceCodeSocketConnectionCreate {
              get { return SR.GetResourceString("TraceCodeSocketConnectionCreate", @"SocketConnection create"); }
        }
        internal static string TraceCodeSpnegoClientNegotiationCompleted {
              get { return SR.GetResourceString("TraceCodeSpnegoClientNegotiationCompleted", @"SpnegoTokenProvider completed SSPI negotiation."); }
        }
        internal static string TraceCodeSpnegoServiceNegotiationCompleted {
              get { return SR.GetResourceString("TraceCodeSpnegoServiceNegotiationCompleted", @"SpnegoTokenAuthenticator completed SSPI negotiation."); }
        }
        internal static string TraceCodeSpnegoClientNegotiation {
              get { return SR.GetResourceString("TraceCodeSpnegoClientNegotiation", @"Client's outgoing SSPI negotiation."); }
        }
        internal static string TraceCodeSpnegoServiceNegotiation {
              get { return SR.GetResourceString("TraceCodeSpnegoServiceNegotiation", @"Service's outgoing SSPI negotiation."); }
        }
        internal static string TraceCodeSslClientCertMissing {
              get { return SR.GetResourceString("TraceCodeSslClientCertMissing", @"The remote SSL client failed to provide a required certificate."); }
        }
        internal static string TraceCodeStreamSecurityUpgradeAccepted {
              get { return SR.GetResourceString("TraceCodeStreamSecurityUpgradeAccepted", @"The stream security upgrade was accepted successfully."); }
        }
        internal static string TraceCodeTcpChannelMessageReceiveFailed {
              get { return SR.GetResourceString("TraceCodeTcpChannelMessageReceiveFailed", @"Failed to receive a message over TCP channel"); }
        }
        internal static string TraceCodeTcpChannelMessageReceived {
              get { return SR.GetResourceString("TraceCodeTcpChannelMessageReceived", @"Received a message over TCP channel"); }
        }
        internal static string TraceCodeUnderstoodMessageHeader {
              get { return SR.GetResourceString("TraceCodeUnderstoodMessageHeader", @"Understood message header."); }
        }
        internal static string TraceCodeUnhandledAction {
              get { return SR.GetResourceString("TraceCodeUnhandledAction", @"No service available to handle this action"); }
        }
        internal static string TraceCodeUnhandledExceptionInUserOperation {
              get { return SR.GetResourceString("TraceCodeUnhandledExceptionInUserOperation", @"Unhandled exception in user operation '{0}.{1}'."); }
        }
        internal static string TraceCodeWebHostFailedToActivateService {
              get { return SR.GetResourceString("TraceCodeWebHostFailedToActivateService", @"Webhost could not activate service"); }
        }
        internal static string TraceCodeWebHostFailedToCompile {
              get { return SR.GetResourceString("TraceCodeWebHostFailedToCompile", @"Webhost couldn't compile service"); }
        }
        internal static string TraceCodeWmiPut {
              get { return SR.GetResourceString("TraceCodeWmiPut", @"Setting a value via WMI."); }
        }
        internal static string TraceCodeWsmexNonCriticalWsdlExportError {
              get { return SR.GetResourceString("TraceCodeWsmexNonCriticalWsdlExportError", @"A non-critical error or warning occurred during WSDL Export"); }
        }
        internal static string TraceCodeWsmexNonCriticalWsdlImportError {
              get { return SR.GetResourceString("TraceCodeWsmexNonCriticalWsdlImportError", @"A non-critical error or warning occurred in the MetadataExchangeClient during WSDL Import This could result in some endpoints not being imported."); }
        }
        internal static string TraceCodeFailedToOpenIncomingChannel {
              get { return SR.GetResourceString("TraceCodeFailedToOpenIncomingChannel", @"An incoming channel was disposed because there was an error while attempting to open it."); }
        }
        internal static string TraceCodeTransportListen {
              get { return SR.GetResourceString("TraceCodeTransportListen", @"Listen at '{0}'."); }
        }
        internal static string TraceCodeWsrmInvalidCreateSequence {
              get { return SR.GetResourceString("TraceCodeWsrmInvalidCreateSequence", @"An invalid create sequence message was received."); }
        }
        internal static string TraceCodeWsrmInvalidMessage {
              get { return SR.GetResourceString("TraceCodeWsrmInvalidMessage", @"An invalid WS-RM message was received."); }
        }
        internal static string TraceCodeWsrmMaxPendingChannelsReached {
              get { return SR.GetResourceString("TraceCodeWsrmMaxPendingChannelsReached", @"An incoming create sequence request was rejected because the maximum pending channel count was reached."); }
        }
        internal static string TraceCodeWsrmMessageDropped {
              get { return SR.GetResourceString("TraceCodeWsrmMessageDropped", @"A message in a WS-RM sequence has been dropped because it could not be buffered."); }
        }
        internal static string TraceCodeWsrmReceiveAcknowledgement {
              get { return SR.GetResourceString("TraceCodeWsrmReceiveAcknowledgement", @"WS-RM SequenceAcknowledgement received."); }
        }
        internal static string TraceCodeWsrmReceiveLastSequenceMessage {
              get { return SR.GetResourceString("TraceCodeWsrmReceiveLastSequenceMessage", @"WS-RM Last Sequence message received."); }
        }
        internal static string TraceCodeWsrmReceiveSequenceMessage {
              get { return SR.GetResourceString("TraceCodeWsrmReceiveSequenceMessage", @"WS-RM Sequence message received."); }
        }
        internal static string TraceCodeWsrmSendAcknowledgement {
              get { return SR.GetResourceString("TraceCodeWsrmSendAcknowledgement", @"WS-RM SequenceAcknowledgement sent."); }
        }
        internal static string TraceCodeWsrmSendLastSequenceMessage {
              get { return SR.GetResourceString("TraceCodeWsrmSendLastSequenceMessage", @"WS-RM Last Sequence message sent."); }
        }
        internal static string TraceCodeWsrmSendSequenceMessage {
              get { return SR.GetResourceString("TraceCodeWsrmSendSequenceMessage", @"WS-RM Sequence message sent."); }
        }
        internal static string TraceCodeWsrmSequenceFaulted {
              get { return SR.GetResourceString("TraceCodeWsrmSequenceFaulted", @"A WS-RM sequence has faulted."); }
        }
        internal static string TraceCodeChannelConnectionDropped {
              get { return SR.GetResourceString("TraceCodeChannelConnectionDropped", @"Channel connection was dropped"); }
        }
        internal static string TraceCodeAsyncCallbackThrewException {
              get { return SR.GetResourceString("TraceCodeAsyncCallbackThrewException", @"An async callback threw an exception!"); }
        }
        internal static string TraceCodeMetadataExchangeClientSendRequest {
              get { return SR.GetResourceString("TraceCodeMetadataExchangeClientSendRequest", @"The MetadataExchangeClient is sending a request for metadata."); }
        }
        internal static string TraceCodeMetadataExchangeClientReceiveReply {
              get { return SR.GetResourceString("TraceCodeMetadataExchangeClientReceiveReply", @"The MetadataExchangeClient received a reply."); }
        }
        internal static string TraceCodeWarnHelpPageEnabledNoBaseAddress {
              get { return SR.GetResourceString("TraceCodeWarnHelpPageEnabledNoBaseAddress", @"The ServiceDebugBehavior Help Page is enabled at a relative address and cannot be created because there is no base address."); }
        }
        internal static string TraceCodeTcpConnectError {
              get { return SR.GetResourceString("TraceCodeTcpConnectError", @"The TCP connect operation failed."); }
        }
        internal static string TraceCodeTxSourceTxScopeRequiredIsTransactedTransport {
              get { return SR.GetResourceString("TraceCodeTxSourceTxScopeRequiredIsTransactedTransport", @"The transaction '{0}' was received for operation '{1}' from a transacted transport, such as MSMQ."); }
        }
        internal static string TraceCodeTxSourceTxScopeRequiredIsTransactionFlow {
              get { return SR.GetResourceString("TraceCodeTxSourceTxScopeRequiredIsTransactionFlow", @"The transaction '{0}' was flowed to operation '{1}'."); }
        }
        internal static string TraceCodeTxSourceTxScopeRequiredIsAttachedTransaction {
              get { return SR.GetResourceString("TraceCodeTxSourceTxScopeRequiredIsAttachedTransaction", @"The transaction '{0}' was received for operation '{1}' from an InstanceContext transaction."); }
        }
        internal static string TraceCodeTxSourceTxScopeRequiredUsingExistingTransaction {
              get { return SR.GetResourceString("TraceCodeTxSourceTxScopeRequiredUsingExistingTransaction", @"Existing transaction '{0}' being used for operation '{1}'."); }
        }
        internal static string TraceCodeTxCompletionStatusCompletedForAutocomplete {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusCompletedForAutocomplete", @"The transaction '{0}' for operation '{1}' was completed due to the TransactionAutoComplete OperationBehaviorAttribute member being set to true."); }
        }
        internal static string TraceCodeTxCompletionStatusCompletedForError {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusCompletedForError", @"The transaction '{0}' for operation '{1}' was completed due to an unhandled execution exception."); }
        }
        internal static string TraceCodeTxCompletionStatusCompletedForSetComplete {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusCompletedForSetComplete", @"The transaction '{0}' for operation '{1}' was completed due to a call to SetTransactionComplete."); }
        }
        internal static string TraceCodeTxCompletionStatusCompletedForTACOSC {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusCompletedForTACOSC", @"The transaction '{0}' was completed when the session was closed due to the TransactionAutoCompleteOnSessionClose ServiceBehaviorAttribute member."); }
        }
        internal static string TraceCodeTxCompletionStatusCompletedForAsyncAbort {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusCompletedForAsyncAbort", @"The transaction '{0}' for operation '{1}' was completed due to asynchronous abort."); }
        }
        internal static string TraceCodeTxCompletionStatusRemainsAttached {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusRemainsAttached", @"The transaction '{0}' for operation '{1}' remains attached to the InstanceContext."); }
        }
        internal static string TraceCodeTxCompletionStatusAbortedOnSessionClose {
              get { return SR.GetResourceString("TraceCodeTxCompletionStatusAbortedOnSessionClose", @"The transaction '{0}' was aborted because it was uncompleted when the session was closed and the TransactionAutoCompleteOnSessionClose OperationBehaviorAttribute was set to false."); }
        }
        internal static string TraceCodeTxReleaseServiceInstanceOnCompletion {
              get { return SR.GetResourceString("TraceCodeTxReleaseServiceInstanceOnCompletion", @"The service instance was released on the completion of the transaction '{0}' because the ReleaseServiceInstanceOnTransactionComplete ServiceBehaviorAttribute was set to true."); }
        }
        internal static string TraceCodeTxAsyncAbort {
              get { return SR.GetResourceString("TraceCodeTxAsyncAbort", @"The transaction '{0}' was asynchronously aborted."); }
        }
        internal static string TraceCodeTxFailedToNegotiateOleTx {
              get { return SR.GetResourceString("TraceCodeTxFailedToNegotiateOleTx", @"The OleTransactions protocol negotiation failed for coordination context '{0}'."); }
        }
        internal static string TraceCodeTxSourceTxScopeRequiredIsCreateNewTransaction {
              get { return SR.GetResourceString("TraceCodeTxSourceTxScopeRequiredIsCreateNewTransaction", @"The transaction '{0}' for operation '{1}' was newly created."); }
        }
        internal static string TraceCodeActivatingMessageReceived {
              get { return SR.GetResourceString("TraceCodeActivatingMessageReceived", @"Activating message received."); }
        }
        internal static string TraceCodeDICPInstanceContextCached {
              get { return SR.GetResourceString("TraceCodeDICPInstanceContextCached", @"InstanceContext cached for InstanceId {0}."); }
        }
        internal static string TraceCodeDICPInstanceContextRemovedFromCache {
              get { return SR.GetResourceString("TraceCodeDICPInstanceContextRemovedFromCache", @"InstanceContext for InstanceId {0} removed from cache."); }
        }
        internal static string TraceCodeInstanceContextBoundToDurableInstance {
              get { return SR.GetResourceString("TraceCodeInstanceContextBoundToDurableInstance", @"DurableInstance's InstanceContext refcount incremented."); }
        }
        internal static string TraceCodeInstanceContextDetachedFromDurableInstance {
              get { return SR.GetResourceString("TraceCodeInstanceContextDetachedFromDurableInstance", @"DurableInstance's InstanceContext refcount decremented."); }
        }
        internal static string TraceCodeContextChannelFactoryChannelCreated {
              get { return SR.GetResourceString("TraceCodeContextChannelFactoryChannelCreated", @"ContextChannel created."); }
        }
        internal static string TraceCodeContextChannelListenerChannelAccepted {
              get { return SR.GetResourceString("TraceCodeContextChannelListenerChannelAccepted", @"A new ContextChannel was accepted."); }
        }
        internal static string TraceCodeContextProtocolContextAddedToMessage {
              get { return SR.GetResourceString("TraceCodeContextProtocolContextAddedToMessage", @"Context added to Message."); }
        }
        internal static string TraceCodeContextProtocolContextRetrievedFromMessage {
              get { return SR.GetResourceString("TraceCodeContextProtocolContextRetrievedFromMessage", @"Context retrieved from Message."); }
        }
        internal static string TraceCodeWorkflowServiceHostCreated {
              get { return SR.GetResourceString("TraceCodeWorkflowServiceHostCreated", @"WorkflowServiceHost created."); }
        }
        internal static string TraceCodeServiceDurableInstanceDeleted {
              get { return SR.GetResourceString("TraceCodeServiceDurableInstanceDeleted", @"ServiceDurableInstance '{0}' deleted from persistence store."); }
        }
        internal static string TraceCodeServiceDurableInstanceDisposed {
              get { return SR.GetResourceString("TraceCodeServiceDurableInstanceDisposed", @"ServiceDurableInstance '{0}' disposed."); }
        }
        internal static string TraceCodeServiceDurableInstanceLoaded {
              get { return SR.GetResourceString("TraceCodeServiceDurableInstanceLoaded", @"ServiceDurableInstance loaded from persistence store."); }
        }
        internal static string TraceCodeServiceDurableInstanceSaved {
              get { return SR.GetResourceString("TraceCodeServiceDurableInstanceSaved", @"ServiceDurableInstance saved to persistence store."); }
        }
        internal static string TraceCodeWorkflowDurableInstanceLoaded {
              get { return SR.GetResourceString("TraceCodeWorkflowDurableInstanceLoaded", @"WorkflowDurableInstance '{0}' loaded."); }
        }
        internal static string TraceCodeWorkflowDurableInstanceActivated {
              get { return SR.GetResourceString("TraceCodeWorkflowDurableInstanceActivated", @"WorkflowDurableInstance '{0}' activated."); }
        }
        internal static string TraceCodeWorkflowDurableInstanceAborted {
              get { return SR.GetResourceString("TraceCodeWorkflowDurableInstanceAborted", @"WorkflowDurableInstance aborted."); }
        }
        internal static string TraceCodeWorkflowOperationInvokerItemQueued {
              get { return SR.GetResourceString("TraceCodeWorkflowOperationInvokerItemQueued", @"Work item enqueued."); }
        }
        internal static string TraceCodeWorkflowRequestContextReplySent {
              get { return SR.GetResourceString("TraceCodeWorkflowRequestContextReplySent", @"Reply sent for InstanceId {0}."); }
        }
        internal static string TraceCodeWorkflowRequestContextFaultSent {
              get { return SR.GetResourceString("TraceCodeWorkflowRequestContextFaultSent", @"Fault Sent for InstanceId {0}."); }
        }
        internal static string TraceCodeSqlPersistenceProviderSQLCallStart {
              get { return SR.GetResourceString("TraceCodeSqlPersistenceProviderSQLCallStart", @"Sql execution started."); }
        }
        internal static string TraceCodeSqlPersistenceProviderSQLCallEnd {
              get { return SR.GetResourceString("TraceCodeSqlPersistenceProviderSQLCallEnd", @"Sql execution complete."); }
        }
        internal static string TraceCodeSqlPersistenceProviderOpenParameters {
              get { return SR.GetResourceString("TraceCodeSqlPersistenceProviderOpenParameters", @"SqlPersistenceProvider.Open() parameters."); }
        }
        internal static string TraceCodeSyncContextSchedulerServiceTimerCancelled {
              get { return SR.GetResourceString("TraceCodeSyncContextSchedulerServiceTimerCancelled", @"SynchronizationContextWorkflowSchedulerService - Timer {0} cancelled."); }
        }
        internal static string TraceCodeSyncContextSchedulerServiceTimerCreated {
              get { return SR.GetResourceString("TraceCodeSyncContextSchedulerServiceTimerCreated", @"SynchronizationContextWorkflowSchedulerService - Timer {0} created for InstanceId {1}."); }
        }
        internal static string TraceCodeSyndicationReadFeedBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationReadFeedBegin", @"Reading of a syndication feed started."); }
        }
        internal static string TraceCodeSyndicationReadFeedEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationReadFeedEnd", @"Reading of a syndication feed completed."); }
        }
        internal static string TraceCodeSyndicationReadItemBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationReadItemBegin", @"Reading of a syndication item started."); }
        }
        internal static string TraceCodeSyndicationReadItemEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationReadItemEnd", @"Reading of a syndication item completed."); }
        }
        internal static string TraceCodeSyndicationWriteFeedBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteFeedBegin", @"Writing of a syndication feed started."); }
        }
        internal static string TraceCodeSyndicationWriteFeedEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteFeedEnd", @"Writing of a syndication feed completed."); }
        }
        internal static string TraceCodeSyndicationWriteItemBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteItemBegin", @"Writing of a syndication item started."); }
        }
        internal static string TraceCodeSyndicationWriteItemEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteItemEnd", @"Writing of a syndication item completed."); }
        }
        internal static string TraceCodeSyndicationProtocolElementIgnoredOnWrite {
              get { return SR.GetResourceString("TraceCodeSyndicationProtocolElementIgnoredOnWrite", @"Syndication element with name '{0}' and namespace '{1}' was not written."); }
        }
        internal static string TraceCodeSyndicationProtocolElementInvalid {
              get { return SR.GetResourceString("TraceCodeSyndicationProtocolElementInvalid", @"Syndication element with name '{0}' and namespace '{1}' is invalid."); }
        }
        internal static string TraceCodeWebUnknownQueryParameterIgnored {
              get { return SR.GetResourceString("TraceCodeWebUnknownQueryParameterIgnored", @"HTTP query string parameter with name '{0}' was ignored."); }
        }
        internal static string TraceCodeWebRequestMatchesOperation {
              get { return SR.GetResourceString("TraceCodeWebRequestMatchesOperation", @"Incoming HTTP request with URI '{0}' matched operation '{1}'."); }
        }
        internal static string TraceCodeWebRequestDoesNotMatchOperations {
              get { return SR.GetResourceString("TraceCodeWebRequestDoesNotMatchOperations", @"Incoming HTTP request with URI '{0}' does not match any operation."); }
        }
        internal static string UTTMustBeAbsolute {
              get { return SR.GetResourceString("UTTMustBeAbsolute", @"Parameter 'baseAddress' must an absolute uri."); }
        }
        internal static string UTTBaseAddressMustBeAbsolute {
              get { return SR.GetResourceString("UTTBaseAddressMustBeAbsolute", @"BaseAddress must an absolute uri."); }
        }
        internal static string UTTCannotChangeBaseAddress {
              get { return SR.GetResourceString("UTTCannotChangeBaseAddress", @"Cannot change BaseAddress after calling MakeReadOnly."); }
        }
        internal static string UTTMultipleMatches {
              get { return SR.GetResourceString("UTTMultipleMatches", @"There were multiple UriTemplateMatch results, but MatchSingle was called."); }
        }
        internal static string UTTBaseAddressNotSet {
              get { return SR.GetResourceString("UTTBaseAddressNotSet", @"BaseAddress has not been set. Set the BaseAddress property before calling MakeReadOnly, Match, or MatchSingle."); }
        }
        internal static string UTTEmptyKeyValuePairs {
              get { return SR.GetResourceString("UTTEmptyKeyValuePairs", @"KeyValuePairs must have at least one element."); }
        }
        internal static string UTBindByPositionWrongCount {
              get { return SR.GetResourceString("UTBindByPositionWrongCount", @"UriTemplate '{0}' contains {1} path variables and {2} query variables but {3} values were passed to the BindByPosition method. The number of values passed to BindByPosition should be greater than or equal to the number of path variables in the template and cannot be greater than the total number of variables in the template."); }
        }
        internal static string UTBadBaseAddress {
              get { return SR.GetResourceString("UTBadBaseAddress", @"baseAddress must an absolute Uri."); }
        }
        internal static string UTQueryNamesMustBeUnique {
              get { return SR.GetResourceString("UTQueryNamesMustBeUnique", @"The UriTemplate '{0}' is not valid; each portion of the query string must be of the form 'name' or of the form 'name=value', where each name is unique. Note that the names are case-insensitive. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTQueryCannotEndInAmpersand {
              get { return SR.GetResourceString("UTQueryCannotEndInAmpersand", @"The UriTemplate '{0}' is not valid; the query string cannot end with '&amp;'. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTQueryCannotHaveEmptyName {
              get { return SR.GetResourceString("UTQueryCannotHaveEmptyName", @"The UriTemplate '{0}' is not valid; each portion of the query string must be of the form 'name' or of the form 'name=value'. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTVarNamesMustBeUnique {
              get { return SR.GetResourceString("UTVarNamesMustBeUnique", @"The UriTemplate '{0}' is not valid; the UriTemplate variable named '{1}' appears multiple times in the template. Note that UriTemplate variable names are case-insensitive. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTTAmbiguousQueries {
              get { return SR.GetResourceString("UTTAmbiguousQueries", @"UriTemplateTable does not support '{0}' and '{1}' since they are not equivalent, but cannot be disambiguated because they have equivalent paths and the same common literal values for the query string. See the documentation for UriTemplateTable for more detail."); }
        }
        internal static string UTTOtherAmbiguousQueries {
              get { return SR.GetResourceString("UTTOtherAmbiguousQueries", @"UriTemplateTable does not support multiple templates that have equivalent path as template '{0}' but have different query strings, where the query strings cannot all be disambiguated via literal values. See the documentation for UriTemplateTable for more detail."); }
        }
        internal static string UTTDuplicate {
              get { return SR.GetResourceString("UTTDuplicate", @"UriTemplateTable (with allowDuplicateEquivalentUriTemplates = false) does not support both '{0}' and '{1}', since they are equivalent. Call MakeReadOnly with allowDuplicateEquivalentUriTemplates = true to use both of these UriTemplates in the same table. See the documentation for UriTemplateTable for more detail."); }
        }
        internal static string UTInvalidFormatSegmentOrQueryPart {
              get { return SR.GetResourceString("UTInvalidFormatSegmentOrQueryPart", @"UriTemplate does not support '{0}' as a valid format for a segment or a query part."); }
        }
        internal static string BindUriTemplateToNullOrEmptyPathParam {
              get { return SR.GetResourceString("BindUriTemplateToNullOrEmptyPathParam", @"The path variable '{0}' in the UriTemplate must be bound to a non-empty string value."); }
        }
        internal static string UTBindByPositionNoVariables {
              get { return SR.GetResourceString("UTBindByPositionNoVariables", @"UriTemplate '{0}' contains no variables; yet the BindByPosition method was called with {1} values."); }
        }
        internal static string UTCSRLookupBeforeMatch {
              get { return SR.GetResourceString("UTCSRLookupBeforeMatch", @"UTCSR - Lookup was called before match"); }
        }
        internal static string UTDoesNotSupportAdjacentVarsInCompoundSegment {
              get { return SR.GetResourceString("UTDoesNotSupportAdjacentVarsInCompoundSegment", @"The UriTemplate '{0}' is not valid; UriTemplate does not support two adjacent variables with no literal in compound segments, such as in the segment '{1}'."); }
        }
        internal static string UTQueryCannotHaveCompoundValue {
              get { return SR.GetResourceString("UTQueryCannotHaveCompoundValue", @"The UriTemplate '{0}' is not valid; each portion of the query string must be of the form 'name=value', when value cannot be a compound segment. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTQueryMustHaveLiteralNames {
              get { return SR.GetResourceString("UTQueryMustHaveLiteralNames", @"The UriTemplate '{0}' is not valid; each portion of the query string must be of the form 'name' or of the form 'name=value', where name is a simple literal. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTAdditionalDefaultIsInvalid {
              get { return SR.GetResourceString("UTAdditionalDefaultIsInvalid", @"Changing an inline default value with information from the additional default values is not supported; the default value to the variable '{0}' was already provided as part of the UriTemplate '{1}'. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTDefaultValuesAreImmutable {
              get { return SR.GetResourceString("UTDefaultValuesAreImmutable", @"The default values of UriTemplate are immutable; they cannot be modified after the construction of the UriTemplate instance. See the documentation of UriTemplate for more details."); }
        }
        internal static string UTDefaultValueToCompoundSegmentVar {
              get { return SR.GetResourceString("UTDefaultValueToCompoundSegmentVar", @"The UriTemplate '{0}' is not valid; the UriTemplate compound path segment '{1}' provides a default value to variable '{2}'. Note that UriTemplate doesn't support default values to variables in compound segments. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTDefaultValueToQueryVar {
              get { return SR.GetResourceString("UTDefaultValueToQueryVar", @"The UriTemplate '{0}' is not valid; the UriTemplate variable declaration '{1}' provides a default value to query variable '{2}'. Note that UriTemplate doesn't support default values to query variables. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTInvalidDefaultPathValue {
              get { return SR.GetResourceString("UTInvalidDefaultPathValue", @"The UriTemplate '{0}' is not valid; the UriTemplate variable declaration '{1}' provides an empty default value to path variable '{2}'. Note that UriTemplate path variables cannot be bound to a null or empty value. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTInvalidVarDeclaration {
              get { return SR.GetResourceString("UTInvalidVarDeclaration", @"The UriTemplate '{0}' is not valid; the UriTemplate variable declaration '{1}' isn't a valid variable construct. Note that UriTemplate variable definitions are either a simple, non-empty, variable name or a 'name=value' format, where the name must not be empty and the value provides a default value to the variable. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTInvalidWildcardInVariableOrLiteral {
              get { return SR.GetResourceString("UTInvalidWildcardInVariableOrLiteral", @"The UriTemplate '{0}' is not valid; the wildcard ('{1}') cannot appear in a variable name or literal, unless as a construct for a wildcard segment. Note that a wildcard segment, either a literal or a variable, is valid only as the last path segment in the template; the wildcard can appear only once. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTStarVariableWithDefaults {
              get { return SR.GetResourceString("UTStarVariableWithDefaults", @"The UriTemplate '{0}' is not valid; the UriTemplate last path segment '{1}' provides a default value to final star variable '{2}'. Note that UriTemplate doesn't support default values to final star variable. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTDefaultValueToCompoundSegmentVarFromAdditionalDefaults {
              get { return SR.GetResourceString("UTDefaultValueToCompoundSegmentVarFromAdditionalDefaults", @"The UriTemplate '{0}' is not valid; the path variable '{1}', defined as part of a compound path segment has been provided with a default value as part of the additional defaults. Note that UriTemplate doesn't support default values to variables in compound segments. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTDefaultValueToQueryVarFromAdditionalDefaults {
              get { return SR.GetResourceString("UTDefaultValueToQueryVarFromAdditionalDefaults", @"The UriTemplate '{0}' is not valid; the query variable '{1}' has been provided a default value as part of the additional defaults. Note that UriTemplate doesn't support default values to query variables. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTNullableDefaultAtAdditionalDefaults {
              get { return SR.GetResourceString("UTNullableDefaultAtAdditionalDefaults", @"The UriTemplate '{0}' is not valid; the additional default value '{1}' has a null value as default value. Note that null default values must be only provided to concrete path variables. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTNullableDefaultMustBeFollowedWithNullables {
              get { return SR.GetResourceString("UTNullableDefaultMustBeFollowedWithNullables", @"The UriTemplate '{0}' is not valid; the UriTemplate path variable '{1}' has a null default value while following path variable '{2}' has no defaults or provides a non-null default value. Note that UriTemplate path variable with null default value must be followed only with other path variables with null defaulted values. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTNullableDefaultMustNotBeFollowedWithLiteral {
              get { return SR.GetResourceString("UTNullableDefaultMustNotBeFollowedWithLiteral", @"The UriTemplate '{0}' is not valid; the UriTemplate path variable '{1}' has a null default value while the following path segment '{2}' is not a variable segment with a null default value. Note that UriTemplate path variable with null default values must be followed only with other path variables with null defaulted value. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTNullableDefaultMustNotBeFollowedWithWildcard {
              get { return SR.GetResourceString("UTNullableDefaultMustNotBeFollowedWithWildcard", @"The UriTemplate '{0}' is not valid; the UriTemplate path variable '{1}' has a null default value while the template is finished with a wildcard. Note that UriTemplate path variable with null default values must be followed only with other path variables with null defaulted value. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTStarVariableWithDefaultsFromAdditionalDefaults {
              get { return SR.GetResourceString("UTStarVariableWithDefaultsFromAdditionalDefaults", @"The UriTemplate '{0}' is not valid; the UriTemplate final star variable '{1}' has been provides a default value as part of the additional defaults information. Note that UriTemplate doesn't support default values to final star variable. See the documentation for UriTemplate for more details."); }
        }
        internal static string UTTInvalidTemplateKey {
              get { return SR.GetResourceString("UTTInvalidTemplateKey", @"An invalid template '{0}' was passed as the key in a pair of template and its associated object. UriTemplateTable Key-Value pairs must always contain a valid UriTemplate object as key; note that UriTemplateTable doesn't support templates that are ignoring the trailing slash in respect to matching. See the documentation for UriTemplateTable for more details."); }
        }
        internal static string UTTNullTemplateKey {
              get { return SR.GetResourceString("UTTNullTemplateKey", @"A null UriTemplate was passed as the key in a pair of template and its associated object. UriTemplateTable Key-Value pairs must always contain a valid UriTemplate object as key. See the documentation for UriTemplateTable for more details."); }
        }
        internal static string UTBindByNameCalledWithEmptyKey {
              get { return SR.GetResourceString("UTBindByNameCalledWithEmptyKey", @"The BindByName method of UriTemplate was called with an empty name in the collection of arguments for the bind. Note that the NameValueCollection or the Dictionary passed to BindByName cannot contain an empty (or null) name as a key. See the documentation of UriTemplate for more details."); }
        }
        internal static string UTBothLiteralAndNameValueCollectionKey {
              get { return SR.GetResourceString("UTBothLiteralAndNameValueCollectionKey", @"The UriTemplate contains a literal value for query key '{0}', but that key also is present in the NameValueCollection. Either remove that key from the NameValueCollection, or else change the UriTemplate to not have a query literal for that key."); }
        }
        internal static string ExtensionNameNotSpecified {
              get { return SR.GetResourceString("ExtensionNameNotSpecified", @"The name of the extension element must be specified."); }
        }
        internal static string UnsupportedRssVersion {
              get { return SR.GetResourceString("UnsupportedRssVersion", @"The Rss20Serializer does not support RSS version '{0}'."); }
        }
        internal static string Atom10SpecRequiresTextConstruct {
              get { return SR.GetResourceString("Atom10SpecRequiresTextConstruct", @"The Atom10 specification requires '{0}' to have one of these values: \""text\"", \""html\"", \""xhtml\"", however this value is '{1}' in the document being deserialized."); }
        }
        internal static string ErrorInLine {
              get { return SR.GetResourceString("ErrorInLine", @"Error in line {0} position {1}."); }
        }
        internal static string ErrorParsingFeed {
              get { return SR.GetResourceString("ErrorParsingFeed", @"An error was encountered when parsing the feed's XML. Refer to the inner exception for more details."); }
        }
        internal static string ErrorParsingDocument {
              get { return SR.GetResourceString("ErrorParsingDocument", @"An error was encountered when parsing the document's XML. Refer to the inner exception for more details."); }
        }
        internal static string ErrorParsingItem {
              get { return SR.GetResourceString("ErrorParsingItem", @"An error was encountered when parsing the item's XML. Refer to the inner exception for more details."); }
        }
        internal static string ErrorParsingDateTime {
              get { return SR.GetResourceString("ErrorParsingDateTime", @"An error was encountered when parsing a DateTime value in the XML."); }
        }
        internal static string OuterElementNameNotSpecified {
              get { return SR.GetResourceString("OuterElementNameNotSpecified", @"The outer element name must be specified."); }
        }
        internal static string UnknownFeedXml {
              get { return SR.GetResourceString("UnknownFeedXml", @"The element with name '{0}' and namespace '{1}' is not an allowed feed format."); }
        }
        internal static string UnknownDocumentXml {
              get { return SR.GetResourceString("UnknownDocumentXml", @"The element with name '{0}' and namespace '{1}' is not an allowed document format."); }
        }
        internal static string UnknownItemXml {
              get { return SR.GetResourceString("UnknownItemXml", @"The element with name '{0}' and namespace '{1}' is not an allowed item format."); }
        }
        internal static string FeedFormatterDoesNotHaveFeed {
              get { return SR.GetResourceString("FeedFormatterDoesNotHaveFeed", @"The syndication feed formatter must be configured with a syndication feed."); }
        }
        internal static string DocumentFormatterDoesNotHaveDocument {
              get { return SR.GetResourceString("DocumentFormatterDoesNotHaveDocument", @"The document formatter must be configured with a document."); }
        }
        internal static string ItemFormatterDoesNotHaveItem {
              get { return SR.GetResourceString("ItemFormatterDoesNotHaveItem", @"The syndication item formatter must be configured with a syndication item."); }
        }
        internal static string UnbufferedItemsCannotBeCloned {
              get { return SR.GetResourceString("UnbufferedItemsCannotBeCloned", @"A feed containing items that are not buffered (i.e. the items are not stored in an IList) cannot clone its items. Buffer the items in the feed before calling Clone on it or pass false to the Clone method."); }
        }
        internal static string FeedHasNonContiguousItems {
              get { return SR.GetResourceString("FeedHasNonContiguousItems", @"The feed being deserialized has non-contiguous sets of items in it. This is not supported by '{0}'."); }
        }
        internal static string FeedCreatedNullCategory {
              get { return SR.GetResourceString("FeedCreatedNullCategory", @"The feed created a null category."); }
        }
        internal static string ItemCreatedNullCategory {
              get { return SR.GetResourceString("ItemCreatedNullCategory", @"The item created a null category."); }
        }
        internal static string FeedCreatedNullPerson {
              get { return SR.GetResourceString("FeedCreatedNullPerson", @"The feed created a null person."); }
        }
        internal static string ItemCreatedNullPerson {
              get { return SR.GetResourceString("ItemCreatedNullPerson", @"The item created a null person."); }
        }
        internal static string FeedCreatedNullItem {
              get { return SR.GetResourceString("FeedCreatedNullItem", @"=The feed created a null item."); }
        }
        internal static string TraceCodeSyndicationFeedReadBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationFeedReadBegin", @"Reading of a syndication feed started."); }
        }
        internal static string TraceCodeSyndicationFeedReadEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationFeedReadEnd", @"Reading of a syndication feed completed."); }
        }
        internal static string TraceCodeSyndicationItemReadBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationItemReadBegin", @"Reading of a syndication item started."); }
        }
        internal static string TraceCodeSyndicationItemReadEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationItemReadEnd", @"Reading of a syndication item completed."); }
        }
        internal static string TraceCodeSyndicationFeedWriteBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationFeedWriteBegin", @"Writing of a syndication feed started."); }
        }
        internal static string TraceCodeSyndicationFeedWriteEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationFeedWriteEnd", @"Writing of a syndication feed completed."); }
        }
        internal static string TraceCodeSyndicationItemWriteBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationItemWriteBegin", @"Writing of a syndication item started."); }
        }
        internal static string TraceCodeSyndicationItemWriteEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationItemWriteEnd", @"Writing of a syndication item completed."); }
        }
        internal static string TraceCodeSyndicationProtocolElementIgnoredOnRead {
              get { return SR.GetResourceString("TraceCodeSyndicationProtocolElementIgnoredOnRead", @"Syndication XML node of type '{0}' with name '{1}' and namespace '{2}' ignored on read."); }
        }
        internal static string TraceCodeSyndicationReadServiceDocumentBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationReadServiceDocumentBegin", @"Reading of a service document started."); }
        }
        internal static string TraceCodeSyndicationReadServiceDocumentEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationReadServiceDocumentEnd", @"Reading of a service document completed."); }
        }
        internal static string TraceCodeSyndicationWriteServiceDocumentBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteServiceDocumentBegin", @"Writing of a service document started."); }
        }
        internal static string TraceCodeSyndicationWriteServiceDocumentEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteServiceDocumentEnd", @"Writing of a service document completed."); }
        }
        internal static string TraceCodeSyndicationReadCategoriesDocumentBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationReadCategoriesDocumentBegin", @"Reading of a categories document started."); }
        }
        internal static string TraceCodeSyndicationReadCategoriesDocumentEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationReadCategoriesDocumentEnd", @"Reading of a categories document completed."); }
        }
        internal static string TraceCodeSyndicationWriteCategoriesDocumentBegin {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteCategoriesDocumentBegin", @"Writing of a categories document started."); }
        }
        internal static string TraceCodeSyndicationWriteCategoriesDocumentEnd {
              get { return SR.GetResourceString("TraceCodeSyndicationWriteCategoriesDocumentEnd", @"Writing of a categories document completed."); }
        }
        internal static string FeedAuthorsIgnoredOnWrite {
              get { return SR.GetResourceString("FeedAuthorsIgnoredOnWrite", @"The feed's authors were not serialized as part of serializing the feed in RSS 2.0 format."); }
        }
        internal static string FeedContributorsIgnoredOnWrite {
              get { return SR.GetResourceString("FeedContributorsIgnoredOnWrite", @"The feed's contributors were not serialized as part of serializing the feed in RSS 2.0 format."); }
        }
        internal static string FeedIdIgnoredOnWrite {
              get { return SR.GetResourceString("FeedIdIgnoredOnWrite", @"The feed's id was not serialized as part of serializing the feed in RSS 2.0 format."); }
        }
        internal static string FeedLinksIgnoredOnWrite {
              get { return SR.GetResourceString("FeedLinksIgnoredOnWrite", @"The feed's links were not serialized as part of serializing the feed in RSS 2.0 format."); }
        }
        internal static string ItemAuthorsIgnoredOnWrite {
              get { return SR.GetResourceString("ItemAuthorsIgnoredOnWrite", @"The item's authors were not serialized as part of serializing the feed in RSS 2.0 format."); }
        }
        internal static string ItemContributorsIgnoredOnWrite {
              get { return SR.GetResourceString("ItemContributorsIgnoredOnWrite", @"The item's contributors were not serialized as part of serializing the feed in RSS 2.0 format."); }
        }
        internal static string ItemLinksIgnoredOnWrite {
              get { return SR.GetResourceString("ItemLinksIgnoredOnWrite", @"The item's links were not serialized as part of serializing the feed in RSS 2.0 format."); }
        }
        internal static string ItemCopyrightIgnoredOnWrite {
              get { return SR.GetResourceString("ItemCopyrightIgnoredOnWrite", @"The item's copyrights were not serialized as part of serializing the feed in RSS 2.0 format."); }
        }
        internal static string ItemContentIgnoredOnWrite {
              get { return SR.GetResourceString("ItemContentIgnoredOnWrite", @"The item's content was not serialized as part of serializing the feed in RSS 2.0 format."); }
        }
        internal static string ItemLastUpdatedTimeIgnoredOnWrite {
              get { return SR.GetResourceString("ItemLastUpdatedTimeIgnoredOnWrite", @"The item's last updated time was not serialized as part of serializing the feed in RSS 2.0 format."); }
        }
        internal static string OuterNameOfElementExtensionEmpty {
              get { return SR.GetResourceString("OuterNameOfElementExtensionEmpty", @"The outer name of the element extension cannot be empty."); }
        }
        internal static string InvalidObjectTypePassed {
              get { return SR.GetResourceString("InvalidObjectTypePassed", @"The Type of object passed as parameter '{0}' is not derived from {1}. Ensure that the type of object passed is either of type {1} or derived from {1}."); }
        }
        internal static string UnableToImpersonateWhileSerializingReponse {
              get { return SR.GetResourceString("UnableToImpersonateWhileSerializingReponse", @"Failed to impersonate client identity during serialization of the response message."); }
        }
        internal static string XmlLineInfo {
              get { return SR.GetResourceString("XmlLineInfo", @"Line {0}, position {1}."); }
        }
        internal static string XmlFoundEndOfFile {
              get { return SR.GetResourceString("XmlFoundEndOfFile", @"end of file"); }
        }
        internal static string XmlFoundElement {
              get { return SR.GetResourceString("XmlFoundElement", @"element '{0}' from namespace '{1}'"); }
        }
        internal static string XmlFoundEndElement {
              get { return SR.GetResourceString("XmlFoundEndElement", @"end element '{0}' from namespace '{1}'"); }
        }
        internal static string XmlFoundText {
              get { return SR.GetResourceString("XmlFoundText", @"text '{0}'"); }
        }
        internal static string XmlFoundCData {
              get { return SR.GetResourceString("XmlFoundCData", @"cdata '{0}'"); }
        }
        internal static string XmlFoundComment {
              get { return SR.GetResourceString("XmlFoundComment", @"comment '{0}'"); }
        }
        internal static string XmlFoundNodeType {
              get { return SR.GetResourceString("XmlFoundNodeType", @"node {0}"); }
        }
        internal static string XmlStartElementExpected {
              get { return SR.GetResourceString("XmlStartElementExpected", @"Start element expected. Found {0}."); }
        }
        internal static string SingleWsdlNotGenerated {
              get { return SR.GetResourceString("SingleWsdlNotGenerated", @"A single WSDL document could not be generated for this service. Multiple service contract namespaces were found ({0}). Ensure that all your service contracts have the same namespace."); }
        }
        internal static string SFxDocExt_MainPageIntroSingleWsdl {
              get { return SR.GetResourceString("SFxDocExt_MainPageIntroSingleWsdl", @"You can also access the service description as a single file:"); }
        }
        internal static string TaskMethodParameterNotSupported {
              get { return SR.GetResourceString("TaskMethodParameterNotSupported", @"The use of '{0}' on the task-based asynchronous method is not supported."); }
        }
        internal static string TaskMethodMustNotHaveOutParameter {
              get { return SR.GetResourceString("TaskMethodMustNotHaveOutParameter", @"Client side task-based asynchronous method must not have any out or ref parameters. Any data that would have been returned through an out or ref parameter should instead be returned as part of the TResult in the resulting task."); }
        }
        internal static string SFxCannotImportAsParameters_OutputParameterAndTask {
              get { return SR.GetResourceString("SFxCannotImportAsParameters_OutputParameterAndTask", @"Generating message contract since the operation has multiple return values."); }
        }
        internal static string ID0020 {
              get { return SR.GetResourceString("ID0020", @"ID0020: The collection is empty."); }
        }
        internal static string ID0023 {
              get { return SR.GetResourceString("ID0023", @"ID0023: Failed to create an instance of '{0}' from configuration. A custom configuration element was specified, but the method LoadCustomConfiguration was not implemented. Override LoadCustomConfiguration to handle custom configuration loading."); }
        }
        internal static string ID2004 {
              get { return SR.GetResourceString("ID2004", @"ID2004: IAsyncResult must be the AsyncResult instance returned from the Begin call. The runtime is expecting '{0}', and the actual type is '{1}'."); }
        }
        internal static string ID3002 {
              get { return SR.GetResourceString("ID3002", @"ID3002: WSTrustServiceContract could not create a SecurityTokenService instance from WSTrustServiceContract.SecurityTokenServiceConfiguration."); }
        }
        internal static string ID3004 {
              get { return SR.GetResourceString("ID3004", @"ID3004: Cannot obtain the schema for namespace: '{0}'."); }
        }
        internal static string ID3022 {
              get { return SR.GetResourceString("ID3022", @"ID3022: The WSTrustServiceContract only supports receiving RequestSecurityToken messages. If you need to support more message types, override the WSTrustServiceContract.DispatchRequest method."); }
        }
        internal static string ID3023 {
              get { return SR.GetResourceString("ID3023", @"ID3023: The WSTrustServiceContract only supports receiving RequestSecurityToken messages asynchronously. If you need to support more message types, override the WSTrustServiceContract.BeginDispatchRequest and EndDispatchRequest."); }
        }
        internal static string ID3097 {
              get { return SR.GetResourceString("ID3097", @"ID3097: ServiceHost does not contain any valid Endpoints. Add at least one valid endpoint in the SecurityTokenServiceConfiguration.TrustEndpoints collection."); }
        }
        internal static string ID3112 {
              get { return SR.GetResourceString("ID3112", @"ID3112: Unrecognized RequestType '{0}' specified in the incoming request."); }
        }
        internal static string ID3113 {
              get { return SR.GetResourceString("ID3113", @"ID3113: The WSTrustServiceContract does not support receiving '{0}' messages with the '{1}' SOAP action. If you need to support this, override the ValidateDispatchContext method."); }
        }
        internal static string ID3114 {
              get { return SR.GetResourceString("ID3114", @"ID3114: The WSTrustServiceContract cannot deserialize the WS-Trust request."); }
        }
        internal static string ID3137 {
              get { return SR.GetResourceString("ID3137", @"ID3137: The TrustVersion '{0}', is not supported, only 'TrustVersion.WSTrust13' and 'TrustVersion.WSTrustFeb2005' is supported."); }
        }
        internal static string ID3138 {
              get { return SR.GetResourceString("ID3138", @"ID3138: The RequestSecurityTokenResponse that was received did not contain a SecurityToken."); }
        }
        internal static string ID3139 {
              get { return SR.GetResourceString("ID3139", @"ID3139: The WSTrustChannel cannot compute a proof key. The KeyType '{0}' is not supported. Valid proof key types supported by the WSTrustChannel are WSTrust13 and WSTrustFeb2005."); }
        }
        internal static string ID3140 {
              get { return SR.GetResourceString("ID3140", @"ID3140: Specify one or more BaseAddresses to enable metadata or set DisableWsdl to true in the SecurityTokenServiceConfiguration."); }
        }
        internal static string ID3141 {
              get { return SR.GetResourceString("ID3141", @"ID3141: The RequestType '{0}', is not supported. If you need to support this RequestType, override the corresponding virtual method in your SecurityTokenService derived class."); }
        }
        internal static string ID3144 {
              get { return SR.GetResourceString("ID3144", @"ID3144: The PortType '{0}' Operation '{1}' has Message '{2}' is expected to have only one part but contains '{3}'."); }
        }
        internal static string ID3146 {
              get { return SR.GetResourceString("ID3146", @"ID3146: WsdlEndpointConversionContext.WsdlPort cannot be null."); }
        }
        internal static string ID3147 {
              get { return SR.GetResourceString("ID3147", @"ID3147: WsdlEndpointConversionContext.WsdlPort.Service cannot be null."); }
        }
        internal static string ID3148 {
              get { return SR.GetResourceString("ID3148", @"ID3148: WsdlEndpointConversionContext.WsdlPort.Service.ServiceDescription cannot be null."); }
        }
        internal static string ID3149 {
              get { return SR.GetResourceString("ID3149", @"ID3149: Cannot find an input message type for PortType '({0}, {1})' for operation '{2}' in the given ServiceDescription."); }
        }
        internal static string ID3150 {
              get { return SR.GetResourceString("ID3150", @"ID3150: Cannot find an output message type for PortType '({0}, {1})' for operation '{2}' in the given ServiceDescription."); }
        }
        internal static string ID3190 {
              get { return SR.GetResourceString("ID3190", @"ID3190: The WSTrustChannel cannot compute a proof key without a valid SecurityToken set as the RequestSecurityToken.UseKey when the RequestSecurityToken.KeyType is '{0}'."); }
        }
        internal static string ID3191 {
              get { return SR.GetResourceString("ID3191", @"ID3191: The WSTrustChannel received a RequestedSecurityTokenResponse message containing an Entropy without a ComputedKeyAlgorithm."); }
        }
        internal static string ID3192 {
              get { return SR.GetResourceString("ID3192", @"ID3192: The WSTrustChannel cannot compute a proof key. The received RequestedSecurityTokenResponse does not contain a RequestedProofToken and the ComputedKeyAlgorithm specified in the response is not supported: '{0}'."); }
        }
        internal static string ID3193 {
              get { return SR.GetResourceString("ID3193", @"ID3193: The WSTrustChannel cannot compute a proof key. The received RequestedSecurityTokenResponse indicates that the proof key is computed using combined entropy. However, the response does not include an entropy."); }
        }
        internal static string ID3194 {
              get { return SR.GetResourceString("ID3194", @"ID3194: The WSTrustChannel cannot compute a proof key. The received RequestedSecurityTokenResponse indicates that the proof key is computed using combined entropy. However, the request does not include an entropy."); }
        }
        internal static string ID3269 {
              get { return SR.GetResourceString("ID3269", @"ID3269: Cannot determine the TrustVersion. It must either be specified explicitly, or a SecurityBindingElement must be present in the binding."); }
        }
        internal static string ID3270 {
              get { return SR.GetResourceString("ID3270", @"ID3270: The WSTrustChannel does not support multi-leg issuance protocols. The RSTR received from the STS must be enclosed in a RequestSecurityTokenResponseCollection element."); }
        }
        internal static string ID3285 {
              get { return SR.GetResourceString("ID3285", @"ID3285: The WS-Trust operation '{0}' is not valid or unsupported."); }
        }
        internal static string ID3286 {
              get { return SR.GetResourceString("ID3286", @"ID3286: The 'inner' parameter must implement the 'System.ServiceModel.Channels.IChannel' interface."); }
        }
        internal static string ID3287 {
              get { return SR.GetResourceString("ID3287", @"ID3287: WSTrustChannelFactory does not support changing the value of this property after a channel is created."); }
        }
        internal static string ID4008 {
              get { return SR.GetResourceString("ID4008", @"ID4008: '{0}' does not provide an implementation for '{1}'."); }
        }
        internal static string ID4039 {
              get { return SR.GetResourceString("ID4039", @"ID4039: A custom ServiceAuthorizationManager has been configured. Any custom ServiceAuthorizationManager must be derived from IdentityModelServiceAuthorizationManager."); }
        }
        internal static string ID4041 {
              get { return SR.GetResourceString("ID4041", @"ID4041: Cannot configure the ServiceHost '{0}'. The ServiceHost is in a bad state and cannot be configured."); }
        }
        internal static string ID4053 {
              get { return SR.GetResourceString("ID4053", @"ID4053: The token has WS-SecureConversation version '{0}'.  Version '{1}' was expected."); }
        }
        internal static string ID4072 {
              get { return SR.GetResourceString("ID4072", @"ID4072: The SecurityTokenHandler '{0}' registered for TokenType '{1}' must derive from '{2}'."); }
        }
        internal static string ID4101 {
              get { return SR.GetResourceString("ID4101", @"ID4101: The token cannot be validated because it is not a SamlSecurityToken or a Saml2SecurityToken. Token type: '{0}'"); }
        }
        internal static string ID4192 {
              get { return SR.GetResourceString("ID4192", @"ID4192: The reader is not positioned on a KeyInfo element that can be read."); }
        }
        internal static string ID4240 {
              get { return SR.GetResourceString("ID4240", @"ID4240: The tokenRequirement must derived from 'RecipientServiceModelSecurityTokenRequirement' for SecureConversationSecurityTokens. The tokenRequirement is of type '{0}'."); }
        }
        internal static string ID4244 {
              get { return SR.GetResourceString("ID4244", @"ID4244: Internal error: sessionAuthenticator must support IIssuanceSecurityTokenAuthenticator."); }
        }
        internal static string ID4245 {
              get { return SR.GetResourceString("ID4245", @"ID4245: Internal error: sessionAuthenticator must support ICommunicationObject."); }
        }
        internal static string ID4268 {
              get { return SR.GetResourceString("ID4268", @"ID4268: MergeClaims must have at least one identity that is not null."); }
        }
        internal static string ID4271 {
              get { return SR.GetResourceString("ID4271", @"ID4271: No IAuthorizationPolicy was found for the Transport security token '{0}'."); }
        }
        internal static string ID4274 {
              get { return SR.GetResourceString("ID4274", @"ID4274: The Configuration property of this SecurityTokenHandler is set to null. Tokens cannot be read or validated in this state. Set this property or add this SecurityTokenHandler to a SecurityTokenHandlerCollection with a valid Configuration property."); }
        }
        internal static string ID4285 {
              get { return SR.GetResourceString("ID4285", @"ID4285: Cannot replace SecurityToken with Id '{0}' in cache with new one. Token must exist in cache to be replaced."); }
        }
        internal static string ID4287 {
              get { return SR.GetResourceString("ID4287", @"ID4287: The SecurityTokenRequirement '{0}' doesn't contain a ListenUri."); }
        }
        internal static string ID5004 {
              get { return SR.GetResourceString("ID5004", @"ID5004: Unrecognized namespace: '{0}'."); }
        }
        internal static string TraceAuthorize {
              get { return SR.GetResourceString("TraceAuthorize", @"Authorize"); }
        }
        internal static string TraceOnAuthorizeRequestFailed {
              get { return SR.GetResourceString("TraceOnAuthorizeRequestFailed", @"OnAuthorizeRequest Failed."); }
        }
        internal static string TraceOnAuthorizeRequestSucceed {
              get { return SR.GetResourceString("TraceOnAuthorizeRequestSucceed", @"OnAuthorizeRequest Succeeded."); }
        }
        internal static string AuthFailed {
              get { return SR.GetResourceString("AuthFailed", @"Authentication failed."); }
        }
        internal static string DuplicateFederatedClientCredentialsParameters {
              get { return SR.GetResourceString("DuplicateFederatedClientCredentialsParameters", @"The IssuedSecurityTokenProvider cannot support the FederatedClientCredentialsParameters. The FederatedClientCredentialsParameters has already provided the '{0}' parameter."); }
        }
        internal static string UnsupportedTrustVersion {
              get { return SR.GetResourceString("UnsupportedTrustVersion", @"The TrustVersion '{0}', is not supported, only 'TrustVersion.WSTrust13' and 'TrustVersion.WSTrustFeb2005' is supported."); }
        }
        internal static string InputMustBeDelegatingHandlerElementError {
              get { return SR.GetResourceString("InputMustBeDelegatingHandlerElementError", @"The input {0} must be a '{1}' object."); }
        }
        internal static string InputTypeListEmptyError {
              get { return SR.GetResourceString("InputTypeListEmptyError", @"The input handler list cannot be empty."); }
        }
        internal static string DelegatingHandlerArrayHasNonNullInnerHandler {
              get { return SR.GetResourceString("DelegatingHandlerArrayHasNonNullInnerHandler", @"The '{0}' list is invalid because the property '{1}' of '{2}' is not null."); }
        }
        internal static string DelegatingHandlerArrayFromFuncContainsNullItem {
              get { return SR.GetResourceString("DelegatingHandlerArrayFromFuncContainsNullItem", @"The '{0}' list created by the Func '{1}' is invalid because it contains one or more null items."); }
        }
        internal static string HttpMessageHandlerFactoryConfigInvalid_WithBothTypeAndHandlerList {
              get { return SR.GetResourceString("HttpMessageHandlerFactoryConfigInvalid_WithBothTypeAndHandlerList", @"The config element '{0}' is invalid because the attribute '{1}' and the sub element '{2}' were both specified. These are mutually exclusive items and cannot be used simultaneouly."); }
        }
        internal static string HttpMessageHandlerFactoryWithFuncCannotGenerateConfig {
              get { return SR.GetResourceString("HttpMessageHandlerFactoryWithFuncCannotGenerateConfig", @"This '{0}' object cannot be used to generate configuration because it was created with the constructor that takes a '{1}' as the paramter.  This functionality is not supported through configuration files.  Please use a different constructor if you wish to generate a configuration file."); }
        }
        internal static string HttpMessageHandlerTypeNotSupported {
              get { return SR.GetResourceString("HttpMessageHandlerTypeNotSupported", @"Invalid type: '{0}'. It must inherit from base type '{1}', cannot be abstract, and must expose a public default constructor."); }
        }
        internal static string HttpMessageHandlerChannelFactoryNullPipeline {
              get { return SR.GetResourceString("HttpMessageHandlerChannelFactoryNullPipeline", @"'{0}' cannot return a null '{1}' instance. Please ensure that '{0}' returns a valid '{1}' instance."); }
        }
        internal static string HttpPipelineOperationCanceledError {
              get { return SR.GetResourceString("HttpPipelineOperationCanceledError", @"HTTP pipeline operation cancelled."); }
        }
        internal static string HttpPipelineMessagePropertyMissingError {
              get { return SR.GetResourceString("HttpPipelineMessagePropertyMissingError", @"The message property '{0}' is missing in the HttpRequestMessage. Please make sure this property not removed or changed from the properties of the HttpRequestMessage. If you are creating a new HttpRequestMessage, please copy this property from the old message to the new one."); }
        }
        internal static string HttpPipelineMessagePropertyTypeError {
              get { return SR.GetResourceString("HttpPipelineMessagePropertyTypeError", @"The message property '{0}' inside the HttpRequestMessage is not with expected type '{1}'. Please make sure this property not removed or changed from the properties of the HttpRequestMessage. If you are creating a new HttpRequestMessage, please copy this property from the old message to the new one."); }
        }
        internal static string InvalidContentTypeError {
              get { return SR.GetResourceString("InvalidContentTypeError", @"The value '{0}' is not a valid content type."); }
        }
        internal static string HttpPipelineNotSupportedOnClientSide {
              get { return SR.GetResourceString("HttpPipelineNotSupportedOnClientSide", @"The property '{0}' is not supported when building a ChannelFactory. The property value must be null when calling BuildChannelFactory."); }
        }
        internal static string CanNotLoadTypeGotFromConfig {
              get { return SR.GetResourceString("CanNotLoadTypeGotFromConfig", @"Cound not load type '{0}' from the assemblies in current AppDomain."); }
        }
        internal static string HttpPipelineNotSupportNullResponseMessage {
              get { return SR.GetResourceString("HttpPipelineNotSupportNullResponseMessage", @"The HTTP response message should not be null. Please ensure your '{0}' instance returns a non-null '{1}' object."); }
        }
        internal static string WebSocketInvalidProtocolNoHeader {
              get { return SR.GetResourceString("WebSocketInvalidProtocolNoHeader", @"The subprotocol '{0}' was not requested by the client - no '{1}' header was included in the request."); }
        }
        internal static string WebSocketInvalidProtocolNotInClientList {
              get { return SR.GetResourceString("WebSocketInvalidProtocolNotInClientList", @"The subprotocol '{0}' was not requested by the client. The client requested the following subprotocol(s): '{1}'."); }
        }
        internal static string WebSocketInvalidProtocolInvalidCharInProtocolString {
              get { return SR.GetResourceString("WebSocketInvalidProtocolInvalidCharInProtocolString", @"The subprotocol '{0}' is invalid because it contains the invalid character '{1}'."); }
        }
        internal static string WebSocketInvalidProtocolContainsMultipleSubProtocolString {
              get { return SR.GetResourceString("WebSocketInvalidProtocolContainsMultipleSubProtocolString", @"The value specified ('{0}') contains more than one subprotocol which is not supported."); }
        }
        internal static string WebSocketInvalidProtocolEmptySubprotocolString {
              get { return SR.GetResourceString("WebSocketInvalidProtocolEmptySubprotocolString", @"Empty string is not a valid subprotocol value. Please use \""null\"" to specify no value."); }
        }
        internal static string WebSocketOpaqueStreamContentNotSupportError {
              get { return SR.GetResourceString("WebSocketOpaqueStreamContentNotSupportError", @"This method is not supported for this HTTP content."); }
        }
        internal static string WebSocketElementConfigInvalidHttpMessageHandlerFactoryType {
              get { return SR.GetResourceString("WebSocketElementConfigInvalidHttpMessageHandlerFactoryType", @"Invalid value for the {0} type. The type '{1}' does not derive from the appropriate base class '{2}' or is abstract."); }
        }
        internal static string WebSocketEndpointOnlySupportWebSocketError {
              get { return SR.GetResourceString("WebSocketEndpointOnlySupportWebSocketError", @"This service only supports WebSocket connections."); }
        }
        internal static string WebSocketEndpointDoesNotSupportWebSocketError {
              get { return SR.GetResourceString("WebSocketEndpointDoesNotSupportWebSocketError", @"This service does not support WebSocket connections."); }
        }
        internal static string WebSocketUpgradeFailedError {
              get { return SR.GetResourceString("WebSocketUpgradeFailedError", @"WebSocket upgrade request failed. Received response status code '{0} ({1})', expected: '{2} ({3})'."); }
        }
        internal static string WebSocketUpgradeFailedHeaderMissingError {
              get { return SR.GetResourceString("WebSocketUpgradeFailedHeaderMissingError", @"WebSocket upgrade request failed. The header '{0}' is missing in the response."); }
        }
        internal static string WebSocketUpgradeFailedWrongHeaderError {
              get { return SR.GetResourceString("WebSocketUpgradeFailedWrongHeaderError", @"WebSocket upgrade request failed. The value of header '{0}' is '{1}'. The expected value is '{2}'."); }
        }
        internal static string WebSocketUpgradeFailedInvalidProtocolError {
              get { return SR.GetResourceString("WebSocketUpgradeFailedInvalidProtocolError", @"Unexpected response - the server accepted the upgrade request but specified the subprotocol '{0}' when no subprotocol was requested."); }
        }
        internal static string WebSocketContextWebSocketCannotBeAccessedError {
              get { return SR.GetResourceString("WebSocketContextWebSocketCannotBeAccessedError", @"WebSocket object cannot be accessed directly."); }
        }
        internal static string WebSocketTransportError {
              get { return SR.GetResourceString("WebSocketTransportError", @"A WebSocket error occurred."); }
        }
        internal static string WebSocketUnexpectedCloseMessageError {
              get { return SR.GetResourceString("WebSocketUnexpectedCloseMessageError", @"Unexpected WebSocket close message received when receiving a message."); }
        }
        internal static string WebSocketStreamWriteCalledAfterEOMSent {
              get { return SR.GetResourceString("WebSocketStreamWriteCalledAfterEOMSent", @"Cannot write to the stream because the end of the stream marker was already written."); }
        }
        internal static string WebSocketCannotCreateRequestClientChannelWithCertainWebSocketTransportUsage {
              get { return SR.GetResourceString("WebSocketCannotCreateRequestClientChannelWithCertainWebSocketTransportUsage", @"HttpChannelFactory cannot create the channel with shape '{0}' when the {1} of {2} was set as '{3}'."); }
        }
        internal static string WebSocketMaxPendingConnectionsReached {
              get { return SR.GetResourceString("WebSocketMaxPendingConnectionsReached", @"Maximum number of pending WebSocket connections ({0}) has been reached. Consider increasing the '{1}' quota on the '{2}' property of the transport."); }
        }
        internal static string WebSocketOpeningHandshakePropertiesNotAvailable {
              get { return SR.GetResourceString("WebSocketOpeningHandshakePropertiesNotAvailable", @"The opening handshake properties associated with the current WebSocket connection are not available. The most likely cause is that the property '{0}' on the '{1}' object returned from the custom '{2}' is not set."); }
        }
        internal static string AcceptWebSocketTimedOutError {
              get { return SR.GetResourceString("AcceptWebSocketTimedOutError", @"The operation to establish the WebSocket connection timed out. To increase this time limit, use the OpenTimeout property on the service endpoint's binding."); }
        }
        internal static string TaskCancelledError {
              get { return SR.GetResourceString("TaskCancelledError", @"The task was cancelled."); }
        }
        internal static string ClientWebSocketFactory_GetWebSocketVersionFailed {
              get { return SR.GetResourceString("ClientWebSocketFactory_GetWebSocketVersionFailed", @"An error occured when getting the WebSocketVersion from the WebSocket factory of type '{0}'. See the inner exception for details."); }
        }
        internal static string ClientWebSocketFactory_InvalidWebSocketVersion {
              get { return SR.GetResourceString("ClientWebSocketFactory_InvalidWebSocketVersion", @"The WebSocketVersion returned by the WebSocket factory of type '{0}' is either null, empty or invalid."); }
        }
        internal static string ClientWebSocketFactory_CreateWebSocketFailed {
              get { return SR.GetResourceString("ClientWebSocketFactory_CreateWebSocketFailed", @"An error occurred when creating the WebSocket with the factory of type '{0}'. See the inner exception for details."); }
        }
        internal static string ClientWebSocketFactory_InvalidWebSocket {
              get { return SR.GetResourceString("ClientWebSocketFactory_InvalidWebSocket", @"WebSocket creation failed. The '{0}' returned a WebSocket that is either null or not opened."); }
        }
        internal static string ClientWebSocketFactory_InvalidSubProtocol {
              get { return SR.GetResourceString("ClientWebSocketFactory_InvalidSubProtocol", @"The WebSocket returned by the factory of type '{0}' has the SubProtocol '{1}' that doesn't match the requested SubProtocol value '{2}'."); }
        }
        internal static string MultipleClientWebSocketFactoriesSpecified {
              get { return SR.GetResourceString("MultipleClientWebSocketFactoriesSpecified", @"The '{0}' contains multiple '{1}' objects, which is invalid. At most one '{1}' should be specified."); }
        }
        internal static string WebSocketSendTimedOut {
              get { return SR.GetResourceString("WebSocketSendTimedOut", @"The Send operation timed out after '{0}'. Increase the SendTimeout value on the Binding. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string WebSocketReceiveTimedOut {
              get { return SR.GetResourceString("WebSocketReceiveTimedOut", @"The Receive operation timed out after '{0}'. For duplex sessionful channels, the receive timeout is also the idle timeout for the channel, so consider setting a suitably large value for the ReceiveTimeout value on the Binding. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string WebSocketOperationTimedOut {
              get { return SR.GetResourceString("WebSocketOperationTimedOut", @"The '{0}' operation timed out after '{1}'. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string WebSocketsServerSideNotSupported {
              get { return SR.GetResourceString("WebSocketsServerSideNotSupported", @"This platform does not support server side WebSockets."); }
        }
        internal static string WebSocketsClientSideNotSupported {
              get { return SR.GetResourceString("WebSocketsClientSideNotSupported", @"This platform does not support client side WebSockets natively. Support for client side WebSockets can be enabled on this platform by providing an implementation of {0}."); }
        }
        internal static string WebSocketsNotSupportedInClassicPipeline {
              get { return SR.GetResourceString("WebSocketsNotSupportedInClassicPipeline", @"WebSockets are not supported in the classic pipeline mode. Consider using the integrated pipeline mode for the application pool."); }
        }
        internal static string WebSocketModuleNotLoaded {
              get { return SR.GetResourceString("WebSocketModuleNotLoaded", @"The WebSocketModule is not loaded. Check if the WebSocket feature is installed and the WebSocketModule is enabled in the list of IIS modules (see http://go.microsoft.com/fwlink/?LinkId=231398 for details)."); }
        }
        internal static string WebSocketTransportPolicyAssertionInvalid {
              get { return SR.GetResourceString("WebSocketTransportPolicyAssertionInvalid", @"The name of the policy being imported for contract '{0}:{1}' is invalid:'{2}'. It should be either '{3}', '{4}' or '{5}'."); }
        }
        internal static string WebSocketVersionMismatchFromServer {
              get { return SR.GetResourceString("WebSocketVersionMismatchFromServer", @"The server didn't accept the connection request. It is possible that the WebSocket protocol version on your client doesn't match the one on the server('{0}')."); }
        }
        internal static string WebSocketSubProtocolMismatchFromServer {
              get { return SR.GetResourceString("WebSocketSubProtocolMismatchFromServer", @"The server didn't accept the connection request. It is possible that the WebSocket subprotocol sent by your client is not supported by the server. Protocol(s) supported by the server are '{0}'."); }
        }
        internal static string WebSocketContentTypeMismatchFromServer {
              get { return SR.GetResourceString("WebSocketContentTypeMismatchFromServer", @"The server didn't accept the connection request. It is possible that the client side message encoding format doesn't match the setting on the server side. Please check your binding settings."); }
        }
        internal static string WebSocketContentTypeAndTransferModeMismatchFromServer {
              get { return SR.GetResourceString("WebSocketContentTypeAndTransferModeMismatchFromServer", @"The server didn't accept the connection request. It is possible that the client side message encoding format or message transfer mode doesn't match the setting on the server side. Please check your binding settings."); }
        }
        internal static string ResponseHeaderWithRequestHeadersCollection {
              get { return SR.GetResourceString("ResponseHeaderWithRequestHeadersCollection", @"This collection holds request headers and cannot contain the specified response header '{0}'."); }
        }
        internal static string RequestHeaderWithResponseHeadersCollection {
              get { return SR.GetResourceString("RequestHeaderWithResponseHeadersCollection", @"This collection holds response headers and cannot contain the specified request header '{0}'."); }
        }
        internal static string MessageVersionNoneRequiredForHttpMessageSupport {
              get { return SR.GetResourceString("MessageVersionNoneRequiredForHttpMessageSupport", @"Support for {0} and {1} can not be enabled with {2} when the {3} of the {4} is '{5}'.  Ensure the {4} used with the binding has a {3} of '{6}'. "); }
        }
        internal static string WebHeaderEnumOperationCantHappen {
              get { return SR.GetResourceString("WebHeaderEnumOperationCantHappen", @"Enumeration has either not started or has already finished."); }
        }
        internal static string WebHeaderEmptyStringCall {
              get { return SR.GetResourceString("WebHeaderEmptyStringCall", @"The parameter '{0}' cannot be an empty string."); }
        }
        internal static string WebHeaderInvalidControlChars {
              get { return SR.GetResourceString("WebHeaderInvalidControlChars", @"Specified value has invalid Control characters."); }
        }
        internal static string WebHeaderInvalidCRLFChars {
              get { return SR.GetResourceString("WebHeaderInvalidCRLFChars", @"Specified value has invalid CRLF characters."); }
        }
        internal static string WebHeaderInvalidHeaderChars {
              get { return SR.GetResourceString("WebHeaderInvalidHeaderChars", @"Specified value has invalid HTTP Header characters."); }
        }
        internal static string WebHeaderInvalidNonAsciiChars {
              get { return SR.GetResourceString("WebHeaderInvalidNonAsciiChars", @"Specified value has invalid non-ASCII characters."); }
        }
        internal static string WebHeaderArgumentOutOfRange {
              get { return SR.GetResourceString("WebHeaderArgumentOutOfRange", @"Specified argument was out of the range of valid values."); }
        }
        internal static string CopyHttpHeaderFailed {
              get { return SR.GetResourceString("CopyHttpHeaderFailed", @"Failed to copy the HTTP header '{0}' with value '{1}' to '{2}'."); }
        }
        internal static string XmlInvalidConversion {
              get { return SR.GetResourceString("XmlInvalidConversion", @"The value '{0}' cannot be parsed as the type '{1}'."); }
        }
        internal static string XmlInvalidStream {
              get { return SR.GetResourceString("XmlInvalidStream", @"Stream returned by OperationStreamProvider cannot be null."); }
        }
        internal static string LockTimeoutExceptionMessage {
              get { return SR.GetResourceString("LockTimeoutExceptionMessage", @"Cannot claim lock within the allotted timeout of {0}. The time allotted to this operation may have been a portion of a longer timeout."); }
        }
        internal static string InvalidEnumArgument {
              get { return SR.GetResourceString("InvalidEnumArgument", @"The value of argument '{0}' ({1}) is invalid for Enum type '{2}'."); }
        }
        internal static string InvalidTypedProxyMethodHandle {
              get { return SR.GetResourceString("InvalidTypedProxyMethodHandle", @"The specified method handle is incorrect for the proxy of type '{0}'"); }
        }
        internal static string FailedToCreateTypedProxy {
              get { return SR.GetResourceString("FailedToCreateTypedProxy", @"Failed to create a typed proxy for type '{0}'"); }
        }
        internal static string Arg_SystemException {
              get { return SR.GetResourceString("Arg_SystemException", @"System error."); }
        }
        internal static string SecurityTokenRequirementDoesNotContainProperty {
              get { return SR.GetResourceString("SecurityTokenRequirementDoesNotContainProperty", @"The token requirement does not contain a property '{0}'."); }
        }
        internal static string SecurityTokenRequirementHasInvalidTypeForProperty {
              get { return SR.GetResourceString("SecurityTokenRequirementHasInvalidTypeForProperty", @"The token requirement has an unexpected type '{1}' for property '{0}'. The expected property type is '{2}'."); }
        }
        internal static string TokenCancellationNotSupported {
              get { return SR.GetResourceString("TokenCancellationNotSupported", @"The token provider '{0}' does not support token cancellation."); }
        }
        internal static string TokenProviderUnableToGetToken {
              get { return SR.GetResourceString("TokenProviderUnableToGetToken", @"The token provider '{0}' was unable to provide a security token."); }
        }
        internal static string TokenProviderUnableToRenewToken {
              get { return SR.GetResourceString("TokenProviderUnableToRenewToken", @"The token provider '{0}' was unable to renew the security token."); }
        }
        internal static string TokenRenewalNotSupported {
              get { return SR.GetResourceString("TokenRenewalNotSupported", @"The token provider '{0}' does not support token renewal."); }
        }
        internal static string UserNameCannotBeEmpty {
              get { return SR.GetResourceString("UserNameCannotBeEmpty", @"The username cannot be empty."); }
        }
        internal static string ActivityBoundary {
              get { return SR.GetResourceString("ActivityBoundary", @"ActivityBoundary"); }
        }
        internal static string StringNullOrEmpty {
              get { return SR.GetResourceString("StringNullOrEmpty", @"StringNullOrEmpty"); }
        }
        internal static string GenericCallbackException {
              get { return SR.GetResourceString("GenericCallbackException", @"GenericCallbackException"); }
        }
        internal static string ArgumentCannotBeEmptyString {
              get { return SR.GetResourceString("ArgumentCannotBeEmptyString", @"The argument must be a non-empty string."); }
        }
        internal static string KeyIdentifierClauseDoesNotSupportKeyCreation {
              get { return SR.GetResourceString("KeyIdentifierClauseDoesNotSupportKeyCreation", @"This SecurityKeyIdentifierClause does not support key creation."); }
        }
        internal static string SymmetricKeyLengthTooShort {
              get { return SR.GetResourceString("SymmetricKeyLengthTooShort", @"The length of the symmetric key specified is too short ({0} bytes)."); }
        }
        internal static string KeyIdentifierCannotCreateKey {
              get { return SR.GetResourceString("KeyIdentifierCannotCreateKey", @"This SecurityKeyIdentifier does not have any clause that can create a key."); }
        }
        internal static string NoKeyIdentifierClauseFound {
              get { return SR.GetResourceString("NoKeyIdentifierClauseFound", @"No clause of type '{0}' was found in the SecurityKeyIdentifier."); }
        }
        internal static string LocalIdCannotBeEmpty {
              get { return SR.GetResourceString("LocalIdCannotBeEmpty", @"The localId cannot be empty. Specify a valid 'localId'."); }
        }
        internal static string UnableToResolveKeyReference {
              get { return SR.GetResourceString("UnableToResolveKeyReference", @"The token resolver is unable to resolve the security key reference '{0}'."); }
        }
        internal static string CannotValidateSecurityTokenType {
              get { return SR.GetResourceString("CannotValidateSecurityTokenType", @"The security token authenticator '{0}' cannot validate a token of type '{1}'."); }
        }
        internal static string UnableToResolveTokenReference {
              get { return SR.GetResourceString("UnableToResolveTokenReference", @"The token resolver is unable to resolve the token reference '{0}'."); }
        }
        internal static string UnauthorizedAccess_MemStreamBuffer {
              get { return SR.GetResourceString("UnauthorizedAccess_MemStreamBuffer", @"MemoryStream's internal buffer cannot be accessed."); }
        }
        internal static string ConfigurationFilesNotSupported {
              get { return SR.GetResourceString("ConfigurationFilesNotSupported", @"Configuration files are not supported."); }
        }
        internal static string X509ChainBuildFail {
              get { return SR.GetResourceString("X509ChainBuildFail", @"The X.509 certificate {0} chain building failed. The certificate that was used has a trust chain that cannot be verified. Replace the certificate or change the certificateValidationMode. {1}"); }
        }
        internal static string ImpersonationLevelNotSupported {
            get { return SR.GetResourceString("ImpersonationLevelNotSupported", @"The authentication modes using Kerberos do not support the impersonation level '{0}'. Specify identification or impersonation."); }
        }
#endif
        internal static Type ResourceType {
              get { return typeof(FxResources.System.Private.ServiceModel.SR); }
        }
    }
}
namespace FxResources.System.Private.ServiceModel
{
    // The type of this class is used to create the ResourceManager instance as the type name matches the name of the embedded resources file
    internal static class SR
    {
    }
}
