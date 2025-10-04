//go:build windows

package winhello

import (
	"bytes"
	"time"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"golang.org/x/sys/windows"
)

type WinHelloHashAlgorithm string

const (
	WinHelloHashAlgorithmSHA256 WinHelloHashAlgorithm = "SHA-256"
	WinHelloHashAlgorithmSHA384 WinHelloHashAlgorithm = "SHA-384"
	WinHelloHashAlgorithmSHA512 WinHelloHashAlgorithm = "SHA-512"
)

type WinHelloCOSEAlgorithm int32

const (
	WinHelloCOSEAlgorithmEcdsaP256WithSHA256 WinHelloCOSEAlgorithm = -7
	WinHelloCOSEAlgorithmEcdsaP384WithSHA384 WinHelloCOSEAlgorithm = -35
	WinHelloCOSEAlgorithmEcdsaP521WithSHA512 WinHelloCOSEAlgorithm = -36

	WinHelloCOSEAlgorithmRSASSAPKCS1V15WithSHA256 WinHelloCOSEAlgorithm = -257
	WinHelloCOSEAlgorithmRSASSAPKCS1V15WithSHA384 WinHelloCOSEAlgorithm = -258
	WinHelloCOSEAlgorithmRSASSAPKCS1V15WithSHA512 WinHelloCOSEAlgorithm = -259

	WinHelloCOSEAlgorithmRSAPSSWithSHA256 WinHelloCOSEAlgorithm = -37
	WinHelloCOSEAlgorithmRSAPSSWithSHA384 WinHelloCOSEAlgorithm = -38
	WinHelloCOSEAlgorithmRSAPSSWithSHA512 WinHelloCOSEAlgorithm = -39
)

type WinHelloCTAPTransport uint32

const (
	WinHelloCTAPTransportUSB WinHelloCTAPTransport = 1 << iota
	WinHelloCTAPTransportNFC
	WinHelloCTAPTransportBLE
	WinHelloCTAPTransportTest
	WinHelloCTAPTransportInternal
	WinHelloCTAPTransportHybrid
	WinHelloCTAPTransportSmartCard
	WinHelloCTAPTransportFlagsMask WinHelloCOSEAlgorithm = 0x0000007F
)

type WinHelloUserVerification uint32

const (
	WinHelloUserVerificationAny WinHelloUserVerification = iota
	WinHelloUserVerificationOptional
	WinHelloUserVerificationOptionalWithCredentialIDList
	WinHelloUserVerificationRequired
)

type WinHelloAuthenticatorAttachment uint32

const (
	WinHelloAuthenticatorAttachmentAny WinHelloAuthenticatorAttachment = iota
	WinHelloAuthenticatorAttachmentPlatform
	WinHelloAuthenticatorAttachmentCrossPlatform
	WinHelloAuthenticatorAttachmentCrossPlatformU2FV2
)

type WinHelloUserVerificationRequirement uint32

const (
	WinHelloUserVerificationRequirementAny WinHelloUserVerificationRequirement = iota
	WinHelloUserVerificationRequirementRequired
	WinHelloUserVerificationRequirementPreferred
	WinHelloUserVerificationRequirementDiscouraged
)

type WinHelloAttestationConveyancePreference uint32

const (
	WinHelloAttestationConveyancePreferenceAny WinHelloAttestationConveyancePreference = iota
	WinHelloAttestationConveyancePreferenceNone
	WinHelloAttestationConveyancePreferenceIndirect
	WinHelloAttestationConveyancePreferenceDirect
)

type WinHelloEnterpriseAttestation uint32

const (
	WinHelloEnterpriseAttestationNone WinHelloEnterpriseAttestation = iota
	WinHelloEnterpriseAttestationVendorFacilitated
	WinHelloEnterpriseAttestationPlatformManaged
)

type WinHelloLargeBlobSupport uint32

const (
	WinHelloLargeBlobSupportNone WinHelloLargeBlobSupport = iota
	WinHelloLargeBlobSupportRequired
	WinHelloLargeBlobSupportPreferred
)

type WinHelloCredentialLargeBlobOperation uint32

const (
	WinHelloCredentialLargeBlobOperationNone WinHelloCredentialLargeBlobOperation = iota
	WinHelloCredentialLargeBlobOperationGet
	WinHelloCredentialLargeBlobOperationSet
	WinHelloCredentialLargeBlobOperationDelete
)

const WinHelloAuthenticatorHMACSecretValuesFlag = 0x00100000

type WinHelloAttestationDecodeType uint32

const (
	WinHelloAttestationDecodeNone WinHelloAttestationDecodeType = iota
	WinHelloAttestationDecodeCommon
)

type WinHelloCredentialLargeBlobStatus uint32

const (
	WinHelloCredentialLargeBlobStatusNone WinHelloCredentialLargeBlobStatus = iota
	WinHelloCredentialLargeBlobStatusSuccess
	WinHelloCredentialLargeBlobStatusNotSupported
	WinHelloCredentialLargeBlobStatusInvalidData
	WinHelloCredentialLargeBlobStatusInvalidParameter
	WinHelloCredentialLargeBlobStatusNotFound
	WinHelloCredentialLargeBlobStatusMultipleCredentials
	WinHelloCredentialLargeBlobStatusLackOfSpace
	WinHelloCredentialLargeBlobStatusPlatformError
	WinHelloCredentialLargeBlobStatusAuthenticatorError
)

type AuthenticatorGetAssertionOptions struct {
	Timeout                               time.Duration
	AuthenticatorAttachment               WinHelloAuthenticatorAttachment
	UserVerificationRequirement           WinHelloUserVerificationRequirement
	U2FAppID                              string
	CancellationID                        *windows.GUID
	CredentialLargeBlobOperation          WinHelloCredentialLargeBlobOperation
	CredentialLargeBlob                   []byte
	BrowserInPrivateMode                  bool
	AutoFill                              bool
	JsonExt                               []byte
	CredentialHints                       []webauthntypes.PublicKeyCredentialHint
	RemoteWebOrigin                       string
	PublicKeyCredentialRequestOptionsJSON []byte
	AuthenticatorID                       []byte
}

type WinHelloGetAssertionResponse struct {
	*ctaptypes.AuthenticatorGetAssertionResponse
	CredLargeBlob              []byte
	CredLargeBlobStatus        WinHelloCredentialLargeBlobStatus
	UsedTransport              []webauthntypes.AuthenticatorTransport
	ClientDataJSON             []byte
	AuthenticationResponseJSON []byte
	hmacSecret                 *webauthntypes.AuthenticationExtensionsPRFValues
}

func (a *_WEBAUTHN_ASSERTION) ToGetAssertionResponse() (
	*WinHelloGetAssertionResponse,
	error,
) {
	authDataRaw := bytes.Clone(unsafe.Slice(a.PbAuthenticatorData, a.CbAuthenticatorData))
	authData, err := ctaptypes.ParseGetAssertionAuthData(authDataRaw)
	if err != nil {
		return nil, err
	}

	resp := &ctaptypes.AuthenticatorGetAssertionResponse{
		Credential: webauthntypes.PublicKeyCredentialDescriptor{
			Type: webauthntypes.PublicKeyCredentialType(windows.UTF16PtrToString(a.Credential.PwszCredentialType)),
			ID:   bytes.Clone(unsafe.Slice(a.Credential.PbId, a.Credential.CbId)),
		},
		AuthData:    authData,
		AuthDataRaw: authDataRaw,
		Signature:   bytes.Clone(unsafe.Slice(a.PbSignature, a.CbSignature)),
	}

	userID := bytes.Clone(unsafe.Slice(a.PbUserId, a.CbUserId))
	if userID != nil && len(userID) > 0 {
		resp.User = &webauthntypes.PublicKeyCredentialUserEntity{
			ID: userID,
		}
	}

	winHelloResp := &WinHelloGetAssertionResponse{
		AuthenticatorGetAssertionResponse: resp,
	}

	if a.DwVersion >= 2 {
		winHelloResp.CredLargeBlob = bytes.Clone(unsafe.Slice(a.PbCredLargeBlob, a.CbCredLargeBlob))
		winHelloResp.CredLargeBlobStatus = WinHelloCredentialLargeBlobStatus(a.DwCredLargeBlobStatus)
	}

	if a.DwVersion >= 3 && a.PHmacSecret != nil {
		winHelloResp.hmacSecret = &webauthntypes.AuthenticationExtensionsPRFValues{
			First:  bytes.Clone(unsafe.Slice(a.PHmacSecret.PbFirst, a.PHmacSecret.CbFirst)),
			Second: bytes.Clone(unsafe.Slice(a.PHmacSecret.PbSecond, a.PHmacSecret.CbSecond)),
		}
	}

	if a.DwVersion >= 4 {
		winHelloResp.UsedTransport = flagsToTransports(a.DwUsedTransport)
	}

	if a.DwVersion >= 5 {
		unsignedExtensionOutputsRaw := bytes.Clone(unsafe.Slice(a.PbUnsignedExtensionOutputs, a.CbUnsignedExtensionOutputs))
		if unsignedExtensionOutputsRaw != nil && len(unsignedExtensionOutputsRaw) > 0 {
			if err := cbor.Unmarshal(unsignedExtensionOutputsRaw, &resp.UnsignedExtensionOutputs); err != nil {
				return nil, err
			}
		}
	}

	if a.DwVersion >= 6 {
		clientDataJSONRaw := bytes.Clone(unsafe.Slice(a.PbClientDataJSON, a.CbClientDataJSON))
		if clientDataJSONRaw != nil && len(clientDataJSONRaw) > 0 {
			winHelloResp.ClientDataJSON = clientDataJSONRaw
		}
		authenticationResponseJSONRaw := bytes.Clone(unsafe.Slice(a.PbAuthenticationResponseJSON, a.CbAuthenticationResponseJSON))
		if authenticationResponseJSONRaw != nil && len(authenticationResponseJSONRaw) > 0 {
			winHelloResp.AuthenticationResponseJSON = authenticationResponseJSONRaw
		}
	}

	return winHelloResp, nil
}

type AuthenticatorMakeCredentialOptions struct {
	Timeout                                time.Duration
	AuthenticatorAttachment                WinHelloAuthenticatorAttachment
	RequireResidentKey                     bool
	UserVerificationRequirement            WinHelloUserVerificationRequirement
	AttestationConveyancePreference        WinHelloAttestationConveyancePreference
	CancellationID                         *windows.GUID
	EnterpriseAttestation                  WinHelloEnterpriseAttestation
	LargeBlobSupport                       WinHelloLargeBlobSupport
	PreferResidentKey                      bool
	BrowserInPrivateMode                   bool
	JsonExt                                []byte
	CredentialHints                        []webauthntypes.PublicKeyCredentialHint
	ThirdPartyPayment                      bool
	RemoteWebOrigin                        string
	PublicKeyCredentialCreationOptionsJSON []byte
	AuthenticatorID                        []byte
}

type WinHelloMakeCredentialResponse struct {
	*ctaptypes.AuthenticatorMakeCredentialResponse
	CredentialID             []byte
	UsedTransport            []webauthntypes.AuthenticatorTransport
	LargeBlobSupported       bool
	ResidentKey              bool
	PRFEnabled               bool
	HMACSecret               *webauthntypes.AuthenticationExtensionsPRFValues
	ThirdPartyPayment        bool
	Transports               []webauthntypes.AuthenticatorTransport
	ClientDataJSON           []byte
	RegistrationResponseJSON []byte
}

func (a *_WEBAUTHN_CREDENTIAL_ATTESTATION) ToMakeCredentialResponse() (*WinHelloMakeCredentialResponse, error) {
	authDataRaw := bytes.Clone(unsafe.Slice(a.PbAuthenticatorData, a.CbAuthenticatorData))
	authData, err := ctaptypes.ParseMakeCredentialAuthData(authDataRaw)
	if err != nil {
		return nil, err
	}

	resp := &ctaptypes.AuthenticatorMakeCredentialResponse{
		Format:      webauthntypes.AttestationStatementFormatIdentifier(windows.UTF16PtrToString(a.PwszFormatType)),
		AuthData:    authData,
		AuthDataRaw: authDataRaw,
	}

	attestationRaw := bytes.Clone(unsafe.Slice(a.PbAttestation, a.CbAttestation))
	if resp.Format != webauthntypes.AttestationStatementFormatIdentifierNone &&
		attestationRaw != nil &&
		len(attestationRaw) > 0 {
		if err := cbor.Unmarshal(attestationRaw, &resp.AttestationStatement); err != nil {
			return nil, err
		}
	}

	winHelloResp := &WinHelloMakeCredentialResponse{
		AuthenticatorMakeCredentialResponse: resp,
		CredentialID:                        bytes.Clone(unsafe.Slice(a.PbCredentialId, a.CbCredentialId)),
	}

	if a.DwVersion >= 3 {
		winHelloResp.UsedTransport = flagsToTransports(a.DwUsedTransport)
	}

	if a.DwVersion >= 4 {
		winHelloResp.EnterpriseAttestation = int32ToBool(a.BEpAtt)
		winHelloResp.LargeBlobSupported = int32ToBool(a.BLargeBlobSupported)
		winHelloResp.ResidentKey = int32ToBool(a.BResidentKey)
	}

	if a.DwVersion >= 5 {
		winHelloResp.PRFEnabled = int32ToBool(a.BPrfEnabled)
	}

	if a.DwVersion >= 6 {
		unsignedExtensionOutputsRaw := bytes.Clone(unsafe.Slice(a.PbUnsignedExtensionOutputs, a.CbUnsignedExtensionOutputs))
		if unsignedExtensionOutputsRaw != nil && len(unsignedExtensionOutputsRaw) > 0 {
			if err := cbor.Unmarshal(unsignedExtensionOutputsRaw, &resp.UnsignedExtensionOutputs); err != nil {
				return nil, err
			}
		}
	}

	if a.DwVersion >= 7 && a.PHmacSecret != nil {
		winHelloResp.HMACSecret = &webauthntypes.AuthenticationExtensionsPRFValues{
			First:  bytes.Clone(unsafe.Slice(a.PHmacSecret.PbFirst, a.PHmacSecret.CbFirst)),
			Second: bytes.Clone(unsafe.Slice(a.PHmacSecret.PbSecond, a.PHmacSecret.CbSecond)),
		}
		winHelloResp.ThirdPartyPayment = int32ToBool(a.BThirdPartyPayment)
	}

	if a.DwVersion >= 8 {
		winHelloResp.Transports = flagsToTransports(a.DwTransports)
		clientDataJSONRaw := bytes.Clone(unsafe.Slice(a.PbClientDataJSON, a.CbClientDataJSON))
		if clientDataJSONRaw != nil && len(clientDataJSONRaw) > 0 {
			winHelloResp.ClientDataJSON = clientDataJSONRaw
		}
		registrationResponseJSONRaw := bytes.Clone(unsafe.Slice(a.PbRegistrationResponseJSON, a.CbRegistrationResponseJSON))
		if registrationResponseJSONRaw != nil && len(registrationResponseJSONRaw) > 0 {
			winHelloResp.RegistrationResponseJSON = registrationResponseJSONRaw
		}
	}

	return winHelloResp, nil
}

func flagsToTransports(flags uint32) []webauthntypes.AuthenticatorTransport {
	var tr []webauthntypes.AuthenticatorTransport

	switch {
	case flags&uint32(WinHelloCTAPTransportUSB) != 0:
		tr = append(tr, webauthntypes.AuthenticatorTransportUSB)
	case flags&uint32(WinHelloCTAPTransportNFC) != 0:
		tr = append(tr, webauthntypes.AuthenticatorTransportNFC)
	case flags&uint32(WinHelloCTAPTransportBLE) != 0:
		tr = append(tr, webauthntypes.AuthenticatorTransportBLE)
	case flags&uint32(WinHelloCTAPTransportInternal) != 0:
		tr = append(tr, webauthntypes.AuthenticatorTransportInternal)
	case flags&uint32(WinHelloCTAPTransportHybrid) != 0:
	case flags&uint32(WinHelloCTAPTransportSmartCard) != 0:
		tr = append(tr, webauthntypes.AuthenticatorTransportSmartCard)
		tr = append(tr, webauthntypes.AuthenticatorTransportHybrid)
	}

	return tr
}
