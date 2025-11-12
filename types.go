//go:build windows

package winhello

import (
	"bytes"
	"strings"
	"time"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"golang.org/x/sys/windows"
)

type HashAlgorithm string

const (
	HashAlgorithmSHA256 HashAlgorithm = "SHA-256"
	HashAlgorithmSHA384 HashAlgorithm = "SHA-384"
	HashAlgorithmSHA512 HashAlgorithm = "SHA-512"
)

type COSEAlgorithm int32

const (
	COSEAlgorithmEcdsaP256WithSHA256 COSEAlgorithm = -7
	COSEAlgorithmEcdsaP384WithSHA384 COSEAlgorithm = -35
	COSEAlgorithmEcdsaP521WithSHA512 COSEAlgorithm = -36

	COSEAlgorithmRSASSAPKCS1V15WithSHA256 COSEAlgorithm = -257
	COSEAlgorithmRSASSAPKCS1V15WithSHA384 COSEAlgorithm = -258
	COSEAlgorithmRSASSAPKCS1V15WithSHA512 COSEAlgorithm = -259

	COSEAlgorithmRSAPSSWithSHA256 COSEAlgorithm = -37
	COSEAlgorithmRSAPSSWithSHA384 COSEAlgorithm = -38
	COSEAlgorithmRSAPSSWithSHA512 COSEAlgorithm = -39
)

type CTAPTransport uint32

const (
	CTAPTransportUSB CTAPTransport = 1 << iota
	CTAPTransportNFC
	CTAPTransportBLE
	CTAPTransportTest
	CTAPTransportInternal
	CTAPTransportHybrid
	CTAPTransportSmartCard
	CTAPTransportFlagsMask COSEAlgorithm = 0x0000007F
)

type UserVerification uint32

const (
	UserVerificationAny UserVerification = iota
	UserVerificationOptional
	UserVerificationOptionalWithCredentialIDList
	UserVerificationRequired
)

type AuthenticatorAttachment uint32

const (
	AuthenticatorAttachmentAny AuthenticatorAttachment = iota
	AuthenticatorAttachmentPlatform
	AuthenticatorAttachmentCrossPlatform
	AuthenticatorAttachmentCrossPlatformU2FV2
)

type UserVerificationRequirement uint32

const (
	UserVerificationRequirementAny UserVerificationRequirement = iota
	UserVerificationRequirementRequired
	UserVerificationRequirementPreferred
	UserVerificationRequirementDiscouraged
)

type AttestationConveyancePreference uint32

const (
	AttestationConveyancePreferenceAny AttestationConveyancePreference = iota
	AttestationConveyancePreferenceNone
	AttestationConveyancePreferenceIndirect
	AttestationConveyancePreferenceDirect
)

type EnterpriseAttestation uint32

const (
	EnterpriseAttestationNone EnterpriseAttestation = iota
	EnterpriseAttestationVendorFacilitated
	EnterpriseAttestationPlatformManaged
)

type LargeBlobSupport uint32

const (
	LargeBlobSupportNone LargeBlobSupport = iota
	LargeBlobSupportRequired
	LargeBlobSupportPreferred
)

type CredentialLargeBlobOperation uint32

const (
	CredentialLargeBlobOperationNone CredentialLargeBlobOperation = iota
	CredentialLargeBlobOperationGet
	CredentialLargeBlobOperationSet
	CredentialLargeBlobOperationDelete
)

const AuthenticatorHMACSecretValuesFlag = 0x00100000

type AttestationDecodeType uint32

const (
	AttestationDecodeNone AttestationDecodeType = iota
	AttestationDecodeCommon
)

type CredentialLargeBlobStatus uint32

const (
	CredentialLargeBlobStatusNone CredentialLargeBlobStatus = iota
	CredentialLargeBlobStatusSuccess
	CredentialLargeBlobStatusNotSupported
	CredentialLargeBlobStatusInvalidData
	CredentialLargeBlobStatusInvalidParameter
	CredentialLargeBlobStatusNotFound
	CredentialLargeBlobStatusMultipleCredentials
	CredentialLargeBlobStatusLackOfSpace
	CredentialLargeBlobStatusPlatformError
	CredentialLargeBlobStatusAuthenticatorError
)

type AuthenticatorGetAssertionOptions struct {
	Timeout                               time.Duration
	AuthenticatorAttachment               AuthenticatorAttachment
	UserVerificationRequirement           UserVerificationRequirement
	U2FAppID                              string
	CancellationID                        *windows.GUID
	CredentialLargeBlobOperation          CredentialLargeBlobOperation
	CredentialLargeBlob                   []byte
	BrowserInPrivateMode                  bool
	AutoFill                              bool
	JsonExt                               []byte
	CredentialHints                       []webauthntypes.PublicKeyCredentialHint
	RemoteWebOrigin                       string
	PublicKeyCredentialRequestOptionsJSON []byte
	AuthenticatorID                       []byte
}

type GetAssertionResponse struct {
	*ctaptypes.AuthenticatorGetAssertionResponse
	CredLargeBlob              []byte
	CredLargeBlobStatus        CredentialLargeBlobStatus
	UsedTransport              []webauthntypes.AuthenticatorTransport
	ClientDataJSON             []byte
	AuthenticationResponseJSON []byte
	hmacSecret                 *webauthntypes.AuthenticationExtensionsPRFValues
}

func (a *_WEBAUTHN_ASSERTION) ToGetAssertionResponse() (
	*GetAssertionResponse,
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

	winHelloResp := &GetAssertionResponse{
		AuthenticatorGetAssertionResponse: resp,
	}

	if a.DwVersion >= 2 {
		winHelloResp.CredLargeBlob = bytes.Clone(unsafe.Slice(a.PbCredLargeBlob, a.CbCredLargeBlob))
		winHelloResp.CredLargeBlobStatus = CredentialLargeBlobStatus(a.DwCredLargeBlobStatus)
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
	AuthenticatorAttachment                AuthenticatorAttachment
	RequireResidentKey                     bool
	UserVerificationRequirement            UserVerificationRequirement
	AttestationConveyancePreference        AttestationConveyancePreference
	CancellationID                         *windows.GUID
	EnterpriseAttestation                  EnterpriseAttestation
	LargeBlobSupport                       LargeBlobSupport
	PreferResidentKey                      bool
	BrowserInPrivateMode                   bool
	JsonExt                                []byte
	CredentialHints                        []webauthntypes.PublicKeyCredentialHint
	ThirdPartyPayment                      bool
	RemoteWebOrigin                        string
	PublicKeyCredentialCreationOptionsJSON []byte
	AuthenticatorID                        []byte
}

type MakeCredentialResponse struct {
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

func (a *_WEBAUTHN_CREDENTIAL_ATTESTATION) ToMakeCredentialResponse() (*MakeCredentialResponse, error) {
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

	winHelloResp := &MakeCredentialResponse{
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

type MakeCredentialRequest struct {
	*ctaptypes.AuthenticatorMakeCredentialRequest
	RawRPID              []byte
	EmptyPinAuth         bool
	HMACSecretExt        int32
	PRFExt               int32
	HMACSecretSaltValues []byte
	LargeBlobKeyExt      int32
	LargeBlobSupport     uint32
	JSONExt              []byte
}

func (r *_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST) ToMakeCredentialRequest() (*MakeCredentialRequest, error) {
	// Client Data Hash
	req := &MakeCredentialRequest{
		AuthenticatorMakeCredentialRequest: &ctaptypes.AuthenticatorMakeCredentialRequest{
			ClientDataHash:        bytes.Clone(unsafe.Slice(r.PbClientDataHash, r.CbClientDataHash)),
			PinUvAuthParam:        bytes.Clone(unsafe.Slice(r.PbPinAuth, r.CbPinAuth)),
			PinUvAuthProtocol:     ctaptypes.PinUvAuthProtocol(r.DwPinProtocol),
			EnterpriseAttestation: uint(r.DwEnterpriseAttestation),
		},
		RawRPID:              bytes.Clone(unsafe.Slice(r.PbRpId, r.CbRpId)),
		EmptyPinAuth:         int32ToBool(r.FEmptyPinAuth),
		HMACSecretExt:        r.LHmacSecretExt,
		PRFExt:               r.LPrfExt,
		HMACSecretSaltValues: bytes.Clone(unsafe.Slice(r.PbHmacSecretSaltValues, r.CbHmacSecretSaltValues)),
		LargeBlobKeyExt:      r.LLargeBlobKeyExt,
		LargeBlobSupport:     r.DwLargeBlobSupport,
		JSONExt:              bytes.Clone(unsafe.Slice(r.PbJsonExt, r.CbJsonExt)),
	}

	// RP Information
	if r.PRpInformation != nil {
		req.RP = webauthntypes.PublicKeyCredentialRpEntity{
			ID:   strings.Clone(windows.UTF16PtrToString(r.PRpInformation.PwszId)),
			Name: strings.Clone(windows.UTF16PtrToString(r.PRpInformation.PwszName)),
		}
	}

	// User Information
	if r.PUserInformation != nil {
		req.User = webauthntypes.PublicKeyCredentialUserEntity{
			ID:          bytes.Clone(unsafe.Slice(r.PUserInformation.PbId, r.PUserInformation.CbId)),
			Name:        strings.Clone(windows.UTF16PtrToString(r.PUserInformation.PwszName)),
			DisplayName: strings.Clone(windows.UTF16PtrToString(r.PUserInformation.PwszDisplayName)),
			Icon:        strings.Clone(windows.UTF16PtrToString(r.PUserInformation.PwszIcon)),
		}
	}

	// Crypto Parameters
	if r.WebAuthNCredentialParameters.CCredentialParameters > 0 {
		req.PubKeyCredParams = make([]webauthntypes.PublicKeyCredentialParameters, r.WebAuthNCredentialParameters.CCredentialParameters)
		credParams := unsafe.Slice(r.WebAuthNCredentialParameters.PCredentialParameters, r.WebAuthNCredentialParameters.CCredentialParameters)

		for i := range credParams {
			req.PubKeyCredParams[i].Type = webauthntypes.PublicKeyCredentialType(strings.Clone(windows.UTF16PtrToString(credParams[i].PwszCredentialType)))
			req.PubKeyCredParams[i].Algorithm = key.Alg(credParams[i].LAlg)
		}
	}

	// Credentials used for exclusion
	if r.CredentialList.CCredentials > 0 {
		req.ExcludeList = make([]webauthntypes.PublicKeyCredentialDescriptor, r.CredentialList.CCredentials)
		for i, cred := range unsafe.Slice(r.CredentialList.PpCredentials, r.CredentialList.CCredentials) {
			req.ExcludeList[i].Type = webauthntypes.PublicKeyCredentialType(strings.Clone(windows.UTF16PtrToString(cred.PwszCredentialType)))
			req.ExcludeList[i].ID = bytes.Clone(unsafe.Slice(cred.PbId, cred.CbId))
			req.ExcludeList[i].Transports = flagsToTransports(cred.DwTransports)
		}
	}

	// Optional extensions to parse when performing the operation.
	cborExtensionMap := bytes.Clone(unsafe.Slice(r.PbCborExtensionsMap, r.CbCborExtensionsMap))
	req.Extensions = new(ctaptypes.CreateExtensionInputs)
	if err := cbor.NewDecoder(bytes.NewReader(cborExtensionMap)).Decode(&req.Extensions); err != nil {
		return nil, err
	}

	// Authenticator Options
	if r.PAuthenticatorOptions != nil {
		req.Options = make(map[ctaptypes.Option]bool)

		setOption := func(typ ctaptypes.Option, opt int32) {
			switch opt {
			case +1:
				req.Options[typ] = true
			case 0:
				// option isn't defined
			case -1:
				req.Options[typ] = false
			}
		}

		setOption(ctaptypes.OptionUserPresence, r.PAuthenticatorOptions.LUp)
		setOption(ctaptypes.OptionUserVerification, r.PAuthenticatorOptions.LUv)
		setOption(ctaptypes.OptionResidentKeys, r.PAuthenticatorOptions.LRequireResidentKey)
	}

	// Pin Auth
	req.EmptyPinAuth = int32ToBool(r.FEmptyPinAuth)
	req.PinUvAuthParam = bytes.Clone(unsafe.Slice(r.PbPinAuth, r.CbPinAuth))

	// "hmac-secret": true extension
	req.Extensions.CreateHMACSecretInput = &ctaptypes.CreateHMACSecretInput{
		HMACSecret: int32ToBool(r.LHmacSecretExt),
	}

	// "hmac-secret-mc" extension
	if r.PHmacSecretMcExtension != nil {
		req.Extensions.CreateHMACSecretMCInput = &ctaptypes.CreateHMACSecretMCInput{
			HMACSecret: ctaptypes.HMACSecret{
				SaltEnc:  bytes.Clone(unsafe.Slice(r.PHmacSecretMcExtension.PbEncryptedSalt, r.PHmacSecretMcExtension.CbEncryptedSalt)),
				SaltAuth: bytes.Clone(unsafe.Slice(r.PHmacSecretMcExtension.PbSaltAuth, r.PHmacSecretMcExtension.CbSaltAuth)),
			},
		}

		if r.PHmacSecretMcExtension.PKeyAgreement != nil {
			// It seems Windows doesn't support the Octet Key Pair key type.
			req.Extensions.CreateHMACSecretMCInput.HMACSecret.KeyAgreement = key.Key{
				iana.KeyParameterKty:    r.PHmacSecretMcExtension.PKeyAgreement.LKty,
				iana.KeyParameterAlg:    r.PHmacSecretMcExtension.PKeyAgreement.LAlg,
				iana.EC2KeyParameterCrv: r.PHmacSecretMcExtension.PKeyAgreement.LCrv,
				iana.EC2KeyParameterX:   bytes.Clone(unsafe.Slice(r.PHmacSecretMcExtension.PKeyAgreement.PbX, r.PHmacSecretMcExtension.PKeyAgreement.CbX)),
				iana.EC2KeyParameterY:   bytes.Clone(unsafe.Slice(r.PHmacSecretMcExtension.PKeyAgreement.PbY, r.PHmacSecretMcExtension.PKeyAgreement.CbY)),
			}
		}
	}

	// "credProtect" extension
	req.Extensions.CreateCredProtectInput = &ctaptypes.CreateCredProtectInput{
		CredProtect: int(r.DwCredProtect),
	}

	// "credBlob" extension
	req.Extensions.CreateCredBlobInput = &ctaptypes.CreateCredBlobInput{
		CredBlob: bytes.Clone(unsafe.Slice(r.PbCredBlobExt, r.CbCredBlobExt)),
	}

	// "minPinLength" extension
	req.Extensions.CreateMinPinLengthInput = &ctaptypes.CreateMinPinLengthInput{
		MinPinLength: int32ToBool(r.LMinPinLengthExt),
	}

	return req, nil
}

type CTAPCBORGetAssertionRequest struct {
	*ctaptypes.AuthenticatorGetAssertionRequest
	RawRPID                   []byte
	EmptyPinAuth              bool
	HMACSecretSaltValues      []byte
	LargeBlobKeyExt           int32
	CredLargeBlobOperation    uint32
	CredLargeBlobCompressed   []byte
	CredLargeBlobOriginalSize uint32
	JSONExt                   []byte
}

func (r *_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST) ToGetAssertionRequest() (*CTAPCBORGetAssertionRequest, error) {
	req := &CTAPCBORGetAssertionRequest{
		AuthenticatorGetAssertionRequest: &ctaptypes.AuthenticatorGetAssertionRequest{
			RPID:              windows.UTF16PtrToString(r.PwszRpId),
			ClientDataHash:    bytes.Clone(unsafe.Slice(r.PbClientDataHash, r.CbClientDataHash)),
			PinUvAuthParam:    bytes.Clone(unsafe.Slice(r.PbPinAuth, r.CbPinAuth)),
			PinUvAuthProtocol: ctaptypes.PinUvAuthProtocol(r.DwPinProtocol),
		},
		RawRPID:                   bytes.Clone(unsafe.Slice(r.PbRpId, r.CbRpId)),
		EmptyPinAuth:              int32ToBool(r.FEmptyPinAuth),
		HMACSecretSaltValues:      bytes.Clone(unsafe.Slice(r.PbHmacSecretSaltValues, r.CbHmacSecretSaltValues)),
		LargeBlobKeyExt:           r.LLargeBlobKeyExt,
		CredLargeBlobOperation:    r.DwCredLargeBlobOperation,
		CredLargeBlobCompressed:   bytes.Clone(unsafe.Slice(r.PbCredLargeBlobCompressed, r.CbCredLargeBlobCompressed)),
		CredLargeBlobOriginalSize: r.DwCredLargeBlobOriginalSize,
		JSONExt:                   bytes.Clone(unsafe.Slice(r.PbJsonExt, r.CbJsonExt)),
	}

	// Credentials used for inclusion
	if r.CredentialList.CCredentials > 0 {
		req.AllowList = make([]webauthntypes.PublicKeyCredentialDescriptor, r.CredentialList.CCredentials)
		for i, cred := range unsafe.Slice(r.CredentialList.PpCredentials, r.CredentialList.CCredentials) {
			req.AllowList[i].Type = webauthntypes.PublicKeyCredentialType(strings.Clone(windows.UTF16PtrToString(cred.PwszCredentialType)))
			req.AllowList[i].ID = bytes.Clone(unsafe.Slice(cred.PbId, cred.CbId))
			req.AllowList[i].Transports = flagsToTransports(cred.DwTransports)
		}
	}

	// Optional extensions to parse when performing the operation.
	cborExtensionMap := bytes.Clone(unsafe.Slice(r.PbCborExtensionsMap, r.CbCborExtensionsMap))
	req.Extensions = new(ctaptypes.GetExtensionInputs)
	if err := cbor.NewDecoder(bytes.NewReader(cborExtensionMap)).Decode(&req.Extensions); err != nil {
		return nil, err
	}

	// HMAC Salt Extension (Optional)
	if r.PHmacSaltExtension != nil {
		req.Extensions.GetHMACSecretInput = &ctaptypes.GetHMACSecretInput{
			HMACSecret: ctaptypes.HMACSecret{
				SaltEnc:  bytes.Clone(unsafe.Slice(r.PHmacSaltExtension.PbEncryptedSalt, r.PHmacSaltExtension.CbEncryptedSalt)),
				SaltAuth: bytes.Clone(unsafe.Slice(r.PHmacSaltExtension.PbSaltAuth, r.PHmacSaltExtension.CbSaltAuth)),
			},
		}

		if r.PHmacSaltExtension.PKeyAgreement != nil {
			// It seems Windows doesn't support the Octet Key Pair key type.
			req.Extensions.GetHMACSecretInput.HMACSecret.KeyAgreement = key.Key{
				iana.KeyParameterKty:    r.PHmacSaltExtension.PKeyAgreement.LKty,
				iana.KeyParameterAlg:    r.PHmacSaltExtension.PKeyAgreement.LAlg,
				iana.EC2KeyParameterCrv: r.PHmacSaltExtension.PKeyAgreement.LCrv,
				iana.EC2KeyParameterX:   bytes.Clone(unsafe.Slice(r.PHmacSaltExtension.PKeyAgreement.PbX, r.PHmacSaltExtension.PKeyAgreement.CbX)),
				iana.EC2KeyParameterY:   bytes.Clone(unsafe.Slice(r.PHmacSaltExtension.PKeyAgreement.PbY, r.PHmacSaltExtension.PKeyAgreement.CbY)),
			}
		}
	}

	// "credBlob" extension
	req.Extensions.GetCredBlobInput = &ctaptypes.GetCredBlobInput{
		CredBlob: int32ToBool(r.LCredBlobExt),
	}

	// Authenticator Options
	if r.PAuthenticatorOptions != nil {
		req.Options = make(map[ctaptypes.Option]bool)

		setOption := func(typ ctaptypes.Option, opt int32) {
			switch opt {
			case +1:
				req.Options[typ] = true
			case 0:
				// option isn't defined
			case -1:
				req.Options[typ] = false
			}
		}

		setOption(ctaptypes.OptionUserPresence, r.PAuthenticatorOptions.LUp)
		setOption(ctaptypes.OptionUserVerification, r.PAuthenticatorOptions.LUv)
		setOption(ctaptypes.OptionResidentKeys, r.PAuthenticatorOptions.LRequireResidentKey)
	}

	return req, nil
}

type CTAPCBORGetAssertionResponse struct {
	*GetAssertionResponse
	UserInformation             *webauthntypes.PublicKeyCredentialUserEntity
	NumberOfCredentials         uint
	UserSelected                int
	LargeBlobKey                []byte
	UnsignedExtensionOutputsRaw []byte
}

func flagsToTransports(flags uint32) []webauthntypes.AuthenticatorTransport {
	var tr []webauthntypes.AuthenticatorTransport

	switch {
	case flags&uint32(CTAPTransportUSB) != 0:
		tr = append(tr, webauthntypes.AuthenticatorTransportUSB)
	case flags&uint32(CTAPTransportNFC) != 0:
		tr = append(tr, webauthntypes.AuthenticatorTransportNFC)
	case flags&uint32(CTAPTransportBLE) != 0:
		tr = append(tr, webauthntypes.AuthenticatorTransportBLE)
	case flags&uint32(CTAPTransportInternal) != 0:
		tr = append(tr, webauthntypes.AuthenticatorTransportInternal)
	case flags&uint32(CTAPTransportHybrid) != 0:
	case flags&uint32(CTAPTransportSmartCard) != 0:
		tr = append(tr, webauthntypes.AuthenticatorTransportSmartCard)
		tr = append(tr, webauthntypes.AuthenticatorTransportHybrid)
	}

	return tr
}

func transportsToFlags(transports []webauthntypes.AuthenticatorTransport) uint32 {
	dwTransports := uint32(0)
	for _, tr := range transports {
		switch tr {
		case webauthntypes.AuthenticatorTransportUSB:
			dwTransports |= uint32(CTAPTransportUSB)
		case webauthntypes.AuthenticatorTransportNFC:
			dwTransports |= uint32(CTAPTransportNFC)
		case webauthntypes.AuthenticatorTransportBLE:
			dwTransports |= uint32(CTAPTransportBLE)
		case webauthntypes.AuthenticatorTransportSmartCard:
			dwTransports |= uint32(CTAPTransportSmartCard)
		case webauthntypes.AuthenticatorTransportHybrid:
			dwTransports |= uint32(CTAPTransportHybrid)
		case webauthntypes.AuthenticatorTransportInternal:
			dwTransports |= uint32(CTAPTransportInternal)
		}
	}

	return dwTransports
}
