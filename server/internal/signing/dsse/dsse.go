// Package dsse signs and verifies the Ricevanta single-signature DSSE profile.
package dsse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

type PayloadType string

const (
	TypeBundleManifest                PayloadType = "application/vnd.ricevanta.bundle-manifest+json"
	TypeAssignment                    PayloadType = "application/vnd.ricevanta.assignment+json"
	TypeRulePackManifest              PayloadType = "application/vnd.ricevanta.rulepack-manifest+json"
	TypeCommand                       PayloadType = "application/vnd.ricevanta.command+json"
	TypeCommandDispatchGrant          PayloadType = "application/vnd.ricevanta.command-dispatch-grant+json"
	TypeComplianceStatement           PayloadType = "application/vnd.ricevanta.compliance-statement+json"
	TypeIntelDelta                    PayloadType = "application/vnd.ricevanta.intel-delta+json"
	TypeRelease                       PayloadType = "application/vnd.ricevanta.release+json"
	TypeExtensionManifest             PayloadType = "application/vnd.ricevanta.extension-manifest+yaml"
	TypeExtensionIndex                PayloadType = "application/vnd.ricevanta.extension-index+json"
	TypeEscrowAck                     PayloadType = "application/vnd.ricevanta.escrow-ack+json"
	TypeEscrowRetirementAuthorization PayloadType = "application/vnd.ricevanta.escrow-retirement-authorization+json"

	MaxPayloadBytes  = 16 * 1024 * 1024
	MaxEnvelopeBytes = 24 * 1024 * 1024
	MaxSignatures    = 1
)

type Verified struct {
	PayloadType    PayloadType
	Payload        []byte
	KeyID          string
	EnvelopeSHA256 [32]byte
}

var (
	ErrEnvelopeTooLarge = errors.New("dsse envelope too large")
	ErrEnvelope         = errors.New("dsse envelope format")
	ErrSignatureCount   = errors.New("dsse signature count")
	ErrPayloadType      = errors.New("dsse unsupported payload type")
	ErrTypeMismatch     = errors.New("dsse unexpected payload type")
	ErrKeyID            = errors.New("dsse keyid format")
	ErrPayloadTooLarge  = errors.New("dsse payload too large")
	ErrBase64           = errors.New("dsse base64 format")
	ErrSignature        = errors.New("dsse invalid signature")
	ErrPublicKey        = errors.New("dsse public key length")
	ErrPrivateKey       = errors.New("dsse private key format")
)

func supported(t PayloadType) bool {
	switch t {
	case TypeBundleManifest, TypeAssignment, TypeRulePackManifest, TypeCommand, TypeCommandDispatchGrant, TypeComplianceStatement, TypeIntelDelta, TypeRelease, TypeExtensionManifest, TypeExtensionIndex, TypeEscrowAck, TypeEscrowRetirementAuthorization:
		return true
	default:
		return false
	}
}

// Sign encodes opaque payload bytes and signs their PAE with a consistent Ed25519 key.
// The fingerprint is a certificate hint; Sign does not check certificate trust.
func Sign(payloadType PayloadType, payload []byte, certificateSHA256 [32]byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if !supported(payloadType) {
		return nil, ErrPayloadType
	}
	if len(payload) > MaxPayloadBytes {
		return nil, ErrPayloadTooLarge
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrPrivateKey
	}
	if !bytes.Equal(privateKey, ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])) {
		return nil, ErrPrivateKey
	}
	signature := ed25519.Sign(privateKey, pae(payloadType, payload))
	return []byte(`{"payloadType":"` + string(payloadType) + `","payload":"` + base64.StdEncoding.EncodeToString(payload) + `","signatures":[{"keyid":"` + hex.EncodeToString(certificateSHA256[:]) + `","sig":"` + base64.StdEncoding.EncodeToString(signature) + `"}]}`), nil
}

// Verify checks caller intent and the signature under the supplied key.
// Callers must authorize that key separately. KeyID is an unauthenticated hint.
func Verify(envelope []byte, expectedType PayloadType, publicKey ed25519.PublicKey) (Verified, error) {
	p, e := parseEnvelope(envelope, expectedType)
	if e != nil {
		return Verified{}, e
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return Verified{}, ErrPublicKey
	}
	if !ed25519.Verify(publicKey, pae(p.typ, p.payload), p.signature) {
		return Verified{}, ErrSignature
	}
	return Verified{PayloadType: p.typ, Payload: p.payload, KeyID: p.keyID, EnvelopeSHA256: sha256.Sum256(envelope)}, nil
}
