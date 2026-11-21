// Package legacyv3 reads what @vaultys/id 3.x wallets left behind: the
// identity of a store that only kept its 32-byte entropy, the version 0
// relationship certificates of 3.x handshakes, and DHIES v1 messages.
//
// It mirrors typescript/src/legacyV3.ts and dhiesV1Legacy.ts (the reference)
// and is tested against wallets written by the published 3.0.4
// (testdata/legacy-v3-vectors.json).
//
// A v0 certificate is signed as SHA-256("VAULTYS_SIGN" || v0 encoding), the
// same domain as SignChallenge, and the v0 encoding leaves the metadata out:
// anyone who obtains a SignChallenge signature over chosen bytes can assemble
// one. VerifyV0Certificate therefore says that a certificate is well formed
// and signed by both parties, never that it should be trusted: only the v0
// certificates already held by a 3.x store when it is migrated may be (their
// hashes are recorded then, see CertificateHash), as TypeScript does.
package legacyv3

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
)

// Hint is the identity type and algorithm a 3.x store was created with.
type Hint struct {
	Type vaultysid.IdentityType
	Alg  string // "ed25519", "dilithium_ed25519" or "dilithium"
}

// ReopenDefault is what IdManager.fromStore in 3.x made of a store holding
// only entropy: a machine ed25519 identity, whatever it was created as.
var ReopenDefault = Hint{Type: vaultysid.TypeMachine, Alg: "ed25519"}

var (
	// ErrNoCertificate: the certificates cannot tell the type and algorithm,
	// and neither a hint nor a fallback was given.
	ErrNoCertificate = errors.New("3.x store without certificates: pass the identity type and algorithm it was created with")
	// ErrHintMismatch: the hint contradicts the store's certificates.
	ErrHintMismatch = errors.New("the type/algorithm hint does not match the identity found in the store's certificates")
	// ErrFIDO2Wallet: a 3.x FIDO2 wallet, whose store does not hold the
	// credential id of the security key.
	ErrFIDO2Wallet = errors.New("3.x FIDO2 wallet: the store does not hold the credential id of the security key, so it cannot be reopened from the store alone")
	// ErrNotFound: no identity derived from this entropy is in the certificates.
	ErrNotFound = errors.New("no identity type/algorithm derived from this entropy appears in the store's certificates")
)

var signIncipit = []byte("VAULTYS_SIGN")

// V0Certificate is a COMPLETE version 0 relationship certificate.
type V0Certificate struct {
	Protocol  string
	Service   string
	Timestamp int64
	Pk1       []byte
	Pk2       []byte
	Nonce     []byte
	Sign1     []byte
	Sign2     []byte
}

type v0Wire struct {
	Version   *int   `msgpack:"version"`
	Protocol  string `msgpack:"protocol"`
	Service   string `msgpack:"service"`
	Timestamp int64  `msgpack:"timestamp"`
	Pk1       []byte `msgpack:"pk1"`
	Pk2       []byte `msgpack:"pk2"`
	Nonce     []byte `msgpack:"nonce"`
	Sign1     []byte `msgpack:"sign1"`
	Sign2     []byte `msgpack:"sign2"`
}

// DecodeV0Certificate decodes a complete v0 certificate. It does not check
// the signatures.
func DecodeV0Certificate(certificate []byte) (*V0Certificate, error) {
	var w v0Wire
	if err := msgpack.Unmarshal(certificate, &w); err != nil {
		return nil, fmt.Errorf("not a v0 certificate: %w", err)
	}
	if w.Version != nil && *w.Version != 0 {
		return nil, fmt.Errorf("not a v0 certificate: version %d", *w.Version)
	}
	if w.Protocol == "" || w.Service == "" || len(w.Pk1) == 0 || len(w.Pk2) == 0 || len(w.Nonce) != 32 || len(w.Sign1) == 0 || len(w.Sign2) == 0 {
		return nil, errors.New("not a complete v0 certificate")
	}
	return &V0Certificate{Protocol: w.Protocol, Service: w.Service, Timestamp: w.Timestamp, Pk1: w.Pk1, Pk2: w.Pk2, Nonce: w.Nonce, Sign1: w.Sign1, Sign2: w.Sign2}, nil
}

// The 3.x hand-rolled v0 encoder, byte for byte (its fixstr headers wrap
// above 31 bytes and its 64-bit integers use the int64 marker, as in 3.x).

func writeName(b *bytes.Buffer, name string) {
	b.WriteByte(byte(0xa0 + len(name)))
	b.WriteString(name)
}

func writeString(b *bytes.Buffer, name, value string) {
	writeName(b, name)
	b.WriteByte(byte(0xa0 + len(value)))
	b.WriteString(value)
}

func writeBuffer(b *bytes.Buffer, name string, value []byte) {
	writeName(b, name)
	if len(value) <= 65535 {
		b.Write([]byte{0xc5, byte(len(value) >> 8), byte(len(value))})
	} else {
		b.Write([]byte{0xc6, byte(len(value) >> 24), byte(len(value) >> 16), byte(len(value) >> 8), byte(len(value))})
	}
	b.Write(value)
}

func writeInt(b *bytes.Buffer, name string, v int64) {
	writeName(b, name)
	switch {
	case v >= 0 && v <= 0x7f:
		b.WriteByte(byte(v))
	case v < 0 && v >= -0x20:
		b.WriteByte(byte(v))
	case v > 0 && v <= 0xff:
		b.Write([]byte{0xcc, byte(v)})
	case v >= -0x80 && v <= 0x7f:
		b.Write([]byte{0xd0, byte(v)})
	case v > 0 && v <= 0xffff:
		b.Write([]byte{0xcd, byte(v >> 8), byte(v)})
	case v >= -0x8000 && v <= 0x7fff:
		b.Write([]byte{0xd1, byte(v >> 8), byte(v)})
	case v > 0 && v <= 0xffffffff:
		b.Write([]byte{0xce, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	case v >= -0x80000000 && v <= 0x7fffffff:
		b.Write([]byte{0xd2, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	case v > 0:
		var out [9]byte
		out[0] = 0xd3
		binary.BigEndian.PutUint64(out[1:], uint64(v))
		b.Write(out[:])
	default:
		b.WriteByte(0x00)
	}
}

// EncodeUnsignedV0 is the byte string both parties signed.
func EncodeUnsignedV0(c *V0Certificate) []byte {
	var b bytes.Buffer
	b.WriteByte(0x87)
	writeString(&b, "protocol", c.Protocol)
	writeString(&b, "service", c.Service)
	writeInt(&b, "timestamp", c.Timestamp)
	writeBuffer(&b, "pk1", c.Pk1)
	writeBuffer(&b, "pk2", c.Pk2)
	writeBuffer(&b, "nonce", c.Nonce)
	writeName(&b, "metadata")
	b.WriteByte(0x80)
	return b.Bytes()
}

func verifyV0Signature(id *vaultysid.VaultysID, rawID, unsigned, signature []byte) bool {
	// 3.x signed through signChallenge; 2.x through SHA-256(id || challenge)
	if id.VerifyChallenge(unsigned, signature) == nil {
		return true
	}
	h := sha256.New()
	h.Write(rawID)
	h.Write(unsigned)
	return id.KeyManager.Verify(h.Sum(nil), signature) == nil
}

// VerifyV0Certificate checks both signatures of a complete v0 certificate
// with the 3.x rules (both ids serialized at version 0). It does NOT make the
// certificate trustworthy: see the package documentation.
func VerifyV0Certificate(certificate []byte) bool {
	c, err := DecodeV0Certificate(certificate)
	if err != nil {
		return false
	}
	id1, err1 := vaultysid.FromID(c.Pk1, nil)
	id2, err2 := vaultysid.FromID(c.Pk2, nil)
	if err1 != nil || err2 != nil || id1.GetVersion() != 0 || id2.GetVersion() != 0 {
		return false
	}
	unsigned := EncodeUnsignedV0(c)
	return verifyV0Signature(id2, c.Pk2, unsigned, c.Sign2) && verifyV0Signature(id1, c.Pk1, unsigned, c.Sign1)
}

// CertificateHash is the hex SHA-256 under which a migrated store records a
// trusted v0 certificate.
func CertificateHash(certificate []byte) string {
	h := sha256.Sum256(certificate)
	return hex.EncodeToString(h[:])
}

func sameIdentity(me *vaultysid.VaultysID, rawID []byte) bool {
	other, err := vaultysid.FromID(rawID, nil)
	if err != nil {
		return false
	}
	return me.Type == other.Type && bytes.Equal(me.KeyManager.GetPublicKey(), other.KeyManager.GetPublicKey())
}

// Involves tells whether me is one of the two parties of a v0 certificate.
func Involves(me *vaultysid.VaultysID, certificate []byte) bool {
	c, err := DecodeV0Certificate(certificate)
	return err == nil && (sameIdentity(me, c.Pk1) || sameIdentity(me, c.Pk2))
}

// A 3.x FIDO2 wallet stores only entropy too: its X25519 key comes from it
// (secret = SHA-512(entropy)[0:32]) but the credential id does not.
func isOwnFIDO2Party(entropy, rawID []byte) bool {
	id, err := vaultysid.FromID(rawID, nil)
	if err != nil || !id.IsHardware() {
		return false
	}
	seed := sha512.Sum512(entropy)
	pub, err := curve25519.X25519(seed[:32], curve25519.Basepoint)
	return err == nil && bytes.Equal(pub, id.KeyManager.GetCypherPublicKey())
}

var candidateAlgs = []string{"ed25519", "dilithium_ed25519", "dilithium"}
var candidateTypes = []vaultysid.IdentityType{vaultysid.TypePerson, vaultysid.TypeMachine, vaultysid.TypeOrganization}

// RecoverIdentity rebuilds the identity of a 3.x store from its entropy and
// the certificates it holds (contacts, registrations, web of trust).
//
// The type and algorithm are found by matching the candidates against the
// certificates. With no certificate to match, hint is used if given
// (guessed = false: the caller vouches for it), else fallback (guessed =
// true: keep the entropy until the identity is confirmed), else
// ErrNoCertificate. A hint that contradicts the certificates is refused, and
// so is a FIDO2 wallet.
func RecoverIdentity(entropy []byte, certificates [][]byte, hint, fallback *Hint) (id *vaultysid.VaultysID, guessed bool, err error) {
	if len(entropy) != 32 {
		return nil, false, errors.New("not a 3.x store: no 32-byte entropy")
	}
	var v0 [][]byte
	for _, c := range certificates {
		if _, err := DecodeV0Certificate(c); err == nil {
			v0 = append(v0, c)
		}
	}
	matches := func(id *vaultysid.VaultysID) bool {
		for _, c := range v0 {
			if Involves(id, c) {
				return true
			}
		}
		return false
	}
	if hint != nil {
		id, err := vaultysid.FromEntropyAlg(entropy, hint.Type, hint.Alg)
		if err != nil {
			return nil, false, err
		}
		if len(v0) > 0 && !matches(id) {
			return nil, false, ErrHintMismatch
		}
		return id, false, nil
	}
	if len(v0) == 0 {
		if fallback == nil {
			return nil, false, ErrNoCertificate
		}
		id, err := vaultysid.FromEntropyAlg(entropy, fallback.Type, fallback.Alg)
		return id, err == nil, err
	}
	for _, alg := range candidateAlgs {
		for _, t := range candidateTypes {
			id, err := vaultysid.FromEntropyAlg(entropy, t, alg)
			if err != nil {
				return nil, false, err
			}
			if matches(id) {
				return id, false, nil
			}
		}
	}
	for _, c := range v0 {
		d, _ := DecodeV0Certificate(c)
		if isOwnFIDO2Party(entropy, d.Pk1) || isOwnFIDO2Party(entropy, d.Pk2) {
			return nil, false, ErrFIDO2Wallet
		}
	}
	return nil, false, ErrNotFound
}

// TrustedCertificates returns the hashes of the v0 certificates a migration
// records: those that involve id and verify.
func TrustedCertificates(id *vaultysid.VaultysID, certificates [][]byte) map[string]bool {
	out := map[string]bool{}
	for _, c := range certificates {
		if Involves(id, c) && VerifyV0Certificate(c) {
			out[CertificateHash(c)] = true
		}
	}
	return out
}

// ErrDHIESV1Decrypt is returned for any DHIES v1 decryption failure.
var ErrDHIESV1Decrypt = errors.New("DHIES v1: decryption failed")

// DecryptDHIESV1 opens a DHIES message written by 3.x:
// nonce(24) || ephemeral_pk(32) || secretbox || mac(32).
//
// The sender's key only enters the KDF: nothing proves who encrypted the
// message (anyone holding the recipient's public key can produce one under
// any sender), so the plaintext must be treated as coming from an unverified
// sender. 4.0 never writes this format.
func DecryptDHIESV1(message, recipientSecret, recipientPublic, claimedSenderPublic []byte) ([]byte, error) {
	if len(message) < 24+32+secretbox.Overhead+32 || len(recipientSecret) != 32 || len(recipientPublic) != 32 || len(claimedSenderPublic) != 32 {
		return nil, ErrDHIESV1Decrypt
	}
	var nonce [24]byte
	copy(nonce[:], message[:24])
	ephemeral := message[24:56]
	mac := message[len(message)-32:]
	ciphertext := message[56 : len(message)-32]
	shared, err := curve25519.X25519(recipientSecret, ephemeral)
	if err != nil {
		return nil, ErrDHIESV1Decrypt
	}
	context := append(append([]byte("DHIES-KDF"), claimedSenderPublic...), recipientPublic...)
	derive := func(label byte) []byte {
		h := sha512.New()
		h.Write(shared)
		h.Write(context)
		h.Write([]byte{label})
		return h.Sum(nil)[:32]
	}
	encKey, macKey := derive(0x01), derive(0x02)
	defer func() {
		for _, b := range [][]byte{shared, encKey, macKey} {
			for i := range b {
				b[i] = 0
			}
		}
	}()
	h := sha256.New()
	h.Write(macKey)
	h.Write(claimedSenderPublic)
	h.Write(nonce[:])
	h.Write(ciphertext)
	if subtle.ConstantTimeCompare(h.Sum(nil), mac) != 1 {
		return nil, ErrDHIESV1Decrypt
	}
	var key [32]byte
	copy(key[:], encKey)
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	for i := range key {
		key[i] = 0
	}
	if !ok {
		return nil, ErrDHIESV1Decrypt
	}
	return plaintext, nil
}
