//go:build ignore
// +build ignore

// Deterministic cross-language vectors of the v1 handshake (VAULTYS_HANDSHAKE_V1)
// between HYBRID identities (dilithium_ed25519), produced by Go for TypeScript:
// the reverse of typescript/test/interops/generate-hybrid-handshake-vectors.ts.
// Regenerate with (from go/test/compatibility):
//
//	go run generate_hybrid_handshake_vectors.go
//
// Writes testdata/hybrid-handshake-go-vectors.json and copies it to
// ../../../typescript/test/interops/. Running it twice produces byte-identical
// output.
//
// Signatures: the Ed25519 half comes from the real VaultysID.SignHandshake
// (Ed25519 is deterministic); the ML-DSA-87 half uses the deterministic variant
// of FIPS 204 (circl SignTo with randomized = false) instead of the hedged one,
// so that the file is reproducible. Both are valid for any verifier; the
// generator checks that the real (hedged) signature and the deterministic one
// both verify.
package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/keymanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

const (
	fileName  = "hybrid-handshake-go-vectors.json"
	serviceID = "https://service.test"
	timestamp = uint64(1763769600000) // 2025-11-22T00:00:00Z, fixed
)

// pinned test inputs: SHA-512 of a readable label, truncated. Never use such
// values outside tests.
func pinned(name string, length int) []byte {
	sum := sha512.Sum512([]byte("VaultysID Go hybrid handshake test vector/" + name))
	return sum[:length]
}

func check(ok bool, format string, args ...interface{}) {
	if !ok {
		panic(fmt.Sprintf("hybrid handshake vectors: "+format, args...))
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func signHandshakeDeterministic(identity *vaultysid.VaultysID, unsigned []byte) []byte {
	km, ok := identity.KeyManager.(*keymanager.HybridManager)
	check(ok, "not a hybrid identity")
	live := must(identity.SignHandshake(unsigned))
	digest := sha256.Sum256(append([]byte("VAULTYS_HANDSHAKE_V1"), unsigned...))
	edSig := live[:64]
	var priv mldsa87.PrivateKey
	check(priv.UnmarshalBinary(km.Signer.SecretKey) == nil, "ML-DSA private key")
	pqSig := make([]byte, mldsa87.SignatureSize)
	check(mldsa87.SignTo(&priv, append(append([]byte{}, digest[:]...), edSig...), nil, false, pqSig) == nil, "ML-DSA sign")
	signature := append(append([]byte{}, edSig...), pqSig...)
	verifier := must(vaultysid.FromID(identity.ToBytes(), nil))
	check(verifier.VerifyHandshake(unsigned, live) == nil, "the real hybrid signature does not verify")
	check(verifier.VerifyHandshake(unsigned, signature) == nil, "the deterministic hybrid signature does not verify")
	return signature
}

type identityVector struct {
	Algorithm string `json:"algorithm"`
	Type      int    `json:"type"`
	Entropy   string `json:"entropy"`
	IDLength  int    `json:"idLength"`
	ID        string `json:"id"`
	DID       string `json:"did"`
}

type orderedMetadata [][2]string

// MarshalJSON keeps the entry order (Go maps would sort anyway; explicit is clearer).
func (m orderedMetadata) MarshalJSON() ([]byte, error) {
	out := []byte("{")
	for i, e := range m {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, must(json.Marshal(e[0]))...)
		out = append(out, ':')
		out = append(out, must(json.Marshal(e[1]))...)
	}
	return append(out, '}'), nil
}

type handshakeVector struct {
	Name      string `json:"name"`
	Initiator string `json:"initiator"`
	Responder string `json:"responder"`
	Version   int    `json:"version"`
	Protocol  string `json:"protocol"`
	Service   string `json:"service"`
	Timestamp uint64 `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Metadata  struct {
		PK1 orderedMetadata `json:"pk1"`
		PK2 orderedMetadata `json:"pk2"`
	} `json:"metadata"`
	UnsignedBytes   string `json:"unsignedBytes"`
	HandshakeDigest string `json:"handshakeDigest"`
	Sign1           string `json:"sign1"`
	Sign2           string `json:"sign2"`
	Init            string `json:"init"`
	Step1           string `json:"step1"`
	Complete        string `json:"complete"`
}

type negativeVector struct {
	Name     string `json:"name"`
	Complete string `json:"complete"`
}

func flip(b []byte, offset int) []byte {
	out := append([]byte{}, b...)
	out[offset] ^= 0x01
	return out
}

func toOrdered(md challenger.Metadata) orderedMetadata {
	out := orderedMetadata{}
	for _, e := range md {
		out = append(out, [2]string{e.Key, e.Value})
	}
	return out
}

func main() {
	specs := []struct {
		name string
		t    vaultysid.IdentityType
	}{
		{"hybrid_person", 0x01},
		{"hybrid_organization", 0x02},
		{"pq_hybrid_person", 0x11},
		{"pq_hybrid_machine", 0x10},
	}
	identities := map[string]identityVector{}
	ids := map[string]*vaultysid.VaultysID{}
	for _, s := range specs {
		entropy := pinned("entropy/"+s.name, 32)
		id := must(vaultysid.FromEntropyAlg(entropy, s.t, "dilithium_ed25519"))
		_, ok := id.KeyManager.(*keymanager.HybridManager)
		check(ok, "%s: key manager", s.name)
		parsed := must(vaultysid.FromID(id.ToBytes(), nil))
		check(parsed.DID() == id.DID() && string(parsed.ToBytes()) == string(id.ToBytes()), "%s: id round trip", s.name)
		ids[s.name] = id
		identities[s.name] = identityVector{"dilithium_ed25519", int(s.t), hex.EncodeToString(entropy), len(id.ToBytes()), hex.EncodeToString(id.ToBytes()), id.DID()}
	}

	cases := [][3]string{
		{"hybrid_person_to_organization", "hybrid_person", "hybrid_organization"},
		{"pq_hybrid_person_to_machine", "pq_hybrid_person", "pq_hybrid_machine"},
	}
	var handshakes []handshakeVector
	var negative []negativeVector
	for i, c := range cases {
		name, initiatorName, responderName := c[0], c[1], c[2]
		initiator, responder := ids[initiatorName], ids[responderName]
		binding := base64.StdEncoding.EncodeToString(pinned("binding/"+name, 32))
		md1 := challenger.NewMetadata(map[string]string{"name": initiatorName, "vaultys.channel-binding": binding, "vaultys.service": serviceID})
		md2 := challenger.NewMetadata(map[string]string{"name": responderName, "vaultys.channel-binding": binding, "vaultys.service": serviceID})
		nonce := pinned("nonce/"+name, 32)
		full := challenger.Challenge{
			Version: 1, Protocol: "p2p", Service: "auth", Timestamp: timestamp,
			PK1: initiator.ToBytes(), PK2: responder.ToBytes(), Nonce: nonce,
			Metadata: challenger.ChallengeMetadata{PK1: md1, PK2: md2},
		}
		unsigned := must(challenger.SerializeUnsigned(&full))
		digest := sha256.Sum256(append([]byte("VAULTYS_HANDSHAKE_V1"), unsigned...))
		full.Sign2 = signHandshakeDeterministic(responder, unsigned)
		full.Sign1 = signHandshakeDeterministic(initiator, unsigned)

		initMsg := challenger.Challenge{
			Version: 1, Protocol: "p2p", Service: "auth", Timestamp: timestamp,
			PK1: initiator.ToBytes(), Nonce: nonce[:16],
			Metadata: challenger.ChallengeMetadata{PK1: md1},
		}
		step1Msg := full
		step1Msg.Sign1 = nil
		init := must(challenger.Serialize(&initMsg))
		step1 := must(challenger.Serialize(&step1Msg))
		complete := must(challenger.Serialize(&full))

		ch, err := challenger.Deserialize(init)
		check(err == nil && ch.State == challenger.StateInit, "%s: INIT does not parse: %v", name, err)
		ch, err = challenger.Deserialize(step1)
		check(err == nil && ch.State == challenger.StateStep1, "%s: STEP1 does not verify: %v", name, err)
		_, err = challenger.VerifyCertificate(complete)
		check(err == nil, "%s: COMPLETE does not verify: %v", name, err)

		v := handshakeVector{
			Name: name, Initiator: initiatorName, Responder: responderName,
			Version: 1, Protocol: "p2p", Service: "auth", Timestamp: timestamp,
			Nonce:           hex.EncodeToString(nonce),
			UnsignedBytes:   hex.EncodeToString(unsigned),
			HandshakeDigest: hex.EncodeToString(digest[:]),
			Sign1:           hex.EncodeToString(full.Sign1),
			Sign2:           hex.EncodeToString(full.Sign2),
			Init:            hex.EncodeToString(init),
			Step1:           hex.EncodeToString(step1),
			Complete:        hex.EncodeToString(complete),
		}
		v.Metadata.PK1 = toOrdered(md1)
		v.Metadata.PK2 = toOrdered(md2)
		handshakes = append(handshakes, v)

		// Tampered COMPLETE certificates (first handshake only): every verifier MUST refuse them.
		if i != 0 {
			continue
		}
		other := challenger.NewMetadata(map[string]string{"name": initiatorName, "vaultys.channel-binding": binding, "vaultys.service": "https://other.test"})
		tampered := []struct {
			suffix string
			change func(c *challenger.Challenge)
		}{
			{"sign1_ed25519_half_altered", func(c *challenger.Challenge) { c.Sign1 = flip(c.Sign1, 10) }},
			{"sign1_mldsa_half_altered", func(c *challenger.Challenge) { c.Sign1 = flip(c.Sign1, 64+100) }},
			{"sign2_mldsa_half_altered", func(c *challenger.Challenge) { c.Sign2 = flip(c.Sign2, len(c.Sign2)-5) }},
			{"sign1_ed25519_only", func(c *challenger.Challenge) { c.Sign1 = c.Sign1[:64] }},
			{"sign2_mldsa_only", func(c *challenger.Challenge) { c.Sign2 = c.Sign2[64:] }},
			{"service_metadata_changed", func(c *challenger.Challenge) { c.Metadata = challenger.ChallengeMetadata{PK1: other, PK2: md2} }},
		}
		for _, t := range tampered {
			c := full
			t.change(&c)
			certificate := must(challenger.Serialize(&c))
			_, err := challenger.VerifyCertificate(certificate)
			check(err != nil, "%s/%s: tampered certificate accepted", name, t.suffix)
			negative = append(negative, negativeVector{name + "/" + t.suffix, hex.EncodeToString(certificate)})
		}
	}

	out := struct {
		Description string                    `json:"description"`
		Producer    string                    `json:"producer"`
		Domain      string                    `json:"domain"`
		Algorithm   string                    `json:"algorithm"`
		Identities  map[string]identityVector `json:"identities"`
		Handshakes  []handshakeVector         `json:"handshakes"`
		Negative    []negativeVector          `json:"negative"`
	}{
		Description: "VAULTYS_HANDSHAKE_V1 between hybrid (dilithium_ed25519) identities, produced by Go. ML-DSA-87 half signed with the deterministic variant of FIPS 204 (rnd = 0); every verifier MUST accept `handshakes` and refuse `negative`.",
		Producer:    "go",
		Domain:      "VAULTYS_HANDSHAKE_V1",
		Algorithm:   "dilithium_ed25519",
		Identities:  identities,
		Handshakes:  handshakes,
		Negative:    negative,
	}
	data := append(must(json.MarshalIndent(out, "", "  ")), '\n')
	main := filepath.Join("testdata", fileName)
	check(os.WriteFile(main, data, 0o644) == nil, "write %s", main)
	fmt.Println("wrote", main)
	copyTo := filepath.Join("..", "..", "..", "typescript", "test", "interops", fileName)
	check(os.WriteFile(copyTo, data, 0o644) == nil, "write %s", copyTo)
	fmt.Println("copied to", copyTo)
}
