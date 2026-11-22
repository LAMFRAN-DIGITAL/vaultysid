//go:build ignore
// +build ignore

// Deterministic cross-language vectors of the "post-quantum peer required"
// option of the contact handshake (RequestConnectWithOptions /
// AcceptConnectWithOptions in Go, askContact / acceptContact in TypeScript;
// rfc/PROTOCOL.md §12.1), produced by Go for TypeScript: the reverse of
// typescript/test/interops/generate-contact-pq-vectors.ts, which explains what
// is frozen. Regenerate with (from go/test/compatibility):
//
//	go run generate_contact_pq_vectors.go
//
// Writes testdata/contact-pq-peer-go-vectors.json and copies it to
// ../../../typescript/test/interops/. Running it twice produces byte-identical
// output (INIT messages are unsigned; the only signature is Ed25519).
package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"github.com/vaultys/vaultysid/go/pkg/xwingchannel"
)

const (
	fileName  = "contact-pq-peer-go-vectors.json"
	timestamp = uint64(1763769600000) // 2025-11-22T00:00:00Z, fixed
)

func pinned(name string, length int) []byte {
	sum := sha512.Sum512([]byte("VaultysID Go contact PQ test vector/" + name))
	return sum[:length]
}

func check(ok bool, format string, args ...interface{}) {
	if !ok {
		panic(fmt.Sprintf("contact PQ vectors: "+format, args...))
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type identityVector struct {
	Algorithm       string `json:"algorithm"`
	Type            int    `json:"type"`
	Entropy         string `json:"entropy"`
	IDLength        int    `json:"idLength"`
	ID              string `json:"id"`
	DID             string `json:"did"`
	PostQuantumPeer bool   `json:"postQuantumPeer"`
}

type initVector struct {
	Name                string `json:"name"`
	Initiator           string `json:"initiator"`
	Init                string `json:"init"`
	ResponderWithOption string `json:"responderWithOption"`
}

type step1Vector struct {
	Name                string `json:"name"`
	Initiator           string `json:"initiator"`
	Responder           string `json:"responder"`
	UnsignedBytes       string `json:"unsignedBytes"`
	Sign2               string `json:"sign2"`
	Step1               string `json:"step1"`
	InitiatorWithOption string `json:"initiatorWithOption"`
}

func main() {
	specs := []struct {
		name      string
		t         vaultysid.IdentityType
		algorithm string
		pq        bool
	}{
		{"ed25519_person", 0x01, "ed25519", false},
		{"ed25519_organization", 0x02, "ed25519", false},
		{"dilithium_person", 0x01, "dilithium", true},
		{"hybrid_person", 0x01, "dilithium_ed25519", true},
		{"pq_hybrid_person", 0x11, "dilithium_ed25519", true},
		{"pq_dilithium_machine", 0x10, "dilithium", true},
	}
	identities := map[string]identityVector{}
	ids := map[string]*vaultysid.VaultysID{}
	var inits []initVector
	for _, s := range specs {
		entropy := pinned("entropy/"+s.name, 32)
		id := must(vaultysid.FromEntropyAlg(entropy, s.t, s.algorithm))
		parsed := must(vaultysid.FromID(id.ToBytes(), nil))
		check(parsed.DID() == id.DID() && string(parsed.ToBytes()) == string(id.ToBytes()), "%s: id round trip", s.name)
		check(xwingchannel.IsPostQuantumPeer(parsed) == s.pq, "%s: classification", s.name)
		ids[s.name] = id
		identities[s.name] = identityVector{s.algorithm, int(s.t), hex.EncodeToString(entropy), len(id.ToBytes()), hex.EncodeToString(id.ToBytes()), id.DID(), s.pq}

		initMsg := challenger.Challenge{
			Version: 1, Protocol: "p2p", Service: "auth", Timestamp: timestamp,
			PK1: id.ToBytes(), Nonce: pinned("nonce/init/"+s.name, 16),
			Metadata: challenger.ChallengeMetadata{PK1: challenger.NewMetadata(map[string]string{"name": s.name})},
		}
		init := must(challenger.Serialize(&initMsg))
		ch, err := challenger.Deserialize(init)
		check(err == nil && ch.State == challenger.StateInit, "%s: INIT does not parse: %v", s.name, err)
		expected := "PEER_NOT_PQ"
		if s.pq {
			expected = "PQ_CHECK_PASSED"
		}
		inits = append(inits, initVector{"init_from_" + s.name, s.name, hex.EncodeToString(init), expected})
	}

	var step1s []step1Vector
	for _, c := range [][3]string{{"hybrid_person_to_ed25519_organization", "hybrid_person", "ed25519_organization"}} {
		name, initiatorName, responderName := c[0], c[1], c[2]
		full := challenger.Challenge{
			Version: 1, Protocol: "p2p", Service: "auth", Timestamp: timestamp,
			PK1: ids[initiatorName].ToBytes(), PK2: ids[responderName].ToBytes(), Nonce: pinned("nonce/step1/"+name, 32),
			Metadata: challenger.ChallengeMetadata{
				PK1: challenger.NewMetadata(map[string]string{"name": initiatorName}),
				PK2: challenger.NewMetadata(map[string]string{"name": responderName}),
			},
			State: challenger.StateStep1,
		}
		unsigned := must(challenger.SerializeUnsigned(&full))
		full.Sign2 = must(ids[responderName].SignHandshake(unsigned))
		step1 := must(challenger.Serialize(&full))
		ch, err := challenger.Deserialize(step1)
		check(err == nil && ch.State == challenger.StateStep1, "%s: STEP1 does not verify: %v", name, err)
		check(!xwingchannel.IsPostQuantumPeer(must(vaultysid.FromID(ch.PK2, nil))), "%s: responder must be classical", name)
		step1s = append(step1s, step1Vector{name, initiatorName, responderName, hex.EncodeToString(unsigned), hex.EncodeToString(full.Sign2), hex.EncodeToString(step1), "PEER_NOT_PQ"})
	}

	out := struct {
		Description string                    `json:"description"`
		Producer    string                    `json:"producer"`
		Domain      string                    `json:"domain"`
		Code        string                    `json:"code"`
		Identities  map[string]identityVector `json:"identities"`
		Init        []initVector              `json:"init"`
		Step1       []step1Vector             `json:"step1"`
	}{
		Description: "Contact handshake (p2p/auth) with the post-quantum peer option (rfc/PROTOCOL.md §12.1), produced by Go. A responder with the option MUST refuse `init` marked PEER_NOT_PQ before signing STEP1 and let the others pass this check; an initiator with the option MUST refuse `step1` (sign2 verifies, pk2 is Ed25519) before signing COMPLETE.",
		Producer:    "go",
		Domain:      "VAULTYS_HANDSHAKE_V1",
		Code:        "PEER_NOT_PQ",
		Identities:  identities,
		Init:        inits,
		Step1:       step1s,
	}
	data := append(must(json.MarshalIndent(out, "", "  ")), '\n')
	main := filepath.Join("testdata", fileName)
	check(os.WriteFile(main, data, 0o644) == nil, "write %s", main)
	fmt.Println("wrote", main)
	copyTo := filepath.Join("..", "..", "..", "typescript", "test", "interops", fileName)
	check(os.WriteFile(copyTo, data, 0o644) == nil, "write %s", copyTo)
	fmt.Println("copied to", copyTo)
}
