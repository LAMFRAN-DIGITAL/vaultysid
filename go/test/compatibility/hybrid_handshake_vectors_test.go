package compatibility

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/keymanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// Cross-language vectors of the v1 handshake between hybrid (dilithium_ed25519)
// identities, in both directions:
//   - testdata/hybrid-handshake-ts-vectors.json, produced by
//     typescript/test/interops/generate-hybrid-handshake-vectors.ts (TS -> Go);
//   - testdata/hybrid-handshake-go-vectors.json, produced by
//     generate_hybrid_handshake_vectors.go (Go -> TS), checked here too and
//     replayed by typescript/test/hybridHandshakeVectors.test.ts.
type hybridHandshakeVectors struct {
	Producer   string `json:"producer"`
	Domain     string `json:"domain"`
	Algorithm  string `json:"algorithm"`
	Identities map[string]struct {
		Algorithm string `json:"algorithm"`
		Type      int    `json:"type"`
		Entropy   string `json:"entropy"`
		IDLength  int    `json:"idLength"`
		ID        string `json:"id"`
		DID       string `json:"did"`
	} `json:"identities"`
	Handshakes []struct {
		Name            string `json:"name"`
		Initiator       string `json:"initiator"`
		Responder       string `json:"responder"`
		Timestamp       uint64 `json:"timestamp"`
		Nonce           string `json:"nonce"`
		UnsignedBytes   string `json:"unsignedBytes"`
		HandshakeDigest string `json:"handshakeDigest"`
		Sign1           string `json:"sign1"`
		Sign2           string `json:"sign2"`
		Init            string `json:"init"`
		Step1           string `json:"step1"`
		Complete        string `json:"complete"`
	} `json:"handshakes"`
	Negative []struct {
		Name     string `json:"name"`
		Complete string `json:"complete"`
	} `json:"negative"`
}

func checkHybridHandshakeVectors(t *testing.T, file, producer string) {
	raw, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	var v hybridHandshakeVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("invalid vectors JSON: %v", err)
	}
	if v.Producer != producer || v.Domain != "VAULTYS_HANDSHAKE_V1" || v.Algorithm != "dilithium_ed25519" {
		t.Fatalf("unexpected header: %s %s %s", v.Producer, v.Domain, v.Algorithm)
	}
	if len(v.Identities) != 4 || len(v.Handshakes) != 2 || len(v.Negative) != 6 {
		t.Fatalf("unexpected vector counts: %d identities, %d handshakes, %d negative", len(v.Identities), len(v.Handshakes), len(v.Negative))
	}

	// Same entropy -> same hybrid identity in both languages.
	ids := map[string][]byte{}
	for name, ident := range v.Identities {
		id, err := vaultysid.FromEntropyAlg(mustHex(t, ident.Entropy), vaultysid.IdentityType(ident.Type), ident.Algorithm)
		if err != nil {
			t.Fatalf("%s: FromEntropyAlg: %v", name, err)
		}
		if _, ok := id.KeyManager.(*keymanager.HybridManager); !ok {
			t.Fatalf("%s: not a hybrid key manager", name)
		}
		if !bytes.Equal(id.ToBytes(), mustHex(t, ident.ID)) || len(id.ToBytes()) != ident.IDLength {
			t.Fatalf("%s: id differs from %s", name, producer)
		}
		if id.DID() != ident.DID {
			t.Fatalf("%s: DID %s, want %s", name, id.DID(), ident.DID)
		}
		ids[name] = id.ToBytes()
	}

	for _, h := range v.Handshakes {
		t.Run(h.Name, func(t *testing.T) {
			complete := mustHex(t, h.Complete)
			ch, err := challenger.VerifyCertificate(complete)
			if err != nil {
				t.Fatalf("%s certificate rejected: %v", producer, err)
			}
			if !bytes.Equal(ch.PK1, ids[h.Initiator]) || !bytes.Equal(ch.PK2, ids[h.Responder]) {
				t.Fatal("pk1 / pk2 are not the vector identities")
			}
			if ch.Timestamp != h.Timestamp || !bytes.Equal(ch.Nonce, mustHex(t, h.Nonce)) {
				t.Fatal("timestamp or nonce differ")
			}
			unsigned, err := challenger.SerializeUnsigned(ch)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(unsigned, mustHex(t, h.UnsignedBytes)) {
				t.Fatal("unsigned bytes differ")
			}
			digest := sha256.Sum256(append([]byte("VAULTYS_HANDSHAKE_V1"), unsigned...))
			if !bytes.Equal(digest[:], mustHex(t, h.HandshakeDigest)) {
				t.Fatal("handshake digest differs")
			}
			if !bytes.Equal(ch.Sign1, mustHex(t, h.Sign1)) || !bytes.Equal(ch.Sign2, mustHex(t, h.Sign2)) {
				t.Fatal("signatures differ")
			}
			if len(ch.Sign1) != 64+4627 || len(ch.Sign2) != 64+4627 {
				t.Fatalf("hybrid signatures must be 64 + 4627 bytes, got %d and %d", len(ch.Sign1), len(ch.Sign2))
			}
			// re-serialization is byte-identical
			again, err := challenger.Serialize(ch)
			if err != nil || !bytes.Equal(again, complete) {
				t.Fatal("COMPLETE does not round-trip")
			}
			// the signatures verify only in the handshake domain
			id1, _ := vaultysid.FromID(ch.PK1, nil)
			if id1.VerifyHandshake(unsigned, ch.Sign1) != nil || id1.Verify(unsigned, ch.Sign1) == nil || id1.VerifyChallenge(unsigned, ch.Sign1) == nil {
				t.Fatal("sign1 must verify in VAULTYS_HANDSHAKE_V1 only")
			}
			init, err := challenger.Deserialize(mustHex(t, h.Init))
			if err != nil || init.State != challenger.StateInit {
				t.Fatalf("INIT: %v", err)
			}
			step1, err := challenger.Deserialize(mustHex(t, h.Step1))
			if err != nil || step1.State != challenger.StateStep1 {
				t.Fatalf("STEP1: %v", err)
			}
		})
	}

	for _, n := range v.Negative {
		if _, err := challenger.VerifyCertificate(mustHex(t, n.Complete)); err == nil {
			t.Errorf("%s: tampered %s certificate accepted", n.Name, producer)
		}
	}
}

func TestHybridHandshakeVectorsFromTypeScript(t *testing.T) {
	checkHybridHandshakeVectors(t, "hybrid-handshake-ts-vectors.json", "typescript")
}

func TestHybridHandshakeVectorsFromGo(t *testing.T) {
	checkHybridHandshakeVectors(t, "hybrid-handshake-go-vectors.json", "go")
	// the copy replayed by TypeScript is the same file
	ours, err := os.ReadFile(filepath.Join("testdata", "hybrid-handshake-go-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := os.ReadFile(filepath.Join("..", "..", "..", "typescript", "test", "interops", "hybrid-handshake-go-vectors.json"))
	if err != nil {
		t.Skip("typescript/ not present next to go/")
	}
	if !bytes.Equal(ours, theirs) {
		t.Fatal("typescript/test/interops/hybrid-handshake-go-vectors.json differs: rerun go run generate_hybrid_handshake_vectors.go")
	}
}
