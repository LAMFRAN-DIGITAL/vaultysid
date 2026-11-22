package compatibility

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/idmanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"github.com/vaultys/vaultysid/go/pkg/xwingchannel"
)

// Cross-language vectors of the post-quantum peer option of the contact
// handshake (rfc/PROTOCOL.md §12.1), in both directions:
//   - testdata/contact-pq-peer-ts-vectors.json, produced by
//     typescript/test/interops/generate-contact-pq-vectors.ts (TS -> Go);
//   - testdata/contact-pq-peer-go-vectors.json, produced by
//     generate_contact_pq_vectors.go (Go -> TS), checked here too and replayed
//     by typescript/test/contactPqVectors.test.ts.
type contactPQVectors struct {
	Producer   string `json:"producer"`
	Domain     string `json:"domain"`
	Code       string `json:"code"`
	Identities map[string]struct {
		Algorithm       string `json:"algorithm"`
		Type            int    `json:"type"`
		Entropy         string `json:"entropy"`
		ID              string `json:"id"`
		DID             string `json:"did"`
		PostQuantumPeer bool   `json:"postQuantumPeer"`
	} `json:"identities"`
	Init []struct {
		Name                string `json:"name"`
		Initiator           string `json:"initiator"`
		Init                string `json:"init"`
		ResponderWithOption string `json:"responderWithOption"`
	} `json:"init"`
	Step1 []struct {
		Name                string `json:"name"`
		Initiator           string `json:"initiator"`
		Responder           string `json:"responder"`
		UnsignedBytes       string `json:"unsignedBytes"`
		Sign2               string `json:"sign2"`
		Step1               string `json:"step1"`
		InitiatorWithOption string `json:"initiatorWithOption"`
	} `json:"step1"`
}

func checkContactPQVectors(t *testing.T, file, producer string) {
	raw, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	var v contactPQVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("invalid vectors JSON: %v", err)
	}
	if v.Producer != producer || v.Domain != "VAULTYS_HANDSHAKE_V1" || v.Code != idmanager.CodePeerNotPQ {
		t.Fatalf("unexpected header: %s %s %s", v.Producer, v.Domain, v.Code)
	}
	if len(v.Identities) != 6 || len(v.Init) != 6 || len(v.Step1) != 1 {
		t.Fatalf("unexpected vector counts: %d identities, %d init, %d step1", len(v.Identities), len(v.Init), len(v.Step1))
	}

	// Same entropy -> same identity, and the same classification, in both languages.
	for name, ident := range v.Identities {
		id, err := vaultysid.FromEntropyAlg(mustHex(t, ident.Entropy), vaultysid.IdentityType(ident.Type), ident.Algorithm)
		if err != nil {
			t.Fatalf("%s: FromEntropyAlg: %v", name, err)
		}
		if !bytes.Equal(id.ToBytes(), mustHex(t, ident.ID)) || id.DID() != ident.DID {
			t.Fatalf("%s: identity differs from %s", name, producer)
		}
		public, err := vaultysid.FromID(mustHex(t, ident.ID), nil)
		if err != nil || xwingchannel.IsPostQuantumPeer(public) != ident.PostQuantumPeer {
			t.Fatalf("%s: post-quantum classification differs from %s (%v)", name, producer, err)
		}
	}

	responder, err := vaultysid.GeneratePersonAlg("dilithium_ed25519")
	if err != nil {
		t.Fatal(err)
	}
	m := idmanager.NewManager(responder, idmanager.NewMemoryStore())
	for _, in := range v.Init {
		t.Run(in.Name, func(t *testing.T) {
			init := mustHex(t, in.Init)
			parsed, err := challenger.Deserialize(init)
			if err != nil || parsed.State != challenger.StateInit || !bytes.Equal(parsed.PK1, mustHex(t, v.Identities[in.Initiator].ID)) {
				t.Fatalf("INIT: %v", err)
			}
			sess, step1, err := m.AcceptConnectWithOptions(init, nil, idmanager.ConnectOptions{RequirePostQuantumPeer: true})
			switch in.ResponderWithOption {
			case "PEER_NOT_PQ":
				if !idmanager.IsContactCode(err, idmanager.CodePeerNotPQ) || sess != nil || step1 != nil {
					t.Fatalf("expected PEER_NOT_PQ before STEP1, got %v", err)
				}
			case "PQ_CHECK_PASSED":
				// a frozen INIT is then refused by the liveliness window, never by the option
				if err == nil || idmanager.IsContactCode(err, idmanager.CodePeerNotPQ) {
					t.Fatalf("expected a liveliness refusal, got %v", err)
				}
			default:
				t.Fatalf("unknown expectation %q", in.ResponderWithOption)
			}
			// without the option no INIT is refused for its algorithm
			if _, _, err := m.AcceptConnect(init, nil); idmanager.IsContactCode(err, idmanager.CodePeerNotPQ) {
				t.Fatal("PEER_NOT_PQ without the option")
			}
		})
	}
	if len(m.Contacts()) != 0 {
		t.Fatal("no contact may be saved")
	}

	for _, s := range v.Step1 {
		t.Run(s.Name, func(t *testing.T) {
			step1, err := challenger.Deserialize(mustHex(t, s.Step1))
			if err != nil || step1.State != challenger.StateStep1 {
				t.Fatalf("STEP1 does not verify: %v", err)
			}
			unsigned, err := challenger.SerializeUnsigned(step1)
			if err != nil || !bytes.Equal(unsigned, mustHex(t, s.UnsignedBytes)) || !bytes.Equal(step1.Sign2, mustHex(t, s.Sign2)) {
				t.Fatal("unsigned bytes or sign2 differ")
			}
			peer, err := vaultysid.FromID(step1.PK2, nil)
			if err != nil || peer.VerifyHandshake(unsigned, step1.Sign2) != nil {
				t.Fatal("sign2 must verify against pk2")
			}
			if s.InitiatorWithOption != "PEER_NOT_PQ" || xwingchannel.IsPostQuantumPeer(peer) || !bytes.Equal(step1.PK2, mustHex(t, v.Identities[s.Responder].ID)) {
				t.Fatal("an initiator with the option must refuse this responder")
			}
		})
	}

	// The hybrid STEP1 of the hybrid handshake vectors pass the initiator's check.
	for _, f := range []string{"hybrid-handshake-ts-vectors.json", "hybrid-handshake-go-vectors.json"} {
		raw, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		var h hybridHandshakeVectors
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatal(err)
		}
		for _, hs := range h.Handshakes {
			step1, err := challenger.Deserialize(mustHex(t, hs.Step1))
			if err != nil {
				t.Fatal(err)
			}
			peer, err := vaultysid.FromID(step1.PK2, nil)
			if err != nil || !xwingchannel.IsPostQuantumPeer(peer) {
				t.Fatalf("%s/%s: hybrid responder must pass the check", f, hs.Name)
			}
		}
	}
}

func TestContactPQVectorsFromTypeScript(t *testing.T) {
	checkContactPQVectors(t, "contact-pq-peer-ts-vectors.json", "typescript")
}

func TestContactPQVectorsFromGo(t *testing.T) {
	checkContactPQVectors(t, "contact-pq-peer-go-vectors.json", "go")
	ours, err := os.ReadFile(filepath.Join("testdata", "contact-pq-peer-go-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := os.ReadFile(filepath.Join("..", "..", "..", "typescript", "test", "interops", "contact-pq-peer-go-vectors.json"))
	if err != nil {
		t.Skip("typescript/ not present next to go/")
	}
	if !bytes.Equal(ours, theirs) {
		t.Fatal("typescript/test/interops/contact-pq-peer-go-vectors.json differs: rerun go run generate_contact_pq_vectors.go")
	}
}
