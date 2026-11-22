package idmanager

import (
	"sync/atomic"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/keymanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"github.com/vaultys/vaultysid/go/pkg/xwingchannel"
)

// ConnectOptions.RequirePostQuantumPeer: the contact handshake (RequestConnect /
// AcceptConnect, the Go counterpart of askContact / acceptContact) refuses a
// peer that does not sign with ML-DSA, before signing anything (rfc/PROTOCOL.md §12.1).

// countingSigner counts the signatures an identity produces (the challenger
// signs only through VaultysID.SignHandshake, hence KeyManager.Sign).
type countingSigner struct {
	keymanager.KeyManager
	count *atomic.Int32
}

func (c countingSigner) Sign(data []byte) ([]byte, error) {
	c.count.Add(1)
	return c.KeyManager.Sign(data)
}

func countSignatures(identity *vaultysid.VaultysID) *atomic.Int32 {
	n := &atomic.Int32{}
	identity.KeyManager = countingSigner{KeyManager: identity.KeyManager, count: n}
	return n
}

func managerWith(t *testing.T, generate func() (*vaultysid.VaultysID, error)) (*Manager, *vaultysid.VaultysID) {
	t.Helper()
	id, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	return NewManager(id, NewMemoryStore()), id
}

func hybridPerson() (*vaultysid.VaultysID, error) {
	return vaultysid.GeneratePersonAlg("dilithium_ed25519")
}

var required = ConnectOptions{RequirePostQuantumPeer: true}

func TestContactPostQuantumPeer_HybridAcceptedBothSides(t *testing.T) {
	alice, aliceID := managerWith(t, hybridPerson)
	bob, bobID := managerWith(t, hybridPerson)
	sessA, initMsg, err := alice.RequestConnectWithOptions(nil, required)
	if err != nil {
		t.Fatal(err)
	}
	sessB, step1, err := bob.AcceptConnectWithOptions(initMsg, nil, required)
	if err != nil {
		t.Fatal(err)
	}
	complete, gotBob, err := sessA.Complete(step1)
	if err != nil {
		t.Fatal(err)
	}
	gotAlice, err := sessB.Finalize(complete)
	if err != nil {
		t.Fatal(err)
	}
	if gotBob.DID() != bobID.DID() || gotAlice.DID() != aliceID.DID() {
		t.Fatal("wrong contacts")
	}
	if !xwingchannel.IsPostQuantumPeer(gotBob) || !xwingchannel.IsPostQuantumPeer(gotAlice) {
		t.Fatal("saved contacts must keep their hybrid key manager")
	}
	if len(alice.Contacts()) != 1 || len(bob.Contacts()) != 1 {
		t.Fatal("each side saves the other")
	}
}

func TestContactPostQuantumPeer_DilithiumAccepted(t *testing.T) {
	alice, _ := managerWith(t, hybridPerson)
	bob, bobID := managerWith(t, func() (*vaultysid.VaultysID, error) { return vaultysid.GeneratePersonAlg("dilithium") })
	sessA, initMsg, _ := alice.RequestConnectWithOptions(nil, required)
	_, step1, err := bob.AcceptConnect(initMsg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, got, err := sessA.Complete(step1); err != nil || got.DID() != bobID.DID() {
		t.Fatal(err)
	}
}

func TestContactPostQuantumPeer_InitiatorRefusesEd25519(t *testing.T) {
	alice, aliceID := managerWith(t, hybridPerson)
	bob, _ := managerWith(t, vaultysid.GeneratePerson)
	sessA, initMsg, err := alice.RequestConnectWithOptions(nil, required)
	if err != nil {
		t.Fatal(err)
	}
	// INIT carries no signature; count from here on
	signed := countSignatures(aliceID)
	_, step1, err := bob.AcceptConnect(initMsg, nil)
	if err != nil {
		t.Fatal(err)
	}
	complete, contact, err := sessA.Complete(step1)
	if !IsContactCode(err, CodePeerNotPQ) {
		t.Fatalf("expected PEER_NOT_PQ, got %v", err)
	}
	if complete != nil || contact != nil {
		t.Fatal("no COMPLETE may be produced")
	}
	if n := signed.Load(); n != 0 {
		t.Fatalf("initiator signed %d message(s)", n)
	}
	if len(alice.Contacts()) != 0 {
		t.Fatal("no contact may be saved")
	}
	if !sessA.Challenger().HasFailed() {
		t.Fatal("the session must end in ERROR")
	}
}

func TestContactPostQuantumPeer_ResponderRefusesEd25519(t *testing.T) {
	alice, _ := managerWith(t, vaultysid.GeneratePerson)
	bob, bobID := managerWith(t, hybridPerson)
	signed := countSignatures(bobID)
	_, initMsg, err := alice.RequestConnect(nil)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	sess, step1, err := bob.AcceptConnectWithOptions(initMsg, func(*vaultysid.VaultysID) error { called = true; return nil }, required)
	if !IsContactCode(err, CodePeerNotPQ) {
		t.Fatalf("expected PEER_NOT_PQ, got %v", err)
	}
	if sess != nil || step1 != nil {
		t.Fatal("no STEP1 may be produced")
	}
	if called {
		t.Fatal("the consent callback must not see a refused peer")
	}
	if n := signed.Load(); n != 0 {
		t.Fatalf("responder signed %d message(s)", n)
	}
	if len(bob.Contacts()) != 0 {
		t.Fatal("no contact may be saved")
	}
}

func TestContactPostQuantumPeer_OffByDefault(t *testing.T) {
	alice, _ := managerWith(t, vaultysid.GeneratePerson)
	bob, _ := managerWith(t, hybridPerson)
	sessA, initMsg, _ := alice.RequestConnect(nil)
	sessB, step1, err := bob.AcceptConnectWithOptions(initMsg, nil, ConnectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	complete, _, err := sessA.Complete(step1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessB.Finalize(complete); err != nil {
		t.Fatal(err)
	}
	// the refusal is a ContactError, never confused with a channel error
	err = &ContactError{Code: CodePeerNotPQ}
	if CodePeerNotPQ != "PEER_NOT_PQ" || xwingchannel.IsCode(err, CodePeerNotPQ) || IsContactCode(nil, CodePeerNotPQ) {
		t.Fatal("ContactError / IsContactCode")
	}
	// an INIT for another service is still refused first
	ch := challenger.New(mustPerson(t))
	init, _ := ch.Init("p2p", "transfer")
	b, _ := challenger.Serialize(init)
	if _, _, err := bob.AcceptConnectWithOptions(b, nil, required); err == nil || IsContactCode(err, CodePeerNotPQ) {
		t.Fatal("protocol / service are checked before the post-quantum option", err)
	}
}
