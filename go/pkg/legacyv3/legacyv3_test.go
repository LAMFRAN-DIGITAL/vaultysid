package legacyv3

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/keymanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// Wallets written by the published @vaultys/id 3.0.4
// (typescript/test/interops/generate-legacy-v3-vectors.ts).
type wallet struct {
	Name    string `json:"name"`
	Created struct {
		Type int    `json:"type"`
		Alg  string `json:"alg"`
	} `json:"created"`
	DID          string   `json:"did"`
	ID           string   `json:"id"`
	Entropy      string   `json:"entropy"`
	Certificates []string `json:"certificates"`
}

type vectors struct {
	Wallets             []wallet `json:"wallets"`
	LonelyReopenedDID   string   `json:"lonelyReopenedDid"`
	TamperedCertificate string   `json:"tamperedCertificate"`
	DHIESV1             struct {
		To        string `json:"to"`
		SenderID  string `json:"senderId"`
		Message   string `json:"message"`
		Plaintext string `json:"plaintext"`
	} `json:"dhiesV1"`
}

func load(t *testing.T) vectors {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "legacy-v3-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func certificates(t *testing.T, w wallet) [][]byte {
	out := make([][]byte, len(w.Certificates))
	for i, c := range w.Certificates {
		out[i] = unhex(t, c)
	}
	return out
}

func (v vectors) wallet(name string) wallet {
	for _, w := range v.Wallets {
		if w.Name == name {
			return w
		}
	}
	panic("no wallet " + name)
}

func TestRecoversEveryWalletFromItsCertificates(t *testing.T) {
	v := load(t)
	for _, w := range v.Wallets {
		if len(w.Certificates) == 0 {
			continue
		}
		id, guessed, err := RecoverIdentity(unhex(t, w.Entropy), certificates(t, w), nil, &ReopenDefault)
		if err != nil {
			t.Fatalf("%s: %v", w.Name, err)
		}
		if guessed {
			t.Errorf("%s: guessed although the certificates tell", w.Name)
		}
		if id.DID() != w.DID {
			t.Errorf("%s: DID %s, want %s", w.Name, id.DID(), w.DID)
		}
		if int(id.Type) != w.Created.Type {
			t.Errorf("%s: type %d, want %d", w.Name, id.Type, w.Created.Type)
		}
		if n := len(TrustedCertificates(id, certificates(t, w))); n != len(w.Certificates) {
			t.Errorf("%s: %d trusted certificates, want %d", w.Name, n, len(w.Certificates))
		}
	}
}

func TestStoreWithoutCertificates(t *testing.T) {
	v := load(t)
	w := v.wallet("lonely")
	entropy := unhex(t, w.Entropy)
	if _, _, err := RecoverIdentity(entropy, nil, nil, nil); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("want ErrNoCertificate, got %v", err)
	}
	// without anything better, as 3.x reopened it
	id, guessed, err := RecoverIdentity(entropy, nil, nil, &ReopenDefault)
	if err != nil || !guessed || id.DID() != v.LonelyReopenedDID {
		t.Fatalf("fallback: %v guessed=%v did=%s want %s", err, guessed, id.DID(), v.LonelyReopenedDID)
	}
	// the app knows what it created
	id, guessed, err = RecoverIdentity(entropy, nil, &Hint{Type: vaultysid.IdentityType(w.Created.Type), Alg: w.Created.Alg}, &ReopenDefault)
	if err != nil || guessed || id.DID() != w.DID {
		t.Fatalf("hint: %v guessed=%v did=%s want %s", err, guessed, id.DID(), w.DID)
	}
}

func TestRefusesAHintThatContradictsTheCertificates(t *testing.T) {
	w := load(t).wallet("alice")
	_, _, err := RecoverIdentity(unhex(t, w.Entropy), certificates(t, w), &Hint{Type: vaultysid.TypeOrganization, Alg: "ed25519"}, nil)
	if !errors.Is(err, ErrHintMismatch) {
		t.Fatalf("want ErrHintMismatch, got %v", err)
	}
}

func TestVerifiesV0CertificatesWithThe3xRules(t *testing.T) {
	v := load(t)
	for _, w := range v.Wallets {
		for i, c := range certificates(t, w) {
			if !VerifyV0Certificate(c) {
				t.Errorf("%s certificate %d does not verify", w.Name, i)
			}
		}
	}
	if VerifyV0Certificate(unhex(t, v.TamperedCertificate)) {
		t.Error("tampered certificate verifies")
	}
	// another wallet's certificates are not alice's
	alice, _, err := RecoverIdentity(unhex(t, v.wallet("alice").Entropy), certificates(t, v.wallet("alice")), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	carolOnly := certificates(t, v.wallet("carol"))
	if !Involves(alice, carolOnly[0]) {
		t.Error("alice is in her certificate with carol")
	}
	lonely, _, _ := RecoverIdentity(unhex(t, v.wallet("lonely").Entropy), nil, nil, &ReopenDefault)
	if Involves(lonely, carolOnly[0]) {
		t.Error("an unrelated identity is involved")
	}
}

func TestDecryptsDHIESV1AsWrittenBy3x(t *testing.T) {
	v := load(t)
	w := v.wallet(v.DHIESV1.To)
	bob, _, err := RecoverIdentity(unhex(t, w.Entropy), certificates(t, w), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := bob.KeyManager.(keymanager.CypherSecretProvider).GetCypherSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	sender, err := vaultysid.FromID(unhex(t, v.DHIESV1.SenderID), nil)
	if err != nil {
		t.Fatal(err)
	}
	message := unhex(t, v.DHIESV1.Message)
	plaintext, err := DecryptDHIESV1(message, sk, bob.KeyManager.GetCypherPublicKey(), sender.KeyManager.GetCypherPublicKey())
	if err != nil || string(plaintext) != v.DHIESV1.Plaintext {
		t.Fatalf("got %q, %v", plaintext, err)
	}
	// another claimed sender, or a flipped byte: refused
	if _, err := DecryptDHIESV1(message, sk, bob.KeyManager.GetCypherPublicKey(), bob.KeyManager.GetCypherPublicKey()); err == nil {
		t.Error("opens under another claimed sender")
	}
	message[30] ^= 1
	if _, err := DecryptDHIESV1(message, sk, bob.KeyManager.GetCypherPublicKey(), sender.KeyManager.GetCypherPublicKey()); err == nil {
		t.Error("opens a modified message")
	}
}

func TestEncodesUnsignedV0ByteForByte(t *testing.T) {
	// re-encoding a decoded certificate must give what 3.x signed: checked
	// through the signatures of every certificate
	v := load(t)
	c, err := DecodeV0Certificate(unhex(t, v.wallet("alice").Certificates[0]))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := vaultysid.FromID(c.Pk1, nil)
	if !verifyV0Signature(id, c.Pk1, EncodeUnsignedV0(c), c.Sign1) {
		t.Fatal("pk1 signature does not verify over the re-encoded bytes")
	}
	c.Timestamp++
	if verifyV0Signature(id, c.Pk1, EncodeUnsignedV0(c), c.Sign1) {
		t.Fatal("signature verifies over another timestamp")
	}
}
