package proton_api_bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

func hashB64(b []byte) string {
	h := sha256.New()
	h.Write(b)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// helper: makes an addrKR (a normal signing/encryption keypair) for tests.
func newAddrKR(t *testing.T) *crypto.KeyRing {
	t.Helper()
	pgp := crypto.PGP()
	k, err := pgp.KeyGeneration().AddUserId("test", "test@example.com").New().GenerateKey()
	if err != nil {
		t.Fatalf("addr key gen: %v", err)
	}
	kr, err := crypto.NewKeyRing(k)
	if err != nil {
		t.Fatalf("addr keyring: %v", err)
	}
	return kr
}

// helper: produces a fresh nodeKR.
func newNodeKR(t *testing.T) *crypto.KeyRing {
	t.Helper()
	pgp := crypto.PGP()
	k, err := pgp.KeyGeneration().AddUserId("node", "node@example.com").New().GenerateKey()
	if err != nil {
		t.Fatalf("node key gen: %v", err)
	}
	kr, err := crypto.NewKeyRing(k)
	if err != nil {
		t.Fatalf("node keyring: %v", err)
	}
	return kr
}

// TestBlockEncryptDecryptRoundTrip mirrors the upload + download crypto flow.
// It is the regression test for: "gopenpgp: error in reading data message:
// openpgp: invalid data: tag byte does not have MSB set" on download.
func TestBlockEncryptDecryptRoundTrip(t *testing.T) {
	pgp := crypto.PGP()

	addrKR := newAddrKR(t)
	nodeKR := newNodeKR(t)

	// Build a fresh session key (as createFileUploadDraft does).
	sessionKey, err := pgp.GenerateSessionKey()
	if err != nil {
		t.Fatalf("gen session key: %v", err)
	}

	// Pretend block payload — anything that wouldn't itself happen to look
	// like a valid PGP packet header.
	plaintext := []byte(strings.Repeat("hello proton drive ", 1000))

	// --- Upload path: encrypt block + sign + encrypt the signature ---
	sessionEnc, err := pgp.Encryption().SessionKey(sessionKey).New()
	if err != nil {
		t.Fatalf("session enc: %v", err)
	}
	encMsg, err := sessionEnc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt block: %v", err)
	}
	encData := encMsg.Bytes()

	signHandle, err := pgp.Sign().SigningKeys(addrKR).Detached().New()
	if err != nil {
		t.Fatalf("sign handle: %v", err)
	}
	rawSig, err := signHandle.Sign(plaintext, crypto.Bytes)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigEncHandle, err := pgp.Encryption().Recipients(nodeKR).New()
	if err != nil {
		t.Fatalf("sig enc handle: %v", err)
	}
	encSig, err := sigEncHandle.Encrypt(rawSig)
	if err != nil {
		t.Fatalf("encrypt sig: %v", err)
	}
	encSigArmor, err := encSig.Armor()
	if err != nil {
		t.Fatalf("armor sig: %v", err)
	}

	// --- Download path: feed exactly what the server would store back into
	// decryptBlockIntoBuffer and check the round-trip. ---
	var out bytes.Buffer
	err = decryptBlockIntoBuffer(
		sessionKey,
		addrKR,
		nodeKR,
		hashB64(encData),
		encSigArmor,
		&out,
		io.NopCloser(bytes.NewReader(encData)),
	)
	if err != nil {
		t.Fatalf("decryptBlockIntoBuffer: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("round-trip plaintext mismatch (len got %d want %d)", out.Len(), len(plaintext))
	}
}
