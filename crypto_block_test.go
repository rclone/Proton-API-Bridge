package proton_api_bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	proton "github.com/rclone/go-proton-api"
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

// readFirstPacket parses the first OpenPGP packet from b.
func readFirstPacket(t *testing.T, b []byte) packet.Packet {
	t.Helper()
	p, err := packet.Read(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	return p
}

// TestBlockEncryptCryptoRefresh checks that the upload path produces Proton
// Drive's new crypto-refresh (RFC 9580) file-content format: a v6 PKESK content
// key packet and a v2 SEIPD data packet encrypted with AES-256-GCM. It also
// round-trips the block back through decryptBlockIntoBuffer to confirm the new
// format is still readable by the download path.
func TestBlockEncryptCryptoRefresh(t *testing.T) {
	pgp := crypto.PGP()

	addrKR := newAddrKR(t)
	nodeKR := newNodeKR(t)

	// Build the content key packet the way go-proton-api does for an upload.
	// This yields the v6 session key and populates ContentKeyPacket with the
	// v6 PKESK.
	var req proton.CreateFileReq
	sessionKey, err := req.SetContentKeyPacketAndSignature(nodeKR)
	if err != nil {
		t.Fatalf("SetContentKeyPacketAndSignature: %v", err)
	}

	// The content key packet must be a v6 PKESK.
	contentKeyPacket, err := base64.StdEncoding.DecodeString(req.ContentKeyPacket)
	if err != nil {
		t.Fatalf("decode content key packet: %v", err)
	}
	ek, ok := readFirstPacket(t, contentKeyPacket).(*packet.EncryptedKey)
	if !ok {
		t.Fatalf("content key packet: not a PKESK packet")
	}
	if ek.Version != 6 {
		t.Fatalf("content key packet: got PKESK version %d, want 6", ek.Version)
	}

	plaintext := []byte(strings.Repeat("hello proton drive ", 1000))

	// --- Upload path: encrypt block (new format) + sign + encrypt signature ---
	sessionEnc, err := protonDrivePGP().Encryption().SessionKey(sessionKey).New()
	if err != nil {
		t.Fatalf("session enc: %v", err)
	}
	encMsg, err := sessionEnc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt block: %v", err)
	}
	encData := encMsg.Bytes()

	// The block data packet must be a v2 SEIPD using AES-256-GCM.
	se, ok := readFirstPacket(t, encData).(*packet.SymmetricallyEncrypted)
	if !ok {
		t.Fatalf("block data: got %T, want *packet.SymmetricallyEncrypted", readFirstPacket(t, encData))
	}
	if se.Version != 2 {
		t.Fatalf("block data: got SEIPD version %d, want 2", se.Version)
	}
	if se.Mode != packet.AEADModeGCM {
		t.Fatalf("block data: got AEAD mode %d, want GCM (%d)", se.Mode, packet.AEADModeGCM)
	}
	if se.Cipher != packet.CipherAES256 {
		t.Fatalf("block data: got cipher %d, want AES-256 (%d)", se.Cipher, packet.CipherAES256)
	}

	// Signature path is unchanged (default profile).
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

	// --- Download path: the new format must still decrypt cleanly. ---
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
