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
	encSig, err := proton.EncryptMessageNonAead(nodeKR, rawSig, nil)
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

// newNodeKRv6 produces a v6 file node keyring the way the upload path does
// (generateLockedKey with aead=true), so it carries the same AEAD preferences
// as a real crypto-refresh file node key.
func newNodeKRv6(t *testing.T) *crypto.KeyRing {
	t.Helper()
	passphrase := []byte("test-passphrase")
	lockedArm, err := generateLockedKey("Drive key", "noreply@protonmail.com", passphrase, true)
	if err != nil {
		t.Fatalf("generate v6 node key: %v", err)
	}
	locked, err := crypto.NewKeyFromArmored(lockedArm)
	if err != nil {
		t.Fatalf("parse v6 node key: %v", err)
	}
	unlocked, err := locked.Unlock(passphrase)
	if err != nil {
		t.Fatalf("unlock v6 node key: %v", err)
	}
	if unlocked.GetVersion() != 6 {
		t.Fatalf("node key version: got %d, want 6", unlocked.GetVersion())
	}
	kr, err := crypto.NewKeyRing(unlocked)
	if err != nil {
		t.Fatalf("v6 node keyring: %v", err)
	}
	return kr
}

// checkNonAead asserts msg is in the pre-crypto-refresh wire format: a v3
// PKESK followed by a v1 SEIPD packet.
func checkNonAead(t *testing.T, label string, msg []byte) {
	t.Helper()
	r := packet.NewReader(bytes.NewReader(msg))
	p, err := r.Next()
	if err != nil {
		t.Fatalf("%s: read first packet: %v", label, err)
	}
	ek, ok := p.(*packet.EncryptedKey)
	if !ok {
		t.Fatalf("%s: first packet: got %T, want PKESK", label, p)
	}
	if ek.Version != 3 {
		t.Fatalf("%s: PKESK version: got %d, want 3", label, ek.Version)
	}
	p, err = r.Next()
	if err != nil {
		t.Fatalf("%s: read second packet: %v", label, err)
	}
	se, ok := p.(*packet.SymmetricallyEncrypted)
	if !ok {
		t.Fatalf("%s: second packet: got %T, want SEIPD", label, p)
	}
	if se.Version != 1 {
		t.Fatalf("%s: SEIPD version: got %d, want 1", label, se.Version)
	}
}

// TestAuxEncryptionNonAeadWithV6NodeKey checks that everything encrypted to a
// v6 file node key other than the block data stays in the pre-crypto-refresh
// format. The Proton clients cannot decrypt AEAD-encrypted auxiliary fields
// (xattr, block signatures, node passphrases), showing "the file or some of
// its data cannot be decrypted" in the web app, so the format must not follow
// the node key's AEAD preferences.
func TestAuxEncryptionNonAeadWithV6NodeKey(t *testing.T) {
	pgp := crypto.PGP()
	addrKR := newAddrKR(t)
	nodeKR := newNodeKRv6(t)

	// Block signature (as uploadFile does): old format.
	plaintext := []byte(strings.Repeat("hello proton drive ", 1000))
	signHandle, err := pgp.Sign().SigningKeys(addrKR).Detached().New()
	if err != nil {
		t.Fatalf("sign handle: %v", err)
	}
	rawSig, err := signHandle.Sign(plaintext, crypto.Bytes)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	encSig, err := proton.EncryptMessageNonAead(nodeKR, rawSig, nil)
	if err != nil {
		t.Fatalf("encrypt sig: %v", err)
	}
	checkNonAead(t, "block signature", encSig.Bytes())

	// Block data of a revision of an existing crypto-refresh file keeps the
	// v2 SEIPD format (driven by the stored v6 content key), and the download
	// path still verifies the old-format encrypted signature next to it.
	sessionKey, err := protonDrivePGP().GenerateSessionKey()
	if err != nil {
		t.Fatalf("generate v6 session key: %v", err)
	}
	sessionEnc, err := protonDrivePGP().Encryption().SessionKey(sessionKey).New()
	if err != nil {
		t.Fatalf("session enc: %v", err)
	}
	encMsg, err := sessionEnc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt block: %v", err)
	}
	encData := encMsg.Bytes()
	if se, ok := readFirstPacket(t, encData).(*packet.SymmetricallyEncrypted); !ok || se.Version != 2 {
		t.Fatalf("block data: want SEIPD version 2, got %#v", readFirstPacket(t, encData))
	}
	encSigArmor, err := encSig.Armor()
	if err != nil {
		t.Fatalf("armor sig: %v", err)
	}
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
		t.Fatalf("round-trip plaintext mismatch")
	}

	// Xattr (encrypted to the file node key by commitNewRevision): old format.
	var commitReq proton.CommitRevisionReq
	err = commitReq.SetEncXAttrString(addrKR, nodeKR, &proton.RevisionXAttrCommon{
		ModificationTime: "2026-08-01T00:00:00+0000",
		Size:             1234,
	})
	if err != nil {
		t.Fatalf("SetEncXAttrString: %v", err)
	}
	xattrMsg, err := crypto.NewPGPMessageFromArmored(commitReq.XAttr)
	if err != nil {
		t.Fatalf("unarmor xattr: %v", err)
	}
	checkNonAead(t, "xattr", xattrMsg.Bytes())

	// Node passphrase (generateNodeKeys encrypts it to the parent keyring —
	// exercised here with a v6 keyring to prove the format is pinned): old
	// format, and the detached signature must verify.
	_, nodePassphraseEnc, nodePassphraseSig, err := generateNodeKeys(nodeKR, addrKR, true)
	if err != nil {
		t.Fatalf("generateNodeKeys: %v", err)
	}
	passMsg, err := crypto.NewPGPMessageFromArmored(nodePassphraseEnc)
	if err != nil {
		t.Fatalf("unarmor passphrase: %v", err)
	}
	checkNonAead(t, "node passphrase", passMsg.Bytes())
	dec, err := pgp.Decryption().DecryptionKeys(nodeKR).New()
	if err != nil {
		t.Fatalf("dec handle: %v", err)
	}
	passPlain, err := dec.Decrypt(passMsg.Bytes(), crypto.Bytes)
	if err != nil {
		t.Fatalf("decrypt passphrase: %v", err)
	}
	verify, err := pgp.Verify().VerificationKeys(addrKR).New()
	if err != nil {
		t.Fatalf("verify handle: %v", err)
	}
	res, err := verify.VerifyDetached(passPlain.Bytes(), []byte(nodePassphraseSig), crypto.Armor)
	if err != nil {
		t.Fatalf("verify passphrase sig: %v", err)
	}
	if sigErr := res.SignatureError(); sigErr != nil {
		t.Fatalf("passphrase signature: %v", sigErr)
	}
}

// TestContentKeyPacketOldFormat checks that new files get a pre-crypto-refresh
// content key: a non-v6 session key wrapped in a v3 PKESK. Files rclone
// originates in the crypto-refresh format cannot be decrypted by the official
// Proton clients, so the new format must never be used at file creation, only
// followed on revisions of files that already use it.
func TestContentKeyPacketOldFormat(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		nodeKR := newNodeKR(t)
		if v6 {
			nodeKR = newNodeKRv6(t)
		}
		var req proton.CreateFileReq
		sessionKey, err := req.SetContentKeyPacketAndSignature(nodeKR)
		if err != nil {
			t.Fatalf("v6=%v: SetContentKeyPacketAndSignature: %v", v6, err)
		}
		contentKeyPacket, err := base64.StdEncoding.DecodeString(req.ContentKeyPacket)
		if err != nil {
			t.Fatalf("v6=%v: decode content key packet: %v", v6, err)
		}
		ek, ok := readFirstPacket(t, contentKeyPacket).(*packet.EncryptedKey)
		if !ok {
			t.Fatalf("v6=%v: content key packet: not a PKESK packet", v6)
		}
		if ek.Version != 3 {
			t.Fatalf("v6=%v: content key packet: got PKESK version %d, want 3", v6, ek.Version)
		}

		// A block encrypted with this session key must be a v1 SEIPD, even
		// through the crypto-refresh block-encryption handle the upload path
		// uses.
		sessionEnc, err := protonDrivePGP().Encryption().SessionKey(sessionKey).New()
		if err != nil {
			t.Fatalf("v6=%v: session enc: %v", v6, err)
		}
		encMsg, err := sessionEnc.Encrypt([]byte("block data"))
		if err != nil {
			t.Fatalf("v6=%v: encrypt block: %v", v6, err)
		}
		se, ok := readFirstPacket(t, encMsg.Bytes()).(*packet.SymmetricallyEncrypted)
		if !ok {
			t.Fatalf("v6=%v: block data: not a SEIPD packet", v6)
		}
		if se.Version != 1 {
			t.Fatalf("v6=%v: block data: got SEIPD version %d, want 1", v6, se.Version)
		}
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

// TestBlockEncryptCryptoRefresh checks the revision path for a file that
// already has a crypto-refresh content key (one created by an official Proton
// client with the new format): the stored v6 session key selects a v2 SEIPD
// data packet encrypted with AES-256-GCM, and the block still round-trips
// through decryptBlockIntoBuffer.
//
// New files do NOT use this format — see TestContentKeyPacketOldFormat and
// TestBlockEncryptDecryptRoundTrip for the creation path.
func TestBlockEncryptCryptoRefresh(t *testing.T) {
	pgp := crypto.PGP()

	addrKR := newAddrKR(t)
	nodeKR := newNodeKR(t)

	// A v6 session key, as decrypted from an existing crypto-refresh file's
	// stored content key packet.
	sessionKey, err := protonDrivePGP().GenerateSessionKey()
	if err != nil {
		t.Fatalf("generate v6 session key: %v", err)
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

	// The block signature stays in the pre-crypto-refresh format.
	signHandle, err := pgp.Sign().SigningKeys(addrKR).Detached().New()
	if err != nil {
		t.Fatalf("sign handle: %v", err)
	}
	rawSig, err := signHandle.Sign(plaintext, crypto.Bytes)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	encSig, err := proton.EncryptMessageNonAead(nodeKR, rawSig, nil)
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
