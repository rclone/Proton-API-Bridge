package proton_api_bridge

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func TestReencryptKeyPacketPreservesSessionKey(t *testing.T) {
	srcKR := newTestKeyRing(t)
	dstKR := newTestKeyRing(t)
	addrKR := newTestKeyRing(t)

	_, originalPassphrase, _, err := generateNodeKeys(srcKR, addrKR)
	if err != nil {
		t.Fatalf("generateNodeKeys: %v", err)
	}

	originalSplit, err := crypto.NewPGPSplitMessageFromArmored(originalPassphrase)
	if err != nil {
		t.Fatalf("parse original passphrase: %v", err)
	}
	originalSessionKey, err := srcKR.DecryptSessionKey(originalSplit.GetBinaryKeyPacket())
	if err != nil {
		t.Fatalf("decrypt original session key: %v", err)
	}

	reencryptedPassphrase, _, err := reencryptKeyPacket(srcKR, dstKR, addrKR, originalPassphrase)
	if err != nil {
		t.Fatalf("reencryptKeyPacket: %v", err)
	}

	reencryptedSplit, err := crypto.NewPGPSplitMessageFromArmored(reencryptedPassphrase)
	if err != nil {
		t.Fatalf("parse reencrypted passphrase: %v", err)
	}
	reencryptedSessionKey, err := dstKR.DecryptSessionKey(reencryptedSplit.GetBinaryKeyPacket())
	if err != nil {
		t.Fatalf("decrypt reencrypted session key: %v", err)
	}

	if originalSessionKey.GetBase64Key() != reencryptedSessionKey.GetBase64Key() {
		t.Fatalf("expected session key to be preserved")
	}
	if originalSessionKey.Algo != reencryptedSessionKey.Algo {
		t.Fatalf("expected session key algo %q, got %q", originalSessionKey.Algo, reencryptedSessionKey.Algo)
	}
}

func newTestKeyRing(t *testing.T) *crypto.KeyRing {
	t.Helper()

	passphrase := []byte("test-passphrase")
	armoredKey, err := helper.GenerateKey("Test", "test@example.com", passphrase, "x25519", 0)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := crypto.NewKeyFromArmored(armoredKey)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	unlockedKey, err := key.Unlock(passphrase)
	if err != nil {
		t.Fatalf("unlock key: %v", err)
	}
	kr, err := crypto.NewKeyRing(unlockedKey)
	if err != nil {
		t.Fatalf("new key ring: %v", err)
	}

	return kr
}
