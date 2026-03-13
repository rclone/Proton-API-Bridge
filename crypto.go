package proton_api_bridge

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func generatePassphrase() (string, error) {
	token, err := crypto.RandomToken(32)
	if err != nil {
		return "", err
	}

	tokenBase64 := base64.StdEncoding.EncodeToString(token)
	return tokenBase64, nil
}

func generateCryptoKey() (string, string, error) {
	passphrase, err := generatePassphrase()
	if err != nil {
		return "", "", err
	}

	// all hardcoded values from iOS drive
	key, err := helper.GenerateKey("Drive key", "noreply@protonmail.com", []byte(passphrase), "x25519", 0)
	if err != nil {
		return "", "", err
	}

	return passphrase, key, nil
}

// taken from Proton Go API Backend
func encryptWithSignature(kr, addrKR *crypto.KeyRing, b []byte) (string, string, error) {
	enc, err := kr.Encrypt(crypto.NewPlainMessage(b), nil)
	if err != nil {
		return "", "", err
	}

	encArm, err := enc.GetArmored()
	if err != nil {
		return "", "", err
	}

	sig, err := addrKR.SignDetached(crypto.NewPlainMessage(b))
	if err != nil {
		return "", "", err
	}

	sigArm, err := sig.GetArmored()
	if err != nil {
		return "", "", err
	}

	return encArm, sigArm, nil
}

func generateNodeKeys(kr, addrKR *crypto.KeyRing) (string, string, string, error) {
	nodePassphrase, nodeKey, err := generateCryptoKey()
	if err != nil {
		return "", "", "", err
	}

	nodePassphraseEnc, nodePassphraseSignature, err := encryptWithSignature(kr, addrKR, []byte(nodePassphrase))
	if err != nil {
		return "", "", "", err
	}

	return nodeKey, nodePassphraseEnc, nodePassphraseSignature, nil
}

func reencryptKeyPacket(srcKR, dstKR, addrKR *crypto.KeyRing, passphrase string) (string, error) {
	oldSplitMessage, err := crypto.NewPGPSplitMessageFromArmored(passphrase)
	if err != nil {
		return "", err
	}

	sessionKey, err := srcKR.DecryptSessionKey(oldSplitMessage.KeyPacket)
	if err != nil {
		return "", err
	}

	newKeyPacket, err := dstKR.EncryptSessionKey(sessionKey)
	if err != nil {
		return "", err
	}

	newSplitMessage := crypto.NewPGPSplitMessage(newKeyPacket, oldSplitMessage.DataPacket)

	return newSplitMessage.GetArmored()
}

func getKeyRing(kr, addrKR *crypto.KeyRing, key, passphrase, passphraseSignature string) (*crypto.KeyRing, error) {
	enc, err := crypto.NewPGPMessageFromArmored(passphrase)
	if err != nil {
		return nil, err
	}

	dec, err := kr.Decrypt(enc, nil, crypto.GetUnixTime())
	if err != nil {
		return nil, err
	}

	sig, err := crypto.NewPGPSignatureFromArmored(passphraseSignature)
	if err != nil {
		return nil, err
	}

	if err := addrKR.VerifyDetached(dec, sig, crypto.GetUnixTime()); err != nil {
		return nil, err
	}

	lockedKey, err := crypto.NewKeyFromArmored(key)
	if err != nil {
		return nil, err
	}

	unlockedKey, err := lockedKey.Unlock(dec.GetBinary())
	if err != nil {
		return nil, err
	}

	return crypto.NewKeyRing(unlockedKey)
}

func decryptBlockIntoBuffer(sessionKey *crypto.SessionKey, addrKR, nodeKR *crypto.KeyRing, originalHash, encSignature string, buffer io.ReaderFrom, block io.ReadCloser) error {
	data, err := io.ReadAll(block)
	if err != nil {
		return err
	}

	plainMessage, err := sessionKey.Decrypt(data)
	if err != nil {
		return err
	}

	encSignatureArm, err := crypto.NewPGPMessageFromArmored(encSignature)
	if err != nil {
		return err
	}

	err = addrKR.VerifyDetachedEncrypted(plainMessage, encSignatureArm, nodeKR, crypto.GetUnixTime())
	if err != nil {
		return err
	}

	_, err = buffer.ReadFrom(plainMessage.NewReader())
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write(data)
	hash := h.Sum(nil)
	base64Hash := base64.StdEncoding.EncodeToString(hash)
	if err != nil {
		return err
	}
	if base64Hash != originalHash {
		return ErrDownloadedBlockHashVerificationFailed
	}

	return nil
}

// decryptSessionKey tries multiple keyrings to decrypt a session key.
// Fallback chain: srcParentKR -> addrKR -> userKR
func decryptSessionKey(keyPacket []byte, candidates ...*crypto.KeyRing) (*crypto.SessionKey, error) {
	var err error
	tried := false
	for _, kr := range candidates {
		if kr == nil {
			continue
		}
		tried = true
		var sk *crypto.SessionKey
		sk, err = kr.DecryptSessionKey(keyPacket)
		if err == nil {
			return sk, nil
		}
	}
	if !tried {
		return nil, fmt.Errorf("decryptSessionKey: no non-nil keyrings provided")
	}
	return nil, err
}

// ReEncryptPassphrase re-encrypts a node passphrase to a new parent
// keyring while reusing the original symmetric session key.
func ReEncryptPassphrase(armoredPassphrase string, srcParentKR, dstParentKR, addrKR, userKR *crypto.KeyRing) (string, error) {
	split, err := crypto.NewPGPSplitMessageFromArmored(armoredPassphrase)
	if err != nil {
		return "", fmt.Errorf("reEncryptPassphrase: split: %w", err)
	}

	sk, err := decryptSessionKey(split.GetBinaryKeyPacket(), srcParentKR, addrKR, userKR)
	if err != nil {
		return "", fmt.Errorf("reEncryptPassphrase: decrypt session key: %w", err)
	}

	newKeyPacket, err := dstParentKR.EncryptSessionKey(sk)
	if err != nil {
		return "", fmt.Errorf("reEncryptPassphrase: encrypt session key: %w", err)
	}

	armored, err := crypto.NewPGPSplitMessage(newKeyPacket, split.GetBinaryDataPacket()).GetArmored()
	if err != nil {
		return "", fmt.Errorf("reEncryptPassphrase: armor: %w", err)
	}
	return armored, nil
}

// ReEncryptName re-encrypts a node name for a new parent keyring while
// reusing the original name session key and optionally changing the plaintext.
func ReEncryptName(armoredName, newName string, srcParentKR, dstParentKR, addrKR, userKR *crypto.KeyRing) (string, error) {
	split, err := crypto.NewPGPSplitMessageFromArmored(armoredName)
	if err != nil {
		return "", fmt.Errorf("reEncryptName: split: %w", err)
	}

	sk, err := decryptSessionKey(split.GetBinaryKeyPacket(), srcParentKR, addrKR, userKR)
	if err != nil {
		return "", fmt.Errorf("reEncryptName: decrypt session key: %w", err)
	}

	dataPacket, err := sk.EncryptAndSign(crypto.NewPlainMessageFromString(newName), addrKR)
	if err != nil {
		return "", fmt.Errorf("reEncryptName: encrypt: %w", err)
	}

	newKeyPacket, err := dstParentKR.EncryptSessionKey(sk)
	if err != nil {
		return "", fmt.Errorf("reEncryptName: encrypt session key: %w", err)
	}

	return crypto.NewPGPSplitMessage(newKeyPacket, dataPacket).GetArmored()
}
