package proton_api_bridge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/rclone/go-proton-api"
)

const fileOrFolderNotFoundCode proton.Code = 2501

func buildVerificationToken(verificationCode, encData []byte) []byte {
	verificationToken := make([]byte, len(verificationCode))
	for idx := range verificationCode {
		if idx < len(encData) {
			verificationToken[idx] = verificationCode[idx] ^ encData[idx]
		} else {
			verificationToken[idx] = verificationCode[idx]
		}
	}

	return verificationToken
}

type revisionVerificationResult struct {
	VerificationCode string
	ContentKeyPacket string
}

type blockUploadClient interface {
	UploadBlock(context.Context, string, string, io.Reader) error
}

func uploadBlockWithClient(ctx context.Context, client blockUploadClient, bareURL, token string, block io.Reader) error {
	return client.UploadBlock(ctx, bareURL, token, block)
}

func setStringFieldIfPresent(target any, fieldName, value string) {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return
	}

	field := v.FieldByName(fieldName)
	if !field.IsValid() {
		switch fieldName {
		case "SignatureEmail", "NameSignatureEmail":
			field = v.FieldByName("SignatureAddress")
		}
	}
	if !field.IsValid() || !field.CanSet() || field.Kind() != reflect.String {
		return
	}

	field.SetString(value)
}

func setVerifierTokenIfPresent(info *proton.BlockUploadInfo, token string) {
	v := reflect.ValueOf(info)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	v = v.Elem()
	field := v.FieldByName("Verifier")
	if !field.IsValid() || !field.CanSet() || field.Kind() != reflect.Pointer {
		return
	}
	if field.Type().Elem().Kind() != reflect.Struct {
		return
	}

	verifier := reflect.New(field.Type().Elem())
	tokenField := verifier.Elem().FieldByName("Token")
	if !tokenField.IsValid() || !tokenField.CanSet() || tokenField.Kind() != reflect.String {
		return
	}

	tokenField.SetString(token)
	field.Set(verifier)
}

func collectUploadErrors(errChan <-chan error, count int, cancelUploads context.CancelFunc) error {
	var firstErr error
	for i := 0; i < count; i++ {
		err := <-errChan
		if err != nil && firstErr == nil {
			firstErr = err
			cancelUploads()
		}
	}

	return firstErr
}

func validateUploadBatchCardinality(uploadRespCount, pendingCount int) error {
	if uploadRespCount != pendingCount {
		return fmt.Errorf("request block upload returned %d links for %d pending blocks", uploadRespCount, pendingCount)
	}

	return nil
}

func getRevisionVerificationCompat(ctx context.Context, client any, shareID, volumeID, linkID, revisionID string) (revisionVerificationResult, error) {
	tryCall := func(methodName string, args ...any) (revisionVerificationResult, bool, error) {
		resultValues, called, err := findAndCallMethod(client, methodName, args...)
		if !called || err != nil {
			return revisionVerificationResult{}, called, err
		}

		if len(resultValues) != 2 {
			return revisionVerificationResult{}, true, newMethodCompatibilityError("%s has incompatible result count", methodName)
		}

		callErr, err := extractErrorResult(resultValues[1])
		if err != nil {
			return revisionVerificationResult{}, true, newMethodCompatibilityError("%s has incompatible error result: %w", methodName, err)
		}
		if callErr != nil {
			return revisionVerificationResult{}, true, callErr
		}

		result := resultValues[0]
		if result.Kind() == reflect.Pointer {
			if result.IsNil() {
				return revisionVerificationResult{}, true, newMethodCompatibilityError("%s returned nil result pointer", methodName)
			}
			result = result.Elem()
		}
		if result.Kind() != reflect.Struct {
			return revisionVerificationResult{}, true, newMethodCompatibilityError("%s returned non-struct result", methodName)
		}

		verificationCode := result.FieldByName("VerificationCode")
		contentKeyPacket := result.FieldByName("ContentKeyPacket")
		if !verificationCode.IsValid() || !contentKeyPacket.IsValid() || verificationCode.Kind() != reflect.String || contentKeyPacket.Kind() != reflect.String {
			return revisionVerificationResult{}, true, newMethodCompatibilityError("%s returned incompatible verification fields", methodName)
		}

		return revisionVerificationResult{
			VerificationCode: verificationCode.String(),
			ContentKeyPacket: contentKeyPacket.String(),
		}, true, nil
	}

	var compatErr error

	byVolumeRes, called, err := tryCall("GetRevisionVerificationByVolume", ctx, volumeID, linkID, revisionID)
	if called {
		if err == nil {
			return byVolumeRes, nil
		}
		if !isMethodCompatibilityError(err) {
			return byVolumeRes, err
		}
		compatErr = err
	}

	byShareRes, called, err := tryCall("GetRevisionVerification", ctx, shareID, linkID, revisionID)
	if called {
		if err == nil {
			return byShareRes, nil
		}
		if !isMethodCompatibilityError(err) {
			return byShareRes, err
		}
		if compatErr == nil {
			compatErr = err
		}
	}

	if compatErr != nil {
		return revisionVerificationResult{}, compatErr
	}

	return revisionVerificationResult{}, nil
}

func recoverBrokenConflictState(err error, linkState proton.LinkState, deleteStaleLink func() error) (bool, error) {
	apiErr := new(proton.APIError)
	if !errors.As(err, &apiErr) || apiErr.Code != fileOrFolderNotFoundCode || linkState != proton.LinkStateDraft {
		return false, err
	}

	if deleteErr := deleteStaleLink(); deleteErr != nil {
		return false, deleteErr
	}

	return true, nil
}

func (protonDrive *ProtonDrive) handleRevisionConflict(ctx context.Context, link *proton.Link, createFileResp *proton.CreateFileRes) (string, bool, error) {
	if link != nil {
		linkID := link.LinkID

		draftRevision, err := protonDrive.GetRevisions(ctx, link, proton.RevisionStateDraft)
		if err != nil {
			shouldRecreateDraft, recoveredErr := recoverBrokenConflictState(err, link.State, func() error {
				return protonDrive.c.DeleteChildren(ctx, protonDrive.MainShare.ShareID, link.ParentLinkID, linkID)
			})
			if shouldRecreateDraft {
				// Link is in a broken conflict state (name reserved but no readable revisions).
				// Delete the stale link and recreate draft from scratch.
				return "", true, nil
			}

			return "", false, recoveredErr
		}

		// if we have a draft revision, depending on the user config, we can abort the upload or recreate a draft
		// if we have no draft revision, then we can create a new draft revision directly (there is a restriction of 1 draft revision per file)
		if len(draftRevision) > 0 {
			// TODO: maintain clientUID to mark that this is our own draft (which can indicate failed upload attempt!)
			if protonDrive.Config.ReplaceExistingDraft {
				// Question: how do we observe for file upload cancellation -> clientUID?
				// Random thoughts: if there are concurrent modification to the draft, the server should be able to catch this when commiting the revision
				// since the manifestSignature (hash) will fail to match

				// delete the draft revision (will fail if the file only have a draft but no active revisions)
				if link.State == proton.LinkStateDraft {
					// delete the link (skipping trash, otherwise it won't work)
					err = protonDrive.c.DeleteChildren(ctx, protonDrive.MainShare.ShareID, link.ParentLinkID, linkID)
					if err != nil {
						return "", false, err
					}

					return "", true, nil
				}

				// delete the draft revision
				err = protonDrive.c.DeleteRevision(ctx, protonDrive.MainShare.ShareID, linkID, draftRevision[0].ID)
				if err != nil {
					return "", false, err
				}
			} else {
				// if there is a draft, based on the web behavior, it will ask if the user wants to replace the failed upload attempt
				// current behavior, we report an error to not upload the file (conservative)
				return "", false, ErrDraftExists
			}
		}

		// create a new revision
		newRevision, err := protonDrive.c.CreateRevision(ctx, protonDrive.MainShare.ShareID, linkID)
		if err != nil {
			return "", false, err
		}

		return newRevision.ID, false, nil
	} else if createFileResp != nil {
		return createFileResp.RevisionID, false, nil
	} else {
		// should not happen anymore, since the file search will include the draft now
		return "", false, ErrInternalErrorOnFileUpload
	}
}

func (protonDrive *ProtonDrive) createFileUploadDraft(ctx context.Context, parentLink *proton.Link, filename string, modTime time.Time, mimeType string) (string, string, *crypto.SessionKey, *crypto.KeyRing, error) {
	parentNodeKR, err := protonDrive.getLinkKR(ctx, parentLink)
	if err != nil {
		return "", "", nil, nil, err
	}

	/*
		Encryption: parent link's node key
		Signature: share's signature address keys
	*/
	newNodeKey, newNodePassphraseEnc, newNodePassphraseSignature, err := generateNodeKeys(parentNodeKR, protonDrive.DefaultAddrKR)
	if err != nil {
		return "", "", nil, nil, err
	}

	createFileReq := proton.CreateFileReq{
		ParentLinkID: parentLink.LinkID,

		// Name     string // Encrypted File Name
		// Hash     string // Encrypted File Name hash
		MIMEType: mimeType, // MIME Type

		// ContentKeyPacket          string // The block's key packet, encrypted with the node key.
		// ContentKeyPacketSignature string // Unencrypted signature of the content session key, signed with the NodeKey

		NodeKey:                 newNodeKey,                 // The private NodeKey, used to decrypt any file/folder content.
		NodePassphrase:          newNodePassphraseEnc,       // The passphrase used to unlock the NodeKey, encrypted by the owning Link/Share keyring.
		NodePassphraseSignature: newNodePassphraseSignature, // The signature of the NodePassphrase

		SignatureAddress: protonDrive.signatureAddress, // Signature email address used to sign passphrase and name
	}

	/*
		Encryption: parent link's node key
		Signature: share's signature address keys
	*/
	err = createFileReq.SetName(filename, protonDrive.DefaultAddrKR, parentNodeKR)
	if err != nil {
		return "", "", nil, nil, err
	}

	/*
		Encryption: parent link's node key
		Signature: parent link's node key
	*/
	signatureVerificationKR, err := protonDrive.getSignatureVerificationKeyring([]string{parentLink.SignatureEmail}, parentNodeKR)
	if err != nil {
		return "", "", nil, nil, err
	}
	parentHashKey, err := parentLink.GetHashKey(parentNodeKR, signatureVerificationKR)
	if err != nil {
		return "", "", nil, nil, err
	}

	/* Use parent's hash key */
	err = createFileReq.SetHash(filename, parentHashKey)
	if err != nil {
		return "", "", nil, nil, err
	}

	/*
		Encryption: parent link's node key
		Signature: share's signature address keys
	*/
	newNodeKR, err := getKeyRing(parentNodeKR, protonDrive.DefaultAddrKR, newNodeKey, newNodePassphraseEnc, newNodePassphraseSignature)
	if err != nil {
		return "", "", nil, nil, err
	}

	/*
		Encryption: current link's node key
		Signature: share's signature address keys
	*/
	newSessionKey, err := createFileReq.SetContentKeyPacketAndSignature(newNodeKR)
	if err != nil {
		return "", "", nil, nil, err
	}

	createFileAction := func() (*proton.CreateFileRes, *proton.Link, error) {
		createFileResp, err := protonDrive.c.CreateFile(ctx, protonDrive.MainShare.ShareID, createFileReq)
		if err != nil {
			// FIXME: check for duplicated filename by relying on checkAvailableHashes -> able to retrieve linkID too
			// Also saving generating resources such as new nodeKR, etc.

			if err != proton.ErrFileNameExist {
				// other real error caught
				return nil, nil, err
			}

			// search for the link within this folder which has an active/draft revision as we have a file creation conflict
			link, err := protonDrive.SearchByNameInActiveFolder(ctx, parentLink, filename, true, false, proton.LinkStateActive)
			if err != nil {
				return nil, nil, err
			}

			if link == nil {
				link, err = protonDrive.SearchByNameInActiveFolder(ctx, parentLink, filename, true, false, proton.LinkStateDraft)
				if err != nil {
					return nil, nil, err
				}

				if link == nil {
					// we have a real problem here (unless the assumption is wrong)
					// since we can't create a new file AND we can't locate a file with active/draft revision in it
					return nil, nil, ErrCantLocateRevision
				}
			}

			return nil, link, nil
		}

		return &createFileResp, nil, nil
	}

	createFileResp, link, err := createFileAction()
	if err != nil {
		return "", "", nil, nil, err
	}

	revisionID, shouldSubmitCreateFileRequestAgain, err := protonDrive.handleRevisionConflict(ctx, link, createFileResp)
	if err != nil {
		return "", "", nil, nil, err
	}

	if shouldSubmitCreateFileRequestAgain {
		// the case where the link has only a draft but no active revision
		// we need to delete the link and recreate one
		// this path runs at most once to avoid unbounded create/retry loops
		createFileResp, link, err = createFileAction()
		if err != nil {
			return "", "", nil, nil, err
		}

		revisionID, _, err = protonDrive.handleRevisionConflict(ctx, link, createFileResp)
		if err != nil {
			return "", "", nil, nil, err
		}
	}

	linkID := ""
	if link != nil {
		linkID = link.LinkID

		// get original sessionKey and nodeKR for the current link
		parentNodeKR, err = protonDrive.getLinkKRByID(ctx, link.ParentLinkID)
		if err != nil {
			return "", "", nil, nil, err
		}
		signatureVerificationKR, err := protonDrive.getSignatureVerificationKeyring([]string{link.SignatureEmail})
		if err != nil {
			return "", "", nil, nil, err
		}
		newNodeKR, err = link.GetKeyRing(parentNodeKR, signatureVerificationKR)
		if err != nil {
			return "", "", nil, nil, err
		}
		newSessionKey, err = link.GetSessionKey(newNodeKR)
		if err != nil {
			return "", "", nil, nil, err
		}
	} else {
		linkID = createFileResp.ID
	}

	return linkID, revisionID, newSessionKey, newNodeKR, nil
}

func (protonDrive *ProtonDrive) uploadAndCollectBlockData(ctx context.Context, newSessionKey *crypto.SessionKey, newNodeKR *crypto.KeyRing, file io.Reader, linkID, revisionID string) ([]byte, int64, []int64, string, error) {
	type PendingUploadBlocks struct {
		blockUploadInfo proton.BlockUploadInfo
		encData         []byte
	}

	if newSessionKey == nil || newNodeKR == nil {
		return nil, 0, nil, "", ErrMissingInputUploadAndCollectBlockData
	}

	totalFileSize := int64(0)

	verificationRes, err := getRevisionVerificationCompat(ctx, protonDrive.c, protonDrive.MainShare.ShareID, protonDrive.MainShare.VolumeID, linkID, revisionID)
	if err != nil {
		return nil, 0, nil, "", err
	}
	verificationCode, err := base64.StdEncoding.DecodeString(verificationRes.VerificationCode)
	if err != nil {
		return nil, 0, nil, "", err
	}

	pendingUploadBlocks := make([]PendingUploadBlocks, 0)
	manifestSignatureData := make([]byte, 0)
	uploadPendingBlocks := func() error {
		if len(pendingUploadBlocks) == 0 {
			return nil
		}

		blockList := make([]proton.BlockUploadInfo, 0)
		for i := range pendingUploadBlocks {
			blockList = append(blockList, pendingUploadBlocks[i].blockUploadInfo)
		}
		blockUploadReq := proton.BlockUploadReq{
			AddressID:  protonDrive.MainShare.AddressID,
			ShareID:    protonDrive.MainShare.ShareID,
			LinkID:     linkID,
			RevisionID: revisionID,

			BlockList: blockList,
		}
		setStringFieldIfPresent(&blockUploadReq, "VolumeID", protonDrive.MainShare.VolumeID)
		blockUploadResp, err := protonDrive.c.RequestBlockUpload(ctx, blockUploadReq)
		if err != nil {
			return err
		}
		if err := validateUploadBatchCardinality(len(blockUploadResp), len(pendingUploadBlocks)); err != nil {
			return err
		}

		uploadCtx, cancelUploads := context.WithCancel(ctx)
		defer cancelUploads()

		errChan := make(chan error, len(blockUploadResp))
		uploadBlockWrapper := func(ctx context.Context, errChan chan error, bareURL, token string, block io.Reader) {
			// log.Println("Before semaphore")
			if err := protonDrive.blockUploadSemaphore.Acquire(ctx, 1); err != nil {
				errChan <- err
				return
			}
			defer protonDrive.blockUploadSemaphore.Release(1)
			// log.Println("After semaphore")
			// defer log.Println("Release semaphore")

			errChan <- uploadBlockWithClient(ctx, protonDrive.c, bareURL, token, block)
		}
		for i := range blockUploadResp {
			go uploadBlockWrapper(uploadCtx, errChan, blockUploadResp[i].BareURL, blockUploadResp[i].Token, bytes.NewReader(pendingUploadBlocks[i].encData))
		}

		if err := collectUploadErrors(errChan, len(blockUploadResp), cancelUploads); err != nil {
			return err
		}

		pendingUploadBlocks = pendingUploadBlocks[:0]

		return nil
	}

	shouldContinue := true
	sha1Digests := sha1.New()
	blockSizes := make([]int64, 0)
	for i := 1; shouldContinue; i++ {
		if (i-1) > 0 && (i-1)%UPLOAD_BATCH_BLOCK_SIZE == 0 {
			err := uploadPendingBlocks()
			if err != nil {
				return nil, 0, nil, "", err
			}
		}

		// read at most data of size UPLOAD_BLOCK_SIZE
		// for some reason, .Read might not actually read up to buffer size -> use io.ReadFull
		data := make([]byte, UPLOAD_BLOCK_SIZE) // FIXME: get block size from the server config instead of hardcoding it
		readBytes, err := io.ReadFull(file, data)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// might still have data to read!
				if readBytes == 0 {
					break
				}
				shouldContinue = false
			} else {
				// all other errors
				return nil, 0, nil, "", err
			}
		}
		data = data[:readBytes]
		totalFileSize += int64(readBytes)
		sha1Digests.Write(data)
		blockSizes = append(blockSizes, int64(readBytes))

		// encrypt block data
		/*
			Encryption: current link's session key
			Signature: share's signature address keys
		*/
		dataPlainMessage := crypto.NewPlainMessage(data)
		encData, err := newSessionKey.Encrypt(dataPlainMessage)
		if err != nil {
			return nil, 0, nil, "", err
		}

		encSignature, err := protonDrive.DefaultAddrKR.SignDetachedEncrypted(dataPlainMessage, newNodeKR)
		if err != nil {
			return nil, 0, nil, "", err
		}
		encSignatureStr, err := encSignature.GetArmored()
		if err != nil {
			return nil, 0, nil, "", err
		}

		h := sha256.New()
		h.Write(encData)
		hash := h.Sum(nil)
		base64Hash := base64.StdEncoding.EncodeToString(hash)
		if err != nil {
			return nil, 0, nil, "", err
		}
		manifestSignatureData = append(manifestSignatureData, hash...)

		blockUploadInfo := proton.BlockUploadInfo{
			Index:        i, // iOS drive: BE starts with 1
			Size:         int64(len(encData)),
			EncSignature: encSignatureStr,
			Hash:         base64Hash,
		}
		if len(verificationCode) > 0 {
			verificationToken := buildVerificationToken(verificationCode, encData)
			setVerifierTokenIfPresent(&blockUploadInfo, base64.StdEncoding.EncodeToString(verificationToken))
		}

		pendingUploadBlocks = append(pendingUploadBlocks, PendingUploadBlocks{
			blockUploadInfo: blockUploadInfo,
			encData:         encData,
		})
	}
	err = uploadPendingBlocks()
	if err != nil {
		return nil, 0, nil, "", err
	}

	sha1Hash := sha1Digests.Sum(nil)
	sha1String := hex.EncodeToString(sha1Hash)
	return manifestSignatureData, totalFileSize, blockSizes, sha1String, nil
}

func (protonDrive *ProtonDrive) commitNewRevision(ctx context.Context, nodeKR *crypto.KeyRing, xAttrCommon *proton.RevisionXAttrCommon, manifestSignatureData []byte, linkID, revisionID string) error {
	manifestSignature, err := protonDrive.DefaultAddrKR.SignDetached(crypto.NewPlainMessage(manifestSignatureData))
	if err != nil {
		return err
	}
	manifestSignatureString, err := manifestSignature.GetArmored()
	if err != nil {
		return err
	}

	commitRevisionReq := proton.CommitRevisionReq{
		ManifestSignature: manifestSignatureString,
		SignatureAddress:  protonDrive.signatureAddress,
	}

	err = commitRevisionReq.SetEncXAttrString(protonDrive.DefaultAddrKR, nodeKR, xAttrCommon)
	if err != nil {
		return err
	}

	err = protonDrive.c.CommitRevision(ctx, protonDrive.MainShare.ShareID, linkID, revisionID, commitRevisionReq)
	if err != nil {
		return err
	}

	return nil
}

// testParam is for integration test only
// 0 = normal mode
// 1 = up to create revision
// 2 = up to block upload
func (protonDrive *ProtonDrive) uploadFile(ctx context.Context, parentLink *proton.Link, filename string, modTime time.Time, file io.Reader, testParam int) (string, *proton.RevisionXAttrCommon, error) {
	// TODO: if we should use github.com/gabriel-vasile/mimetype to detect the MIME type from the file content itself
	// Note: this approach might cause the upload progress to display the "fake" progress, since we read in all the content all-at-once
	// mimetype.SetLimit(0)
	// mType := mimetype.Detect(fileContent)
	// mimeType := mType.String()

	// detect MIME type by looking at the filename only
	mimeType := mime.TypeByExtension(filepath.Ext(filename))
	if mimeType == "" {
		// api requires a mime type passed in
		mimeType = "text/plain"
	}

	/* step 1: create a draft */
	linkID, revisionID, newSessionKey, newNodeKR, err := protonDrive.createFileUploadDraft(ctx, parentLink, filename, modTime, mimeType)
	if err != nil {
		return "", nil, err
	}

	if testParam == 1 {
		return "", nil, nil
	}

	/* step 2: upload blocks and collect block data */
	manifestSignature, fileSize, blockSizes, digests, err := protonDrive.uploadAndCollectBlockData(ctx, newSessionKey, newNodeKR, file, linkID, revisionID)
	if err != nil {
		return "", nil, err
	}

	if testParam == 2 {
		// for integration tests
		// we try to simulate blocks uploaded but not yet commited
		return "", nil, nil
	}

	/* step 3: mark the file as active by commiting the revision */
	xAttrCommon := &proton.RevisionXAttrCommon{
		ModificationTime: modTime.Format("2006-01-02T15:04:05-0700"), /* ISO8601 */
		Size:             fileSize,
		BlockSizes:       blockSizes,
		Digests: map[string]string{
			"SHA1": digests,
		},
	}
	err = protonDrive.commitNewRevision(ctx, newNodeKR, xAttrCommon, manifestSignature, linkID, revisionID)
	if err != nil {
		return "", nil, err
	}

	return linkID, xAttrCommon, nil
}

func (protonDrive *ProtonDrive) UploadFileByReader(ctx context.Context, parentLinkID string, filename string, modTime time.Time, file io.Reader, testParam int) (string, *proton.RevisionXAttrCommon, error) {
	parentLink, err := protonDrive.getLink(ctx, parentLinkID)
	if err != nil {
		return "", nil, err
	}

	return protonDrive.uploadFile(ctx, parentLink, filename, modTime, file, testParam)
}

func (protonDrive *ProtonDrive) UploadFileByPath(ctx context.Context, parentLink *proton.Link, filename string, filePath string, testParam int) (string, *proton.RevisionXAttrCommon, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()

	info, err := os.Stat(filePath)
	if err != nil {
		return "", nil, err
	}

	in := bufio.NewReader(f)

	return protonDrive.uploadFile(ctx, parentLink, filename, info.ModTime(), in, testParam)
}

/*
There is a route that proton-go-api doesn't have - checkAvailableHashes.
This is used to quickly find the next available filename when the originally supplied filename is taken in the current folder.

Based on the code below, which is taken from the Proton iOS Drive app, we can infer that:
- when a file is to be uploaded && there is filename conflict after the first upload:
	- on web, user will be prompted with a) overwrite b) keep both by appending filename with iteration number c) do nothing
- on the iOS client logic, we can see that when the filename conflict happens (after the upload attampt failed)
	- the filename will be hashed by using filename + iteration
	- 10 iterations will be done per batch, each iteration's hash will be sent to the server
	- the server will return available hashes, and the client will take the lowest iteration as the filename to be used
	- will be used to search for the next available filename (using hashes avoids the filename being known to the server)
*/
