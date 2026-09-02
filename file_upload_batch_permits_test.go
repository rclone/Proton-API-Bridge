package proton_api_bridge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/rclone/go-proton-api"
	"golang.org/x/sync/semaphore"
)

func TestFailedBlockBatchReleasesEverySemaphorePermit(t *testing.T) {
	originalBlockSize := UPLOAD_BLOCK_SIZE
	originalBatchSize := UPLOAD_BATCH_BLOCK_SIZE
	UPLOAD_BLOCK_SIZE = 16
	UPLOAD_BATCH_BLOCK_SIZE = 2
	t.Cleanup(func() {
		UPLOAD_BLOCK_SIZE = originalBlockSize
		UPLOAD_BATCH_BLOCK_SIZE = originalBatchSize
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/drive/blocks":
			_, err := io.WriteString(w, fmt.Sprintf(
				`{"Code":1000,"UploadLinks":[{"Token":"error-token","BareURL":%q},{"Token":"success-token","BareURL":%q}]}`,
				serverURL(r, "/storage/blocks/error"),
				serverURL(r, "/storage/blocks/success"),
			))
			if err != nil {
				t.Error(err)
			}
		case "/storage/blocks/error":
			w.WriteHeader(http.StatusBadGateway)
			_, err := io.WriteString(w, `{"Code":0,"Error":"simulated bad gateway"}`)
			if err != nil {
				t.Error(err)
			}
		case "/storage/blocks/success":
			time.Sleep(100 * time.Millisecond)
			_, err := io.WriteString(w, `{"Code":1000}`)
			if err != nil {
				t.Error(err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	manager := proton.New(
		proton.WithHostURL(server.URL),
		proton.WithRetryCount(0),
	)
	defer manager.Close()
	client := manager.NewClient("", "", "")
	defer client.Close()

	pgp := crypto.PGP()
	signingKey, err := pgp.KeyGeneration().AddUserId("test", "test@example.com").New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signingKeyRing, err := crypto.NewKeyRing(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := pgp.KeyGeneration().AddUserId("node", "node@example.com").New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	nodeKeyRing, err := crypto.NewKeyRing(nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey, err := pgp.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}

	blockSemaphore := semaphore.NewWeighted(2)
	drive := &ProtonDrive{
		MainShare: &proton.Share{
			ShareMetadata: proton.ShareMetadata{ShareID: "share-id"},
			AddressID:     "address-id",
		},
		DefaultAddrKR:        signingKeyRing,
		c:                    client,
		blockUploadSemaphore: blockSemaphore,
	}

	_, _, _, _, err = drive.uploadAndCollectBlockData(
		context.Background(),
		sessionKey,
		nodeKeyRing,
		bytes.NewReader([]byte("0123456789abcdef0123456789abcdef")),
		"link-id",
		"revision-id",
	)
	if err == nil {
		t.Fatal("expected failed block upload")
	}

	acquireCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := blockSemaphore.Acquire(acquireCtx, 2); err != nil {
		t.Fatalf("failed batch leaked a block-upload permit: %v", err)
	}
	blockSemaphore.Release(2)
}

func serverURL(r *http.Request, path string) string {
	return "http://" + r.Host + path
}
