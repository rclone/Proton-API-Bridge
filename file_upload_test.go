package proton_api_bridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/rclone/go-proton-api"
)

type revisionVerificationByVolumeOnlyClient struct {
	calledByVolume bool
}

type fakeRevisionVerification struct {
	VerificationCode string
	ContentKeyPacket string
}

func (c *revisionVerificationByVolumeOnlyClient) GetRevisionVerificationByVolume(context.Context, string, string, string) (fakeRevisionVerification, error) {
	c.calledByVolume = true
	return fakeRevisionVerification{VerificationCode: "vol", ContentKeyPacket: "pkt"}, nil
}

type revisionVerificationByShareOnlyClient struct {
	calledByShare bool
}

func (c *revisionVerificationByShareOnlyClient) GetRevisionVerification(context.Context, string, string, string) (fakeRevisionVerification, error) {
	c.calledByShare = true
	return fakeRevisionVerification{VerificationCode: "share", ContentKeyPacket: "pkt"}, nil
}

type revisionVerificationInvalidSignatureClient struct{}

func (c *revisionVerificationInvalidSignatureClient) GetRevisionVerificationByVolume(context.Context, string) (fakeRevisionVerification, error) {
	return fakeRevisionVerification{}, nil
}

type revisionVerificationInvalidVolumeFallbackClient struct {
	calledByShare bool
}

func (c *revisionVerificationInvalidVolumeFallbackClient) GetRevisionVerificationByVolume(context.Context, string) (fakeRevisionVerification, error) {
	return fakeRevisionVerification{}, nil
}

func (c *revisionVerificationInvalidVolumeFallbackClient) GetRevisionVerification(context.Context, string, string, string) (fakeRevisionVerification, error) {
	c.calledByShare = true
	return fakeRevisionVerification{VerificationCode: "share", ContentKeyPacket: "pkt"}, nil
}

type revisionVerificationPanicClient struct{}

func (c *revisionVerificationPanicClient) GetRevisionVerificationByVolume(context.Context, string, string, string) (fakeRevisionVerification, error) {
	panic("boom")
}

type revisionVerificationMissingClient struct{}

type uploadBlockCountClient struct {
	calls int
	err   error
}

func (c *uploadBlockCountClient) UploadBlock(context.Context, string, string, io.Reader) error {
	c.calls++
	return c.err
}

func TestBuildVerificationTokenXorsWithEncryptedBlock(t *testing.T) {
	verificationCode := []byte{0x10, 0x20, 0x30, 0x40}
	encData := []byte{0x01, 0x02, 0x03, 0x04}

	got := buildVerificationToken(verificationCode, encData)
	want := []byte{0x11, 0x22, 0x33, 0x44}

	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected token: got=%v want=%v", got, want)
	}
}

func TestBuildVerificationTokenKeepsTailWhenBlockShorter(t *testing.T) {
	verificationCode := []byte{0x10, 0x20, 0x30, 0x40}
	encData := []byte{0x01, 0x02}

	got := buildVerificationToken(verificationCode, encData)
	want := []byte{0x11, 0x22, 0x30, 0x40}

	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected token: got=%v want=%v", got, want)
	}
}

func TestRecoverBrokenConflictStateRecreatesWhenCode2501(t *testing.T) {
	apiErr := &proton.APIError{Code: fileOrFolderNotFoundCode, Status: 422, Message: "File or folder not found"}
	err := fmt.Errorf("wrapped transport error: %w", apiErr)

	deleteCalls := 0
	shouldRecreate, gotErr := recoverBrokenConflictState(err, proton.LinkStateDraft, func() error {
		deleteCalls++
		return nil
	})

	if gotErr != nil {
		t.Fatalf("expected nil error, got %v", gotErr)
	}
	if !shouldRecreate {
		t.Fatalf("expected recreate=true")
	}
	if deleteCalls != 1 {
		t.Fatalf("expected one delete call, got %d", deleteCalls)
	}
}

func TestRecoverBrokenConflictStatePropagatesDeleteError(t *testing.T) {
	apiErr := &proton.APIError{Code: fileOrFolderNotFoundCode, Status: 422, Message: "File or folder not found"}
	err := fmt.Errorf("wrapped transport error: %w", apiErr)
	deleteErr := errors.New("delete failed")

	shouldRecreate, gotErr := recoverBrokenConflictState(err, proton.LinkStateDraft, func() error {
		return deleteErr
	})

	if !errors.Is(gotErr, deleteErr) {
		t.Fatalf("expected delete error, got %v", gotErr)
	}
	if shouldRecreate {
		t.Fatalf("expected recreate=false")
	}
}

func TestRecoverBrokenConflictStateReturnsOriginalErrorOnOtherCode(t *testing.T) {
	originalErr := fmt.Errorf("wrapped transport error: %w", &proton.APIError{Code: 2500, Status: 422, Message: "conflict"})

	deleteCalls := 0
	shouldRecreate, gotErr := recoverBrokenConflictState(originalErr, proton.LinkStateDraft, func() error {
		deleteCalls++
		return nil
	})

	if !errors.Is(gotErr, originalErr) {
		t.Fatalf("expected original error, got %v", gotErr)
	}
	if shouldRecreate {
		t.Fatalf("expected recreate=false")
	}
	if deleteCalls != 0 {
		t.Fatalf("expected no delete call, got %d", deleteCalls)
	}
}

func TestRecoverBrokenConflictStateReturnsOriginalErrorForUnrelated2501(t *testing.T) {
	originalErr := fmt.Errorf("wrapped transport error: %w", &proton.APIError{Code: fileOrFolderNotFoundCode, Status: 422, Message: "name reserved"})

	deleteCalls := 0
	shouldRecreate, gotErr := recoverBrokenConflictState(originalErr, proton.LinkStateActive, func() error {
		deleteCalls++
		return nil
	})

	if !errors.Is(gotErr, originalErr) {
		t.Fatalf("expected original error, got %v", gotErr)
	}
	if shouldRecreate {
		t.Fatalf("expected recreate=false")
	}
	if deleteCalls != 0 {
		t.Fatalf("expected no delete call, got %d", deleteCalls)
	}
}

func TestRecoverBrokenConflictStateRecreatesDraftWithoutMessageMatch(t *testing.T) {
	apiErr := &proton.APIError{Code: fileOrFolderNotFoundCode, Status: 422, Message: "draft conflict"}
	err := fmt.Errorf("wrapped transport error: %w", apiErr)

	deleteCalls := 0
	shouldRecreate, gotErr := recoverBrokenConflictState(err, proton.LinkStateDraft, func() error {
		deleteCalls++
		return nil
	})

	if gotErr != nil {
		t.Fatalf("expected nil error, got %v", gotErr)
	}
	if !shouldRecreate {
		t.Fatalf("expected recreate=true")
	}
	if deleteCalls != 1 {
		t.Fatalf("expected one delete call, got %d", deleteCalls)
	}
}

func TestGetRevisionVerificationCompatPrefersVolumeRoute(t *testing.T) {
	client := &revisionVerificationByVolumeOnlyClient{}

	res, err := getRevisionVerificationCompat(context.Background(), client, "share", "volume", "link", "revision")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !client.calledByVolume {
		t.Fatalf("expected volume route to be used")
	}
	if res.VerificationCode != "vol" {
		t.Fatalf("unexpected verification code: %q", res.VerificationCode)
	}
}

func TestGetRevisionVerificationCompatFallsBackToShareRoute(t *testing.T) {
	client := &revisionVerificationByShareOnlyClient{}

	res, err := getRevisionVerificationCompat(context.Background(), client, "share", "volume", "link", "revision")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !client.calledByShare {
		t.Fatalf("expected share route fallback to be used")
	}
	if res.VerificationCode != "share" {
		t.Fatalf("unexpected verification code: %q", res.VerificationCode)
	}
}

func TestGetRevisionVerificationCompatFallsBackWhenVolumeRouteSignatureIsIncompatible(t *testing.T) {
	client := &revisionVerificationInvalidVolumeFallbackClient{}

	res, err := getRevisionVerificationCompat(context.Background(), client, "share", "volume", "link", "revision")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !client.calledByShare {
		t.Fatalf("expected share route fallback to be used")
	}
	if res.VerificationCode != "share" {
		t.Fatalf("unexpected verification code: %q", res.VerificationCode)
	}
}

func TestGetRevisionVerificationCompatHandlesInvalidSignature(t *testing.T) {
	_, err := getRevisionVerificationCompat(context.Background(), &revisionVerificationInvalidSignatureClient{}, "share", "volume", "link", "revision")
	if err == nil {
		t.Fatalf("expected error for incompatible signature")
	}
}

func TestGetRevisionVerificationCompatHandlesPanickingMethod(t *testing.T) {
	_, err := getRevisionVerificationCompat(context.Background(), &revisionVerificationPanicClient{}, "share", "volume", "link", "revision")
	if err == nil {
		t.Fatalf("expected panic to be converted into error")
	}
}

func TestGetRevisionVerificationCompatAllowsMissingMethods(t *testing.T) {
	res, err := getRevisionVerificationCompat(context.Background(), &revisionVerificationMissingClient{}, "share", "volume", "link", "revision")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res.VerificationCode != "" || res.ContentKeyPacket != "" {
		t.Fatalf("expected empty compatibility result, got %#v", res)
	}
}

func TestCollectUploadErrorsReturnsFirstErrorAndStillDrains(t *testing.T) {
	errChan := make(chan error, 3)
	errChan <- nil
	firstErr := errors.New("first")
	errChan <- firstErr
	errChan <- errors.New("second")

	cancelCalls := 0
	err := collectUploadErrors(errChan, 3, func() {
		cancelCalls++
	})

	if !errors.Is(err, firstErr) {
		t.Fatalf("expected first error, got %v", err)
	}
	if cancelCalls != 1 {
		t.Fatalf("expected one cancel call, got %d", cancelCalls)
	}
	if len(errChan) != 0 {
		t.Fatalf("expected channel to be fully drained, remaining=%d", len(errChan))
	}
}

func TestCollectUploadErrorsNoErrorNoCancel(t *testing.T) {
	errChan := make(chan error, 2)
	errChan <- nil
	errChan <- nil

	cancelCalls := 0
	err := collectUploadErrors(errChan, 2, func() {
		cancelCalls++
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cancelCalls != 0 {
		t.Fatalf("expected zero cancel calls, got %d", cancelCalls)
	}
}

func TestUploadBlockWithClientDelegatesSingleCall(t *testing.T) {
	wantErr := errors.New("permanent upload failure")
	client := &uploadBlockCountClient{err: wantErr}

	err := uploadBlockWithClient(context.Background(), client, "https://example.invalid/upload", "token", bytes.NewReader([]byte("payload")))
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
	if client.calls != 1 {
		t.Fatalf("expected one upload call, got %d", client.calls)
	}
}

func TestValidateUploadBatchCardinalityMatches(t *testing.T) {
	err := validateUploadBatchCardinality(3, 3)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateUploadBatchCardinalityMismatch(t *testing.T) {
	err := validateUploadBatchCardinality(2, 3)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
}
