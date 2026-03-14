package common

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/go-resty/resty/v2"
	"github.com/rclone/go-proton-api"
)

type fakePreRequestHookClient struct {
	hooks []resty.RequestMiddleware
}

func (f *fakePreRequestHookClient) AddPreRequestHook(hook resty.RequestMiddleware) {
	f.hooks = append(f.hooks, hook)
}

func TestAttachDriveSDKHeaderHookSkipsEmptyVersion(t *testing.T) {
	fakeClient := &fakePreRequestHookClient{}
	attachDriveSDKHeaderHook(fakeClient, "")

	if len(fakeClient.hooks) != 0 {
		t.Fatalf("expected no hooks, got %d", len(fakeClient.hooks))
	}
}

func TestAttachDriveSDKHeaderHookSetsHeader(t *testing.T) {
	fakeClient := &fakePreRequestHookClient{}
	attachDriveSDKHeaderHook(fakeClient, "js@0.10.0")

	if len(fakeClient.hooks) != 1 {
		t.Fatalf("expected one hook, got %d", len(fakeClient.hooks))
	}

	r := resty.New().R().SetContext(context.Background())
	if err := fakeClient.hooks[0](resty.New(), r); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if got := r.Header.Get("x-pm-drive-sdk-version"); got != "js@0.10.0" {
		t.Fatalf("expected drive sdk header to be set, got %q", got)
	}
}

func TestGetProtonManagerRetriesRequests(t *testing.T) {
	t.Run("succeeds after retry budget is consumed", func(t *testing.T) {
		// Objective (positive): prove getProtonManager enables manager-level retries by succeeding
		// only after the initial call plus default retry count have been attempted.
		var callCount atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/core/v4/addresses" {
				t.Fatalf("expected request path %q, got %q", "/core/v4/addresses", r.URL.Path)
			}

			if callCount.Add(1) <= int32(defaultAPIRequestRetryCount) {
				w.Header().Set("Retry-After", "-10")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"Error":"temporary outage"}`))
				return
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Addresses":[]}`))
		}))
		defer server.Close()

		// Arrange
		manager := getProtonManager("bridge-test", "bridge-test-agent")
		configureManagerForRetryTest(t, manager, server.URL)

		client := manager.NewClient("", "", "")
		defer client.Close()
		defer manager.Close()

		// Act
		addresses, err := client.GetAddresses(context.Background())

		// Assert
		if err != nil {
			t.Fatalf("expected request to succeed after retries, got error: %v", err)
		}
		if len(addresses) != 0 {
			t.Fatalf("expected no addresses from fake response, got %d", len(addresses))
		}

		expectedCalls := int32(defaultAPIRequestRetryCount + 1)
		if got := callCount.Load(); got != expectedCalls {
			t.Fatalf("expected %d calls (initial + retries), got %d", expectedCalls, got)
		}
	})

}

func configureManagerForRetryTest(t *testing.T, manager *proton.Manager, baseURL string) {
	t.Helper()

	managerValue := reflect.ValueOf(manager)
	if managerValue.Kind() != reflect.Pointer || managerValue.IsNil() {
		t.Fatal("expected non-nil proton manager pointer")
	}

	rcField := managerValue.Elem().FieldByName("rc")
	if !rcField.IsValid() {
		t.Fatal("expected manager to contain resty client field")
	}

	rcValue := reflect.NewAt(rcField.Type(), unsafe.Pointer(rcField.UnsafeAddr())).Elem()
	rc, ok := rcValue.Interface().(*resty.Client)
	if !ok || rc == nil {
		t.Fatal("expected manager resty client to be accessible")
	}

	rc.SetBaseURL(baseURL)
	rc.SetRetryWaitTime(time.Millisecond)
	rc.SetRetryMaxWaitTime(time.Millisecond)
}
