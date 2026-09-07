package common_test

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/rclone/Proton-API-Bridge/common"
	"github.com/rclone/go-proton-api"
	"github.com/rclone/go-proton-api/server"
	"github.com/stretchr/testify/require"
)

// redirectTransport sends every request to the fake server, since Config has
// no host setting and the manager always targets the real API.
type redirectTransport struct {
	target *url.URL
	next   http.RoundTripper
}

func (t redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = t.target.Scheme
	req.URL.Host = t.target.Host
	req.Host = t.target.Host
	return t.next.RoundTrip(req)
}

// credentialStore stands in for the config file rclone persists tokens to.
type credentialStore struct {
	mu   sync.Mutex
	cred common.ReusableCredentialData
}

func (s *credentialStore) save(auth proton.Auth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cred.UID, s.cred.AccessToken, s.cred.RefreshToken = auth.UID, auth.AccessToken, auth.RefreshToken
}

func (s *credentialStore) load() (uid, acc, ref string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cred.UID, s.cred.AccessToken, s.cred.RefreshToken, s.cred.RefreshToken != ""
}

func (s *credentialStore) snapshot() *common.ReusableCredentialData {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cred
	return &c
}

// A Config.AuthRefreshHook must be registered on the client Login creates, so
// a second login from the same saved session survives the first one rotating
// the refresh token.
func TestLogin_RegistersAuthRefreshHook(t *testing.T) {
	s := server.New()
	defer s.Close()

	_, _, err := s.CreateUser("user", []byte("pass"))
	require.NoError(t, err)
	s.SetAuthLife(time.Second)

	target, err := url.Parse(s.GetHostURL())
	require.NoError(t, err)
	transport := redirectTransport{target: target, next: proton.InsecureTransport()}

	store := &credentialStore{}

	// First login with username and password, as rclone does when it has no
	// cached credentials.
	first := &common.Config{
		AppVersion: "test", UserAgent: "test", Transport: transport,
		FirstLoginCredential: &common.FirstLoginCredentialData{Username: "user", Password: "pass"},
		ReusableCredential:   &common.ReusableCredentialData{},
	}
	_, firstClient, cred, _, _, _, err := common.Login(context.Background(), first, store.save, func() {})
	require.NoError(t, err)
	store.save(proton.Auth{UID: cred.UID, AccessToken: cred.AccessToken, RefreshToken: cred.RefreshToken})
	saltedKeyPass := cred.SaltedKeyPass

	// Second login from the saved session, as a second Fs or a second process
	// would do, with the hook reading back from the shared store.
	reused := store.snapshot()
	reused.SaltedKeyPass = saltedKeyPass
	second := &common.Config{
		AppVersion: "test", UserAgent: "test", Transport: transport,
		UseReusableLogin:   true,
		ReusableCredential: reused,
		AuthRefreshHook:    store.load,
	}
	deauthed := false
	_, secondClient, _, _, _, _, err := common.Login(context.Background(), second, store.save, func() { deauthed = true })
	require.NoError(t, err)

	// Let the access tokens expire, then have the first client refresh and
	// rotate the shared refresh token.
	time.Sleep(2 * time.Second)
	_, err = firstClient.GetUser(context.Background())
	require.NoError(t, err)

	// The second client's own refresh token is now spent. Without the hook it
	// would be de-authed here.
	_, err = secondClient.GetUser(context.Background())
	require.NoError(t, err)
	require.False(t, deauthed, "second login was de-authed despite newer credentials in the store")
}
