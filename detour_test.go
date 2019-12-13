package detour

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/netx"
	"github.com/stretchr/testify/assert"
)

var (
	directMsg string = "hello direct"
	detourMsg string = "hello detour"
	iranResp  string = `HTTP/1.1 403 Forbidden
Connection:close

<html><head><meta http-equiv="Content-Type" content="text/html; charset=windows-1256"><title>M1-6
</title></head><body><iframe src="http://10.10.34.34?type=Invalid Site&policy=MainPolicy " style="width: 100%; height: 100%" scrolling="no" marginwidth="0" marginheight="0" frameborder="0" vspace="0" hspace="0"></iframe></body></html>Connection closed by foreign host.`
)

func proxyTo(proxiedURL string) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		u, _ := url.Parse(proxiedURL)
		return net.Dial(network, u.Host)
	}
}

func TestBlockedImmediately(t *testing.T) {
	defer RemoveFromWl("127.0.0.1")
	defer stopMockServers()
	proxiedURL, _ := newMockServer(detourMsg)
	firstReadTimeoutToDetour = 50 * time.Millisecond
	mockURL, mock := newMockServer(directMsg)

	client := &http.Client{Timeout: 50 * time.Millisecond}
	mock.Timeout(200*time.Millisecond, directMsg)
	resp, err := client.Get(mockURL)
	assert.Error(t, err, "direct access to a timeout url should fail")

	client = newClient(proxiedURL, 100*time.Millisecond)
	resp, err = client.Get("http://255.0.0.1") // it's reserved for future use so will always time out
	if assert.NoError(t, err, "should have no error if dialing times out") {
		assert.True(t, wlTemporarily("255.0.0.1:80"), "should be added to whitelist if dialing times out")
		assertContent(t, resp, detourMsg, "should detour if dialing times out")
	}

	client = newClient(proxiedURL, 100*time.Millisecond)
	resp, err = client.Get("http://127.0.0.1:4325") // hopefully this port didn't open, so connection will be refused
	if assert.NoError(t, err, "should have no error if connection is refused") {
		assert.True(t, wlTemporarily("127.0.0.1:4325"), "should be added to whitelist if connection is refused")
		assertContent(t, resp, detourMsg, "should detour if connection is refused")
	}

	u, _ := url.Parse(mockURL)
	resp, err = client.Get(mockURL)
	if assert.NoError(t, err, "should have no error if reading times out") {
		assert.True(t, wlTemporarily(u.Host), "should be added to whitelist if reading times out")
		assertContent(t, resp, detourMsg, "should detour if reading times out")
	}

	client = newClient(proxiedURL, 100*time.Millisecond)
	RemoveFromWl(u.Host)
	resp, err = client.PostForm(mockURL, url.Values{"key": []string{"value"}})
	if assert.Error(t, err, "Non-idempotent method should not be detoured in same connection") {
		assert.True(t, wlTemporarily(u.Host), "but should be added to whitelist so will detour next time")
	}
}

func TestReadFailedImmediately(t *testing.T) {
	defer RemoveFromWl("127.0.0.1")
	defer stopMockServers()
	proxiedURL, _ := newMockServer(detourMsg)
	firstReadTimeoutToDetour = 50 * time.Millisecond
	mockURL, _ := newMockServer(directMsg)

	client := newDirectFailingClient(proxiedURL, 1*time.Hour, 0)
	u, _ := url.Parse(mockURL)
	resp, err := client.Get(mockURL)
	if assert.NoError(t, err, "should have no error if reading fails immediately") {
		defer resp.Body.Close()
		assert.True(t, wlTemporarily(u.Host), "should be added to whitelist if reading fails immediately")
		assertContent(t, resp, detourMsg, "should detour if reading fails immediately")
	}
}

func TestReadFailedEventually(t *testing.T) {
	defer RemoveFromWl("127.0.0.1")
	defer stopMockServers()
	proxiedURL, _ := newMockServer(detourMsg)
	firstReadTimeoutToDetour = 50 * time.Millisecond
	longMessage := make([]byte, 10000)
	rand.Read(longMessage)
	mockURL, _ := newMockServer(string(longMessage))

	client := newDirectFailingClient(proxiedURL, 1*time.Hour, 1)
	u, _ := url.Parse(mockURL)
	resp, err := client.Get(mockURL)
	if assert.NoError(t, err, "should get response if reading fails after first read") {
		defer resp.Body.Close()
		_, copyErr := io.Copy(ioutil.Discard, resp.Body)
		if assert.Error(t, copyErr, "reading should have failed eventually") {
			assert.True(t, wlTemporarily(u.Host), "should be added to whitelist if reading fails after first read")
		}
	}
}

func TestRemoveFromWhitelist(t *testing.T) {
	defer RemoveFromWl("127.0.0.1")
	defer stopMockServers()
	proxiedURL, proxy := newMockServer(detourMsg)
	proxy.Timeout(200*time.Millisecond, detourMsg)
	firstReadTimeoutToDetour = 50 * time.Millisecond
	mockURL, _ := newMockServer(directMsg)
	client := newDetourFailingClient(proxiedURL, 1*time.Hour, 0)

	u, _ := url.Parse(mockURL)
	AddToWl(u.Host, false)
	_, err := client.Get(mockURL)
	if assert.Error(t, err, "should have error if reading times out through detour") {
		time.Sleep(250 * time.Millisecond)
		assert.False(t, whitelisted(u.Host), "should be removed from whitelist if reading times out through detour")
	}

}

func TestClosing(t *testing.T) {
	defer RemoveFromWl("localhost")
	defer stopMockServers()
	proxiedURL, proxy := newMockServer(detourMsg)
	proxy.Timeout(200*time.Millisecond, detourMsg)
	firstReadTimeoutToDetour = 50 * time.Millisecond
	mockURL, mock := newMockServer(directMsg)
	mock.Msg(directMsg)
	if _, err := newClient(proxiedURL, 100*time.Millisecond).Get(mockURL); err != nil {
		log.Debugf("Unable to send GET request to mock URL: %v", err)
	}
}

func TestIranRules(t *testing.T) {
	defer RemoveFromWl("localhost")
	defer stopMockServers()
	proxiedURL, _ := newMockServer(detourMsg)
	firstReadTimeoutToDetour = 50 * time.Millisecond
	SetCountry("IR")
	u, mock := newMockServer(directMsg)
	client := newClient(proxiedURL, 100*time.Millisecond)

	mock.Raw(iranResp)
	resp, err := client.Get(u)
	if assert.NoError(t, err, "should not error if content hijacked in Iran") {
		assertContent(t, resp, detourMsg, "should detour if content hijacked in Iran")
	}

	// this test can verifies dns hijack detection if runs inside Iran,
	// but only will time out and detour if runs outside Iran
	resp, err = client.Get("http://" + iranRedirectAddr)
	if assert.NoError(t, err, "should not error if dns hijacked in Iran") {
		assertContent(t, resp, detourMsg, "should detour if dns hijacked in Iran")
	}
}

func newClient(proxyURL string, timeout time.Duration) *http.Client {
	return newDetourFailingClient(proxyURL, timeout, math.MaxInt64)
}

func newDirectFailingClient(proxyURL string, timeout time.Duration, directFailAfterReads int64) *http.Client {
	return newFailingClient(proxyURL, timeout, directFailAfterReads, math.MaxInt64)
}

func newDetourFailingClient(proxyURL string, timeout time.Duration, detourFailAfterReads int64) *http.Client {
	return newFailingClient(proxyURL, timeout, math.MaxInt64, detourFailAfterReads)
}

func newFailingClient(proxyURL string, timeout time.Duration, directFailAfterReads int64, detourFailAfterReads int64) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := Dialer(
					func(ctx context.Context, network, addr string) (net.Conn, error) {
						// for simplicity, we use the same timeout for direct dialer.
						newCTX, _ := context.WithTimeout(ctx, firstReadTimeoutToDetour)
						conn, err := netx.DialContext(newCTX, network, addr)
						if err == nil {
							conn = &eventuallyFailingConn{Conn: conn, failAfterReads: directFailAfterReads}
						}
						return conn, err
					},
					func(ctx context.Context, network, addr string) (net.Conn, error) {
						conn, err := proxyTo(proxyURL)(ctx, network, addr)
						if err == nil {
							conn = &eventuallyFailingConn{Conn: conn, failAfterReads: detourFailAfterReads}
						}
						return conn, err
					},
				)
				return dialer(ctx, network, addr)
			},
		},
		Timeout: timeout,
	}
}

func assertContent(t *testing.T, resp *http.Response, msg string, reason string) {
	b, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err, reason)
	assert.Equal(t, msg, string(b), reason)
}

type eventuallyFailingConn struct {
	net.Conn
	failAfterReads int64
	numReads       int64
}

func (conn *eventuallyFailingConn) Read(b []byte) (int, error) {
	currentReads := atomic.AddInt64(&conn.numReads, 1)
	if currentReads > conn.failAfterReads {
		return 0, &net.OpError{
			Op:     "read",
			Net:    "tcp",
			Source: conn.Conn.LocalAddr(),
			Addr:   conn.Conn.RemoteAddr(),
			Err:    errors.New("failing unexpectedly"),
		}
	}
	return conn.Conn.Read(b)
}
