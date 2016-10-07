package detour

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckSubdomain(t *testing.T) {
	AddToWl("facebook.com", true)
	assert.True(t, whitelisted("www.facebook.com:80"), "should match subdomain")
	assert.True(t, whitelisted("sub2.facebook.com:80"), "should match all subdomains")
}

func TestDumpWhiteList(t *testing.T) {
	AddToWl("a.com:80", true)
	AddToWl("b.com:80", false)
	dumped := DumpWhitelist()
	assert.Contains(t, dumped, "a.com", "dumped list should contain permanent items")
	assert.NotContains(t, dumped, "b.com", "dumped list should not contain temporary items")
}
