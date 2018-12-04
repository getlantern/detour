package detour

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckSubdomain(t *testing.T) {
	clear()
	addToWl("facebook.com", true)
	assert.True(t, whitelisted("www.facebook.com:80"), "should match subdomain")
	assert.True(t, whitelisted("sub2.facebook.com:80"), "should match all subdomains")
}

func TestRadixList(t *testing.T) {
	l := newRadixList([]string{"google.com", "www.stuff.com:443"})

	assert.True(t, l.containsExactly("google.com:80"))
	assert.True(t, l.containsExactly("www.stuff.com"))
	assert.True(t, l.matchesPrefix("www.google.com"))
	assert.True(t, l.matchesPrefix("google.com"))
	assert.True(t, l.matchesPrefix("www.stuff.com"))
	assert.False(t, l.matchesPrefix("dude.stuff.com"))
}
