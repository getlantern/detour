package detour

import (
	"net"
	"sync"

	"github.com/armon/go-radix"
)

var (
	muWhitelist      sync.RWMutex
	permWhitelist    = newRadixList(nil)
	tempWhitelist    = newRadixList(nil)
	forceWhitelist   = newRadixList(nil)
	forceUnwhitelist = newRadixList(nil)
)

func clear() {
	muWhitelist.Lock()
	defer muWhitelist.Unlock()
	permWhitelist = newRadixList(nil)
	tempWhitelist = newRadixList(nil)
	forceWhitelist = newRadixList(nil)
	forceUnwhitelist = newRadixList(nil)
}

// UpdatePermanentWhitelist sets the permanent whitelist to the given list of
// addresses.
func UpdatePermanentWhitelist(addrs []string) {
	muWhitelist.Lock()
	defer muWhitelist.Unlock()
	permWhitelist = newRadixList(addrs)
}

// ForceWhitelist forcibly whitelists the given address, irrespective of what
// happens to the permanent and temporary whitelists.
func ForceWhitelist(addr string) {
	log.Tracef("Force whitelisting %v", addr)
	muWhitelist.Lock()
	defer muWhitelist.Unlock()
	forceWhitelist.add(addr)
}

// addToWl adds a domain to whitelist, all subdomains of this domain
// are also considered to be in the whitelist.
func addToWl(addr string, permanent bool) {
	log.Tracef("Adding %v to whitelist. Permanent? %v", addr, permanent)
	muWhitelist.Lock()
	defer muWhitelist.Unlock()
	if permanent {
		permWhitelist.add(addr)
	} else {
		tempWhitelist.add(addr)
	}
}

func forceUnwhitelisted(addr string) {
	log.Tracef("Forcibly removing %v from whitelist.", addr)
	muWhitelist.Lock()
	defer muWhitelist.Unlock()
	forceUnwhitelist.add(addr)
}

func whitelisted(_addr string) bool {
	muWhitelist.RLock()
	defer muWhitelist.RUnlock()
	host := hostOnly(_addr)
	log.Tracef("Checking if %v is whitelisted", _addr)
	if forceUnwhitelist.matchesPrefix(host) {
		log.Tracef("%v is force unwhitelisted", _addr)
		return false
	}
	if forceWhitelist.matchesPrefix(host) {
		log.Tracef("%v is force whitelisted", _addr)
		return true
	}
	if permWhitelist.matchesPrefix(host) {
		log.Tracef("%v is permantently whitelisted", _addr)
		return true
	}
	if tempWhitelist.matchesPrefix(host) {
		log.Tracef("%v is temporarily whitelisted", _addr)
		return true
	}
	log.Tracef("%v is not whitelisted", _addr)
	return false
}

func wlTemporarily(addr string) bool {
	muWhitelist.RLock()
	defer muWhitelist.RUnlock()
	return tempWhitelist.containsExactly(addr)
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return host
}

type radixList struct {
	tree *radix.Tree
}

func newRadixList(addrs []string) *radixList {
	l := &radixList{radix.New()}
	for _, addr := range addrs {
		l.add(addr)
	}
	return l
}

func (l *radixList) add(addr string) bool {
	_, updated := l.tree.Insert(reverse(hostOnly(addr)), true)
	return updated
}

func (l *radixList) delete(addr string) {
	l.tree.Delete(reverse(hostOnly(addr)))
}

func (l *radixList) containsExactly(addr string) bool {
	_, found := l.tree.Get(reverse(hostOnly(addr)))
	return found
}

func (l *radixList) matchesPrefix(host string) bool {
	_, _, found := l.tree.LongestPrefix(reverse(host))
	return found
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
