package detour

import (
	"net"
	"strings"
	"sync"
)

type wlEntry struct {
	permanent bool
}

var (
	muWhitelist    sync.RWMutex
	whitelist      = make(map[string]wlEntry)
	forceWhitelist = make(map[string]wlEntry)
)

func ForceWhitelist(addr string) {
	log.Debugf("Force whitelisting %v", addr)
	muWhitelist.Lock()
	defer muWhitelist.Unlock()
	forceWhitelist[hostOnly(addr)] = wlEntry{true}
}

// AddToWl adds a domain to whitelist, all subdomains of this domain
// are also considered to be in the whitelist.
func AddToWl(addr string, permanent bool) {
	log.Debugf("Adding %v to whitelist. Permanent? %v", addr, permanent)
	muWhitelist.Lock()
	defer muWhitelist.Unlock()
	whitelist[hostOnly(addr)] = wlEntry{permanent}
}

func RemoveFromWl(addr string) {
	log.Debugf("Removing %v from whitelist.", addr)
	muWhitelist.Lock()
	defer muWhitelist.Unlock()
	delete(whitelist, hostOnly(addr))
}

func DumpWhitelist() (wl []string) {
	wl = make([]string, 1)
	muWhitelist.Lock()
	defer muWhitelist.Unlock()
	for k, v := range whitelist {
		if v.permanent {
			wl = append(wl, k)
		}
	}
	return
}

func whitelisted(_addr string) (in bool) {
	muWhitelist.RLock()
	defer muWhitelist.RUnlock()
	log.Debugf("Checking if %v is whitelisted", _addr)
	for addr := hostOnly(_addr); addr != ""; addr = getParentDomain(addr) {
		_, forced := forceWhitelist[addr]
		if forced {
			log.Debugf("%v is force whitelisted as %v", _addr, addr)
			return true
		}
		_, whitelisted := whitelist[addr]
		if whitelisted {
			log.Debugf("%v is whitelisted as %v", _addr, addr)
			return true
		}
	}
	log.Debugf("%v is not whitelisted", _addr)
	return
}

func wlTemporarily(addr string) bool {
	muWhitelist.RLock()
	defer muWhitelist.RUnlock()
	// temporary domains are always full ones, just check map
	p, ok := whitelist[hostOnly(addr)]
	return ok && p.permanent == false
}

func getParentDomain(addr string) string {
	parts := strings.SplitN(addr, ".", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return host
}
