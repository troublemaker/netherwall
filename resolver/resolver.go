package resolver

import (
	"net"
	"strings"
	"sync"
)

// TODO cache TTL
var res_cache map[string]string
var lock = sync.RWMutex{}

func init() {
	res_cache = make(map[string]string, 10000)
}

func Lookup(ip string) (names string) {
	res, ok := res_cache[ip]
	if ok {
		return res
	}

	addr, err := net.LookupAddr(ip)
	if err != nil {
		res = " "
	} else {
		res = strings.Join(addr[:], ";")
	}

	lock.Lock()
	defer lock.Unlock()
	res_cache[ip] = res
	return res
}
