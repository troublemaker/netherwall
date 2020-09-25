package resolver

import (
	"net"
	"strings"
)

// TODO cache TTL
var res_cache map[string]string

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
	
	res_cache[ip] = res
	return res
}
