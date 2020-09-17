package resolver

import (
	"net"
	"strings"
)

var res_cache map[string]string

func init() {
	res_cache = make(map[string]string, 10000)
}

func Lookup(ip string) (names string, err error) {
	res, ok := res_cache[ip]
	if ok {
		return res, nil
	}

	addr, err := net.LookupAddr(ip)
	if err != nil {
		return "", err
	}
	res = strings.Join(addr[:], ";")
	res_cache[ip] = res
	return res, nil
}
