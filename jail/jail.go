package jail

import (
	"errors"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"net"
	"sync"
	"time"
)

var x struct{} //empty value

var ip_list map[string]int
var whitelist map[string]struct{}
var lock = sync.RWMutex{}
var schedulerSleep = time.Minute
var ipt *iptables.IPTables
var DecPerCycle = 1

const chain string = "ipvoid"

func init() {
	var err error
	ip_list = make(map[string]int, 1000)
	whitelist = make(map[string]struct{}, 100)
	whitelist["127.0.0.1"] = x

	go scheduledRemoval()
	ipt, err = iptables.New()
	if err != nil {
		fmt.Printf("IPtables init issue: %v", err)
	}

	err = ipt.ClearChain("filter", chain)
	if err != nil {
		fmt.Printf("IPtables clear chain issue: %v", err)
	}

	err = ipt.AppendUnique("filter", "INPUT", "-j", chain)
	if err != nil {
		fmt.Printf("IPtables attach chain issue: %v", err)
	}
}

//TODO add CIDR support
func AppendWhitelist(ip string) {
	res := net.ParseIP(ip)
	if res == nil {
		fmt.Printf("Whitelist: parameter is not an IP: %s \n", ip)
		return
	}
	whitelist[ip] = x
	fmt.Println("IP added to whitelist: " + ip)
}

func BlockIP(ip string, points int) error {

	//todo IP4 only
	res := net.ParseIP(ip)
	if res == nil {
		return errors.New("Parameter is not an IP")
	}

	//check whitelist
	_, ok := whitelist[ip]
	if ok {
		fmt.Println("BlockIP. IP not blocked (exists in whitelist): " + ip)
		return nil
	}
	addIP(ip, points)
	return nil
}

func addIP(ip string, points int) {
	err := ipt.AppendUnique("filter", chain, "-s", ip, "-j", "DROP")
	if err != nil {
		fmt.Printf("Adding IP to iptables failed: %v", err)
		return
	}
	fmt.Printf("JAILED: %s with %d points.", ip, points)
	lock.Lock()
	defer lock.Unlock()
	ip_list[ip] = points
}

func decreaseJailTime() {
	lock.Lock()
	defer lock.Unlock()

	for k, v := range ip_list {
		ip_list[k] = v - DecPerCycle
		fmt.Printf("Status: %s : %d \n", k, ip_list[k])

		if ip_list[k] <= 0 {
			err := ipt.Delete("filter", chain, "-s", k, "-j", "DROP")
			if err != nil {
				fmt.Printf("Delete IP from iptables failed: %v", err)
			}
			delete(ip_list, k)
			fmt.Printf("Removing IP: %s \n", k)
		}
	}

}

func scheduledRemoval() {
	for {
		time.Sleep(schedulerSleep)
		decreaseJailTime()
	}
}
