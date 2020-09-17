package jail

import (
	"container/ring"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type iptablesImp interface {
	AppendUnique(table, chain string, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	ClearChain(table, chain string) error
}

var x struct{} //empty value
var ipt iptablesImp

var Ip_list map[string]float32
var JailHistory *ring.Ring
var whitelist map[string]struct{}
var lock = sync.RWMutex{}
var schedulerSleep = time.Minute
var decJailedPerCycle float32 = 1
var chain = ""

func init() {
	Ip_list = make(map[string]float32, 1024)
	JailHistory = ring.New(1024)
	whitelist = make(map[string]struct{}, 100)
	whitelist["127.0.0.1"] = x
	go scheduledRemoval()

}

func Setup(iptimp iptablesImp, chainname string) error {
	ipt = iptimp
	chain = chainname

	err := ipt.ClearChain("filter", chain)
	if err != nil {
		fmt.Printf("IPtables clear chain issue: %v", err)
		return err
	}

	err = ipt.AppendUnique("filter", "INPUT", "-j", chain)
	if err != nil {
		fmt.Printf("IPtables attach chain issue: %v", err)
		return err
	}
	return nil
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

func BlockIP(ip string, points float32) error {

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

func addIP(ip string, points float32) {
	err := ipt.AppendUnique("filter", chain, "-s", ip, "-j", "DROP")
	if err != nil {
		fmt.Printf("Adding IP to iptables failed: %v", err)
		return
	}
	fmt.Printf("JAILED: %s with %.2f points. \n", ip, points)
	//add to history
	JailHistory.Value = time.Now().Format(time.Stamp) + " : " + ip
	JailHistory = JailHistory.Next()

	lock.Lock()
	defer lock.Unlock()
	Ip_list[ip] = points
}

func decreaseJailTime() {
	lock.Lock()
	defer lock.Unlock()

	for k, v := range Ip_list {
		Ip_list[k] = v - decJailedPerCycle
		//fmt.Printf("IP Jail status: %s : %.2f \n", k, Ip_list[k])

		if Ip_list[k] <= 0 {
			err := ipt.Delete("filter", chain, "-s", k, "-j", "DROP")
			if err != nil {
				fmt.Printf("Delete IP from iptables failed: %v", err)
			}
			delete(Ip_list, k)
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
