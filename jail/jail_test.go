package jail

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)



type mockFireWall struct {
	blockedIPs map[string]struct{}
}

func (mf *mockFireWall) AppendUnique(table, chain string, rulespec ...string) error {
	fmt.Printf("IPTables (test):  -AppendUnique: %s \n", rulespec[1])
	mf.blockedIPs[rulespec[1]] = x
	return nil
}

func (mf *mockFireWall) Delete(table, chain string, rulespec ...string) error {
	fmt.Printf("IPTables (test):  -Delete: %s \n", rulespec[1])
	delete(mf.blockedIPs, rulespec[1])
	fmt.Printf("IPTables (test):  blocked IPs list len: %d \n", len(mf.blockedIPs))
	return nil
}

func (mf *mockFireWall) ClearChain(table, chain string) error {
	fmt.Printf("IPTables (test):  -ClearChain \n")
	mf.blockedIPs = make(map[string]struct{})
	return nil
}


func newMockFireWall() *mockFireWall {
	mf := new(mockFireWall)
	mf.blockedIPs = make(map[string]struct{})
	return mf
}


func init() {
	//override default periods
	schedulerSleep = time.Millisecond * 100

	ipt = newMockFireWall()
	Setup(ipt)

}

func TestJail(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	AppendWhitelist("1.1.1.1/24")
	AppendWhitelist("2.1.1.1/24")
	BlockIP("1.1.1.1", 100)
	iter := 0
	for iter < 4 {
		ip := randIpV4()
		BlockIP(ip, 15)
		BlockIP(ip, 20)
		time.Sleep(time.Millisecond * 150)
		iter++
	}
	n := len(Ip_list)
	if n != 4 {
		t.Fatalf("expected 4 elements, got %d \n", n)
	}
	time.Sleep(time.Second * 5)

	n = len(Ip_list)
	if n != 0 {
		t.Fatalf("expected 0 elements, got %d \n", n)
	}

	//TODO: test # of rules in iptables

}

func randIpV4() string {
	blocks := []string{}
	for i := 0; i < 4; i++ {
		number := rand.Intn(255)
		blocks = append(blocks, strconv.Itoa(number))
	}

	return strings.Join(blocks, ".")
}
