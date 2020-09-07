package jail

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
	"fmt"
)


type mockFireWall struct {
	blockedIPs map[string]struct{}
}

func (mf *mockFireWall) AppendUnique(table, chain string, rulespec ...string) error {
	fmt.Printf("IPTables (test):  Add IP: %s \n", rulespec[1])
	mf.blockedIPs[rulespec[1]] = x
	return nil
}

func (mf *mockFireWall) Delete(table, chain string, rulespec ...string) error {
	fmt.Printf("IPTables (test):  Remove IP: %s \n", rulespec[1])
	delete(mf.blockedIPs, rulespec[1])
	fmt.Printf("IPTables (test):  blocked IPs list len: %d \n", len(mf.blockedIPs))
	return nil
}



func newMockFireWall() *mockFireWall {
	mf := new(mockFireWall)
	mf.blockedIPs = make (map[string]struct{})
	return mf
}


	

//override default periods
func init() {
	ipt = newMockFireWall() 
	Setup(ipt)
	schedulerSleep = time.Millisecond * 100
}

func TestJail(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	AppendWhitelist("1.1.1.1")
	BlockIP("1.1.1.1", 100)
	iter := 0
	for iter < 4 {
		BlockIP(randIpV4(), 15)
		time.Sleep(time.Millisecond * 150)
		iter++
	}
	n := len(ip_list)
	if n != 4 {
		t.Fatalf("expected 5 elements, got %d \n", n)
	}
	time.Sleep(time.Second * 3)

	n = len(ip_list)
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
