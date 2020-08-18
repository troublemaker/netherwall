package jail

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)

//override default periods
func init() {
	jailTime = time.Second
	schedulerSleep = time.Millisecond * 100
}

func TestJail(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	AppendWhitelist("1.1.1.1")
	BlockIP("1.1.1.1")
	iter := 0
	for iter < 4 {
		BlockIP(randIpV4())
		time.Sleep(time.Millisecond * 150)
		iter++
	}
	n := len(ip_list)
	if n != 4 {
		t.Fatalf("expected 5 elements, got %d \n", n)
	}
	time.Sleep(time.Second * 2)

	n = len(ip_list)
	if n != 0 {
		t.Fatalf("expected 0 elements, got %d \n", n)
	}
}

func randIpV4() string {
	blocks := []string{}
	for i := 0; i < 4; i++ {
		number := rand.Intn(255)
		blocks = append(blocks, strconv.Itoa(number))
	}

	return strings.Join(blocks, ".")
}
