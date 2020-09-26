package voidlog

import (
	"container/ring"
	"fmt"
	"time"
)

var LogHistory *ring.Ring

func init() {
	LogHistory = ring.New(10240)
}

func Log(format string, a ...interface{}) {
	s := time.Now().Format(time.Stamp) + " : " + fmt.Sprintf(format, a...)
	fmt.Print(s)
	LogHistory.Value = s
	LogHistory = LogHistory.Next()
}
