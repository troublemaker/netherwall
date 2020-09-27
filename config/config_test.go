package config

import (
	"fmt"
	"testing"
)

func init() {

	configFile = "testconf.json"
}

func TestConf(t *testing.T) {
	err := Setup()
	if err != nil {
		t.Fatalf("Couldn't read config file %s \n", err.Error())
		return
	}
	fmt.Printf("DATA: %v \n", Data)
}
