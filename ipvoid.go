package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"ipvoid/filemonitor"
	"ipvoid/jail"
	"os"
	"regexp"
	"strconv"
	"strings"
	"github.com/coreos/go-iptables/iptables"
)

type Configuration struct {
	LogFile      string
	IpRegEx      string
	RulesFile    string
	BanThreshold int
	IPWhitelist  string
	Rules        map[*regexp.Regexp]int
}

var fm *filemonitor.FileMonitor
var watchlist map[string]int
var config Configuration

func main() {

	initConfig()
	initJail()

	rIP, _ := regexp.Compile(config.IpRegEx) //IP regexp

	fm = filemonitor.NewFileMonitor()
	fc, err := fm.AddFile(config.LogFile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	for {
		select {
		case line := <-fc.Cout:
			for r, v := range config.Rules {
				if r.MatchString(line) {
					ip := rIP.FindString(line)
					watchlist[ip] += v
					fmt.Printf("%d | "+line, watchlist[ip])
					if watchlist[ip] >= config.BanThreshold {
						jail.BlockIP(ip)
					}

				}
			}

		case err := <-fc.Cerr:
			fmt.Println(err)
			return
		}
	}

}

func initConfig() {
	watchlist = make(map[string]int, 1000)

	//read config
	conf, _ := os.Open("config.json")
	decoder := json.NewDecoder(conf)
	config = Configuration{}
	err := decoder.Decode(&config)
	if err != nil {
		fmt.Println("config error:", err)
	}
	fmt.Println(config)

	config.Rules = make(map[*regexp.Regexp]int, 10) //init rules
	readRules(config.RulesFile, config.Rules)       //read rules
	readWhitelist(config.IPWhitelist)
}


func initJail(){
	ipt, err := iptables.New()
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
	jail.Setup(ipt)
}

func readWhitelist(path string) {
	file, _ := os.Open(path)
	reader := bufio.NewReader(file)
	lineN := 0
	eof := false
	for !eof {
		lineN++
		bytes, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			fmt.Println("whilelist file read error:", err)
			return
		}
		if err == io.EOF {
			eof = true
			continue
		}

		line := string(bytes[:len(bytes)-1])
		jail.AppendWhitelist(line)

	}
}

func readRules(path string, rules map[*regexp.Regexp]int) {
	file, _ := os.Open(path)
	reader := bufio.NewReader(file)
	lineN := 0
	eof := false
	for !eof {
		lineN++
		bytes, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			fmt.Println("rules file read error:", err)
			return
		}
		if err == io.EOF {
			eof = true
			continue
		}

		line := string(bytes[:len(bytes)-1])
		i := strings.Index(line, " ")

		if i > -1 {
			pointsString := line[:i]
			rule := line[i+1:]

			points, err := strconv.Atoi(pointsString)
			if err != nil {
				fmt.Println("Rules error: Points is not integer. line:", lineN)
				return
			}

			r, err := regexp.Compile(rule)
			if err != nil {
				fmt.Println("Rules error: Bad regexp. Line: ", lineN)
				return
			}

			rules[r] = points

		} else {
			fmt.Println("Rules error: No delimiter. line:", lineN)
			return
		}
	}
}
