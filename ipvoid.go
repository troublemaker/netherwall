package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"ipvoid/filemonitor"
	"ipvoid/jail"
	"ipvoid/resolver"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
    "html/template"
    "net/http"	
	"github.com/coreos/go-iptables/iptables"
	"sort"
)

type StatPageData struct {
    Watchlist []stat
    Jaillist []stat
}

type stat struct {
    IP   string
    Score float32
    Host string
}




type Configuration struct {
	LogFile      string
	IpRegEx      string
	RulesFile    string
	BanThreshold int
	IPWhitelist  string
	Rules        map[*regexp.Regexp]int
}

var fm *filemonitor.FileMonitor
var watchlist map[string]float32
var config Configuration
var decPerCycle float32 = 0.05
const chain string = "ipvoid"


//TODO clear Jail on shutdown
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

	go webserver()

	timer := time.NewTicker(time.Minute)

	for {
		select {
		case line := <-fc.Cout:
			for r, v := range config.Rules {
				if r.MatchString(line) {
					ip := rIP.FindString(line)
					watchlist[ip] += float32(v)
					fmt.Printf("%.2f | "+line, watchlist[ip])
					resolver.Lookup(ip)
					if watchlist[ip] >= float32(config.BanThreshold) {
						jail.BlockIP(ip, watchlist[ip])
					}

				}
			}

		case err := <-fc.Cerr:
			fmt.Println(err)
			return

		case <-timer.C:
			for k, v := range watchlist {
				watchlist[k] = v - decPerCycle
				//fmt.Printf("IP Score status: %s : %.2f \n", k, watchlist[k])

				if watchlist[k] <= 0 {
					delete(watchlist, k)
					fmt.Printf("Removing IP: %s \n", k)
				}
			}
		}
	}

}

func initConfig() {
	watchlist = make(map[string]float32, 1000)

	//read config
	conf, _ := os.Open("config.json")
	decoder := json.NewDecoder(conf)
	config = Configuration{}
	err := decoder.Decode(&config)
	if err != nil {
		fmt.Println("config error:", err)
		os.Exit(1)
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
		os.Exit(1)
	}

	err = jail.Setup(ipt, chain)
	if err != nil {
		fmt.Printf("IPtables setup issue: %v", err)
		os.Exit(1)
	}
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


func webserver() {
    tmpl := template.Must(template.ParseFiles("template/index.html"))
    http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
    	data := StatPageData{}

	    var statWatch []stat
	    var statJail []stat

	    //sorting watch list 
	    for k, v := range watchlist {
	    	host, _ := resolver.Lookup(k)
	        statWatch = append(statWatch, stat{k, v, host})
	    }

	    sort.Slice(statWatch, func(i, j int) bool {
	        return statWatch[i].Score > statWatch[j].Score
	    })

	    //sorting jail list
	    for k, v := range jail.Ip_list {
	    	host, _ := resolver.Lookup(k)
	        statJail = append(statJail, stat{k, v, host})
	    }

	    sort.Slice(statJail, func(i, j int) bool {
	        return statJail[i].Score > statJail[j].Score
	    })


    	data.Watchlist = statWatch
    	data.Jaillist = statJail
    	tmpl.Execute(w, data)
    })
    http.ListenAndServe(":9900", nil)
}
