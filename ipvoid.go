package main

import (
	"bufio"
	"encoding/json"
	"encoding/gob"
	"fmt"
	"log"
	"github.com/coreos/go-iptables/iptables"
	"html/template"
	"io"
	"ipvoid/filemonitor"
	"ipvoid/jail"
	"ipvoid/resolver"
	"ipvoid/voidlog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type StatPageData struct {
	Watchlist []stat
	Jaillist  []stat
	History   []string
	Log       []string
}

type stat struct {
	IP    string
	Score float32
	Host  string
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

const statedir string = "state"


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


	loadState()
	go webserver()
	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

	timer := time.NewTicker(time.Minute)

	for {
		select {
		case line := <-fc.Cout:
			for r, v := range config.Rules {
				if r.MatchString(line) {
					ip := rIP.FindString(line)
					watchlist[ip] += float32(v)
					//fmt.Printf("%.2f | " + line, watchlist[ip])
					voidlog.Log("%.2f | "+line, watchlist[ip])
					resolver.Lookup(ip)
					if watchlist[ip] >= float32(config.BanThreshold) {
						jail.BlockIP(ip, watchlist[ip])
					}

				}
			}

		case err := <-fc.Cerr:
			//fmt.Println(err)
			voidlog.Log(err)
			return

		case <-timer.C:
			for k, v := range watchlist {
				watchlist[k] = v - decPerCycle
				//fmt.Printf("IP Score status: %s : %.2f \n", k, watchlist[k])

				if watchlist[k] <= 0 {
					delete(watchlist, k)
					//fmt.Printf("Removing IP: %s \n", k)
					voidlog.Log("Removing IP: %s \n", k)
				}
			}
		case <-terminate:
			log.Println("Shutting down")
			onShutDown()
			os.Exit(0)

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

func initJail() {
	ipt, err := iptables.New()
	if err != nil {
		fmt.Printf("IPtables init issue: %v", err)
		os.Exit(1)
	}

	err = jail.Setup(ipt)
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
		var stathistory []string
		var log []string

		//sorting watch list
		for k, v := range watchlist {
			host := resolver.Lookup(k)
			statWatch = append(statWatch, stat{k, v, host})
		}

		sort.Slice(statWatch, func(i, j int) bool {
			return statWatch[i].Score > statWatch[j].Score
		})

		//sorting jail list
		for k, v := range jail.Ip_list {
			host := resolver.Lookup(k)
			statJail = append(statJail, stat{k, v, host})
		}

		sort.Slice(statJail, func(i, j int) bool {
			return statJail[i].Score > statJail[j].Score
		})

		//copy jail history data
		jail.JailHistory.Do(func(p interface{}) {
			if p != nil {
				stathistory = append(stathistory, p.(string))
			}
		})
		//reverse history
		for i, j := 0, len(stathistory)-1; i < j; i, j = i+1, j-1 {
			stathistory[i], stathistory[j] = stathistory[j], stathistory[i]
		}

		//copy log data
		voidlog.LogHistory.Do(func(p interface{}) {
			if p != nil {
				log = append(log, p.(string))
			}
		})
		//reverse log
		for i, j := 0, len(log)-1; i < j; i, j = i+1, j-1 {
			log[i], log[j] = log[j], log[i]
		}

		data.Watchlist = statWatch
		data.Jaillist = statJail
		data.History = stathistory
		data.Log = log
		tmpl.Execute(w, data)
	})
	http.ListenAndServe(":9900", nil)
}



func onShutDown() {
	jail.ClearJail()
	storeState()
}


func storeState() {
	if _, err := os.Stat(statedir); os.IsNotExist(err) {
		os.MkdirAll(statedir, 0755)
	} 

	file, err := os.Create(statedir + "/watchlist")
	if err != nil {
		log.Println("Couldn't save state: File create failed. " + err.Error())
		return
	}
	encoder := gob.NewEncoder(file)
	encoder.Encode(watchlist)
	file.Close()
}


func loadState() {
	file, err := os.Open(statedir + "/watchlist")
	if err != nil {
		return
	}
	defer file.Close()
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&watchlist)
	if err != nil {
		log.Println("Couldn't load state " + err.Error())
	} else {
		log.Println("State loaded")
	}
	
	for ip, v := range watchlist {
		if v >= float32(config.BanThreshold) {
			jail.BlockIP(ip, v)
		}
	}
}
