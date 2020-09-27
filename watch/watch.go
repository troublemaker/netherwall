package watch

import (
	"encoding/gob"
	"fmt"
	"ipvoid/config"
	"ipvoid/filemonitor"
	"ipvoid/jail"
	"ipvoid/resolver"
	"ipvoid/voidlog"
	"log"
	"os"
	"regexp"
	"time"
)

var fm *filemonitor.FileMonitor
var Watchlist map[string]float32

const statedir string = "state"

func Run() {
	Watchlist = make(map[string]float32, 1000)
	loadState()

	rIP, _ := regexp.Compile(config.Data.IpRegEx) //IP regexp

	fm = filemonitor.NewFileMonitor()
	fc, err := fm.AddFile(config.Data.LogFile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	timer := time.NewTicker(time.Minute)

	for {
		select {
		case line := <-fc.Cout:
			for r, v := range config.Data.Rules {
				if r.MatchString(line) {
					ip := rIP.FindString(line)
					Watchlist[ip] += float32(v)
					voidlog.Log("%.2f | "+line, Watchlist[ip])
					resolver.Lookup(ip)
					if Watchlist[ip] >= float32(config.Data.BanThreshold) {
						jail.BlockIP(ip, Watchlist[ip])
					}

				}
			}

		case err := <-fc.Cerr:
			voidlog.Log(err)
			return

		case <-timer.C:
			for k, v := range Watchlist {
				Watchlist[k] = v - config.Data.DecreasePerMinute
				//log.Printf("IP Score status: %s : %.2f \n", k, Watchlist[k])

				if Watchlist[k] <= 0 {
					delete(Watchlist, k)
					voidlog.Log("Removing IP: %s \n", k)
				}
			}
		}
	}
}

func StoreState() {
	if _, err := os.Stat(statedir); os.IsNotExist(err) {
		os.MkdirAll(statedir, 0755)
	}

	file, err := os.Create(statedir + "/watchlist")
	if err != nil {
		log.Println("Couldn't save state: File create failed. " + err.Error())
		return
	}
	encoder := gob.NewEncoder(file)
	encoder.Encode(Watchlist)
	file.Close()
}

func loadState() {
	file, err := os.Open(statedir + "/watchlist")
	if err != nil {
		return
	}
	defer file.Close()
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&Watchlist)
	if err != nil {
		log.Println("Couldn't load state " + err.Error())
	} else {
		log.Println("State loaded")
	}

	for ip, v := range Watchlist {
		if v >= float32(config.Data.BanThreshold) {
			jail.BlockIP(ip, v)
		}
	}
}
