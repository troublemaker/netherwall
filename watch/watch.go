package watch

import (
	"encoding/gob"
	"fmt"
	"ipvoid/config"
	"ipvoid/filemonitor"
	"ipvoid/ipdb"
	"ipvoid/jail"
	"ipvoid/resolver"
	"ipvoid/voidlog"
	"log"
	"os"
	"regexp"
	"time"
)

var fm *filemonitor.FileMonitor
var Watchlist map[string]float32 //TODO: possible RC (from web module)
var proxyDB *ipdb.IPDataBase
var geoDB *ipdb.IPDataBase

const statedir string = "state"

func Run() {
	Watchlist = make(map[string]float32, 1000)
	loadState()

	rIP, _ := regexp.Compile(config.Data.IpRegEx) //IP regexp

	fm = filemonitor.NewFileMonitor()
	fc, err := fm.AddFile(config.Data.LogFile)
	if err != nil {
		log.Println(err.Error())
		return
	}

	timer := time.NewTicker(time.Minute)

	for {
		select {
		case line := <-fc.Cout:
			//TODO: validate IP
			ip := rIP.FindString(line)

			//PROCESS HTTP REQUEST VS RULES
			for r, v := range config.Data.Rules {
				if r.MatchString(line) {
					multiplyFactorsLog := ""
					//check ProxyDB
					if proxyDB != nil && proxyDB.Loaded {
						_, ipRange := proxyDB.CheckIP(ip)

						if ipRange != nil {
							//multiply for proxy match
							v = v * config.Data.ProxyScoreMultiplier
							multiplyFactorsLog = fmt.Sprintf("PROXY[x%d] ", config.Data.ProxyScoreMultiplier)

							//check if we have a country match
							countryMatched := false
							for _, v := range config.Data.ProxyCountriesList {
								if v == ipRange.CoutryCode {
									countryMatched = true
									break
								}
							}

							if config.Data.ProxyCountriesListModeWhitelist {
								if !countryMatched {
									v = v * config.Data.ProxyCountryScoreMultiplier
									multiplyFactorsLog = multiplyFactorsLog + fmt.Sprintf("%s[x%d] ", ipRange.CoutryCode, config.Data.ProxyCountryScoreMultiplier)
								}
							} else {
								if countryMatched {
									v = v * config.Data.ProxyCountryScoreMultiplier
									multiplyFactorsLog = multiplyFactorsLog + fmt.Sprintf("%s[x%d] ", ipRange.CoutryCode, config.Data.ProxyCountryScoreMultiplier)
								}
							}
						}
					}

					Watchlist[ip] += float32(v)
					voidlog.Log(fmt.Sprintf("%.2f | ", Watchlist[ip]) + multiplyFactorsLog + line)
					resolver.Lookup(ip)

					if Watchlist[ip] >= float32(config.Data.BanThreshold) {
						jail.BlockIP(ip, Watchlist[ip])
					}

				}
			}

			//PROCESS IP ITSELF
			if geoDB != nil && geoDB.Loaded {
				_, ipRange := geoDB.CheckIP(ip)
				if ipRange != nil {
					if proxyDB != nil && proxyDB.Loaded {

						//check if we have a country match
						countryMatched := false
						for _, v := range config.Data.GeoBlockCountriesList {
							if v == ipRange.CoutryCode {
								countryMatched = true
								break
							}
						}

						if (config.Data.GeoBlockCountriesListModeWhitelist && !countryMatched) || (!config.Data.GeoBlockCountriesListModeWhitelist && countryMatched) {
							Watchlist[ip] += float32(config.Data.GeoBlockDuration)
							voidlog.Log(fmt.Sprintf("%.2f | ", Watchlist[ip]) + fmt.Sprintf("GEO-BLOCK[%s] ", ipRange.CoutryCode) + line)
							jail.BlockIP(ip, Watchlist[ip])
						}
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
					voidlog.Logf("Removing IP: %s \n", k)
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

func AddProxyDB(prDB *ipdb.IPDataBase) {
	proxyDB = prDB
}

func AddGeoDB(gDB *ipdb.IPDataBase) {
	geoDB = gDB
}
