package config

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Configuration struct {
	LogFile                            string
	IpRegEx                            string
	RulesFile                          string
	BanThreshold                       int
	DecreasePerMinute                  float32
	IPWhitelist                        string
	CIDRWhitelist                      []string
	Rules                              map[*regexp.Regexp]int
	UseProxyDetection                  bool
	ProxyCSV                           string
	ProxyScoreMultiplier               int
	ProxyCountryScoreMultiplier        int
	ProxyCountriesList                 []string
	ProxyCountriesListModeWhitelist    bool
	UseGEODetection                    bool
	GeoBlockCSV                        string
	GeoBlockCountriesList              []string
	GeoBlockCountriesListModeWhitelist bool
	GeoBlockDuration                   int
}

var Data Configuration = Configuration{}
var configFile = "config.json"

func Setup() error {
	conf, err := os.Open(configFile)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(conf)
	err = decoder.Decode(&Data)
	if err != nil {
		return err
	}

	//init rules
	Data.Rules = make(map[*regexp.Regexp]int, 10)

	//read rules
	err = readRules(Data.RulesFile, Data.Rules)
	if err != nil {
		return err
	}

	return nil
}

func readRules(path string, rules map[*regexp.Regexp]int) error {
	file, _ := os.Open(path)
	reader := bufio.NewReader(file)
	lineN := 0
	eof := false
	for !eof {
		lineN++
		bytes, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return err
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
				log.Println("Rules error: Points is not integer. line:", lineN)
				return err
			}

			r, err := regexp.Compile(rule)
			if err != nil {
				log.Println("Rules error: Bad regexp. Line: ", lineN)
				return err
			}

			rules[r] = points

		} else {
			log.Println("Rules error: No delimiter. line:", lineN)
			return err
		}
	}

	return nil
}
