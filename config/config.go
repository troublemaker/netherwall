package config

import (
	"bufio"
	"regexp"
	"encoding/json"
	"os"
	"fmt"
	"io"
	"strconv"
	"strings"
)


type Configuration struct {
	LogFile      string
	IpRegEx      string
	RulesFile    string
	BanThreshold int
	DecreasePerMinute float32
	IPWhitelist  string
	CIDRWhitelist []string
	Rules        map[*regexp.Regexp]int
}

var Data Configuration = Configuration{}

func Setup() error {
	conf, err := os.Open("config.json")
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(conf)
	err = decoder.Decode(&Data)
	if err != nil {
		return err
	}
	fmt.Println(Data)

	Data.Rules = make(map[*regexp.Regexp]int, 10) //init rules
	readRules(Data.RulesFile, Data.Rules)       //read rules
	//readWhitelist(Data.IPWhitelist)

	return nil
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


// func readWhitelist(path string) {
// 	file, _ := os.Open(path)
// 	reader := bufio.NewReader(file)
// 	lineN := 0
// 	eof := false
// 	for !eof {
// 		lineN++
// 		bytes, err := reader.ReadBytes('\n')
// 		if err != nil && err != io.EOF {
// 			fmt.Println("whilelist file read error:", err)
// 			return
// 		}
// 		if err == io.EOF {
// 			eof = true
// 			continue
// 		}

// 		line := string(bytes[:len(bytes)-1])
// 		jail.AppendWhitelist(line)

// 	}
// }

