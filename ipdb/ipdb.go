package ipdb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

type IPRange struct {
	ipStart    int
	ipEnd      int
	CoutryCode string
	CoutryName string
}

type IPDataBase struct {
	ipStartArray []int
	ipRangeMap   map[int]IPRange
	Loaded       bool
}

func Create(path string) (error, *IPDataBase) {
	ips := &IPDataBase{Loaded: false}

	ips.ipStartArray = make([]int, 0)
	ips.ipRangeMap = make(map[int]IPRange)

	file, err := os.Open(path)
	if err != nil {
		return err, ips
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {

		line := scanner.Text()
		elements := strings.Split(line, ",")

		for i, e := range elements {
			elements[i] = strings.Trim(e, "\"")
		}

		ipStart, err := strconv.Atoi(elements[0])
		if err != nil {
			return err, ips
		}

		ipEnd, err := strconv.Atoi(elements[1])
		if err != nil {
			return err, ips
		}

		//TODO validate all values
		ips.ipStartArray = append(ips.ipStartArray, ipStart)
		ips.ipRangeMap[ipStart] = IPRange{ipStart, ipEnd, elements[2], elements[3]}

	}

	sort.Ints(ips.ipStartArray)
	ips.Loaded = true
	return nil, ips

}

func (ips *IPDataBase) CheckIP(ip string) (error, *IPRange) {
	err, ipInt := ip2Int(ip)

	if err != nil {
		return err, nil
	}

	offset := ips.findOffset(ipInt)

	if (ips.ipRangeMap[offset].ipStart <= ipInt) && (ips.ipRangeMap[offset].ipEnd >= ipInt) {
		//log.Printf("PROXY: %+v \n", ips.ipRangeMap[offset])
		ipRange := ips.ipRangeMap[offset]
		return nil, &ipRange
	}

	return nil, nil

}

func (ips *IPDataBase) findOffset(ipInt int) int {
	index := sort.SearchInts(ips.ipStartArray, ipInt)

	if len(ips.ipStartArray) == index {
		return ips.ipStartArray[index-1]
	}

	if 0 == index {
		return ips.ipStartArray[index]
	}

	if ips.ipStartArray[index] == ipInt {
		return ips.ipStartArray[index]
	} else {
		return ips.ipStartArray[index-1]
	}

}

func ip2Int(ip string) (error, int) {
	res := net.ParseIP(ip)
	if res == nil {
		return errors.New("Parameter is not an IP"), 0
	}
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	return nil, int(long)
}
