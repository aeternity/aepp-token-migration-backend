package utils

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// GetIPFromRequest gets ip from current request
func GetIPFromRequest(req *http.Request) (net.IP, error) {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("userip: %q is not IP:port", req.RemoteAddr)
	}

	userIP := net.ParseIP(ip)
	if userIP == nil {
		return nil, fmt.Errorf("userip: %q is not IP:port", req.RemoteAddr)
	}
	return userIP, nil
}

// LogRequest log user request
func LogRequest(req *http.Request, route string) {
	ip, err := GetIPFromRequest(req)
	if err != nil {
		log.Println("[ERROR] Cannot get user ip!", err)
		// http.Error(w, "Cannot get user ip!", 400)
		// return
	}

	logStr := fmt.Sprintf("IP: %v, Route: %s", ip, route)

	log.Printf(logStr)
	// go writeLogToFile(logStr)
}

func writeLogToFile(data string) {
	t := time.Now()
	date := fmt.Sprintf(t.Format("2006-01-02"))
	path := fmt.Sprintf("./logs/%s-log.log", date)

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("[ERROR] Cannot create file!", err)
	}
	defer file.Close()

	hour := strconv.Itoa(t.Hour())
	if len(hour) == 1 {
		hour = fmt.Sprintf("0%v", hour)
	}

	minutes := strconv.Itoa(t.Minute())
	if len(minutes) == 1 {
		minutes = fmt.Sprintf("0%v", minutes)
	}

	seconds := strconv.Itoa(t.Second())
	if len(seconds) == 1 {
		seconds = fmt.Sprintf("0%v", seconds)
	}

	//file.WriteString(fmt.Sprintln(fmt.Sprintf("%v:%v:%v:%d | ", hour, minutes, seconds, t.Nanosecond()), data))
}

// GetContractSource get contract source from the provided URL
func GetContractSource(contractRawUrlGit string) string {

	if contractRawUrlGit == "" {
		log.Println("Provide url git repo")
		dat, err := ioutil.ReadFile("contract/test-contract.aes")
		if err != nil {
			log.Println(err)
			return ""
		}

		return string(dat)
	}

	resp, err := http.Get(contractRawUrlGit)
	if err != nil {
		log.Printf("Somthing went wrong! Error: %s", err)
		return ""
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Somthing went wrong! Error: %s", err)
		return ""
	}

	return string(body)
}

// PreHashFormat prepare string format before hashing
func PreHashFormat(address string, amount string) string {
	return strings.ToUpper(fmt.Sprintf("%s:%s", address, amount))
}
