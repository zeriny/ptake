package ptake_pkg

import (
	"bufio"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"

)

func readCache(file string) (cacheMap map[string]int) {
	cacheMap = make(map[string]int)
	_, err := os.Stat(file)
	if err == nil {
		items := readFile(file)
		for i := range items {
			cacheMap[items[i]] = 1
		}
	}
	return cacheMap
}

func saveCache(s string, file string) {
	f, err := os.OpenFile(file, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	_, err = f.WriteString(s + "\n")
	if err != nil {
		log.Fatalln(err)
	}
}

func readFile(path string) (lines []string) {
	fmt.Println("Read File: ", path)
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln(err)
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)
	// Hint: The default MaxScanTokenSize is set with 64 * 1024 (65536). If exceeded, ErrTooLong will be thrown.
	scanner.Buffer([]byte{}, bufio.MaxScanTokenSize*10)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanner.Err() != nil {
		log.Fatalln(scanner.Err())
	}
	return lines
}

func readFqdnFile(path string, index int) (lines []string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ",") {
			subdomain := strings.Split(line, ",")[index]
			lines = append(lines, subdomain)
		} else {
			lines = append(lines, line)
		}
	}
	if scanner.Err() != nil {
		log.Fatalln(err)
	}

	return lines
}

func saveFqdnFile(sld string, subdomains []string, outputFile string) {
	f, err := os.OpenFile(outputFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalln(err)
	}

	defer f.Close()

	for i := range subdomains {
		_, err = f.WriteString(sld + "," + subdomains[i] + "\n")
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func readCnameFile(path string) (fqdns []string, cnames []CNAME, Error error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		var cname CNAME
		json.Unmarshal(line, &cname)
		cnames = append(cnames, cname)
		fqdns = append(fqdns, cname.Domain)
	}
	return fqdns, cnames, scanner.Err()
}

func saveCnameFile(cname CNAME, path string) {
	results, _ := json.Marshal(cname)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	file.WriteString(string(results)+"\n")
}

func saveChainFile(chain DnsChain, path string) {
	results, _ := json.Marshal(chain)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	file.WriteString(string(results)+"\n")
}


func saveNsFile(ns NSType, path string) {
	results, _ := json.Marshal(ns)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	file.WriteString(string(results)+"\n")
}


func readDomainStatus(path string) (fqdns []string, Error error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		var domainStatus DomainStatus
		json.Unmarshal(line, &domainStatus)
		fqdns = append(fqdns, domainStatus.Domain)
	}
	return fqdns, scanner.Err()
}

func saveDomainStatus(domainStatus DomainStatus, output string) {
	file, err := os.OpenFile(output, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	status, _ := json.Marshal(domainStatus)
	writer.WriteString(string(status)+"\n")
	writer.Flush()
}
