package ptake_pkg

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"ptake/config"
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
	wf, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Println(err)
	}
	defer wf.Close()
	wf.Write(results)
	wf.WriteString("\n")
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
	wf, err := os.OpenFile(output, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Println(err)
	}
	defer wf.Close()
	status, _ := json.Marshal(domainStatus)
	wf.Write(status)
	wf.WriteString("\n")
}

func getCheckInfo(status DomainStatus, o *config.GlobalConfig) (resultStr string) {

	if status.VulnerableLevel != 0 {
		switch status.Type {
		case "Available":
			resultStr = fmt.Sprintf("[Available]  %s\n", status.Domain)
		case "MatchServicePattern":
			resultStr = fmt.Sprintf("[MatchServicePattern] %s", status.Domain)
			for i := range status.MatchedServices {
				matchedService := status.MatchedServices[i]
				resultStr += fmt.Sprintf(" -(%s)", strings.ToUpper(matchedService.Service))
			}
			//resultStr = fmt.Sprintf("[%s]%s", status.MatchServiceCnames, status.Domain)
		case "AbandonedService":
			resultStr = fmt.Sprintf("[AbandonedService] %s ", status.Domain)
			for i := range status.MatchedServices {
				matchedService := status.MatchedServices[i]
				resultStr += fmt.Sprintf(" -(%s)\n", strings.ToUpper(matchedService.Service))
			}

			for i := range status.VulCnames {
				resultStr += fmt.Sprintf("[CnameVulnerable]  %s -> %s\n", status.Domain, status.VulCnames[i].Domain) + getCheckInfo(status.VulCnames[i], o)
			}

		case "CnameVulnerable":
			resultStr = ""
			for i := range status.VulCnames {
				resultStr += fmt.Sprintf("[CnameVulnerable]  %s -> %s\n", status.Domain, status.VulCnames[i].Domain) + getCheckInfo(status.VulCnames[i], o)
			}
		default:
			resultStr = fmt.Sprintf("[Vulnerable]%s", status.Domain)
		}
	}

	if status.VulnerableLevel == 0 && o.Verbose {
		resultStr = fmt.Sprintf("[NotVulnerable]%s", status.Domain)
	}
	return resultStr
}

//func saveJson(serviceInfo, subdomain, output string) {
//	var res Results
//	if strings.Contains(serviceInfo, "DOMAIN AVAILABLE") {
//		service := strings.Split(serviceInfo, " - ")[1]
//		serviceCname := strings.Split(serviceInfo, " - ")[2]
//
//		res = Results{
//			Subdomain:  strings.ToLower(subdomain),
//			Vulnerable: true,
//			Type:       "cname available",
//			Service:    strings.ToLower(service),
//			Domain:     strings.ToLower(serviceCname),
//		}
//	} else {
//		if serviceInfo != "" {
//			res = Results{
//				Subdomain:  strings.ToLower(subdomain),
//				Vulnerable: true,
//				Type: "match fingerprints",
//				Service: strings.ToLower(serviceInfo),
//			}
//		} else {
//			res = Results{
//				Subdomain:  strings.ToLower(subdomain),
//				Vulnerable: false,
//			}
//		}
//	}
//
//	f, err := os.OpenFile(output, os.O_CREATE|os.O_RDWR, 0600)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	defer f.Close()
//
//	file, err := ioutil.ReadAll(f)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	var data []Results
//	json.Unmarshal(file, &data)
//	data = append(data, res)
//
//	results, _ := json.Marshal(data)
//
//	wf, err := os.OpenFile(output, os.O_CREATE|os.O_RDWR, 0600)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	defer wf.Close()
//
//	wf.Write(results)
//}

//func saveDomainStatus(domainStatus DomainStatus, output string) {
//	f, err := os.OpenFile(output, os.O_CREATE|os.O_RDWR, 0600)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	defer f.Close()
//
//	file, err := ioutil.ReadAll(f)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	var data []DomainStatus
//	json.Unmarshal(file, &data)
//	data = append(data, domainStatus)
//
//	results, _ := json.Marshal(data)
//
//	wf, err := os.OpenFile(output, os.O_CREATE|os.O_RDWR, 0600)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	defer wf.Close()
//
//	wf.Write(results)
//}
