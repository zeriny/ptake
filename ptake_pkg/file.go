package ptake_pkg

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)


func readFile(path string) (lines []string, Error error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func readFqdnFile(path string, index int) (lines []string, Error error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ","){
			subdomain := strings.Split(line, ",")[index]
			lines = append(lines, subdomain)
		} else{
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
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

// isJSON returns true if the suffix of the output file is ".json"
func isJSON(output string) (json bool) {
	json = false

	if strings.Contains(output, ".json") {
		if output[len(output)-5:] == ".json" {
			json = true
		}
	}
	return json
}

func save(s string, file string){
	f, err := os.OpenFile(file, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	_, err = f.WriteString(s+"\n")
	if err != nil {
		log.Fatalln(err)
	}
}
func saveSubdomains(sld string, subdomains []string, outputFile string) {
	f, err := os.OpenFile(outputFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalln(err)
	}

	defer f.Close()
	for i := range subdomains{
		_, err = f.WriteString(sld+","+subdomains[i]+"\n")
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func saveCnames(cname CNAME, output string) {
	results, _ := json.Marshal(cname)
	wf, err := os.OpenFile(output, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Println(err)
	}
	defer wf.Close()
	wf.Write(results)
	wf.WriteString("\n")
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

func getCheckInfo(status DomainStatus, o *Options) (resultStr string){

	if status.VulnerableLevel!=0{
		switch status.Type {
		case "Available":
			resultStr = fmt.Sprintf("[Available]  %s\n", status.Domain)
		case "MatchServicePattern":
			resultStr = fmt.Sprintf("[MatchServicePattern] %s",status.Domain)
			for i := range status.MatchedServices{
				matchedService := status.MatchedServices[i]
				resultStr += fmt.Sprintf(" -(%s)", strings.ToUpper(matchedService.Service))
			}
			//resultStr = fmt.Sprintf("[%s]%s", status.MatchServiceCnames, status.Domain)
		case "AbandonedService":
			resultStr = fmt.Sprintf("[AbandonedService] %s ", status.Domain)
			for i := range status.MatchedServices{
				matchedService := status.MatchedServices[i]
				resultStr += fmt.Sprintf(" -(%s)\n", strings.ToUpper(matchedService.Service))
			}

			for i := range status.VulCnames{
				resultStr += fmt.Sprintf("[CnameVulnerable]  %s -> %s\n", status.Domain, status.VulCnames[i].Domain) + getCheckInfo(status.VulCnames[i], o)
			}

		case "CnameVulnerable":
			resultStr = ""
			for i := range status.VulCnames{
				//resultStr = fmt.Sprintf("[%s]%s", status.VulCnames[i].Type, status.VulCnames[i].Domain)
				//status.VulCnames[i].Type
				//resultStr += "|"+fmt.Sprintf("[%s]%s", status.VulCnames[i].Type, status.VulCnames[i].Domain)
				resultStr += fmt.Sprintf("[CnameVulnerable]  %s -> %s\n", status.Domain, status.VulCnames[i].Domain) + getCheckInfo(status.VulCnames[i], o)
			}
		default:
			resultStr = fmt.Sprintf("[Vulnerable]%s", status.Domain)
		}
	}

	if status.VulnerableLevel==0 && o.Verbose{
		resultStr = fmt.Sprintf("[NotVulnerable]%s", status.Domain)
	}
	return resultStr
}