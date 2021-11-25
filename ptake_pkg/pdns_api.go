package ptake_pkg

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
	"strings"
)

func getSubdomainFromPDNS(domain string, timeout int, retries int, conf Conf) (subdomains []string) {
	domain2Count := make(map[string]int)

	url := fmt.Sprintf(conf.PdnsSubdomainUrl, domain)
	tokenHeader := make(map[string]string)
	tokenHeader["fdp-token"] = conf.PdnsApiToken

	var body []byte
	var respBody PDNSResponse
	for i := 1; i <= retries; i++ {
		body = get(url, timeout, tokenHeader)
		if body == nil {
			log.Printf("[PDNS API - subdomain] No response! Retrying %s...", domain)
			time.Sleep(1 * time.Second)
			continue
		}
	}
	jsonErr := json.Unmarshal(body, &respBody)
	if jsonErr != nil {
		log.Printf("[PDNS API - subdomain] %s: %s\n", domain, jsonErr)
		return subdomains
	}

	if respBody.StatusCode != 200 {
		return subdomains
	}

	// Sum up all RequestCount for each rrname
	data := respBody.Data
	for i := range data {
		fqdn := data[i].RRName
		rdata := strings.TrimRight(data[i].Rdata, ";")
		if fqdn == domain {
			continue
		}

		if !strings.Contains(rdata, ".") {
			continue
		}
		_, ok := domain2Count[fqdn]
		if ok {
			domain2Count[fqdn] = domain2Count[fqdn] + data[i].Count
		} else {
			domain2Count[fqdn] = data[i].Count
		}
	}

	// Filter by access count
	for fqdn, count := range domain2Count {
		if count >= conf.SubAccess {
			subdomains = append(subdomains, fqdn)
		}
	}
	if len(subdomains)== 0{
		subdomains = append(subdomains, domain)
	}
	return subdomains
}

// Get CNAME records via PDN API.
// TODO:
// 1. set parameters by configurations. (done)
// 2. filter CNAME records by access count and last_seen time, ensuring the records are still alive.
func getCnamesFromPDNS(domain string, timeout int, retries int, conf Conf) (cnames []string) {
	//limit := 200
	//minAccess := 200

	url := fmt.Sprintf(conf.PdnsCnameUrl, domain)
	tokenHeader := make(map[string]string)
	tokenHeader["fdp-token"] = conf.PdnsApiToken

	var body []byte
	var respBody PDNSResponse
	for i := 1; i <= retries; i++ {
		body = get(url, timeout, tokenHeader)
		if body == nil {
			log.Printf("[PDNS API - CNAME] No response! Retrying %s...", domain)
			time.Sleep(1 * time.Second)
			continue
		}
	}

	jsonErr := json.Unmarshal(body, &respBody)
	if jsonErr != nil {
		log.Printf("[PDNS API - CNAME] %s: %s\n", domain, jsonErr)
		return cnames
	}

	if respBody.StatusCode != 200 {
		return cnames
	}

	data := respBody.Data
	var cnameList []string
	for i := range data {
		rdata := strings.TrimRight(data[i].Rdata, ";")
		if data[i].Count > conf.CnameAccess {
			cnameList = append(cnameList, rdata)
		}
	}

	for i := range cnameList {
		cnames = append(cnames, cnameList[i])
	}

	return cnames
}
