package ptake_pkg

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"ptake/config"
	"strings"
	"time"
)

func getPDNSResponse(url string, timeout int, addHeaders map[string]string) (body PDNSResponse, retry bool) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(url)
	req.Header.Add("Connection", "close")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36")
	for header := range addHeaders {
		req.Header.Add(header, addHeaders[header])
	}
	req.Header.SetMethod("GET")

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	client := &fasthttp.Client{TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	client.DoTimeout(req, resp, time.Duration(timeout)*time.Second)
	b := resp.Body()
	if b == nil {
		return body, true
	}
	jsonErr := json.Unmarshal(b, &body)
	if jsonErr != nil {
		log.Errorf("[PDNS API - getPDNSResponse] %s: %s", url, jsonErr)
		return body, true
	}
	return body, false
}

func getSubdomainFromPDNS(domain string, timeout int, retries int, conf config.Conf) (subdomains []string) {
	domain2Count := make(map[string]int)

	now := time.Now()
	sd, _ := time.ParseDuration("-24h")
	endtime := now.Format("20060102150405")
	starttime := now.Add(sd*7).Format("20060102150405") // only fetch 7-day data

	url := fmt.Sprintf(conf.PdnsSubdomainUrl, domain, starttime, endtime)

	tokenHeader := make(map[string]string)
	tokenHeader["fdp-token"] = conf.PdnsApiToken

	var respBody PDNSResponse
	var retryFlag bool

	for i := 1; i <= retries; i++ {
		respBody, retryFlag = getPDNSResponse(url, timeout, tokenHeader)
		if retryFlag == false {
			break
		}
		log.Warningf("[PDNS API - subdomain] No response! Retrying %s...", domain)
		time.Sleep(1 * time.Second)
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

// Get DNS records via PDN API.
// TODO:
// 1. set parameters by configurations. (done)
// 2. filter DNS records by access count, ensuring the records are still alive (done).
func getChainsFromPDNS(domain string, timeout int, retries int, conf config.Conf) (chains []PDNSRecord) {
	// Only get cname chains appeared on the detection day.
	now := time.Now()
	sd, _ := time.ParseDuration("-24h")
	endtime := now.Format("20060102150405")
	starttime := now.Add(sd*3).Format("20060102150405") // only fetch one-day data

	url := fmt.Sprintf(conf.PdnsChainUrl, domain, starttime, endtime)
	tokenHeader := make(map[string]string)
	tokenHeader["fdp-token"] = conf.PdnsApiToken

	var respBody PDNSResponse
	var retryFlag bool

	for i := 1; i <= retries; i++ {
		respBody, retryFlag = getPDNSResponse(url, timeout, tokenHeader)
		if retryFlag == false {
			break
		}
		log.Warningf("[PDNS API - CNAME] No response! Retrying %s...", domain)
		time.Sleep(2 * time.Second)
	}

	if respBody.StatusCode != 200 {
		return chains
	}

	data := respBody.Data
	var metaList []PDNSRecord
	for i := range data {
		if data[i].Count > conf.CnameAccess {
			metaList = append(metaList, data[i])
		}
	}

	for i := range metaList {
		chains = append(chains, metaList[i])
	}

	return chains
}


func getNsFromPDNS(domain string, timeout int, retries int, conf config.Conf) (ns NSType) {

	// Only get NSs in the recent 1 day.
	now := time.Now()
	//sd, _ := time.ParseDuration("-24h")
	endtime := now.Format("20060102150405")
	//starttime := now.Add(sd*1).Format("20060102150405")

	url := fmt.Sprintf(conf.PdnsNsUrl, domain, endtime)
	tokenHeader := make(map[string]string)
	tokenHeader["fdp-token"] = conf.PdnsApiToken

	var respBody PDNSResponse
	var retryFlag bool

	for i := 1; i <= retries; i++ {
		respBody, retryFlag = getPDNSResponse(url, timeout, tokenHeader)
		if retryFlag == false {
			break
		}
		log.Warningf("[PDNS API - NS] No response! Retrying %s...", domain)
		time.Sleep(1 * time.Second)
	}

	if respBody.StatusCode != 200 {
		return ns
	}

	data := respBody.Data
	ns.Domain = domain
	for i := range data {
		//rdata := strings.TrimRight(data[i].Rdata, ";")
		//rdata = strings.TrimRight(rdata, ".")
		ns.NameServers = append(ns.NameServers, data[i])
	}

	return ns
}


func getRCnameFromPDNS(domain string, timeout int, retries int, conf config.Conf) (rcnames []string) {

	// Only get chains during the recent 7 days.
	now := time.Now()
	sd, _ := time.ParseDuration("-24h")
	endtime := now.Format("20060102150405")
	starttime := now.Add(sd*7).Format("20060102150405")

	url := fmt.Sprintf(conf.PdnsReverseCnameUrl, domain, starttime, endtime)
	tokenHeader := make(map[string]string)
	tokenHeader["fdp-token"] = conf.PdnsApiToken

	var respBody PDNSResponse
	var retryFlag bool

	for i := 1; i <= retries; i++ {
		respBody, retryFlag = getPDNSResponse(url, timeout, tokenHeader)
		if retryFlag == false {
			break
		}
		log.Warningf("[PDNS API - RCNAME] No response! Retrying %s...", domain)
		time.Sleep(1 * time.Second)
	}

	if respBody.StatusCode != 200 {
		return rcnames
	}

	data := respBody.Data
	var rcnameList []string
	for i := range data {
		rrname := strings.TrimRight(data[i].RRName, ";")
		rrname = strings.TrimRight(rrname, ".")
		if data[i].Count > conf.CnameAccess {
			rcnameList = append(rcnameList, rrname)
		}
	}

	for i := range rcnameList {
		rcnames = append(rcnames, rcnameList[i])
	}

	return rcnames
}