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

func getFlintResponse(url string, timeout int, addHeaders map[string]string) (respBody FlintRRsetResponse, retry bool) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(url)
	//req.Header.Add("Connection", "close")
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
		return respBody, true
	} else {
		jsonErr := json.Unmarshal(b, &respBody)
		if jsonErr != nil {
			log.Errorf("[PDNS Flint API] %s: %s", url, jsonErr)
		}
	}
	return respBody, false
}

func getDtreeResponse(url string, timeout int, addHeaders map[string]string) (respBody DtreeSubdomainResponse, retry bool) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(url)
	//req.Header.Add("Connection", "close")
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
		return respBody, true
	} else {
		jsonErr := json.Unmarshal(b, &respBody)
		if jsonErr != nil {
			log.Errorf("[PDNS Dtree API] %s: %s", jsonErr, url)
		}
	}
	return respBody, false
}

func getSubdomainFromPDNS(domain string, timeout int, retries int, conf config.Conf) (subdomains []string) {
	lastkey := ""
	fetchCount := 0
	domain2Count := make(map[string]int)
	tokenHeader := make(map[string]string)
	tokenHeader["fdp-token"] = conf.PdnsApiToken
	url := fmt.Sprintf(conf.PdnsSubdomainUrl, domain)

	// Iteratively fetch data from PDNS pages.
	for {
		var respBody DtreeSubdomainResponse
		var retryFlag bool

		currUrl := url
		if lastkey != "" {
			currUrl = url+fmt.Sprintf(`?lastkey='%s'`, lastkey)
		}
		for i := 1; i <= retries; i++ {
			respBody, retryFlag = getDtreeResponse(currUrl, timeout, tokenHeader)
			if retryFlag == false {
				break
			}
			log.Warningf("[PDNS API - subdomain] No response! Retrying %s...", domain)
			time.Sleep(1 * time.Second)
		}

		if respBody.StatusCode != 200 {
			return subdomains
		}
		fetchCount += 1
		// Sum up all RequestCount for each rrname
		lastkey = respBody.LastKey
		data := respBody.Data
		for i := range data {
			fqdn := data[i].Domain
			_, ok := domain2Count[fqdn]
			//if ok {
			//	domain2Count[fqdn] = domain2Count[fqdn] + data[i].Count
			//} else {
			//	domain2Count[fqdn] = data[i].Count
			//}

			if ok {
				domain2Count[fqdn] = domain2Count[fqdn] + 1
			} else {
				domain2Count[fqdn] = 1
			}
		}

		//log.Printf("%s, %d", domain, fetchCount)
		// Stop iterative data fetch if no data is left or the fetchCount reaches the max number.
		if lastkey == "" || fetchCount >= conf.MaxFetchCount {
			break
		}
	}

	// Filter by access count
	for fqdn, count := range domain2Count {
		//saveCache(fmt.Sprintf("%s;%s;%d", domain, fqdn, count), fmt.Sprintf("/root/ptake/results/evaluation/parameters/tranco10k_fqdn_tav.txt", ))
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
func getChainsFromPDNS(domain string, timeout int, retries int, conf config.Conf) (chains []FlintRRsetRecord) {
	// Only get cname chains appeared 3 days before the detection day.
	now := time.Now()
	sd, _ := time.ParseDuration("-24h")
	endtime := now.Format("20060102150405")
	starttime := now.Add(sd*conf.ChainDuration).Format("20060102150405")
	url := fmt.Sprintf(conf.PdnsChainUrl, domain, starttime, endtime)

	tokenHeader := make(map[string]string)
	tokenHeader["fdp-token"] = conf.PdnsApiToken
	lastkey := ""
	fetchCount := 0

	// Iteratively fetch data from PDNS pages.
	for {
		var respBody FlintRRsetResponse
		var retryFlag bool

		currUrl := url
		if lastkey != "" {
			currUrl = url+fmt.Sprintf(`&lastkey='%s'`, lastkey)
		}

		for i := 1; i <= retries; i++ {
			respBody, retryFlag = getFlintResponse(currUrl, timeout, tokenHeader)
			if retryFlag == false {
				break
			}
			log.Warningf("[PDNS API - CNAME] No response! Retrying %s...", domain)
			time.Sleep(2 * time.Second)
		}

		if respBody.StatusCode != 200 {
			return chains
		}
		fetchCount += 1
		lastkey = respBody.LastKey
		data := respBody.Data
		var metaList []FlintRRsetRecord
		for i := range data {
			if data[i].Count > conf.CnameAccess {
				metaList = append(metaList, data[i])
			}
		}

		for i := range metaList {
			chains = append(chains, metaList[i])
		}
		//log.Printf("%s, %d", domain, fetchCount)

		if lastkey == "" || fetchCount >= conf.MaxFetchCount {
			break
		}
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

	var respBody FlintRRsetResponse
	var retryFlag bool

	for i := 1; i <= retries; i++ {
		respBody, retryFlag = getFlintResponse(url, timeout, tokenHeader)
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

	tokenHeader := make(map[string]string)
	tokenHeader["fdp-token"] = conf.PdnsApiToken
	url := fmt.Sprintf(conf.PdnsReverseCnameUrl, domain, starttime, endtime)

	lastkey := ""
	fetchCount := 0

	// Iteratively fetch data from PDNS pages.
	for {
		var respBody FlintRRsetResponse
		var retryFlag bool
		currUrl := url
		if lastkey != "" {
			currUrl = url+fmt.Sprintf(`&lastkey='%s'`, lastkey)
		}
		for i := 1; i <= retries; i++ {
			respBody, retryFlag = getFlintResponse(currUrl, timeout, tokenHeader)
			if retryFlag == false {
				break
			}
			log.Warningf("[PDNS API - RCNAME] No response! Retrying %s...", domain)
			time.Sleep(1 * time.Second)
		}

		if respBody.StatusCode != 200 {
			return rcnames
		}
		fetchCount += 1
		lastkey = respBody.LastKey
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
		if lastkey == "" || fetchCount >= conf.MaxFetchCount {
			break
		}
	}
	return rcnames
}