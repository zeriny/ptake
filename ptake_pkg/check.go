package ptake_pkg

import (
	"bytes"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"path"
	"ptake/config"
	"strings"
	"time"
)

func matchHttpBodyFp(body []byte, fp []byte) (match bool){
	match = false
	if bytes.Contains(body, fp) {
		// TODO: change to regexp
		match = true
	}
	return match
}

func matchHttpHeaderFp(header string, fp string) (match bool){
	if strings.Contains(header, strings.ToLower(fp)){
		return true
	}
	return false
}

func matchDnsFp(cnames []CNAME, fp string)(match bool) {
	for i := range cnames{
		if  cnames[i].Domain == fp{
			return true
		}
	}
	return false
}

func matchNxEndpoint(cnames []CNAME) (match bool) {
	for i := range cnames {
		if isNxdomain(cnames[i].Domain) {
			return true
		}
	}
	return false
}

func matchAllFps(body []byte, header string, cnames []CNAME, matchedServices []config.Service) (match bool){
	for i := range matchedServices {
		currService := matchedServices[i]

		// cname should be an nxdomain
		if currService.NXDomain {
			match = matchNxEndpoint(cnames)
			if match {break}
		}

		// HTTP response body
		for j := range currService.Fingerprint {
			match = matchHttpBodyFp(body, []byte(currService.Fingerprint[j]))
			if match {break}
		}

		//// HTTP response header
		for j := range currService.HttpFingerprint {
			match = matchHttpHeaderFp(header, currService.HttpFingerprint[j])
			if match {break}
		}

		// cname chains
		for j := range currService.DnsFingerprint{
			match = matchDnsFp(cnames, currService.DnsFingerprint[j])
			if match {break}
		}
	}
	return match
}

// TODO: change to regexp
// Automatically generate regexp: https://regex-generator.olafneumann.org/
func matchServicePattern(domain string, patterns string) (match bool) {
	if strings.Contains(domain, patterns) {
		return true
	}
	return false
}
// checkFingerprints is the interface to check whether web contents contain vulnerable services' fingerprints.
func checkFingerprints(domain CNAME, domainStatus DomainStatus, forceSSL bool, timeout int) (newDomainStatus DomainStatus) {

	header, body := get(domain.Domain, timeout, false)
	if body == nil {
		header, body = get(domain.Domain, timeout, true)
	}
	header = strings.ToLower(header)

	matchedServices := domainStatus.MatchedServices
	match := false

	// Check fingerprints to see if the given domain is matched to an abandoned service.
	match = matchAllFps(body, header, domain.Cnames, matchedServices)
	if match == false && domainStatus.Type == "CnameVulnerable" {
		for i := range domainStatus.VulCnames {
			cnameStatus := domainStatus.VulCnames[i]
			match = matchAllFps(body, header, domain.Cnames, cnameStatus.MatchedServices)
			if match {
				break
			}
		}
	}
	if match {
		domainStatus.VulnerableLevel = 2
		domainStatus.Type = "AbandonedService"
	}
	return domainStatus
}


//checkServicePattern is the interface to check whether there are CNAME matching vulnerable service cname patterns.
//Returning Matched Service list.
func checkServicePattern(domain string, allServices []config.Service) (matchedServices []config.Service) {
	for i := range allServices {
		namePatterns := allServices[i].NamePatterns
		isVulnerable := allServices[i].IsVulnerable
		if isVulnerable{
			for j := range namePatterns {
				if matchServicePattern(domain, namePatterns[j]) {
					matchedServices = append(matchedServices, allServices[i])
				}
			}
		}
	}
	return matchedServices
}


// recursive is the function to check the status of all domain names in DNS chains, and check whether they are matched
// with some service name patterns.
func recursive(domain CNAME, o *config.GlobalConfig, domainCache *cache.Cache) (domainStatus DomainStatus) {
	if status, found := domainCache.Get(domain.Domain); found {
		return status.(DomainStatus)
	}
	services := o.ServiceList
	domainStatus.VulnerableLevel = 0
	domainStatus.Domain = domain.Domain
	domainStatus.CheckTime = time.Now().Format("2006-01-02 15:04:05")

	// Check whether subdomain is expired and can be registered.
	if o.CheckAvailable {
		available := isAvailable(domain.Domain)
		if available {
			domainStatus.VulnerableLevel = 2
			domainStatus.Type = "Available"
		}
	}

	// Check whether subdomain matches any domain patterns of vulnerable services.
	matchedServices := checkServicePattern(domain.Domain, services)
	if matchedServices != nil {
		domainStatus.MatchedServices = matchedServices
		domainStatus.Type = "MatchServicePattern"
		domainStatus.VulnerableLevel = 1
	}

	// Recursively check whether the CNAMEs are vulnerable:
	// (1) if the CheckFull option is set, or
	// (2) if the current domain is not vulnerable
	if o.CheckFull || domainStatus.VulnerableLevel == 0 {

		// Get CNAME records
		cnames := domain.Cnames
		if cnames != nil {
			for i := range cnames {
				cnameStatus := recursive(cnames[i], o, domainCache)
				if cnameStatus.VulnerableLevel == 0 {
					continue
				}
				// If the current domain is innocent but some cnames are vulnerable,
				// the vulnerable Type of the current domain is set with CnameVulnerable,
				// and the details of vulnerable CNAMEs are appended to VulCnames.
				if cnameStatus.VulnerableLevel >= domainStatus.VulnerableLevel {
					// set the highest threat level in the DNS chain.
					domainStatus.VulnerableLevel = cnameStatus.VulnerableLevel
					domainStatus.Type = "CnameVulnerable"
					domainStatus.VulCnames = append(domainStatus.VulCnames, cnameStatus)
				}
			}
		}
	}
	domainCache.Set(domain.Domain, domainStatus, cache.NoExpiration)
	return domainStatus
}

// This function is the interface to check whether a subdomain can be taken over via vulnerable services.
func checkService(domain CNAME, cacheFile string, o *config.GlobalConfig) {
	domainCache := cache.New(30*time.Second, 10*time.Second)
	domainStatus := recursive(domain, o, domainCache)

	// If we find some service patterns are matched, while the domain name is not expired yet
	if domainStatus.VulnerableLevel == 1 {
		// Check whether HttpBody/HttpHeaders/DnsChains match any fingerprints of vulnerable services.
		domainStatus = checkFingerprints(domain, domainStatus, o.Ssl, o.Timeout)
	}

	domainStatus.CheckTime = time.Now().Format("2006-01-02 15:04:05")

	// Output vulnerable result.
	//checkInfo := getCheckInfo(domainStatus, o)
	//if checkInfo == "" {
	//	fmt.Println("[+] " + domain.Domain)
	//	fmt.Println(domainStatus)
	//} else{
	//	if domainStatus.VulnerableLevel >= 1 {
	//		fmt.Println("[+] " + domain.Domain)
	//		fmt.Println(checkInfo)
	//	} else if o.Verbose {
	//		fmt.Println(checkInfo)
	//	}
	//}

	if o.OutputPath != "" {
		if domainStatus.VulnerableLevel > 0 {
			vulnerablePath := path.Join(o.OutputPath, "vulnerable.txt")
			saveDomainStatus(domainStatus, vulnerablePath)
			getNS(domain.Domain, o) // Get the current name servers of vulnerable domain names
			log.Infof("Check subdomains: (%s) %s", domain.Domain, domainStatus.Type)
		} else if o.Verbose {
			domainStatus.Type = "NotVulnerable"
			normalPath := path.Join(o.OutputPath, "normal.txt")
			saveDomainStatus(domainStatus, normalPath)
			log.Infof("Check subdomains: (%s) %s", domain.Domain, domainStatus.Type)
		}
	}

	saveCache(domain.Domain, cacheFile)
}

//func getCheckInfo(status DomainStatus, o *config.GlobalConfig) (resultStr string) {
//
//	if status.VulnerableLevel != 0 {
//		switch status.Type {
//		case "Available":
//			resultStr = fmt.Sprintf("[Available]  %s\n", status.Domain)
//		case "MatchServicePattern":
//			resultStr = fmt.Sprintf("[MatchServicePattern] %s", status.Domain)
//			for i := range status.MatchedServices {
//				matchedService := status.MatchedServices[i]
//				resultStr += fmt.Sprintf(" -(%s)", strings.ToUpper(matchedService.Service))
//			}
//			//resultStr = fmt.Sprintf("[%s]%s", status.MatchServiceCnames, status.Domain)
//		case "AbandonedService":
//			resultStr = fmt.Sprintf("[AbandonedService] %s ", status.Domain)
//			for i := range status.MatchedServices {
//				matchedService := status.MatchedServices[i]
//				resultStr += fmt.Sprintf(" -(%s)\n", strings.ToUpper(matchedService.Service))
//			}
//
//			for i := range status.VulCnames {
//				resultStr += fmt.Sprintf("[CnameVulnerable]  %s -> %s\n", status.Domain, status.VulCnames[i].Domain) + getCheckInfo(status.VulCnames[i], o)
//			}
//
//		case "CnameVulnerable":
//			resultStr = ""
//			for i := range status.VulCnames {
//				resultStr += fmt.Sprintf("[CnameVulnerable]  %s -> %s\n", status.Domain, status.VulCnames[i].Domain) + getCheckInfo(status.VulCnames[i], o)
//			}
//		default:
//			resultStr = fmt.Sprintf("[Vulnerable]%s", status.Domain)
//		}
//	}
//
//	if status.VulnerableLevel == 0 && o.Verbose {
//		resultStr = fmt.Sprintf("[NotVulnerable]%s", status.Domain)
//	}
//	return resultStr
//}