package ptake_pkg

import (
	"bytes"
	"fmt"
	"github.com/patrickmn/go-cache"
	"log"
	"path"
	"ptake/config"
	"strings"
	"time"
)

//matchServiceCNAME is the interface to check whether there are CNAME matching vulnerable service cname patterns
func checkServicePattern(domain string, services []config.Service) (matchedServices []MatchedService) {

	for i := range services {
		var matchedPatterns []string
		service := services[i].Service
		patterns := services[i].NamePatterns

		for j := range patterns {
			// TODO: change to regexp
			if strings.Contains(domain, patterns[j]) {
				matchedPatterns = append(matchedPatterns, patterns[j])
			}
		}
		if matchedPatterns != nil {
			var matchedService MatchedService
			matchedService.Service = service
			matchedService.MatchedPatterns = matchedPatterns
			matchedServices = append(matchedServices, matchedService)
		}
	}

	return matchedServices
}

//TODO: add DNS / HTTP header fingerprints
// checkFingerprints is the interface to check whether web contents contain vulnerable services' fingerprints.
func checkFingerprints(subdomain string, domainStatus DomainStatus, forceSSL bool, timeout int, allServices []config.Service) (newDomainStatus DomainStatus) {

	// Check if response body matches vulnerable services' fingerprints
	url := "http://" + subdomain
	if forceSSL {
		url = "https://" + subdomain
	}
	var addHeader map[string]string
	body := get(url, timeout, addHeader)

	matchedServices := domainStatus.MatchedServices
	match := false

	for j := range allServices {
		service := allServices[j].Service
		for i := range matchedServices {
			serviceName := matchedServices[i].Service
			if serviceName == service {
				//var matchedFingerprints []string
				fingerprints := allServices[j].Fingerprint
				for k := range fingerprints {
					if bytes.Contains(body, []byte(fingerprints[k])) {
						// TODO: change to regexp
						match = true
						matchedServices[i].MatchedFingerprints = append(matchedServices[i].MatchedFingerprints,
							strings.ToUpper(serviceName))
					}
				}
			}
		}
	}
	if match {
		domainStatus.VulnerableLevel = 2
		domainStatus.Type = "AbandonedService"
		//domainStatus.MatchedServices = matchedServices
		newDomainStatus = domainStatus
	}
	if match == false && domainStatus.Type == "CnameVulnerable" {
		for i := range domainStatus.VulCnames {
			cnameStatus := domainStatus.VulCnames[i]
			newDomainStatus = checkFingerprints(cnameStatus.Domain, cnameStatus, forceSSL, timeout, allServices)
		}
	}
	return newDomainStatus
}

// recursive is the function to check the status of all domain names in DNS chains.
func recursive(domain CNAME, o *config.GlobalConfig, domainCache *cache.Cache, depth int) (domainStatus DomainStatus) {
	if status, found := domainCache.Get(domain.Domain); found {
		return status.(DomainStatus)
	}

	services := o.ServiceList
	domainStatus.VulnerableLevel = 0
	domainStatus.Domain = domain.Domain
	domainStatus.CheckTime = time.Now().Format("2006-01-02 15:04:05")
	if depth > 5 {
		domainCache.Set(domain.Domain, domainStatus, cache.NoExpiration)
		return domainStatus
	}

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
				//TODO: break the loop
				cnameStatus := recursive(cnames[i], o, domainCache, depth+1)
				//domainCache.Set(cnames[i], cnameStatus, cache.NoExpiration)
				if cnameStatus.VulnerableLevel == 0 {
					continue
				}
				// If the current domain is innocent but some cnames are vulnerable,
				// the Type of the current domain is set with CnameVulnerable,
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
	domainStatus := recursive(domain, o, domainCache, 1)
	// Only Match Service CNAME Patterns
	if domainStatus.VulnerableLevel == 1 {
		// Check whether Web contents match any fingerprints of vulnerable services.
		domainStatus = checkFingerprints(domain.Domain, domainStatus, o.Ssl, o.Timeout, o.ServiceList)
	}
	domainStatus.CheckTime = time.Now().Format("2006-01-02 15:04:05")
	// Output vulnerable result information.
	checkInfo := getCheckInfo(domainStatus, o)
	if domainStatus.VulnerableLevel >= 1 {
		fmt.Println("[+] " + domain.Domain)
		fmt.Println(checkInfo)
	} else if o.Verbose {
		fmt.Println(checkInfo)
	}

	if o.OutputPath != "" {
		if domainStatus.VulnerableLevel > 0 {
			vulnerablePath := path.Join(o.OutputPath, "vulnerable.txt")
			saveDomainStatus(domainStatus, vulnerablePath)
		} else if o.Verbose {
			normalPath := path.Join(o.OutputPath, "normal.txt")
			saveDomainStatus(domainStatus, normalPath)
		}
	}
	log.Printf("Check subdomains: (%s) %s \n", domain, domainStatus.Type)

	saveCache(domain.Domain, cacheFile)
}
