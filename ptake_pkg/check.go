package ptake_pkg

import (
	"bytes"
	"fmt"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"path"
	"ptake/config"
	"strings"
	"time"
)

// web content fingerprint to determine an abandoned service
func matchHttpBodyFp(body []byte, fp []byte) (match bool, matchedFp string){
	match = false
	if bytes.Contains(body, fp) {
		// TODO: change to regexp
		match = true
		matchedFp = string(fp)
	}
	return match, matchedFp
}

// http header fingerprint to determine an abandoned service
func matchHttpHeaderFp(header string, fp string) (match bool, matchedFp string){
	if strings.Contains(header, strings.ToLower(fp)){
		return true, strings.ToLower(fp)
	}
	return false, matchedFp
}

// dns fingerprint (CNAME, NS) to determine an abandoned service
func matchDnsFp(cname DnsChain, fp string)(match bool, matchedFp string) {
	if  cname.Name == fp {
		return true, fp
	}
	return false, matchedFp
}

// non-exist CNAME to determine an abandoned service
func matchNxEndpoint(chain DnsChain) (match bool, nxdomain string) {
	if isIP(chain.Name) {
		return false, nxdomain
	}
	if isNxdomain(chain.Name) {
		return true, chain.Name
	}
	return false, nxdomain
}

// all types of fingerprints to determine an abandoned service
func matchAllFps(body []byte, header string, chain DnsChain, matchedServices []config.Service) (match bool, matchedFp string){
	for i := range matchedServices {
		currService := matchedServices[i]

		// domain should point to a nxdomain
		if currService.NXDomain {
			var nxdomain string
			match, nxdomain = matchNxEndpoint(chain)
			if match {
				matchedFp = "[NXDOMAIN] " + nxdomain
				break
			}
		}

		// HTTP response body
		for j := range currService.Fingerprint {
			var bodyFp string
			match, bodyFp = matchHttpBodyFp(body, []byte(currService.Fingerprint[j]))
			if match {
				matchedFp = "[Body] " + bodyFp
				break
			}
		}

		//// HTTP response header
		for j := range currService.HttpFingerprint {
			var headerFp string
			match, headerFp = matchHttpHeaderFp(header, currService.HttpFingerprint[j])
			if match {
				matchedFp = "[Header] " + headerFp
				break
			}
		}

		// match specific CNAME/NS
		for j := range currService.DnsFingerprint{
			var dnsFp string
			match, dnsFp = matchDnsFp(chain, currService.DnsFingerprint[j])
			if match {
				matchedFp = "[DNS] " + dnsFp
				break
			}
		}
	}
	return match, matchedFp
}

// TODO: change to regexp
// Automatically generate regexp: https://regex-generator.olafneumann.org/
func matchServicePattern(domain string, pattern string) (match bool) {
	if strings.HasSuffix(domain, pattern) {
		return true
	}
	return false
}


// checkFingerprints is the interface to check whether web contents contain vulnerable services' fingerprints.
func checkFingerprints(domain DnsChain, domainStatus DomainStatus, forceSSL bool, timeout int) (newDomainStatus DomainStatus) {

	header, body := Get(domain.Name, timeout, false)
	if body == nil {
		header, body = Get(domain.Name, timeout, true)
	}
	header = strings.ToLower(header)

	matchedServices := domainStatus.MatchedServices
	match := false
	matchedFp := ""

	// Check fingerprints to see if the given domain is matched to an abandoned service.
	match, matchedFp = matchAllFps(body, header, domain, matchedServices)
	if match == false && len(domainStatus.Cnames)>0 {
		for i := range domainStatus.Cnames {
			cnameStatus := domainStatus.Cnames[i]
			cnameFQDN := domainStatus.Domain

			chains := domain.Chains
			if chains != nil {
				for j := range chains {
					if chains[j].Name == cnameFQDN{
						match, matchedFp = matchAllFps(body, header, chains[j], cnameStatus.MatchedServices)
						if match {
							break
						}
					}
				}
			}
		}
	}
	if match {
		domainStatus.VulnerableLevel = 4
		domainStatus.Type = "AbandonedService"
		domainStatus.MatchedFp = matchedFp
	}
	return domainStatus
}


//checkServicePattern is the interface to check whether there are CNAME matching vulnerable service cname patterns.
//Returning Matched Service list.
func checkServicePattern(domain string, allServices []config.Service) (matchedServices []config.Service, matchVulnerableService bool) {
	matchVulnerableService = false
	for i := range allServices {
		currService := allServices[i]
		namePatterns := currService.NamePatterns
		isVulnerable := currService.IsVulnerable
		for j := range namePatterns {
			if matchServicePattern(domain, namePatterns[j]) {
				matchedServices = append(matchedServices, currService)
				if isVulnerable {
					matchVulnerableService = true
				}
			}
		}
	}
	return matchedServices, matchVulnerableService
}


// recursive is the function to check the status of all domain names in DNS chains, and check whether they are matched
// with some service name patterns.
func recursive(domain DnsChain, o *config.GlobalConfig, domainCache *cache.Cache) (domainStatus DomainStatus) {
	if status, found := domainCache.Get(domain.Name); found {
		return status.(DomainStatus)
	}
	services := o.ServiceList
	domainStatus.VulnerableLevel = 0
	domainStatus.Type = "NotVulnerable"
	domainStatus.Domain = domain.Name
	domainStatus.CheckTime = time.Now().Format("2006-01-02 15:04:05")

	// Check whether subdomain is expired and can be registered.
	if o.CheckAvailable {
		available := isAvailable(domain.Name)
		if available {
			domainStatus.VulnerableLevel = 1
			domainStatus.Type = "Available"
		}
	}

	// Check whether subdomain matches any domain patterns of vulnerable services.
	matchedServices, matchVulService := checkServicePattern(domain.Name, services)
	if matchedServices != nil {
		// Match Services
		domainStatus.MatchedServices = matchedServices
		domainStatus.Type = "MatchNotVulServicePattern"
		domainStatus.VulnerableLevel = 2
		if matchVulService {
			// Match Vulnerable Services
			domainStatus.Type = "MatchVulServicePattern"
			domainStatus.VulnerableLevel = 3
		}
	}

	// Recursively check whether the CNAMEs are vulnerable:
	// (1) if the CheckFull option is set, or
	// (2) if the current domain is not vulnerable, or
	// (3) if the current domain matches non-vulnerable service patterns
	if o.CheckFull || domainStatus.VulnerableLevel == 0 || domainStatus.VulnerableLevel == 2{

		// Get CNAME records
		chains := domain.Chains
		if chains != nil {
			for i := range chains {
				cnameStatus := recursive(chains[i], o, domainCache)
				//if cnameStatus.VulnerableLevel == 0 {
				//	continue
				//}
				// If the current domain is innocent but some cnames are vulnerable,
				// the vulnerable Type of the current domain is set with CnameVulnerable,
				// and the details of vulnerable CNAMEs are appended to VulCnames.
				if cnameStatus.VulnerableLevel >= domainStatus.VulnerableLevel {
					// set the highest threat level in the DNS chain.
					domainStatus.VulnerableLevel = cnameStatus.VulnerableLevel
					domainStatus.Type = cnameStatus.Type
				}
				domainStatus.Cnames = append(domainStatus.Cnames, cnameStatus)
			}
		}
	}
	domainCache.Set(domain.Name, domainStatus, cache.NoExpiration)
	return domainStatus
}

// This function is the interface to check whether a subdomain can be taken over via vulnerable services.
func checkService(domain DnsChain, cacheFile string, o *config.GlobalConfig) {
	log.Infof("Check: %s", domain.Name)
	domainCache := cache.New(30*time.Second, 10*time.Second)
	domainStatus := recursive(domain, o, domainCache)

	// If we find some service patterns are matched, while the domain name is not expired yet
	if domainStatus.VulnerableLevel == 3 {
		// Check whether HttpBody/HttpHeaders/DnsChains match any fingerprints of vulnerable services.
		domainStatus = checkFingerprints(domain, domainStatus, o.Ssl, o.Timeout)
	}

	// Add check time to the outermost domain name.
	domainStatus.CheckTime = time.Now().Format("2006-01-02 15:04:05")

	if o.OutputPath != "" {
		if domainStatus.VulnerableLevel > 0 {
			vulnerablePath := path.Join(o.OutputPath, "vulnerable.txt")
			saveDomainStatus(domainStatus, vulnerablePath)
			getNS(domain.Name, o) // Get the current name servers of vulnerable domain names
			log.Infof("Check results: (%s) %s", domain.Name, domainStatus.Type)
		} else if o.Verbose {
			domainStatus.Type = "NotVulnerable"
			normalPath := path.Join(o.OutputPath, "normal.txt")
			saveDomainStatus(domainStatus, normalPath)
			log.Infof("Check results: (%s) %s", domain.Name, domainStatus.Type)
		}
	} else {
		fmt.Println(domainStatus.Domain, domainStatus.Type)
	}

	saveCache(domain.Name, cacheFile)
}
