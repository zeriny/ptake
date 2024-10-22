package ptake_pkg

import (
	"fmt"
	"net"
	"os"
	"path"
	"ptake/config"
	"strings"
	"time"

	"github.com/haccer/available"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

// Judge whether a domain has a legal format.
// Brute-force validation.
// TODO: more constraints.
func isLegalDomain(domain string) (flag bool) {
	if !strings.Contains(domain, ".") {
		return false
	}
	if len(domain) > 64 {
		return false
	}

	illegalCharacters := "'~!?@#$`%^&()+/<>,[]{}\\/"
	for i := range illegalCharacters {
		ch := string(illegalCharacters[i])
		if strings.Contains(domain, ch) {
			return false
		}
	}
	illegalPrefixes := ".-"
	for i := range illegalPrefixes {
		ch := string(illegalPrefixes[i])
		if strings.HasPrefix(domain, ch) {
			return false
		}
	}
	var illegalLabels = [...]string{".-", ".*"}
	for i := range illegalLabels {
		label := string(illegalLabels[i])
		if strings.Contains(domain, label) {
			return false
		}
	}

	return true
}

func isIP(s string) (flag bool) {
	address := net.ParseIP(s)
	if address == nil {
		flag = false
	} else {
		flag = true
	}
	return flag
}

// Filter out domain names in illegal format.
func domainFilter(subdomains []string) (filteredSubdomains []string) {
	if len(subdomains) == 0 {
		return subdomains
	}
	for i := range subdomains {
		fqdn := subdomains[i]
		isLegal := isLegalDomain(fqdn)
		if isLegal == false {
			saveCache(fqdn, "illegal_domain.txt")
			continue
		}
		if strings.HasPrefix(fqdn, "*.") || strings.Contains(fqdn, "*") {
			fqdn = strings.Replace(fqdn, "*", "rAnD0msUb", -1)
		}
		filteredSubdomains = append(filteredSubdomains, fqdn)
	}
	filteredSubdomains = removeDuplicates(filteredSubdomains)
	return filteredSubdomains
}

func getSubdomains(sld string, o *config.GlobalConfig) {
	var subdomains []string
	subdomains = getSubdomainFromPDNS(sld, o.Timeout, o.Retries, o.Config)

	//TODO: Filter algorithm-generated subdomains
	filteredSubdomains := domainFilter(subdomains)
	//filteredSubdomains :=removeDuplicates(subdomains)

	// Output results and save caches.
	fqdnFile := path.Join(o.OutputDir, "fqdn.txt")
	cacheFile := path.Join(o.CachePath, "sld_cache.txt")

	if o.Verbose {
		log.Infof("Get subdomains: %s (%d)", sld, len(filteredSubdomains))
	}
	saveFqdnFile(sld, filteredSubdomains, fqdnFile)
	saveCache(sld, cacheFile)
}

func getPassiveChainsRecursive(subdomain string, o *config.GlobalConfig, domainCache *cache.Cache, depth int) (chain DnsChain) {
	// The subdomain has been handled
	if item, found := domainCache.Get(subdomain); found {
		return item.(DnsChain)
	}

	// The max recursive depth.
	if depth > o.Config.RecursiveDepth {
		domainCache.Set(subdomain, chain, cache.NoExpiration)
		return chain
	}

	chain.Name = subdomain
	var metaList []FlintRRsetRecord
	// Recursively get CNAME records via passive DNS API.
	metaList = getChainsFromPDNS(subdomain, o.Timeout, o.Retries, o.Config)
	//cnames = domainFilter(cnames)

	// Only leave the first <cnameLimit> cnames
	cnameLimit := Min(len(metaList), o.Config.CnameListSize)
	currCnameCount := 0
	for i := range metaList {
		if currCnameCount > cnameLimit {
			break
		}
		rdata := strings.TrimRight(metaList[i].Rdata, ";")
		rdata = strings.TrimRight(rdata, ".")
		rtype := metaList[i].RRType

		if rdata == subdomain {
			continue
		}

		if rdata == "" {
			continue
		}

		var curr DnsChain

		if rtype == "CNAME" {
			currCnameCount += 1
			curr = getPassiveChainsRecursive(rdata, o, domainCache, depth+1)
		} else if (rtype == "A") || (rtype == "NS") {
			currCnameCount += 1
			curr.Name = rdata
			curr.Chains = nil
		}
		chain.Chains = append(chain.Chains, curr)
	}

	if o.Verbose {
		log.Infof("Look up: %s (depth: %d, results:%d)", subdomain, depth, len(chain.Chains))
	}
	domainCache.Set(subdomain, chain, cache.NoExpiration)
	return chain
}

func getActiveChainsRecursive(subdomain string, rrset []ActiveRRsetRecord, o *config.GlobalConfig, depth int) (chain DnsChain) {

	chain.Name = subdomain
	for i := range rrset {
		rname := rrset[i].RRName
		rdata := rrset[i].Rdata
		rtype := rrset[i].RRType
		if rname != subdomain {
			continue
		}
		if rtype == "A" {
			var leaf DnsChain
			leaf.Name = rdata
			leaf.Chains = nil

			var curr DnsChain
			curr.Name = rname
			curr.Chains = append(curr.Chains, leaf)
			chain.Chains = append(chain.Chains, curr)
		} else if rtype == "CNAME" {
			curr := getActiveChainsRecursive(rdata, rrset, o, depth+1)
			chain.Chains = append(chain.Chains, curr)
		}
	}
	if o.Verbose {
		log.Infof("Look up: %s (depth: %d, results:%d)", subdomain, depth, len(chain.Chains))
	}
	return chain
}

// Resolve subdomain and fetch CNAME records
// Output CNAME object: {domain: "domain", cnames: []CNAME}
func getChains(subdomain string, o *config.GlobalConfig, domainCache *cache.Cache, active_dns bool) {
	isLegal := isLegalDomain(subdomain)
	if isLegal == false {
		log.Warningf("[-] '%s' is not in legal format.", subdomain)
		return
	}

	var chain DnsChain
	if active_dns == true {
		// The subdomain has been handled
		if item, found := domainCache.Get(subdomain); found {
			chain = item.(DnsChain)
		} else {
			rrset := domainLookup(subdomain)
			chain = getActiveChainsRecursive(subdomain, rrset, o, 1)
			domainCache.Set(subdomain, chain, cache.NoExpiration)
		}
	} else {
		chain = getPassiveChainsRecursive(subdomain, o, domainCache, 1)
	}

	// Output results and save caches.
	chainPath := path.Join(o.OutputDir, "chain.txt")
	cacheFile := path.Join(o.CachePath, "fqdn_cache.txt")

	if len(chain.Chains) > 0 {
		saveChainFile(chain, chainPath)
	}
	saveCache(chain.Name, cacheFile)
}

func getNS(subdomain string, o *config.GlobalConfig) {
	isLegal := isLegalDomain(subdomain)
	if isLegal == false {
		log.Warningf("[-] '%s' is not in legal format.", subdomain)
		return
	}
	// TODO: get base domain
	baseDomain := getBaseDomain(subdomain)
	ns := getNsFromPDNS(baseDomain, o.Timeout, o.Retries, o.Config)

	// Output results and save caches.
	nsPath := path.Join(o.OutputDir, "ns.txt")
	if len(ns.NameServers) > 0 {
		saveNsFile(ns, nsPath)
	}
}

// TODO: check NXDOMAIN
func isNxdomain(domain string) bool {
	if domain == "" {
		return false
	}
	if _, err := net.LookupHost(domain); err != nil {
		if strings.Contains(fmt.Sprintln(err), "no such host") {
			return true
		}
	}
	return false
}

// isAvailable returns true if the domain to be checked can be registerd
func isAvailable(domain string) bool {
	// Using an API implemented by golang: https://github.com/haccer/available.
	// The package has been modified:
	// 1. fingerprint.go: change the fingerprint of "ca" to "Not Found"
	// 2. check.go: remove the special condition for "ca" [line79], and line88 should be 'else if'
	flag := available.Domain(domain)
	return flag
}

func IsAvailable(domain string) bool {
	// Using an API implemented by golang: https://github.com/haccer/available.
	// The package has been modified:
	// 1. fingerprint.go: change the fingerprint of "ca" to "Not Found"
	// 2. check.go: remove the special condition for "ca" [line79], and line88 should be 'else if'
	flag := available.Domain(domain)
	return flag
}

// Get DNS records via active domain resolution.
func domainLookup(domain string) (chains []ActiveRRsetRecord) {
	d := new(dns.Msg)
	d.SetQuestion(domain+".", dns.TypeA)
	ret, err := dns.Exchange(d, "8.8.8.8:53")
	if err != nil {
		return
	}

	for _, a := range ret.Answer {
		var chain ActiveRRsetRecord
		if t, ok := a.(*dns.CNAME); ok {
			chain.RRName = strings.TrimRight(t.Hdr.Name, ".")
			chain.RRType = "CNAME"
			chain.Rdata = strings.TrimRight(t.Target, ".")
		} else if t, ok := a.(*dns.A); ok {
			chain.RRName = strings.TrimRight(t.Hdr.Name, ".")
			chain.RRType = "A"
			chain.Rdata = t.A.To4().String()
		}
		chains = append(chains, chain)
	}
	return chains
}

func getBaseDomain(domain string) (base string) {
	base, _ = publicsuffix.EffectiveTLDPlusOne(domain)
	return base
}

func getRCnameRecuresive(subdomain string, o *config.GlobalConfig, rcnameCache *cache.Cache, domainList map[string]int, depth int) (rcname CNAME) {
	// The subdomain has been handled
	if item, found := rcnameCache.Get(subdomain); found {
		return item.(CNAME)
	}

	// The max recursive depth.
	if depth > o.Config.RecursiveDepth {
		rcnameCache.Set(subdomain, rcname, cache.NoExpiration)
		return rcname
	}

	rcname.Domain = subdomain
	if depth > 1 {
		domainList[subdomain] = 1
	}

	var cnames []string
	// Recursively get reversed CNAME records via passive DNS API.
	cnames = getRCnameFromPDNS(subdomain, o.Timeout, o.Retries, o.Config)
	cnames = domainFilter(cnames)

	// Only leave the first <cnameLimit> cnames
	//cnameLimit := Min(len(cnames), o.Config.CnameListSize)
	cnameLimit := len(cnames)
	for i := range cnames[:cnameLimit] {
		if cnames[i] == subdomain {
			continue
		}
		curr := getRCnameRecuresive(cnames[i], o, rcnameCache, domainList, depth+1)
		rcname.Cnames = append(rcname.Cnames, curr)
	}
	if o.Verbose {
		log.Infof("Reverse Look up: %s (depth: %d, cname:%d)", subdomain, depth, len(rcname.Cnames))
	}
	rcnameCache.Set(subdomain, rcname, cache.NoExpiration)
	return rcname
}

func getRCnames(subdomain string, o *config.GlobalConfig) {
	rcnameCache := cache.New(30*time.Second, 10*time.Second)
	domainList := make(map[string]int)
	rcname := getRCnameRecuresive(subdomain, o, rcnameCache, domainList, 1)

	// Output results and save caches.
	rcnamePath := path.Join(o.OutputDir, "vulnerable_rcname.txt")
	rdomainPath := o.OutputDir + "_reverse"
	rdomainFile := path.Join(rdomainPath, "fqdn.txt")
	cacheFile := path.Join(o.CachePath, "reverse_cache.txt")

	if len(rcname.Cnames) > 0 {
		saveCnameFile(rcname, rcnamePath)
	}
	_, err := os.Stat(rdomainPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(rdomainPath, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}

	for fqdn := range domainList {
		sld := getBaseDomain(fqdn)
		if sld != "" {
			currFqdnList := []string{fqdn}
			saveFqdnFile(sld, currFqdnList, rdomainFile)
		}
	}
	saveCache(rcname.Domain, cacheFile)
}
