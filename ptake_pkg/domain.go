package ptake_pkg

import (
	"fmt"
	"github.com/haccer/available"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
	"net"
	"path"
	"ptake/config"
	"strings"
	"time"
)

func resolve(domain string) (res []string) {
	d := new(dns.Msg)
	d.SetQuestion(domain+".", dns.TypeCNAME)
	ret, err := dns.Exchange(d, "8.8.8.8:53")
	if err != nil {
		return
	}

	for _, a := range ret.Answer {
		if t, ok := a.(*dns.CNAME); ok {
			var cname = t.Target
			res = append(res, cname)
		}
	}
	return res
}

// Judge whether a domain has a legal format.
// TODO: more constraints.
func isLegalDomain(domain string) (flag bool) {
	if !strings.Contains(domain, ".") {
		return false
	}

	illegalCharacters := "~!@#$%^&()+/<>,[]\\/"
	for i := range illegalCharacters {
		ch := string(illegalCharacters[i])
		if strings.Contains(domain, ch) {
			return false
		}
	}
	illegalPrefixes := "."
	for i := range illegalPrefixes {
		ch := string(illegalPrefixes[i])
		if strings.HasPrefix(domain, ch) {
			return false
		}
	}
	return true
}

func isIP(s string) (flag bool) {
	address := net.ParseIP(s)
	if address == nil {
		flag = false
	}else {
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
	fqdnFile := path.Join(o.OutputPath, "fqdn.txt")
	cacheFile := path.Join(o.CachePath, "sld_cache.txt")

	if o.Verbose {
		//fmt.Printf("Get subdomains: %s (%d)\n", sld, len(filteredSubdomains))
		//log.Printf("Get subdomains: %s (%d)\n", sld, len(filteredSubdomains))
		log.Infof("Get subdomains: %s (%d)", sld, len(filteredSubdomains))
	}
	saveFqdnFile(sld, filteredSubdomains, fqdnFile)
	saveCache(sld, cacheFile)
}

func getChainsRecursive(subdomain string, o *config.GlobalConfig, domainCache *cache.Cache, depth int) (chain DnsChain) {
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
	var metaList []PDNSRecord
	// Recursively get CNAME records via passive DNS API.
	metaList = getChainsFromPDNS(subdomain, o.Timeout, o.Retries, o.Config)
	//cnames = domainFilter(cnames)

	// Only leave the first <cnameLimit> cnames
	cnameLimit := Min(len(metaList), o.Config.CnameListSize)
	for i := range metaList[:cnameLimit] {
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
			curr = getChainsRecursive(rdata, o, domainCache, depth+1)
		} else if (rtype == "A") || (rtype == "NS") {
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

// Resolve subdomain and fetch CNAME records
// Output CNAME object: {domain: "domain", cnames: []CNAME}
func getChains(subdomain string, o *config.GlobalConfig) {
	isLegal := isLegalDomain(subdomain)
	if isLegal == false {
		log.Warningf("[-] '%s' is not in legal format.", subdomain)
		return
	}

	domainCache := cache.New(30*time.Second, 10*time.Second)
	chain := getChainsRecursive(subdomain, o, domainCache, 1)

	// Output results and save caches.
	chainPath := path.Join(o.OutputPath, "chain.txt")
	cacheFile := path.Join(o.CachePath, "fqdn_cache.txt")

	if len(chain.Chains) > 0 {
		saveChainFile(chain, chainPath)
	}
	saveCache(chain.Name, cacheFile)
}

func getNS(subdomain string, o *config.GlobalConfig) {
	isLegal := isLegalDomain(subdomain)
	if isLegal == false {
		//log.Printf("[-] '%s' is not in legal format.\n", subdomain)
		log.Warningf("[-] '%s' is not in legal format.", subdomain)
		return
	}
	// TODO: get base domain
	baseDomain := getBaseDomain(subdomain)
	ns := getNsFromPDNS(baseDomain, o.Timeout, o.Retries, o.Config)

	// Output results and save caches.
	nsPath := path.Join(o.OutputPath, "ns.txt")
	if len(ns.NameServers) > 0 {
		saveNsFile(ns, nsPath)
	}
}

// TODO: check NXDOMAIN
func isNxdomain(domain string) bool {
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

func getBaseDomain(domain string) (base string) {
	base, _ = publicsuffix.EffectiveTLDPlusOne(domain)
	return base
}

func getRCnameRecuresive(subdomain string, o *config.GlobalConfig, domainCache *cache.Cache, depth int) (rcname CNAME) {
	// The subdomain has been handled
	if item, found := domainCache.Get(subdomain); found {
		return item.(CNAME)
	}

	// The max recursive depth.
	if depth > o.Config.RecursiveDepth {
		domainCache.Set(subdomain, rcname, cache.NoExpiration)
		return rcname
	}

	rcname.Domain = subdomain
	var cnames []string
	// Recursively get reversed CNAME records via passive DNS API.
	cnames = getRCnameFromPDNS(subdomain, o.Timeout, o.Retries, o.Config)
	cnames = domainFilter(cnames)

	// Only leave the first <cnameLimit> cnames
	cnameLimit := Min(len(cnames), o.Config.CnameListSize)
	for i := range cnames[:cnameLimit] {
		if cnames[i] == subdomain {
			continue
		}
		curr := getRCnameRecuresive(cnames[i], o, domainCache, depth+1)
		rcname.Cnames = append(rcname.Cnames, curr)
	}
	if o.Verbose {
		log.Infof("Reverse Look up: %s (depth: %d, cname:%d)", subdomain, depth, len(rcname.Cnames))
	}
	domainCache.Set(subdomain, rcname, cache.NoExpiration)
	return rcname
}

func getRCnames(subdomain string, o *config.GlobalConfig) {
	domainCache := cache.New(30*time.Second, 10*time.Second)
	rcname := getRCnameRecuresive(subdomain, o, domainCache, 1)

	// Output results and save caches.
	rcnamePath := path.Join(o.OutputPath, "vulnerable_rcname.txt")
	cacheFile := path.Join(o.CachePath, "reverse_cache.txt")
	//log.Printf("Get cnames: %s (%d)", subdomain, len(cname.Cnames))
	//log.Infof("Get cnames: %s (%d)", subdomain, len(cname.Cnames))
	if len(rcname.Cnames) > 0 {
		saveCnameFile(rcname, rcnamePath)
	}
	saveCache(rcname.Domain, cacheFile)
}
