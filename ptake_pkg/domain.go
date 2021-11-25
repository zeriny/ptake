package ptake_pkg

import (
	"fmt"
	"github.com/haccer/available"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"log"
	"net"
	"path"
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

	illegalCharacters := "~!@#$%^&*()+*/<>,[]\\/"
	for i := range illegalCharacters {
		ch := string(illegalCharacters[i])
		if strings.Contains(domain, ch) {
			return false
		}
	}
	illegalPrefixes := "_-."
	for i := range illegalPrefixes {
		ch := string(illegalPrefixes[i])
		if strings.HasPrefix(domain, ch) {
			return false
		}
	}
	return true
}

// Filter algo-generated domains
// TODO: Identify random-looking subdomains
func domainFilter(subdomains []string) (filteredSubdomains []string) {
	for i := range subdomains {
		fqdn := subdomains[i]
		isLegal := isLegalDomain(fqdn)
		if isLegal == false {
			continue
		}
		filteredSubdomains = append(filteredSubdomains, fqdn)
	}
	filteredSubdomains = removeDuplicates(filteredSubdomains)
	return filteredSubdomains
}

func getSubdomains(sld string, o *Options) {
	var subdomains []string
	for i := 1; i <= o.Retries; i++ {
		subdomains = getSubdomainFromPDNS(sld, o.Timeout*100, o.Config)
		if subdomains != nil {
			break
		}
		log.Printf("Retry getSubdomainFrom PDNS: %s\n", sld)
		time.Sleep(2 * time.Second)
	}

	//TODO: Filter algorithm-generated subdomains
	filteredSubdomains := domainFilter(subdomains)

	// Output results and save caches.
	fqdnFile := path.Join(o.InputPath, "fqdn.txt")
	cacheFile := path.Join(o.CachePath, "sld_cache.txt")

	if o.Verbose {
		fmt.Printf("Get subdomains: %s (%d)\n", sld, len(filteredSubdomains))
	}
	log.Printf("Get subdomains: %s (%d)", sld, len(filteredSubdomains))
	saveFqdnFile(sld, filteredSubdomains, fqdnFile)
	saveCache(sld, cacheFile)
}

func getCnamesRecursive(subdomain string, o *Options, domainCache *cache.Cache, depth int) (cname CNAME) {
	// The subdomain has been handled
	if item, found := domainCache.Get(subdomain); found {
		return item.(CNAME)
	}

	// The max recursive depth.
	if depth > o.Config.RecursiveDepth {
		domainCache.Set(subdomain, cname, cache.NoExpiration)
		return cname
	}

	cname.Domain = subdomain
	var cnames []string
	// Recursively get CNAME records via passive DNS API.
	for i := 1; i <= o.Retries; i++ {
		cnames = getCnamesFromPDNS(subdomain, o.Timeout, o.Config)
		if cnames != nil {
			break
		}
		log.Printf("Retry getCnamesFromPDNS: %s\n", subdomain)
		time.Sleep(2 * time.Second)
	}
	cnames = domainFilter(cnames)

	// Only leave the first <cnameLimit> cnames
	cnameLimit := Min(len(cnames), o.Config.CnameListSize)
	for i := range cnames[:cnameLimit] {
		if cnames[i] == subdomain {
			continue
		}
		// TODO: Identify random-looking CNAMEs
		curr := getCnamesRecursive(cnames[i], o, domainCache, depth+1)
		cname.Cnames = append(cname.Cnames, curr)
	}
	if o.Verbose {
		fmt.Printf("Look up: %s (depth: %d, cname:%d)\n", subdomain, depth, len(cname.Cnames))
	}
	domainCache.Set(subdomain, cname, cache.NoExpiration)
	return cname
}

// Resolve subdomain and fetch CNAME records
// Output CNAME object: {domain: "domain", cnames: []CNAME}
func getCnames(subdomain string, o *Options) {
	isLegal := isLegalDomain(subdomain)
	if isLegal == false {
		fmt.Printf("[-] '%s' is not with legal domain format.", subdomain)
		return
	}

	domainCache := cache.New(30*time.Second, 10*time.Second)
	cname := getCnamesRecursive(subdomain, o, domainCache, 1)

	// Output results and save caches.
	cnamePath := path.Join(o.InputPath, "cname.txt")
	cacheFile := path.Join(o.CachePath, "fqdn_cache.txt")
	log.Printf("Get cnames: %s (%d)", subdomain, len(cname.Cnames))
	if len(cname.Cnames) > 0 {
		saveCnameFile(cname, cnamePath)
	}
	saveCache(cname.Domain, cacheFile)
}

// TODO: check NXDOMAIN
func nxdomain(nameserver string) bool {
	if _, err := net.LookupHost(nameserver); err != nil {
		if strings.Contains(fmt.Sprintln(err), "no such host") {
			return true
		}
	}
	return false
}

// isAvailable returns true if the domain to be checked can be registerd
func isAvailable(domain string) bool {
	// Using an API implemented by golang: https://github.com/haccer/available.
	available := available.Domain(domain)
	return available
}
