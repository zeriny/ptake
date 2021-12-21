package ptake_pkg

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"path"
	"ptake/config"
	"sync"
)

func StartGetSubdomains(o *config.GlobalConfig) {
	var sldList []string
	var sldCache map[string]int

	// Load SLDs to be handled.
	sldFile := path.Join(o.InputPath, "sld.txt")
	sldList = readFile(sldFile)

	cacheFile := path.Join(o.CachePath, "sld_cache.txt")
	sldCache = readCache(cacheFile) // Load SLDs that have been handled.

	chanStream := make(chan string, o.Threads*10)
	wg := new(sync.WaitGroup)

	// Consumer
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for sld := range chanStream {
				getSubdomains(sld, o)
			}
			wg.Done()
		}()
	}

	// Producer
	for i := 0; i < len(sldList); i++ {
		_, ok := sldCache[sldList[i]]
		if ok {
			continue
		}
		chanStream <- sldList[i]
	}

	close(chanStream)
	wg.Wait()
	fmt.Println("[+] Get subdomains over!")
}

func StartGetChains(o *config.GlobalConfig) {
	var subdomainList []string
	subdomainCache := make(map[string]int)

	// Load FQDNs to be handled.
	fqdnPath := path.Join(o.OutputPath, "fqdn.txt")
	subdomainList = readFqdnFile(fqdnPath, 1)

	cacheFile := path.Join(o.CachePath, "fqdn_cache.txt")
	subdomainCache = readCache(cacheFile) // Load FQDNs that have been handled.

	chanStream := make(chan string, o.Threads*10)
	wg := new(sync.WaitGroup)

	// Consumer
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for subdomain := range chanStream {
				getChains(subdomain, o)
			}
			wg.Done()
		}()
	}

	// Producer
	for i := 0; i < len(subdomainList); i++ {
		_, ok := subdomainCache[subdomainList[i]]
		if ok {
			continue
		}
		chanStream <- subdomainList[i]
	}

	close(chanStream)
	wg.Wait()
	fmt.Println("[+] Get chains over!")
}

func StartChecker(o *config.GlobalConfig) {
	var chainsList []string
	var subdomainCache map[string]int

	_, err := os.Stat(o.OutputPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(o.OutputPath, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Load CNAME chains to be checked.
	chainPath := path.Join(o.OutputPath, "chain.txt")
	chainsList = readFile(chainPath)

	// Load Subdomains that have been checked.
	cacheFile := path.Join(o.CachePath, "check_cache.txt")
	subdomainCache = readCache(cacheFile)

	chanStream := make(chan DnsChain, o.Threads*10)
	wg := new(sync.WaitGroup)

	// Consumer
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for chain := range chanStream {
				checkService(chain, cacheFile, o)
			}
			wg.Done()
		}()
	}

	// Producer
	for i := 0; i < len(chainsList); i++ {
		var chain DnsChain
		json.Unmarshal([]byte(chainsList[i]), &chain)
		_, ok := subdomainCache[chain.Name]
		if ok {
			continue
		}
		chanStream <- chain
	}

	close(chanStream)
	wg.Wait()
	fmt.Println("Check CNAMEs over!")
}


func StartGetReverseCnames(o *config.GlobalConfig) {
	var fqdnList []string
	domainCache := make(map[string]int)

	// Load domain names to be handled.
	fqdnPath := path.Join(o.OutputPath, "vulnerable_fqdn.txt")
	fqdnList = readFile(fqdnPath)

	cacheFile := path.Join(o.CachePath, "reverse_cache.txt")
	domainCache = readCache(cacheFile) // Load domain names that have been handled.

	chanStream := make(chan string, o.Threads*10)
	wg := new(sync.WaitGroup)

	// Consumer
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for subdomain := range chanStream {
				getRCnames(subdomain, o)
			}
			wg.Done()
		}()
	}

	// Producer
	for i := 0; i < len(fqdnList); i++ {
		_, ok := domainCache[fqdnList[i]]
		if ok {
			continue
		}
		chanStream <- fqdnList[i]
	}

	close(chanStream)
	wg.Wait()
	fmt.Println("[+] Get reverse chains over!")
}