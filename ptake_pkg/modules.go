package ptake_pkg

import (
	"fmt"
	"github.com/patrickmn/go-cache"
	"log"
	"os"
	"path"
	"sync"
	"time"
)

func StartGetSubdomains(o *Options) {
	var err error
	var sldList []string
	sldCache := make(map[string]int)

	domainCache := cache.New(30*time.Second, 10*time.Second)
	sldFile := path.Join(o.InputPath, "sld.txt")
	fqdnFile := path.Join(o.InputPath, "fqdn.txt")
	cacheFile := path.Join(o.CachePath, "sld_cache.txt")

	// Load SLDs to be handled.
	_, err = os.Stat(sldFile)
	if err == nil {
		sldList, err = readFile(sldFile)
		if err != nil {
			log.Fatalln(err)
		}
	}

	// Load SLDs that have been handled.
	_, err = os.Stat(cacheFile)
	if err == nil {
		slds, _ := readFile(cacheFile)
		for i := range slds{
			sldCache[slds[i]] = 1
		}
	}
	//sldList = append(sldList, "twitter.com")

	chanStream := make(chan string, o.Threads*10)
	wg := new(sync.WaitGroup)

	// Consumer
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for sld := range chanStream {
				getSubdomains(sld, fqdnFile, cacheFile, o, domainCache)
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

func StartGetCnames(o *Options) {
	var subdomainList []string
	var err error
	subdomainCache := make(map[string]int)

	fqdnPath := path.Join(o.InputPath, "fqdn.txt")
	cnamePath := path.Join(o.InputPath, "cname.txt")
	cacheFile := path.Join(o.CachePath, "fqdn_cache.txt")

	if fqdnPath != "" {
		subdomainList, err = readFqdnFile(fqdnPath, 1)
		if err != nil {
			log.Fatalln(err)
		}
	}

	// Load Subdomains that have been resolved.
	_, err = os.Stat(cacheFile)
	if err == nil {
		fqdns, _ := readFile(cacheFile)
		for i := range fqdns{
			subdomainCache[fqdns[i]] = 1
		}
	}


	domainCache := cache.New(30*time.Second, 10*time.Second)
	chanStream := make(chan string, o.Threads*10)
	wg := new(sync.WaitGroup)

	// Consumer
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for subdomain := range chanStream {
				getCnames(subdomain, cnamePath, cacheFile, o, domainCache)
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
	fmt.Println("[+] Get cnames over!")
}

func StartChecker(o *Options) {
	var cnameList []CNAME
	var err error
	subdomainCache := make(map[string]int)


	// Initialize
	cnamePath := path.Join(o.InputPath, "cname.txt")
	//vulnerablePath := path.Join(o.Output, "vulnerable.txt")
	//normalPath := path.Join(o.Output, "normal.txt")
	cacheFile := path.Join(o.CachePath, "check_cache.txt")


	if cnamePath != "" {
		_, cnameList, err = readCnameFile(cnamePath)
		if err != nil {
			log.Fatalln(err)
		}
	}

	// Load Subdomains that have been checked.
	_, err = os.Stat(cacheFile)
	if err == nil {
		fqdns, _ := readFile(cacheFile)
		for i := range fqdns{
			subdomainCache[fqdns[i]] = 1
		}
	}

	domainCache := cache.New(30*time.Second, 10*time.Second)
	chanStream := make(chan CNAME, o.Threads*10)
	wg := new(sync.WaitGroup)

	// Consumer
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for cname := range chanStream {
				checkService(cname, o, domainCache)
				save(cname.Domain, cacheFile)
			}
			wg.Done()
		}()
	}

	// Producer
	for i := 0; i < len(cnameList); i++ {
		_, ok := subdomainCache[cnameList[i].Domain]
		if ok {
			continue
		}
		chanStream <- cnameList[i]
	}

	close(chanStream)
	wg.Wait()
	fmt.Println("Check CNAMEs over!")
}
