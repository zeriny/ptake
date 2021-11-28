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

func StartGetCnames(o *config.GlobalConfig) {
	var subdomainList []string
	subdomainCache := make(map[string]int)

	// Load FQDNs to be handled.
	fqdnPath := path.Join(o.InputPath, "fqdn.txt")
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
				getCnames(subdomain, o)
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

func StartChecker(o *config.GlobalConfig) {
	var cnameList []string
	var subdomainCache map[string]int

	_, err := os.Stat(o.OutputPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(o.OutputPath, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Load CNAME chains to be checked.
	cnamePath := path.Join(o.InputPath, "cname.txt")
	cnameList = readFile(cnamePath)

	// Load Subdomains that have been checked.
	cacheFile := path.Join(o.CachePath, "check_cache.txt")
	subdomainCache = readCache(cacheFile)

	chanStream := make(chan CNAME, o.Threads*10)
	wg := new(sync.WaitGroup)

	// Consumer
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for cname := range chanStream {
				checkService(cname, cacheFile, o)
			}
			wg.Done()
		}()
	}

	// Producer
	for i := 0; i < len(cnameList); i++ {
		var cname CNAME
		json.Unmarshal([]byte(cnameList[i]), &cname)
		_, ok := subdomainCache[cname.Domain]
		if ok {
			continue
		}
		chanStream <- cname
	}

	close(chanStream)
	wg.Wait()
	fmt.Println("Check CNAMEs over!")
}
