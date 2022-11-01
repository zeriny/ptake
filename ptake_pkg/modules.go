package ptake_pkg

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"path"
	"ptake/config"
	"sync"
)

func StartGetSubdomains(o *config.GlobalConfig) {
	var sldList []string
	var sldCache map[string]int

	sldList, sldCache = getSldList(o)
	chanStream := make(chan string, o.Threads*10)
	wg := new(sync.WaitGroup)

	// Consumer
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for sld := range chanStream {
				if sld != ""{
					getSubdomains(sld, o)
				}
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

	subdomainList, subdomainCache = getFqdnList(o)
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
	var subdomainCache map[string]int
	subdomainCache = getCheckerCache(o)
	chanStream := make(chan DnsChain, o.Threads*10)
	wg := new(sync.WaitGroup)

	// Consumer
	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			for chain := range chanStream {
				checkService(chain, o)
			}
			wg.Done()
		}()
	}

	// Producer: Load CNAME chains to be checked from file.
	chainPath := path.Join(o.OutputDir, "chain.txt")
	file, err := os.Open(chainPath)
	if err != nil {
		log.Println("There are no DNS chains obtained for the tested FQDNs.")
		log.Fatalln(err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	for {
		var chain DnsChain
		lineBytes, err := reader.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Println("Error: %s\n", err.Error())
		}
		lineBytes = bytes.TrimRight(lineBytes, "\n")
		json.Unmarshal(lineBytes, &chain)
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

	fqdnList, domainCache = getVulFqdnList(o)
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