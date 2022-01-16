package main

import (
    "bufio"
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "os"
    "ptake/config"
    "ptake/ptake_pkg"
    "strings"
    "sync"
)

func loadServiceList(file string) (serviceList []config.Service) {
    config, err := ioutil.ReadFile(file)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    err = json.Unmarshal(config, &serviceList)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    return serviceList
}

func checkFingerprint(originName string, service string, matchedFp []string, chain ptake_pkg.CNAME, services []config.Service){
    vulDomain := chain.Domain
    match := false
    for i := range services {
        currService := services[i]
        namePatterns := currService.NamePatterns
        for j := range namePatterns {
            if strings.HasSuffix(vulDomain, namePatterns[j]) {
                match = true
                break
            }
        }
        if match{
            service = currService.Service
            matchedFp = currService.Fingerprint
            break
        }
    }
    if match {
        if chain.Cnames != nil {
            for i := range chain.Cnames {
                cname := chain.Cnames[i]
                checkFingerprint(chain.Domain, service, matchedFp, cname, services)
            }
        }
    } else {
        _, body := ptake_pkg.Get(vulDomain, 3, false)
        if body == nil {
            _, body = ptake_pkg.Get(vulDomain, 3, true)
        }
        for j := range matchedFp{
            if bytes.Contains(body, []byte(matchedFp[j])){
                fmt.Printf("origin: %s, cname: %s, service: %s, fp: %s\n", originName, chain.Domain, service, matchedFp[j])
                break
            }
        }
    }
}

func main() {
    rchainPath := os.Args[1]
    servicePath := os.Args[2]
    threads := 100
    services := loadServiceList(servicePath)

    chanStream := make(chan ptake_pkg.CNAME, threads)
    wg := new(sync.WaitGroup)

    var defaultFps []string
    defaultFps = append(defaultFps, "jfaljdfkasdfadf")

    // Consumer
    for i := 0; i < threads; i++ {
        wg.Add(1)
        go func() {
            for chain := range chanStream {
                checkFingerprint(chain.Domain, "unknownService",defaultFps, chain,  services)
            }
            wg.Done()
        }()
    }

    // Producer: Load CNAME chains to be checked.
    file, err := os.Open(rchainPath)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer file.Close()
    reader := bufio.NewReader(file)
    for {
        var chain ptake_pkg.CNAME
        lineBytes, err := reader.ReadBytes('\n')
        if err == io.EOF {
            break
        }
        if err != nil {
            fmt.Println("Error: %s\n", err.Error())
        }
        lineBytes = bytes.TrimRight(lineBytes, "\n")
        json.Unmarshal(lineBytes, &chain)
        chanStream <- chain
    }

}
