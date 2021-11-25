package modules

type CNAME struct {
    Domain string  `json:"domain"`
    Cnames []CNAME `json:"cnames"`
}

//func StartGetCnames(o *ptake_pkg.Options) {
//    var subdomainList []string
//    subdomainCache := make(map[string]int)
//
//    // Load FQDNs to be handled.
//    fqdnPath := path.Join(o.InputPath, "fqdn.txt")
//    subdomainList = ptake_pkg.ReadFqdnFile(fqdnPath, 1)
//
//    cacheFile := path.Join(o.CachePath, "fqdn_cache.txt")
//    subdomainCache = ptake_pkg.ReadCache(cacheFile) // Load FQDNs that have been handled.
//
//    chanStream := make(chan string, o.Threads*10)
//    wg := new(sync.WaitGroup)
//
//    // Consumer
//    for i := 0; i < o.Threads; i++ {
//        wg.Add(1)
//        go func() {
//            for subdomain := range chanStream {
//                getCnames(subdomain, o)
//            }
//            wg.Done()
//        }()
//    }
//
//    // Producer
//    for i := 0; i < len(subdomainList); i++ {
//        _, ok := subdomainCache[subdomainList[i]]
//        if ok {
//            continue
//        }
//        chanStream <- subdomainList[i]
//    }
//
//    close(chanStream)
//    wg.Wait()
//    fmt.Println("[+] Get cnames over!")
//}
//
//// Resolve subdomain and fetch CNAME records
//// Output CNAME object: {domain: "domain", cnames: []CNAME}
//func getCnames(subdomain string, o *ptake_pkg.Options) {
//    isLegal := ptake_pkg.IsLegalDomain(subdomain)
//    if isLegal == false {
//        log.Printf("[-] '%s' is not in legal format.\n", subdomain)
//        return
//    }
//
//    domainCache := cache.New(30*time.Second, 10*time.Second)
//    cname := getCnamesRecursive(subdomain, o, domainCache, 1)
//
//    // Output results and save caches.
//    cnamePath := path.Join(o.InputPath, "cname.txt")
//    cacheFile := path.Join(o.CachePath, "fqdn_cache.txt")
//    log.Printf("Get cnames: %s (%d)", subdomain, len(cname.Cnames))
//    if len(cname.Cnames) > 0 {
//        SaveCnameFile(cname, cnamePath)
//    }
//    ptake_pkg.SaveCache(cname.Domain, cacheFile)
//}
//
//func getCnamesRecursive(subdomain string, o *ptake_pkg.Options, domainCache *cache.Cache, depth int) (cname CNAME) {
//    // The subdomain has been handled
//    if item, found := domainCache.Get(subdomain); found {
//        return item.(CNAME)
//    }
//
//    // The max recursive depth.
//    if depth > o.Config.RecursiveDepth {
//        domainCache.Set(subdomain, cname, cache.NoExpiration)
//        return cname
//    }
//
//    cname.Domain = subdomain
//    var cnames []string
//    // Recursively get CNAME records via passive DNS API.
//    cnames = ptake_pkg.GetCnamesFromPDNS(subdomain, o.Timeout, o.Retries, o.Config)
//    cnames = ptake_pkg.DomainFilter(cnames)
//
//    // Only leave the first <cnameLimit> cnames
//    cnameLimit := ptake_pkg.Min(len(cnames), o.Config.CnameListSize)
//    for i := range cnames[:cnameLimit] {
//        if cnames[i] == subdomain {
//            continue
//        }
//        // TODO: Identify random-looking CNAMEs
//        curr := getCnamesRecursive(cnames[i], o, domainCache, depth+1)
//        cname.Cnames = append(cname.Cnames, curr)
//    }
//    if o.Verbose {
//        fmt.Printf("Look up: %s (depth: %d, cname:%d)\n", subdomain, depth, len(cname.Cnames))
//    }
//    domainCache.Set(subdomain, cname, cache.NoExpiration)
//    return cname
//}
//
//func SaveCnameFile(cname CNAME, path string) {
//    results, _ := json.Marshal(cname)
//    wf, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
//    if err != nil {
//        log.Println(err)
//    }
//    defer wf.Close()
//    wf.Write(results)
//    wf.WriteString("\n")
//}