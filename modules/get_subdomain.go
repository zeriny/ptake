package modules

//func StartGetSubdomains(o *ptake_pkg.Options) {
//    var sldList []string
//    var sldCache map[string]int
//
//    // Load SLDs to be handled.
//    sldFile := path.Join(o.InputPath, "sld.txt")
//    sldList = ptake_pkg.ReadFile(sldFile)
//
//    cacheFile := path.Join(o.CachePath, "sld_cache.txt")
//    sldCache = ptake_pkg.ReadCache(cacheFile) // Load SLDs that have been handled.
//
//    chanStream := make(chan string, o.Threads*10)
//    wg := new(sync.WaitGroup)
//
//    // Consumer
//    for i := 0; i < o.Threads; i++ {
//        wg.Add(1)
//        go func() {
//            for sld := range chanStream {
//                getSubdomains(sld, o)
//            }
//            wg.Done()
//        }()
//    }
//
//    // Producer
//    for i := 0; i < len(sldList); i++ {
//        _, ok := sldCache[sldList[i]]
//        if ok {
//            continue
//        }
//        chanStream <- sldList[i]
//    }
//
//    close(chanStream)
//    wg.Wait()
//    fmt.Println("[+] Get subdomains over!")
//}
//
//func getSubdomains(sld string, o *ptake_pkg.Options) {
//    var subdomains []string
//    subdomains = ptake_pkg.GetSubdomainFromPDNS(sld, o.Timeout, o.Retries, o.Config)
//
//    //TODO: Filter algorithm-generated subdomains
//    filteredSubdomains := ptake_pkg.DomainFilter(subdomains)
//
//    // Output results and save caches.
//    fqdnFile := path.Join(o.InputPath, "fqdn.txt")
//    cacheFile := path.Join(o.CachePath, "sld_cache.txt")
//
//    if o.Verbose {
//        fmt.Printf("Get subdomains: %s (%d)\n", sld, len(filteredSubdomains))
//        log.Printf("Get subdomains: %s (%d)\n", sld, len(filteredSubdomains))
//    }
//    ptake_pkg.SaveFqdnFile(sld, filteredSubdomains, fqdnFile)
//    ptake_pkg.SaveCache(sld, cacheFile)
//}