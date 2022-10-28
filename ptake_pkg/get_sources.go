package ptake_pkg

import (
    "path"
    "ptake/config"
)


// Load SLDs to be handled from files.
func getSldList(o *config.GlobalConfig) (sldList []string, sldCache map[string]int){
    sldList = readFile(o.SldFilePath)

    // Load SLDs that have been handled.
    cacheFile := path.Join(o.CachePath, "sld_cache.txt")
    sldCache = readCache(cacheFile)

    return sldList, sldCache
}

// Load FQDNs to be handled from files.
func getFqdnList(o *config.GlobalConfig) (fqdnList []string, fqdnCache map[string]int){
    fqdnList = readFqdnFile(o.FqdnFilePath, 1)

    // Load FQDNs that have been handled.
    cacheFile := path.Join(o.CachePath, "fqdn_cache.txt")
    fqdnCache = readCache(cacheFile)
    return fqdnList, fqdnCache
}


// Load vulnerable FQDNs to be handled from files.
func getVulFqdnList(o *config.GlobalConfig) (fqdnList []string, fqdnCache map[string]int){
    fqdnPath := path.Join(o.OutputDir, "vulnerable_fqdn.txt")
    fqdnList = readFile(fqdnPath)

    // Load domain names that have been handled.
    cacheFile := path.Join(o.CachePath, "reverse_cache.txt")
    fqdnCache = readCache(cacheFile)

    return fqdnList, fqdnCache
}

// Load domain names that have been checked from files.
func getCheckerCache(o *config.GlobalConfig) (domainCache map[string]int){
    cacheFile := path.Join(o.CachePath, "check_cache.txt")
    domainCache = readCache(cacheFile)
    return domainCache
}