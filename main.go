package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"ptake/ptake_pkg"
	"strings"
)

func main() {
	//GOPATH := os.Getenv("GOPATH")
	//Project := "/src/ptake/"
	//configFile := "services.json"
	//defaultConfig := GOPATH + Project + configFile
	//defaultConfig := path.Join(GOPATH, Project, configFile)

	o := ptake_pkg.Options{}
	flag.StringVar(&o.Modules, "module", "", "Selected modules (splitted by ,).")
	flag.StringVar(&o.Dataset, "dataset", "default", "Dataset name.")
	flag.StringVar(&o.InputPath, "data_path", "", "Path to Dataset.")
	flag.StringVar(&o.OutputPath, "result_path", "", "Output results (json object) to a .txt file.")
	flag.BoolVar(&o.CheckAvailable, "check_status", false, "Check whether CNAMEs are available (can be registered).")
	flag.BoolVar(&o.CheckFull, "check_full", false, "Check full DNS chains no matter whether any cname is vulnerable.")
	flag.BoolVar(&o.Fresh, "fresh", false, "Start a fresh scan. If the flag set, a new scan will be "+
		"start, and the cache file of the last scan will be totally removed.")

	flag.IntVar(&o.Threads, "thread", 10, "Number of concurrent threads.")
	flag.IntVar(&o.Timeout, "timeout", 10, "Seconds to wait before connection timeout.")
	flag.IntVar(&o.Retries, "retry", 3, "Retry the request if it's failed.")

	flag.BoolVar(&o.Ssl, "ssl", false, "Force HTTPS connections (May increase accuracy (Default: http://).")
	flag.BoolVar(&o.Verbose, "v", false, "Display more information per each request.")
	flag.StringVar(&o.ConfigPath, "c", "./config/conf.yaml", "Path to conf.yaml.")
	flag.StringVar(&o.ServicePath, "service", "./config/services.json", "Path to services.json file.")
	flag.StringVar(&o.LogPath, "log", "./ptake.log", "Path to a log file.")

	flag.Parse()

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	ptake_pkg.Initialize(&o)
	log.Println("Initializing...")

	//domainCache := cache.New(30*time.Second, 10*time.Second)
	//ptake_pkg.TestGetCnames("10years.qq.com", o.Timeout, o.Config, domainCache, 1 )
	modules := strings.Split(o.Modules, ",")
	for i := range modules {
		switch modules[i] {
		case "subdomain":
			fmt.Printf("[+] Start module: %s\n", modules[i])
			ptake_pkg.StartGetSubdomains(&o)
		case "cname":
			fmt.Printf("[+] Start module: %s\n", modules[i])
			ptake_pkg.StartGetCnames(&o)
		case "check":
			fmt.Printf("[+] Start module: %s\n", modules[i])
			ptake_pkg.StartChecker(&o)
		default:
			fmt.Println("[-] Please select modules (-module 'subdomain,cname,check').")
		}
	}
	log.Println("Over!")

}
