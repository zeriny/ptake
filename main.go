package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"ptake/config"
	"ptake/ptake_pkg"
	"strings"
)

func main() {
	//GOPATH := os.Getenv("GOPATH")
	//Project := "/src/ptake/"
	//configFile := "services.json"
	//defaultConfig := GOPATH + Project + configFile
	//defaultConfig := path.Join(GOPATH, Project, configFile)

	//o := ptake_pkg.Options{}
	var gc config.GlobalConfig

	flag.StringVar(&gc.Modules, "module", "", "Selected modules (splitted by ,).")
	flag.StringVar(&gc.Dataset, "dataset", "", "Dataset name.")
	flag.StringVar(&gc.InputPath, "data-path", "", "Path to Dataset.")
	flag.StringVar(&gc.OutputPath, "result-path", "", "Output results (json object) to a .txt file (Default: ./results/<dataset>/).")
	flag.BoolVar(&gc.CheckAvailable, "check-status", false, "Check whether CNAMEs are available (can be registered).")
	flag.BoolVar(&gc.CheckFull, "check-full", false, "Check full DNS chains no matter whether any cname is vulnerable.")
	flag.BoolVar(&gc.Fresh, "fresh", false, "Start a fresh scan. If the flag set, a new scan will be "+
		"start, and the cache file of the last scan will be totally removed.")

	flag.IntVar(&gc.Threads, "threads", 100, "Number of concurrent go threads.")
	flag.IntVar(&gc.Timeout, "timeout", 10, "Seconds to wait before connection timeout.")
	flag.IntVar(&gc.Retries, "retry", 3, "Retry the request if it's failed.")
	flag.IntVar(&gc.GoMaxProcs, "go-processes", 0, "Number of CPUs (GOMAXPROCS)")

	flag.BoolVar(&gc.Ssl, "ssl", false, "Force HTTPS connections (May increase accuracy (Default: http://).")
	flag.BoolVar(&gc.Verbose, "v", false, "Display more information per each request.")
	flag.StringVar(&gc.ConfigPath, "c", "./config/conf.yaml", "Path to conf.yaml.")
	flag.StringVar(&gc.ServicePath, "service", "./config/services.json", "Path to services.json file.")
	flag.StringVar(&gc.LogPath, "log", "", "Path to a log file.")

	flag.Parse()

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	config.Initialize(&gc)
	log.Println("Initializing...")


	modules := strings.Split(gc.Modules, ",")
	for i := range modules {
		switch modules[i] {
		case "subdomain":
			fmt.Printf("[+] Start module: %s\n", modules[i])
			ptake_pkg.StartGetSubdomains(&gc)
		case "cname":
			fmt.Printf("[+] Start module: %s\n", modules[i])
			ptake_pkg.StartGetCnames(&gc)
		case "check":
			fmt.Printf("[+] Start module: %s\n", modules[i])
			ptake_pkg.StartChecker(&gc)
		default:
			fmt.Println("[-] Please select modules (-module 'subdomain,cname,check').")
		}
	}
	log.Println("Scan Over!")

}
