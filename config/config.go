package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Conf struct {
	SubAccess           int           `yaml:"sub_access"`
	CnameAccess         int           `yaml:"cname_access"`
	RecursiveDepth      int           `yaml:"recursive_depth"`
	CnameListSize       int           `yaml:"cname_list_size"`
	PdnsChainUrl        string        `yaml:"pdns_chain_url"`
	PdnsSubdomainUrl    string        `yaml:"pdns_subdomain_url"`
	PdnsNsUrl           string        `yaml:"pdns_ns_url"`
	PdnsReverseCnameUrl string        `yaml:"pdns_reverse_cname_url"`
	PdnsApiToken        string        `yaml:"pdns_api_token"`
	PdnsApiAccess       string        `yaml:"pdns_api_fdp_access"`
	PdnsApiSecret       string        `yaml:"pdns_api_fdp_secret"`
	SubDuration         time.Duration `yaml:"sub_duration"`
	ChainDuration       time.Duration `yaml:"chain_duration"`
	MaxFetchCount       int           `yaml:"max_fetch_count"`
}

type GlobalConfig struct {
	Dataset        string
	SldFilePath    string
	FqdnFilePath   string
	OutputDir      string
	ScanDate       string
	CheckAvailable bool
	CheckFull      bool
	Fresh          bool
	Ssl            bool
	Verbose        bool

	Modules    string
	Threads    int
	Timeout    int
	Retries    int
	GoMaxProcs int

	ServicePath string
	ServiceList []Service
	ConfigPath  string
	Config      Conf
	CachePath   string
	LogPath     string
}

type Service struct {
	Service         string   `json:"service"`
	NamePatterns    []string `json:"name_patterns"`
	Fingerprint     []string `json:"fingerprint,omitempty"`
	HttpFingerprint []string `json:"http_fingerprint,omitempty"`
	DnsFingerprint  []string `json:"dns_fingerprint,omitempty"`
	NXDomain        bool     `json:"nxdomain,omitempty"`
	IsVulnerable    bool     `json:"is_vulnerable"`
}

type MyFormatter struct{}

func (m *MyFormatter) Format(entry *log.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	timestamp := entry.Time.Format("2006-01-02 15:04:05")
	var newLog string

	//HasCaller()为true才会有调用信息
	if entry.HasCaller() {
		fName := path.Base(entry.Caller.File)
		newLog = fmt.Sprintf("[%s] [%s:%d %s] %s\n",
			timestamp, fName, entry.Caller.Line, entry.Caller.Function, entry.Message)
	} else {
		newLog = fmt.Sprintf("[%s] %s\n", timestamp, entry.Message)
	}

	b.WriteString(newLog)
	return b.Bytes(), nil
}

// redefine JsonFormatter struct in logrus
type MyJSONFormatter struct {
	// TimestampFormat sets the format used for marshaling timestamps.
	// The format to use is the same than for time.Format or time.Parse from the standard
	// library.
	// The standard Library already provides a set of predefined format.
	TimestampFormat string

	// DisableTimestamp allows disabling automatic timestamps in output
	DisableTimestamp bool

	// DisableHTMLEscape allows disabling html escaping in output
	DisableHTMLEscape bool

	// DataKey allows users to put all the log entry parameters into a nested dictionary at a given key.
	DataKey string

	FieldMap log.FieldMap

	// CallerPrettyfier can be set by the user to modify the content
	// of the function and file keys in the json data when ReportCaller is
	// activated. If any of the returned value is the empty string the
	// corresponding key will be removed from json fields.
	CallerPrettyfier func(*runtime.Frame) (function string, file string, line int, funcName string)

	// PrettyPrint will indent all json logs
	PrettyPrint bool
}

func loadConfig(confFile string) (c Conf) {
	yamlConfig, err := ioutil.ReadFile(confFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = yaml.Unmarshal(yamlConfig, &c)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return c
}

func loadServiceList(file string) (serviceList []Service) {
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

func splitInputFile(inputPath string, outputPath string, l int) {
	var lines []string
	file, err := os.Open(inputPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanner.Err() != nil {
		log.Fatalln(err)
	}

	for i := range lines {
		outputBase := fmt.Sprintf("%salexa_%dk", outputPath, (i/l + 1))
		err := os.MkdirAll(outputBase, os.ModePerm)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		outputPath := path.Join(outputBase, "sld.txt")
		fmt.Println(outputPath)
		f, err := os.OpenFile(outputPath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalln(err)
		}
		defer f.Close()
		_, err = f.WriteString(lines[i] + "\n")
		if err != nil {
			log.Fatalln(err)
		}
	}

}

func Initialize(o *GlobalConfig) {
	fmt.Println("[+] Initializing...")
	defaultDataPath := "./data/"
	defaultOutputPath := "./results/"

	// SLD Path
	if strings.Contains(o.Modules, "subdomain") {
		if o.SldFilePath == "" {
			o.SldFilePath = path.Join(defaultDataPath, o.Dataset, "sld.txt")
			fmt.Printf("[+] Input data path (SLD list): %s\n", o.SldFilePath)
		}
		_, err := os.Stat(o.SldFilePath)
		if os.IsNotExist(err) {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	// Result Path
	if o.OutputDir == "" {
		date := time.Now().Format("20060102")
		if o.ScanDate != "20001212" {
			date = o.ScanDate
		}
		o.OutputDir = path.Join(defaultOutputPath, date, o.Dataset)
		fmt.Printf("[+] Output results path: %s\n", o.OutputDir)
	}
	//Create an output directory if it doesn't exist.
	_, err := os.Stat(o.OutputDir)
	if os.IsNotExist(err) {
		err := os.MkdirAll(o.OutputDir, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}

	//FQDN Path
	if o.FqdnFilePath == "" {
		o.FqdnFilePath = path.Join(o.OutputDir, "fqdn.txt")
		fmt.Printf("[+] Subdomain (fqdn) path: %s\n", o.FqdnFilePath)
	}
	// Cache Path
	o.CachePath = path.Join(o.OutputDir, "cache")
	err1 := os.MkdirAll(o.CachePath, os.ModePerm)
	if err1 != nil {
		fmt.Println(err1)
		os.Exit(1)
	}

	logPath := path.Join(o.OutputDir, "ptake.log")
	if o.Fresh {
		fmt.Println("[!] A fresh scan will be start. It's going to remove cache files...")
		dir, _ := ioutil.ReadDir(o.CachePath)
		for _, d := range dir {
			os.RemoveAll(path.Join([]string{o.CachePath, d.Name()}...))
		}
		fmt.Printf("[!] Cache files in %s are removed!\n", o.CachePath)
		os.Remove(logPath)
		fmt.Printf("[!] Log file is removed (%s)\n", logPath)
	}

	// Log Path
	if o.LogPath != "" {
		logPath = o.LogPath
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)
	log.SetFormatter(&MyFormatter{})
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(true)

	// Configurations
	o.Config = loadConfig(o.ConfigPath)
	o.ServiceList = loadServiceList(o.ServicePath)
	fmt.Printf("[+] Load %d services.\n", len(o.ServiceList))

	if o.GoMaxProcs != 0 {
		runtime.GOMAXPROCS(o.GoMaxProcs)
	}

	fmt.Println("[+] Initialize over.")

}
