package ptake_pkg

type Conf struct {
	SubAccess        int    `yaml:"sub_access"`
	CnameAccess      int    `yaml:"cname_access"`
	RecursiveDepth   int    `yaml:"recursive_depth"`
	CnameListSize    int    `yaml:"cname_list_size"`
	PdnsCnameUrl     string `yaml:"pdns_cname_url"`
	PdnsSubdomainUrl string `yaml:"pdns_subdomain_url"`
	PdnsApiToken     string `yaml:"pdns_api_token"`
}

type Options struct {
	Dataset        string
	InputPath      string
	OutputPath     string
	CheckAvailable bool
	CheckFull      bool
	Fresh          bool
	Ssl            bool
	Verbose        bool

	Modules string
	Threads int
	Timeout int
	Retries int

	ServicePath string
	ServiceList []Service
	ConfigPath  string
	Config      Conf
	CachePath   string
	LogPath     string
}

type Service struct {
	Service      string   `json:"service"`
	NamePatterns []string `json:"name_patterns"`
	Fingerprint  []string `json:"fingerprint"`
	NXDomain     bool     `json:"nxdomain"`
}

type MatchedService struct {
	Service             string   `json:"service"`
	MatchedPatterns     []string `json:"matched_patterns"`
	MatchedFingerprints []string `json:"matched_fingerprints"`
}

type DomainStatus struct {
	Domain          string `json:"domain"`
	VulnerableLevel int    `json:"vulnerable_level"` // The highest threat level of Domain
	// level 0: Not vulnerable
	// level 1: MatchServicePattern
	// level 2: Available
	Type string `json:"type"` // Vulnerable types: Available, MatchServicePattern, CnameVulnerable, AbandonedService
	//AvailableCnames []string `json:"available_cnames"` // Set if Type is CnameAvailable
	MatchedServices []MatchedService `json:"matched_services"` // Set if Type is MatchServicePattern
	//MatchServiceFps []string `json:"match_service_fps"` // Set if Vulnerable is 2
	VulCnames []DomainStatus `json:"vul_cnames"` // Set when Type is CnameVulnerable
}

type PDNSResponse struct {
	StatusCode int          `json:"code"`
	Status     string       `json:"status"`
	Data       []PDNSRecord `json:"data,omitempty"`
}

type PDNSRecord struct {
	Count  int    `json:"count"`
	RRName string `json:"rrname"`
	RRType string `json:"rrtype"`
	Rdata  string `json:"rdata,omitempty"`
	//TimeFirst int `json:"time_first"`
	//TimeLast int `json:"time_last"`
}

type CNAME struct {
	Domain string  `json:"domain"`
	Cnames []CNAME `json:"cnames"`
}

type Results struct {
	Subdomain  string `json:"subdomain"`
	Vulnerable bool   `json:"vulnerable"`
	Type       string `json:"type"`
	Service    string `json:"service,omitempty"`
	Domain     string `json:"nonexist_domain,omitempty"`
}
