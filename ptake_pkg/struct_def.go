package ptake_pkg

import "ptake/config"

//type MatchedService struct {
//	Service             string   `json:"service"`
//	MatchedPatterns     []string `json:"matched_patterns"`
//	MatchedFingerprints []string `json:"matched_fingerprints"`
//}

type DomainStatus struct {
	Domain          string `json:"domain"`
	VulnerableLevel int    `json:"vulnerable_level"` // The highest threat level of Domain
	Type string `json:"type"`
	MatchedServices []config.Service `json:"matched_services"` // Set if Type is MatchServicePattern
	//MatchServiceFps []string `json:"match_service_fps"` // Set if Vulnerable is 2
	VulCnames []DomainStatus `json:"vul_cnames"` // Set when Type is CnameVulnerable
	CheckTime string `json:"check_time"` // Checking Time
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
	TimeFirst int64 `json:"time_first"`
	TimeLast int64 `json:"time_last"`
}

type CNAME struct {
	Domain string  `json:"domain"`
	Cnames []CNAME `json:"cnames"`
}

type DnsChain struct {
	Name string  `json:"name"`
	Chains []DnsChain `json:"chains"`
}
type NSType struct {
	Domain string `json:"domain"`
	NameServers []PDNSRecord `json:"name_servers"`
}

type Results struct {
	Subdomain  string `json:"subdomain"`
	Vulnerable bool   `json:"vulnerable"`
	Type       string `json:"type"`
	Service    string `json:"service,omitempty"`
	Domain     string `json:"nonexist_domain,omitempty"`
}
