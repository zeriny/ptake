package ptake_pkg

import "ptake/config"

//type MatchedService struct {
//	Service             string   `json:"service"`
//	MatchedPatterns     []string `json:"matched_patterns"`
//	MatchedFingerprints []string `json:"matched_fingerprints"`
//}

type DomainStatus struct {
	Domain          string           `json:"domain"`
	VulnerableLevel int              `json:"vulnerable_level"` // The highest threat level of Domain
	Type            string           `json:"type"`
	MatchedServices []config.Service `json:"matched_services"` // Set if Type is MatchServicePattern
	MatchedFp       string           `json:"matched_fp"`
	Cnames          []DomainStatus   `json:"cnames"`
	CheckTime       string           `json:"check_time"` // Checking Time
}

type FlintRRsetResponse struct {
	StatusCode int                `json:"code"`
	Status     string             `json:"status"`
	Data       []FlintRRsetRecord `json:"data,omitempty"`
	LastKey    string             `json:"lastkey,omitempty"`
}

type FlintRRsetRecord struct {
	Count     int    `json:"count"`
	RRName    string `json:"rrname"`
	RRType    string `json:"rrtype"`
	Rdata     string `json:"rdata,omitempty"`
	TimeFirst int64  `json:"time_first"`
	TimeLast  int64  `json:"time_last"`
}

type DtreeSubdomainResponse struct {
	StatusCode int                    `json:"code"`
	Status     string                 `json:"status"`
	Data       []DtreeSubdomainRecord `json:"data,omitempty"`
	LastKey    string                 `json:"lastKey,omitempty"`
}

type DtreeSubdomainRecord struct {
	Domain   string `json:"domain"`
	TimeLast string `json:"lastSeen"`
	NoError  int8   `json:"noError"`
}

type ActiveRRsetRecord struct {
	RRName string `json:"rrname"`
	RRType string `json:"rrtype"`
	Rdata  string `json:"rdata,omitempty"`
}

type CNAME struct {
	Domain string  `json:"domain"`
	Cnames []CNAME `json:"cnames"`
}

type DnsChain struct {
	Name   string     `json:"name"`
	Chains []DnsChain `json:"chains"`
}
type NSType struct {
	Domain      string             `json:"domain"`
	NameServers []FlintRRsetRecord `json:"name_servers"`
}

type Results struct {
	Subdomain  string `json:"subdomain"`
	Vulnerable bool   `json:"vulnerable"`
	Type       string `json:"type"`
	Service    string `json:"service,omitempty"`
	Domain     string `json:"nonexist_domain,omitempty"`
}
