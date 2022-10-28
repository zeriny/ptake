## Usage

```
Usage of /Users/evelyn/Documents/code/gopath/bin/go_build_main_go:
  -c string
        Path to conf.yaml. (default "./config/conf.yaml")
  -check-full
        Check full DNS chains no matter whether any cname is vulnerable.
  -check-status
        Check whether CNAMEs are available (expired).
  -data-path string
        Path to sld.txt (e.g., dataset/sld.txt).
  -dataset string
        Dataset name.
  -date string
        Date string of scanning. (default "20001212")
  -fresh
        Start a fresh scan. If the flag set, a new scan will be start, and the cache file of the last scan will be totally removed.
  -go-processes int
        Number of CPUs (GOMAXPROCS)
  -log string
        Path to a log file.
  -module string
        Selected modules (splitted by ',' e.g., 'subdomain,chain,check').
  -result-path string
        Output results (json object) to a .txt file (Default: ./results/<dataset>/).
  -retry int
        Retry the request if it's failed. (default 3)
  -service string
        Path to services.json file. (default "./config/services.json")
  -ssl
        Force HTTPS connections (May increase accuracy (Default: http://).
  -threads int
        Number of concurrent go threads. (default 100)
  -timeout int
        Seconds to wait before connection timeout. (default 2)
  -v    Display more information per each request.

```



#### Example

Get subdomain names of the given SLD list:

```shell
$ go run main.go --module="subdomain" -v --data-path="./data/alexa1k/sld.txt" --result-path="./results/alexa1k/" --threads=100 --retry=1 --timeout=100 -check-full -check-status
```

Get DNS resolution chains via passive DNS API:

```shell
$ go run main.go --module="chain" --result-path="./results/alexa1k/" -v --threads=100 --retry=1 -check-full -check-status
```

Check domain status:

```shell
$ go run main.go --module="check" --result-path="./results/alexa1k/" -v --threads=100 --retry=1 --timeout=3 -check-full -check-status
```



If there is no need for getting subdomain names (`subdomain` module), please put the FQDN list in a file named fqdn.txt (`./results/alexa1k/fqdn.txt`). 



## Configuration

config/conf.yaml

```yaml
sub_access: 10
cname_access: 200
cname_list_size: 10
recursive_depth: 5

pdns_subdomain_url: "https://api.secrank.cn/flint/rrset/*.%s?mode=6&start=%s&end=%s&limit=10000"
pdns_chain_url: "https://api.secrank.cn/flint/rrset/%s?start=%s&end=%s&rtype=-1&limit=1000"
pdns_reverse_cname_url: "https://api.secrank.cn/flint/rdata/%s?start=%s&end=%s&rtype=-1"
pdns_ns_url: "https://api.secrank.cn/flint/rrset/%s?start=20210101000000&end=%s&rtype=2&limit=10"
pdns_api_token: "replace with a real token"
```



## Compile
```
$ env GOOS=linux GOARCH=amd64 go build -o ./bin/ptake_amd64 main.go
```