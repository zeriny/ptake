## Usage

```
Usage:
  -c string
        Path to conf.yaml. (default "./config/conf.yaml")
  -check-full
        Check full DNS chains no matter whether any cname is vulnerable.
  -check-status
        Check whether CNAMEs are available (can be registered).
  -dataset string
        Dataset name.
  -date string
        Date string of scanning. (default "20001212")
  -fqdn-file string
        Path to Subdomain (fqdn) file.
  -fresh
        Start a fresh scan. If the flag set, a new scan will be start, and the cache file of the last scan will be totally removed.
  -go-processes int
        Number of CPUs (GOMAXPROCS)
  -log string
        Path to a log file.
  -module string
        Selected modules (splitted by ,).
  -output-dir string
        Directory to save results (Default: ./results/<dataset>/).
  -retry int
        Retry the request if it's failed. (default 3)
  -service string
        Path to services.json file. (default "./config/services.json")
  -sld-file string
        Path to SLD file.
  -ssl
        Force HTTPS connections (May increase accuracy (Default: http://).
  -threads int
        Number of concurrent go threads. (default 100)
  -timeout int
        Seconds to wait before connection timeout. (default 2)
  -v    Display more information per each request.

```


## Configuration

config/conf.yaml

```yaml
sub_access: 1
cname_access: 200
cname_list_size: 10
recursive_depth: 5

sub_duration: 3
chain_duration: 3

max_fetch_count: 50 
pdns_subdomain_url: "https://api.secrank.cn/dtree/%s"
pdns_chain_url: "https://api.secrank.cn/flint/rrset/%s?start=%s&end=%s&rtype=-1&limit=10"
pdns_reverse_cname_url: "https://api.secrank.cn/flint/rdata/%s?start=%s&end=%s&rtype=-1"
pdns_ns_url: "https://api.secrank.cn/flint/rrset/%s?start=20210101000000&end=%s&rtype=2&limit=10"
pdns_api_token: "1bf55ed07a5c8ae****************"
```



## Compile
```
$ env GOOS=linux GOARCH=amd64 go build -o ./bin/ptake_amd64 main.go
$ env GOOS=linux GOARCH=arm64 go build -o ./bin/ptake_arm64 main.go
```

#### Example

Get subdomain names of the given SLD list:

```shell
$ ./bin/ptake_amd64 --module="subdomain" -v --sld-file="./data/alexa1k/sld.txt" --output-dir="./results/alexa1k/" --threads=100 --retry=1 --timeout=100 -check-full -check-status
```

Get DNS resolution chains via passive DNS API:

```shell
$ ./bin/ptake_amd64 --module="chain" --fqdn-file="./results/alexa1k/fqdn.txt" --output-dir="./results/alexa1k/" -v --threads=100 --retry=1 -check-full -check-status
```

Check domain status:

```shell
$ ./bin/ptake_amd64 --module="check" --output-dir="./results/alexa1k/" -v --threads=100 --retry=1 --timeout=3 -check-full -check-status
```



If there is no need for getting subdomain names (`subdomain` module), please put the FQDN list in a file named fqdn.txt (`./results/alexa1k/fqdn.txt`). 

