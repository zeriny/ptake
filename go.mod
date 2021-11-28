module ptake

go 1.17

require (
	github.com/domainr/whois v0.0.0-20211025160740-e7d4e4b2d0ab // indirect
	github.com/sirupsen/logrus v1.8.1
	gopkg.in/yaml.v2 v2.4.0
	ptake/ptake_pkg v0.0.0
)

require (
	github.com/PuerkitoBio/goquery v1.7.1 // indirect
	github.com/andybalholm/brotli v1.0.2 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/haccer/available v0.0.0 // indirect
	github.com/klauspost/compress v1.13.4 // indirect
	github.com/miekg/dns v1.1.43 // indirect
	github.com/patrickmn/go-cache v0.0.0 // indirect
	github.com/saintfish/chardet v0.0.0-20120816061221-3af4cd4741ca // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.31.0 // indirect
	github.com/zonedb/zonedb v1.0.3419 // indirect
	golang.org/x/net v0.0.0-20210916014120-12bc252f5db8 // indirect
	golang.org/x/sys v0.0.0-20210514084401-e8d321eab015 // indirect
	golang.org/x/text v0.3.7 // indirect
)

replace ptake/ptake_pkg => ./ptake_pkg

replace ptake/modules => ./modules

replace github.com/haccer/available => ../github.com/haccer/available

replace github.com/valyala/fasthttp => ../github.com/valyala/fasthttp

replace github.com/patrickmn/go-cache => ../github.com/patrickmn/go-cache
