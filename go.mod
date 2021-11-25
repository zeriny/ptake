module ptake

go 1.17

require (
	github.com/domainr/whois v0.0.0-20211025160740-e7d4e4b2d0ab // indirect
	github.com/haccer/available v0.0.0
	github.com/patrickmn/go-cache v0.0.0
	github.com/valyala/fasthttp v1.31.0
	gopkg.in/yaml.v2 v2.4.0 // indirect
	ptake/ptake_pkg v0.0.0
	ptake/modules v0.0.0
)

replace ptake/ptake_pkg => ./ptake_pkg

replace ptake/modules => ./modules

replace github.com/haccer/available => ../github.com/haccer/available

replace github.com/valyala/fasthttp => ../github.com/valyala/fasthttp

replace github.com/patrickmn/go-cache => ../github.com/patrickmn/go-cache
