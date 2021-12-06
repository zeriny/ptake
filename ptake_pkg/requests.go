package ptake_pkg

import (
	"crypto/tls"
	"github.com/valyala/fasthttp"
	"time"
)

func get(domain string, timeout int, forceSSL bool) (header string, body []byte) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	url := "http://" + domain
	if forceSSL {
		url = "https://" + domain
	}

	req.SetRequestURI(url)
	req.Header.Add("Connection", "close")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36")
	req.Header.SetMethod("GET")

	resp := fasthttp.AcquireResponse()
	//defer fasthttp.ReleaseResponse(resp)

	client := &fasthttp.Client{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		NoDefaultUserAgentHeader:true, // Don't send: User-Agent: fasthttp
	}
	client.DoRedirects(req, resp, 5) // Follow 3xx redirects.
	client.DoTimeout(req, resp, time.Duration(timeout)*time.Second)
	h := resp.Header.String()
	b := resp.Body()

	return h, b
}
