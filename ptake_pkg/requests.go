package ptake_pkg

import (
	"crypto/tls"
	"github.com/valyala/fasthttp"
	"time"
)

func get(url string, timeout int, addHeaders map[string]string) (body []byte) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(url)
	req.Header.Add("Connection", "close")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36")
	for header := range addHeaders {
		req.Header.Add(header, addHeaders[header])
	}
	req.Header.SetMethod("GET")

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	client := &fasthttp.Client{TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	client.DoTimeout(req, resp, time.Duration(timeout)*time.Second)
	b := resp.Body()
	return b
}
