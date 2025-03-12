package internal

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	HeaderAccept        = "Accept"
	HeaderAuthorization = "Authorization"
	HeaderContentType   = "Content-Type"
)

const (
	ContentText          = "text/plain; charset=utf-8"
	ContentJSON          = "application/json"
	ContentXML           = "application/xml"
	ContentForm          = "application/x-www-form-urlencoded"
	ContentStream        = "application/octet-stream"
	ContentMultipartForm = "multipart/form-data"
)

func NewClient() *resty.Client {
	return resty.NewWithClient(&http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 60 * time.Second,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:          0,
			MaxIdleConnsPerHost:   1000,
			MaxConnsPerHost:       1000,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	})
}
