package internal

import (
	"context"
	"net/http"
	"strconv"
	"strings"
)

// ReqLog 请求日志
type ReqLog struct {
	err  error
	data map[string]string
}

// Set 设置日志K-KV
func (l *ReqLog) Set(k, v string) {
	l.data[k] = v
}

func (l *ReqLog) SetError(err error) {
	l.err = err
}

// SetReqHeader 设置请求头
func (l *ReqLog) SetReqHeader(h http.Header) {
	if len(h) == 0 {
		return
	}
	l.data["req_header"] = HeaderEncode(h)
}

// SetBody 设置请求Body
func (l *ReqLog) SetReqBody(b []byte) {
	if b == nil {
		return
	}
	l.data["req_body"] = string(b)
}

// SetRespHeader 设置返回头
func (l *ReqLog) SetRespHeader(h http.Header) {
	l.data["resp_header"] = HeaderEncode(h)
}

// SetResp 设置返回报文
func (l *ReqLog) SetRespBody(b []byte) {
	l.data["resp_body"] = string(b)
}

// SetStatusCode 设置HTTP状态码
func (l *ReqLog) SetStatusCode(code int) {
	l.data["status_code"] = strconv.Itoa(code)
}

// Do 日志记录
func (l *ReqLog) Do(ctx context.Context, log func(ctx context.Context, err error, data map[string]string)) {
	if log == nil {
		return
	}
	log(ctx, l.err, l.data)
}

// NewReqLog 生成请求日志
func NewReqLog(method, reqURL string) *ReqLog {
	return &ReqLog{
		data: map[string]string{
			"method": method,
			"url":    reqURL,
		},
	}
}

func HeaderEncode(h http.Header) string {
	var buf strings.Builder
	for k, vals := range h {
		if buf.Len() > 0 {
			buf.WriteString(";")
		}
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(strings.Join(vals, ","))
	}
	return buf.String()
}
