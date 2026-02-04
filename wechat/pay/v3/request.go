package v3

import (
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/noble-gase/he/internal"
	"github.com/tidwall/gjson"
)

type File struct {
	name   string
	reader io.ReadSeeker
}

type Request struct {
	header      http.Header
	query       url.Values
	body        X
	encryptKeys []string
	file        File

	client *Client
}

// SetHeader 设置Header
func (r *Request) SetHeader(k string, vs ...string) *Request {
	for _, v := range vs {
		r.header.Add(k, v)
	}
	return r
}

// SetQuery 设置Query参数
func (r *Request) SetQuery(k string, vs ...string) *Request {
	for _, v := range vs {
		r.query.Add(k, v)
	}
	return r
}

// SetBody 设置JSON请求Body
func (r *Request) SetBody(body X, encryptKeys ...string) *Request {
	r.body = body
	r.encryptKeys = encryptKeys
	return r
}

// SetFile 设置上传文件
func (r *Request) SetFile(filename string, reader io.ReadSeeker) *Request {
	r.file.name = filename
	r.file.reader = reader
	return r
}

func (r *Request) Get(ctx context.Context, path string) (gjson.Result, error) {
	r.header.Set(internal.HeaderAccept, internal.ContentJSON)

	b, err := r.client.do(ctx, http.MethodGet, path, r.header, r.query, nil)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}

func (r *Request) Post(ctx context.Context, path string) (gjson.Result, error) {
	r.header.Set(internal.HeaderAccept, internal.ContentJSON)
	r.header.Set(internal.HeaderContentType, internal.ContentJSON)

	// 敏感信息加密
	if len(r.body) != 0 && len(r.encryptKeys) != 0 {
		sn, err := r.client.encrypt(ctx, r.body, r.encryptKeys...)
		if err != nil {
			return internal.FailE(err)
		}
		r.header.Set(HeaderSerial, sn)
	}

	b, err := r.client.do(ctx, http.MethodPost, path, r.header, r.query, r.body)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}

func (r *Request) Upload(ctx context.Context, path string) (gjson.Result, error) {
	r.header.Set(internal.HeaderAccept, internal.ContentJSON)

	b, err := r.client.upload(ctx, path, r.header, r.file.name, r.file.reader)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}
