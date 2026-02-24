package v3

import (
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/noble-gase/he/internal"
	"github.com/tidwall/gjson"
)

type Request struct {
	path   string
	header http.Header
	query  url.Values
	body   internal.X
	files  []*resty.MultipartField

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

// SetFile 设置上传文件
func (r *Request) SetFile(param, filename string, reader io.Reader) *Request {
	r.files = append(r.files, &resty.MultipartField{
		Param:    param,
		FileName: filename,
		Reader:   reader,
	})
	return r
}

// SetBody 设置JSON请求Body 或 文件上传data
func (r *Request) SetBody(body internal.X) *Request {
	r.body = body
	return r
}

func (r *Request) Get(ctx context.Context) (gjson.Result, error) {
	r.header.Set(HeaderRequestID, uuid.NewString())
	r.header.Set(internal.HeaderAccept, internal.ContentJSON)

	b, err := r.client.do(ctx, http.MethodGet, r.path, r.header, r.query, nil)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}

func (r *Request) Post(ctx context.Context) (gjson.Result, error) {
	r.header.Set(HeaderRequestID, uuid.NewString())
	r.header.Set(internal.HeaderAccept, internal.ContentJSON)
	r.header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := r.client.do(ctx, http.MethodPost, r.path, r.header, r.query, r.body)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}

func (r *Request) PostEncrypt(ctx context.Context) (gjson.Result, error) {
	r.header.Set(HeaderEncryptType, "AES")
	r.header.Set(HeaderRequestID, uuid.NewString())
	r.header.Set(internal.HeaderContentType, internal.ContentText)

	b, err := r.client.docrypto(ctx, http.MethodPost, r.path, r.header, r.query, r.body)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}

func (r *Request) Upload(ctx context.Context) (gjson.Result, error) {
	r.header.Set(HeaderRequestID, uuid.NewString())

	b, err := r.client.upload(ctx, r.path, r.header, r.query, r.files, r.body)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}
