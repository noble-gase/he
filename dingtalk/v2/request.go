package v2

import (
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/go-resty/resty/v2"
	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/kvkit"
	"github.com/tidwall/gjson"
)

type Request struct {
	header http.Header
	query  url.Values
	body   internal.X
	form   kvkit.KV
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

// SetBody 设置JSON请求Body
func (r *Request) SetBody(body internal.X) *Request {
	r.body = body
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

// SetForm 设置上传表单数据
func (r *Request) SetForm(k, v string) *Request {
	r.form.Set(k, v)
	return r
}

func (r *Request) Get(ctx context.Context, path string) (gjson.Result, error) {
	if r.client.token == nil {
		return internal.Fail("token loader is nil (forgotten set?)")
	}

	token, err := r.client.token(ctx)
	if err != nil {
		return internal.FailE(err)
	}
	r.query.Set(AccessToken, token)

	b, err := r.client.do(ctx, http.MethodGet, path, r.header, r.query, nil)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}

func (r *Request) Post(ctx context.Context, path string) (gjson.Result, error) {
	if r.client.token == nil {
		return internal.Fail("token loader is nil (forgotten set?)")
	}

	token, err := r.client.token(ctx)
	if err != nil {
		return internal.FailE(err)
	}
	r.query.Set(AccessToken, token)

	r.header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := r.client.do(ctx, http.MethodPost, path, r.header, r.query, r.body)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}

func (r *Request) Upload(ctx context.Context, path string) (gjson.Result, error) {
	if r.client.token == nil {
		return internal.Fail("token loader is nil (forgotten set?)")
	}

	token, err := r.client.token(ctx)
	if err != nil {
		return internal.FailE(err)
	}
	r.query.Set(AccessToken, token)

	b, err := r.client.upload(ctx, path, r.header, r.query, r.files, r.form)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}
