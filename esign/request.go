package esign

import (
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/noble-gase/he/internal"
	"github.com/tidwall/gjson"
)

type Request struct {
	header http.Header
	query  url.Values
	body   internal.X
	stream io.ReadSeeker

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

// SetStream 设置文件上传流
func (r *Request) SetStream(reader io.ReadSeeker) *Request {
	r.stream = reader
	return r
}

// SetBody 设置请求Body 或 文件上传data
func (r *Request) SetBody(body internal.X) *Request {
	r.body = body
	return r
}

func (r *Request) Get(ctx context.Context, path string) (gjson.Result, error) {
	r.header.Set(internal.HeaderAccept, AcceptAll)

	b, err := r.client.do(ctx, http.MethodGet, path, r.header, r.query, nil)
	if err != nil {
		return internal.FailE(err)
	}
	return Result(b)
}

func (r *Request) Post(ctx context.Context, path string) (gjson.Result, error) {
	r.header.Set(internal.HeaderAccept, AcceptAll)

	b, err := r.client.do(ctx, http.MethodPost, path, r.header, r.query, r.body)
	if err != nil {
		return internal.FailE(err)
	}
	return Result(b)
}

func (r *Request) Upload(ctx context.Context, url string) error {
	r.header.Set(internal.HeaderContentType, internal.ContentStream)

	b, err := r.client.stream(ctx, url, r.header, r.stream)
	if err != nil {
		return err
	}
	return ErrFromStream(b)
}
