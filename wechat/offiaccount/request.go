package offiaccount

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/go-resty/resty/v2"
	"github.com/noble-gase/he/internal"
	"github.com/tidwall/gjson"
)

type Request struct {
	header http.Header
	query  url.Values
	body   X
	form   KV
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
func (r *Request) SetBody(body X) *Request {
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
	return result(b)
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
	return result(b)
}

// BufferGet 获取 buffer (如：获取媒体资源)
func (r *Request) BufferGet(ctx context.Context, path string) ([]byte, error) {
	if r.client.token == nil {
		return nil, errors.New("token loader is nil (forgotten set?)")
	}

	token, err := r.client.token(ctx)
	if err != nil {
		return nil, err
	}
	r.query.Set(AccessToken, token)

	b, err := r.client.do(ctx, http.MethodGet, path, r.header, r.query, nil)
	if err != nil {
		return nil, err
	}
	if _, err = result(b); err != nil {
		return nil, err
	}
	return b, nil
}

// BufferPost 获取 buffer (如：获取二维码)
func (r *Request) BufferPost(ctx context.Context, path string) ([]byte, error) {
	if r.client.token == nil {
		return nil, errors.New("token loader is nil (forgotten set?)")
	}

	token, err := r.client.token(ctx)
	if err != nil {
		return nil, err
	}
	r.query.Set(AccessToken, token)

	r.header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := r.client.do(ctx, http.MethodPost, path, r.header, r.query, r.body)
	if err != nil {
		return nil, err
	}
	if _, err = result(b); err != nil {
		return nil, err
	}
	return b, nil
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
	return result(b)
}
