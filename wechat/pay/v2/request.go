package v2

import (
	"context"
)

type Request struct {
	params XML
	client *Client
}

func (r *Request) SetXML(v XML) *Request {
	r.params = v
	return r
}

// Post 无证书请求
func (r *Request) Post(ctx context.Context, path string) (XML, error) {
	b, err := r.client.do(ctx, path, r.params)
	if err != nil {
		return nil, err
	}

	ret, err := result(b)
	if err != nil {
		return nil, err
	}
	if err = r.client.Verify(ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// TlsPost 带证书请求，如：申请退款
func (r *Request) TlsPost(ctx context.Context, path string) (XML, error) {
	b, err := r.client.doTls(ctx, path, r.params)
	if err != nil {
		return nil, err
	}

	ret, err := result(b)
	if err != nil {
		return nil, err
	}
	if err = r.client.Verify(ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// Buffer 无证书请求，如：下载交易订单
func (r *Request) Buffer(ctx context.Context, path string) ([]byte, error) {
	b, err := r.client.do(ctx, path, r.params)
	if err != nil {
		return nil, err
	}

	ret, err := XMLToKV(b)
	// 能解析出XML，说明发生错误
	if err == nil && len(ret) != 0 {
		return nil, errFromXML(ret)
	}
	return b, nil
}

// TlsBuffer 带证书请求，如：下载资金账单
func (r *Request) TlsBuffer(ctx context.Context, path string) ([]byte, error) {
	b, err := r.client.doTls(ctx, path, r.params)
	if err != nil {
		return nil, err
	}

	ret, err := XMLToKV(b)
	// 能解析出XML，说明发生错误
	if err == nil && len(ret) != 0 {
		return nil, errFromXML(ret)
	}
	return b, nil
}
