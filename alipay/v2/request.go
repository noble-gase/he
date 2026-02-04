package v2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/noble-gase/he/internal"
	"github.com/tidwall/gjson"
)

type Request struct {
	method  string
	options KV
	content X

	files []*resty.MultipartField
	form  KV

	client *Client
}

// SetSignRSA 使用「RSA」签名类型
func (r *Request) SetSignRSA() *Request {
	r.options.Set("sign_type", "RSA")
	return r
}

// SetSignRSA2 使用「RSA2」签名类型
func (r *Request) SetSignRSA2() *Request {
	r.options.Set("sign_type", "RSA2")
	return r
}

// SetEncrypt AES加密请求
func (r *Request) SetEncrypt() *Request {
	r.options.Set("encrypt_type", "AES")
	return r
}

// SetNotifyURL 设置异步回调通知URL
func (r *Request) SetNotifyURL(url string) *Request {
	r.options.Set("notify_url", url)
	return r
}

// SetReturnURL 设置支付成功跳转URL
func (r *Request) SetReturnURL(url string) *Request {
	r.options.Set("return_url", url)
	return r
}

// SetAppAuthToken 设置第三方应用授权Token
func (r *Request) SetAppAuthToken(token string) *Request {
	r.options.Set("app_auth_token", token)
	return r
}

// SetBizJSON 设置业务参数（biz_content）
func (r *Request) SetBizJSON(data X) *Request {
	r.content = data
	return r
}

// SetBizForm 设置业务参数，如：上传表单参数
func (r *Request) SetBizForm(form KV) *Request {
	r.form = form
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

func (r *Request) buildBizKV() (KV, error) {
	biz := KV{}

	for k, v := range r.form {
		biz.Set(k, v)
	}
	if len(r.content) == 0 {
		return biz, nil
	}

	b, err := json.Marshal(r.content)
	if err != nil {
		return nil, err
	}

	if r.options.Get("encrypt_type") == "AES" {
		cipher, err := r.client.encrypt(string(b))
		if err != nil {
			return nil, err
		}
		biz.Set("biz_content", cipher)
	} else {
		biz.Set("biz_content", string(b))
	}
	return biz, nil
}

// Post 发起网关请求
func (r *Request) Post(ctx context.Context) (gjson.Result, error) {
	biz, err := r.buildBizKV()
	if err != nil {
		return internal.FailE(err)
	}

	header := http.Header{}
	header.Set(internal.HeaderAccept, internal.ContentJSON)
	header.Set(internal.HeaderContentType, internal.ContentForm)

	return r.client.do(ctx, r.method, header, r.options, biz)
}

// Upload 文件上传
//
//	[参考](https://opendocs.alipay.com/apis/api_4/alipay.merchant.item.file.upload)
func (r *Request) Upload(ctx context.Context) (gjson.Result, error) {
	biz, err := r.buildBizKV()
	if err != nil {
		return internal.FailE(err)
	}

	header := http.Header{}
	header.Set(internal.HeaderAccept, internal.ContentJSON)

	return r.client.upload(ctx, r.method, header, r.options, r.files, biz)
}

// AppExecute 生成签名字符串（发送给商户 App 客户端）
//
//	[参考](https://opendocs.alipay.com/open/e65d4f60_alipay.trade.app.pay)
func (r *Request) AppExecute() (string, error) {
	biz, err := r.buildBizKV()
	if err != nil {
		return "", err
	}

	common, _, err := r.client.buildCommon(r.method, r.options, biz)
	if err != nil {
		return "", err
	}

	for k, v := range biz {
		common.Set(k, v)
	}
	return common.URLEncode(), nil
}

// PageExecute 生成页面 支付链接（GET）或 支付表单（POST）
//
//	[参考](https://opendocs.alipay.com/open/59da99d0_alipay.trade.page.pay)
func (r *Request) PageExecute(method string) (string, error) {
	biz, err := r.buildBizKV()
	if err != nil {
		return "", err
	}

	common, _, err := r.client.buildCommon(r.method, r.options, biz)
	if err != nil {
		return "", err
	}

	switch strings.ToUpper(method) {
	case "GET":
		for k, v := range biz {
			common.Set(k, v)
		}
		return r.client.gateway + "?" + common.URLEncode(), nil
	case "POST":
		var builder strings.Builder

		builder.WriteString(fmt.Sprintf(`<form name="punchout_form" method="post" action="%s?%s">`, r.client.gateway, common.URLEncode()))
		builder.WriteByte('\n')

		for k, v := range biz {
			builder.WriteString(fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, k, html.EscapeString(v)))
			builder.WriteByte('\n')
		}

		builder.WriteString(`<input type="submit" value="立即支付" style="display:none" >`)
		builder.WriteByte('\n')
		builder.WriteString(`</form>`)
		builder.WriteByte('\n')
		builder.WriteString(`<script>document.forms[0].submit();</script>`)

		return builder.String(), nil
	default:
		return "", errors.New("invalid http method")
	}
}
