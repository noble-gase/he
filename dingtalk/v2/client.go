package v2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/noble-gase/he/dingtalk/event"
	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/kvkit"
	"github.com/tidwall/gjson"
)

// ServerConfig 服务器配置
type ServerConfig struct {
	token  string
	aeskey string
}

// Client 钉钉新版API客户端
type Client struct {
	host   string
	appkey string
	secret string
	srvCfg ServerConfig

	client *resty.Client

	token  func(ctx context.Context) (string, error)
	logger func(ctx context.Context, err error, data map[string]string)
}

// AppKey 返回 Client ID
func (c *Client) ClientID() string {
	return c.appkey
}

// Secret 返回 Client Secret
func (c *Client) Secret() string {
	return c.secret
}

// SetServerConfig 设置服务器配置
//
//	[参考](https://open.dingtalk.com/document/development/event-subscription-overview)
func (c *Client) SetServerConfig(token, aeskey string) {
	c.srvCfg.token = token
	c.srvCfg.aeskey = aeskey
}

func (c *Client) SetHttpClient(cli *http.Client) {
	c.client = resty.NewWithClient(cli)
}

// SetTokenLoader 设置AccessToken加载器
func (c *Client) SetTokenLoader(fn func(ctx context.Context) (string, error)) {
	c.token = fn
}

func (c *Client) SetLogger(fn func(ctx context.Context, err error, data map[string]string)) {
	c.logger = fn
}

func (c *Client) R() *Request {
	return &Request{
		header: make(http.Header),
		query:  make(url.Values),
		form:   make(kvkit.KV),

		client: c,
	}
}

func (c *Client) url(path string, query url.Values) string {
	var builder strings.Builder

	builder.WriteString(c.host)
	if len(path) != 0 && path[0] != '/' {
		builder.WriteString("/")
	}
	builder.WriteString(path)
	if len(query) != 0 {
		builder.WriteString("?")
		builder.WriteString(query.Encode())
	}
	return builder.String()
}

func (c *Client) do(ctx context.Context, method, path string, header http.Header, query url.Values, params internal.X) ([]byte, error) {
	var (
		body []byte
		err  error
	)

	if params != nil {
		body, err = json.Marshal(params)
		if err != nil {
			return nil, err
		}
	}

	reqURL := c.url(path, query)

	log := internal.NewReqLog(method, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqHeader(header)
	log.SetReqBody(body)

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		SetBody(body).
		Execute(method, reqURL)
	if err != nil {
		log.SetError(err)
		return nil, err
	}

	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(resp.Body())

	if !resp.IsSuccess() {
		return nil, exception(resp)
	}
	return resp.Body(), nil
}

func (c *Client) upload(ctx context.Context, path string, header http.Header, query url.Values, files []*resty.MultipartField, form kvkit.KV) ([]byte, error) {
	reqURL := c.url(path, query)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqHeader(header)
	log.Set("form_data", form.Encode("=", "&"))

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		SetMultipartFields(files...).
		SetMultipartFormData(form).
		Post(reqURL)
	if err != nil {
		log.SetError(err)
		return nil, err
	}

	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(resp.Body())

	if !resp.IsSuccess() {
		return nil, errors.New(resp.Status())
	}
	return resp.Body(), nil
}

// AccessToken 获取接口调用凭据
func (c *Client) AccessToken(ctx context.Context) (gjson.Result, error) {
	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentJSON)

	body := internal.X{
		"appKey":    c.appkey,
		"appSecret": c.secret,
	}

	b, err := c.do(ctx, http.MethodPost, "/v1.0/oauth2/accessToken", header, nil, body)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}

// VerifyEventMsg 验证事件消息
//
//	[服务器URL验证]
//	URL参数中的 signature、timestamp、nonce 和 包体内的 encrypt 字段
//	注意：验证成功后，返回 success 加密字符串
//
//	[事件消息验证]
//	URL参数中的 msg_signature、timestamp、nonce 和 包体内的 encrypt 字段
//
//	[参考](https://open.dingtalk.com/document/development/http-callback-overview)
func (c *Client) VerifyEventMsg(signature string, items ...string) error {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return errors.New("missing server config (forgotten configure?)")
	}
	if v := event.SignWithSHA1(c.srvCfg.token, items...); v != signature {
		return fmt.Errorf("signature verified fail, expect=%s, actual=%s", signature, v)
	}
	return nil
}

// DecodeEventMsg 事件消息解密
//
//	使用包体内的 encrypt 字段
//	[参考](https://open.dingtalk.com/document/development/http-callback-overview)
func (c *Client) DecodeEventMsg(encrypt string) ([]byte, error) {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return event.Decrypt(c.appkey, c.srvCfg.aeskey, encrypt)
}

// EncodeEventReply 事件回复加密
//
//	[参考](https://open.dingtalk.com/document/development/http-callback-overview)
func (c *Client) EncodeEventReply(msg string) (kvkit.KV, error) {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return event.Reply(c.appkey, c.srvCfg.token, c.srvCfg.aeskey, msg)
}

// NewClient 钉钉新版API客户端
func NewClient(clientId, secret string) *Client {
	return &Client{
		client: internal.NewClient(),
		host:   "https://api.dingtalk.com",
		appkey: clientId,
		secret: secret,
	}
}
