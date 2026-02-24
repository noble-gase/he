package wecom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/wechat/event"
)

// ServerConfig 服务器配置
type ServerConfig struct {
	token  string
	aeskey string
}

// Client 企业微信(内部应用开发)
type Client struct {
	host   string
	corpid string
	secret string
	srvCfg ServerConfig

	client *resty.Client

	token  func(ctx context.Context) (string, error)
	logger func(ctx context.Context, err error, data map[string]string)
}

// AppID 返回AppID
func (c *Client) CorpID() string {
	return c.corpid
}

// Secret 返回Secret
func (c *Client) Secret() string {
	return c.secret
}

// SetServerConfig 设置服务器配置
//
//	[参考](https://developer.work.weixin.qq.com/document/path/90968)
func (c *Client) SetServerConfig(token, aeskey string) {
	c.srvCfg.token = token
	c.srvCfg.aeskey = aeskey
}

func (c *Client) SetHttpClient(cli *http.Client) {
	c.client = resty.NewWithClient(cli)
}

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
		form:   make(KV),

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

func (c *Client) do(ctx context.Context, method, path string, header http.Header, query url.Values, params X) ([]byte, error) {
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
		return nil, errors.New(resp.Status())
	}
	return resp.Body(), nil
}

func (c *Client) upload(ctx context.Context, path string, header http.Header, query url.Values, files []*resty.MultipartField, form KV) ([]byte, error) {
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

// OAuthURL 生成网页授权URL
//
//	[参考](https://developer.work.weixin.qq.com/document/path/91022)
func (c *Client) OAuthURL(scope AuthScope, redirectURI, state, agentID string) string {
	query := url.Values{}

	query.Set("appid", c.corpid)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", string(scope))
	query.Set("state", state)
	query.Set("agentid", agentID)

	return fmt.Sprintf("https://open.weixin.qq.com/connect/cuth2/authorize?%s#wechat_redirect", query.Encode())
}

// AccessToken 获取接口调用凭据
func (c *Client) AccessToken(ctx context.Context) (gjson.Result, error) {
	query := url.Values{}

	query.Set("corpid", c.corpid)
	query.Set("corpsecret", c.secret)

	b, err := c.do(ctx, http.MethodGet, "/cgi-bin/gettoken", nil, query, nil)
	if err != nil {
		return internal.FailE(err)
	}
	return result(b)
}

// VerifyEventMsg 验证事件消息
//
//	[服务器URL验证]
//	URL参数中的 msg_signature、timestamp、nonce、echostr
//	注意：验证成功后，需将 echostr 解密，然后返回 msg 字段值
//
//	[事件消息验证]
//	URL参数中的 msg_signature、timestamp、nonce 和包体内的 Encrypt 字段
//
//	[参考](https://developer.work.weixin.qq.com/document/path/90930)
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
//	使用包体内的 Encrypt 字段
//	[参考](https://developer.work.weixin.qq.com/document/path/96211)
func (c *Client) DecodeEventMsg(encrypt string) ([]byte, error) {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return event.Decrypt(c.corpid, c.srvCfg.aeskey, encrypt)
}

// EncodeEventReply 事件回复加密
//
//	[参考](https://developer.work.weixin.qq.com/document/path/96211)
func (c *Client) EncodeEventReply(msg string) (KV, error) {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return event.Reply(c.corpid, c.srvCfg.token, c.srvCfg.aeskey, msg)
}

// NewClient 生成一个企业微信（内部应用开发）实例
func NewClient(corpid, secret string) *Client {
	return &Client{
		host:   "https://qyapi.weixin.qq.com",
		corpid: corpid,
		secret: secret,
		client: internal.NewClient(),
	}
}
