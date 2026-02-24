package offiaccount

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

// Client 微信公众号
type Client struct {
	host   string
	appid  string
	secret string
	srvCfg ServerConfig

	client *resty.Client

	token  func(ctx context.Context) (string, error)
	logger func(ctx context.Context, err error, data map[string]string)
}

// AppID returns appid
func (c *Client) AppID() string {
	return c.appid
}

// Secret returns app secret
func (c *Client) Secret() string {
	return c.secret
}

// SetServerConfig 设置服务器配置
//
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/Access_Overview.html)
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
		form:   make(KV),

		client: c,
	}
}

// URL 生成请求URL
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

// OAuth2URL 生成网页授权URL
//
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html)
func (c *Client) OAuth2URL(scope AuthScope, redirectURI, state string) string {
	query := url.Values{}

	query.Set("appid", c.appid)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", string(scope))
	query.Set("state", state)

	return fmt.Sprintf("https://open.weixin.qq.com/connect/oauth2/authorize?%s#wechat_redirect", query.Encode())
}

// SubscribeMsgAuthURL 公众号一次性订阅消息授权URL
//
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/One-time_subscription_info.html)
func (c *Client) SubscribeMsgAuthURL(scene, templateID, redirectURL, reserved string) string {
	query := url.Values{}

	query.Set("appid", c.appid)
	query.Set("action", "get_confirm")
	query.Set("scene", scene)
	query.Set("template_id", templateID)
	query.Set("redirect_url", redirectURL)
	query.Set("reserved", reserved)

	return fmt.Sprintf("https://c.weixin.qq.com/c/subscribemsg?%s#wechat_redirect", query.Encode())
}

// Code2OAuthToken 获取网页授权Token
func (c *Client) Code2OAuthToken(ctx context.Context, code string) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", c.appid)
	query.Set("secret", c.secret)
	query.Set("code", code)
	query.Set("grant_type", "authorization_code")

	b, err := c.do(ctx, http.MethodGet, "/sns/oauth2/access_token", nil, query, nil)
	if err != nil {
		return internal.FailE(err)
	}
	return result(b)
}

// RefreshOAuthToken 刷新网页授权Token
func (c *Client) RefreshOAuthToken(ctx context.Context, refreshToken string) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", c.appid)
	query.Set("grant_type", "refresh_token")
	query.Set("refresh_token", refreshToken)

	b, err := c.do(ctx, http.MethodGet, "/sns/oauth2/refresh_token", nil, query, nil)
	if err != nil {
		return internal.FailE(err)
	}
	return result(b)
}

// AccessToken 获取接口调用凭据
func (c *Client) AccessToken(ctx context.Context) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", c.appid)
	query.Set("secret", c.secret)
	query.Set("grant_type", "client_credential")

	b, err := c.do(ctx, http.MethodGet, "/cgi-bin/token", nil, query, nil)
	if err != nil {
		return internal.FailE(err)
	}
	return result(b)
}

// StableAccessToken 获取稳定版接口调用凭据
//
//	有两种调用模式:
//	[普通模式] access_token 有效期内重复调用该接口不会更新 access_token，绝大部分场景下使用该模式；
//	[强制刷新模式] 会导致上次获取的 access_token 失效，并返回新的 access_token
func (c *Client) StableAccessToken(ctx context.Context, forceRefresh bool) (gjson.Result, error) {
	params := X{
		"grant_type":    "client_credential",
		"appid":         c.appid,
		"secret":        c.secret,
		"force_refresh": forceRefresh,
	}

	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := c.do(ctx, http.MethodPost, "/cgi-bin/stable_token", header, nil, params)
	if err != nil {
		return internal.FailE(err)
	}
	return result(b)
}

// VerifyEventMsg 验证事件消息
//
//	[服务器URL验证]
//	   URL参数中的 signature、timestamp、nonce
//	   注意：验证成功后，原样返回 echostr 字段值
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/Access_Overview.html)
//
//	[事件消息验证]
//	[明文模式] URL参数中的 signature、timestamp、nonce
//	[安全模式] URL参数中的 msg_signature、timestamp、nonce 和 包体内的 Encrypt 字段
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Message_encryption_and_decryption_instructions.html)
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
//	根据配置的数据格式，解析 XML/JSON
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Message_encryption_and_decryption_instructions.html)
func (c *Client) DecodeEventMsg(encrypt string) ([]byte, error) {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return event.Decrypt(c.appid, c.srvCfg.aeskey, encrypt)
}

// EncodeEventReply 事件回复加密
//
//	根据配置的数据格式，输出 XML/JSON
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Message_encryption_and_decryption_instructions.html)
func (c *Client) EncodeEventReply(msg string) (KV, error) {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return event.Reply(c.appid, c.srvCfg.token, c.srvCfg.aeskey, msg)
}

// NewClient生成一个公众号实例
func NewClient(appid, secret string) *Client {
	return &Client{
		host:   "https://api.weixin.qq.com",
		appid:  appid,
		secret: secret,
		client: internal.NewClient(),
	}
}
