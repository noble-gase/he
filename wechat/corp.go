package wechat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"

	"github.com/noble-gase/he/internal"
)

// Corp 企业微信(企业内部开发)
type Corp struct {
	host   string
	corpid string
	secret string
	srvCfg ServerConfig
	token  atomic.Value
	client *resty.Client
	logger func(ctx context.Context, err error, data map[string]string)
}

// AppID 返回AppID
func (c *Corp) CorpID() string {
	return c.corpid
}

// Secret 返回Secret
func (c *Corp) Secret() string {
	return c.secret
}

func (c *Corp) url(path string, query url.Values) string {
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

func (c *Corp) do(ctx context.Context, method, path string, header http.Header, query url.Values, params X) ([]byte, error) {
	reqURL := c.url(path, query)

	log := internal.NewReqLog(method, reqURL)
	defer log.Do(ctx, c.logger)

	var (
		body []byte
		err  error
	)

	if params != nil {
		body, err = json.Marshal(params)
		if err != nil {
			log.SetError(err)
			return nil, err
		}
		log.SetReqBody(string(body))
	}

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
	log.SetRespBody(string(resp.Body()))
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode())
	}
	return resp.Body(), nil
}

// OAuthURL 生成网页授权URL
//
//	[参考](https://developer.work.weixin.qq.com/document/path/91022)
func (c *Corp) OAuthURL(scope AuthScope, redirectURI, state, agentID string) string {
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
func (c *Corp) AccessToken(ctx context.Context) (gjson.Result, error) {
	query := url.Values{}

	query.Set("corpid", c.corpid)
	query.Set("corpsecret", c.secret)

	b, err := c.do(ctx, http.MethodGet, "/cgi-bin/gettoken", nil, query, nil)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// AutoLoadAccessToken 自动加载AccessToken
func (c *Corp) AutoLoadAccessToken(fn func(ctx context.Context, c *Corp) (string, error), interval time.Duration) error {
	ctx := context.Background()

	// 初始化AccessToken
	token, err := fn(ctx, c)
	if err != nil {
		return err
	}
	c.token.Store(token)

	// 异步定时加载
	go func(ctx context.Context) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			_token, _ := fn(ctx, c)
			if len(token) != 0 {
				c.token.Store(_token)
			}
		}
	}(ctx)

	return nil
}

func (c *Corp) getToken() (string, error) {
	v := c.token.Load()
	if v == nil {
		return "", errors.New("access_token is empty (forgotten auto load?)")
	}
	token, ok := v.(string)
	if !ok {
		return "", errors.New("access_token is not a string")
	}
	return token, nil
}

// GetJSON GET请求JSON数据
func (c *Corp) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	token, err := c.getToken()
	if err != nil {
		return internal.Fail(err)
	}
	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	b, err := c.do(ctx, http.MethodGet, path, nil, query, nil)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// PostJSON POST请求JSON数据
func (c *Corp) PostJSON(ctx context.Context, path string, params X) (gjson.Result, error) {
	token, err := c.getToken()
	if err != nil {
		return internal.Fail(err)
	}
	query := url.Values{}
	query.Set(AccessToken, token)

	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := c.do(ctx, http.MethodPost, path, header, query, params)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// GetBuffer GET请求获取buffer (如：获取媒体资源)
func (c *Corp) GetBuffer(ctx context.Context, path string, query url.Values) ([]byte, error) {
	token, err := c.getToken()
	if err != nil {
		return nil, err
	}
	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	b, err := c.do(ctx, http.MethodGet, path, nil, query, nil)
	if err != nil {
		return nil, err
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("%d | %s", code, ret.Get("errmsg").String())
	}
	return b, nil
}

// PostBuffer POST请求获取buffer (如：获取二维码)
func (c *Corp) PostBuffer(ctx context.Context, path string, params X) ([]byte, error) {
	token, err := c.getToken()
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set(AccessToken, token)

	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := c.do(ctx, http.MethodPost, path, header, query, params)
	if err != nil {
		return nil, err
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("%d | %s", code, ret.Get("errmsg").String())
	}
	return b, nil
}

// Upload 上传媒体资源
func (c *Corp) Upload(ctx context.Context, reqPath, fieldName, filePath string, formData Form, query url.Values) (gjson.Result, error) {
	token, err := c.getToken()
	if err != nil {
		return internal.Fail(err)
	}

	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	reqURL := c.url(reqPath, query)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	resp, err := c.client.R().
		SetContext(ctx).
		SetFile(fieldName, filePath).
		SetFormData(formData).
		Post(reqURL)
	if err != nil {
		log.SetError(err)
		return internal.Fail(err)
	}
	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(string(resp.Body()))
	if !resp.IsSuccess() {
		return internal.Fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode()))
	}

	ret := gjson.ParseBytes(resp.Body())
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// UploadWithReader 上传媒体资源
func (c *Corp) UploadWithReader(ctx context.Context, reqPath, fieldName, fileName string, reader io.Reader, formData Form, query url.Values) (gjson.Result, error) {
	token, err := c.getToken()
	if err != nil {
		return internal.Fail(err)
	}

	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	reqURL := c.url(reqPath, query)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	resp, err := c.client.R().
		SetContext(ctx).
		SetMultipartField(fieldName, fileName, "", reader).
		SetFormData(formData).
		Post(reqURL)
	if err != nil {
		log.SetError(err)
		return internal.Fail(err)
	}
	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(string(resp.Body()))
	if !resp.IsSuccess() {
		return internal.Fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode()))
	}

	ret := gjson.ParseBytes(resp.Body())
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
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
func (c *Corp) VerifyEventMsg(signature string, items ...string) error {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return errors.New("missing server config (forgotten configure?)")
	}
	if v := SignWithSHA1(c.srvCfg.token, items...); v != signature {
		return fmt.Errorf("signature verified fail, expect=%s, actual=%s", signature, v)
	}
	return nil
}

// DecodeEventMsg 事件消息解密
//
//	使用包体内的 Encrypt 字段
//	[参考](https://developer.work.weixin.qq.com/document/path/96211)
func (c *Corp) DecodeEventMsg(encrypt string) ([]byte, error) {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return EventDecrypt(c.corpid, c.srvCfg.aeskey, encrypt)
}

// EncodeEventReply 事件回复加密
//
//	[参考](https://developer.work.weixin.qq.com/document/path/96211)
func (c *Corp) EncodeEventReply(msg V) (V, error) {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return EventReply(c.corpid, c.srvCfg.token, c.srvCfg.aeskey, msg)
}

// CorpOption 企业微信设置项
type CorpOption func(c *Corp)

// WithCorpSrvCfg 设置企业微信服务器配置
//
//	[参考](https://developer.work.weixin.qq.com/document/path/90968)
func WithCorpSrvCfg(token, aeskey string) CorpOption {
	return func(c *Corp) {
		c.srvCfg.token = token
		c.srvCfg.aeskey = aeskey
	}
}

// WithCorpClient 设置企业微信请求的 HTTP Client
func WithCorpClient(cli *http.Client) CorpOption {
	return func(c *Corp) {
		c.client = resty.NewWithClient(cli)
	}
}

// WithCorpLogger 设置企业微信日志记录
func WithCorpLogger(fn func(ctx context.Context, err error, data map[string]string)) CorpOption {
	return func(c *Corp) {
		c.logger = fn
	}
}

// NewCorp 生成一个企业微信(企业内部开发)实例
func NewCorp(corpid, secret string, options ...CorpOption) *Corp {
	c := &Corp{
		host:   "https://qyapi.weixin.qq.com",
		corpid: corpid,
		secret: secret,
		client: internal.NewClient(),
	}
	for _, f := range options {
		f(c)
	}
	return c
}
