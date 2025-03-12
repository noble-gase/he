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

// OfficialAccount 微信公众号
type OfficialAccount struct {
	host   string
	appid  string
	secret string
	srvCfg ServerConfig
	token  atomic.Value
	client *resty.Client
	logger func(ctx context.Context, err error, data map[string]string)
}

// AppID returns appid
func (oa *OfficialAccount) AppID() string {
	return oa.appid
}

// Secret returns app secret
func (oa *OfficialAccount) Secret() string {
	return oa.secret
}

// URL 生成请求URL
func (oa *OfficialAccount) url(path string, query url.Values) string {
	var builder strings.Builder

	builder.WriteString(oa.host)
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

func (oa *OfficialAccount) do(ctx context.Context, method, path string, header http.Header, query url.Values, params X) ([]byte, error) {
	reqURL := oa.url(path, query)

	log := internal.NewReqLog(method, reqURL)
	defer log.Do(ctx, oa.logger)

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

	resp, err := oa.client.R().
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

// OAuth2URL 生成网页授权URL
//
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html)
func (oa *OfficialAccount) OAuth2URL(scope AuthScope, redirectURI, state string) string {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", string(scope))
	query.Set("state", state)

	return fmt.Sprintf("https://open.weixin.qq.com/connect/oauth2/authorize?%s#wechat_redirect", query.Encode())
}

// SubscribeMsgAuthURL 公众号一次性订阅消息授权URL
//
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/One-time_subscription_info.html)
func (oa *OfficialAccount) SubscribeMsgAuthURL(scene, templateID, redirectURL, reserved string) string {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("action", "get_confirm")
	query.Set("template_id", templateID)
	query.Set("redirect_url", redirectURL)
	query.Set("reserved", reserved)

	return fmt.Sprintf("https://oa.weixin.qq.com/oa/subscribemsg?%s#wechat_redirect", query.Encode())
}

// Code2OAuthToken 获取网页授权Token
func (oa *OfficialAccount) Code2OAuthToken(ctx context.Context, code string) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("secret", oa.secret)
	query.Set("code", code)
	query.Set("grant_type", "authorization_code")

	b, err := oa.do(ctx, http.MethodGet, "/sns/oauth2/access_token", nil, query, nil)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// RefreshOAuthToken 刷新网页授权Token
func (oa *OfficialAccount) RefreshOAuthToken(ctx context.Context, refreshToken string) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("grant_type", "refresh_token")
	query.Set("refresh_token", refreshToken)

	b, err := oa.do(ctx, http.MethodGet, "/sns/oauth2/refresh_token", nil, query, nil)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// AccessToken 获取接口调用凭据
func (oa *OfficialAccount) AccessToken(ctx context.Context) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("secret", oa.secret)
	query.Set("grant_type", "client_credential")

	b, err := oa.do(ctx, http.MethodGet, "/cgi-bin/token", nil, query, nil)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// StableAccessToken 获取稳定版接口调用凭据
//
//	有两种调用模式:
//	[普通模式] access_token 有效期内重复调用该接口不会更新 access_token，绝大部分场景下使用该模式；
//	[强制刷新模式] 会导致上次获取的 access_token 失效，并返回新的 access_token
func (oa *OfficialAccount) StableAccessToken(ctx context.Context, forceRefresh bool) (gjson.Result, error) {
	params := X{
		"grant_type":    "client_credential",
		"appid":         oa.appid,
		"secret":        oa.secret,
		"force_refresh": forceRefresh,
	}

	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := oa.do(ctx, http.MethodPost, "/cgi-bin/stable_token", header, nil, params)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// AutoLoadAccessToken 自动加载AccessToken(使用StableAccessToken接口)
func (oa *OfficialAccount) AutoLoadAccessToken(interval time.Duration) error {
	ctx := context.Background()

	// 初始化AccessToken
	ret, err := oa.StableAccessToken(ctx, false)
	if err != nil {
		return err
	}
	oa.token.Store(ret.Get("access_token").String())

	// 异步定时加载
	go func(ctx context.Context) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			_ret, _ := oa.StableAccessToken(ctx, false)
			if token := _ret.Get("access_token").String(); len(token) != 0 {
				oa.token.Store(token)
			}
		}
	}(ctx)

	return nil
}

// CustomAccessTokenLoad 自定义加载AccessToken
func (oa *OfficialAccount) CustomAccessTokenLoad(fn func(ctx context.Context, oa *OfficialAccount) (string, error), interval time.Duration) error {
	ctx := context.Background()

	// 初始化AccessToken
	token, err := fn(ctx, oa)
	if err != nil {
		return err
	}
	oa.token.Store(token)

	// 异步定时加载
	go func(ctx context.Context) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			_token, _ := fn(ctx, oa)
			if len(token) != 0 {
				oa.token.Store(_token)
			}
		}
	}(ctx)

	return nil
}

func (oa *OfficialAccount) getToken() (string, error) {
	v := oa.token.Load()
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
func (oa *OfficialAccount) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	token, err := oa.getToken()
	if err != nil {
		return internal.Fail(err)
	}
	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	b, err := oa.do(ctx, http.MethodGet, path, nil, query, nil)
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
func (oa *OfficialAccount) PostJSON(ctx context.Context, path string, params X) (gjson.Result, error) {
	token, err := oa.getToken()
	if err != nil {
		return internal.Fail(err)
	}
	query := url.Values{}
	query.Set(AccessToken, token)

	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := oa.do(ctx, http.MethodPost, path, header, query, params)
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
func (oa *OfficialAccount) GetBuffer(ctx context.Context, path string, query url.Values) ([]byte, error) {
	token, err := oa.getToken()
	if err != nil {
		return nil, err
	}
	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	b, err := oa.do(ctx, http.MethodGet, path, nil, query, nil)
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
func (oa *OfficialAccount) PostBuffer(ctx context.Context, path string, params X) ([]byte, error) {
	token, err := oa.getToken()
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set(AccessToken, token)

	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := oa.do(ctx, http.MethodPost, path, header, query, params)
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
func (oa *OfficialAccount) Upload(ctx context.Context, reqPath, fieldName, filePath string, formData Form, query url.Values) (gjson.Result, error) {
	token, err := oa.getToken()
	if err != nil {
		return internal.Fail(err)
	}

	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	reqURL := oa.url(reqPath, query)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.R().
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
func (oa *OfficialAccount) UploadWithReader(ctx context.Context, reqPath, fieldName, fileName string, reader io.Reader, formData Form, query url.Values) (gjson.Result, error) {
	token, err := oa.getToken()
	if err != nil {
		return internal.Fail(err)
	}

	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	reqURL := oa.url(reqPath, query)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.R().
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
//	   URL参数中的 signature、timestamp、nonce
//	   注意：验证成功后，原样返回 echostr 字段值
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/Access_Overview.html)
//
//	[事件消息验证]
//	[明文模式] URL参数中的 signature、timestamp、nonce
//	[安全模式] URL参数中的 msg_signature、timestamp、nonce 和 包体内的 Encrypt 字段
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Message_encryption_and_decryption_instructions.html)
func (oa *OfficialAccount) VerifyEventMsg(signature string, items ...string) error {
	if len(oa.srvCfg.token) == 0 || len(oa.srvCfg.aeskey) == 0 {
		return errors.New("missing server config (forgotten configure?)")
	}
	if v := SignWithSHA1(oa.srvCfg.token, items...); v != signature {
		return fmt.Errorf("signature verified fail, expect=%s, actual=%s", signature, v)
	}
	return nil
}

// DecodeEventMsg 事件消息解密
//
//	使用包体内的 Encrypt 字段
//	根据配置的数据格式，解析 XML/JSON
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Message_encryption_and_decryption_instructions.html)
func (oa *OfficialAccount) DecodeEventMsg(encrypt string) ([]byte, error) {
	if len(oa.srvCfg.token) == 0 || len(oa.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return EventDecrypt(oa.appid, oa.srvCfg.aeskey, encrypt)
}

// EncodeEventReply 事件回复加密
//
//	根据配置的数据格式，输出 XML/JSON
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Message_encryption_and_decryption_instructions.html)
func (oa *OfficialAccount) EncodeEventReply(msg V) (V, error) {
	if len(oa.srvCfg.token) == 0 || len(oa.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return EventReply(oa.appid, oa.srvCfg.token, oa.srvCfg.aeskey, msg)
}

// OAOption 公众号设置项
type OAOption func(oa *OfficialAccount)

// WithOASrvCfg 设置公众号服务器配置
//
//	[参考](https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/Access_Overview.html)
func WithOASrvCfg(token, aeskey string) OAOption {
	return func(oa *OfficialAccount) {
		oa.srvCfg.token = token
		oa.srvCfg.aeskey = aeskey
	}
}

// WithOAClient 设置公众号请求的 HTTP Client
func WithOAClient(cli *http.Client) OAOption {
	return func(oa *OfficialAccount) {
		oa.client = resty.NewWithClient(cli)
	}
}

// WithOALogger 设置公众号日志记录
func WithOALogger(fn func(ctx context.Context, err error, data map[string]string)) OAOption {
	return func(oa *OfficialAccount) {
		oa.logger = fn
	}
}

// NewOfficialAccount 生成一个公众号实例
func NewOfficialAccount(appid, secret string, options ...OAOption) *OfficialAccount {
	oa := &OfficialAccount{
		host:   "https://api.weixin.qq.com",
		appid:  appid,
		secret: secret,
		client: internal.NewClient(),
	}
	for _, f := range options {
		f(oa)
	}
	return oa
}
