package minip

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/cryptokit"
	"github.com/noble-gase/he/wechat/event"
)

// SafeMode 安全鉴权模式配置
type SafeMode struct {
	aesSN  string
	aeskey string
	prvKey *cryptokit.PrivateKey
	pubSN  string
	pubKey *cryptokit.PublicKey
}

// ServerConfig 服务器配置
type ServerConfig struct {
	token  string
	aeskey string
}

// Client 小程序
type Client struct {
	host   string
	appid  string
	secret string
	srvCfg ServerConfig
	sfMode SafeMode

	client *resty.Client

	token  func(ctx context.Context) (string, error)
	logger func(ctx context.Context, err error, data map[string]string)
}

// AppID 返回appid
func (c *Client) AppID() string {
	return c.appid
}

// Secret 返回secret
func (c *Client) Secret() string {
	return c.secret
}

// SetServerConfig 设置服务器配置
//
//	[参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (c *Client) SetServerConfig(token, aeskey string) {
	c.srvCfg.token = token
	c.srvCfg.aeskey = aeskey
}

func (c *Client) SetAesKey(sn, key string) {
	c.sfMode.aesSN = sn
	c.sfMode.aeskey = key
}

func (c *Client) SetPrivateKey(pem []byte) error {
	key, err := cryptokit.NewPrivateKey(pem)
	if err != nil {
		return err
	}
	c.sfMode.prvKey = key
	return nil
}

func (c *Client) SetPublicKey(pem []byte) error {
	key, err := cryptokit.NewPublicKey(pem)
	if err != nil {
		return err
	}
	c.sfMode.pubKey = key
	return nil
}

func (c *Client) SetPrivateKeyFromPfx(pfxData []byte, password string) error {
	key, err := cryptokit.PfxToPrivateKey(pfxData, password)
	if err != nil {
		return err
	}
	c.sfMode.prvKey = key
	return nil
}

func (c *Client) SetTokenLoader(fn func(ctx context.Context) (string, error)) {
	c.token = fn
}

func (c *Client) SetHttpClient(cli *http.Client) {
	c.client = resty.NewWithClient(cli)
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

func (c *Client) dosafe(ctx context.Context, method, path string, header http.Header, query url.Values, params X) ([]byte, error) {
	now := time.Now().Unix()

	// 加密
	params, err := c.encrypt(path, query, params, now)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	// 签名
	sign, err := c.sign(path, now, body)
	if err != nil {
		return nil, err
	}

	header.Set(HeaderAppID, c.appid)
	header.Set(HeaderTimestamp, strconv.FormatInt(now, 10))
	header.Set(HeaderSignature, sign)

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

	// 验签
	if err = c.verify(path, resp.Header(), resp.Body()); err != nil {
		log.SetError(err)
		return nil, err
	}

	// 解密
	data, err := c.decrypt(path, resp.Header(), resp.Body())
	if err != nil {
		log.SetError(err)
		return nil, err
	}
	log.Set("origin_response_body", string(data))
	return data, nil
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

func (c *Client) encrypt(path string, query url.Values, params X, timestamp int64) (X, error) {
	if len(c.sfMode.aeskey) == 0 {
		return nil, errors.New("missing aes-gcm key (forgotten configure?)")
	}

	if params == nil {
		params = X{}
	}

	params["_n"] = base64.StdEncoding.EncodeToString(internal.NonceByte(16))
	params["_appid"] = c.appid
	params["_timestamp"] = timestamp

	for k, v := range query {
		if k != AccessToken && len(v) != 0 {
			params[k] = v[0]
		}
	}

	data, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(c.sfMode.aeskey)
	if err != nil {
		return nil, err
	}

	iv := internal.NonceByte(12)
	aad := fmt.Sprintf("%s|%s|%d|%s", c.url(path, nil), c.appid, timestamp, c.sfMode.aesSN)

	ct, err := cryptokit.AESEncryptGCM(key, iv, data, []byte(aad), nil)
	if err != nil {
		return nil, err
	}

	body := X{
		"iv":      base64.StdEncoding.EncodeToString(iv),
		"data":    base64.StdEncoding.EncodeToString(ct.Data()),
		"authtag": base64.StdEncoding.EncodeToString(ct.Tag()),
	}
	return body, nil
}

func (c *Client) sign(path string, timestamp int64, body []byte) (string, error) {
	if c.sfMode.prvKey == nil {
		return "", errors.New("missing private key (forgotten configure?)")
	}

	var builder strings.Builder

	builder.WriteString(c.url(path, nil))
	builder.WriteString("\n")
	builder.WriteString(c.appid)
	builder.WriteString("\n")
	builder.WriteString(strconv.FormatInt(timestamp, 10))
	builder.WriteString("\n")
	builder.Write(body)

	b, err := c.sfMode.prvKey.SignPSS(crypto.SHA256, []byte(builder.String()), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (c *Client) verify(path string, header http.Header, body []byte) error {
	if c.sfMode.pubKey == nil {
		return errors.New("missing public key (forgotten configure?)")
	}

	if appid := header.Get(HeaderAppID); appid != c.appid {
		return fmt.Errorf("header appid mismatch, expect = %s", c.appid)
	}

	var sign string
	if serial := header.Get(HeaderSerial); serial == c.sfMode.pubSN {
		sign = header.Get(HeaderSignature)
	} else {
		serialDeprecated := header.Get(HeaderSerialDeprecated)
		if serialDeprecated != c.sfMode.pubSN {
			return fmt.Errorf("header serial mismatch, expect = %s", c.sfMode.pubSN)
		}
		sign = header.Get(HeaderSignatureDeprecated)
	}
	b, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	var builder strings.Builder

	builder.WriteString(c.url(path, nil))
	builder.WriteString("\n")
	builder.WriteString(c.appid)
	builder.WriteString("\n")
	builder.WriteString(header.Get(HeaderTimestamp))
	builder.WriteString("\n")
	builder.Write(body)

	return c.sfMode.pubKey.VerifyPSS(crypto.SHA256, []byte(builder.String()), b, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func (c *Client) decrypt(path string, header http.Header, body []byte) ([]byte, error) {
	if len(c.sfMode.aeskey) == 0 {
		return nil, errors.New("missing aes-gcm key (forgotten configure?)")
	}

	key, err := base64.StdEncoding.DecodeString(c.sfMode.aeskey)
	if err != nil {
		return nil, err
	}

	ret := gjson.ParseBytes(body)

	iv, err := base64.StdEncoding.DecodeString(ret.Get("iv").String())
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(ret.Get("data").String())
	if err != nil {
		return nil, err
	}

	tag, err := base64.StdEncoding.DecodeString(ret.Get("authtag").String())
	if err != nil {
		return nil, err
	}

	aad := fmt.Sprintf("%s|%s|%s|%s", c.url(path, nil), c.appid, header.Get(HeaderTimestamp), c.sfMode.aesSN)

	return cryptokit.AESDecryptGCM(key, iv, append(data, tag...), []byte(aad), nil)
}

// Code2Session 通过临时登录凭证code完成登录流程
func (c *Client) Code2Session(ctx context.Context, code string) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", c.appid)
	query.Set("secret", c.secret)
	query.Set("js_code", code)
	query.Set("grant_type", "authorization_code")

	b, err := c.do(ctx, http.MethodGet, "/sns/jscode2session", nil, query, nil)
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
//	[普通模式] access_token有效期内重复调用该接口不会更新access_token，绝大部分场景下使用该模式；
//	[强制刷新模式] 会导致上次获取的access_token失效，并返回新的access_token
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

// DecodeEncryptData 解析加密数据，如：授权的用户信息和手机号
//
//	[参考](https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/signature.html)
func (*Client) DecodeEncryptData(sessionKey, iv, encryptData string) ([]byte, error) {
	keyBlock, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("session_key base64.decode error: %w", err)
	}
	ivBlock, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, fmt.Errorf("iv base64.decode error: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(encryptData)
	if err != nil {
		return nil, fmt.Errorf("encrypt_data base64.decode error: %w", err)
	}
	return cryptokit.AESDecryptCBC(keyBlock, ivBlock, data)
}

// VerifyEventMsg 验证事件消息
//
//	[服务器URL验证]
//	URL参数中的 signature、timestamp、nonce
//	注意：验证成功后，原样返回 echostr 字段值
//
//	[事件消息验证]
//	[明文模式] URL参数中的 signature、timestamp、nonce
//	[安全模式] URL参数中的 msg_signature、timestamp、nonce 和包体内的 Encrypt 字段
//
//	[参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
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
//	[参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (c *Client) DecodeEventMsg(encrypt string) ([]byte, error) {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return event.Decrypt(c.appid, c.srvCfg.aeskey, encrypt)
}

// EncodeEventReply 事件回复加密
//
//	根据配置的数据格式，输出 XML/JSON
//	[参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (c *Client) EncodeEventReply(msg KV) (KV, error) {
	if len(c.srvCfg.token) == 0 || len(c.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return event.Reply(c.appid, c.srvCfg.token, c.srvCfg.aeskey, msg)
}

// NewClient 生成一个小程序实例
func NewClient(appid, secret string) *Client {
	return &Client{
		host:   "https://api.weixin.qq.com",
		appid:  appid,
		secret: secret,
		client: internal.NewClient(),
	}
}
