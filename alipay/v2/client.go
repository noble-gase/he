package v2

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/cryptokit"
	"github.com/noble-gase/he/internal/kvkit"
)

// Client 支付宝客户端
type Client struct {
	gateway string
	appid   string
	aesKey  string
	prvKey  *cryptokit.PrivateKey
	pubKey  *cryptokit.PublicKey
	client  *resty.Client
	logger  func(ctx context.Context, err error, data map[string]string)
}

// AppID 返回appid
func (c *Client) AppID() string {
	return c.appid
}

func (c *Client) SetPrivateKey(pem []byte) error {
	key, err := cryptokit.NewPrivateKey(pem)
	if err != nil {
		return err
	}
	c.prvKey = key
	return nil
}

func (c *Client) SetPublicKey(pem []byte) error {
	key, err := cryptokit.NewPublicKey(pem)
	if err != nil {
		return err
	}
	c.pubKey = key
	return nil
}

func (c *Client) SetPrivateKeyFromPKCS1Raw(raw []byte) error {
	pem := cryptokit.FormatPrivatePemRaw(string(raw), cryptokit.RSA_PRIVATE_KEY)
	return c.SetPrivateKey([]byte(pem))
}

func (c *Client) SetPublicKeyFromPCKS1Raw(raw []byte) error {
	pem := cryptokit.FormatPublicPemRaw(string(raw), cryptokit.RSA_PUBLIC_KEY)
	return c.SetPublicKey([]byte(pem))
}

func (c *Client) SetPrivateKeyFromPKCS8Raw(raw []byte) error {
	pem := cryptokit.FormatPrivatePemRaw(string(raw), cryptokit.PRIVATE_KEY)
	return c.SetPrivateKey([]byte(pem))
}

func (c *Client) SetPublicKeyFromPCKS8Raw(raw []byte) error {
	pem := cryptokit.FormatPublicPemRaw(string(raw), cryptokit.PUBLIC_KEY)
	return c.SetPublicKey([]byte(pem))
}

func (c *Client) SetHttpClient(cli *http.Client) {
	c.client = resty.NewWithClient(cli)
}

func (c *Client) SetLogger(fn func(ctx context.Context, err error, data map[string]string)) {
	c.logger = fn
}

// R 构建网关请求
func (c *Client) R(method string) *Request {
	return &Request{
		method:  method,
		options: make(KV),
		form:    make(KV),

		client: c,
	}
}

// do 向支付宝网关发送请求
func (c *Client) do(ctx context.Context, method string, header http.Header, options, biz KV) (gjson.Result, error) {
	common, hash, err := c.buildCommon(method, options, biz)
	if err != nil {
		return internal.FailE(err)
	}

	reqURL := c.gateway + "?" + common.URLEncode()

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqHeader(header)
	log.SetReqBody([]byte(biz.URLEncode()))

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		SetFormData(biz).
		Post(reqURL)
	if err != nil {
		log.SetError(err)
		return internal.FailE(err)
	}

	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(resp.Body())

	if !resp.IsSuccess() {
		return internal.Fail(resp.Status())
	}
	return c.parseResponse(c.respkey(method), resp.Body(), hash)
}

func (c *Client) upload(ctx context.Context, method string, header http.Header, options KV, files []*resty.MultipartField, biz KV) (gjson.Result, error) {
	common, hash, err := c.buildCommon(method, options, biz)
	if err != nil {
		return internal.FailE(err)
	}

	reqURL := c.gateway + "?" + common.URLEncode()

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqHeader(header)
	log.SetReqBody([]byte(biz.URLEncode()))

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		SetMultipartFields(files...).
		SetMultipartFormData(biz).
		Post(reqURL)
	if err != nil {
		log.SetError(err)
		return internal.FailE(err)
	}

	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(resp.Body())

	if !resp.IsSuccess() {
		return internal.Fail(resp.Status())
	}
	return c.parseResponse(c.respkey(method), resp.Body(), hash)
}

func (c *Client) buildCommon(method string, options, biz KV) (KV, crypto.Hash, error) {
	common := KV{}

	// 公共必填参数
	common.Set("app_id", c.appid)
	common.Set("method", method)
	common.Set("format", "json")
	common.Set("charset", "UTF-8")
	common.Set("timestamp", time.Now().In(time.Local).Format(time.DateTime))
	common.Set("version", "1.0")

	for k, v := range options {
		common.Set(k, v)
	}

	sign, h, err := c.sign(common, biz)
	if err != nil {
		return nil, 0, err
	}
	common.Set("sign", sign)

	return common, h, nil
}

func (c *Client) parseResponse(key string, body []byte, hash crypto.Hash) (gjson.Result, error) {
	if c.pubKey == nil {
		return internal.Fail("missing public key (forgotten configure?)")
	}

	ret := gjson.ParseBytes(body)

	// 签名
	sign, err := base64.StdEncoding.DecodeString(ret.Get("sign").String())
	if err != nil {
		return internal.FailE(err)
	}

	// 特殊错误响应
	if errResp := ret.Get("error_response"); errResp.Exists() {
		if err = c.pubKey.Verify(hash, []byte(errResp.Raw), sign); err != nil {
			return internal.FailE(err)
		}
		return errResp, nil
	}

	// 正常响应
	resp := ret.Get(key)

	// 验签
	if err = c.pubKey.Verify(hash, []byte(resp.Raw), sign); err != nil {
		return internal.FailE(err)
	}

	// JSON串，直接返回
	if strings.HasPrefix(ret.String(), "{") {
		return resp, nil
	}

	// 非JSON串，需解密
	data, err := c.decrypt(ret.String())
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(data), nil
}

func (c *Client) sign(common, biz KV) (string, crypto.Hash, error) {
	if c.prvKey == nil {
		return "", 0, errors.New("missing private key (forgotten configure?)")
	}

	kv := KV{}

	for k, v := range common {
		kv.Set(k, v)
	}
	for k, v := range biz {
		kv.Set(k, v)
	}

	h := crypto.SHA256
	if strings.EqualFold(kv.Get("sign_type"), "RSA") {
		h = crypto.SHA1
	}

	sign, err := c.prvKey.Sign(h, []byte(
		kv.Encode("=", "&", kvkit.WithEmptyMode(kvkit.EmptyIgnore)),
	))
	if err != nil {
		return "", 0, err
	}
	return string(sign), h, nil
}

func (*Client) respkey(method string) string {
	return strings.ReplaceAll(method, ".", "_") + "_response"
}

func (c *Client) encrypt(data string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(c.aesKey)
	if err != nil {
		return "", err
	}

	ct, err := cryptokit.AESEncryptCBC(key, make([]byte, 16), []byte(data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct.Bytes()), nil
}

func (c *Client) decrypt(cipher string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(c.aesKey)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		return nil, err
	}
	return cryptokit.AESDecryptCBC(key, make([]byte, 16), data)
}

// VerifyNotify 验证异步回调通知表单数据
//
//	[参考](https://opendocs.alipay.com/open/00dn78)
func (c *Client) VerifyNotify(form url.Values) error {
	if c.pubKey == nil {
		return errors.New("missing public key (forgotten configure?)")
	}

	sign, err := base64.StdEncoding.DecodeString(form.Get("sign"))
	if err != nil {
		return err
	}

	v := KV{}
	for key, vals := range form {
		if key == "sign_type" || key == "sign" || len(vals) == 0 {
			continue
		}
		v.Set(key, vals[0])
	}
	str := v.Encode("=", "&", kvkit.WithEmptyMode(kvkit.EmptyIgnore))

	h := crypto.SHA256
	if strings.EqualFold(form.Get("sign_type"), "RSA") {
		h = crypto.SHA1
	}
	return c.pubKey.Verify(h, []byte(str), sign)
}

// DecodeEncryptData 解析加密数据，如：授权的用户信息和手机号
func (c *Client) DecodeEncryptData(hash crypto.Hash, data, sign string) ([]byte, error) {
	if c.pubKey == nil {
		return nil, errors.New("missing public key (forgotten configure?)")
	}

	signByte, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return nil, fmt.Errorf("sign base64.decode error: %w", err)
	}
	if err = c.pubKey.Verify(hash, []byte(`"`+data+`"`), signByte); err != nil {
		return nil, fmt.Errorf("sign verified error: %w", err)
	}
	return c.decrypt(data)
}

// NewClient 生成支付宝客户端
func NewClient(appid, aesKey string) *Client {
	return &Client{
		appid:   appid,
		aesKey:  aesKey,
		gateway: "https://openapi.alipay.com/gateway.do",
		client:  internal.NewClient(),
	}
}

// NewSandbox 生成支付宝沙箱环境
func NewSandbox(appid, aesKey string) *Client {
	return &Client{
		appid:   appid,
		aesKey:  aesKey,
		gateway: "https://openapi-sandbox.dl.alipaydev.com/gateway.do",
		client:  internal.NewClient(),
	}
}
