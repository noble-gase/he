package v3

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/cryptokit"
	"github.com/noble-gase/he/internal/kvkit"
)

// Client 支付宝V3客户端(仅支持v3版本的接口可用)
type Client struct {
	host   string
	appid  string
	aesKey string
	prvKey *cryptokit.PrivateKey
	pubKey *cryptokit.PublicKey
	client *resty.Client
	logger func(ctx context.Context, err error, data map[string]string)
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

// R 构建请求
//
//	[参考](https://opendocs.alipay.com/open-v3/054oog)
func (c *Client) R(path string) *Request {
	return &Request{
		path:   path,
		header: make(http.Header),
		query:  make(url.Values),

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

func (c *Client) do(ctx context.Context, method, path string, header http.Header, query url.Values, bizdata internal.X) ([]byte, error) {
	var (
		body []byte
		err  error
	)

	if bizdata != nil {
		body, err = json.Marshal(bizdata)
		if err != nil {
			return nil, err
		}
	}

	authStr, err := c.authorization(method, path, query, body, header)
	if err != nil {
		return nil, err
	}
	header.Set(internal.HeaderAuthorization, authStr)

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

	// 签名校验
	if err = c.verify(resp.Header(), resp.Body()); err != nil {
		return nil, err
	}
	return resp.Body(), nil
}

func (c *Client) docrypto(ctx context.Context, method, path string, header http.Header, query url.Values, bizdata internal.X) ([]byte, error) {
	var (
		body   []byte
		cipher string
		err    error
	)

	if bizdata != nil {
		body, err = json.Marshal(bizdata)
		if err != nil {
			return nil, err
		}

		cipher, err = c.encrypt(body)
		if err != nil {
			return nil, err
		}
	}

	authStr, err := c.authorization(method, path, query, []byte(cipher), header)
	if err != nil {
		return nil, err
	}
	header.Set(internal.HeaderAuthorization, authStr)

	reqURL := c.url(path, query)

	log := internal.NewReqLog(method, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqHeader(header)
	if bizdata != nil {
		log.SetReqBody(body)
		log.Set("encrypt", cipher)
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
	log.SetRespBody(resp.Body())

	if !resp.IsSuccess() {
		return nil, exception(resp)
	}

	// 签名校验
	if err = c.verify(resp.Header(), resp.Body()); err != nil {
		return nil, err
	}

	decrypt, err := c.decrypt(string(resp.Body()))
	if err != nil {
		return nil, err
	}
	log.Set("decrypt", string(decrypt))
	return decrypt, nil
}

func (c *Client) upload(ctx context.Context, path string, header http.Header, query url.Values, files []*resty.MultipartField, bizdata internal.X) ([]byte, error) {
	var (
		data []byte
		err  error
	)

	if bizdata != nil {
		data, err = json.Marshal(bizdata)
		if err != nil {
			return nil, err
		}
	}

	authStr, err := c.authorization(http.MethodPost, path, query, data, header)
	if err != nil {
		return nil, err
	}
	header.Set(internal.HeaderAuthorization, authStr)

	reqURL := c.url(path, query)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqHeader(header)
	if bizdata != nil {
		log.Set("biz_data", string(data))
	}

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		SetMultipartFields(files...).
		SetMultipartField("data", "", internal.ContentJSON, bytes.NewReader(data)).
		Post(reqURL)
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

	// 签名校验
	if err = c.verify(resp.Header(), resp.Body()); err != nil {
		return nil, err
	}
	return resp.Body(), nil
}

func (c *Client) authorization(method, path string, query url.Values, body []byte, header http.Header) (string, error) {
	if c.prvKey == nil {
		return "", errors.New("missing private key (forgotten configure?)")
	}

	authStr := fmt.Sprintf("app_id=%s,nonce=%s,timestamp=%d", c.appid, internal.Nonce(32), time.Now().UnixMilli())

	var builder strings.Builder

	builder.WriteString(authStr)
	builder.WriteString("\n")
	builder.WriteString(method)
	builder.WriteString("\n")
	builder.WriteString(path)
	if len(query) != 0 {
		builder.WriteString("?")
		builder.WriteString(query.Encode())
	}
	builder.WriteString("\n")
	if len(body) != 0 {
		builder.Write(body)
		builder.WriteString("\n")
	}
	if token := header.Get(HeaderAppAuthToken); len(token) != 0 {
		builder.WriteString(token)
		builder.WriteString("\n")
	}

	sign, err := c.prvKey.Sign(crypto.SHA256, []byte(builder.String()))
	if err != nil {
		return "", err
	}
	auth := fmt.Sprintf("ALIPAY-SHA256withRSA %s,sign=%s", authStr, base64.StdEncoding.EncodeToString(sign))
	return auth, nil
}

func (c *Client) verify(header http.Header, body []byte) error {
	if c.pubKey == nil {
		return errors.New("missing public key (forgotten configure?)")
	}

	signByte, err := base64.StdEncoding.DecodeString(header.Get(HeaderSignature))
	if err != nil {
		return err
	}

	nonce := header.Get(HeaderNonce)
	timestamp := header.Get(HeaderTimestamp)

	var builder strings.Builder

	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")

	if len(body) != 0 {
		builder.Write(body)
		builder.WriteString("\n")
	}
	return c.pubKey.Verify(crypto.SHA256, []byte(builder.String()), signByte)
}

func (c *Client) encrypt(data []byte) (string, error) {
	key, err := base64.StdEncoding.DecodeString(c.aesKey)
	if err != nil {
		return "", err
	}

	ct, err := cryptokit.AESEncryptCBC(key, make([]byte, 16), data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct.Bytes()), nil
}

func (c *Client) decrypt(encryptData string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(c.aesKey)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(encryptData)
	if err != nil {
		return nil, err
	}
	return cryptokit.AESDecryptCBC(key, make([]byte, 16), data)
}

// VerifyNotify 验证异步回调通知表单数据
//
//	[参考](https://opendocs.alipay.com/open-v3/05vuxp)
func (c *Client) VerifyNotify(form url.Values) error {
	if c.pubKey == nil {
		return errors.New("missing public key (forgotten configure?)")
	}

	sign, err := base64.StdEncoding.DecodeString(form.Get("sign"))
	if err != nil {
		return err
	}

	v := kvkit.KV{}
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

// NewClientV3 生成支付宝客户端V3
func NewClientV3(appid, aesKey string) *Client {
	return &Client{
		host:   "https://openapi.alipay.com",
		appid:  appid,
		aesKey: aesKey,
		client: internal.NewClient(),
	}
}

// NewSandboxV3 生成支付宝沙箱V3
func NewSandboxV3(appid, aesKey string) *Client {
	return &Client{
		host:   "http://openapi.sandbox.dl.alipaydev.com",
		appid:  appid,
		aesKey: aesKey,
		client: internal.NewClient(),
	}
}
