package v3

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/cryptokit"
)

type Cert struct {
	SerialNo   string `json:"serial_no"`   // 证书序列号
	EffectedAt int64  `json:"effected_at"` // 证书启用时间
	ExpiredAt  int64  `json:"expired_at"`  // 证书过期时间
	PemBlock   []byte `json:"pem_block"`   // 证书PEM内容
}

// Client 微信支付V3
type Client struct {
	host   string
	mchid  string
	apikey string
	prvSN  string
	prvKey *cryptokit.PrivateKey

	client *resty.Client

	cert   func(ctx context.Context, sn string) (*Cert, error)
	logger func(ctx context.Context, err error, data map[string]string)
}

// MchID 返回mchid
func (c *Client) MchID() string {
	return c.mchid
}

// ApiKey 返回APIv3密钥
func (c *Client) ApiKey() string {
	return c.apikey
}

// SetApiKey 设置APIv3密钥
func (c *Client) SetApiKey(key string) {
	c.apikey = key
}

// SetPrivateKey 设置私钥
func (c *Client) SetPrivateKey(sn string, pem []byte) error {
	key, err := cryptokit.NewPrivateKey(pem)
	if err != nil {
		return err
	}
	c.prvSN = sn
	c.prvKey = key
	return nil
}

// SetPrivateKeyFromPfx 设置私钥(pf12)
func (c *Client) SetPrivateKeyFromPfx(sn string, pfxData []byte, password string) error {
	key, err := cryptokit.PfxToPrivateKey(pfxData, password)
	if err != nil {
		return err
	}
	c.prvSN = sn
	c.prvKey = key
	return nil
}

func (c *Client) SetHttpClient(cli *http.Client) {
	c.client = resty.NewWithClient(cli)
}

// SetCertLoader 设置签名证书加载器
//
//	⚠️ 注意：参数`sn`为空时，应返回启用时间最晚的证书
func (c *Client) SetCertLoader(fn func(ctx context.Context, sn string) (*Cert, error)) {
	c.cert = fn
}

func (c *Client) SetLogger(fn func(ctx context.Context, err error, data map[string]string)) {
	c.logger = fn
}

func (c *Client) R() *Request {
	return &Request{
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

// Certificates 下载平台证书
//
//	[参考](https://pay.weixin.qq.com/doc/v3/merchant/4012551764)
func (c *Client) Certificates(ctx context.Context) ([]Cert, error) {
	sign, err := c.sign(http.MethodGet, "/v3/certificates", nil, "")
	if err != nil {
		return nil, err
	}

	header := http.Header{}
	header.Set(internal.HeaderAuthorization, sign)
	header.Set(internal.HeaderAccept, internal.ContentJSON)

	reqURL := c.url("/v3/certificates", nil)

	log := internal.NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqHeader(header)

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		Get(reqURL)
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
	if err = c.Verify(ctx, resp.Header(), resp.Body()); err != nil {
		return nil, err
	}

	data := gjson.GetBytes(resp.Body(), "data").Array()

	certs := make([]Cert, 0, len(data))
	for _, v := range data {
		serialNo := v.Get("serial_no").String()

		// 启用时间
		effectedAt, err := time.Parse(time.RFC3339, v.Get("effective_time").String())
		if err != nil {
			return nil, err
		}
		// 过期时间
		expiredAt, err := time.Parse(time.RFC3339, v.Get("expire_time").String())
		if err != nil {
			return nil, err
		}

		// 证书信息
		cert := v.Get("encrypt_certificate")

		nonce := cert.Get("nonce").String()
		data := cert.Get("ciphertext").String()
		aad := cert.Get("associated_data").String()

		block, err := cryptokit.AESDecryptGCM([]byte(c.apikey), []byte(nonce), []byte(data), []byte(aad), nil)
		if err != nil {
			return nil, err
		}
		certs = append(certs, Cert{
			SerialNo:   serialNo,
			EffectedAt: effectedAt.Unix(),
			ExpiredAt:  expiredAt.Unix(),
			PemBlock:   block,
		})
	}
	return certs, nil
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

	sign, err := c.sign(method, path, query, string(body))
	if err != nil {
		return nil, err
	}
	header.Set(internal.HeaderAuthorization, sign)

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
	if err = c.Verify(ctx, resp.Header(), resp.Body()); err != nil {
		return nil, err
	}
	return resp.Body(), nil
}

func (c *Client) upload(ctx context.Context, path string, header http.Header, filename string, reader io.ReadSeeker) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, reader); err != nil {
		return nil, err
	}
	sha := hex.EncodeToString(h.Sum(nil))

	meta := fmt.Sprintf(`{"filename":"%s","sha256":"%s"}`, filename, sha)
	sign, err := c.sign(http.MethodPost, path, nil, meta)
	if err != nil {
		return nil, err
	}
	header.Set(internal.HeaderAuthorization, sign)

	// 文件指针移动到头部
	if _, _err := reader.Seek(0, 0); _err != nil {
		return nil, _err
	}

	reqURL := c.url(path, nil)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqHeader(header)
	log.Set("metadata", meta)

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		SetMultipartField("file", filename, "", reader).
		SetMultipartField("meta", "", internal.ContentJSON, strings.NewReader(meta)).
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
	if err = c.Verify(ctx, resp.Header(), resp.Body()); err != nil {
		return nil, err
	}
	return resp.Body(), nil
}

func (c *Client) sign(method, path string, query url.Values, body string) (string, error) {
	if c.prvKey == nil {
		return "", errors.New("missing private key (forgotten configure?)")
	}

	nonce := internal.Nonce(32)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	var builder strings.Builder

	builder.WriteString(method)
	builder.WriteString("\n")
	builder.WriteString(path)
	if len(query) != 0 {
		builder.WriteString("?")
		builder.WriteString(query.Encode())
	}
	builder.WriteString("\n")
	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")
	if len(body) != 0 {
		builder.WriteString(body)
	}
	builder.WriteString("\n")

	sign, err := c.prvKey.Sign(crypto.SHA256, []byte(builder.String()))
	if err != nil {
		return "", err
	}

	auth := fmt.Sprintf(AuthFmt, c.mchid, nonce, base64.StdEncoding.EncodeToString(sign), timestamp, c.prvSN)
	return auth, nil
}

// encrypt 敏感信息加密
//
//	[参考](https://pay.weixin.qq.com/doc/v3/merchant/4013053264)
func (c *Client) encrypt(ctx context.Context, data X, keys ...string) (string, error) {
	if c.cert == nil {
		return "", errors.New("cert loader is nil (forgotten set?)")
	}

	// 加载最新证书
	cert, err := c.cert(ctx, "")
	if err != nil {
		return "", err
	}
	if cert == nil || len(cert.PemBlock) == 0 {
		return "", errors.New("cert load failed")
	}

	key, err := cryptokit.NewPublicKey(cert.PemBlock)
	if err != nil {
		return "", err
	}

	for _, k := range keys {
		if v, ok := data[k]; ok && v != nil {
			s := internal.AnyToStr(v)
			b, err := key.EncryptOAEP(crypto.SHA1, []byte(s))
			if err != nil {
				return "", err
			}
			data[k] = string(b)
		}
	}
	return cert.SerialNo, nil
}

// Verify 验证微信签名
//
//	[参考](https://pay.weixin.qq.com/doc/v3/merchant/4013053249)
func (c *Client) Verify(ctx context.Context, header http.Header, body []byte) error {
	if c.cert == nil {
		return errors.New("cert loader is nil (forgotten set?)")
	}

	sn := header.Get(HeaderSerial)
	if len(sn) == 0 {
		return nil
	}

	// 加载指定证书
	cert, err := c.cert(ctx, sn)
	if err != nil {
		return err
	}
	if cert == nil || len(cert.PemBlock) == 0 {
		return fmt.Errorf("cert(%s) load failed", sn)
	}

	key, err := cryptokit.NewPublicKey(cert.PemBlock)
	if err != nil {
		return err
	}

	nonce := header.Get(HeaderNonce)
	timestamp := header.Get(HeaderTimestamp)
	sign := header.Get(HeaderSignature)

	var builder strings.Builder

	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")
	if len(body) != 0 {
		builder.Write(body)
	}
	builder.WriteString("\n")

	return key.Verify(crypto.SHA256, []byte(builder.String()), []byte(sign))
}

// DecryptNotify 回调通知Body解密
//
//	[参考](https://pay.weixin.qq.com/doc/v3/merchant/4013070368)
func (c *Client) DecryptNotify(ctx context.Context, body []byte) (gjson.Result, error) {
	resource := gjson.GetBytes(body, "resource")

	nonce := resource.Get("nonce").String()
	data := resource.Get("ciphertext").String()
	aad := resource.Get("associated_data").String()

	b, err := cryptokit.AESDecryptGCM([]byte(c.apikey), []byte(nonce), []byte(data), []byte(aad), nil)
	if err != nil {
		return internal.FailE(err)
	}
	return gjson.ParseBytes(b), nil
}

// Download 下载资源 (需先获取download_url)
func (c *Client) Download(ctx context.Context, downloadURL string, w io.Writer) error {
	sign, err := c.sign(http.MethodGet, downloadURL, nil, "")
	if err != nil {
		return err
	}

	log := internal.NewReqLog(http.MethodGet, downloadURL)
	defer log.Do(ctx, c.logger)

	log.Set(internal.HeaderAuthorization, sign)

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeader(internal.HeaderAuthorization, sign).
		SetDoNotParseResponse(true).
		Get(downloadURL)
	if err != nil {
		log.SetError(err)
		return err
	}

	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())

	if !resp.IsSuccess() {
		ret := gjson.ParseBytes(resp.Body())
		return fmt.Errorf("%s | %s", ret.Get("code").String(), ret.Get("message").String())
	}
	_, err = io.Copy(w, resp.RawResponse.Body)
	return err
}

// APPAPI 用于APP拉起支付
func (c *Client) APPAPI(appid, prepayID string) (KV, error) {
	nonce := internal.Nonce(32)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	kv := KV{}

	kv.Set("appid", appid)
	kv.Set("partnerid", c.mchid)
	kv.Set("prepayid", prepayID)
	kv.Set("package", "Sign=WXPay")
	kv.Set("noncestr", nonce)
	kv.Set("timestamp", timestamp)

	var builder strings.Builder

	builder.WriteString(appid)
	builder.WriteString("\n")
	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")
	builder.WriteString(prepayID)
	builder.WriteString("\n")

	sign, err := c.prvKey.Sign(crypto.SHA256, []byte(builder.String()))
	if err != nil {
		return nil, err
	}
	kv.Set("sign", string(sign))

	return kv, nil
}

// JSAPI 用于JS拉起支付
func (c *Client) JSAPI(appid, prepayID string) (KV, error) {
	nonce := internal.Nonce(32)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	kv := KV{}

	kv.Set("appId", appid)
	kv.Set("nonceStr", nonce)
	kv.Set("package", "prepay_id="+prepayID)
	kv.Set("signType", "RSA")
	kv.Set("timeStamp", timestamp)

	var builder strings.Builder

	builder.WriteString(appid)
	builder.WriteString("\n")
	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")
	builder.WriteString("prepay_id=" + prepayID)
	builder.WriteString("\n")

	sign, err := c.prvKey.Sign(crypto.SHA256, []byte(builder.String()))
	if err != nil {
		return nil, err
	}
	kv.Set("sign", string(sign))

	return kv, nil
}

// NewClient 生成一个微信支付(v3)实例
func NewClient(mchid, apikey string) *Client {
	return &Client{
		host:   "https://api.mch.weixin.qq.com",
		mchid:  mchid,
		apikey: apikey,
		client: internal.NewClient(),
	}
}
