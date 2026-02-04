package v2

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/cryptokit"
	"github.com/noble-gase/he/internal/hashkit"
	"github.com/noble-gase/he/internal/kvkit"
)

// Client 微信支付
type Client struct {
	host   string
	mchid  string
	apikey string

	client *resty.Client
	tlsCli *resty.Client

	logger func(ctx context.Context, err error, data map[string]string)
}

// MchID 返回mchid
func (c *Client) MchID() string {
	return c.mchid
}

// ApiKey 返回apikey
func (c *Client) ApiKey() string {
	return c.apikey
}

func (c *Client) SetHttpClient(cli *http.Client) {
	c.client = resty.NewWithClient(cli)
}

func (c *Client) SetTlsClient(cli *http.Client) {
	c.tlsCli = resty.NewWithClient(cli)
}

func (c *Client) SetTlsCertFromPemFile(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	c.tlsCli.SetCertificates(cert)
	return nil
}

func (c *Client) SetTlsCertFromPemBlock(certPem, keyPem []byte) error {
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return err
	}
	c.tlsCli.SetCertificates(cert)
	return nil
}

func (c *Client) SetTlsCertFromPfx(pfxData []byte) error {
	cert, err := cryptokit.PfxToCert(pfxData, c.mchid)
	if err != nil {
		return err
	}
	c.tlsCli.SetCertificates(cert)
	return nil
}

func (c *Client) SetLogger(fn func(ctx context.Context, err error, data map[string]string)) {
	c.logger = fn
}

func (c *Client) R() *Request {
	return &Request{
		params: make(XML),
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

func (c *Client) do(ctx context.Context, path string, params XML) ([]byte, error) {
	params.Set("sign", c.Sign(params))

	body, err := KVToXML(params)
	if err != nil {
		return nil, err
	}

	reqURL := c.url(path, nil)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqBody([]byte(body))

	resp, err := c.client.R().
		SetContext(ctx).
		SetBody(body).
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

func (c *Client) doTls(ctx context.Context, path string, params XML) ([]byte, error) {
	params.Set("sign", c.Sign(params))

	body, err := KVToXML(params)
	if err != nil {
		return nil, err
	}

	reqURL := c.url(path, nil)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqBody([]byte(body))

	resp, err := c.tlsCli.R().
		SetContext(ctx).
		SetBody(body).
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

func (c *Client) Sign(v XML) string {
	signStr := v.Encode("=", "&", kvkit.WithIgnoreKeys("sign"), kvkit.WithEmptyMode(kvkit.EmptyIgnore)) + "&key=" + c.apikey

	signType := v.Get("sign_type")
	if len(signType) == 0 {
		signType = v.Get("signType")
	}

	if SignAlgo(strings.ToUpper(signType)) == SignHMacSHA256 {
		return strings.ToUpper(hashkit.HMacSHA256(c.apikey, signStr))
	}
	return strings.ToUpper(hashkit.MD5(signStr))
}

func (c *Client) Verify(v XML) error {
	sign := c.Sign(v)
	if s := v.Get("sign"); s != sign {
		return fmt.Errorf("sign verify failed, expect = %s, actual = %s", sign, s)
	}
	return nil
}

// DecryptRefund 退款结果通知解密
func (c *Client) DecryptRefund(encrypt string) (XML, error) {
	cipherText, err := base64.StdEncoding.DecodeString(encrypt)
	if err != nil {
		return nil, err
	}
	plainText, err := cryptokit.AESDecryptECB([]byte(hashkit.MD5(c.apikey)), cipherText)
	if err != nil {
		return nil, err
	}
	return XMLToKV(plainText)
}

// APPAPI 用于APP拉起支付
func (c *Client) APPAPI(appid, prepayID string) XML {
	v := XML{}

	v.Set("appid", appid)
	v.Set("partnerid", c.mchid)
	v.Set("prepayid", prepayID)
	v.Set("package", "Sign=WXPay")
	v.Set("noncestr", internal.Nonce(16))
	v.Set("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("sign", c.Sign(v))

	return v
}

// JSAPI 用于JS拉起支付
func (c *Client) JSAPI(appid, prepayID string) XML {
	v := XML{}

	v.Set("appId", appid)
	v.Set("nonceStr", internal.Nonce(16))
	v.Set("package", "prepay_id="+prepayID)
	v.Set("signType", "MD5")
	v.Set("timeStamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("paySign", c.Sign(v))

	return v
}

// MinipRedpackJSAPI 小程序领取红包
func (c *Client) MinipRedpackJSAPI(appid, pkg string) XML {
	v := XML{}

	v.Set("appId", appid)
	v.Set("nonceStr", internal.Nonce(16))
	v.Set("package", url.QueryEscape(pkg))
	v.Set("timeStamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("signType", "MD5")

	signStr := fmt.Sprintf("appId=%s&nonceStr=%s&package=%s&timeStamp=%s&key=%s", appid, v.Get("nonceStr"), v.Get("package"), v.Get("timeStamp"), c.apikey)
	v.Set("paySign", hashkit.MD5(signStr))

	return v
}

// NewClient 生成一个微信支付实例
func NewClient(mchid, apikey string) *Client {
	return &Client{
		host:   "https://api.mch.weixin.qq.com",
		mchid:  mchid,
		apikey: apikey,
		client: internal.NewClient(),
		tlsCli: internal.NewClient(),
	}
}
