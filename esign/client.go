package esign

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
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

	"github.com/noble-gase/he/internal"
)

// Client E签宝客户端
type Client struct {
	host   string
	appid  string
	secret string
	client *resty.Client
	logger func(ctx context.Context, err error, data map[string]string)
}

func (c *Client) SetHttpClient(cli *http.Client) {
	c.client = resty.NewWithClient(cli)
}

func (c *Client) SetLogger(fn func(ctx context.Context, err error, data map[string]string)) {
	c.logger = fn
}

// R 构建HTTP请求
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

func (c *Client) do(ctx context.Context, method, path string, header http.Header, query url.Values, params internal.X) ([]byte, error) {
	signOpts := make([]SignOption, 0)
	if len(query) != 0 {
		signOpts = append(signOpts, WithSignValues(query))
	}

	var (
		body []byte
		err  error
	)

	if params != nil {
		body, err = json.Marshal(params)
		if err != nil {
			return nil, err
		}
		contentMD5 := ContentMD5(body)

		header.Set(internal.HeaderContentType, "application/json; charset=UTF-8")
		header.Set(HeaderContentMD5, contentMD5)

		signOpts = append(signOpts, WithSignContMD5(contentMD5), WithSignContType("application/json; charset=UTF-8"))
	}

	header.Set(HeaderTSignOpenAppID, c.appid)
	header.Set(HeaderTSignOpenAuthMode, AuthModeSign)
	header.Set(HeaderTSignOpenCaTimestamp, strconv.FormatInt(time.Now().UnixMilli(), 10))

	sign := NewSigner(method, path, signOpts...).Do(c.secret)
	header.Set(HeaderTSignOpenCaSignature, sign)

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

func (c *Client) stream(ctx context.Context, uploadURL string, header http.Header, reader io.ReadSeeker) ([]byte, error) {
	h := md5.New()
	if _, err := io.Copy(h, reader); err != nil {
		return nil, err
	}
	md5 := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// 文件指针移动到头部
	if _, err := reader.Seek(0, 0); err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, 20<<10)) // 20kb
	if _, err := io.Copy(buf, reader); err != nil {
		return nil, err
	}

	header.Set(HeaderContentMD5, md5)

	log := internal.NewReqLog(http.MethodPut, uploadURL)
	defer log.Do(ctx, c.logger)

	log.SetReqHeader(header)

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		SetBody(buf.Bytes()).
		Put(uploadURL)
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

// Verify 签名验证 (回调通知等)
func (c *Client) Verify(header http.Header, body []byte) error {
	appid := header.Get(HeaderTSignOpenAppID)
	timestamp := header.Get(HeaderTSignOpenTimestamp)
	sign := header.Get(HeaderTSignOpenSignature)

	if appid != c.appid {
		return fmt.Errorf("appid mismatch, expect = %s, actual = %s", c.appid, appid)
	}

	h := hmac.New(sha256.New, []byte(c.secret))
	h.Write([]byte(timestamp))
	h.Write(body)
	if v := hex.EncodeToString(h.Sum(nil)); v != sign {
		return fmt.Errorf("signature mismatch, expect = %s, actual = %s", v, sign)
	}
	return nil
}

// NewClient 返回E签宝客户端
func NewClient(appid, secret string) *Client {
	return &Client{
		host:   "https://openapi.esign.cn",
		appid:  appid,
		secret: secret,
		client: internal.NewClient(),
	}
}

// NewSandbox 返回E签宝「沙箱环境」客户端
func NewSandbox(appid, secret string) *Client {
	return &Client{
		host:   "https://smlopenapi.esign.cn",
		appid:  appid,
		secret: secret,
		client: internal.NewClient(),
	}
}
