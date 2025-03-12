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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"

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

func (c *Client) do(ctx context.Context, method, path string, query url.Values, params X) (gjson.Result, error) {
	reqURL := c.url(path, query)

	log := internal.NewReqLog(method, reqURL)
	defer log.Do(ctx, c.logger)

	header := http.Header{}

	header.Set(internal.HeaderAccept, AcceptAll)
	header.Set(HeaderTSignOpenAppID, c.appid)
	header.Set(HeaderTSignOpenAuthMode, AuthModeSign)
	header.Set(HeaderTSignOpenCaTimestamp, strconv.FormatInt(time.Now().UnixMilli(), 10))

	var (
		body []byte
		err  error
	)

	options := make([]SignOption, 0)
	if len(query) != 0 {
		options = append(options, WithSignValues(query))
	}

	if params != nil {
		body, err = json.Marshal(params)
		if err != nil {
			log.SetError(err)
			return internal.Fail(err)
		}
		log.SetReqBody(string(body))

		contentMD5 := ContentMD5(body)

		header.Set(internal.HeaderContentType, "application/json; charset=UTF-8")
		header.Set(HeaderContentMD5, contentMD5)

		options = append(options, WithSignContMD5(contentMD5), WithSignContType("application/json; charset=UTF-8"))
	}

	header.Set(HeaderTSignOpenCaSignature, NewSigner(method, path, options...).Do(c.secret))

	log.SetReqHeader(header)

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		SetBody(body).
		Execute(method, reqURL)
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
	if code := ret.Get("code").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("%d | %s", code, ret.Get("message")))
	}
	return ret.Get("data"), nil
}

func (c *Client) doStream(ctx context.Context, uploadURL string, reader io.ReadSeeker) error {
	log := internal.NewReqLog(http.MethodPut, uploadURL)
	defer log.Do(ctx, c.logger)

	h := md5.New()
	if _, err := io.Copy(h, reader); err != nil {
		log.SetError(err)
		return err
	}

	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentStream)
	header.Set(HeaderContentMD5, base64.StdEncoding.EncodeToString(h.Sum(nil)))
	log.SetReqHeader(header)

	// 文件指针移动到头部
	if _, err := reader.Seek(0, 0); err != nil {
		log.SetError(err)
		return err
	}

	buf := bytes.NewBuffer(make([]byte, 0, 20<<10)) // 20kb
	if _, err := io.Copy(buf, reader); err != nil {
		log.SetError(err)
		return err
	}

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		SetBody(buf.Bytes()).
		Put(uploadURL)
	if err != nil {
		log.SetError(err)
		return err
	}
	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(string(resp.Body()))
	if !resp.IsSuccess() {
		return fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode())
	}

	ret := gjson.ParseBytes(resp.Body())
	if code := ret.Get("errCode").Int(); code != 0 {
		return fmt.Errorf("%d | %s", code, ret.Get("msg"))
	}
	return nil
}

// GetJSON GET请求JSON数据
func (c *Client) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	return c.do(ctx, http.MethodGet, path, query, nil)
}

// PostJSON POST请求JSON数据
func (c *Client) PostJSON(ctx context.Context, path string, params X) (gjson.Result, error) {
	return c.do(ctx, http.MethodPost, path, nil, params)
}

// PutStream 上传文件流
func (c *Client) PutStream(ctx context.Context, uploadURL string, reader io.ReadSeeker) error {
	return c.doStream(ctx, uploadURL, reader)
}

// PutStreamFromFile 通过文件上传文件流
func (c *Client) PutStreamFromFile(ctx context.Context, uploadURL, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return c.doStream(ctx, uploadURL, f)
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

// Option 自定义设置项
type Option func(c *Client)

// WithHttpClient 设置自定义 HTTP Client
func WithHttpClient(cli *http.Client) Option {
	return func(c *Client) {
		c.client = resty.NewWithClient(cli)
	}
}

// WithLogger 设置日志记录
func WithLogger(fn func(ctx context.Context, err error, data map[string]string)) Option {
	return func(c *Client) {
		c.logger = fn
	}
}

// NewClient 返回E签宝客户端
func NewClient(appid, secret string, options ...Option) *Client {
	c := &Client{
		host:   "https://openapi.esign.cn",
		appid:  appid,
		secret: secret,
		client: internal.NewClient(),
	}
	for _, f := range options {
		f(c)
	}
	return c
}

// NewSandbox 返回E签宝「沙箱环境」客户端
func NewSandbox(appid, secret string, options ...Option) *Client {
	c := &Client{
		host:   "https://smlopenapi.esign.cn",
		appid:  appid,
		secret: secret,
		client: internal.NewClient(),
	}
	for _, f := range options {
		f(c)
	}
	return c
}
