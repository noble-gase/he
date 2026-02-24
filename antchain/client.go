package antchain

import (
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/cryptokit"
)

// Config 客户端配置
type Config struct {
	BizID      string                `json:"biz_id"`      // 链ID (a00e36c5)
	TenantID   string                `json:"tenant_id"`   // 租户ID
	AccessID   string                `json:"access_id"`   // AccessID
	AccessKey  *cryptokit.PrivateKey `json:"access_key"`  // AccessKey
	Account    string                `json:"account"`     // 链账户
	MyKmsKeyID string                `json:"mykmskey_id"` // 托管标识
}

// ChainCallOption 链调用选项
type ChainCallOption func(params internal.X)

func WithParam(key string, value any) ChainCallOption {
	return func(params internal.X) {
		params[key] = value
	}
}

// Client 蚂蚁联盟链客户端
type Client struct {
	endpoint string
	config   *Config

	client *resty.Client

	logger func(ctx context.Context, err error, data map[string]string)
}

func (c *Client) SetHttpClient(cli *http.Client) {
	c.client = resty.NewWithClient(cli)
}

func (c *Client) SetLogger(fn func(ctx context.Context, err error, data map[string]string)) {
	c.logger = fn
}

func (c *Client) shakehand(ctx context.Context) (string, error) {
	timeStr := strconv.FormatInt(time.Now().UnixMilli(), 10)

	sign, err := c.config.AccessKey.Sign(crypto.SHA256, []byte(c.config.AccessID+timeStr))
	if err != nil {
		return "", err
	}

	params := internal.X{
		"accessId": c.config.AccessID,
		"time":     timeStr,
		"secret":   hex.EncodeToString(sign),
	}
	return c.do(ctx, c.endpoint+SHAKE_HAND, nil, params)
}

func (c *Client) chainCall(ctx context.Context, method string, options ...ChainCallOption) (string, error) {
	token, err := c.shakehand(ctx)
	if err != nil {
		return "", err
	}

	params := internal.X{}
	for _, f := range options {
		f(params)
	}
	params["bizid"] = c.config.BizID
	params["accessId"] = c.config.AccessID
	params["method"] = method
	params["token"] = token

	return c.do(ctx, c.endpoint+CHAIN_CALL, nil, params)
}

func (c *Client) chainCallForBiz(ctx context.Context, method string, options ...ChainCallOption) (string, error) {
	token, err := c.shakehand(ctx)
	if err != nil {
		return "", err
	}

	params := internal.X{}
	for _, f := range options {
		f(params)
	}
	params["orderId"] = uuid.New().String()
	params["bizid"] = c.config.BizID
	params["account"] = c.config.Account
	params["mykmsKeyId"] = c.config.MyKmsKeyID
	params["method"] = method
	params["accessId"] = c.config.AccessID
	params["tenantid"] = c.config.TenantID
	params["token"] = token

	return c.do(ctx, c.endpoint+CHAIN_CALL_FOR_BIZ, nil, params)
}

func (c *Client) do(ctx context.Context, reqURL string, header http.Header, params internal.X) (string, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return "", err
	}

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	log.SetReqHeader(header)
	log.SetReqBody(body)

	resp, err := c.client.R().
		SetContext(ctx).
		SetHeader(internal.HeaderContentType, internal.ContentJSON).
		SetBody(body).
		Post(reqURL)
	if err != nil {
		log.SetError(err)
		return "", err
	}

	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(resp.Body())

	if !resp.IsSuccess() {
		return "", errors.New(resp.Status())
	}

	ret := gjson.ParseBytes(resp.Body())
	if !ret.Get("success").Bool() {
		return "", fmt.Errorf("%s | %s", ret.Get("code").String(), ret.Get("data").String())
	}
	return ret.Get("data").String(), nil
}

// NewClient 生成蚂蚁联盟链客户端
func NewClient(cfg *Config) *Client {
	return &Client{
		endpoint: "https://rest.baas.alipay.com",
		config:   cfg,
		client:   internal.NewClient(),
	}
}
